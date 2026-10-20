//! `decented-net` — generic decentralised real-time transport.
//!
//! Nostr relays are used only to find the other players (an encrypted offer /
//! answer exchange keyed by a short room code). After that every peer talks to
//! the host directly over QUIC: one reliable, ordered stream per peer plus QUIC
//! datagrams for lossy traffic. On a LAN the host also broadcasts a UDP beacon
//! so a joiner can connect with no internet at all.
//!
//! The API is synchronous and non-blocking: every call returns at once, and
//! everything that takes time happens on the crate's own tokio runtime and
//! comes back as events from `poll()`.
//!
//! Adapted from Axe'n'Stax (MIT) — see `NOTICE`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

pub use bytes::Bytes;
pub use nostr::{Keys, PublicKey};

mod client;
#[cfg(test)]
mod fake_ws;
mod host;
mod identity;
pub mod ifaces;
mod lan;
pub mod migration;
pub mod nat;
pub mod netbind;
mod quic;
pub mod relay;
pub mod rendezvous;
pub mod room;
mod virt;

pub use client::{join, join_addr, join_lan, join_session_addr, join_with_relay, ClientHandle};
pub use host::HostHandle;
pub use identity::{npub_of, Identity};
pub use lan::{lan_browse, LanBrowser};
pub use netbind::{check_lan_binding, lan_blocked, LanBindError, LanSocketHook, VPN_BLOCKS_LAN};
pub use virt::{
    host_virtual, join_virtual, virtual_link_queue, virtual_pair, VirtualLink, VirtualLinkReceiver,
    VirtualLinkSender, MAX_VIRTUAL_PACKET, VIRTUAL_MTU,
};

#[cfg(test)]
mod tests;

/// Relays used when the app does not configure its own.
pub use decented_relays::DEFAULT_RELAYS;
/// STUN servers used when the app does not configure its own.
pub const DEFAULT_STUN: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
/// UDP port of the LAN beacon.
pub const DEFAULT_LAN_PORT: u16 = 7715;
/// Version of this crate's own wire (offer/answer, hello/welcome, beacon, and
/// the ALPN). v2: 6-char codes with the Argon2id room derivation and a signed
/// host welcome. v3: the encrypted answer names the host identity, which must
/// sign the welcome (review-net-1 N1). v4: the joiner proves admission first
/// and sends its identity only after verifying the welcome (review-net-1 N5).
/// v5: 6-letter codes from a 24-letter alphabet and the `room-v3` salt, so the
/// room derivation changed.
/// v6: the identify frame and the welcome carry the sender's inbox relays
/// (0 to 3 `wss://` URLs, each at most 256 characters), covered by the same
/// signatures as the attestation; both digests changed. The room derivation
/// is the same as v5, so a v5 build and a v6 one do find each other on the
/// relays and are told "version"; on the LAN the beacon is filtered on the
/// version, so they never list each other.
/// v7: signed welcome and identify bind a fresh server challenge and the
/// migration session, descriptor, term and endpoint roles when enabled.
/// A v1 build can never half-match a later one: different tags, different
/// ALPN, and the beacon is filtered on it. v2 to v4 share the room
/// derivation, so a mix is told "version"; v5 has its own derivation, so a v5
/// build and an older one never find each other on the relays at all, and the
/// bump keeps an older LAN browser from listing a v5 beacon (a code of letters
/// outside I and O is valid in both alphabets) and joining it by beacon token.
pub const NET_PROTOCOL_VERSION: u32 = 7;
/// Largest reliable message `send_reliable` will carry (and accept: a bigger
/// frame from a peer ends the connection).
pub const MAX_RELIABLE_LEN: usize = 1024;
/// Largest lossy message `send_lossy` will carry (always fits a QUIC datagram
/// at the minimum 1200-byte path MTU).
pub const MAX_LOSSY_LEN: usize = 1024;
/// Most player seats in a room. A playing host occupies one seat.
pub const MAX_PLAYERS: u8 = 8;

/// Everything the transport needs to know about this install.
#[derive(Clone, Debug)]
pub struct NetConfig {
    /// Where `identity.key` lives.
    pub data_dir: PathBuf,
    /// `wss://` relay URLs for room-code rendezvous. Empty = LAN only.
    /// The player's order is the priority order.
    pub relays: Vec<String>,
    /// While every relay in `relays` is failing, also try the built-in
    /// defaults (the app says so). On by default; off for [`NetConfig::lan_only`].
    pub relay_fallback: bool,
    /// `host:port` STUN servers. Empty = no reflexive candidate.
    pub stun: Vec<String>,
    /// UDP port of the LAN beacon (host sends to it, browsers bind it).
    pub lan_port: u16,
    /// UDP port QUIC binds. 0 = ephemeral.
    pub quic_port: u16,
    /// Whether the host reserves a local player seat. Defaults to true.
    /// Set false for a dedicated host with only remote players.
    pub host_has_player: bool,
    /// The app's id. It namespaces room codes, the QUIC ALPN and the LAN
    /// beacon, so two apps on this crate never cross-connect. The crate has
    /// no default: the app passes its own to [`NetConfig::new`].
    pub app_tag: String,
    /// This install's inbox relays: at most 3 `wss://` URLs of at most 256
    /// characters each (anything else is dropped before sending). They travel
    /// next to the attestation in the identify frame and the welcome, signed
    /// with it, and come back to the app beside the peer's attestation. A host
    /// that withholds its attestation ([`NetConfig::withhold_host_attestation`])
    /// withholds these too.
    pub inbox_relays: Vec<String>,
    /// Leave the host's persona attestation and inbox relays out of its
    /// welcome (it then carries the key only; the app can share the persona once it has
    /// accepted the joiner). `None` = the transport's default: withheld on
    /// virtual links ([`host_virtual`]: anyone in radio range can get as far as
    /// the welcome), sent on LAN and code joins.
    pub withhold_host_attestation: Option<bool>,
    /// Binds a socket that talks to local peers to the local network, so a VPN
    /// cannot swallow it (Android: the Wi-Fi `Network`). See [`netbind`].
    /// `None` = sockets use the default route.
    pub lan_socket_hook: Option<LanSocketHook>,
    /// A VPN is carrying the phone's internet traffic (the app sets this; it
    /// knows the network). A router port mapping (UPnP) would then name the
    /// home router's real public address while the VPN carries the traffic,
    /// so no UPnP is attempted and no room-code offer carries a UPnP
    /// candidate. STUN still reports the address the VPN presents.
    pub vpn_active: bool,
    /// How long a silent connection lives before it is dropped. Default 6 s.
    /// QUIC uses the lower of the two ends' values (and never less than three
    /// round-trip timeouts), so a peer can only shorten it. A longer timeout
    /// also delays the drop events that start a host migration.
    pub idle_timeout: std::time::Duration,
    /// How often an idle connection sends a keep-alive. Default 1 s.
    pub keep_alive: std::time::Duration,
    /// The app's own TLS exporter label (RFC 5705). `None` (the default) =
    /// none. When set, Fray computes 32 bytes per connection with it and an
    /// empty context, on both ends: [`ClientHandle::app_binding`] and
    /// [`HostHandle::app_binding`] return them. Both ends of one connection
    /// get the same bytes; two different TLS sessions never do. The label must
    /// start with `EXPORTER-`, be at most 249 bytes, and differ from every
    /// label Fray uses itself (`EXPORTER-decented-net-hello-v2`); anything else
    /// fails the host or join at start, like a bad idle-timeout pair. The value
    /// is `None` if the exporter fails. A host that resumes or stands by gives
    /// each peer's new connection its own value, the same way.
    pub app_binding_label: Option<String>,
    /// Tests only: whether the hooked LAN endpoint treats loopback sources as
    /// local (always so outside tests: loopback is this device).
    #[cfg(test)]
    pub(crate) lan_allow_loopback: bool,
}

impl NetConfig {
    /// Defaults for everything but the data directory and the app tag.
    pub fn new(data_dir: impl Into<PathBuf>, app_tag: impl Into<String>) -> Self {
        NetConfig {
            data_dir: data_dir.into(),
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            relay_fallback: true,
            stun: DEFAULT_STUN.iter().map(|s| s.to_string()).collect(),
            lan_port: DEFAULT_LAN_PORT,
            quic_port: 0,
            host_has_player: true,
            app_tag: app_tag.into(),
            inbox_relays: Vec::new(),
            withhold_host_attestation: None,
            lan_socket_hook: None,
            vpn_active: false,
            idle_timeout: quic::IDLE_TIMEOUT,
            keep_alive: quic::KEEP_ALIVE,
            app_binding_label: None,
            #[cfg(test)]
            lan_allow_loopback: true,
        }
    }

    /// The checked idle-timeout / keep-alive pair: both non-zero and
    /// `keep_alive < idle_timeout`. Checked where the config is first used.
    pub(crate) fn liveness(&self) -> Result<quic::Liveness, String> {
        quic::Liveness::new(self.idle_timeout, self.keep_alive)
    }

    /// Everything checked where the config is first used: the liveness pair
    /// and the app's exporter label.
    pub(crate) fn checked(&self) -> Result<quic::Liveness, String> {
        if let Some(label) = &self.app_binding_label {
            quic::check_app_label(label)?;
        }
        self.liveness()
    }

    /// No relays and no STUN: a host or joiner that never touches the internet.
    pub fn lan_only(mut self) -> Self {
        self.relays.clear();
        self.relay_fallback = false;
        self.stun.clear();
        self
    }
}

/// Start hosting. Watch [`HostHandle::poll`] for `Ready` or `Failed`.
pub fn host(cfg: &NetConfig, id: &Identity, room: RoomInfo) -> HostHandle {
    host::host(cfg, &virt::host_identity(cfg, id, false), room)
}

/// Host over a caller-supplied relay (`None` = LAN only).
pub fn host_with_relay(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    relay: Option<Box<dyn relay::RendezvousRelay>>,
) -> HostHandle {
    host::host_with_relay(cfg, &virt::host_identity(cfg, id, false), room, relay)
}

/// Start the designated standby's passive, unadvertised control listener.
/// The code and credentials arrive through the existing encrypted consent path.
pub fn host_standby(
    cfg: &NetConfig,
    id: &Identity,
    code: &str,
    descriptor: migration::Descriptor,
) -> Result<HostHandle, String> {
    let policy = migration::EndpointPolicy {
        descriptor,
        role: migration::LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    host::start_session_endpoint(
        cfg,
        &virt::host_identity(cfg, id, false),
        RoomInfo {
            name: "Standby".into(),
            max_players: MAX_PLAYERS,
        },
        code,
        policy,
    )
}
/// Resume exactly the signed promotion under the existing room code. Ordinary
/// host() still generates a fresh code. Known roster links may authenticate
/// while gameplay admission remains closed; the runner requires ResumeProof.
pub fn resume_host(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    code: &str,
    descriptor: migration::Descriptor,
    promotion: migration::Promotion,
) -> Result<HostHandle, String> {
    let policy = migration::EndpointPolicy {
        descriptor,
        role: migration::LinkRole::Successor,
        promotion: Some(promotion),
        membership: None,
    };
    host::start_session_endpoint(
        cfg,
        &virt::host_identity(cfg, id, false),
        room,
        code,
        policy,
    )
}

/// What the host advertises.
#[derive(Clone, Debug)]
pub struct RoomInfo {
    pub name: String,
    /// Including the host. Clamped to `2..=MAX_PLAYERS`.
    pub max_players: u8,
}

/// A connected peer, as numbered by the host. Never reused within one host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u32);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer{}", self.0)
    }
}

/// How a connection got through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PathKind {
    /// Same network: a LAN beacon join, or a room-code join whose LAN candidate won.
    Lan,
    /// Through the internet: a STUN, UPnP or IPv6 candidate won.
    Direct,
    /// Over a [`VirtualLink`] (Bluetooth LE L2CAP in the app).
    Virtual,
}

/// Why a peer left (host side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaveReason {
    /// The peer closed the connection.
    Left,
    /// Nothing heard from the peer within the idle timeout.
    TimedOut,
    /// The host kicked it.
    Kicked,
    /// The connection broke some other way.
    Error(String),
}

/// Why the connection to the host ended (client side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The host shut down or closed the connection.
    HostLeft,
    /// The host kicked us.
    Kicked,
    /// We stayed on the confirm screen too long and the host dropped us (not
    /// a ban: we may join again).
    ConfirmTimeout,
    /// Nothing heard from the host within the idle timeout.
    TimedOut,
    /// The connection broke some other way.
    Error(String),
}

/// The stages a join goes through, in order. `Failed` names the one that broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinStage {
    /// Binding a socket and gathering our own candidates.
    Preparing,
    /// Room-code join: reaching relays, sending the offer, waiting for the answer.
    FindingHost,
    /// Punching and racing QUIC across the host's candidates (or dialling the
    /// LAN address directly). For a code join each candidate must also send a
    /// verified welcome before it can win.
    Connecting,
    /// QUIC is up; verifying the host's welcome, then (only to a verified
    /// host) sending our identity and waiting to be seated.
    Handshake,
}

/// Why a join failed. `Display` gives friendly copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailReason {
    /// The code is not 6 characters from the room-code alphabet.
    BadCode,
    /// No relay could be reached.
    RelayUnreachable,
    /// Relays were reached but no host answered the code.
    NoAnswer,
    /// The host answered but no candidate address connected.
    PunchFailed,
    /// The room is full.
    RoomFull,
    /// The room is not accepting players (a match is running).
    RoomClosed,
    /// The host runs an incompatible version.
    VersionMismatch,
    /// The host's signed welcome did not verify, or (code join) it was not
    /// signed by the identity the encrypted relay answer named, or it named a
    /// different relay key than the one that answered. Fails closed.
    HostUnverified,
    /// Two different keys answered our offer for this code: someone else knows
    /// the code and is racing the real host. Fails closed.
    HostConflict,
    /// The host refused our admission proof: wrong or stale code / LAN token
    /// (the room rotated it), or we were kicked from this room earlier.
    NotAdmitted,
    /// Local socket / runtime / protocol trouble.
    Network(String),
    /// A virtual link opened but the host never sent its pre-frame (or the
    /// link closed first).
    NoLinkAnswer,
}

impl std::fmt::Display for FailReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailReason::BadCode => write!(f, "That isn't a valid room code."),
            FailReason::RelayUnreachable => {
                write!(f, "Couldn't reach the internet meeting points (relays).")
            }
            FailReason::NoAnswer => write!(
                f,
                "Code not found (check the code, or the host may have started)."
            ),
            FailReason::PunchFailed => {
                write!(f, "Found the host but couldn't connect to their phone.")
            }
            FailReason::RoomFull => write!(f, "Room full."),
            FailReason::RoomClosed => write!(f, "That game has already started."),
            FailReason::VersionMismatch => {
                write!(f, "The host is running a different version of the app.")
            }
            FailReason::HostUnverified => {
                write!(f, "Couldn't confirm who the host is, so we didn't join.")
            }
            FailReason::HostConflict => write!(
                f,
                "Someone else answered that code too, so we didn't join. Ask the host to make a new game."
            ),
            FailReason::NotAdmitted => {
                write!(f, "The host didn't let us in (the code may be out of date).")
            }
            FailReason::Network(e) => write!(f, "Network problem: {e}"),
            FailReason::NoLinkAnswer => write!(f, "The host's phone didn't answer over the link."),
        }
    }
}

/// Host-side events, from [`HostHandle::poll`].
#[derive(Clone, Debug)]
pub enum HostEvent {
    /// Listening; the room code is live (relays and beacon start in the background).
    Ready {
        code: String,
    },
    /// Hosting could not start at all.
    Failed {
        reason: String,
    },
    /// A joiner is seated. `pubkey` is the identity key it proved over this
    /// connection; `attestation` is the persona attestation it sent with that
    /// proof (signed with it, so it was not swapped on the way). This crate
    /// does not verify the attestation: the app must, against `pubkey`.
    /// `inbox_relays` are the joiner's inbox relays from the same signed
    /// frame (validated: at most 3 `wss://` URLs, each at most 256 chars).
    PeerJoined {
        peer: PeerId,
        pubkey: PublicKey,
        path: PathKind,
        rtt_ms: u32,
        attestation: Option<String>,
        inbox_relays: Vec<String>,
    },
    PeerLeft {
        peer: PeerId,
        reason: LeaveReason,
    },
    Reliable {
        peer: PeerId,
        bytes: Bytes,
    },
    Lossy {
        peer: PeerId,
        bytes: Bytes,
    },
}

/// Client-side events, from [`ClientHandle::poll`].
#[derive(Clone, Debug)]
pub enum ClientEvent {
    Progress {
        stage: JoinStage,
    },
    /// In. `host_name` / `host_pubkey` come from the host's welcome, signed
    /// over this connection (and, for a code join, from the same key that
    /// answered the code). Show "Join <host_name>'s game?" before entering
    /// the lobby; backing out is just [`ClientHandle::shutdown`].
    /// `attestation` is the host's persona attestation from the same signed
    /// welcome. Not verified here: the app must check it against `host_pubkey`.
    /// `inbox_relays` are the host's, from the same signed welcome (empty if
    /// the host withheld them).
    Connected {
        path: PathKind,
        host_name: String,
        host_pubkey: PublicKey,
        attestation: Option<String>,
        inbox_relays: Vec<String>,
    },
    Failed {
        stage: JoinStage,
        reason: FailReason,
    },
    Reliable(Bytes),
    Lossy(Bytes),
    Disconnected {
        reason: DisconnectReason,
    },
}

/// A room heard on the LAN beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanRoom {
    pub name: String,
    pub code: String,
    pub player_count: u8,
    pub max_players: u8,
    /// Where to dial: the beacon's source IP and the advertised QUIC port.
    pub addr: SocketAddr,
    /// The room's LAN admission token (hex), proven in the hello.
    pub token: String,
}

/// The crate's own runtime. Created on first use; lives for the process.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("decented-net")
            .enable_all()
            .build()
            .expect("decented-net: could not start the tokio runtime")
    })
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
