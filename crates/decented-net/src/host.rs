//! Hosting a room: QUIC listener, room-code rendezvous, LAN beacon, peers.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nostr::{Keys, PublicKey};

use crate::lan::{Beacon, BeaconSender};
use crate::nat::candidates::{gather, punch_targets};
use crate::quic::{self, close, Ended, Inbound, Link};
use crate::relay::{MultiRelay, RendezvousRelay, TagFilter};
use crate::rendezvous::{open_offer, seal_answer, Answer, Candidate, KIND_JOIN_OFFER};
use crate::room::{
    derive_days, derive_invite_days, utc_today, InviteId, RoomSecrets, ROOM_TAG_LETTER,
};
use crate::{
    Admission, HostEvent, Identity, LeaveReason, NetConfig, PathKind, PeerId, RoomInfo,
    MAX_PLAYERS, NET_PROTOCOL_VERSION,
};

const BEACON_EVERY: Duration = Duration::from_secs(1);
/// A re-sent offer (same session) is re-answered at most this often.
const REANSWER_EVERY: Duration = Duration::from_millis(900);
/// New join sessions answered per [`NEW_SESSION_WINDOW`]; more offers are ignored
/// (each answered offer costs punches to the joiner's candidates).
const MAX_NEW_SESSIONS: usize = 16;
const NEW_SESSION_WINDOW: Duration = Duration::from_secs(10);
/// Answered sessions remembered (oldest evicted beyond this).
const MAX_SESSIONS: usize = 256;
/// Reliable messages from one peer waiting for the app to `poll`; one more
/// and the peer is disconnected (it is flooding, or the app has stalled).
pub const MAX_QUEUED_RELIABLE: usize = 256;
/// Datagrams from one peer waiting for `poll`; more are dropped.
pub const MAX_QUEUED_LOSSY: usize = 64;
/// How long a kicked peer's connection stays open so a last message flushes.
const KICK_FLUSH: Duration = Duration::from_millis(250);
pub(crate) const UPNP_RENEW_CHECK: Duration = Duration::from_secs(60);
/// Most invites a host holds at once ([`HostHandle::add_invite`]). Each costs
/// two relay tags in the host's one standing subscription.
pub const MAX_INVITES: usize = 256;

/// An event plus the per-peer counter it occupies until polled.
/// An event for `poll`; the counter, when set, is the inbound queue it was
/// counted in and the payload bytes to release when it leaves.
type Queued<E> = (
    E,
    Option<(Arc<Inbound>, usize)>,
    u64,
    Option<PeerEventFence>,
);
struct PeerEventFence {
    live: Arc<AtomicBool>,
    binding: Option<crate::migration::ConnectionBinding>,
    key: Option<[u8; 32]>,
    player: Option<u64>,
}
impl PeerEventFence {
    fn new(link: &Link) -> Self {
        Self {
            live: link.session_live.clone(),
            binding: link.migration.clone(),
            key: link.session_key,
            player: link.session_player,
        }
    }
    fn valid(&self, shared: &Shared) -> bool {
        if !self.live.load(Ordering::Acquire) {
            return false;
        }
        let Some(binding) = &self.binding else {
            return true;
        };
        let Some(key) = self.key else {
            return false;
        };
        shared
            .session_policy
            .lock()
            .map(|policy| {
                policy.as_ref().is_some_and(|p| {
                    p.authorize(binding, key).is_ok()
                        && (binding.client == crate::migration::LinkRole::Original
                            || p.player_for_key(key) == self.player)
                })
            })
            .unwrap_or(false)
    }
}

/// Who may join: proofs of any of these tokens are admitted.
struct Tokens {
    /// Published in the LAN beacon; rotated when the room opens or closes.
    lan: [u8; 32],
    /// From the code, for today and yesterday (online hosts only).
    code: Vec<[u8; 32]>,
    /// From each live invite, for today and yesterday (online hosts only).
    /// Installed by the host task; `remove_invite` strips a row at once.
    invites: Vec<(InviteId, [u8; 32])>,
    /// From each listener-level invite while this room is its app's invite
    /// target ([`crate::Listener::add_invite`]); empty otherwise.
    keep_invites: Vec<(InviteId, [u8; 32])>,
}

fn random_token() -> [u8; 32] {
    let mut t = [0u8; 32];
    getrandom::fill(&mut t).expect("OS RNG unavailable");
    t
}

pub(crate) struct Shared {
    peers: Mutex<HashMap<PeerId, Link>>,
    session_policy: Mutex<Option<crate::migration::EndpointPolicy>>,
    app_tag: String,
    /// The app's exporter label ([`NetConfig::app_binding_label`]).
    app_binding_label: Option<String>,
    /// The reliable limits every peer link runs with ([`NetConfig::max_reliable_len`]
    /// and the bounds beside it).
    limits: crate::ReliableLimits,
    pending_handshakes: AtomicUsize,
    generation: AtomicU64,
    /// The generation, published when the pin bumps it: a pending ordinary
    /// handshake watches it and is closed as a closed room once it changes.
    generation_tx: tokio::sync::watch::Sender<u64>,
    #[cfg(test)]
    before_registration: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    /// Tests move the host's UTC day on (to roll the room tags at "midnight");
    /// 0 = no override.
    #[cfg(test)]
    test_day: AtomicU64,
    /// Each connected peer's identity key (for the kick deny-list).
    peer_keys: Mutex<HashMap<PeerId, PublicKey>>,
    /// Identity keys kicked from this room; refused for the room's life.
    denied: Mutex<HashSet<PublicKey>>,
    tokens: Mutex<Tokens>,
    /// The live invites' secrets (at most [`MAX_INVITES`]). The handle edits
    /// this; the host task derives the tags and tokens from it. Lock this
    /// before `tokens` when holding both.
    invites: Mutex<HashMap<InviteId, [u8; 32]>>,
    open: AtomicBool,
    max_peers: usize,
    /// Shared by every room on one listener, so peer ids are unique on the
    /// endpoint.
    next_peer: Arc<AtomicU32>,
    /// The room has shut down (or its task ended): nobody is seated in it any
    /// more. Set under the peer lock.
    retired: AtomicBool,
    /// The room's listener has told its handle that it closed the room
    /// (once; see [`Shared::tell_listener_closed`]).
    listener_closed: AtomicBool,
    /// The current room code ([`HostHandle::rotate_code`] changes it). Lock
    /// this before `tokens` when holding both.
    code: Mutex<String>,
    /// What the room announces in its answers ([`HostHandle::announced`]).
    announced: Mutex<Vec<Candidate>>,
    /// The listener this room shares, if any, and the room's id on it.
    pub(crate) seat: Option<crate::listener::Seat>,
    ev_tx: Mutex<mpsc::Sender<Queued<HostEvent>>>,
    relays_up: AtomicUsize,
    relays_total: AtomicUsize,
    /// The LAN endpoint's address (the only endpoint's, without a LAN hook).
    local_addr: Mutex<Option<SocketAddr>>,
    /// The online endpoint's address; `None` without a LAN hook (one endpoint).
    online_addr: Mutex<Option<SocketAddr>>,
    /// Signs every welcome, so joiners can verify who they reached.
    host_keys: Keys,
    /// The host identity's persona attestation, if any (unverified seam).
    attestation: Option<String>,
    /// The host identity's inbox relays, sent in the welcome next to the attestation.
    inbox_relays: Vec<String>,
    /// The throwaway key each join session's relay answer was signed with
    /// (named in that session's welcome).
    answer_keys: Mutex<AnswerKeys>,
    room_name: String,
    /// Reported for every peer instead of the path its hello claims (a
    /// virtual host knows all its peers came over a virtual link).
    path_override: Option<PathKind>,
}

/// The throwaway key behind each recent join session's relay answer, so the
/// welcome can name the key that signed the answer the joiner is acting on.
#[derive(Default)]
pub(crate) struct AnswerKeys {
    by_session: HashMap<String, PublicKey>,
    /// Oldest first; the map holds at most [`MAX_SESSIONS`].
    order: std::collections::VecDeque<String>,
}

impl Shared {
    /// Remember the key that signed the answer to join session `session`.
    fn record_answer_key(&self, session: &str, key: PublicKey) {
        let Ok(mut keys) = self.answer_keys.lock() else {
            return;
        };
        // The first key recorded for a session stays: someone who re-offers a
        // session id they saw cannot swap the key its real joiner will be told.
        if let std::collections::hash_map::Entry::Vacant(slot) =
            keys.by_session.entry(session.to_string())
        {
            slot.insert(key);
            keys.order.push_back(session.to_string());
        }
        while keys.order.len() > MAX_SESSIONS {
            if let Some(old) = keys.order.pop_front() {
                keys.by_session.remove(&old);
            }
        }
    }

    /// The key to name in a welcome: the one that signed the answer to the
    /// hello's join session, or, for a hello that did not come from a relay
    /// answer (a LAN or virtual link, a session-bound reconnect, an answer
    /// long forgotten), a fresh key no answer was ever signed with.
    fn answer_key_for(&self, session: Option<&str>) -> PublicKey {
        session
            .and_then(|s| {
                self.answer_keys
                    .lock()
                    .ok()
                    .and_then(|k| k.by_session.get(s).copied())
            })
            .unwrap_or_else(|| Keys::generate().public_key())
    }

    pub(crate) fn emit(&self, ev: HostEvent) {
        self.emit_at(ev, self.generation.load(Ordering::Acquire));
    }
    fn emit_at(&self, ev: HostEvent, generation: u64) {
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((ev, None, generation, None));
        }
    }
    fn emit_registered(&self, peer: PeerId, generation: u64, ev: HostEvent) -> bool {
        let Ok(peers) = self.peers.lock() else {
            return false;
        };
        if self.generation.load(Ordering::Acquire) != generation
            || !peers
                .get(&peer)
                .is_some_and(|link| link.generation == generation)
        {
            return false;
        }
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((
                ev,
                None,
                generation,
                Some(PeerEventFence::new(&peers[&peer])),
            ));
        }
        true
    }

    /// Queue a peer message if that peer is still registered and under `cap`
    /// messages and `max_bytes` payload bytes.
    fn emit_counted(
        &self,
        peer: PeerId,
        generation: u64,
        ev: HostEvent,
        counter: &Arc<Inbound>,
        cap: usize,
        max_bytes: usize,
    ) -> Emitted {
        let Ok(peers) = self.peers.lock() else {
            return Emitted::Full;
        };
        if self.generation.load(Ordering::Acquire) != generation
            || !peers
                .get(&peer)
                .is_some_and(|link| link.generation == generation)
        {
            return Emitted::Detached;
        }
        let len = match &ev {
            HostEvent::Reliable { bytes, .. } | HostEvent::Lossy { bytes, .. } => bytes.len(),
            _ => 0,
        };
        if counter.admit(len, cap, max_bytes).is_err() {
            return Emitted::Full;
        }
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((
                ev,
                Some((Arc::clone(counter), len)),
                generation,
                Some(PeerEventFence::new(&peers[&peer])),
            ));
        }
        Emitted::Queued
    }

    /// The LAN admission token now (what the beacon, or a virtual link's
    /// pre-frame, carries).
    pub(crate) fn lan_token(&self) -> [u8; 32] {
        self.tokens
            .lock()
            .map(|t| t.lan)
            .unwrap_or_else(|_| random_token())
    }

    fn rotate_lan_token(&self) {
        if let Ok(mut t) = self.tokens.lock() {
            t.lan = random_token();
        }
    }

    /// Every token a hello may prove, in precedence order: the LAN token, the
    /// code's, then each invite's. A hello that proves several is credited to
    /// the first.
    pub(crate) fn admission_tokens(&self) -> Vec<(Admission, [u8; 32])> {
        self.tokens
            .lock()
            .map(|t| {
                std::iter::once((Admission::Lan, t.lan))
                    .chain(t.code.iter().map(|c| (Admission::Code, *c)))
                    .chain(
                        t.invites
                            .iter()
                            .chain(t.keep_invites.iter())
                            .map(|(id, token)| (Admission::Invite(*id), *token)),
                    )
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Detach and optionally ban in the same lock order as final admission.
    /// A concurrent authenticated reconnect cannot slip between removal/ban.
    fn detach_peer(&self, peer: PeerId, ban: bool) -> Option<Link> {
        let mut peers = self.peers.lock().ok()?;
        let link = peers.get(&peer)?.clone();
        let mut keys = self.peer_keys.lock().ok()?;
        let mut denied = if ban {
            Some(self.denied.lock().ok()?)
        } else {
            None
        };
        if let Some(key) = keys.remove(&peer) {
            if let Some(denied) = denied.as_mut() {
                denied.insert(key);
            }
        }
        peers.remove(&peer);
        Some(link)
    }
    /// The room is going: nobody is seated from now on (a handshake still
    /// running is refused at its seat), and it leaves its listener.
    pub(crate) fn retire(&self) {
        {
            // Under the peer lock, as every seat is taken: a handshake seated
            // before this is closed with the rest; one after sees the flag.
            let _held = self.peers.lock();
            self.retired.store(true, Ordering::Release);
        }
        if let Some(seat) = &self.seat {
            seat.leave();
        }
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// The room's listener closed it, not its own handle: say so once, so a
    /// game or status page polling the handle learns the room is gone ([`HostEvent::Failed`]).
    pub(crate) fn tell_listener_closed(&self) {
        if !self.listener_closed.swap(true, Ordering::AcqRel) {
            self.emit(HostEvent::Failed {
                reason: LISTENER_SHUTDOWN_REASON.into(),
            });
        }
    }

    /// A start-up event (`Ready`, or a failure before the room is up). A room
    /// on a listener that has been retired since (its listener shut down, or
    /// its handle did) says nothing more: the handle has already heard
    /// `Failed`, or asked for the close. Checked under the peer lock, as
    /// [`Shared::retire`] sets the flag, so nothing slips between the two.
    /// A room of its own always emits, as before.
    fn emit_start(&self, ev: HostEvent) {
        if self.seat.is_some() {
            let _held = self.peers.lock();
            if self.is_retired() {
                return;
            }
            self.emit(ev);
        } else {
            self.emit(ev);
        }
    }

    /// A room failed to start. On a listener that is already gone this is the
    /// listener's shutdown, told once like any other; otherwise `reason`.
    fn fail_start(&self, reason: String) {
        if let Some(seat) = &self.seat {
            if seat.listener().is_none() {
                self.retire();
                self.tell_listener_closed();
                return;
            }
        }
        self.emit_start(HostEvent::Failed { reason });
        self.retire();
    }

    /// The current room code.
    pub(crate) fn current_code(&self) -> String {
        self.code.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Strip listener-level invite tokens (all of them, or `only` that one):
    /// a hello proving them is refused from now on, here and at the seat.
    pub(crate) fn strip_keep_invites(&self, only: Option<InviteId>) {
        if let Ok(mut t) = self.tokens.lock() {
            match only {
                Some(id) => t.keep_invites.retain(|(i, _)| *i != id),
                None => t.keep_invites.clear(),
            }
        }
    }

    /// Close every connection (host gone).
    pub(crate) fn close_all(&self, code: u32, why: &'static [u8]) {
        let links: Vec<Link> = self
            .peers
            .lock()
            .map(|mut p| p.drain().map(|(_, l)| l).collect())
            .unwrap_or_default();
        for l in &links {
            l.conn.close(code.into(), why);
        }
    }
}

/// What became of a message from a peer ([`Shared::emit_counted`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Emitted {
    Queued,
    /// The peer is no longer registered (kicked, retired or gone): dropped.
    /// Its connection is already closing.
    Detached,
    /// The peer is over its queue cap: it is flooding.
    Full,
}

pub(crate) enum Cmd {
    SetOpen(bool),
    /// The set of live invites changed: derive, subscribe, install.
    InvitesChanged,
    /// The room code changed ([`HostHandle::rotate_code`]): derive, subscribe,
    /// install the new one.
    CodeChanged,
    Shutdown(mpsc::Sender<()>),
    /// The room's listener is closing it: as `Shutdown`, then the handle is
    /// told ([`Shared::tell_listener_closed`]) before the ack.
    ListenerShutdown(mpsc::Sender<()>),
}

/// A hosted room. All methods return immediately.
pub struct HostHandle {
    code: String,
    events: Mutex<mpsc::Receiver<Queued<HostEvent>>>,
    shared: Arc<Shared>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
    shut: AtomicBool,
}

/// The reason in the [`HostEvent::Failed`] a room's handle gets when its
/// listener shuts down (see [`HostHandle::closed_by_listener`]).
pub const LISTENER_SHUTDOWN_REASON: &str = "the listener shut down";

/// Start hosting. Watch [`HostHandle::poll`] for `Ready` or `Failed`.
pub fn host(cfg: &NetConfig, id: &Identity, room: RoomInfo) -> HostHandle {
    let relay: Option<Box<dyn RendezvousRelay>> = if cfg.relays.is_empty() {
        None
    } else {
        Some(Box::new(MultiRelay::start_in(
            decented_relays::RelayPool::global(),
            cfg.relays.clone(),
            cfg.relay_fallback,
        )))
    };
    host_with_relay(cfg, id, room, relay)
}

/// Host over a caller-supplied relay (`None` = LAN only).
pub fn host_with_relay(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    relay: Option<Box<dyn RendezvousRelay>>,
) -> HostHandle {
    host_inner(cfg, id, room, relay, None)
}

/// [`host_with_relay`] pinned to UTC day `day` (tests of the midnight overlap).
#[cfg(test)]
pub(crate) fn host_with_relay_at_day(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    relay: Option<Box<dyn RendezvousRelay>>,
    day: u64,
) -> HostHandle {
    host_inner(cfg, id, room, relay, Some(day))
}

fn host_inner(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    relay: Option<Box<dyn RendezvousRelay>>,
    fixed_day: Option<u64>,
) -> HostHandle {
    let cfg = cfg.clone();
    let relays_total = cfg.relays.len();
    start_host(
        id,
        room,
        cfg.host_has_player,
        relays_total,
        None,
        cfg.app_tag.clone(),
        cfg.app_binding_label.clone(),
        cfg.host_limits(),
        None,
        move |code, room, shared, cmd_rx| {
            HostTask {
                cfg,
                room,
                code,
                shared,
                fixed_day,
            }
            .run(relay, cmd_rx)
        },
    )
}

/// Open the consented standby's passive control endpoint, or resume the
/// certified successor under the existing code. A standby never advertises.
pub(crate) fn start_session_endpoint(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    code: &str,
    policy: crate::migration::EndpointPolicy,
) -> Result<HostHandle, String> {
    cfg.checked()?;
    cfg.check_migration_cap()?;
    cfg.advertised()?;
    policy
        .validate(id.pubkey().to_bytes(), code, &cfg.app_tag)
        .map_err(|e| e.to_string())?;
    if policy.role == crate::migration::LinkRole::Original {
        return Err("pin the existing original host handle".into());
    }
    let code = crate::room::normalize_code(code).ok_or("invalid room code")?;
    let mut cfg = cfg.clone();
    let relay: Option<Box<dyn RendezvousRelay>> = if policy.passive() || cfg.relays.is_empty() {
        None
    } else {
        Some(Box::new(MultiRelay::start_in(
            decented_relays::RelayPool::global(),
            cfg.relays.clone(),
            cfg.relay_fallback,
        )))
    };
    cfg.host_has_player = policy
        .descriptor
        .root
        .members
        .iter()
        .any(|m| m.key == Some(id.pubkey().to_bytes()));
    if policy.passive() {
        cfg.relays.clear();
        cfg.stun.clear();
        cfg.relay_fallback = false;
        cfg.host_has_player = false;
    }
    let relays_total = cfg.relays.len();
    let has_player = cfg.host_has_player;
    Ok(start_host(
        id,
        room,
        has_player,
        relays_total,
        None,
        cfg.app_tag.clone(),
        cfg.app_binding_label.clone(),
        cfg.host_limits(),
        Some((code, policy)),
        move |code, room, shared, cmd_rx| {
            HostTask {
                cfg,
                room,
                code,
                shared,
                fixed_day: None,
            }
            .run(relay, cmd_rx)
        },
    ))
}

/// Everything about a host but its transport: the room code, the shared state
/// and the handle. `task` gets the code, the clamped room, the
/// shared state and the command channel, and returns the transport's loop,
/// which runs on the crate runtime (the UDP loop above, or `virt`'s).
pub(crate) fn start_host<F, Fut>(
    id: &Identity,
    room: RoomInfo,
    host_has_player: bool,
    relays_total: usize,
    path_override: Option<PathKind>,
    app_tag: String,
    app_binding_label: Option<String>,
    limits: crate::ReliableLimits,
    pinned: Option<(String, crate::migration::EndpointPolicy)>,
    task: F,
) -> HostHandle
where
    F: FnOnce(String, RoomInfo, Arc<Shared>, tokio::sync::mpsc::UnboundedReceiver<Cmd>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    start_host_with(
        id,
        room,
        host_has_player,
        relays_total,
        path_override,
        app_tag,
        app_binding_label,
        limits,
        pinned,
        None,
        task,
    )
}

/// [`start_host`], for a room on a shared listener when `placement` is set
/// (its code, its seat on the listener and the listener's peer numbering).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_host_with<F, Fut>(
    id: &Identity,
    room: RoomInfo,
    host_has_player: bool,
    relays_total: usize,
    path_override: Option<PathKind>,
    app_tag: String,
    app_binding_label: Option<String>,
    limits: crate::ReliableLimits,
    pinned: Option<(String, crate::migration::EndpointPolicy)>,
    placement: Option<crate::listener::Placement>,
    task: F,
) -> HostHandle
where
    F: FnOnce(String, RoomInfo, Arc<Shared>, tokio::sync::mpsc::UnboundedReceiver<Cmd>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (code, seat, next_peer) = match placement {
        Some(p) => (p.code, Some(p.seat), p.next_peer),
        None => (
            pinned
                .as_ref()
                .map(|(code, _)| code.clone())
                .unwrap_or_else(crate::room::generate_code),
            None,
            Arc::new(AtomicU32::new(1)),
        ),
    };
    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let max_players = room.max_players.clamp(2, MAX_PLAYERS);
    let shared = Arc::new(Shared {
        peers: Mutex::new(HashMap::new()),
        session_policy: Mutex::new(pinned.as_ref().map(|(_, p)| p.clone())),
        app_tag,
        app_binding_label,
        limits,
        pending_handshakes: AtomicUsize::new(0),
        generation: AtomicU64::new(0),
        generation_tx: tokio::sync::watch::Sender::new(0),
        #[cfg(test)]
        before_registration: Mutex::new(None),
        #[cfg(test)]
        test_day: AtomicU64::new(0),
        peer_keys: Mutex::new(HashMap::new()),
        denied: Mutex::new(HashSet::new()),
        tokens: Mutex::new(Tokens {
            lan: random_token(),
            code: Vec::new(),
            invites: Vec::new(),
            keep_invites: Vec::new(),
        }),
        invites: Mutex::new(HashMap::new()),
        open: AtomicBool::new(pinned.is_none()),
        max_peers: max_players as usize - usize::from(host_has_player),
        next_peer,
        retired: AtomicBool::new(false),
        listener_closed: AtomicBool::new(false),
        code: Mutex::new(code.clone()),
        announced: Mutex::new(Vec::new()),
        seat,
        ev_tx: Mutex::new(ev_tx),
        relays_up: AtomicUsize::new(0),
        relays_total: AtomicUsize::new(relays_total),
        local_addr: Mutex::new(None),
        online_addr: Mutex::new(None),
        host_keys: id.keys().clone(),
        attestation: id.attestation().map(str::to_string),
        inbox_relays: id.inbox_relays().to_vec(),
        answer_keys: Mutex::new(AnswerKeys::default()),
        room_name: room.name.clone(),
        path_override,
    });
    let task = task(
        code.clone(),
        RoomInfo {
            name: room.name,
            max_players,
        },
        Arc::clone(&shared),
        cmd_rx,
    );
    let s = Arc::clone(&shared);
    crate::runtime().spawn(async move {
        use futures_util::FutureExt;
        // Backstop: nothing a peer sends should panic the host task, but if it
        // ever does, tell everyone the host is gone instead of leaving them
        // connected to a room that no longer answers.
        if std::panic::AssertUnwindSafe(task)
            .catch_unwind()
            .await
            .is_err()
        {
            log::error!("[host] host task panicked; closing the room");
            s.open.store(false, Ordering::Relaxed);
            s.retire();
            s.close_all(close::HOST_SHUTDOWN, b"host failed");
            s.emit(HostEvent::Failed {
                reason: "internal error".into(),
            });
        }
    });
    HostHandle {
        code,
        events: Mutex::new(ev_rx),
        shared,
        cmd_tx,
        shut: AtomicBool::new(false),
    }
}

impl HostHandle {
    /// Whether the room has ended: shut down, closed by its listener, or its
    /// task failed. Nobody is seated in a closed room and it never recovers.
    pub fn is_closed(&self) -> bool {
        self.shared.is_retired()
    }

    /// Whether the room's listener closed it (the listener was shut down or
    /// dropped), as opposed to the room's own handle or a failure. `true`
    /// from the moment the handle is told (the [`HostEvent::Failed`] with
    /// [`LISTENER_SHUTDOWN_REASON`]); a room of its own is never closed by a
    /// listener. Implies [`HostHandle::is_closed`] once the room is retired.
    pub fn closed_by_listener(&self) -> bool {
        self.shared.listener_closed.load(Ordering::Acquire)
    }

    /// This endpoint's runtime identity. This does not attest a persona.
    pub fn runtime_key(&self) -> PublicKey {
        self.shared.host_keys.public_key()
    }

    /// The runtime key proven by Identify on this currently live connection.
    /// Game admission remains the caller's responsibility.
    pub fn peer_key(&self, peer: PeerId) -> Option<PublicKey> {
        let peers = self.shared.peers.lock().ok()?;
        let link = peers.get(&peer)?;
        if !link.session_live.load(Ordering::Acquire) || link.conn.close_reason().is_some() {
            return None;
        }
        self.shared.peer_keys.lock().ok()?.get(&peer).copied()
    }

    /// Pin the original host after the arming runner freezes and detaches
    /// ordinary connections. Every replacement link must prove the root/role.
    ///
    /// A seated ordinary peer refuses the pin: the game closes stragglers
    /// first. Pending ordinary handshakes (not yet seated, unauthenticated or
    /// awaiting Identify) do not: the pin closes each one as a closed room
    /// (`CLOSED`) and frees its slot, since pinning closes the room to
    /// ordinary joins anyway. Otherwise any LAN host could hold the pin off
    /// by opening a bare QUIC connection every few seconds.
    pub fn pin_session(&self, descriptor: crate::migration::Descriptor) -> Result<(), String> {
        if self.shared.seat.is_some() {
            // Admission of a pinned room (pending-handshake cap, refusals
            // before the hello) is built on the room owning its endpoint; a
            // listener reads the hello first. Until that is designed and
            // tested, a room on a listener does not migrate.
            return Err("a room on a listener cannot migrate".into());
        }
        if self.shared.path_override == Some(PathKind::Virtual) {
            return Err("virtual migration is unsupported".into());
        }
        if self.shared.limits.max_len != crate::MAX_RELIABLE_LEN {
            return Err(format!(
                "max_reliable_len {} is not the default {}: host migration keeps its \
                 journal at the default size, so an app that migrates cannot raise it",
                self.shared.limits.max_len,
                crate::MAX_RELIABLE_LEN
            ));
        }
        let policy = crate::migration::EndpointPolicy {
            descriptor,
            role: crate::migration::LinkRole::Original,
            promotion: None,
            membership: None,
        };
        policy
            .validate(
                self.shared.host_keys.public_key().to_bytes(),
                &self.code,
                &self.shared.app_tag,
            )
            .map_err(|e| e.to_string())?;
        let peers = self.shared.peers.lock().map_err(|_| "host peer lock")?;
        if !peers.is_empty() {
            return Err("ordinary connections must drain before pinning".into());
        }
        let mut current = self
            .shared
            .session_policy
            .lock()
            .map_err(|_| "host policy lock")?;
        if let Some(existing) = &*current {
            if existing == &policy {
                return Ok(());
            }
            return Err("session policy already pinned".into());
        }
        let previous = self
            .shared
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |g| g.checked_add(1))
            .map_err(|_| "host generation exhausted")?;
        *current = Some(policy);
        // Under the peer lock, as every handshake registers: one registered
        // before this sees the change and is closed; one after sees the pin.
        self.shared.generation_tx.send_replace(previous + 1);
        self.shared.open.store(false, Ordering::Relaxed);
        let _ = self.cmd_tx.send(Cmd::SetOpen(false));
        Ok(())
    }
    pub fn connection_binding(&self, peer: PeerId) -> Option<crate::migration::ConnectionBinding> {
        self.shared.peers.lock().ok()?.get(&peer)?.migration.clone()
    }
    /// Install only sequencer-certified membership. Admission sees either the
    /// old complete policy or the new one; removed routes detach under the same
    /// peer lock used by final handshake registration.
    pub fn update_session_membership(
        &self,
        certificate: crate::migration::MembershipCertificate,
    ) -> Result<(), String> {
        let mut peers = self.shared.peers.lock().map_err(|_| "host peer lock")?;
        let mut current = self
            .shared
            .session_policy
            .lock()
            .map_err(|_| "host policy lock")?;
        let existing = current.as_ref().ok_or("host session is not pinned")?;
        let mut next = existing.clone();
        if let Some(previous) = &existing.membership {
            certificate
                .follows(&existing.descriptor.root, previous)
                .map_err(|e| e.to_string())?;
        }
        next.membership = Some(certificate);
        next.validate(
            self.shared.host_keys.public_key().to_bytes(),
            &self.code,
            &self.shared.app_tag,
        )
        .map_err(|e| e.to_string())?;
        let mut keys = self.shared.peer_keys.lock().map_err(|_| "host key lock")?;
        let removed: Vec<_> =
            peers
                .iter()
                .filter_map(|(&peer, link)| {
                    let authorized = link.migration.as_ref().zip(keys.get(&peer)).is_some_and(
                        |(binding, key)| {
                            next.authorize(binding, key.to_bytes()).is_ok()
                                && (binding.client == crate::migration::LinkRole::Original
                                    || next.player_for_key(key.to_bytes()) == link.session_player)
                        },
                    );
                    (!authorized).then_some(peer)
                })
                .collect();
        let links: Vec<_> = removed
            .iter()
            .filter_map(|peer| {
                keys.remove(peer);
                peers.remove(peer).map(|link| {
                    link.session_live.store(false, Ordering::Release);
                    (*peer, link)
                })
            })
            .collect();
        *current = Some(next);
        drop(keys);
        drop(current);
        drop(peers);
        for (peer, link) in links {
            link.conn
                .close(close::CLOSED.into(), b"session membership retired");
            self.shared.emit_at(
                HostEvent::PeerLeft {
                    peer,
                    reason: LeaveReason::Kicked,
                },
                link.generation,
            );
        }
        Ok(())
    }
    /// Build framing from this live link's verified handshake and the current
    /// installed membership, rather than caller-supplied identity/role fields.
    pub fn migration_channel(&self, peer: PeerId) -> Result<crate::migration::Channel, String> {
        let peers = self.shared.peers.lock().map_err(|_| "host peer lock")?;
        let link = peers.get(&peer).ok_or("peer is not connected")?;
        if !link.session_live.load(Ordering::Acquire) || link.conn.close_reason().is_some() {
            return Err("peer connection is closed".into());
        }
        let policy = self
            .shared
            .session_policy
            .lock()
            .map_err(|_| "host policy lock")?;
        let policy = policy.as_ref().ok_or("host session is not pinned")?;
        let binding = link
            .migration
            .clone()
            .ok_or("ordinary peer has no migration binding")?;
        let key = link.session_key.ok_or("peer identity is not bound")?;
        if binding.client != crate::migration::LinkRole::Original
            && policy.player_for_key(key) != link.session_player
        {
            return Err("peer membership changed".into());
        }
        let tls = quic::binding(&link.conn)?;
        let channel = crate::migration::Channel::new_bound(
            policy,
            binding,
            crate::migration::ChannelSide::Server,
            self.shared.host_keys.public_key().to_bytes(),
            key,
            tls,
        )
        .map_err(|error| error.to_string())?;
        link.session_channel_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "session framing already attached; reconnect requires fresh TLS")?;
        Ok(channel)
    }

    /// The app's own exporter value for `peer`'s current connection, under
    /// [`NetConfig::app_binding_label`]: the same 32 bytes that peer's
    /// [`ClientHandle::app_binding`] returns. `None` for an unknown peer, when
    /// no label is configured, or if the exporter failed. A peer that comes
    /// back on a new connection (a resume) gets that connection's own value.
    /// `peer` is this host's transport id: a migration successor numbers its
    /// peers afresh, so don't pass a migration seat or logical peer as one.
    pub fn app_binding(&self, peer: PeerId) -> Option<[u8; 32]> {
        self.link(peer)?.app_binding
    }

    /// Exporter for a ResumeProof challenge on this live authenticated link.
    pub fn tls_binding(&self, peer: PeerId) -> Option<[u8; 32]> {
        quic::binding(&self.link(peer)?.conn).ok()
    }

    /// Park every handshake just before it is seated, until the test has
    /// reached the barrier twice (tests of changes made in that window).
    #[cfg(test)]
    pub(crate) fn pause_before_seating(&self, barrier: Option<Arc<tokio::sync::Barrier>>) {
        if let Ok(mut b) = self.shared.before_registration.lock() {
            *b = barrier;
        }
    }

    /// Move the host's UTC day on (tests of the midnight roll).
    #[cfg(test)]
    pub(crate) fn set_test_day(&self, day: u64) {
        self.shared.test_day.store(day, Ordering::Relaxed);
    }

    /// Let people in by **invite** as well as by the room code. `secret` is 32
    /// random bytes the host generated and keeps; the invite link carries it
    /// with the host's public key (see [`join_invite`](crate::join_invite)).
    ///
    /// **The secret must be uniformly random**, from
    /// [`generate_invite_secret`](crate::generate_invite_secret) or an
    /// equivalent OS-RNG source. The invite's relay tags, keys and admission
    /// token are plain hashes of it, with no stretching, so anything guessable
    /// (a counter, a timestamp, a short phrase padded out) can be searched
    /// offline by anyone watching the relays.
    ///
    /// Callable at any time while hosting. The host then also listens on the
    /// invite's relay tags (today's and yesterday's, rolled at UTC midnight
    /// like the code's), answers offers on them under the same rules as the
    /// code (only while the room is open), and admits a hello proving the
    /// invite's token. Which one a joiner used is reported as
    /// [`Admission::Invite`] on [`HostEvent::PeerJoined`].
    ///
    /// Returns the invite's [`InviteId`] (derived from the secret, which it
    /// does not reveal); adding the same secret again returns the same id and
    /// takes no further slot. At most [`MAX_INVITES`] (256) are live at once:
    /// beyond that this returns an error. The listening starts a moment after
    /// this returns, on the host's task.
    ///
    /// Invites ride on the code-room host: they need relays, as the code does
    /// (on a host without relays they are accepted and can never be reached),
    /// and a virtual-link host refuses them.
    pub fn add_invite(&self, secret: [u8; 32]) -> Result<InviteId, String> {
        if self.shared.path_override == Some(PathKind::Virtual) {
            return Err("a virtual-link host has no relay rendezvous for invites".into());
        }
        let id = InviteId::of(&secret);
        {
            let mut live = self.shared.invites.lock().map_err(|_| "host invite lock")?;
            if !live.contains_key(&id) && live.len() >= MAX_INVITES {
                return Err(format!("too many invites (at most {MAX_INVITES})"));
            }
            live.insert(id, secret);
        }
        let _ = self.cmd_tx.send(Cmd::InvitesChanged);
        Ok(id)
    }

    /// Revoke an invite. From the moment this returns, a hello proving its
    /// token is refused, and so is one already mid-handshake (it is checked
    /// again when the peer would be seated); the host stops listening on its tags and stops
    /// answering offers sent to them (that lands on the host task's next
    /// turn, and an offer answered just before is a rendezvous only, never
    /// an admission). `false` if no such invite was live.
    ///
    /// Fray does **not** drop connections that were admitted by the invite:
    /// the game decides whether to [`kick`](Self::kick) those peers.
    pub fn remove_invite(&self, id: InviteId) -> bool {
        let removed = match self.shared.invites.lock() {
            Ok(mut live) => {
                let removed = live.remove(&id).is_some();
                if let Ok(mut t) = self.shared.tokens.lock() {
                    t.invites.retain(|(i, _)| *i != id);
                }
                removed
            }
            Err(_) => false,
        };
        if removed {
            let _ = self.cmd_tx.send(Cmd::InvitesChanged);
        }
        removed
    }

    /// The room code (also delivered in `Ready`, and changed by
    /// [`rotate_code`](Self::rotate_code)).
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Give the room a new code, for new joiners only: nobody already in the
    /// room is dropped. Returns the new code (also from [`code`](Self::code)).
    ///
    /// From the moment this returns, a hello proving the old code is
    /// refused, and so is one already mid-handshake (checked again at the
    /// seat), and the LAN admission token is rotated too, so a beacon heard
    /// before does not admit anyone later. The room answers the new code on
    /// the relays a moment later, on the host's task (the code is stretched,
    /// as at the UTC midnight roll, which this reuses). A room on a
    /// [`Listener`](crate::Listener) never gets a code another room of its app
    /// holds there.
    ///
    /// Refused while a migration session is pinned: its descriptor names the
    /// code.
    pub fn rotate_code(&mut self) -> Result<String, String> {
        if self.shut.load(Ordering::Relaxed) || self.shared.is_retired() {
            return Err("the room is shut down".into());
        }
        if self
            .shared
            .session_policy
            .lock()
            .map(|p| p.is_some())
            .unwrap_or(true)
        {
            return Err("a pinned session keeps its room code".into());
        }
        let old = self.code.clone();
        let install = |new: &str| {
            if let Ok(mut code) = self.shared.code.lock() {
                *code = new.to_string();
                if let Ok(mut t) = self.shared.tokens.lock() {
                    t.code.clear();
                    t.lan = random_token();
                }
            }
        };
        let new = match &self.shared.seat {
            Some(seat) => seat.fresh_code(&self.shared.app_tag, &old, install)?,
            None => {
                let mut new = crate::room::generate_code();
                while new == old {
                    new = crate::room::generate_code();
                }
                install(&new);
                new
            }
        };
        self.code = new.clone();
        let _ = self.cmd_tx.send(Cmd::CodeChanged);
        Ok(new)
    }

    /// Make this room its app's target for listener-level invites
    /// ([`Listener::add_invite`](crate::Listener::add_invite)), or stop it
    /// being one. At most one room per app is the target: setting one clears
    /// the previous. An invite join then lands here, reported as
    /// [`Admission::Invite`]; with no target, invite joins are refused as for
    /// an invite that is not live. The previous target stops admitting those
    /// invites at once (a handshake it had mid-way is refused at the seat);
    /// this room answers them a moment later, on its task. Only for a room on
    /// a listener.
    pub fn set_invite_target(&self, target: bool) -> Result<(), String> {
        match &self.shared.seat {
            Some(seat) => seat.set_target(&self.shared, target),
            None => Err("only a room on a listener takes listener invites".into()),
        }
    }

    /// Whether this room is its app's target for listener-level invites.
    pub fn is_invite_target(&self) -> bool {
        self.shared.seat.as_ref().is_some_and(|s| s.is_target())
    }

    /// The candidates this room announces in its answers, as gathered when it
    /// started listening (the same list the `[host] listening on` log line
    /// prints): the discovered ones, then the configured
    /// [`advertise`](crate::NetConfig::advertise) addresses. Empty until
    /// `Ready`. A room on a [`Listener`](crate::Listener) announces the
    /// listener's.
    pub fn announced(&self) -> Vec<Candidate> {
        self.shared
            .announced
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    pub fn poll(&self) -> Option<HostEvent> {
        let receiver = self.events.lock().ok()?;
        loop {
            let (ev, counter, generation, session_live) = receiver.try_recv().ok()?;
            if let Some((c, len)) = counter {
                c.release(len);
            }
            if generation == self.shared.generation.load(Ordering::Acquire)
                && session_live.is_none_or(|fence| fence.valid(&self.shared))
            {
                return Some(ev);
            }
        }
    }

    /// The LAN admission token currently in the beacon (hex). Needed to dial
    /// the host directly with [`crate::join_addr`].
    pub fn lan_token(&self) -> String {
        self.shared
            .tokens
            .lock()
            .map(|t| hex::encode(t.lan))
            .unwrap_or_default()
    }

    pub fn send_reliable(&self, peer: PeerId, bytes: Bytes) {
        if let Some(l) = self.link(peer) {
            l.send_reliable(bytes);
        }
    }

    pub fn send_lossy(&self, peer: PeerId, bytes: Bytes) {
        if let Some(l) = self.link(peer) {
            l.send_lossy(bytes);
        }
    }

    pub fn broadcast_reliable(&self, bytes: Bytes) {
        let links: Vec<Link> = match self.shared.peers.lock() {
            Ok(p) => p.values().cloned().collect(),
            Err(_) => return,
        };
        for l in links {
            l.send_reliable(bytes.clone());
        }
    }

    /// Disconnect a peer. Emits `PeerLeft{Kicked}`. Its identity key is refused
    /// for the rest of this room's life. Anything already sent to it (a
    /// rejection message, say) gets a moment to flush before the close.
    pub fn kick(&self, peer: PeerId) {
        self.remove_peer(peer, true, close::KICKED, b"kicked");
    }

    /// Disconnect a peer without banning it (e.g. it was refused because the
    /// room was full or a match was running): it may dial back in. Emits
    /// `PeerLeft{Kicked}`.
    pub fn disconnect(&self, peer: PeerId) {
        self.remove_peer(peer, false, close::KICKED, b"kicked");
    }

    /// As [`disconnect`](Self::disconnect) (no ban, the same close code and
    /// flush), but the peer is told why: `reason` is a short plain sentence
    /// meant for the player, cut to at most [`MAX_DISCONNECT_REASON`](crate::MAX_DISCONNECT_REASON) bytes on
    /// a character boundary. Its client sees
    /// `Disconnected(KickedWith(reason))` once the text has been cleaned (see
    /// [`DisconnectReason::KickedWith`](crate::DisconnectReason::KickedWith)); an empty reason, or one that is
    /// nothing but invisible characters, shows as plain `Kicked`. Emits
    /// `PeerLeft{Kicked}`.
    ///
    /// The reason `"kicked"` is what plain `disconnect` sends, so it reads as
    /// plain `Kicked` too.
    ///
    /// Meant for connected players: a close that arrives during the join
    /// handshake shows as `Failed(NotAdmitted)` with no text.
    ///
    /// An older client receiving this close reads it as `Kicked`, so nothing
    /// breaks; a client of this version talking to an older host sees `Kicked`.
    pub fn disconnect_with_reason(&self, peer: PeerId, reason: &str) {
        let cut = crate::cut_reason(reason);
        self.remove_peer(peer, false, close::KICKED, cut.as_bytes());
    }

    /// As [`disconnect`](Self::disconnect), for a joiner that did not confirm
    /// in time: its client sees `Disconnected(ConfirmTimeout)`, not `Kicked`.
    pub fn confirm_timeout(&self, peer: PeerId) {
        self.remove_peer(peer, false, close::CONFIRM_TIMEOUT, b"kicked");
    }

    fn remove_peer(&self, peer: PeerId, ban: bool, code: u32, reason: &[u8]) {
        if let Some(l) = self.shared.detach_peer(peer, ban) {
            let generation = l.generation;
            let reason = Bytes::copy_from_slice(reason);
            crate::runtime().spawn(async move {
                tokio::time::sleep(KICK_FLUSH).await;
                l.conn.close(code.into(), &reason);
            });
            self.shared.emit_at(
                HostEvent::PeerLeft {
                    peer,
                    reason: LeaveReason::Kicked,
                },
                generation,
            );
        }
    }

    /// Open: answer the code on relays, broadcast the LAN beacon, accept new
    /// players. Closed (match running): none of those.
    /// Each change rotates the LAN admission token, so a token heard in an
    /// earlier lobby does not admit anyone later.
    pub fn set_open(&self, open: bool) {
        self.set_open_inner(open, true);
    }

    /// As [`set_open`](Self::set_open), but the LAN admission token stays as
    /// it is. For a game rolling back a failed armed switch: the token it
    /// handed its players (in the switch) still admits them when they dial
    /// back in, although the room closed or reopened since. Use it only for
    /// that rollback window; anywhere else, [`set_open`](Self::set_open)'s
    /// rotation is what keeps a token heard in an earlier lobby from
    /// admitting anyone later.
    pub fn set_open_keeping_token(&self, open: bool) {
        self.set_open_inner(open, false);
    }

    fn set_open_inner(&self, open: bool, rotate: bool) {
        if self
            .shared
            .session_policy
            .lock()
            .map(|p| p.as_ref().is_some_and(|p| p.passive()))
            .unwrap_or(true)
        {
            return;
        }
        if self.shared.open.swap(open, Ordering::Relaxed) != open && rotate {
            self.shared.rotate_lan_token();
        }
        let _ = self.cmd_tx.send(Cmd::SetOpen(open));
    }

    pub fn is_open(&self) -> bool {
        self.shared.open.load(Ordering::Relaxed)
    }

    pub fn peer_count(&self) -> usize {
        self.shared.peers.lock().map(|p| p.len()).unwrap_or(0)
    }

    pub fn rtt_ms(&self, peer: PeerId) -> Option<u32> {
        self.link(peer).map(|l| l.rtt_ms())
    }

    /// `(connected, configured)` relays.
    pub fn relays_connected(&self) -> (usize, usize) {
        (
            self.shared.relays_up.load(Ordering::Relaxed),
            self.shared.relays_total.load(Ordering::Relaxed),
        )
    }

    /// The local QUIC address once listening. With a LAN socket hook this is
    /// the LAN endpoint (the one in the beacon and the LAN candidates).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.shared.local_addr.lock().ok().and_then(|a| *a)
    }

    /// The online endpoint's address (the one STUN, UPnP and IPv6 candidates
    /// name), once listening. It differs from [`local_addr`](Self::local_addr)
    /// only when a LAN socket hook is set: then the host has two endpoints.
    /// Without a hook it is the same address.
    pub fn online_addr(&self) -> Option<SocketAddr> {
        let online = self.shared.online_addr.lock().ok().and_then(|a| *a);
        online.or_else(|| self.local_addr())
    }

    /// Close every connection ("host left"), stop advertising and release the
    /// router mapping. Blocks for at most ~1 s so the close reaches peers.
    pub fn shutdown(self) {
        self.shutdown_inner(Duration::from_millis(1000));
    }

    fn shutdown_inner(&self, wait: Duration) {
        if self.shut.swap(true, Ordering::Relaxed) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        if self.cmd_tx.send(Cmd::Shutdown(tx)).is_ok() {
            let _ = rx.recv_timeout(wait);
        }
    }

    fn link(&self, peer: PeerId) -> Option<Link> {
        self.shared.peers.lock().ok()?.get(&peer).cloned()
    }

    pub(crate) fn shared_arc(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    pub(crate) fn cmd_sender(&self) -> tokio::sync::mpsc::UnboundedSender<Cmd> {
        self.cmd_tx.clone()
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.shutdown_inner(Duration::from_millis(200));
    }
}

pub(crate) struct HostTask {
    pub(crate) cfg: NetConfig,
    pub(crate) room: RoomInfo,
    pub(crate) code: String,
    pub(crate) shared: Arc<Shared>,
    /// Tests pin the UTC day; otherwise it follows the clock.
    pub(crate) fixed_day: Option<u64>,
}

/// Answered offers, keyed by `(session, offer signer)`.
#[derive(Default)]
struct Offers {
    sessions: HashMap<(String, PublicKey), Answered>,
    /// When recent new sessions were answered (rate limit).
    recent: std::collections::VecDeque<Instant>,
}

struct Answered {
    event: nostr::Event,
    accepted: bool,
    last_sent: Instant,
    sends: u32,
    targets: Vec<SocketAddr>,
}

/// What a room answers and punches with: its own endpoint's, or its
/// listener's.
struct Net {
    /// The endpoints this room accepts on itself (none on a listener).
    endpoint: Option<quinn::Endpoint>,
    online_ep: Option<quinn::Endpoint>,
    candidates: Vec<Candidate>,
    announced: Vec<Candidate>,
    punchers: Punchers,
    local: Option<SocketAddr>,
    online: Option<SocketAddr>,
    mapping: Arc<Mutex<Option<crate::nat::upnp::PortMapping>>>,
}

impl HostTask {
    /// Bind and gather (a room of its own), or take the listener's.
    async fn net(&self, relay_present: bool) -> Result<Net, String> {
        // A room on a shared listener takes the listener's; any other binds
        // and owns its own endpoint.
        if let Some(seat) = &self.shared.seat {
            let l = seat
                .listener()
                .ok_or_else(|| "the listener is shut down".to_string())?;
            return Ok(Net {
                endpoint: None,
                online_ep: None,
                candidates: l.candidates.clone(),
                announced: l.announced.clone(),
                punchers: l.punchers.clone(),
                local: l.local,
                online: l.online,
                mapping: Arc::new(Mutex::new(None)),
            });
        }
        let live = self.cfg.checked()?;
        let advertised = self.cfg.advertised()?;
        let only = self.cfg.advertise_only;
        let online = upnp_wanted(relay_present, self.cfg.vpn_active) && !only;
        let prep = prepare_advertising(
            self.cfg.quic_port,
            online,
            self.cfg.stun.clone(),
            self.cfg.lan_socket_hook.clone(),
            Advertise {
                list: advertised,
                only,
            },
        )
        .await?;
        let announced = prep.announced();
        // With a LAN hook there are two endpoints: the LAN one (hooked; its
        // port goes in the LAN candidates and the beacon) and the online one
        // (never hooked; STUN, UPnP and IPv6). Without a hook there is one.
        let (lan_socket, online_socket) = match prep.lan_socket {
            Some(lan) => (lan, Some(prep.socket)),
            None => (prep.socket, None),
        };
        let endpoint = quic::server_endpoint(lan_socket, &self.cfg.app_tag, live)?;
        let online_ep =
            match online_socket.map(|s| quic::server_endpoint(s, &self.cfg.app_tag, live)) {
                Some(Ok(ep)) => Some(ep),
                Some(Err(e)) => return Err(e),
                None => None,
            };
        Ok(Net {
            local: endpoint.local_addr().ok(),
            online: online_ep.as_ref().and_then(|e| e.local_addr().ok()),
            endpoint: Some(endpoint),
            online_ep,
            candidates: prep.candidates,
            announced,
            punchers: Punchers {
                online: Arc::new(prep.punch_socket),
                lan: prep.lan_punch_socket.map(Arc::new),
            },
            mapping: Arc::new(Mutex::new(prep.mapping)),
        })
    }

    pub(crate) async fn run(
        mut self,
        relay: Option<Box<dyn RendezvousRelay>>,
        mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    ) {
        if let Err(e) = self.cfg.checked().and_then(|_| self.cfg.advertised()) {
            self.shared.fail_start(e);
            return;
        }
        let only = self.cfg.advertise_only;
        let net = match self.net(relay.is_some()).await {
            Ok(n) => n,
            Err(e) => {
                self.shared.fail_start(e);
                return;
            }
        };
        let Net {
            endpoint,
            online_ep,
            candidates,
            announced,
            punchers,
            local,
            online,
            mapping,
        } = net;
        if let Ok(mut a) = self.shared.local_addr.lock() {
            *a = local;
        }
        if let Ok(mut a) = self.shared.online_addr.lock() {
            *a = online;
        }
        if let Ok(mut a) = self.shared.announced.lock() {
            *a = announced.clone();
        }
        self.code = self.shared.current_code();
        log::info!(
            "[host] listening on {local:?} (online {:?}), code {}, candidates {:?}",
            online,
            self.code,
            announced
        );

        // Listen on today's and yesterday's room tag (a joiner whose clock has
        // already passed midnight, or a room opened before midnight). Only an
        // online host pays for the derivation.
        let mut day = self.today();
        // `code_secrets` is the code's; `invite_rooms` each live invite's;
        // `secrets` is all of them, which is what offers are matched against.
        let mut code_secrets: Vec<RoomSecrets> = Vec::new();
        let mut invite_rooms: HashMap<InviteId, Vec<RoomSecrets>> = HashMap::new();
        if relay.is_some() {
            // A rotation while this ran is caught by its `CodeChanged`.
            code_secrets = match self.derive_code(day).await {
                // Only the room's current code is answered.
                Ok((code, s)) if self.install_code(&code, &s) => s,
                Ok(_) => Vec::new(),
                Err(e) => {
                    self.shared.fail_start(e);
                    return;
                }
            };
        } else {
            self.set_code_tokens(&code_secrets);
        }
        if relay.is_some() {
            self.sync_invites(&mut invite_rooms, day);
        }
        let mut secrets = all_rooms(&code_secrets, &invite_rooms);
        let mut filter = offer_filter(&secrets);
        // Before an offer takes a relay queue slot it must open with one of
        // our current room keys; anything else is junk.
        let accept_keys: Arc<Mutex<Vec<RoomSecrets>>> = Arc::new(Mutex::new(secrets.clone()));
        if let Some(r) = &relay {
            let k = Arc::clone(&accept_keys);
            r.set_accept(Some(Arc::new(move |ev: &nostr::Event| {
                let Ok(rooms) = k.lock() else { return false };
                room_for(ev, &rooms)
                    .is_some_and(|room| open_offer(&room.keys, ev, crate::unix_now()).is_ok())
            })));
            let _ = r.subscribe(filter.clone());
        }
        let mut last_upnp_check = Instant::now();
        self.code = self.shared.current_code();
        if self.shared.seat.is_some() && self.shared.is_retired() {
            // Closed while starting (the listener went, or the handle did):
            // no `Ready`, and the loop below would only close what is closed.
            return;
        }
        self.shared.emit_start(HostEvent::Ready {
            code: self.code.clone(),
        });

        let mut beacon = BeaconSender::new(self.cfg.lan_port, self.cfg.lan_socket_hook.as_ref());
        let mut last_beacon = Instant::now() - BEACON_EVERY;
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seen: HashSet<nostr::EventId> = HashSet::new();
        let mut offers = Offers::default();
        let mut done: Option<mpsc::Sender<()>> = None;
        let mut by_listener = false;

        loop {
            tokio::select! {
                incoming = async {
                    match &endpoint {
                        Some(ep) => ep.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let Some(incoming) = incoming else { break };
                    // The hooked LAN endpoint answers around the VPN, so it
                    // serves local sources only; the online endpoint takes
                    // anyone. (Without a hook there is one endpoint, as before.)
                    if online_ep.is_some() && !self.lan_source_ok(incoming.remote_address()) {
                        log::info!("[host] ignoring a non-local source on the LAN endpoint: {}", incoming.remote_address());
                        incoming.ignore();
                        continue;
                    }
                    tokio::spawn(accept_peer(incoming, Arc::clone(&self.shared)));
                }
                incoming = async {
                    match &online_ep {
                        Some(ep) => ep.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let Some(incoming) = incoming else { break };
                    tokio::spawn(accept_peer(incoming, Arc::clone(&self.shared)));
                }
                cmd = cmd_rx.recv() => match cmd {
                    Some(Cmd::InvitesChanged) => {
                        if let Some(r) = &relay {
                            self.sync_invites(&mut invite_rooms, day);
                            secrets = all_rooms(&code_secrets, &invite_rooms);
                            if let Ok(mut k) = accept_keys.lock() {
                                *k = secrets.clone();
                            }
                            filter = offer_filter(&secrets);
                            if self.is_open() {
                                let _ = r.subscribe(filter.clone());
                            }
                        }
                    }
                    Some(Cmd::CodeChanged) => {
                        // The handle already stripped the old code's tokens.
                        if let Some(r) = &relay {
                            match self.derive_code(day).await {
                                Ok((code, s)) => {
                                    // A later rotation sent its own
                                    // `CodeChanged`: only the current code
                                    // is installed.
                                    if self.install_code(&code, &s) {
                                        code_secrets = s;
                                        secrets = all_rooms(&code_secrets, &invite_rooms);
                                        if let Ok(mut k) = accept_keys.lock() {
                                            *k = secrets.clone();
                                        }
                                        filter = offer_filter(&secrets);
                                        if self.is_open() {
                                            let _ = r.subscribe(filter.clone());
                                        }
                                        log::info!("[host] room code changed");
                                    }
                                }
                                Err(e) => log::warn!("[host] new code: {e}"),
                            }
                        }
                        self.code = self.shared.current_code();
                    }
                    Some(Cmd::SetOpen(open)) => {
                        if let Some(r) = &relay {
                            let _ = if open { r.subscribe(filter.clone()) } else { r.unsubscribe() };
                        }
                        if open {
                            last_beacon = Instant::now() - BEACON_EVERY;
                        }
                    }
                    Some(Cmd::Shutdown(tx)) => { done = Some(tx); break; }
                    Some(Cmd::ListenerShutdown(tx)) => { done = Some(tx); by_listener = true; break; }
                    None => break,
                },
                _ = tick.tick() => {
                    let open = self.is_open();
                    if let Some(r) = &relay {
                        let now_day = self.today();
                        if now_day > day {
                            // Midnight UTC: roll to the new today + yesterday.
                            match self.derive_code(now_day).await {
                                Ok((code, s)) => {
                                    day = now_day;
                                    // A rotation meanwhile leaves the old
                                    // code's tokens out; its own
                                    // `CodeChanged` derives the new one.
                                    if self.install_code(&code, &s) {
                                        code_secrets = s;
                                    } else {
                                        code_secrets.clear();
                                    }
                                    // The invites roll with the code.
                                    invite_rooms.clear();
                                    self.sync_invites(&mut invite_rooms, day);
                                    secrets = all_rooms(&code_secrets, &invite_rooms);
                                    if let Ok(mut k) = accept_keys.lock() {
                                        *k = secrets.clone();
                                    }
                                    filter = offer_filter(&secrets);
                                    if open {
                                        let _ = r.subscribe(filter.clone());
                                    }
                                    log::info!("[host] rolled room tags to day {day}");
                                }
                                Err(e) => log::warn!("[host] day roll: {e}"),
                            }
                        }
                        let (up, total) = r.connected();
                        self.shared.relays_up.store(up, Ordering::Relaxed);
                        self.shared.relays_total.store(total, Ordering::Relaxed);
                        while let Some(ev) = r.try_recv() {
                            if seen.len() > 4096 { seen.clear(); }
                            if !seen.insert(ev.id) { continue; }
                            self.on_offer(&ev, &secrets, r.as_ref(), &candidates, &mut offers, &punchers, open);
                        }
                    }
                    // An advertise-only host announces nothing it discovered: no beacon.
                    if open && !only && last_beacon.elapsed() >= BEACON_EVERY {
                        last_beacon = Instant::now();
                        if let Some(local) = local {
                            let players = usize::from(self.cfg.host_has_player)
                                + self.shared.peers.lock().map(|p| p.len()).unwrap_or(0);
                            // The beacon is IPv4 broadcast; never advertise
                            // the dual-stack socket's `::` wildcard in it.
                            let host_ip = crate::nat::candidates::local_outbound_v4()
                                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)
                                .into();
                            beacon.send(&Beacon {
                                v: NET_PROTOCOL_VERSION,
                                app: self.cfg.app_tag.clone(),
                                name: self.room.name.clone(),
                                code: self.code.clone(),
                                player_count: players.min(255) as u8,
                                max_players: self.room.max_players,
                                addr: SocketAddr::new(host_ip, local.port()).to_string(),
                                port: local.port(),
                                token: self.shared.tokens.lock().map(|t| hex::encode(t.lan)).unwrap_or_default(),
                            });
                        }
                    }
                    offers.sessions.retain(|_, a| a.last_sent.elapsed() < Duration::from_secs(300));
                    if last_upnp_check.elapsed() >= UPNP_RENEW_CHECK {
                        // Keep the router mapping alive (it only renews when due).
                        last_upnp_check = Instant::now();
                        let m = Arc::clone(&mapping);
                        tokio::task::spawn_blocking(move || {
                            if let Ok(mut g) = m.lock() {
                                if let Some(pm) = g.as_mut() {
                                    if let Err(e) = pm.renew(Instant::now()) {
                                        log::info!("[nat] router mapping renew failed: {e}");
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }

        // Shutdown: tell every peer the host left, then let the closes flush.
        // A room on a listener leaves it first, so no handshake still running
        // is seated after the close.
        self.shared.retire();
        self.shared.close_all(close::HOST_SHUTDOWN, b"host left");
        if by_listener {
            self.shared.tell_listener_closed();
        }
        if let Some(ep) = &endpoint {
            ep.close(close::HOST_SHUTDOWN.into(), b"host left");
        }
        if let Some(ep) = &online_ep {
            ep.close(close::HOST_SHUTDOWN.into(), b"host left");
        }
        // The router mapping comes off while the closes flush; both endpoints
        // share one 500 ms budget.
        let removal = mapping
            .lock()
            .ok()
            .and_then(|mut g| g.take())
            .map(|m| tokio::task::spawn_blocking(move || m.remove()));
        let idle = async {
            tokio::join!(
                async {
                    if let Some(ep) = &endpoint {
                        ep.wait_idle().await;
                    }
                },
                async {
                    if let Some(ep) = &online_ep {
                        ep.wait_idle().await;
                    }
                }
            );
        };
        let _ = tokio::time::timeout(Duration::from_millis(500), idle).await;
        if let Some(r) = &relay {
            let _ = r.unsubscribe();
        }
        drop(relay);
        if let Some(removal) = removal {
            let _ = removal.await;
        }
        if let Some(tx) = done {
            let _ = tx.send(());
        }
        log::info!("[host] stopped");
    }

    /// Whether the LAN endpoint serves a connection from `remote`.
    fn lan_source_ok(&self, remote: SocketAddr) -> bool {
        let ip = crate::nat::addr::canonical(remote).ip();
        #[cfg(test)]
        if ip.is_loopback() && !self.cfg.lan_allow_loopback {
            return false;
        }
        crate::nat::candidates::is_lan_ip(ip)
    }

    /// The UTC day the host's room tags are for (tests pin or move it).
    fn today(&self) -> u64 {
        #[cfg(test)]
        {
            let moved = self.shared.test_day.load(Ordering::Relaxed);
            if moved != 0 {
                return moved;
            }
        }
        self.fixed_day.unwrap_or_else(utc_today)
    }

    /// Whether offers are being answered now: the room is open and not a
    /// passive standby.
    fn is_open(&self) -> bool {
        self.shared.open.load(Ordering::Relaxed)
            && !self
                .shared
                .session_policy
                .lock()
                .map(|p| p.as_ref().is_some_and(|p| p.passive()))
                .unwrap_or(true)
    }

    /// Bring `rooms` (each live invite's secrets for `day` and `day - 1`) in
    /// line with the invites the handle holds, and install their admission
    /// tokens. Derives only the invites not yet in `rooms`; the caller clears
    /// it when the day rolls. Done under the invite lock, so an invite
    /// removed meanwhile is not resurrected.
    fn sync_invites(&self, rooms: &mut HashMap<InviteId, Vec<RoomSecrets>>, day: u64) {
        match &self.shared.seat {
            // The listener's invites, while this room is its app's target;
            // the listener's lock is held throughout (taken before the room's).
            Some(seat) => seat.with_target_invites(&self.cfg.app_tag, |keep| {
                self.sync_invites_with(rooms, day, keep)
            }),
            None => self.sync_invites_with(rooms, day, &HashMap::new()),
        }
    }

    /// [`Self::sync_invites`], with `keep` the listener-level invites this
    /// room answers (empty unless it is its app's invite target).
    fn sync_invites_with(
        &self,
        rooms: &mut HashMap<InviteId, Vec<RoomSecrets>>,
        day: u64,
        keep: &HashMap<InviteId, [u8; 32]>,
    ) {
        let Ok(live) = self.shared.invites.lock() else {
            return;
        };
        rooms.retain(|id, _| live.contains_key(id) || keep.contains_key(id));
        for (id, secret) in live.iter().chain(keep.iter()) {
            if rooms.contains_key(id) {
                continue;
            }
            match derive_invite_days(&self.cfg.app_tag, secret, day) {
                Ok(r) => {
                    rooms.insert(*id, r);
                }
                Err(e) => log::warn!("[host] invite {id}: {e}"),
            }
        }
        if let Ok(mut t) = self.shared.tokens.lock() {
            let tokens = |of: &dyn Fn(&InviteId) -> bool| -> Vec<(InviteId, [u8; 32])> {
                rooms
                    .iter()
                    .filter(|(id, _)| of(id))
                    .flat_map(|(id, rs)| rs.iter().map(move |r| (*id, r.admit)))
                    .collect()
            };
            t.invites = tokens(&|id| live.contains_key(id));
            t.keep_invites = tokens(&|id| keep.contains_key(id));
        }
    }

    /// The current code's secrets for `day` and the day before, with the
    /// code they were derived for.
    async fn derive_code(&self, day: u64) -> Result<(String, Vec<RoomSecrets>), String> {
        let code = self.shared.current_code();
        let secrets = derive_days(&self.cfg.app_tag, &code, day).await?;
        Ok((code, secrets))
    }

    /// Install `secrets`' admission tokens if `code` is still the room's
    /// code (a rotation meanwhile wins). Whether they were installed.
    fn install_code(&self, code: &str, secrets: &[RoomSecrets]) -> bool {
        let Ok(current) = self.shared.code.lock() else {
            return false;
        };
        if *current != code {
            return false;
        }
        self.set_code_tokens(secrets);
        true
    }

    fn set_code_tokens(&self, secrets: &[RoomSecrets]) {
        if let Ok(mut t) = self.shared.tokens.lock() {
            t.code = secrets.iter().map(|s| s.admit).collect();
        }
    }

    /// Punch towards the addresses a joiner offered. An advertise-only host
    /// sends none: every packet it started would leave by the default route
    /// (not the forward or tunnel it announces), and the joiner dials the
    /// advertised addresses anyway.
    fn punch(&self, punchers: &Punchers, targets: Vec<SocketAddr>, session: String) {
        if !self.cfg.advertise_only {
            punchers.send(targets, session);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_offer(
        &self,
        ev: &nostr::Event,
        secrets: &[RoomSecrets],
        relay: &dyn RendezvousRelay,
        my_candidates: &[Candidate],
        offers: &mut Offers,
        punchers: &Punchers,
        open: bool,
    ) {
        // Pinned rooms stop all accepted reanswers at the commit/arming fence,
        // including a cached offer which ordinary discovery would retransmit.
        if !open
            && self
                .shared
                .session_policy
                .lock()
                .map(|p| p.is_some())
                .unwrap_or(true)
        {
            return;
        }
        let now = crate::unix_now();
        // The offer's `#t` names the day it was derived for; open it with that key.
        let Some(room) = room_for(ev, secrets) else {
            log::debug!("[host] ignoring an offer for an unknown tag");
            return;
        };
        let offer = match open_offer(&room.keys, ev, now) {
            Ok(o) => o,
            Err(e) => {
                log::info!("[host] ignoring an offer: {e:?}");
                return;
            }
        };
        let key = (offer.session.clone(), ev.pubkey);
        // A re-sent offer: the joiner may have missed our answer. Re-send it.
        if let Some(a) = offers.sessions.get_mut(&key) {
            if a.last_sent.elapsed() >= REANSWER_EVERY && a.sends < 12 {
                a.last_sent = Instant::now();
                a.sends += 1;
                let _ = relay.publish(&a.event);
                if a.accepted {
                    self.punch(punchers, a.targets.clone(), offer.session.clone());
                }
            }
            return;
        }
        // Rate-limit new sessions: each one costs an answer and punches.
        offers.recent.retain(|t| t.elapsed() < NEW_SESSION_WINDOW);
        if offers.recent.len() >= MAX_NEW_SESSIONS {
            log::debug!("[host] too many new join sessions; ignoring an offer");
            return;
        }
        offers.recent.push_back(Instant::now());
        let full = self.shared.peers.lock().map(|p| p.len()).unwrap_or(0) >= self.shared.max_peers;
        let refusal = if offer.v != NET_PROTOCOL_VERSION {
            Some("version")
        } else if !open {
            Some("closed")
        } else if full {
            Some("full")
        } else {
            None
        };
        let answer = Answer {
            v: NET_PROTOCOL_VERSION,
            session: offer.session.clone(),
            accepted: refusal.is_none(),
            reason: refusal.map(str::to_string),
            candidates: if refusal.is_none() {
                current_candidates(
                    my_candidates,
                    &self.cfg.advertised().unwrap_or_default(),
                    self.cfg.advertise_only,
                    &punchers.online,
                )
            } else {
                Vec::new()
            },
            sent_at: now,
            // Inside the ciphertext only: the joiner requires the welcome to be
            // signed by this key (review-net-1 N1).
            host_pubkey: self.shared.host_keys.public_key().to_hex(),
        };
        // Signed with a throwaway key made for this one session, never the
        // host identity and never a key shared with another room, day or
        // joiner: observers cannot tell from the author that two answers
        // came from the same host. The welcome names this key.
        let answer_keys = Keys::generate();
        let Ok(event) = seal_answer(&answer_keys, &ev.pubkey, &answer) else {
            return;
        };
        if refusal.is_none() {
            // Before it goes out: the joiner dials only after it has the answer.
            self.shared
                .record_answer_key(&offer.session, answer_keys.public_key());
        }
        let _ = relay.publish(&event);
        let targets = punch_targets(&offer.candidates);
        log::info!(
            "[host] answered offer {} ({}), punch targets {targets:?}",
            offer.session.get(..8).unwrap_or("?"),
            refusal.unwrap_or("accepted")
        );
        if refusal.is_none() {
            self.punch(punchers, targets.clone(), offer.session.clone());
        }
        while offers.sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = offers
                .sessions
                .iter()
                .min_by_key(|(_, a)| a.last_sent)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            offers.sessions.remove(&oldest);
        }
        offers.sessions.insert(
            key,
            Answered {
                event,
                accepted: refusal.is_none(),
                last_sent: Instant::now(),
                sends: 1,
                targets,
            },
        );
    }
}

/// Every room the host answers: the code's, then each invite's.
fn all_rooms(
    code: &[RoomSecrets],
    invites: &HashMap<InviteId, Vec<RoomSecrets>>,
) -> Vec<RoomSecrets> {
    code.iter()
        .chain(invites.values().flatten())
        .cloned()
        .collect()
}

/// The room secrets an offer's `#t` tag names, if it is one of ours.
fn room_for<'a>(ev: &nostr::Event, secrets: &'a [RoomSecrets]) -> Option<&'a RoomSecrets> {
    let letter = ROOM_TAG_LETTER.to_string();
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.len() >= 2 && s[0] == letter)
            .then(|| secrets.iter().find(|r| r.tag == s[1]))
            .flatten()
    })
}

/// The offer subscription for the current room tags.
fn offer_filter(secrets: &[RoomSecrets]) -> TagFilter {
    TagFilter {
        kind: KIND_JOIN_OFFER,
        letter: ROOM_TAG_LETTER,
        values: secrets.iter().map(|s| s.tag.clone()).collect(),
    }
}

/// The candidates to put in an answer now: those gathered at start, with the
/// `v6` entry re-read from the kernel (review-ipv6-1 I3), so a temporary
/// address that rotated while the room was open is not advertised stale; then
/// the configured `advertised` ones. An advertise-only host re-reads nothing:
/// the kernel's address is not one it was told to announce.
pub(crate) fn current_candidates(
    gathered: &[Candidate],
    advertised: &[Candidate],
    advertise_only: bool,
    socket: &UdpSocket,
) -> Vec<Candidate> {
    let base = match socket.local_addr() {
        _ if advertise_only => Vec::new(),
        Ok(local) if local.is_ipv6() => crate::nat::candidates::refresh_v6(
            gathered,
            crate::nat::candidates::local_outbound_v6(),
            local.port(),
        ),
        _ => gathered.to_vec(),
    };
    crate::nat::candidates::append_advertised(base, advertised)
}

/// Clones of the QUIC sockets that send punches. Targets on the local network
/// go out of the LAN endpoint's socket (hooked, so a VPN doesn't swallow them);
/// everything else goes out of the online one, over the phone's normal route.
#[derive(Clone)]
pub(crate) struct Punchers {
    pub(crate) online: Arc<UdpSocket>,
    /// Present only with a LAN socket hook (two endpoints).
    pub(crate) lan: Option<Arc<UdpSocket>>,
}

impl Punchers {
    /// Which socket each target is punched from: local ranges (private,
    /// link-local, ULA; see [`crate::nat::candidates::is_lan_ip`]) out of the
    /// LAN socket, everything else (public v4, v6, CGNAT) out of the online
    /// one. Without a LAN socket everything goes out of the online one.
    pub(crate) fn route(&self, targets: Vec<SocketAddr>) -> Vec<(Arc<UdpSocket>, Vec<SocketAddr>)> {
        let (local, remote): (Vec<SocketAddr>, Vec<SocketAddr>) = match &self.lan {
            Some(_) => targets.into_iter().partition(|a| is_local_target(*a)),
            None => (Vec::new(), targets),
        };
        let mut out = vec![(Arc::clone(&self.online), remote)];
        if let Some(lan) = &self.lan {
            out.push((Arc::clone(lan), local));
        }
        out.retain(|(_, t)| !t.is_empty());
        out
    }

    fn send(&self, targets: Vec<SocketAddr>, session: String) {
        for (socket, targets) in self.route(targets) {
            let session = session.clone();
            tokio::task::spawn_blocking(move || {
                crate::nat::punch::send_punches(&socket, &targets, &session)
            });
        }
    }
}

/// Whether `addr` is on the local network rather than the internet.
fn is_local_target(addr: SocketAddr) -> bool {
    crate::nat::candidates::is_lan_ip(crate::nat::addr::canonical(addr).ip())
}

pub(crate) struct Prepared {
    /// The online socket: STUN, UPnP and IPv6 candidates are gathered on it,
    /// and it is never run through the LAN hook. Without a hook it is also
    /// the only socket.
    pub socket: UdpSocket,
    pub punch_socket: UdpSocket,
    /// With a LAN hook: a second socket, bound through the hook, that serves
    /// local peers (LAN candidates and the beacon's port).
    pub lan_socket: Option<UdpSocket>,
    pub lan_punch_socket: Option<UdpSocket>,
    /// What was gathered (nothing for an advertise-only host).
    pub candidates: Vec<Candidate>,
    /// The configured addresses to announce after them (already checked).
    pub advertised: Vec<Candidate>,
    pub mapping: Option<crate::nat::upnp::PortMapping>,
    /// Whether a router mapping was asked for (see [`upnp_wanted`]).
    #[cfg_attr(not(test), allow(dead_code))]
    pub upnp_attempted: bool,
}

impl Prepared {
    /// What the first answer carries: the gathered candidates, then the
    /// advertised ones.
    pub fn announced(&self) -> Vec<Candidate> {
        crate::nat::candidates::append_advertised(self.candidates.clone(), &self.advertised)
    }
}

/// The addresses a host was told to announce ([`crate::NetConfig::advertise`]),
/// already checked by [`crate::NetConfig::advertised`].
#[derive(Default)]
pub(crate) struct Advertise {
    pub list: Vec<Candidate>,
    /// Gather nothing: announce `list` alone.
    pub only: bool,
}

/// An IPv6 address to announce needs a socket that can answer it: `serving`
/// is the socket whose port the advertised addresses name.
pub(crate) fn check_advertise_family(
    serving: SocketAddr,
    advertised: &[Candidate],
) -> Result<(), String> {
    if serving.is_ipv6() {
        return Ok(());
    }
    match advertised.iter().find(|c| {
        c.addr
            .parse::<SocketAddr>()
            .map(|a| a.is_ipv6())
            .unwrap_or(false)
    }) {
        Some(c) => Err(format!(
            "advertise {}: the UDP socket is IPv4-only, so it cannot answer IPv6",
            c.addr
        )),
        None => Ok(()),
    }
}

/// Whether to ask the router for a port mapping: an online host, and no VPN
/// carrying its traffic (the mapping would advertise the home router's real
/// address while the VPN carries the traffic).
pub(crate) fn upnp_wanted(online: bool, vpn_active: bool) -> bool {
    online && !vpn_active
}

/// Bind the QUIC socket(s) (dual-stack `[::]`, or `0.0.0.0` if that fails) and
/// gather candidates on them (before quinn owns them). UPnP is asked for only
/// when `upnp` (an online host).
///
/// With no `lan_hook` there is one socket, hooked to nothing, that carries
/// every candidate (the joiner's room-code path, and desktops). With a hook
/// there are two: `lan_socket` binds `port` and goes through the hook, and
/// carries only the LAN candidate; `socket` binds an ephemeral port, is never
/// hooked, and carries STUN, UPnP and IPv6. So a phone on a VPN sends its
/// internet traffic through the VPN and only local traffic around it.
pub(crate) async fn prepare(
    port: u16,
    upnp: bool,
    stun: Vec<String>,
    lan_hook: Option<crate::LanSocketHook>,
) -> Result<Prepared, String> {
    prepare_advertising(port, upnp, stun, lan_hook, Advertise::default()).await
}

/// [`prepare`] for a host with configured addresses to announce. With
/// `advertise.only` nothing is gathered: no STUN, no UPnP mapping, no LAN or
/// IPv6 lookup. The sockets bind the same ports either way.
pub(crate) async fn prepare_advertising(
    port: u16,
    upnp: bool,
    stun: Vec<String>,
    lan_hook: Option<crate::LanSocketHook>,
    advertise: Advertise,
) -> Result<Prepared, String> {
    let upnp = upnp && !advertise.only;
    tokio::task::spawn_blocking(move || {
        let split = lan_hook.is_some();
        // The online socket (the only one without a hook).
        let online_port = if split { 0 } else { port };
        let socket = crate::nat::addr::bind_dual_stack(online_port)
            .map_err(|e| format!("could not bind UDP port {online_port}: {e}"))?;
        let local = socket
            .local_addr()
            .map_err(|e| format!("socket has no address: {e}"))?;
        // With a hook the LAN socket binds `port` and serves the advertised
        // addresses, so it is bound now, before anything is gathered or
        // mapped. Local joiners dial it, and it must answer them on the local
        // network, so it is bound there before anything is sent from it.
        // Nothing else is ever sent from it: no STUN, no UPnP.
        let lan_bound = if split {
            let lan = crate::nat::addr::bind_dual_stack(port)
                .map_err(|e| format!("could not bind UDP port {port}: {e}"))?;
            let _ = crate::netbind::bind_lan(lan_hook.as_ref(), &lan);
            let lan_local = lan
                .local_addr()
                .map_err(|e| format!("socket has no address: {e}"))?;
            Some((lan, lan_local))
        } else {
            None
        };
        check_advertise_family(
            lan_bound.as_ref().map_or(local, |(_, l)| *l),
            &advertise.list,
        )?;
        let mapping_thread = upnp.then(|| {
            std::thread::spawn(move || {
                let v4 = crate::nat::candidates::local_outbound_v4()?;
                let internal = SocketAddr::new(std::net::IpAddr::V4(v4), local.port());
                crate::nat::upnp::map_port(internal, crate::nat::upnp::SEARCH_TIMEOUT)
                    .map_err(|e| log::info!("[nat] no router mapping: {e}"))
                    .ok()
            })
        });
        let mut candidates = if advertise.only {
            Vec::new()
        } else {
            gather(&socket, None, &stun, Duration::from_secs(1))
        };
        let mapping = mapping_thread.and_then(|h| h.join().ok().flatten());
        if let Some(m) = &mapping {
            candidates.push(Candidate {
                kind: "upnp".into(),
                addr: m.external_addr().to_string(),
            });
            candidates = crate::nat::candidates::sort_candidates(candidates);
        }
        // An IPv4-only socket (the dual-stack bind fell back) could never
        // answer an IPv6 candidate.
        if !local.is_ipv6() {
            candidates.retain(|c| {
                c.addr
                    .parse::<SocketAddr>()
                    .map(|a| a.is_ipv4())
                    .unwrap_or(false)
            });
        }
        let punch_socket = socket
            .try_clone()
            .map_err(|e| format!("socket clone: {e}"))?;
        // gather() leaves a read timeout on the socket; quinn wants it clean.
        let _ = socket.set_read_timeout(None);

        let (mut lan_socket, mut lan_punch_socket) = (None, None);
        if let Some((lan, lan_local)) = lan_bound {
            // Its own gather names only itself (no STUN servers, no UPnP);
            // of that, only the LAN candidate is used.
            let mut lan_candidates: Vec<Candidate> = if advertise.only {
                Vec::new()
            } else {
                gather(&lan, None, &[], Duration::from_millis(1))
                    .into_iter()
                    .filter(|c| c.kind == crate::nat::candidates::CandidateKind::Lan.as_str())
                    .collect()
            };
            if !lan_local.is_ipv6() {
                lan_candidates.retain(|c| {
                    c.addr
                        .parse::<SocketAddr>()
                        .map(|a| a.is_ipv4())
                        .unwrap_or(false)
                });
            }
            // The online socket's own "lan" entry carries the wrong port.
            candidates.retain(|c| c.kind != crate::nat::candidates::CandidateKind::Lan.as_str());
            // A LAN candidate names a private or link-local address only: a
            // network that hands the phone a public address must not have it
            // advertised for a socket that bypasses the VPN.
            lan_candidates.retain(|c| {
                c.addr
                    .parse::<SocketAddr>()
                    .map(|a| crate::nat::candidates::is_lan_ip(crate::nat::addr::canonical(a).ip()))
                    .unwrap_or(false)
            });
            candidates.extend(lan_candidates);
            candidates = crate::nat::candidates::sort_candidates(candidates);
            lan_punch_socket = Some(lan.try_clone().map_err(|e| format!("socket clone: {e}"))?);
            let _ = lan.set_read_timeout(None);
            lan_socket = Some(lan);
        }
        Ok(Prepared {
            socket,
            punch_socket,
            lan_socket,
            lan_punch_socket,
            candidates,
            advertised: advertise.list,
            mapping,
            upnp_attempted: upnp,
        })
    })
    .await
    .map_err(|e| format!("prepare task: {e}"))?
}

/// Removes a half-set-up peer if `accept_peer` unwinds (a panic must not leave
/// a ghost link holding a seat).
struct PeerGuard {
    shared: Arc<Shared>,
    peer: PeerId,
    conn: quinn::Connection,
    armed: bool,
    /// `PeerJoined` went out, so a leave must be reported.
    announced: bool,
    generation: u64,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let removed = self.shared.detach_peer(self.peer, false).is_some();
        if removed {
            self.conn.close(close::LEAVE.into(), b"internal error");
        }
        if removed && self.announced {
            self.shared.emit_at(
                HostEvent::PeerLeft {
                    peer: self.peer,
                    reason: LeaveReason::Error("internal error".into()),
                },
                self.generation,
            );
        }
    }
}

/// Why a seat can't be given right now, if it can't.
fn seat_refusal(shared: &Shared, peers: &HashMap<PeerId, Link>) -> Option<u32> {
    let session = match shared.session_policy.lock() {
        Ok(p) => p.clone(),
        Err(_) => return Some(close::CLOSED),
    };
    let capacity = if session.as_ref().is_some_and(|p| p.passive()) {
        9
    } else {
        shared.max_peers
    };
    if shared.retired.load(Ordering::Acquire) {
        Some(close::HOST_SHUTDOWN)
    } else if session.is_none() && !shared.open.load(Ordering::Relaxed) {
        Some(close::CLOSED)
    } else if peers.len() >= capacity {
        Some(close::FULL)
    } else {
        None
    }
}

/// One incoming connection: handshake, admit or refuse, then pump until it ends.
///
/// The handshake (see `quic`) runs in this order, all within
/// `HANDSHAKE_TIMEOUT` (`SESSION_HANDSHAKE_DEADLINE` once pinned, timed from
/// accept, so a stalled peer frees its slot): the hello must prove admission before the joiner
/// learns anything about this host; only then is the welcome sent; the joiner
/// says who it is only after verifying that welcome, and is checked against
/// the kick deny-list and seated only then.
pub(crate) async fn accept_peer(incoming: quinn::Incoming, shared: Arc<Shared>) {
    accept_arriving(Arriving::Incoming(incoming), shared).await
}

/// A connection on its way to a room's seat.
#[allow(clippy::large_enum_variant)] // short-lived, one per connection
pub(crate) enum Arriving {
    /// Straight off the room's own endpoint: not yet accepted.
    Incoming(quinn::Incoming),
    /// Accepted by a shared listener, which read the hello to find the room
    /// whose tokens it proves. The room checks it again, as its own.
    Demuxed {
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        hello: Box<quic::Hello>,
        /// When the listener accepted it: the handshake deadline runs from here.
        started: tokio::time::Instant,
    },
}

impl Arriving {
    fn remote(&self) -> SocketAddr {
        match self {
            Arriving::Incoming(i) => i.remote_address(),
            Arriving::Demuxed { conn, .. } => conn.remote_address(),
        }
    }

    /// Turn it away before any handshake work for this room.
    fn refuse(self, code: u32) {
        match self {
            Arriving::Incoming(i) => i.refuse(),
            Arriving::Demuxed { conn, .. } => conn.close(code.into(), b"refused"),
        }
    }
}

/// [`accept_peer`] for a connection from either source.
pub(crate) async fn accept_arriving(arriving: Arriving, shared: Arc<Shared>) {
    struct PendingSlot(Arc<Shared>);
    impl Drop for PendingSlot {
        fn drop(&mut self) {
            self.0.pending_handshakes.fetch_sub(1, Ordering::AcqRel);
        }
    }
    // Register every handshake in the same lock order as pin_session. A pin
    // cannot leave ordinary-generation handshakes running outside its limits:
    // it closes them (`preempted` below).
    let (policy, generation, slot, mut generation_rx) = {
        let Ok(_peers) = shared.peers.lock() else {
            arriving.refuse(close::CLOSED);
            return;
        };
        let policy = match shared.session_policy.lock() {
            Ok(p) => p.clone(),
            Err(_) => {
                arriving.refuse(close::CLOSED);
                return;
            }
        };
        let count = shared.pending_handshakes.fetch_add(1, Ordering::AcqRel);
        if policy.is_some() && count >= 2 {
            shared.pending_handshakes.fetch_sub(1, Ordering::AcqRel);
            arriving.refuse(close::FULL);
            return;
        }
        (
            policy,
            shared.generation.load(Ordering::Acquire),
            PendingSlot(shared.clone()),
            shared.generation_tx.subscribe(),
        )
    };
    // The accepted connection, so a pin can close a pending ordinary
    // handshake with a code (dropping it would close it without one).
    let accepted: Mutex<Option<quinn::Connection>> = Mutex::new(None);
    // Shown as IPv4 when the joiner is IPv4 (it arrives v4-mapped).
    let remote = crate::nat::addr::canonical(arriving.remote());
    let started = match &arriving {
        Arriving::Demuxed { started, .. } => *started,
        Arriving::Incoming(_) => tokio::time::Instant::now(),
    };
    let setup = async {
        let refuse = |conn: &quinn::Connection, code: u32, why: String| {
            conn.close(code.into(), why.as_bytes());
            Err(why)
        };
        let (conn, mut send, mut recv, hello) = match arriving {
            Arriving::Incoming(incoming) => {
                let conn = incoming
                    .accept()
                    .map_err(|e| quic::connection_error_text(&e))?
                    .await
                    .map_err(|e| quic::connection_error_text(&e))?;
                if let Ok(mut accepted) = accepted.lock() {
                    *accepted = Some(conn.clone());
                }
                match quic::server_read_hello(&conn).await {
                    Ok((send, recv, hello)) => (conn, send, recv, hello),
                    Err((code, why)) => return refuse(&conn, code, why),
                }
            }
            Arriving::Demuxed {
                conn,
                send,
                recv,
                hello,
                ..
            } => {
                if let Ok(mut accepted) = accepted.lock() {
                    *accepted = Some(conn.clone());
                }
                (conn, send, recv, *hello)
            }
        };
        // Admission: the hello must prove the room code, an invite or the LAN
        // token before anything about this host is sent.
        let b = quic::binding(&conn)?;
        let tokens = shared.admission_tokens();
        let raw: Vec<[u8; 32]> = tokens.iter().map(|(_, t)| *t).collect();
        let Some(which) = quic::admitted_which(&hello, &b, &raw) else {
            return refuse(
                &conn,
                close::NOT_ADMITTED,
                "no valid admission proof".into(),
            );
        };
        // The token the hello proved, to re-check when the peer is seated.
        let proved = tokens[which];
        // The LAN token is what a virtual link and a session-bound reconnect
        // prove; neither is a person's own join, so they are `Other`.
        let admitted_by = match tokens[which].0 {
            Admission::Lan
                if shared.path_override == Some(PathKind::Virtual) || hello.migration.is_some() =>
            {
                Admission::Other
            }
            by => by,
        };
        match (&policy, &hello.migration) {
            (Some(policy), Some(binding)) => {
                if let Err(e) = policy.check_request(binding) {
                    return refuse(&conn, close::BAD_HELLO, e.to_string());
                }
            }
            (None, None) => {}
            _ => {
                return refuse(
                    &conn,
                    close::BAD_HELLO,
                    "session binding required/mismatched".into(),
                )
            }
        }
        // No point welcoming a joiner there is no seat for (checked again,
        // under the lock, before it is seated).
        let early = shared
            .peers
            .lock()
            .ok()
            .and_then(|p| seat_refusal(&shared, &p));
        if let Some(code) = early {
            return refuse(&conn, code, "refused".into());
        }
        let peer = PeerId(
            shared
                .next_peer
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
                .map_err(|_| "peer namespace exhausted")?,
        );
        let transcript = quic::server_send_welcome_bound(
            &conn,
            &mut send,
            &shared.host_keys,
            shared.attestation.as_deref(),
            &shared.inbox_relays,
            &shared.room_name,
            &shared.answer_key_for(hello.session.as_deref()),
            hello.session.as_deref(),
            peer.0,
            hello.migration.clone(),
        )
        .await?;
        // The joiner verified us; now it says who it is.
        let host_pk = shared.host_keys.public_key();
        let (pk, attestation, inbox_relays) = match quic::server_read_identify(
            &conn,
            &mut recv,
            hello.session.as_deref(),
            &host_pk,
            &transcript,
        )
        .await
        {
            Ok(x) => x,
            Err((code, why)) => return refuse(&conn, code, why),
        };
        if let (Some(policy), Some(binding)) = (&policy, &hello.migration) {
            if let Err(e) = policy.authorize(binding, pk.to_bytes()) {
                return refuse(&conn, close::NOT_ADMITTED, e.to_string());
            }
        }
        if shared
            .denied
            .lock()
            .map(|d| d.contains(&pk))
            .unwrap_or(false)
        {
            return refuse(&conn, close::KICKED, "kicked earlier".into());
        }
        #[cfg(test)]
        {
            let barrier = shared
                .before_registration
                .lock()
                .ok()
                .and_then(|b| b.clone());
            if let Some(barrier) = barrier {
                barrier.wait().await;
                barrier.wait().await;
            }
        }
        Ok((
            conn,
            send,
            recv,
            hello,
            pk,
            attestation,
            inbox_relays,
            peer,
            admitted_by,
            proved,
        ))
    };
    // An ordinary handshake ends when the pin bumps the generation; a
    // session-bound one is never preempted.
    let ordinary = policy.is_none();
    let preempted = async {
        if !ordinary || generation_rx.wait_for(|g| *g != generation).await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    let timed = tokio::time::timeout_at(
        started
            + if policy.is_some() {
                quic::SESSION_HANDSHAKE_DEADLINE
            } else {
                quic::HANDSHAKE_TIMEOUT
            },
        setup,
    );
    let outcome = tokio::select! {
        outcome = timed => outcome,
        () = preempted => {
            if let Some(conn) = accepted.lock().ok().and_then(|mut c| c.take()) {
                conn.close(close::CLOSED.into(), b"room closed");
            }
            log::info!("[host] {remote}: pending handshake closed by the session pin");
            return;
        }
    };
    let (conn, mut send, recv, hello, pubkey, attestation, inbox_relays, peer, admitted_by, proved) =
        match outcome {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => {
                log::info!("[host] {remote}: handshake failed: {e}");
                return;
            }
            Err(_) => {
                log::info!("[host] {remote}: handshake timed out");
                return;
            }
        };

    drop(slot);
    // Seat under the lock so two simultaneous joiners can't both take the last seat.
    let (mut link, out_rx) = Link::new(conn.clone(), shared.limits);
    link.migration = hello.migration.clone();
    link.app_binding = quic::app_binding(&conn, shared.app_binding_label.as_deref());
    link.generation = generation;
    let refused = match shared.peers.lock() {
        Ok(mut peers) => {
            let mut r = if shared.generation.load(Ordering::Acquire) != generation
                || shared
                    .session_policy
                    .lock()
                    .map(
                        |current| match (current.as_ref(), hello.migration.as_ref()) {
                            (Some(current), Some(binding)) => {
                                link.session_key = Some(pubkey.to_bytes());
                                link.session_player = current.player_for_key(pubkey.to_bytes());
                                current.authorize(binding, pubkey.to_bytes()).is_err()
                            }
                            (None, None) => false,
                            _ => true,
                        },
                    )
                    .unwrap_or(true)
            {
                Some(close::CLOSED)
            } else if !shared.admission_tokens().contains(&proved) {
                // The invite (or the day's code token) that admitted this hello
                // was revoked while the handshake ran: not seated.
                Some(close::NOT_ADMITTED)
            } else {
                seat_refusal(&shared, &peers)
            };
            match shared.peer_keys.lock() {
                Ok(mut keys) => match shared.denied.lock() {
                    Ok(denied) => {
                        if denied.contains(&pubkey) {
                            r = Some(close::KICKED);
                        } else if policy.is_some() && keys.values().any(|key| *key == pubkey) {
                            r = Some(close::FULL);
                        }
                        if r.is_none() {
                            keys.insert(peer, pubkey);
                        }
                    }
                    Err(_) => r = Some(close::CLOSED),
                },
                Err(_) => r = Some(close::CLOSED),
            }
            if r.is_none() {
                peers.insert(peer, link.clone());
            }
            r
        }
        Err(_) => return,
    };
    if let Some(code) = refused {
        conn.close(code.into(), b"refused");
        return;
    }
    let mut guard = PeerGuard {
        shared: Arc::clone(&shared),
        peer,
        conn: conn.clone(),
        armed: true,
        announced: false,
        generation,
    };
    if let Err(e) = quic::server_send_accepted(&mut send).await {
        log::info!("[host] {remote}: accept failed: {e}");
        return; // the guard removes the peer
    }
    let path = shared.path_override.unwrap_or(hello.path);
    log::info!("[host] {peer} joined from {remote} via {path:?}");
    if !shared.emit_registered(
        peer,
        generation,
        HostEvent::PeerJoined {
            peer,
            pubkey,
            path,
            rtt_ms: link.rtt_ms(),
            attestation,
            inbox_relays,
            admitted_by,
        },
    ) {
        return;
    }
    guard.announced = true;

    let (s1, s2) = (Arc::clone(&shared), Arc::clone(&shared));
    let (reliable_q, lossy_q) = (Arc::new(Inbound::default()), Arc::new(Inbound::default()));
    let inbound = shared.limits.inbound;
    let ended = quic::pump(
        conn,
        send,
        recv,
        out_rx,
        Arc::clone(&link.queued),
        link.max_reliable_len,
        move |bytes| {
            // A detached peer's frames were on the way before its kick: drop
            // them and keep the stream open, so the kick's flush still runs.
            s1.emit_counted(
                peer,
                generation,
                HostEvent::Reliable { peer, bytes },
                &reliable_q,
                inbound.messages,
                inbound.bytes,
            ) != Emitted::Full
        },
        move |bytes| {
            // Over the cap: dropped, as the network might have.
            s2.emit_counted(
                peer,
                generation,
                HostEvent::Lossy { peer, bytes },
                &lossy_q,
                MAX_QUEUED_LOSSY,
                usize::MAX,
            );
        },
    )
    .await;
    guard.armed = false;
    // Whoever atomically detaches the link reports the leave (kick already did).
    let removed = shared.detach_peer(peer, false).is_some();
    if removed {
        let reason = match ended {
            Ended::Remote(close::KICKED, _) => LeaveReason::Kicked,
            Ended::Remote(..) => LeaveReason::Left,
            Ended::TimedOut => LeaveReason::TimedOut,
            Ended::Local => LeaveReason::Error("closed locally".into()),
            Ended::Error(e) => LeaveReason::Error(e),
        };
        log::info!("[host] {peer} left: {reason:?}");
        shared.emit_at(HostEvent::PeerLeft { peer, reason }, generation);
    }
}

#[cfg(test)]
mod migration_transition_tests {
    use super::*;
    use crate::migration::*;
    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "transition timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn descriptor(
        h: &HostHandle,
        cfg: &NetConfig,
        host: &Identity,
        standby: &Identity,
        player: &Identity,
    ) -> Descriptor {
        let root = Root {
            session: fresh_session().unwrap(),
            app: cfg.app_tag.clone(),
            transport_version: 7,
            game_version: 13,
            checkpoint_version: 1,
            host: host.pubkey().to_bytes(),
            standby: standby.pubkey().to_bytes(),
            controller: host.pubkey().to_bytes(),
            code: room_code_hash(h.code()).unwrap(),
            created_day: 20741,
            roster_revision: 1,
            members: vec![Member {
                player: 1,
                seat: 0,
                key: Some(player.pubkey().to_bytes()),
            }],
            config: [1; 32],
            content: [2; 32],
            limits: ResourceLimits::default(),
        };
        let mut descriptor = Descriptor::offer(root, host.keys()).unwrap();
        descriptor.consent(standby.keys()).unwrap();
        descriptor
    }
    #[test]
    fn pin_closes_pending_ordinary_handshakes_as_a_closed_room() {
        let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-pin-preempt").lan_only();
        cfg.lan_port = 0;
        let original = Identity::ephemeral();
        let standby = Identity::ephemeral();
        let player = Identity::ephemeral();
        let h = host(
            &cfg,
            &original,
            RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
        );
        wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
        let addr = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            h.local_addr().unwrap().port(),
        );
        let descriptor = descriptor(&h, &cfg, &original, &standby, &player);
        let token: [u8; 32] = hex::decode(h.lan_token()).unwrap().try_into().unwrap();
        // Two real QUIC handshakes hold slots on the unpinned listener: a bare
        // connection with no hello and no token, and one that has its verified
        // welcome but deliberately never sends Identify.
        let (endpoint, bare, opened) = crate::runtime().block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let endpoint =
                quic::client_endpoint(socket, &cfg.app_tag, quic::Liveness::DEFAULT).unwrap();
            let bare = endpoint
                .connect(addr, quic::SERVER_NAME)
                .unwrap()
                .await
                .unwrap();
            let conn = endpoint
                .connect(addr, quic::SERVER_NAME)
                .unwrap()
                .await
                .unwrap();
            let check: quic::HostCheck = Arc::new(|_| Ok(()));
            let opened = quic::client_open(&conn, None, PathKind::Lan, &[token], &check)
                .await
                .unwrap();
            (endpoint, bare, opened)
        });
        wait_until(|| h.shared.pending_handshakes.load(Ordering::Acquire) == 2);
        h.pin_session(descriptor.clone()).unwrap();
        let closed_room = |conn: &quinn::Connection| {
            matches!(
                conn.close_reason(),
                Some(quinn::ConnectionError::ApplicationClosed(ref c))
                    if c.error_code == quinn::VarInt::from_u32(close::CLOSED)
            )
        };
        wait_until(|| closed_room(&bare) && closed_room(&opened.conn));
        wait_until(|| h.shared.pending_handshakes.load(Ordering::Acquire) == 0);
        assert!(h.poll().is_none(), "a preempted handshake was seated");
        drop(opened);
        drop(endpoint);
    }
    /// A1 decision 4: migration keeps its journal at the default reliable
    /// size, so every way of arming a room refuses a raised cap.
    #[test]
    fn arming_is_refused_when_the_reliable_cap_is_not_the_default() {
        let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-cap-test").lan_only();
        cfg.lan_port = 0;
        cfg.max_reliable_len = 65_537;
        let original = Identity::ephemeral();
        let standby = Identity::ephemeral();
        let player = Identity::ephemeral();
        let h = host(
            &cfg,
            &original,
            RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
        );
        wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
        let descriptor = descriptor(&h, &cfg, &original, &standby, &player);
        let refused = |e: String| e.contains("max_reliable_len") && e.contains("migration");
        // Pinning the original host.
        assert!(h.pin_session(descriptor.clone()).is_err_and(refused));
        // The standby's control listener (resume_host shares its entry).
        assert!(
            crate::host_standby(&cfg, &standby, h.code(), descriptor.clone())
                .err()
                .is_some_and(refused)
        );
        // A session join.
        let binding = ConnectionBinding {
            session: descriptor.root.session,
            descriptor: descriptor.root.digest().unwrap(),
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        };
        let addr = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            h.local_addr().unwrap().port(),
        );
        assert!(crate::join_session_addr(
            &cfg,
            &player,
            addr,
            &h.lan_token(),
            binding,
            original.pubkey()
        )
        .err()
        .is_some_and(refused));
        // Nothing was pinned: ordinary joins still work at the raised cap.
        assert!(h.is_open());
        // The default cap arms as before.
        cfg.max_reliable_len = crate::MAX_RELIABLE_LEN;
        assert!(cfg.check_migration_cap().is_ok());
        h.shutdown();
    }
    #[test]
    fn pin_fences_detached_pumps_and_queued_events() {
        let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-pin-test").lan_only();
        cfg.lan_port = 0;
        let original = Identity::ephemeral();
        let standby = Identity::ephemeral();
        let player = Identity::ephemeral();
        let h = host(
            &cfg,
            &original,
            RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
        );
        wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
        let addr = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            h.local_addr().unwrap().port(),
        );
        let descriptor = descriptor(&h, &cfg, &original, &standby, &player);
        let client = crate::join_addr(&cfg, &player, addr, &h.lan_token());
        wait_until(|| matches!(client.poll(), Some(crate::ClientEvent::Connected { .. })));
        let mut peer = None;
        wait_until(|| {
            if let Some(HostEvent::PeerJoined { peer: p, .. }) = h.poll() {
                peer = Some(p);
            }
            peer.is_some()
        });
        let peer = peer.unwrap();
        let old = h.link(peer).unwrap();
        let old_generation = old.generation;
        // remove_peer's delayed close leaves the old pump live. Hold a sender
        // behind an explicit barrier until pin_session has advanced generation.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let sender_barrier = barrier.clone();
        let sender = std::thread::spawn(move || {
            sender_barrier.wait();
            client.send_reliable(Bytes::from_static(b"late ordinary input"));
            client
        });
        h.disconnect(peer);
        h.pin_session(descriptor.clone()).unwrap();
        barrier.wait();
        let _client = sender.join().unwrap();
        assert!(
            h.poll().is_none(),
            "queued old-generation leave was exposed"
        );
        assert!(!h.shared.emit_registered(
            peer,
            old_generation,
            HostEvent::PeerJoined {
                peer,
                pubkey: player.pubkey(),
                path: PathKind::Lan,
                rtt_ms: 0,
                attestation: None,
                inbox_relays: vec![],
                admitted_by: Admission::Other,
            }
        ));
        let counter = Arc::new(Inbound::default());
        assert_eq!(
            h.shared.emit_counted(
                peer,
                old_generation,
                HostEvent::Reliable {
                    peer,
                    bytes: Bytes::from_static(b"late")
                },
                &counter,
                16,
                usize::MAX
            ),
            Emitted::Detached
        );
        assert_eq!(counter.messages(), 0);
        let binding = ConnectionBinding {
            session: descriptor.root.session,
            descriptor: descriptor.root.digest().unwrap(),
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        };
        let bound = crate::join_session_addr(
            &cfg,
            &player,
            addr,
            &h.lan_token(),
            binding,
            original.pubkey(),
        )
        .unwrap();
        wait_until(|| matches!(bound.poll(), Some(crate::ClientEvent::Connected { .. })));
        let mut new_peer = None;
        wait_until(|| {
            if let Some(HostEvent::PeerJoined { peer: p, .. }) = h.poll() {
                new_peer = Some(p);
            }
            new_peer.is_some()
        });
        assert_ne!(new_peer, Some(peer));
        while let Some(event) = h.poll() {
            assert!(
                !matches!(event,HostEvent::Reliable{peer:p,..}|HostEvent::Lossy{peer:p,..} if p==peer)
            );
        }
        h.shutdown();
    }
    #[test]
    fn kicked_key_cannot_race_a_previously_authenticated_reconnect_into_a_pinned_host() {
        let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-ban-test").lan_only();
        cfg.lan_port = 0;
        let original = Identity::ephemeral();
        let standby = Identity::ephemeral();
        let player = Identity::ephemeral();
        let h = host(
            &cfg,
            &original,
            RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
        );
        wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
        let addr = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            h.local_addr().unwrap().port(),
        );
        let descriptor = descriptor(&h, &cfg, &original, &standby, &player);
        h.pin_session(descriptor.clone()).unwrap();
        let binding = ConnectionBinding {
            session: descriptor.root.session,
            descriptor: descriptor.root.digest().unwrap(),
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        };
        let first = crate::join_session_addr(
            &cfg,
            &player,
            addr,
            &h.lan_token(),
            binding.clone(),
            original.pubkey(),
        )
        .unwrap();
        wait_until(|| matches!(first.poll(), Some(crate::ClientEvent::Connected { .. })));
        let mut peer = None;
        wait_until(|| {
            if let Some(HostEvent::PeerJoined { peer: p, .. }) = h.poll() {
                peer = Some(p);
            }
            peer.is_some()
        });
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        *h.shared.before_registration.lock().unwrap() = Some(barrier.clone());
        let reconnect = crate::join_session_addr(
            &cfg,
            &player,
            addr,
            &h.lan_token(),
            binding,
            original.pubkey(),
        )
        .unwrap();
        crate::runtime().block_on(barrier.wait()); // Identify passed the early denied check.
        h.kick(peer.unwrap());
        crate::runtime().block_on(barrier.wait()); // Final insertion must see the ban.
        let mut refused = false;
        wait_until(|| {
            if let Some(event) = reconnect.poll() {
                match event {
                    crate::ClientEvent::Failed { .. } => refused = true,
                    crate::ClientEvent::Connected { .. } => panic!("banned reconnect was seated"),
                    _ => {}
                }
            }
            refused
        });
        assert_eq!(h.peer_count(), 0);
        h.shutdown();
    }

    #[test]
    fn the_first_answer_key_recorded_for_a_session_stays() {
        let mut cfg = NetConfig::new(std::env::temp_dir(), "answer-key-test").lan_only();
        cfg.lan_port = 0;
        let h = host(
            &cfg,
            &Identity::ephemeral(),
            RoomInfo {
                name: "r".into(),
                max_players: 4,
            },
        );
        let (first, second) = (Keys::generate().public_key(), Keys::generate().public_key());
        h.shared.record_answer_key("session-a", first);
        // A re-offer of the same session id gets its own answer key, but the
        // welcome keeps naming the first.
        h.shared.record_answer_key("session-a", second);
        assert_eq!(h.shared.answer_key_for(Some("session-a")), first);
        h.shared.record_answer_key("session-b", second);
        assert_eq!(h.shared.answer_key_for(Some("session-b")), second);
        assert_ne!(h.shared.answer_key_for(Some("unknown")), first);
        assert_eq!(h.shared.answer_keys.lock().unwrap().order.len(), 2);
        h.shutdown();
    }

    #[test]
    fn pin_suppresses_cached_accepted_relay_reanswers() {
        use crate::rendezvous::{new_session_id, seal_offer, Offer};
        let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-offer-test").lan_only();
        cfg.lan_port = 0;
        let original = Identity::ephemeral();
        let standby = Identity::ephemeral();
        let player = Identity::ephemeral();
        let h = host(
            &cfg,
            &original,
            RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
        );
        wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
        let secrets =
            crate::room::derive(&cfg.app_tag, h.code(), crate::room::utc_today()).unwrap();
        let joiner = Keys::generate();
        let relay_keys = Keys::generate();
        let offer = Offer {
            v: NET_PROTOCOL_VERSION,
            session: new_session_id(),
            pubkey: joiner.public_key().to_hex(),
            candidates: vec![],
            sent_at: crate::unix_now(),
        };
        let event = seal_offer(&joiner, &secrets.keys.public_key(), &secrets.tag, &offer).unwrap();
        let answer = Answer {
            v: NET_PROTOCOL_VERSION,
            session: offer.session.clone(),
            accepted: true,
            reason: None,
            candidates: vec![],
            sent_at: crate::unix_now(),
            host_pubkey: original.pubkey().to_hex(),
        };
        let answer_event = seal_answer(&relay_keys, &joiner.public_key(), &answer).unwrap();
        let key = (offer.session.clone(), event.pubkey);
        let mut offers = Offers::default();
        offers.sessions.insert(
            key.clone(),
            Answered {
                event: answer_event,
                accepted: true,
                last_sent: Instant::now() - REANSWER_EVERY,
                sends: 1,
                targets: vec![],
            },
        );
        let hub = crate::relay::FakeRelayHub::new();
        let relay = hub.client();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let punchers = Punchers {
            online: socket,
            lan: None,
        };
        let task = HostTask {
            cfg: cfg.clone(),
            room: RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
            code: h.code().into(),
            shared: h.shared.clone(),
            fixed_day: None,
        };
        task.on_offer(
            &event,
            std::slice::from_ref(&secrets),
            &relay,
            &[],
            &mut offers,
            &punchers,
            false,
        );
        assert_eq!(
            offers.sessions[&key].sends, 2,
            "ordinary retransmission positive control"
        );
        offers.sessions.get_mut(&key).unwrap().last_sent = Instant::now() - REANSWER_EVERY;
        h.pin_session(descriptor(&h, &cfg, &original, &standby, &player))
            .unwrap();
        task.on_offer(
            &event,
            &[secrets],
            &relay,
            &[],
            &mut offers,
            &punchers,
            false,
        );
        assert_eq!(
            offers.sessions[&key].sends, 2,
            "cached accepted answer escaped pin"
        );
        h.shutdown();
    }

    #[test]
    fn membership_refresh_preserves_handshakes_and_retirement_fences_queued_peer_events() {
        for detach_before_retirement in [false, true] {
            use crate::migration::{Sequencer, SessionImage};
            let mut cfg =
                NetConfig::new(std::env::temp_dir(), "migration-member-fence-test").lan_only();
            cfg.lan_port = 0;
            let original = Identity::ephemeral();
            let standby = Identity::ephemeral();
            let first = Identity::ephemeral();
            let second = Identity::ephemeral();
            let h = host(
                &cfg,
                &original,
                RoomInfo {
                    name: "Original".into(),
                    max_players: 8,
                },
            );
            wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
            let mut root = descriptor(&h, &cfg, &original, &standby, &first).root;
            root.members.push(Member {
                player: 2,
                seat: 1,
                key: Some(second.pubkey().to_bytes()),
            });
            let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
            descriptor.consent(standby.keys()).unwrap();
            h.pin_session(descriptor.clone()).unwrap();
            let mut image =
                SessionImage::initial(&descriptor.root, &[(1, 10), (2, 11)], vec![0], 1, 100)
                    .unwrap();
            let mut sequencer =
                Sequencer::arm_session(descriptor.root.clone(), image.clone(), standby.keys())
                    .unwrap();
            h.update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
                .unwrap();
            let addr = SocketAddr::new(
                std::net::Ipv4Addr::LOCALHOST.into(),
                h.local_addr().unwrap().port(),
            );
            let binding = ConnectionBinding {
                session: descriptor.root.session,
                descriptor: descriptor.root.digest().unwrap(),
                term: 0,
                client: LinkRole::Player,
                server: LinkRole::Original,
            };
            let a = crate::join_session_addr(
                &cfg,
                &first,
                addr,
                &h.lan_token(),
                binding.clone(),
                original.pubkey(),
            )
            .unwrap();
            wait_until(|| matches!(a.poll(), Some(crate::ClientEvent::Connected { .. })));
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            *h.shared.before_registration.lock().unwrap() = Some(barrier.clone());
            let b = crate::join_session_addr(
                &cfg,
                &second,
                addr,
                &h.lan_token(),
                binding,
                original.pubkey(),
            )
            .unwrap();
            crate::runtime().block_on(barrier.wait());
            let candidate = sequencer
                .next(
                    image.encode(&descriptor.root).unwrap(),
                    100,
                    sequencer.receipt().watermarks.clone(),
                    vec![],
                )
                .unwrap();
            let token = sequencer.stage(candidate).unwrap();
            sequencer.install(token, standby.keys()).unwrap();
            h.update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
                .unwrap();
            crate::runtime().block_on(barrier.wait());
            wait_until(|| matches!(b.poll(), Some(crate::ClientEvent::Connected { .. })));
            let (pa, pb) = {
                let keys = h.shared.peer_keys.lock().unwrap();
                (
                    *keys.iter().find(|(_, k)| **k == first.pubkey()).unwrap().0,
                    *keys.iter().find(|(_, k)| **k == second.pubkey()).unwrap().0,
                )
            };
            let count = Arc::new(Inbound::default());
            let generation = h.shared.generation.load(Ordering::Acquire);
            for peer in [pa, pb] {
                assert_eq!(
                    h.shared.emit_counted(
                        peer,
                        generation,
                        HostEvent::Reliable {
                            peer,
                            bytes: Bytes::from_static(b"queued")
                        },
                        &count,
                        10,
                        usize::MAX
                    ),
                    Emitted::Queued
                );
                assert_eq!(
                    h.shared.emit_counted(
                        peer,
                        generation,
                        HostEvent::Lossy {
                            peer,
                            bytes: Bytes::from_static(b"queued")
                        },
                        &count,
                        10,
                        usize::MAX
                    ),
                    Emitted::Queued
                );
            }
            if detach_before_retirement {
                h.disconnect(pa);
            }
            image.members.remove(0);
            image.inputs.remove(&1);
            image.membership_revision += 1;
            let mut marks = sequencer.receipt().watermarks.clone();
            marks[0].retired = true;
            let candidate = sequencer
                .next(image.encode(&descriptor.root).unwrap(), 100, marks, vec![])
                .unwrap();
            let token = sequencer.stage(candidate).unwrap();
            sequencer.install(token, standby.keys()).unwrap();
            h.update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
                .unwrap();
            let mut left = 0;
            let mut survivor_data = 0;
            let mut survivor_joined = 0;
            while let Some(event) = h.poll() {
                match event {
                    HostEvent::PeerJoined { peer, .. } => {
                        assert_eq!(peer, pb);
                        survivor_joined += 1;
                    }
                    HostEvent::Reliable { peer, .. } | HostEvent::Lossy { peer, .. } => {
                        assert_eq!(peer, pb);
                        survivor_data += 1;
                    }
                    HostEvent::PeerLeft { peer, .. } => {
                        assert_eq!(peer, pa);
                        left += 1;
                    }
                    _ => {}
                }
            }
            assert_eq!((left, survivor_data, survivor_joined), (1, 2, 1));
            assert_eq!(count.messages(), 0);
            assert_eq!(h.peer_count(), 1);
            h.shutdown();
        }
    }

    /// The decision is 5 s overall; the window is fixed here, not read from
    /// the constant, so restoring the old 8 s fails these tests.
    const DEADLINE: Duration = Duration::from_secs(5);
    const DEADLINE_SLACK: Duration = Duration::from_millis(6500);

    /// A pinned host whose root seats every one of `players`.
    fn pinned_host(
        tag: &str,
        players: &[Identity],
    ) -> (
        NetConfig,
        HostHandle,
        Identity,
        SocketAddr,
        ConnectionBinding,
    ) {
        let mut cfg = NetConfig::new(std::env::temp_dir(), tag).lan_only();
        cfg.lan_port = 0;
        let original = Identity::ephemeral();
        let standby = Identity::ephemeral();
        let h = host(
            &cfg,
            &original,
            RoomInfo {
                name: "Original".into(),
                max_players: 8,
            },
        );
        wait_until(|| matches!(h.poll(), Some(HostEvent::Ready { .. })));
        let mut root = descriptor(&h, &cfg, &original, &standby, &players[0]).root;
        for (i, p) in players.iter().enumerate().skip(1) {
            root.members.push(Member {
                player: i as u64 + 1,
                seat: i as u8,
                key: Some(p.pubkey().to_bytes()),
            });
        }
        let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
        descriptor.consent(standby.keys()).unwrap();
        h.pin_session(descriptor.clone()).unwrap();
        let addr = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            h.local_addr().unwrap().port(),
        );
        let binding = ConnectionBinding {
            session: descriptor.root.session,
            descriptor: descriptor.root.digest().unwrap(),
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        };
        (cfg, h, original, addr, binding)
    }

    /// Polls every client together until each has emitted Connected or
    /// Failed; returns, per client, how long after `start` that came and the
    /// event. Panics if any client goes 15 s with neither.
    fn terminals(
        clients: &[&crate::ClientHandle],
        start: Instant,
    ) -> Vec<(Duration, crate::ClientEvent)> {
        let mut out: Vec<Option<(Duration, crate::ClientEvent)>> = vec![None; clients.len()];
        while out.iter().any(Option::is_none) {
            for (client, slot) in clients.iter().zip(out.iter_mut()) {
                while slot.is_none() {
                    match client.poll() {
                        Some(
                            ev @ (crate::ClientEvent::Connected { .. }
                            | crate::ClientEvent::Failed { .. }),
                        ) => *slot = Some((start.elapsed(), ev)),
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "a join hung with no Connected or Failed event"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        out.into_iter().map(Option::unwrap).collect()
    }

    #[test]
    fn pinned_handshake_cuts_stalled_peers_at_the_deadline_and_frees_their_slots() {
        let player = Identity::ephemeral();
        let (cfg, h, original, addr, binding) =
            pinned_host("migration-stall-test", std::slice::from_ref(&player));
        let token: [u8; 32] = hex::decode(h.lan_token()).unwrap().try_into().unwrap();
        // Two peers fill both pinned slots: verified welcome, never Identify.
        let start = Instant::now();
        let (endpoints, stalled) = crate::runtime().block_on(async {
            let (mut endpoints, mut stalled) = (Vec::new(), Vec::new());
            for _ in 0..2 {
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                let endpoint =
                    quic::client_endpoint(socket, &cfg.app_tag, quic::Liveness::DEFAULT).unwrap();
                let conn = endpoint
                    .connect(addr, quic::SERVER_NAME)
                    .unwrap()
                    .await
                    .unwrap();
                let check: quic::HostCheck = Arc::new(|_| Ok(()));
                let opened = quic::client_open_bound(
                    &conn,
                    None,
                    PathKind::Lan,
                    &[token],
                    &check,
                    Some(&binding),
                )
                .await
                .unwrap();
                endpoints.push(endpoint);
                stalled.push(opened);
            }
            (endpoints, stalled)
        });
        assert_eq!(h.shared.pending_handshakes.load(Ordering::Acquire), 2);
        // The 2-slot limit stays: a third handshake is refused at once.
        let early = Instant::now();
        let refused = crate::join_session_addr(
            &cfg,
            &player,
            addr,
            &h.lan_token(),
            binding.clone(),
            original.pubkey(),
        )
        .unwrap();
        let (t, ev) = terminals(&[&refused], early).remove(0);
        assert!(matches!(ev, crate::ClientEvent::Failed { .. }), "{ev:?}");
        assert!(t < Duration::from_secs(2), "refusal took {t:?}");
        drop(refused);
        // The host cuts each stalled handshake by the deadline from accept.
        let cut = crate::runtime().block_on(async {
            let mut cut = Vec::new();
            for opened in &stalled {
                let _ = tokio::time::timeout(Duration::from_secs(15), opened.conn.closed()).await;
                cut.push(start.elapsed());
            }
            cut
        });
        for t in cut {
            assert!(
                (DEADLINE..DEADLINE_SLACK).contains(&t),
                "stalled handshake cut after {t:?}"
            );
        }
        wait_until(|| h.shared.pending_handshakes.load(Ordering::Acquire) == 0);
        drop(stalled);
        drop(endpoints);
        // The freed slot seats an honest rejoin.
        let honest = crate::join_session_addr(
            &cfg,
            &player,
            addr,
            &h.lan_token(),
            binding,
            original.pubkey(),
        )
        .unwrap();
        let (_, ev) = terminals(&[&honest], Instant::now()).remove(0);
        assert!(matches!(ev, crate::ClientEvent::Connected { .. }), "{ev:?}");
        wait_until(|| matches!(h.poll(), Some(HostEvent::PeerJoined { .. })));
        assert_eq!(h.peer_count(), 1);
        h.shutdown();
    }

    #[test]
    fn session_join_has_one_overall_deadline_across_its_stages() {
        let mut cfg =
            NetConfig::new(std::env::temp_dir(), "migration-client-deadline-test").lan_only();
        cfg.lan_port = 0;
        // A listener that takes 2.5 s to complete the QUIC handshake, then
        // never answers the hello, holding the connection open. Staged
        // timeouts would allow 2.5 s plus a whole handshake timeout.
        let (tx, rx) = mpsc::channel();
        let app = cfg.app_tag.clone();
        let server = crate::runtime().spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let endpoint = quic::server_endpoint(socket, &app, quic::Liveness::DEFAULT).unwrap();
            tx.send(endpoint.local_addr().unwrap()).unwrap();
            let incoming = endpoint.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(2500)).await;
            let conn = incoming.accept().unwrap().await.unwrap();
            let reason = conn.closed().await;
            drop(endpoint);
            reason
        });
        let addr = rx.recv().unwrap();
        let binding = ConnectionBinding {
            session: fresh_session().unwrap(),
            descriptor: [7; 32],
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        };
        let start = Instant::now();
        let client = crate::join_session_addr(
            &cfg,
            &Identity::ephemeral(),
            addr,
            &hex::encode([9u8; 32]),
            binding,
            Identity::ephemeral().pubkey(),
        )
        .unwrap();
        let (t, ev) = terminals(&[&client], start).remove(0);
        assert!(
            matches!(
                ev,
                crate::ClientEvent::Failed {
                    stage: crate::JoinStage::Handshake,
                    ..
                }
            ),
            "{ev:?}"
        );
        assert!(
            (DEADLINE..DEADLINE_SLACK).contains(&t),
            "session join failed after {t:?}"
        );
        drop(client);
        // The joiner gave up; the stalled listener never closed it.
        let reason = crate::runtime()
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), server).await })
            .expect("joiner left the connection open")
            .unwrap();
        assert!(
            !matches!(reason, quinn::ConnectionError::LocallyClosed),
            "{reason:?}"
        );
    }

    #[test]
    fn four_concurrent_rejoins_on_two_pinned_slots_each_get_an_event_by_the_deadline() {
        let players: Vec<Identity> = (0..4).map(|_| Identity::ephemeral()).collect();
        let (cfg, h, original, addr, binding) = pinned_host("migration-four-rejoin-test", &players);
        // Park every handshake that reaches registration and never release
        // it: the two holding the slots must still end by the deadline.
        let barrier = Arc::new(tokio::sync::Barrier::new(64));
        *h.shared.before_registration.lock().unwrap() = Some(barrier);
        let join = |p: &Identity| {
            crate::join_session_addr(
                &cfg,
                p,
                addr,
                &h.lan_token(),
                binding.clone(),
                original.pubkey(),
            )
            .unwrap()
        };
        let start = Instant::now();
        let clients: Vec<_> = players.iter().map(join).collect();
        let (mut refused, mut cut) = (0, 0);
        for (t, ev) in terminals(&clients.iter().collect::<Vec<_>>(), start) {
            assert!(matches!(ev, crate::ClientEvent::Failed { .. }), "{ev:?}");
            assert!(t < DEADLINE_SLACK, "a rejoin went {t:?} without an event");
            if t < Duration::from_secs(2) {
                refused += 1;
            } else {
                assert!(t >= DEADLINE, "{t:?}");
                cut += 1;
            }
        }
        assert_eq!((refused, cut), (2, 2));
        drop(clients);
        *h.shared.before_registration.lock().unwrap() = None;
        wait_until(|| h.shared.pending_handshakes.load(Ordering::Acquire) == 0);
        // Retrying with backoff, every rejoin is seated, and no attempt goes
        // past the deadline without an event.
        let mut waiting: Vec<&Identity> = players.iter().collect();
        let mut seated = Vec::new();
        let mut backoff = Duration::from_millis(50);
        for _ in 0..8 {
            let start = Instant::now();
            let attempt: Vec<_> = waiting.iter().map(|p| join(p)).collect();
            let results = terminals(&attempt.iter().collect::<Vec<_>>(), start);
            let mut still = Vec::new();
            for ((p, client), (t, ev)) in waiting.iter().zip(attempt).zip(results) {
                assert!(t < DEADLINE_SLACK, "a rejoin went {t:?} without an event");
                match ev {
                    crate::ClientEvent::Connected { .. } => seated.push(client),
                    _ => still.push(*p),
                }
            }
            waiting = still;
            if waiting.is_empty() {
                break;
            }
            std::thread::sleep(backoff);
            backoff *= 2;
        }
        assert!(waiting.is_empty(), "{} rejoins never seated", waiting.len());
        assert_eq!(h.peer_count(), 4);
        drop(seated);
        h.shutdown();
    }
}

#[cfg(test)]
mod advertise_tests {
    use super::*;

    /// Datagrams `punch` makes reach `watch` (one local socket standing for a
    /// joiner's offered address); the punch itself is 3 rounds 100 ms apart.
    fn punches_seen(advertise_only: bool) -> usize {
        let mut cfg = NetConfig::new(std::env::temp_dir(), "advertise-punch-test").lan_only();
        cfg.lan_port = 0;
        let h = host(
            &cfg,
            &Identity::ephemeral(),
            RoomInfo {
                name: "r".into(),
                max_players: 4,
            },
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !matches!(h.poll(), Some(HostEvent::Ready { .. })) {
            assert!(Instant::now() < deadline, "host not ready");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut task_cfg = cfg.clone();
        task_cfg.advertise_only = advertise_only;
        let task = HostTask {
            cfg: task_cfg,
            room: RoomInfo {
                name: "r".into(),
                max_players: 4,
            },
            code: h.code().into(),
            shared: h.shared.clone(),
            fixed_day: None,
        };
        let watch = UdpSocket::bind("127.0.0.1:0").unwrap();
        watch
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let punchers = Punchers {
            online: Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap()),
            lan: None,
        };
        {
            let _rt = crate::runtime().enter();
            task.punch(
                &punchers,
                vec![watch.local_addr().unwrap()],
                "ab".repeat(16),
            );
        }
        let (until, mut n) = (Instant::now() + Duration::from_millis(1200), 0);
        let mut buf = [0u8; 2048];
        while Instant::now() < until {
            if watch.recv_from(&mut buf).is_ok() {
                n += 1;
            }
        }
        h.shutdown();
        n
    }

    #[test]
    fn an_advertise_only_host_sends_no_punch() {
        assert!(punches_seen(false) > 0, "control: an ordinary host punches");
        assert_eq!(punches_seen(true), 0, "an advertise-only host punched");
    }
}
