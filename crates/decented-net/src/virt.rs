//! QUIC over any point-to-point packet link (Bluetooth LE L2CAP in the app).
//!
//! A [`VirtualLink`] is a pair of packet channels to one peer. This module
//! puts a `quinn::AsyncUdpSocket` over a set of them, so the full transport
//! (handshake, identity, admission, presence, everything above) runs over the
//! link unchanged: a virtual room is a LAN room whose packets travel another
//! way.
//!
//! **Packets on a link.** Every packet starts with a one-byte tag:
//! - [`TAG_TOKEN`] + 32 bytes: the host's *pre-frame*, the first packet on
//!   each link, carrying the room's current LAN admission token (what the LAN
//!   beacon carries: "in radio range = may knock"). Sent once, host → joiner.
//! - [`TAG_QUIC`] + one QUIC datagram: everything after.
//!
//! A joiner whose first packet is not a well-formed pre-frame fails with
//! `NotAdmitted`; a host drops a link whose first packet is not QUIC. Any later
//! packet that is not QUIC (a second pre-frame, an unknown tag, an empty or
//! oversized packet) drops the link on either side.
//!
//! **Sizes.** QUIC runs at a pinned 1200-byte MTU ([`VIRTUAL_MTU`]) with path
//! MTU discovery off, so a link packet is at most 1201 bytes, well under
//! [`MAX_VIRTUAL_PACKET`] (1452).
//!
//! **Addresses.** quinn wants a `SocketAddr` per peer. The host gives each
//! link its own address in 100.64.0.0/10 (never reused within one host); the
//! joiner sees the host at [`HOST_ADDR`]. A link whose channel closes is
//! forgotten: its address becomes unreachable, and QUIC's idle timeout ends
//! the connection.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::client::{spawn, ClientHandle, Target};
use crate::host::{accept_peer, start_host, Cmd, HostHandle, Shared};
use crate::quic::{self, close};
use crate::{FailReason, HostEvent, Identity, JoinStage, NetConfig, PathKind, RoomInfo};

/// QUIC's MTU over a virtual link: pinned (initial = minimum), no discovery.
pub const VIRTUAL_MTU: u16 = 1200;
/// The largest packet either side ever puts on a link (tag included). The
/// link's framing must carry at least this much.
pub const MAX_VIRTUAL_PACKET: usize = 1452;
/// First byte of the host's pre-frame (followed by the 32-byte LAN token).
pub(crate) const TAG_TOKEN: u8 = 0x01;
/// First byte of every QUIC packet on a link.
pub(crate) const TAG_QUIC: u8 = 0x02;
const PREFRAME_LEN: usize = 1 + 32;
/// How long a joiner waits for the host's pre-frame.
const PREFRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// Links one host holds at once (a radio in range can open many; seats are
/// bounded by the room anyway). When full, a new link displaces the oldest
/// one that never started QUIC; if every link has, the newcomer is dropped.
pub(crate) const MAX_LINKS: usize = 32;
/// A link that has not started a QUIC connection this long after its
/// pre-frame is dropped (a silent link must not hold a slot).
pub(crate) const LINK_SETUP_DEADLINE: Duration = Duration::from_secs(10);
/// After a link's connection ends, the link stays this long so the close
/// (a kick, a refusal) reaches the peer; then it is dropped.
const LINK_LINGER: Duration = Duration::from_millis(1000);
/// How often the host sweeps its links (deadline, half-closed links).
const SWEEP_EVERY: Duration = Duration::from_millis(500);
/// Where a joiner sees the host.
pub(crate) const HOST_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 1), 1));
/// A joiner's own (synthetic) address.
const CLIENT_LOCAL: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 2), 1));
/// Host link addresses are 100.64.0.0 + 2.. (inside 100.64.0.0/10).
const LINK_BASE: u32 = u32::from_be_bytes([100, 64, 0, 0]);
const LINK_SPACE: u32 = 1 << 22;

/// One point-to-point packet link to a peer. Each `Vec<u8>` is one packet,
/// delivered whole and in order or not at all; the link's own framing (W2b: a
/// u16 length prefix on the L2CAP stream) must carry [`MAX_VIRTUAL_PACKET`].
/// Closing either channel ends the link.
pub struct VirtualLink {
    /// For logs and UI, e.g. "BLE AA:BB…".
    pub peer_label: String,
    /// Packets to the peer.
    pub tx: mpsc::Sender<Vec<u8>>,
    /// Packets from the peer.
    pub rx: mpsc::Receiver<Vec<u8>>,
}

impl fmt::Debug for VirtualLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualLink")
            .field("peer_label", &self.peer_label)
            .finish_non_exhaustive()
    }
}

/// Feeds a virtual host its incoming links.
pub type VirtualLinkSender = mpsc::Sender<VirtualLink>;
/// What [`host_virtual`] takes.
pub type VirtualLinkReceiver = mpsc::Receiver<VirtualLink>;

/// A queue of incoming links for [`host_virtual`] (no tokio needed by the caller).
pub fn virtual_link_queue(capacity: usize) -> (VirtualLinkSender, VirtualLinkReceiver) {
    mpsc::channel(capacity.max(1))
}

/// Two ends of an in-memory link (tests, the desktop fake BLE): what one
/// sends, the other receives. Returns `(a, b)`: `a` is the end that `a_label`
/// holds, so its `peer_label` is `b_label`, and vice versa. `capacity` is
/// packets buffered each way.
pub fn virtual_pair(a_label: &str, b_label: &str, capacity: usize) -> (VirtualLink, VirtualLink) {
    let (a_tx, b_rx) = mpsc::channel(capacity.max(1));
    let (b_tx, a_rx) = mpsc::channel(capacity.max(1));
    (
        VirtualLink {
            peer_label: b_label.to_string(),
            tx: a_tx,
            rx: a_rx,
        },
        VirtualLink {
            peer_label: a_label.to_string(),
            tx: b_tx,
            rx: b_rx,
        },
    )
}

/// Host a room over virtual links: every link that arrives on `links` may
/// knock (it gets the room's current LAN token, as the beacon would give
/// it), and from there it is exactly a LAN join: the same hello, admission,
/// welcome, identify, kicks and events. No relays, no beacon, no UDP.
/// Peers are reported with [`PathKind::Virtual`].
///
/// The welcome withholds the host's persona attestation and inbox relays unless
/// [`NetConfig::withhold_host_attestation`] is `Some(false)`: anyone in radio
/// range can get as far as the welcome, so it carries only the key.
pub fn host_virtual(
    cfg: &NetConfig,
    id: &Identity,
    room: RoomInfo,
    links: VirtualLinkReceiver,
) -> HostHandle {
    let app_tag = cfg.app_tag.clone();
    let live = cfg.checked();
    let id = host_identity(cfg, id, true);
    start_host(
        &id,
        room,
        cfg.host_has_player,
        0,
        Some(PathKind::Virtual),
        cfg.app_tag.clone(),
        cfg.app_binding_label.clone(),
        None,
        move |code, _room, shared, cmd_rx| run_host(app_tag, live, code, links, shared, cmd_rx),
    )
}

/// The identity a host presents in its welcome: without the attestation if
/// `cfg` says so, or (`None`) if this transport withholds by default.
pub(crate) fn host_identity(cfg: &NetConfig, id: &Identity, withhold_by_default: bool) -> Identity {
    if cfg.withhold_host_attestation.unwrap_or(withhold_by_default) {
        // The inbox relays go with the attestation: they name the persona's
        // relays, so anyone in radio range could read them.
        id.without_attestation()
    } else {
        id.clone().with_inbox_relays(&cfg.inbox_relays)
    }
}

/// Join a host over one virtual link: waits for the host's pre-frame (the
/// LAN token), then joins exactly as [`crate::join_addr`] would. Connects with
/// [`PathKind::Virtual`].
pub fn join_virtual(cfg: &NetConfig, id: &Identity, link: VirtualLink) -> ClientHandle {
    spawn(cfg, id, Target::Virtual(link))
}

/// The virtual host's loop: accept QUIC on the link socket; nothing to
/// advertise (whoever feeds `links` decides who is in range).
async fn run_host(
    app_tag: String,
    live: Result<quic::Liveness, String>,
    code: String,
    links: VirtualLinkReceiver,
    shared: Arc<Shared>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
) {
    let s = Arc::clone(&shared);
    let token: TokenFn = Arc::new(move || s.lan_token());
    let live = match live {
        Ok(l) => l,
        Err(e) => {
            shared.emit(HostEvent::Failed { reason: e });
            return;
        }
    };
    let (endpoint, socket) = match host_endpoint(links, token, &app_tag, live) {
        Ok(x) => x,
        Err(e) => {
            shared.emit(HostEvent::Failed { reason: e });
            return;
        }
    };
    log::info!("[host] listening on virtual links, code {code}");
    shared.emit(HostEvent::Ready { code });
    let mut done = None;
    let mut sweep = tokio::time::interval(SWEEP_EVERY);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                // The link's slot lives as long as its connection (plus a
                // moment for the close to go out), however that ends.
                let addr = incoming.remote_address();
                socket.connection_started(addr);
                let (shared, socket) = (Arc::clone(&shared), Arc::clone(&socket));
                tokio::spawn(async move {
                    use futures_util::FutureExt;
                    let _ = std::panic::AssertUnwindSafe(accept_peer(incoming, shared)).catch_unwind().await;
                    tokio::time::sleep(LINK_LINGER).await;
                    socket.connection_ended(addr);
                });
            }
            _ = sweep.tick() => socket.sweep(),
            cmd = cmd_rx.recv() => match cmd {
                // The handle already applied the open state, and the token
                // (rotated or kept); each new link reads the current one.
                Some(Cmd::SetOpen(_) | Cmd::InvitesChanged) => {}
                Some(Cmd::Shutdown(tx)) => { done = Some(tx); break; }
                None => break,
            },
        }
    }
    shared.close_all(close::HOST_SHUTDOWN, b"host left");
    endpoint.close(close::HOST_SHUTDOWN.into(), b"host left");
    let _ = tokio::time::timeout(Duration::from_millis(500), endpoint.wait_idle()).await;
    if let Some(tx) = done {
        let _ = tx.send(());
    }
    log::info!("[host] stopped (virtual)");
}

/// Wait for the host's pre-frame on a fresh link and return its token.
/// Nothing within the timeout, or the link closing, is a connect failure; a
/// first packet that is anything but a pre-frame is a refusal.
pub(crate) async fn read_preframe(
    link: &mut VirtualLink,
) -> Result<[u8; 32], (JoinStage, FailReason)> {
    match tokio::time::timeout(PREFRAME_TIMEOUT, link.rx.recv()).await {
        Err(_) | Ok(None) => {
            log::info!("[join] {}: no pre-frame", link.peer_label);
            Err((JoinStage::Connecting, FailReason::NoLinkAnswer))
        }
        Ok(Some(p)) => parse_preframe(&p).ok_or_else(|| {
            log::info!(
                "[join] {}: first packet is not a pre-frame ({} bytes)",
                link.peer_label,
                p.len()
            );
            (JoinStage::Preparing, FailReason::NotAdmitted)
        }),
    }
}

fn parse_preframe(p: &[u8]) -> Option<[u8; 32]> {
    if p.len() != PREFRAME_LEN || p[0] != TAG_TOKEN {
        return None;
    }
    p[1..].try_into().ok()
}

fn preframe(token: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(PREFRAME_LEN);
    v.push(TAG_TOKEN);
    v.extend_from_slice(token);
    v
}

/// The transport over a link: the shared settings, with the MTU pinned.
fn transport(live: quic::Liveness) -> Arc<quinn::TransportConfig> {
    let mut t = quic::base_transport(live);
    t.initial_mtu(VIRTUAL_MTU);
    t.min_mtu(VIRTUAL_MTU);
    // `may_fragment = false` would otherwise let quinn probe upwards.
    t.mtu_discovery_config(None);
    Arc::new(t)
}

fn endpoint_config() -> Result<quinn::EndpointConfig, String> {
    let mut c = quinn::EndpointConfig::default();
    // Also tells the peer never to send a bigger datagram.
    c.max_udp_payload_size(VIRTUAL_MTU)
        .map_err(|e| format!("endpoint config: {e}"))?;
    Ok(c)
}

/// A server endpoint over the links arriving on `links`, and its socket (for
/// the link lifecycle). Must run inside the runtime.
fn host_endpoint(
    links: VirtualLinkReceiver,
    token: TokenFn,
    app_tag: &str,
    live: quic::Liveness,
) -> Result<(quinn::Endpoint, Arc<VirtSocket>), String> {
    let mut server = quic::server_config(app_tag, live)?;
    server.transport_config(transport(live));
    // A link is one fixed peer: a packet "from" another link is never that
    // peer moving, it is someone replaying it (connection ids are in clear).
    server.migration(false);
    let socket = Arc::new(VirtSocket::new(
        HOST_ADDR,
        Role::Host {
            incoming: Some(links),
            token,
        },
    ));
    let runtime = quinn::default_runtime().ok_or("no async runtime")?;
    let ep = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config()?,
        Some(server),
        socket.clone(),
        runtime,
    )
    .map_err(|e| format!("endpoint: {e}"))?;
    Ok((ep, socket))
}

/// A client endpoint over one link whose pre-frame was already read; dial
/// [`HOST_ADDR`] on it. Must run inside the runtime.
pub(crate) fn client_endpoint(
    link: VirtualLink,
    app_tag: &str,
    live: quic::Liveness,
) -> Result<quinn::Endpoint, String> {
    let socket = VirtSocket::new(CLIENT_LOCAL, Role::Client);
    socket
        .state
        .lock()
        .map_err(|_| "poisoned")?
        .routes
        .push(Route::new(HOST_ADDR, link));
    let runtime = quinn::default_runtime().ok_or("no async runtime")?;
    let mut ep = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config()?,
        None,
        Arc::new(socket),
        runtime,
    )
    .map_err(|e| format!("endpoint: {e}"))?;
    let mut client = quic::client_config(app_tag, live)?;
    client.transport_config(transport(live));
    ep.set_default_client_config(client);
    Ok(ep)
}

/// The host's current LAN token, read whenever a link arrives.
pub(crate) type TokenFn = Arc<dyn Fn() -> [u8; 32] + Send + Sync>;

enum Role {
    /// New links arrive on `incoming` (`None` once its sender is gone) and
    /// each gets `token()` as its pre-frame.
    Host {
        incoming: Option<VirtualLinkReceiver>,
        token: TokenFn,
    },
    /// One link, set up by [`client_endpoint`].
    Client,
}

struct Route {
    addr: SocketAddr,
    link: VirtualLink,
    opened: Instant,
    /// Connections quinn has started for this address and not yet ended.
    conns: usize,
    /// Whether one ever started (then the link lives by its connections,
    /// not by the setup deadline).
    started: bool,
}

impl Route {
    fn new(addr: SocketAddr, link: VirtualLink) -> Self {
        Route {
            addr,
            link,
            opened: Instant::now(),
            conns: 0,
            started: false,
        }
    }

    /// Silent past the deadline: never started QUIC.
    fn stale(&self) -> bool {
        !self.started && self.opened.elapsed() >= LINK_SETUP_DEADLINE
    }
}

struct State {
    role: Role,
    routes: Vec<Route>,
    /// The next host link address offset (never reused).
    next: u32,
    /// Where the next receive scan starts (fairness across links).
    cursor: usize,
}

/// A `quinn::AsyncUdpSocket` whose "network" is a set of [`VirtualLink`]s.
/// Poll-driven: no tasks of its own; dropping it (quinn does, once the
/// endpoint and its connections are gone) drops every link.
struct VirtSocket {
    local: SocketAddr,
    state: Mutex<State>,
}

impl fmt::Debug for VirtSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtSocket")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl VirtSocket {
    fn new(local: SocketAddr, role: Role) -> Self {
        VirtSocket {
            local,
            state: Mutex::new(State {
                role,
                routes: Vec::new(),
                next: 0,
                cursor: 0,
            }),
        }
    }

    /// quinn started a connection from `addr`.
    fn connection_started(&self, addr: SocketAddr) {
        if let Ok(mut st) = self.state.lock() {
            if let Some(r) = st.routes.iter_mut().find(|r| r.addr == addr) {
                r.conns += 1;
                r.started = true;
            }
        }
    }

    /// A connection from `addr` is over; with none left, drop the link (its
    /// peer may knock again on a new one).
    fn connection_ended(&self, addr: SocketAddr) {
        if let Ok(mut st) = self.state.lock() {
            if let Some(r) = st.routes.iter_mut().find(|r| r.addr == addr) {
                r.conns = r.conns.saturating_sub(1);
                if r.conns == 0 {
                    log::info!(
                        "[virt] {}: connection over; link dropped",
                        r.link.peer_label
                    );
                    st.forget(|r| r.addr == addr);
                }
            }
        }
    }

    /// Drop links past the setup deadline and links whose outgoing side
    /// closed (incoming closes are seen as they happen, in `poll_recv`).
    fn sweep(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.forget(|r| {
                let dead = r.stale() || r.link.tx.is_closed();
                if dead {
                    log::info!(
                        "[virt] {}: silent or half-closed; link dropped",
                        r.link.peer_label
                    );
                }
                dead
            });
        }
    }
}

impl State {
    /// Drop every route `gone` picks (dropping a link closes both channels).
    fn forget(&mut self, mut gone: impl FnMut(&Route) -> bool) {
        let before = self.routes.len();
        self.routes.retain(|r| !gone(r));
        if self.routes.len() != before {
            self.cursor = 0;
        }
    }

    /// Take every link waiting on the host's queue: give each an address
    /// and its pre-frame.
    fn admit_new_links(&mut self, cx: &mut Context) {
        let Role::Host { incoming, token } = &mut self.role else {
            return;
        };
        let mut arrived = Vec::new();
        if let Some(rx) = incoming {
            loop {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(link)) => arrived.push(link),
                    Poll::Ready(None) => {
                        *incoming = None;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }
        if arrived.is_empty() {
            return;
        }
        let token = token();
        for link in arrived {
            if self.routes.len() >= MAX_LINKS {
                // Make room by dropping the oldest link that never started
                // QUIC (a flood of silent links cannot lock joiners out).
                let oldest = self
                    .routes
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.started)
                    .min_by_key(|(_, r)| r.opened);
                match oldest.map(|(i, _)| i) {
                    Some(i) => {
                        log::info!(
                            "[virt] full: {} makes way for {}",
                            self.routes[i].link.peer_label,
                            link.peer_label
                        );
                        self.routes.remove(i);
                        self.cursor = 0;
                    }
                    None => {
                        log::info!("[virt] {}: too many links; dropped", link.peer_label);
                        continue;
                    }
                }
            }
            if link.tx.try_send(preframe(&token)).is_err() {
                log::info!(
                    "[virt] {}: could not send the pre-frame; dropped",
                    link.peer_label
                );
                continue;
            }
            let addr = loop {
                let n = 2 + self.next % (LINK_SPACE - 2);
                self.next = self.next.wrapping_add(1);
                let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(LINK_BASE + n), 1));
                if !self.routes.iter().any(|r| r.addr == a) {
                    break a;
                }
            };
            log::info!("[virt] link {} is {addr}", link.peer_label);
            self.routes.push(Route::new(addr, link));
        }
    }
}

/// A packet from a link, if it is a well-formed QUIC packet; `None` = garbage.
fn quic_payload(p: &[u8]) -> Option<&[u8]> {
    (p.len() >= 2 && p.len() <= MAX_VIRTUAL_PACKET && p[0] == TAG_QUIC).then(|| &p[1..])
}

/// Sending never waits: a full link drops the packet, as a full UDP buffer
/// would, and QUIC recovers.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for VirtSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let Ok(mut st) = self.state.lock() else {
            return Err(io::Error::other("virtual socket poisoned"));
        };
        // An unknown address is a link that went away: unreachable, dropped.
        let Some(route) = st.routes.iter().find(|r| r.addr == transmit.destination) else {
            return Ok(());
        };
        if route.link.tx.is_closed() {
            // Half-closed (the peer stopped reading): the link is over.
            log::info!(
                "[virt] {}: outgoing side closed; link dropped",
                route.link.peer_label
            );
            st.forget(|r| r.addr == transmit.destination);
            return Ok(());
        }
        let seg = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for d in transmit.contents.chunks(seg) {
            if 1 + d.len() > MAX_VIRTUAL_PACKET {
                log::warn!("[virt] dropping an oversized {}-byte datagram", d.len());
                continue;
            }
            let mut p = Vec::with_capacity(1 + d.len());
            p.push(TAG_QUIC);
            p.extend_from_slice(d);
            let _ = route.link.tx.try_send(p);
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Ok(mut st) = self.state.lock() else {
            return Poll::Ready(Err(io::Error::other("virtual socket poisoned")));
        };
        st.admit_new_links(cx);
        let max = bufs.len().min(meta.len());
        let n = st.routes.len();
        let mut filled = 0;
        let mut dead: VecDeque<usize> = VecDeque::new();
        // Poll every link (so each registers the waker) unless the buffers fill.
        for k in 0..n {
            let i = (st.cursor + k) % n;
            if st.routes[i].link.tx.is_closed() {
                log::info!(
                    "[virt] {}: outgoing side closed; link dropped",
                    st.routes[i].link.peer_label
                );
                dead.push_back(i);
                continue;
            }
            while filled < max {
                match st.routes[i].link.rx.poll_recv(cx) {
                    Poll::Ready(Some(p)) => match quic_payload(&p) {
                        Some(d) if d.len() <= bufs[filled].len() => {
                            bufs[filled][..d.len()].copy_from_slice(d);
                            meta[filled] = RecvMeta {
                                addr: st.routes[i].addr,
                                len: d.len(),
                                stride: d.len(),
                                ecn: None,
                                dst_ip: Some(self.local.ip()),
                            };
                            filled += 1;
                        }
                        Some(d) => log::debug!(
                            "[virt] dropping a {}-byte datagram (buffer too small)",
                            d.len()
                        ),
                        None => {
                            log::info!(
                                "[virt] {}: not a QUIC packet ({} bytes); link dropped",
                                st.routes[i].link.peer_label,
                                p.len()
                            );
                            dead.push_back(i);
                            break;
                        }
                    },
                    Poll::Ready(None) => {
                        log::info!("[virt] {}: link closed", st.routes[i].link.peer_label);
                        dead.push_back(i);
                        break;
                    }
                    Poll::Pending => break,
                }
            }
            if filled >= max {
                break;
            }
        }
        if n > 0 {
            st.cursor = (st.cursor + 1) % n;
        }
        if !dead.is_empty() {
            let mut idx = 0;
            st.routes.retain(|_| {
                let keep = !dead.contains(&idx);
                idx += 1;
                keep
            });
            st.cursor = 0;
        }
        if filled > 0 {
            Poll::Ready(Ok(filled))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
