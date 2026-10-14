//! Hosting a room: QUIC listener, room-code rendezvous, LAN beacon, peers.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nostr::{Keys, PublicKey};

use crate::lan::{Beacon, BeaconSender};
use crate::nat::candidates::{gather, punch_targets};
use crate::quic::{self, close, Ended, Link};
use crate::relay::{MultiRelay, RendezvousRelay, TagFilter};
use crate::rendezvous::{open_offer, seal_answer, Answer, Candidate, KIND_JOIN_OFFER};
use crate::room::{derive_days, utc_today, RoomSecrets, ROOM_TAG_LETTER};
use crate::{
    HostEvent, Identity, LeaveReason, NetConfig, PathKind, PeerId, RoomInfo, MAX_PLAYERS,
    NET_PROTOCOL_VERSION,
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
const UPNP_RENEW_CHECK: Duration = Duration::from_secs(60);

/// An event plus the per-peer counter it occupies until polled.
type Queued<E> = (E, Option<Arc<AtomicUsize>>);

/// Who may join: proofs of any of these tokens are admitted.
struct Tokens {
    /// Published in the LAN beacon; rotated when the room opens or closes.
    lan: [u8; 32],
    /// From the code, for today and yesterday (online hosts only).
    code: Vec<[u8; 32]>,
}

fn random_token() -> [u8; 32] {
    let mut t = [0u8; 32];
    getrandom::fill(&mut t).expect("OS RNG unavailable");
    t
}

pub(crate) struct Shared {
    peers: Mutex<HashMap<PeerId, Link>>,
    /// Each connected peer's identity key (for the kick deny-list).
    peer_keys: Mutex<HashMap<PeerId, PublicKey>>,
    /// Identity keys kicked from this room; refused for the room's life.
    denied: Mutex<HashSet<PublicKey>>,
    tokens: Mutex<Tokens>,
    open: AtomicBool,
    max_peers: usize,
    next_peer: AtomicU32,
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
    /// The throwaway key relay answers are signed with (named in the welcome).
    relay_key: PublicKey,
    room_name: String,
    /// Reported for every peer instead of the path its hello claims (a
    /// virtual host knows all its peers came over a virtual link).
    path_override: Option<PathKind>,
}

impl Shared {
    pub(crate) fn emit(&self, ev: HostEvent) {
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((ev, None));
        }
    }

    /// Queue a peer message if that peer is under `cap`. `false` = over.
    fn emit_counted(&self, ev: HostEvent, counter: &Arc<AtomicUsize>, cap: usize) -> bool {
        if counter.fetch_add(1, Ordering::AcqRel) >= cap {
            counter.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((ev, Some(Arc::clone(counter))));
        }
        true
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

    fn admission_tokens(&self) -> Vec<[u8; 32]> {
        self.tokens
            .lock()
            .map(|t| {
                std::iter::once(t.lan)
                    .chain(t.code.iter().copied())
                    .collect()
            })
            .unwrap_or_default()
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

pub(crate) enum Cmd {
    SetOpen(bool),
    Shutdown(mpsc::Sender<()>),
}

/// A hosted room. All methods return immediately.
pub struct HostHandle {
    code: String,
    events: Mutex<mpsc::Receiver<Queued<HostEvent>>>,
    shared: Arc<Shared>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
    shut: AtomicBool,
}

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
        move |code, room, keys, shared, cmd_rx| {
            HostTask {
                cfg,
                keys,
                room,
                code,
                shared,
                fixed_day,
            }
            .run(relay, cmd_rx)
        },
    )
}

/// Everything about a host but its transport: the room code, the shared state
/// and the handle. `task` gets the code, the clamped room, the relay key, the
/// shared state and the command channel, and returns the transport's loop,
/// which runs on the crate runtime (the UDP loop above, or `virt`'s).
pub(crate) fn start_host<F, Fut>(
    id: &Identity,
    room: RoomInfo,
    host_has_player: bool,
    relays_total: usize,
    path_override: Option<PathKind>,
    task: F,
) -> HostHandle
where
    F: FnOnce(
        String,
        RoomInfo,
        Keys,
        Arc<Shared>,
        tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    ) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let code = crate::room::generate_code();
    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let max_players = room.max_players.clamp(2, MAX_PLAYERS);
    let relay_keys = Keys::generate();
    let shared = Arc::new(Shared {
        peers: Mutex::new(HashMap::new()),
        peer_keys: Mutex::new(HashMap::new()),
        denied: Mutex::new(HashSet::new()),
        tokens: Mutex::new(Tokens {
            lan: random_token(),
            code: Vec::new(),
        }),
        open: AtomicBool::new(true),
        max_peers: max_players as usize - usize::from(host_has_player),
        next_peer: AtomicU32::new(1),
        ev_tx: Mutex::new(ev_tx),
        relays_up: AtomicUsize::new(0),
        relays_total: AtomicUsize::new(relays_total),
        local_addr: Mutex::new(None),
        online_addr: Mutex::new(None),
        host_keys: id.keys().clone(),
        attestation: id.attestation().map(str::to_string),
        inbox_relays: id.inbox_relays().to_vec(),
        relay_key: relay_keys.public_key(),
        room_name: room.name.clone(),
        path_override,
    });
    let task = task(
        code.clone(),
        RoomInfo {
            name: room.name,
            max_players,
        },
        relay_keys,
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
    /// The room code (also delivered in `Ready`).
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn poll(&self) -> Option<HostEvent> {
        let (ev, counter) = self.events.lock().ok()?.try_recv().ok()?;
        if let Some(c) = counter {
            c.fetch_sub(1, Ordering::AcqRel);
        }
        Some(ev)
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
        self.remove_peer(peer, true, close::KICKED);
    }

    /// Disconnect a peer without banning it (e.g. it was refused because the
    /// room was full or a match was running): it may dial back in. Emits
    /// `PeerLeft{Kicked}`.
    pub fn disconnect(&self, peer: PeerId) {
        self.remove_peer(peer, false, close::KICKED);
    }

    /// As [`disconnect`](Self::disconnect), for a joiner that did not confirm
    /// in time: its client sees `Disconnected(ConfirmTimeout)`, not `Kicked`.
    pub fn confirm_timeout(&self, peer: PeerId) {
        self.remove_peer(peer, false, close::CONFIRM_TIMEOUT);
    }

    fn remove_peer(&self, peer: PeerId, ban: bool, code: u32) {
        let link = self
            .shared
            .peers
            .lock()
            .ok()
            .and_then(|mut p| p.remove(&peer));
        if let Some(l) = link {
            if let Some(pk) = self
                .shared
                .peer_keys
                .lock()
                .ok()
                .and_then(|mut k| k.remove(&peer))
            {
                if ban {
                    if let Ok(mut d) = self.shared.denied.lock() {
                        d.insert(pk);
                    }
                }
            }
            crate::runtime().spawn(async move {
                tokio::time::sleep(KICK_FLUSH).await;
                l.conn.close(code.into(), b"kicked");
            });
            self.shared.emit(HostEvent::PeerLeft {
                peer,
                reason: LeaveReason::Kicked,
            });
        }
    }

    /// Open: answer the code on relays, broadcast the LAN beacon, accept new
    /// players. Closed (match running): none of those.
    /// Each change rotates the LAN admission token, so a token heard in an
    /// earlier lobby does not admit anyone later.
    pub fn set_open(&self, open: bool) {
        if self.shared.open.swap(open, Ordering::Relaxed) != open {
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
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.shutdown_inner(Duration::from_millis(200));
    }
}

struct HostTask {
    cfg: NetConfig,
    keys: Keys,
    room: RoomInfo,
    code: String,
    shared: Arc<Shared>,
    /// Tests pin the UTC day; otherwise it follows the clock.
    fixed_day: Option<u64>,
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

impl HostTask {
    async fn run(
        self,
        relay: Option<Box<dyn RendezvousRelay>>,
        mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    ) {
        let online = upnp_wanted(relay.is_some(), self.cfg.vpn_active);
        let prep = match prepare(
            self.cfg.quic_port,
            online,
            self.cfg.stun.clone(),
            self.cfg.lan_socket_hook.clone(),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                self.shared.emit(HostEvent::Failed { reason: e });
                return;
            }
        };
        // With a LAN hook there are two endpoints: the LAN one (hooked; its
        // port goes in the LAN candidates and the beacon) and the online one
        // (never hooked; STUN, UPnP and IPv6). Without a hook there is one.
        let (lan_socket, online_socket) = match prep.lan_socket {
            Some(lan) => (lan, Some(prep.socket)),
            None => (prep.socket, None),
        };
        let endpoint = match quic::server_endpoint(lan_socket, &self.cfg.app_tag) {
            Ok(ep) => ep,
            Err(e) => {
                self.shared.emit(HostEvent::Failed { reason: e });
                return;
            }
        };
        let online_ep = match online_socket.map(|s| quic::server_endpoint(s, &self.cfg.app_tag)) {
            Some(Ok(ep)) => Some(ep),
            Some(Err(e)) => {
                self.shared.emit(HostEvent::Failed { reason: e });
                return;
            }
            None => None,
        };
        let local = endpoint.local_addr().ok();
        if let Ok(mut a) = self.shared.local_addr.lock() {
            *a = local;
        }
        if let Ok(mut a) = self.shared.online_addr.lock() {
            *a = online_ep.as_ref().and_then(|e| e.local_addr().ok());
        }
        log::info!(
            "[host] listening on {local:?} (online {:?}), code {}, candidates {:?}",
            online_ep.as_ref().and_then(|e| e.local_addr().ok()),
            self.code,
            prep.candidates
        );

        // Listen on today's and yesterday's room tag (a joiner whose clock has
        // already passed midnight, or a room opened before midnight). Only an
        // online host pays for the derivation.
        let mut day = self.fixed_day.unwrap_or_else(utc_today);
        let mut secrets: Vec<RoomSecrets> = Vec::new();
        if relay.is_some() {
            secrets = match derive_days(&self.cfg.app_tag, &self.code, day).await {
                Ok(s) => s,
                Err(e) => {
                    self.shared.emit(HostEvent::Failed { reason: e });
                    return;
                }
            };
        }
        self.set_code_tokens(&secrets);
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
        let mapping = Arc::new(Mutex::new(prep.mapping));
        let mut last_upnp_check = Instant::now();
        self.shared.emit(HostEvent::Ready {
            code: self.code.clone(),
        });

        let punchers = Punchers {
            online: Arc::new(prep.punch_socket),
            lan: prep.lan_punch_socket.map(Arc::new),
        };
        let mut beacon = BeaconSender::new(self.cfg.lan_port, self.cfg.lan_socket_hook.as_ref());
        let mut last_beacon = Instant::now() - BEACON_EVERY;
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seen: HashSet<nostr::EventId> = HashSet::new();
        let mut offers = Offers::default();
        let mut done: Option<mpsc::Sender<()>> = None;

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
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
                    Some(Cmd::SetOpen(open)) => {
                        if let Some(r) = &relay {
                            let _ = if open { r.subscribe(filter.clone()) } else { r.unsubscribe() };
                        }
                        if open {
                            last_beacon = Instant::now() - BEACON_EVERY;
                        }
                    }
                    Some(Cmd::Shutdown(tx)) => { done = Some(tx); break; }
                    None => break,
                },
                _ = tick.tick() => {
                    let open = self.shared.open.load(Ordering::Relaxed);
                    if let Some(r) = &relay {
                        let now_day = self.fixed_day.unwrap_or_else(utc_today);
                        if now_day > day {
                            // Midnight UTC: roll to the new today + yesterday.
                            match derive_days(&self.cfg.app_tag, &self.code, now_day).await {
                                Ok(s) => {
                                    day = now_day;
                                    secrets = s;
                                    self.set_code_tokens(&secrets);
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
                            self.on_offer(&ev, &secrets, r.as_ref(), &prep.candidates, &mut offers, &punchers, open);
                        }
                    }
                    if open && last_beacon.elapsed() >= BEACON_EVERY {
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
        self.shared.close_all(close::HOST_SHUTDOWN, b"host left");
        endpoint.close(close::HOST_SHUTDOWN.into(), b"host left");
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
            tokio::join!(endpoint.wait_idle(), async {
                if let Some(ep) = &online_ep {
                    ep.wait_idle().await;
                }
            });
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

    fn set_code_tokens(&self, secrets: &[RoomSecrets]) {
        if let Ok(mut t) = self.shared.tokens.lock() {
            t.code = secrets.iter().map(|s| s.admit).collect();
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
                    punchers.send(a.targets.clone(), offer.session.clone());
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
                current_candidates(my_candidates, &punchers.online)
            } else {
                Vec::new()
            },
            sent_at: now,
            // Inside the ciphertext only: the joiner requires the welcome to be
            // signed by this key (review-net-1 N1).
            host_pubkey: self.shared.host_keys.public_key().to_hex(),
        };
        // Signed with the room's throwaway key, never the host identity.
        let Ok(event) = seal_answer(&self.keys, &ev.pubkey, &answer) else {
            return;
        };
        let _ = relay.publish(&event);
        let targets = punch_targets(&offer.candidates);
        log::info!(
            "[host] answered offer {} ({}), punch targets {targets:?}",
            offer.session.get(..8).unwrap_or("?"),
            refusal.unwrap_or("accepted")
        );
        if refusal.is_none() {
            punchers.send(targets.clone(), offer.session.clone());
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
/// address that rotated while the room was open is not advertised stale.
fn current_candidates(gathered: &[Candidate], socket: &UdpSocket) -> Vec<Candidate> {
    match socket.local_addr() {
        Ok(local) if local.is_ipv6() => crate::nat::candidates::refresh_v6(
            gathered,
            crate::nat::candidates::local_outbound_v6(),
            local.port(),
        ),
        _ => gathered.to_vec(),
    }
}

/// Clones of the QUIC sockets that send punches. Targets on the local network
/// go out of the LAN endpoint's socket (hooked, so a VPN doesn't swallow them);
/// everything else goes out of the online one, over the phone's normal route.
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
    pub candidates: Vec<Candidate>,
    pub mapping: Option<crate::nat::upnp::PortMapping>,
    /// Whether a router mapping was asked for (see [`upnp_wanted`]).
    #[cfg_attr(not(test), allow(dead_code))]
    pub upnp_attempted: bool,
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
    tokio::task::spawn_blocking(move || {
        let split = lan_hook.is_some();
        // The online socket (the only one without a hook).
        let online_port = if split { 0 } else { port };
        let socket = crate::nat::addr::bind_dual_stack(online_port)
            .map_err(|e| format!("could not bind UDP port {online_port}: {e}"))?;
        let local = socket
            .local_addr()
            .map_err(|e| format!("socket has no address: {e}"))?;
        let mapping_thread = upnp.then(|| {
            std::thread::spawn(move || {
                let v4 = crate::nat::candidates::local_outbound_v4()?;
                let internal = SocketAddr::new(std::net::IpAddr::V4(v4), local.port());
                crate::nat::upnp::map_port(internal, crate::nat::upnp::SEARCH_TIMEOUT)
                    .map_err(|e| log::info!("[nat] no router mapping: {e}"))
                    .ok()
            })
        });
        let mut candidates = gather(&socket, None, &stun, Duration::from_secs(1));
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
        if split {
            let lan = crate::nat::addr::bind_dual_stack(port)
                .map_err(|e| format!("could not bind UDP port {port}: {e}"))?;
            // Local joiners dial this socket, and it must answer them on the
            // local network, so it is bound there before anything is sent
            // from it. Nothing else is ever sent from it: no STUN, no UPnP.
            let _ = crate::netbind::bind_lan(lan_hook.as_ref(), &lan);
            let lan_local = lan
                .local_addr()
                .map_err(|e| format!("socket has no address: {e}"))?;
            // Its own gather names only itself (no STUN servers, no UPnP);
            // of that, only the LAN candidate is used.
            let mut lan_candidates: Vec<Candidate> =
                gather(&lan, None, &[], Duration::from_millis(1))
                    .into_iter()
                    .filter(|c| c.kind == crate::nat::candidates::CandidateKind::Lan.as_str())
                    .collect();
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
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let removed = self
            .shared
            .peers
            .lock()
            .map(|mut p| p.remove(&self.peer).is_some())
            .unwrap_or(false);
        if let Ok(mut k) = self.shared.peer_keys.lock() {
            k.remove(&self.peer);
        }
        if removed {
            self.conn.close(close::LEAVE.into(), b"internal error");
        }
        if removed && self.announced {
            self.shared.emit(HostEvent::PeerLeft {
                peer: self.peer,
                reason: LeaveReason::Error("internal error".into()),
            });
        }
    }
}

/// Why a seat can't be given right now, if it can't.
fn seat_refusal(shared: &Shared, peers: &HashMap<PeerId, Link>) -> Option<u32> {
    if !shared.open.load(Ordering::Relaxed) {
        Some(close::CLOSED)
    } else if peers.len() >= shared.max_peers {
        Some(close::FULL)
    } else {
        None
    }
}

/// One incoming connection: handshake, admit or refuse, then pump until it ends.
///
/// The handshake (see `quic`) runs in this order, all within
/// `HANDSHAKE_TIMEOUT`: the hello must prove admission before the joiner
/// learns anything about this host; only then is the welcome sent; the joiner
/// says who it is only after verifying that welcome, and is checked against
/// the kick deny-list and seated only then.
pub(crate) async fn accept_peer(incoming: quinn::Incoming, shared: Arc<Shared>) {
    // Shown as IPv4 when the joiner is IPv4 (it arrives v4-mapped).
    let remote = crate::nat::addr::canonical(incoming.remote_address());
    let setup = async {
        let conn = incoming
            .accept()
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
        let refuse = |conn: &quinn::Connection, code: u32, why: String| {
            conn.close(code.into(), why.as_bytes());
            Err(why)
        };
        let (mut send, mut recv, hello) = match quic::server_read_hello(&conn).await {
            Ok(x) => x,
            Err((code, why)) => return refuse(&conn, code, why),
        };
        // Admission: the hello must prove the room code or the LAN token
        // before anything about this host is sent.
        let b = quic::binding(&conn)?;
        if !quic::admitted(&hello, &b, &shared.admission_tokens()) {
            return refuse(
                &conn,
                close::NOT_ADMITTED,
                "no valid admission proof".into(),
            );
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
        let peer = PeerId(shared.next_peer.fetch_add(1, Ordering::Relaxed));
        quic::server_send_welcome(
            &conn,
            &mut send,
            &shared.host_keys,
            shared.attestation.as_deref(),
            &shared.inbox_relays,
            &shared.room_name,
            &shared.relay_key,
            hello.session.as_deref(),
            peer.0,
        )
        .await?;
        // The joiner verified us; now it says who it is.
        let host_pk = shared.host_keys.public_key();
        let (pk, attestation, inbox_relays) =
            match quic::server_read_identify(&conn, &mut recv, hello.session.as_deref(), &host_pk)
                .await
            {
                Ok(x) => x,
                Err((code, why)) => return refuse(&conn, code, why),
            };
        if shared
            .denied
            .lock()
            .map(|d| d.contains(&pk))
            .unwrap_or(false)
        {
            return refuse(&conn, close::KICKED, "kicked earlier".into());
        }
        Ok((conn, send, recv, hello, pk, attestation, inbox_relays, peer))
    };
    let (conn, mut send, recv, hello, pubkey, attestation, inbox_relays, peer) =
        match tokio::time::timeout(quic::HANDSHAKE_TIMEOUT, setup).await {
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

    // Seat under the lock so two simultaneous joiners can't both take the last seat.
    let (link, out_rx) = Link::new(conn.clone());
    let refused = match shared.peers.lock() {
        Ok(mut peers) => {
            let r = seat_refusal(&shared, &peers);
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
    };
    if let Ok(mut k) = shared.peer_keys.lock() {
        k.insert(peer, pubkey);
    }
    if let Err(e) = quic::server_send_accepted(&mut send).await {
        log::info!("[host] {remote}: accept failed: {e}");
        return; // the guard removes the peer
    }
    let path = shared.path_override.unwrap_or(hello.path);
    log::info!("[host] {peer} joined from {remote} via {path:?}");
    shared.emit(HostEvent::PeerJoined {
        peer,
        pubkey,
        path,
        rtt_ms: link.rtt_ms(),
        attestation,
        inbox_relays,
    });
    guard.announced = true;

    let (s1, s2) = (Arc::clone(&shared), Arc::clone(&shared));
    let (reliable_q, lossy_q) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let ended = quic::pump(
        conn,
        send,
        recv,
        out_rx,
        Arc::clone(&link.queued),
        move |bytes| {
            s1.emit_counted(
                HostEvent::Reliable { peer, bytes },
                &reliable_q,
                MAX_QUEUED_RELIABLE,
            )
        },
        move |bytes| {
            // Over the cap: dropped, as the network might have.
            s2.emit_counted(HostEvent::Lossy { peer, bytes }, &lossy_q, MAX_QUEUED_LOSSY);
        },
    )
    .await;
    guard.armed = false;
    if let Ok(mut k) = shared.peer_keys.lock() {
        k.remove(&peer);
    }
    // Whoever removes the link reports the leave (kick already did).
    let removed = shared
        .peers
        .lock()
        .map(|mut p| p.remove(&peer).is_some())
        .unwrap_or(false);
    if removed {
        let reason = match ended {
            Ended::Remote(close::KICKED) => LeaveReason::Kicked,
            Ended::Remote(_) => LeaveReason::Left,
            Ended::TimedOut => LeaveReason::TimedOut,
            Ended::Local => LeaveReason::Error("closed locally".into()),
            Ended::Error(e) => LeaveReason::Error(e),
        };
        log::info!("[host] {peer} left: {reason:?}");
        shared.emit(HostEvent::PeerLeft { peer, reason });
    }
}
