//! One QUIC endpoint (one UDP socket) serving many rooms of one or more apps.
//!
//! A [`Listener`] binds the socket and gathers the candidates once; each
//! [`Listener::host`] opens a room on it, which behaves as a room from
//! [`crate::host`] does (its own code, relay answers, LAN beacon, peers,
//! deny list, events). An incoming connection is told apart in two steps:
//! the application protocol (ALPN) the joiner negotiated picks the app, and
//! the admission token its hello proves picks the room among that app's
//! rooms. Nothing on the wire changes: a joiner cannot tell a room on a
//! listener from a room with its own socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use crate::host::{
    self, prepare_advertising, upnp_wanted, Advertise, Arriving, Cmd, HostHandle, HostTask,
    Punchers, Shared, MAX_INVITES, UPNP_RENEW_CHECK,
};
use crate::quic::{self, close};
use crate::relay::{MultiRelay, RendezvousRelay};
use crate::rendezvous::Candidate;
use crate::room::InviteId;
use crate::{HostEvent, Identity, LanSocketHook, NetConfig, RoomInfo};

/// The endpoint-level settings of a [`Listener`]: what [`NetConfig`] says
/// about the socket, the candidates and the QUIC transport. Everything else
/// (the app tag, relays, LAN beacon port, whether the host has a seat, the
/// reliable limits, the exporter label, the attestation) stays per room, on
/// the [`NetConfig`] passed to [`Listener::host`]; a room's own values for
/// the fields below are ignored.
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    /// UDP port QUIC binds. 0 = ephemeral. See [`NetConfig::quic_port`].
    pub quic_port: u16,
    /// `host:port` STUN servers, asked once at bind. See [`NetConfig::stun`].
    pub stun: Vec<String>,
    /// Ask the router for a port mapping (UPnP) at bind. Never while
    /// `vpn_active` or `advertise_only`. Default true.
    pub upnp: bool,
    /// See [`NetConfig::lan_socket_hook`].
    pub lan_socket_hook: Option<LanSocketHook>,
    /// See [`NetConfig::vpn_active`].
    pub vpn_active: bool,
    /// See [`NetConfig::advertise`] (the same rules, checked at bind).
    pub advertise: Vec<SocketAddr>,
    /// See [`NetConfig::advertise_only`]. Every room on the listener then
    /// sends no LAN beacon and no hole punches.
    pub advertise_only: bool,
    /// See [`NetConfig::idle_timeout`]. The QUIC transport is the
    /// endpoint's, so this is every room's.
    pub idle_timeout: Duration,
    /// See [`NetConfig::keep_alive`].
    pub keep_alive: Duration,
    /// Tests only: see [`NetConfig`]'s field of the same name.
    #[cfg(test)]
    pub(crate) lan_allow_loopback: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig::new()
    }
}

impl ListenerConfig {
    /// The same defaults as [`NetConfig::new`] for these fields, with a
    /// router mapping asked for.
    pub fn new() -> Self {
        ListenerConfig {
            quic_port: 0,
            stun: crate::DEFAULT_STUN.iter().map(|s| s.to_string()).collect(),
            upnp: true,
            lan_socket_hook: None,
            vpn_active: false,
            advertise: Vec::new(),
            advertise_only: false,
            idle_timeout: quic::IDLE_TIMEOUT,
            keep_alive: quic::KEEP_ALIVE,
            #[cfg(test)]
            lan_allow_loopback: true,
        }
    }

    /// The endpoint-level fields of `cfg`, as [`crate::host`] would use them
    /// (a router mapping only when it has relays).
    pub fn from_net(cfg: &NetConfig) -> Self {
        ListenerConfig {
            quic_port: cfg.quic_port,
            stun: cfg.stun.clone(),
            upnp: !cfg.relays.is_empty(),
            lan_socket_hook: cfg.lan_socket_hook.clone(),
            vpn_active: cfg.vpn_active,
            advertise: cfg.advertise.clone(),
            advertise_only: cfg.advertise_only,
            idle_timeout: cfg.idle_timeout,
            keep_alive: cfg.keep_alive,
            #[cfg(test)]
            lan_allow_loopback: cfg.lan_allow_loopback,
        }
    }

    /// A room's config with these endpoint-level fields in place of its own.
    fn apply_to(&self, cfg: &mut NetConfig) {
        cfg.quic_port = self.quic_port;
        cfg.stun = self.stun.clone();
        cfg.lan_socket_hook = self.lan_socket_hook.clone();
        cfg.vpn_active = self.vpn_active;
        cfg.advertise = self.advertise.clone();
        cfg.advertise_only = self.advertise_only;
        cfg.idle_timeout = self.idle_timeout;
        cfg.keep_alive = self.keep_alive;
        #[cfg(test)]
        {
            cfg.lan_allow_loopback = self.lan_allow_loopback;
        }
    }
}

impl From<&NetConfig> for ListenerConfig {
    fn from(cfg: &NetConfig) -> Self {
        ListenerConfig::from_net(cfg)
    }
}

/// One room's entry on its listener.
struct Room {
    id: u64,
    shared: Arc<Shared>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
}

/// One app on the listener: its protocol, its rooms (in the order they
/// opened), its listener-level invites and which room they land in.
struct App {
    tag: String,
    alpn: Vec<u8>,
    rooms: Vec<Room>,
    invites: HashMap<InviteId, [u8; 32]>,
    target: Option<u64>,
}

impl App {
    fn room(&self, id: u64) -> Option<&Room> {
        self.rooms.iter().find(|r| r.id == id)
    }
}

#[derive(Default)]
struct State {
    closed: bool,
    next_room: u64,
    apps: Vec<App>,
}

impl State {
    fn app(&self, tag: &str) -> Option<&App> {
        self.apps.iter().find(|a| a.tag == tag)
    }
    fn app_mut(&mut self, tag: &str) -> Option<&mut App> {
        self.apps.iter_mut().find(|a| a.tag == tag)
    }
}

/// What a listener's rooms share. Lock order: the listener's `state`, then
/// any room's own locks.
pub(crate) struct ListenerShared {
    cfg: ListenerConfig,
    live: quic::Liveness,
    cert: quic::ServerCert,
    /// The LAN endpoint (the only one without a hook), then the online one.
    endpoints: Vec<quinn::Endpoint>,
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) announced: Vec<Candidate>,
    pub(crate) punchers: Punchers,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) online: Option<SocketAddr>,
    /// Peer ids are unique on the endpoint, across rooms.
    next_peer: Arc<AtomicU32>,
    state: Mutex<State>,
}

impl ListenerShared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register `tag`'s protocol on the endpoint if it is new.
    fn ensure_app<'a>(&self, st: &'a mut State, tag: &str) -> Result<&'a mut App, String> {
        if st.app(tag).is_none() {
            let mut alpns: Vec<Vec<u8>> = st.apps.iter().map(|a| a.alpn.clone()).collect();
            let alpn = quic::alpn(tag);
            alpns.push(alpn.clone());
            let config = quic::server_config_for(&self.cert, alpns, self.live)?;
            for ep in &self.endpoints {
                ep.set_server_config(Some(config.clone()));
            }
            st.apps.push(App {
                tag: tag.to_string(),
                alpn,
                rooms: Vec::new(),
                invites: HashMap::new(),
                target: None,
            });
        }
        st.app_mut(tag).ok_or_else(|| "app vanished".to_string())
    }

    /// The live rooms of the app whose protocol is `alpn`, in the order they
    /// opened; `None` for a protocol no app here uses.
    fn rooms_for(&self, alpn: &[u8]) -> Option<Vec<Arc<Shared>>> {
        let st = self.lock();
        let app = st.apps.iter().find(|a| a.alpn == alpn)?;
        Some(
            app.rooms
                .iter()
                .filter(|r| !r.shared.is_retired())
                .map(|r| Arc::clone(&r.shared))
                .collect(),
        )
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
}

/// A room's place on its listener. It holds the listener weakly: a room's
/// handle can outlive the listener, and must not keep its socket bound.
pub(crate) struct Seat {
    listener: Weak<ListenerShared>,
    room: u64,
    app: String,
}

/// What a room on a listener starts with.
pub(crate) struct Placement {
    pub(crate) seat: Seat,
    pub(crate) code: String,
    pub(crate) next_peer: Arc<AtomicU32>,
}

impl Seat {
    /// The listener, while it is alive.
    pub(crate) fn listener(&self) -> Option<Arc<ListenerShared>> {
        self.listener.upgrade()
    }

    /// Leave the listener: no longer demuxed to, no longer an invite target.
    pub(crate) fn leave(&self) {
        let Some(listener) = self.listener() else {
            return;
        };
        let mut st = listener.lock();
        if let Some(app) = st.app_mut(&self.app) {
            app.rooms.retain(|r| r.id != self.room);
            if app.target == Some(self.room) {
                app.target = None;
            }
        }
    }

    /// A code no other room of this app on the listener holds (and not
    /// `old`), handed to `install` while the listener is locked.
    pub(crate) fn fresh_code(
        &self,
        app_tag: &str,
        old: &str,
        install: impl FnOnce(&str),
    ) -> Result<String, String> {
        let listener = self
            .listener()
            .ok_or_else(|| "the listener is shut down".to_string())?;
        let st = listener.lock();
        let taken: Vec<String> = st
            .app(app_tag)
            .map(|a| {
                a.rooms
                    .iter()
                    .filter(|r| r.id != self.room)
                    .map(|r| r.shared.current_code())
                    .collect()
            })
            .unwrap_or_default();
        let new = unique_code(&taken, old);
        install(&new);
        Ok(new)
    }

    pub(crate) fn is_target(&self) -> bool {
        self.listener().is_some_and(|l| {
            l.lock()
                .app(&self.app)
                .is_some_and(|a| a.target == Some(self.room))
        })
    }

    pub(crate) fn set_target(&self, room: &Shared, on: bool) -> Result<(), String> {
        let listener = self
            .listener()
            .ok_or_else(|| "the listener is shut down".to_string())?;
        let mut st = listener.lock();
        if st.closed || room.is_retired() {
            return Err("the room is shut down".into());
        }
        let app = st
            .app_mut(&self.app)
            .filter(|a| a.room(self.room).is_some())
            .ok_or("the room is not on its listener")?;
        if on {
            let previous = app.target.replace(self.room);
            if previous == Some(self.room) {
                return Ok(());
            }
            if let Some(prev) = previous.and_then(|p| app.room(p)) {
                prev.shared.strip_keep_invites(None);
                let _ = prev.cmd_tx.send(Cmd::InvitesChanged);
            }
        } else {
            if app.target != Some(self.room) {
                return Ok(());
            }
            app.target = None;
            room.strip_keep_invites(None);
        }
        if let Some(me) = app.room(self.room) {
            let _ = me.cmd_tx.send(Cmd::InvitesChanged);
        }
        Ok(())
    }

    /// Run `f` with the listener-level invites this room answers (empty
    /// unless it is its app's target), the listener locked throughout.
    pub(crate) fn with_target_invites<R>(
        &self,
        app_tag: &str,
        f: impl FnOnce(&HashMap<InviteId, [u8; 32]>) -> R,
    ) -> R {
        let Some(listener) = self.listener() else {
            return f(&HashMap::new());
        };
        let st = listener.lock();
        match st
            .app(app_tag)
            .filter(|a| a.target == Some(self.room) && a.room(self.room).is_some())
        {
            Some(app) => f(&app.invites),
            None => f(&HashMap::new()),
        }
    }
}

/// A fresh room code that is neither `old` nor in `taken`.
fn unique_code(taken: &[String], old: &str) -> String {
    loop {
        let code = crate::room::generate_code();
        if code != old && !taken.contains(&code) {
            return code;
        }
    }
}

enum ListenerCmd {
    Shutdown(mpsc::Sender<()>),
}

/// One UDP socket and one QUIC endpoint for many rooms of one or more apps
/// (a Keep's). Rooms opened with [`Listener::host`] behave as rooms from
/// [`crate::host`] do; this owns what they share: the socket, the endpoint,
/// the candidates gathered once at bind, the router mapping, and the
/// listener-level invites ([`Listener::add_invite`]).
///
/// Dropping or shutting down the listener closes every room on it.
pub struct Listener {
    shared: Arc<ListenerShared>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<ListenerCmd>,
    shut: AtomicBool,
}

impl Listener {
    /// Bind the socket and gather the candidates (UPnP, STUN, IPv6 and the
    /// advertised addresses, as a host does at start). Blocks until that is
    /// done: up to the STUN and router timeouts (a few seconds), or at once
    /// for an advertise-only listener. Call it from outside any async runtime.
    pub fn bind(cfg: ListenerConfig) -> Result<Listener, String> {
        let live = quic::Liveness::new(cfg.idle_timeout, cfg.keep_alive)?;
        let advertised = crate::checked_advertise(
            &cfg.advertise,
            cfg.advertise_only,
            cfg.lan_socket_hook.is_some(),
            cfg.quic_port,
        )?;
        let (ready_tx, ready_rx) = mpsc::channel();
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        crate::runtime().spawn(run_listener(cfg, live, advertised, ready_tx, cmd_rx));
        let shared = ready_rx
            .recv()
            .map_err(|_| "the listener task ended".to_string())??;
        Ok(Listener {
            shared,
            cmd_tx,
            shut: AtomicBool::new(false),
        })
    }

    /// Open a room on this listener. As [`crate::host`], with these
    /// differences: the endpoint-level fields of `cfg` (those in
    /// [`ListenerConfig`]) are the listener's; the room's code is unique
    /// among this listener's rooms of `cfg.app_tag`; its `app_tag`'s protocol
    /// is registered on the endpoint if new. Several rooms may use the same
    /// [`Identity`]. Watch [`HostHandle::poll`] for `Ready` or `Failed`.
    ///
    /// The room is reachable as soon as this returns (its LAN token exists
    /// and the listener's address is known), so a direct join can be seated,
    /// and `PeerJoined` queued, before the room's `Ready`. A room of its own
    /// ([`crate::host`]) has no endpoint before `Ready`, so there it cannot.
    pub fn host(&self, cfg: &NetConfig, id: &Identity, room: RoomInfo) -> HostHandle {
        let relay: Option<Box<dyn RendezvousRelay>> = if cfg.relays.is_empty() {
            None
        } else {
            Some(Box::new(MultiRelay::start_in(
                decented_relays::RelayPool::global(),
                cfg.relays.clone(),
                cfg.relay_fallback,
            )))
        };
        self.host_with_relay(cfg, id, room, relay)
    }

    /// [`Listener::host`] over a caller-supplied relay (`None` = LAN only).
    pub fn host_with_relay(
        &self,
        cfg: &NetConfig,
        id: &Identity,
        room: RoomInfo,
        relay: Option<Box<dyn RendezvousRelay>>,
    ) -> HostHandle {
        let id = crate::virt::host_identity(cfg, id, false);
        let mut cfg = cfg.clone();
        self.shared.cfg.apply_to(&mut cfg);
        let relays_total = cfg.relays.len();
        let mut st = self.shared.lock();
        let closed = st.closed;
        let refused = if closed {
            Some("the listener is shut down".to_string())
        } else {
            self.shared.ensure_app(&mut st, &cfg.app_tag).err()
        };
        if let Some(reason) = refused {
            drop(st);
            return host::start_host(
                &id,
                room,
                cfg.host_has_player,
                relays_total,
                None,
                cfg.app_tag.clone(),
                cfg.app_binding_label.clone(),
                cfg.host_limits(),
                None,
                move |_code, _room, shared, _cmd_rx| async move {
                    shared.retire();
                    if closed {
                        // The listener's shutdown, told as every room is.
                        shared.tell_listener_closed();
                    } else {
                        shared.emit(HostEvent::Failed { reason });
                    }
                },
            );
        }
        let room_id = st.next_room;
        st.next_room += 1;
        let taken: Vec<String> = st
            .app(&cfg.app_tag)
            .map(|a| a.rooms.iter().map(|r| r.shared.current_code()).collect())
            .unwrap_or_default();
        let placement = Placement {
            seat: Seat {
                listener: Arc::downgrade(&self.shared),
                room: room_id,
                app: cfg.app_tag.clone(),
            },
            code: unique_code(&taken, ""),
            next_peer: Arc::clone(&self.shared.next_peer),
        };
        let app_tag = cfg.app_tag.clone();
        let handle = host::start_host_with(
            &id,
            room,
            cfg.host_has_player,
            relays_total,
            None,
            cfg.app_tag.clone(),
            cfg.app_binding_label.clone(),
            cfg.host_limits(),
            None,
            Some(placement),
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
        );
        // Registered before the lock is released: the room's task takes it
        // before it touches the table (to sync invites, or to leave).
        if let Some(app) = st.app_mut(&app_tag) {
            app.rooms.push(Room {
                id: room_id,
                shared: handle.shared_arc(),
                cmd_tx: handle.cmd_sender(),
            });
        }
        handle
    }

    /// Let people into `app_tag`'s rooms on this listener by **invite**: an
    /// invite join lands in that app's invite target room
    /// ([`HostHandle::set_invite_target`]) and is reported there as
    /// [`crate::Admission::Invite`], as with [`HostHandle::add_invite`]. With
    /// no target room open, invite joins are refused as for an invite that
    /// is not live (no answer; a direct hello is not admitted).
    ///
    /// `secret` follows [`HostHandle::add_invite`]'s rules (uniformly random;
    /// the link carries it with the host's public key, so the target room
    /// must present the key the invite names). Returns the invite's id; the
    /// same secret again returns the same id. At most [`MAX_INVITES`] per
    /// app: beyond that this returns an error. These share the target room's
    /// relay subscription with its own invites; the target room's one
    /// subscription then carries its own invites' tags and these, up to
    /// twice [`MAX_INVITES`] in all, so a Keep should hold a handful. Give
    /// each room and the listener different secrets: if two rooms of an app
    /// hold the same one, a join with it is credited to the room opened first.
    pub fn add_invite(&self, app_tag: &str, secret: [u8; 32]) -> Result<InviteId, String> {
        let id = InviteId::of(&secret);
        let mut st = self.shared.lock();
        if st.closed {
            return Err("the listener is shut down".into());
        }
        let app = self.shared.ensure_app(&mut st, app_tag)?;
        if !app.invites.contains_key(&id) && app.invites.len() >= MAX_INVITES {
            return Err(format!("too many invites (at most {MAX_INVITES})"));
        }
        app.invites.insert(id, secret);
        if let Some(target) = app.target.and_then(|t| app.room(t)) {
            let _ = target.cmd_tx.send(Cmd::InvitesChanged);
        }
        Ok(id)
    }

    /// Revoke a listener-level invite. From the moment this returns, a hello
    /// proving it is refused, and so is one already mid-handshake (checked
    /// again at the seat); the target room stops listening on its tags on
    /// its next turn. `false` if no such invite was live. As with
    /// [`HostHandle::remove_invite`], connections it admitted stay: the game
    /// decides whether to kick them.
    pub fn remove_invite(&self, app_tag: &str, id: InviteId) -> bool {
        let mut st = self.shared.lock();
        let Some(app) = st.app_mut(app_tag) else {
            return false;
        };
        let removed = app.invites.remove(&id).is_some();
        if removed {
            if let Some(target) = app.target.and_then(|t| app.room(t)) {
                target.shared.strip_keep_invites(Some(id));
                let _ = target.cmd_tx.send(Cmd::InvitesChanged);
            }
        }
        removed
    }

    /// The candidates every room on this listener announces, as gathered at
    /// bind: the discovered ones, then the advertised addresses. The same
    /// list the `[listener] listening on` and each room's `[host] listening
    /// on` log line print.
    pub fn announced(&self) -> Vec<Candidate> {
        self.shared.announced.clone()
    }

    /// The local QUIC address (with a LAN socket hook, the LAN endpoint's).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.shared.local
    }

    /// The online endpoint's address; differs from
    /// [`local_addr`](Self::local_addr) only with a LAN socket hook.
    pub fn online_addr(&self) -> Option<SocketAddr> {
        self.shared.online.or(self.shared.local)
    }

    /// Whether the listener has been shut down (by [`Listener::shutdown`] or
    /// a drop in progress): it takes no new rooms and its rooms are closing
    /// or closed.
    pub fn is_closed(&self) -> bool {
        self.shut.load(Ordering::Relaxed) || self.shared.lock().closed
    }

    /// How many rooms are open on the listener now.
    pub fn room_count(&self) -> usize {
        self.shared.lock().apps.iter().map(|a| a.rooms.len()).sum()
    }

    /// Close every room (each peer hears the host left), then the endpoint,
    /// and release the router mapping. Blocks for at most ~1 s.
    ///
    /// Each room's handle is told: its [`poll`](HostHandle::poll) yields
    /// [`HostEvent::Failed`] with the reason "the listener shut down" (once;
    /// the `PeerLeft` of its peers may come before or after it), and
    /// [`HostHandle::is_closed`] is `true`. A room closed by its own handle's
    /// `shutdown` or drop is not told, as it asked. The UDP port is freed
    /// shortly after this returns, even while room handles are still held.
    pub fn shutdown(self) {
        self.shutdown_inner(Duration::from_millis(1000));
    }

    pub(crate) fn shutdown_inner(&self, wait: Duration) {
        if self.shut.swap(true, Ordering::Relaxed) {
            return;
        }
        let deadline = Instant::now() + wait;
        let rooms: Vec<_> = {
            let mut st = self.shared.lock();
            st.closed = true;
            st.apps
                .iter()
                .flat_map(|a| a.rooms.iter().map(|r| r.cmd_tx.clone()))
                .collect()
        };
        let acks: Vec<mpsc::Receiver<()>> = rooms
            .iter()
            .filter_map(|tx| {
                let (ack, done) = mpsc::channel();
                tx.send(Cmd::ListenerShutdown(ack)).ok().map(|_| done)
            })
            .collect();
        for done in acks {
            let _ = done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
        let (ack, done) = mpsc::channel();
        if self.cmd_tx.send(ListenerCmd::Shutdown(ack)).is_ok() {
            let left = deadline.saturating_duration_since(Instant::now());
            let _ = done.recv_timeout(left.max(Duration::from_millis(100)));
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.shutdown_inner(Duration::from_millis(200));
    }
}

/// Bind, gather, report, then accept until shut down.
async fn run_listener(
    cfg: ListenerConfig,
    live: quic::Liveness,
    advertised: Vec<Candidate>,
    ready: mpsc::Sender<Result<Arc<ListenerShared>, String>>,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<ListenerCmd>,
) {
    let only = cfg.advertise_only;
    let upnp = upnp_wanted(cfg.upnp, cfg.vpn_active) && !only;
    let prep = match prepare_advertising(
        cfg.quic_port,
        upnp,
        cfg.stun.clone(),
        cfg.lan_socket_hook.clone(),
        Advertise {
            list: advertised,
            only,
        },
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let announced = prep.announced();
    let (lan_socket, online_socket) = match prep.lan_socket {
        Some(lan) => (lan, Some(prep.socket)),
        None => (prep.socket, None),
    };
    let built = (|| {
        let cert = quic::ServerCert::generate()?;
        // No app yet: each room's app registers its protocol.
        let endpoint = quic::server_endpoint_with(
            lan_socket,
            quic::server_config_for(&cert, Vec::new(), live)?,
        )?;
        let online_ep = match online_socket {
            Some(s) => Some(quic::server_endpoint_with(
                s,
                quic::server_config_for(&cert, Vec::new(), live)?,
            )?),
            None => None,
        };
        Ok::<_, String>((cert, endpoint, online_ep))
    })();
    let (cert, endpoint, online_ep) = match built {
        Ok(x) => x,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let local = endpoint.local_addr().ok();
    let online = online_ep.as_ref().and_then(|e| e.local_addr().ok());
    let mut endpoints = vec![endpoint.clone()];
    endpoints.extend(online_ep.clone());
    let shared = Arc::new(ListenerShared {
        cfg,
        live,
        cert,
        endpoints,
        candidates: prep.candidates,
        announced: announced.clone(),
        punchers: Punchers {
            online: Arc::new(prep.punch_socket),
            lan: prep.lan_punch_socket.map(Arc::new),
        },
        local,
        online,
        next_peer: Arc::new(AtomicU32::new(1)),
        state: Mutex::new(State::default()),
    });
    log::info!("[listener] listening on {local:?} (online {online:?}), candidates {announced:?}");
    if ready.send(Ok(Arc::clone(&shared))).is_err() {
        return;
    }
    let mapping = Arc::new(Mutex::new(prep.mapping));
    let mut renew = tokio::time::interval_at(
        tokio::time::Instant::now() + UPNP_RENEW_CHECK,
        UPNP_RENEW_CHECK,
    );
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut done: Option<mpsc::Sender<()>> = None;
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                // As a host's: the hooked LAN endpoint serves local sources only.
                if online_ep.is_some() && !shared.lan_source_ok(incoming.remote_address()) {
                    log::info!("[listener] ignoring a non-local source on the LAN endpoint: {}", incoming.remote_address());
                    incoming.ignore();
                    continue;
                }
                tokio::spawn(demux(incoming, Arc::clone(&shared)));
            }
            incoming = async {
                match &online_ep {
                    Some(ep) => ep.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(incoming) = incoming else { break };
                tokio::spawn(demux(incoming, Arc::clone(&shared)));
            }
            cmd = cmd_rx.recv() => match cmd {
                Some(ListenerCmd::Shutdown(tx)) => { done = Some(tx); break; }
                None => break,
            },
            _ = renew.tick() => {
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
    // Every room still here goes too (their tasks were told by the handle's
    // shutdown; a room's peers are closed by its own task).
    let rooms: Vec<Arc<Shared>> = {
        let mut st = shared.lock();
        st.closed = true;
        st.apps
            .iter()
            .flat_map(|a| a.rooms.iter().map(|r| Arc::clone(&r.shared)))
            .collect()
    };
    for room in rooms {
        room.retire();
        room.close_all(close::HOST_SHUTDOWN, b"host left");
        // Once: a room whose task already said so does not say it twice.
        room.tell_listener_closed();
    }
    endpoint.close(close::HOST_SHUTDOWN.into(), b"host left");
    if let Some(ep) = &online_ep {
        ep.close(close::HOST_SHUTDOWN.into(), b"host left");
    }
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
    if let Some(removal) = removal {
        let _ = removal.await;
    }
    if let Some(tx) = done {
        let _ = tx.send(());
    }
    log::info!("[listener] stopped");
}

/// One incoming connection: the negotiated protocol picks the app, the
/// hello's admission proof picks the room; then the room takes it as its own.
async fn demux(incoming: quinn::Incoming, listener: Arc<ListenerShared>) {
    let started = tokio::time::Instant::now();
    let remote = crate::nat::addr::canonical(incoming.remote_address());
    let found = async {
        let conn = incoming
            .accept()
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
        let refuse = |conn: &quinn::Connection, code: u32, why: String| {
            conn.close(code.into(), why.as_bytes());
            Err(why)
        };
        let Some(rooms) = quic::negotiated_alpn(&conn).and_then(|p| listener.rooms_for(&p)) else {
            return refuse(&conn, close::NOT_ADMITTED, "unknown application".into());
        };
        let (send, recv, hello) = match quic::server_read_hello(&conn).await {
            Ok(x) => x,
            Err((code, why)) => return refuse(&conn, code, why),
        };
        // One pass over every room's tokens, so the time taken does not say
        // which room (or whether any) the proof matched.
        let binding = quic::binding(&conn)?;
        let (owners, tokens): (Vec<usize>, Vec<[u8; 32]>) = rooms
            .iter()
            .enumerate()
            .flat_map(|(i, room)| {
                room.admission_tokens()
                    .into_iter()
                    .map(move |(_, t)| (i, t))
            })
            .unzip();
        let Some(which) = quic::admitted_which(&hello, &binding, &tokens) else {
            return refuse(
                &conn,
                close::NOT_ADMITTED,
                "no valid admission proof".into(),
            );
        };
        Ok((conn, send, recv, hello, Arc::clone(&rooms[owners[which]])))
    };
    let (conn, send, recv, hello, room) =
        match tokio::time::timeout(quic::HANDSHAKE_TIMEOUT, found).await {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => {
                log::info!("[listener] {remote}: handshake failed: {e}");
                return;
            }
            Err(_) => {
                log::info!("[listener] {remote}: handshake timed out");
                return;
            }
        };
    host::accept_arriving(
        Arriving::Demuxed {
            conn,
            send,
            recv,
            hello: Box::new(hello),
            started,
        },
        room,
    )
    .await;
}
