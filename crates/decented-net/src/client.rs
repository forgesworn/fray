//! Joining a room: by code or invite (relay rendezvous, punch, QUIC race) or
//! straight to a LAN beacon's address.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nostr::{Keys, PublicKey};

use crate::nat::candidates::{dialable, parse_addrs};
use crate::quic::{self, close, Ended, Link};
use crate::relay::{MultiRelay, RendezvousRelay, TagFilter};
use crate::rendezvous::{new_session_id, open_answer, seal_offer, Answer, Offer, KIND_JOIN_ANSWER};
use crate::room::{derive_days, derive_invite_days, normalize_code, utc_today, RoomSecrets};
use crate::{
    ClientEvent, DisconnectReason, FailReason, Identity, JoinStage, LanRoom, NetConfig, PathKind,
    NET_PROTOCOL_VERSION,
};

/// How long to wait for at least one relay to connect.
const RELAY_DEADLINE: Duration = Duration::from_secs(12);
/// How long, after the first offer went out, to wait for an answer.
const ANSWER_DEADLINE: Duration = Duration::from_secs(10);
/// Offers are re-sent this often until answered (relays don't store them).
const OFFER_EVERY: Duration = Duration::from_secs(2);
const LAN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// After the first answer, keep listening at least this long for a second
/// answer from a different key (someone racing the real host) before we
/// report `Connected`.
const ANSWER_SETTLE: Duration = Duration::from_millis(600);
/// Reliable messages from the host waiting for `poll`; one more and we drop
/// the connection (the host is flooding us).
pub const MAX_QUEUED_RELIABLE: usize = 1024;
/// Datagrams from the host waiting for `poll`; more are dropped.
pub const MAX_QUEUED_LOSSY: usize = 128;

type Queued = (ClientEvent, Option<Arc<AtomicUsize>>);

struct Shared {
    local_key: [u8; 32],
    link: Mutex<Option<Link>>,
    ev_tx: Mutex<mpsc::Sender<Queued>>,
    closing: AtomicBool,
    migration: Mutex<Option<crate::migration::ConnectionBinding>>,
}

impl Shared {
    fn emit(&self, ev: ClientEvent) {
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((ev, None));
        }
    }

    fn emit_counted(&self, ev: ClientEvent, counter: &Arc<AtomicUsize>, cap: usize) -> bool {
        if counter.fetch_add(1, Ordering::AcqRel) >= cap {
            counter.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        if let Ok(tx) = self.ev_tx.lock() {
            let _ = tx.send((ev, Some(Arc::clone(counter))));
        }
        true
    }
}

/// A connection (or connection attempt) to a host. All methods return at once.
pub struct ClientHandle {
    events: Mutex<mpsc::Receiver<Queued>>,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
    done_rx: Mutex<mpsc::Receiver<()>>,
}

pub(crate) enum Target {
    /// Code, relay, and a pinned UTC day (tests) or `None` for the clock.
    Code(String, Box<dyn RendezvousRelay>, Option<u64>),
    /// An invite's secret, the host key it pins, the relay, and a pinned UTC
    /// day (tests) or `None` for the clock. Rendezvous as a code join does.
    Invite {
        secret: [u8; 32],
        host_key: PublicKey,
        relay: Box<dyn RendezvousRelay>,
        fixed_day: Option<u64>,
    },
    /// Address and the LAN admission token (hex) from the beacon.
    Lan(
        SocketAddr,
        String,
        Option<(crate::migration::ConnectionBinding, PublicKey)>,
    ),
    /// A point-to-point packet link to the host (see `virt`). Its first
    /// packet carries the room's LAN token; then it is a LAN join.
    Virtual(crate::virt::VirtualLink),
}

/// Join by room code over the configured relays.
pub fn join(cfg: &NetConfig, id: &Identity, code: &str) -> ClientHandle {
    let relay = Box::new(MultiRelay::start_in(
        decented_relays::RelayPool::global(),
        cfg.relays.clone(),
        cfg.relay_fallback,
    ));
    spawn(cfg, id, Target::Code(code.to_string(), relay, None))
}

/// Join by **invite** over the configured relays: the 32-byte `secret` and the
/// host's public key `host_key` that an invite link carries (the host handed
/// them out after [`HostHandle::add_invite`](crate::HostHandle::add_invite)).
///
/// It finds the host the way a code join does, on relay tags derived from the
/// secret (today's, then yesterday's), so the link never holds an address and
/// a revoked invite is simply not answered. The hello proves the invite's
/// admission token, bound to the connection, never sent in the clear.
///
/// **The host is pinned.** Only a host whose welcome is signed by `host_key`
/// (and by the key the encrypted answer named) is joined; any other, even one
/// holding the secret, ends in [`FailReason::HostUnverified`] before this
/// side says who it is. Events and flow are otherwise those of [`join`]; the
/// host sees [`Admission::Invite`](crate::Admission::Invite) with the invite's
/// [`InviteId`](crate::InviteId) ([`InviteId::of`](crate::InviteId::of) the
/// secret).
pub fn join_invite(
    cfg: &NetConfig,
    id: &Identity,
    secret: &[u8; 32],
    host_key: [u8; 32],
) -> ClientHandle {
    let relay = Box::new(MultiRelay::start_in(
        decented_relays::RelayPool::global(),
        cfg.relays.clone(),
        cfg.relay_fallback,
    ));
    join_invite_with_relay(cfg, id, secret, host_key, relay)
}

/// [`join_invite`] over a caller-supplied relay (e.g. [`crate::relay::FakeRelayHub`] in tests).
pub fn join_invite_with_relay(
    cfg: &NetConfig,
    id: &Identity,
    secret: &[u8; 32],
    host_key: [u8; 32],
    relay: Box<dyn RendezvousRelay>,
) -> ClientHandle {
    spawn(cfg, id, invite_target(secret, host_key, relay, None))
}

/// [`join_invite_with_relay`] pinned to UTC day `day` (tests of the midnight overlap).
#[cfg(test)]
pub(crate) fn join_invite_with_relay_at_day(
    cfg: &NetConfig,
    id: &Identity,
    secret: &[u8; 32],
    host_key: [u8; 32],
    relay: Box<dyn RendezvousRelay>,
    day: u64,
) -> ClientHandle {
    spawn(cfg, id, invite_target(secret, host_key, relay, Some(day)))
}

fn invite_target(
    secret: &[u8; 32],
    host_key: [u8; 32],
    relay: Box<dyn RendezvousRelay>,
    fixed_day: Option<u64>,
) -> Target {
    Target::Invite {
        secret: *secret,
        host_key: PublicKey::from_byte_array(host_key),
        relay,
        fixed_day,
    }
}

/// Join a room heard on the LAN beacon: dials its address directly, no internet.
pub fn join_lan(cfg: &NetConfig, id: &Identity, room: &LanRoom) -> ClientHandle {
    spawn(cfg, id, Target::Lan(room.addr, room.token.clone(), None))
}

/// Join a host at a known address (same as a LAN join). `token` is the room's
/// LAN admission token ([`LanRoom::token`], or [`crate::HostHandle::lan_token`]).
pub fn join_addr(cfg: &NetConfig, id: &Identity, addr: SocketAddr, token: &str) -> ClientHandle {
    spawn(cfg, id, Target::Lan(addr, token.to_string(), None))
}

/// Connect a prepared authenticated migration route. The expected runtime
/// identity and signed root/role tuple are checked before Identify is sent.
pub fn join_session_addr(
    cfg: &NetConfig,
    id: &Identity,
    addr: SocketAddr,
    token: &str,
    binding: crate::migration::ConnectionBinding,
    host: PublicKey,
) -> Result<ClientHandle, String> {
    binding.validate().map_err(|e| e.to_string())?;
    Ok(spawn(
        cfg,
        id,
        Target::Lan(addr, token.to_string(), Some((binding, host))),
    ))
}

/// Join by code over a caller-supplied relay (e.g. [`crate::relay::FakeRelayHub`] in tests).
pub fn join_with_relay(
    cfg: &NetConfig,
    id: &Identity,
    code: &str,
    relay: Box<dyn RendezvousRelay>,
) -> ClientHandle {
    spawn(cfg, id, Target::Code(code.to_string(), relay, None))
}

/// [`join_with_relay`] pinned to UTC day `day` (tests of the midnight overlap).
#[cfg(test)]
pub(crate) fn join_with_relay_at_day(
    cfg: &NetConfig,
    id: &Identity,
    code: &str,
    relay: Box<dyn RendezvousRelay>,
    day: u64,
) -> ClientHandle {
    spawn(cfg, id, Target::Code(code.to_string(), relay, Some(day)))
}

pub(crate) fn spawn(cfg: &NetConfig, id: &Identity, target: Target) -> ClientHandle {
    let (ev_tx, ev_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let shared = Arc::new(Shared {
        local_key: id.pubkey().to_bytes(),
        link: Mutex::new(None),
        ev_tx: Mutex::new(ev_tx),
        closing: AtomicBool::new(false),
        migration: Mutex::new(None),
    });
    let s = Arc::clone(&shared);
    let cfg = cfg.clone();
    let keys = id.keys().clone();
    let attestation = id.attestation().map(str::to_string);
    let inbox_relays = cfg.inbox_relays.clone();
    let task = crate::runtime().spawn(async move {
        use futures_util::FutureExt;
        let run = std::panic::AssertUnwindSafe(run(
            cfg,
            keys,
            attestation,
            inbox_relays,
            target,
            Arc::clone(&s),
        ));
        if run.catch_unwind().await.is_err() {
            // Backstop: nothing the host or a relay sends should get here.
            log::error!("[join] client task panicked");
            if let Some(l) = s.link.lock().ok().and_then(|mut l| l.take()) {
                l.conn.close(close::LEAVE.into(), b"internal error");
            }
            s.emit(ClientEvent::Disconnected {
                reason: DisconnectReason::Error("internal error".into()),
            });
        }
        let _ = done_tx.send(());
    });
    ClientHandle {
        events: Mutex::new(ev_rx),
        shared,
        task,
        done_rx: Mutex::new(done_rx),
    }
}

impl ClientHandle {
    /// This connection's local runtime identity.
    pub fn runtime_key(&self) -> [u8; 32] {
        self.shared.local_key
    }

    /// The host key proven by the signed welcome on this live connection.
    /// Game admission and the player's host confirmation remain required.
    pub fn host_key(&self) -> Option<[u8; 32]> {
        let link = self.link()?;
        if !link.session_live.load(Ordering::Acquire) || link.conn.close_reason().is_some() {
            return None;
        }
        link.session_key
    }

    pub fn connection_binding(&self) -> Option<crate::migration::ConnectionBinding> {
        self.shared.migration.lock().ok()?.clone()
    }
    /// Build session framing from the verified welcome and live TLS exporter.
    /// policy supplies the already verified descriptor/current public roster;
    /// it cannot replace the handshake's root, endpoint role or runtime key.
    pub fn migration_channel(
        &self,
        policy: &crate::migration::EndpointPolicy,
    ) -> Result<crate::migration::Channel, String> {
        let link = self.link().ok_or("client is not connected")?;
        if link.conn.close_reason().is_some() {
            return Err("client connection is closed".into());
        }
        let binding = link
            .migration
            .clone()
            .ok_or("ordinary link has no migration binding")?;
        let remote = link.session_key.ok_or("host identity is not bound")?;
        let tls = quic::binding(&link.conn)?;
        let channel = crate::migration::Channel::new_bound(
            policy,
            binding,
            crate::migration::ChannelSide::Client,
            self.shared.local_key,
            remote,
            tls,
        )
        .map_err(|error| error.to_string())?;
        link.session_channel_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "session framing already attached; reconnect requires fresh TLS")?;
        Ok(channel)
    }
    pub fn tls_binding(&self) -> Option<[u8; 32]> {
        quic::binding(&self.link()?.conn).ok()
    }

    /// The app's own exporter value for this connection, under
    /// [`NetConfig::app_binding_label`]: 32 bytes the host's
    /// [`HostHandle::app_binding`] returns too. `None` when no label is
    /// configured, before the connection is up, or if the exporter failed.
    pub fn app_binding(&self) -> Option<[u8; 32]> {
        self.link()?.app_binding
    }

    pub fn poll(&self) -> Option<ClientEvent> {
        let (ev, counter) = self.events.lock().ok()?.try_recv().ok()?;
        if let Some(c) = counter {
            c.fetch_sub(1, Ordering::AcqRel);
        }
        Some(ev)
    }

    pub fn send_reliable(&self, bytes: Bytes) {
        if let Some(l) = self.link() {
            l.send_reliable(bytes);
        }
    }

    pub fn send_lossy(&self, bytes: Bytes) {
        if let Some(l) = self.link() {
            l.send_lossy(bytes);
        }
    }

    pub fn rtt_ms(&self) -> Option<u32> {
        self.link().map(|l| l.rtt_ms())
    }

    pub fn is_connected(&self) -> bool {
        self.link().is_some()
    }

    /// Leave: close the connection (the host sees `PeerLeft{Left}`) or abandon
    /// the attempt. Blocks for at most ~300 ms so the close goes out.
    pub fn shutdown(self) {
        self.shutdown_inner(Duration::from_millis(300));
    }

    fn shutdown_inner(&self, wait: Duration) {
        if self.shared.closing.swap(true, Ordering::Relaxed) {
            return;
        }
        let link = self.shared.link.lock().ok().and_then(|mut l| l.take());
        match link {
            Some(l) => {
                l.conn.close(close::LEAVE.into(), b"bye");
                if let Ok(rx) = self.done_rx.lock() {
                    let _ = rx.recv_timeout(wait);
                }
            }
            None => self.task.abort(),
        }
    }

    fn link(&self) -> Option<Link> {
        self.shared.link.lock().ok()?.clone()
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.shutdown_inner(Duration::from_millis(100));
    }
}

/// When a join stage must end: what is left of the overall session-bound
/// deadline if there is one, else the stage's own timeout from now.
fn stage_end(deadline: Option<tokio::time::Instant>, timeout: Duration) -> tokio::time::Instant {
    deadline.unwrap_or_else(|| tokio::time::Instant::now() + timeout)
}

async fn run(
    cfg: NetConfig,
    keys: Keys,
    attestation: Option<String>,
    inbox_relays: Vec<String>,
    target: Target,
    shared: Arc<Shared>,
) {
    let fail = |stage, reason| shared.emit(ClientEvent::Failed { stage, reason });
    shared.emit(ClientEvent::Progress {
        stage: JoinStage::Preparing,
    });
    let live = match cfg.checked() {
        Ok(l) => l,
        Err(e) => return fail(JoinStage::Preparing, FailReason::Network(e)),
    };

    // For a code join: the relay (kept to spot a racing second answer) and
    // the key that answered, which the welcome must match.
    let mut rendezvous: Option<(Box<dyn RendezvousRelay>, Found)> = None;
    // Admission tokens to prove in the hello.
    let mut tokens: Vec<[u8; 32]> = Vec::new();
    // A virtual link's pre-frame stands in for the LAN beacon: then it is a
    // LAN join to the link's synthetic host address.
    let (target, mut virtual_link) = match target {
        Target::Virtual(mut link) => match crate::virt::read_preframe(&mut link).await {
            Ok(token) => (
                Target::Lan(crate::virt::HOST_ADDR, hex::encode(token), None),
                Some(link),
            ),
            Err((stage, reason)) => return fail(stage, reason),
        },
        t => (t, None),
    };
    // A session-bound join has one overall deadline (no staged timeouts);
    // `None` keeps each stage's own timeout (ordinary LAN and code joins).
    let (mut opened, session, path, deadline) = match target {
        Target::Virtual(_) => unreachable!("converted to a LAN join above"),
        Target::Lan(addr, token, session_link) => {
            let Some(t) = crate::lan::parse_token(&token) else {
                return fail(JoinStage::Preparing, FailReason::NotAdmitted);
            };
            tokens.push(t);
            let (endpoint, path) = match virtual_link.take() {
                None => {
                    // Only a local address is dialled around the VPN.
                    let hook = cfg.lan_socket_hook.clone().filter(|_| {
                        crate::nat::candidates::is_lan_ip(crate::nat::addr::canonical(addr).ip())
                    });
                    let socket = match bind(cfg.quic_port, hook).await {
                        Ok(s) => s,
                        Err(e) => return fail(JoinStage::Preparing, FailReason::Network(e)),
                    };
                    shared.emit(ClientEvent::Progress {
                        stage: JoinStage::Connecting,
                    });
                    (
                        quic::client_endpoint(socket, &cfg.app_tag, live),
                        PathKind::Lan,
                    )
                }
                Some(link) => {
                    shared.emit(ClientEvent::Progress {
                        stage: JoinStage::Connecting,
                    });
                    (
                        crate::virt::client_endpoint(link, &cfg.app_tag, live),
                        PathKind::Virtual,
                    )
                }
            };
            let endpoint = match endpoint {
                Ok(ep) => ep,
                Err(e) => return fail(JoinStage::Connecting, FailReason::Network(e)),
            };
            // Dial start: the session-bound deadline runs from here to Accepted.
            let deadline = session_link
                .as_ref()
                .map(|_| tokio::time::Instant::now() + quic::SESSION_HANDSHAKE_DEADLINE);
            let conn = match endpoint.connect(addr, quic::SERVER_NAME) {
                Ok(c) => match tokio::time::timeout_at(stage_end(deadline, LAN_CONNECT_TIMEOUT), c)
                    .await
                {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(e)) => {
                        log::info!("[join] LAN connect to {addr}: {e}");
                        return fail(JoinStage::Connecting, FailReason::PunchFailed);
                    }
                    Err(_) => return fail(JoinStage::Connecting, FailReason::PunchFailed),
                },
                Err(e) => return fail(JoinStage::Connecting, FailReason::Network(e.to_string())),
            };
            // A LAN join has no answer naming the host: the welcome must verify
            // (some key holds this TLS session), and that is all it can show.
            shared.emit(ClientEvent::Progress {
                stage: JoinStage::Handshake,
            });
            let expected_host = session_link.as_ref().map(|(_, key)| *key);
            let any_host: quic::HostCheck = Arc::new(move |proof| match expected_host {
                Some(key) if proof.pubkey != key => {
                    Err("unexpected session endpoint identity".into())
                }
                _ => Ok(()),
            });
            let open = tokio::time::timeout_at(
                stage_end(deadline, quic::HANDSHAKE_TIMEOUT),
                quic::client_open_bound(
                    &conn,
                    None,
                    path,
                    &tokens,
                    &any_host,
                    session_link.as_ref().map(|(binding, _)| binding),
                ),
            )
            .await
            .unwrap_or_else(|_| Err(quic::HandshakeError::Io("handshake timed out".into())));
            match open {
                Ok(o) => (o, None, path, deadline),
                Err(quic::HandshakeError::Unverified(e)) => {
                    log::warn!("[join] {e}");
                    conn.close(close::HOST_UNVERIFIED.into(), b"host unverified");
                    return fail(JoinStage::Handshake, FailReason::HostUnverified);
                }
                Err(e) => {
                    let ended = conn.close_reason().map(|r| quic::ended_of(&r));
                    let reason =
                        refusal(ended.as_ref()).unwrap_or(FailReason::Network(e.to_string()));
                    return fail(JoinStage::Handshake, reason);
                }
            }
        }
        room_target @ (Target::Code(..) | Target::Invite { .. }) => {
            // A code join and an invite join rendezvous the same way. They
            // differ in where the room secrets come from, and an invite pins
            // the host's key.
            let (source, relay, fixed_day, pinned) = match room_target {
                Target::Code(code, relay, fixed_day) => {
                    let Some(code) = normalize_code(&code) else {
                        return fail(JoinStage::Preparing, FailReason::BadCode);
                    };
                    (RoomSource::Code(code), relay, fixed_day, None)
                }
                Target::Invite {
                    secret,
                    host_key,
                    relay,
                    fixed_day,
                } => (RoomSource::Invite(secret), relay, fixed_day, Some(host_key)),
                _ => unreachable!("matched as a room target above"),
            };
            let prep =
                match crate::host::prepare(cfg.quic_port, false, cfg.stun.clone(), None).await {
                    Ok(p) => p,
                    Err(e) => return fail(JoinStage::Preparing, FailReason::Network(e)),
                };
            shared.emit(ClientEvent::Progress {
                stage: JoinStage::FindingHost,
            });
            let session = new_session_id();
            let day = fixed_day.unwrap_or_else(utc_today);
            let rooms = match &source {
                RoomSource::Code(code) => derive_days(&cfg.app_tag, code, day).await,
                RoomSource::Invite(secret) => derive_invite_days(&cfg.app_tag, secret, day),
            };
            let rooms = match rooms {
                Ok(r) => r,
                Err(e) => return fail(JoinStage::Preparing, FailReason::Network(e)),
            };
            tokens = rooms.iter().map(|r| r.admit).collect();
            // A throwaway key for everything relays see: the install's identity
            // only ever appears inside the encrypted QUIC session.
            let relay_keys = Keys::generate();
            let found = match find_host(
                &relay_keys,
                &rooms,
                &session,
                &prep.candidates,
                relay.as_ref(),
            )
            .await
            {
                Ok(f) => f,
                Err(reason) => return fail(JoinStage::FindingHost, reason),
            };
            let answer = found.answer.clone();
            // An invite names its host: an answer naming anyone else is
            // refused before we punch or dial towards it.
            if let Some(key) = &pinned {
                if PublicKey::from_hex(&answer.host_pubkey).ok().as_ref() != Some(key) {
                    log::warn!("[join] the answer names a host other than the invite's");
                    return fail(JoinStage::Handshake, FailReason::HostUnverified);
                }
            }
            // The host we reach must be the one that answered the code: the
            // answer (encrypted to us, so the relays never see it) names the
            // host identity, and only that identity may sign the
            // connection-bound welcome. Naming the answer's relay key is not
            // enough: that key is public, so an on-path box could name it too
            // (review-net-1 N1). Checked per candidate, before we say who we are.
            let (named, signer) = (answer.host_pubkey.clone(), found.signer);
            let check: quic::HostCheck = Arc::new(move |p| {
                host_matches(p, &named, &signer)?;
                match &pinned {
                    Some(key) if p.pubkey != *key => Err(format!(
                        "welcome signed by {} but the invite pins {key}",
                        p.pubkey
                    )),
                    _ => Ok(()),
                }
            });
            rendezvous = Some((relay, found));
            shared.emit(ClientEvent::Progress {
                stage: JoinStage::Connecting,
            });
            // Whoever answered chose these addresses: only sane ones are
            // punched and dialled (review-ipv6-1 I4). `targets` and `paths`
            // come from the one filtered list, so their indices agree.
            let dial = dialable(&answer.candidates);
            let targets = parse_addrs(&dial);
            let paths: Vec<PathKind> = dial
                .iter()
                .map(|c| {
                    if c.kind == "lan" {
                        PathKind::Lan
                    } else {
                        PathKind::Direct
                    }
                })
                .collect();
            log::info!("[join] host candidates {targets:?}");
            // Punch before quinn owns the socket.
            let (socket, punch_targets, s) = (prep.socket, targets.clone(), session.clone());
            let socket = match tokio::task::spawn_blocking(move || {
                crate::nat::punch::send_punches(&socket, &punch_targets, &s);
                socket
            })
            .await
            {
                Ok(s) => s,
                Err(e) => return fail(JoinStage::Connecting, FailReason::Network(e.to_string())),
            };
            let endpoint = match quic::client_endpoint(socket, &cfg.app_tag, live) {
                Ok(ep) => ep,
                Err(e) => return fail(JoinStage::Connecting, FailReason::Network(e)),
            };
            // Each candidate is dialled and must produce a verified welcome;
            // one that doesn't (a squatter on our LAN, an unrelated host at
            // the same private address) is skipped, not fatal (review-net-1 N4).
            match quic::race_open(&endpoint, &targets, &paths, Some(&session), &tokens, &check)
                .await
            {
                Ok((opened, idx)) => {
                    let path = paths.get(idx).copied().unwrap_or(PathKind::Direct);
                    log::info!("[join] verified host at {} via {path:?}", targets[idx]);
                    shared.emit(ClientEvent::Progress {
                        stage: JoinStage::Handshake,
                    });
                    (opened, Some(session), path, None)
                }
                Err(f) => {
                    log::info!("[join] connect race: {f:?}");
                    let (stage, reason) = race_failure(&f);
                    return fail(stage, reason);
                }
            }
        }
    };
    let conn = opened.conn.clone();

    if let Some((relay, found)) = rendezvous {
        // The host proved it is the one the answer named (checked in the
        // race) ...
        // ... and nobody else may have answered it. Junk never reaches the
        // queue (pre-queue check), so a full queue means someone flooded
        // valid-looking answers: fail closed.
        let settle = ANSWER_SETTLE.saturating_sub(found.at.elapsed());
        tokio::time::sleep(settle).await;
        if relay.overflowed() {
            log::warn!("[join] answer queue overflowed: refusing");
            conn.close(close::HOST_UNVERIFIED.into(), b"host conflict");
            return fail(JoinStage::Handshake, FailReason::HostConflict);
        }
        if let Some(other) = other_answerer(relay.as_ref(), &found.signer) {
            log::warn!("[join] a second key {other} answered our offer: refusing");
            conn.close(close::HOST_UNVERIFIED.into(), b"host conflict");
            return fail(JoinStage::Handshake, FailReason::HostConflict);
        }
    }

    // Only now, with the host verified (and, for a code join, nobody else
    // answering), do we say who we are (review-net-1 N5).
    let id = tokio::time::timeout_at(
        stage_end(deadline, quic::HANDSHAKE_TIMEOUT),
        quic::client_identify(
            &mut opened,
            &keys,
            attestation.as_deref(),
            &inbox_relays,
            session.as_deref(),
        ),
    )
    .await
    .unwrap_or_else(|_| Err(quic::HandshakeError::Io("handshake timed out".into())));
    if let Err(e) = id {
        let ended = conn.close_reason().map(|r| quic::ended_of(&r));
        conn.close(close::LEAVE.into(), b"bye");
        return fail(
            JoinStage::Handshake,
            refusal(ended.as_ref()).unwrap_or(FailReason::Network(e.to_string())),
        );
    }
    let quic::Opened {
        send, recv, proof, ..
    } = opened;
    let (mut link, out_rx) = Link::new(conn.clone());
    link.migration = proof.migration.clone();
    link.app_binding = quic::app_binding(&conn, cfg.app_binding_label.as_deref());
    link.session_key = Some(proof.pubkey.to_bytes());
    if let Ok(mut binding) = shared.migration.lock() {
        *binding = proof.migration.clone();
    }
    if let Ok(mut l) = shared.link.lock() {
        *l = Some(link.clone());
    }
    if shared.closing.load(Ordering::Relaxed) {
        conn.close(close::LEAVE.into(), b"bye");
        return;
    }
    shared.emit(ClientEvent::Connected {
        path,
        host_name: proof.name.clone(),
        host_pubkey: proof.pubkey,
        attestation: proof.attestation.clone(),
        inbox_relays: proof.inbox_relays.clone(),
    });
    let (s1, s2) = (Arc::clone(&shared), Arc::clone(&shared));
    let (reliable_q, lossy_q) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let ended = quic::pump(
        conn,
        send,
        recv,
        out_rx,
        Arc::clone(&link.queued),
        move |b| s1.emit_counted(ClientEvent::Reliable(b), &reliable_q, MAX_QUEUED_RELIABLE),
        move |b| {
            s2.emit_counted(ClientEvent::Lossy(b), &lossy_q, MAX_QUEUED_LOSSY);
        },
    )
    .await;
    if let Ok(mut l) = shared.link.lock() {
        *l = None;
    }
    if shared.closing.load(Ordering::Relaxed) {
        return; // We left; nothing to report.
    }
    let reason = match ended {
        Ended::Remote(close::KICKED) => DisconnectReason::Kicked,
        Ended::Remote(close::CONFIRM_TIMEOUT) => DisconnectReason::ConfirmTimeout,
        Ended::Remote(_) => DisconnectReason::HostLeft,
        Ended::TimedOut => DisconnectReason::TimedOut,
        Ended::Local => DisconnectReason::Error("closed locally".into()),
        Ended::Error(e) => DisconnectReason::Error(e),
    };
    shared.emit(ClientEvent::Disconnected { reason });
}

/// Where a room join's secrets come from.
enum RoomSource {
    /// A normalised room code (Argon2id).
    Code(String),
    /// An invite's 32-byte secret.
    Invite([u8; 32]),
}

/// Bind the QUIC socket of a joiner dialling a local host (a LAN room or a
/// known address): bound to the local network by the app's hook, if any, so a
/// VPN does not swallow the dial. A code join keeps the default route.
async fn bind(
    port: u16,
    lan_hook: Option<crate::LanSocketHook>,
) -> Result<std::net::UdpSocket, String> {
    tokio::task::spawn_blocking(move || {
        let socket = crate::nat::addr::bind_dual_stack(port)
            .map_err(|e| format!("could not bind UDP port {port}: {e}"))?;
        let _ = crate::netbind::bind_lan(lan_hook.as_ref(), &socket);
        Ok(socket)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// A code join's binding between the relay answer and the QUIC host: the
/// welcome must be signed by the identity the encrypted answer named, and
/// name the relay key that signed that answer.
#[cfg(test)]
fn host_matches_answer(proof: &quic::HostProof, found: &Found) -> Result<(), String> {
    host_matches(proof, &found.answer.host_pubkey, &found.signer)
}

/// [`host_matches_answer`] on the answer's named identity (hex) and signer.
fn host_matches(proof: &quic::HostProof, named: &str, signer: &PublicKey) -> Result<(), String> {
    let named = PublicKey::from_hex(named)
        .map_err(|e| format!("the answer names no valid host identity: {e}"))?;
    if proof.pubkey != named {
        return Err(format!(
            "welcome signed by {} but the answer named {named}",
            proof.pubkey
        ));
    }
    if proof.relay_key != *signer {
        return Err(format!(
            "welcome relay key {} != answer key {signer}",
            proof.relay_key
        ));
    }
    Ok(())
}

/// The host's refusal, if it closed the connection with one.
fn refusal(ended: Option<&Ended>) -> Option<FailReason> {
    match ended? {
        Ended::Remote(close::FULL) => Some(FailReason::RoomFull),
        Ended::Remote(close::CLOSED) => Some(FailReason::RoomClosed),
        Ended::Remote(close::VERSION) => Some(FailReason::VersionMismatch),
        Ended::Remote(close::NOT_ADMITTED | close::KICKED) => Some(FailReason::NotAdmitted),
        _ => None,
    }
}

/// What to tell the app when no candidate produced a verified host. An
/// unverifiable welcome anywhere wins (it is the security signal); then a
/// room's refusal (full, closed, version) over "not admitted", which an
/// unrelated host at one of the addresses would also say.
fn race_failure(f: &quic::RaceFailure) -> (JoinStage, FailReason) {
    use quic::{AttemptError, HandshakeError};
    let mut best: Option<FailReason> = None;
    let mut last_io: Option<String> = None;
    for e in &f.errors {
        let AttemptError::Open(err, ended) = e else {
            continue;
        };
        if let HandshakeError::Unverified(_) = err {
            return (JoinStage::Handshake, FailReason::HostUnverified);
        }
        match refusal(ended.as_ref()) {
            Some(FailReason::NotAdmitted) => {
                best.get_or_insert(FailReason::NotAdmitted);
            }
            Some(r) => {
                if matches!(best, None | Some(FailReason::NotAdmitted)) {
                    best = Some(r);
                }
            }
            None => last_io = Some(err.to_string()),
        }
    }
    match (best, last_io) {
        (Some(r), _) => (JoinStage::Handshake, r),
        (None, Some(e)) => (JoinStage::Handshake, FailReason::Network(e)),
        (None, None) if f.connected => (
            JoinStage::Handshake,
            FailReason::Network("handshake timed out".into()),
        ),
        (None, None) => (JoinStage::Connecting, FailReason::PunchFailed),
    }
}

/// The answer that found the host, who signed it, and when it arrived.
struct Found {
    answer: Answer,
    signer: PublicKey,
    at: Instant,
}

/// Subscribe for our answer, wait for a relay, send the offer (re-sending it
/// until answered), and return the host's answer. `rooms` is today's secrets
/// then yesterday's: the first round offers on today's tag only, later rounds
/// on both (covers a host on the other side of UTC midnight).
async fn find_host(
    keys: &Keys,
    rooms: &[RoomSecrets],
    session: &str,
    candidates: &[crate::rendezvous::Candidate],
    relay: &dyn RendezvousRelay,
) -> Result<Found, FailReason> {
    // Only answers that open for this session may take a queue slot, so a
    // flood of junk can never push out the real one.
    let (k, sess) = (keys.clone(), session.to_string());
    relay.set_accept(Some(Arc::new(move |ev: &nostr::Event| {
        open_answer(&k, ev, &sess, crate::unix_now()).is_ok()
    })));
    // The answer subscription goes first: answers are ephemeral and never stored.
    relay
        .subscribe(TagFilter::one(
            KIND_JOIN_ANSWER,
            'p',
            keys.public_key().to_hex(),
        ))
        .map_err(FailReason::Network)?;

    let started = Instant::now();
    while relay.connected().0 == 0 {
        if started.elapsed() > RELAY_DEADLINE {
            return Err(FailReason::RelayUnreachable);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Give the REQ a moment to land on the relay before the offer can be answered.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let first = Instant::now();
    let mut last_offer: Option<Instant> = None;
    let mut round = 0usize;
    loop {
        if last_offer.is_none_or(|t| t.elapsed() >= OFFER_EVERY) {
            // A fresh event each time (new id), same session.
            let offer = Offer {
                v: NET_PROTOCOL_VERSION,
                session: session.to_string(),
                pubkey: keys.public_key().to_hex(),
                candidates: candidates.to_vec(),
                sent_at: crate::unix_now(),
            };
            for room in rooms.iter().take(if round == 0 { 1 } else { rooms.len() }) {
                let ev = seal_offer(keys, &room.keys.public_key(), &room.tag, &offer)
                    .map_err(FailReason::Network)?;
                relay.publish(&ev).map_err(FailReason::Network)?;
            }
            last_offer = Some(Instant::now());
            round += 1;
        }
        while let Some(ev) = relay.try_recv() {
            match open_answer(keys, &ev, session, crate::unix_now()) {
                Ok(a) if a.accepted => {
                    return Ok(Found {
                        answer: a,
                        signer: ev.pubkey,
                        at: Instant::now(),
                    })
                }
                Ok(a) => {
                    return Err(match a.reason.as_deref() {
                        Some("full") => FailReason::RoomFull,
                        Some("closed") => FailReason::RoomClosed,
                        Some("version") => FailReason::VersionMismatch,
                        other => FailReason::Network(format!("refused: {other:?}")),
                    })
                }
                Err(e) => log::debug!("[join] ignoring an answer: {e:?}"),
            }
        }
        if first.elapsed() > ANSWER_DEADLINE {
            return Err(FailReason::NoAnswer);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A valid answer to our session (the pre-queue check already opened it)
/// from any key but `host`, if one arrived.
fn other_answerer(relay: &dyn RendezvousRelay, host: &PublicKey) -> Option<PublicKey> {
    while let Some(ev) = relay.try_recv() {
        if ev.pubkey != *host {
            return Some(ev.pubkey);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{sign_welcome, verify_welcome};

    fn found(relay: &Keys, host: &PublicKey) -> Found {
        Found {
            answer: Answer {
                v: NET_PROTOCOL_VERSION,
                session: "s".into(),
                accepted: true,
                reason: None,
                candidates: Vec::new(),
                sent_at: 0,
                host_pubkey: host.to_hex(),
            },
            signer: relay.public_key(),
            at: Instant::now(),
        }
    }

    /// review-net-1 N1, the reviewer's probe: an on-path attacker without the
    /// code signs a welcome with its own identity naming the real host's
    /// (public) relay key. The welcome verifies, but the joiner must refuse it.
    #[test]
    fn n1_a_welcome_naming_the_real_relay_key_but_signed_by_another_identity_is_refused() {
        let real_relay = Keys::generate();
        let real_host = Keys::generate();
        let attacker = Keys::generate();
        let binding = [42u8; 32];
        let f = found(&real_relay, &real_host.public_key());
        let w = sign_welcome(
            &attacker,
            &binding,
            Some("s"),
            1,
            "Mum",
            &real_relay.public_key(),
            None,
            &[],
        );
        let proof = verify_welcome(&w, &binding, Some("s")).expect("the welcome itself verifies");
        assert_eq!(proof.relay_key, f.signer, "it names the right relay key");
        assert!(
            host_matches_answer(&proof, &f).is_err(),
            "but is not signed by the named host"
        );
        // The real host passes.
        let w = sign_welcome(
            &real_host,
            &binding,
            Some("s"),
            1,
            "Ava",
            &real_relay.public_key(),
            None,
            &[],
        );
        let proof = verify_welcome(&w, &binding, Some("s")).unwrap();
        assert!(host_matches_answer(&proof, &f).is_ok());
        // ... unless the welcome names another relay key (a redirected join).
        let w = sign_welcome(
            &real_host,
            &binding,
            Some("s"),
            1,
            "Ava",
            &Keys::generate().public_key(),
            None,
            &[],
        );
        let proof = verify_welcome(&w, &binding, Some("s")).unwrap();
        assert!(host_matches_answer(&proof, &f).is_err());
    }

    #[test]
    fn an_answer_naming_no_host_identity_fails_closed() {
        let relay = Keys::generate();
        let host = Keys::generate();
        let mut f = found(&relay, &host.public_key());
        let w = sign_welcome(
            &host,
            &[1u8; 32],
            None,
            1,
            "Ava",
            &relay.public_key(),
            None,
            &[],
        );
        let proof = verify_welcome(&w, &[1u8; 32], None).unwrap();
        for bad in ["", "zz", "00"] {
            f.answer.host_pubkey = bad.into();
            assert!(host_matches_answer(&proof, &f).is_err(), "{bad:?}");
        }
    }
}
