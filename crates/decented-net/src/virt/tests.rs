//! Virtual-link tests over in-memory links (tokio channel pairs).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::{
    Bytes, ClientEvent, DisconnectReason, FailReason, HostEvent, LeaveReason, NetConfig, PeerId,
    RoomInfo,
};

fn cfg() -> NetConfig {
    NetConfig::new(std::env::temp_dir(), "test-app").lan_only()
}

fn room(max: u8) -> RoomInfo {
    RoomInfo {
        name: "BT room".into(),
        max_players: max,
    }
}

fn wait_host(h: &HostHandle, secs: u64, mut pred: impl FnMut(&HostEvent) -> bool) -> HostEvent {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        while let Some(ev) = h.poll() {
            if pred(&ev) {
                return ev;
            }
            seen.push(format!("{ev:?}"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("host event not seen within {secs}s; saw {seen:?}");
}

fn wait_client(
    c: &ClientHandle,
    secs: u64,
    mut pred: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        while let Some(ev) = c.poll() {
            if pred(&ev) {
                return ev;
            }
            seen.push(format!("{ev:?}"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("client event not seen within {secs}s; saw {seen:?}");
}

fn outcome(c: &ClientHandle) -> ClientEvent {
    wait_client(c, 15, |e| {
        matches!(
            e,
            ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
        )
    })
}

fn ready_host(id: &Identity, max: u8) -> (HostHandle, VirtualLinkSender) {
    let (links_tx, links_rx) = virtual_link_queue(64);
    let h = host_virtual(&cfg(), id, room(max), links_rx);
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    (h, links_tx)
}

/// Hand the host a fresh link; return the joiner's end.
fn dial(links: &VirtualLinkSender, label: &str) -> VirtualLink {
    let (client_end, host_end) = virtual_pair(label, "host", 256);
    links.try_send(host_end).expect("host takes the link");
    client_end
}

fn recv_within(
    link: &mut VirtualLink,
    secs: u64,
) -> Result<Option<Vec<u8>>, tokio::time::error::Elapsed> {
    crate::runtime()
        .block_on(async { tokio::time::timeout(Duration::from_secs(secs), link.rx.recv()).await })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    /// Joiner → host.
    Up,
    /// Host → joiner.
    Down,
}

type PacketLog = Arc<Mutex<Vec<(Dir, Vec<u8>)>>>;
type Rewrite = Box<dyn FnMut(Dir, Vec<u8>) -> Option<Vec<u8>> + Send>;

/// A link through a middlebox: every packet is logged and may be rewritten
/// or dropped; aborting the task cuts the link both ways (a radio drop).
/// The tap never closes the host's side by itself: it runs until the host
/// drops the link (`host_closed`) or it is aborted.
struct Tap {
    log: PacketLog,
    task: tokio::task::JoinHandle<()>,
    host_closed: Arc<AtomicBool>,
}

fn tapped(links: &VirtualLinkSender, label: &str, mut f: Rewrite) -> (VirtualLink, Tap) {
    let (client_end, mid_c) = virtual_pair(label, "tap", 256);
    let (mid_h, host_end) = virtual_pair("tap", label, 256);
    links.try_send(host_end).expect("host takes the link");
    let log: PacketLog = Arc::new(Mutex::new(Vec::new()));
    let l = Arc::clone(&log);
    let host_closed = Arc::new(AtomicBool::new(false));
    let hc = Arc::clone(&host_closed);
    let task = crate::runtime().spawn(async move {
        let VirtualLink {
            tx: to_client,
            rx: mut from_client,
            ..
        } = mid_c;
        let VirtualLink {
            tx: to_host,
            rx: mut from_host,
            ..
        } = mid_h;
        let mut client_open = true;
        loop {
            let (dir, p) = tokio::select! {
                p = from_client.recv(), if client_open => (Dir::Up, p),
                p = from_host.recv() => (Dir::Down, p),
            };
            let Some(p) = p else {
                if dir == Dir::Down {
                    hc.store(true, Ordering::SeqCst);
                    break;
                }
                client_open = false;
                continue;
            };
            l.lock().unwrap().push((dir, p.clone()));
            let Some(p) = f(dir, p) else { continue };
            let _ = if dir == Dir::Up {
                to_host.send(p).await
            } else {
                to_client.send(p).await
            };
        }
    });
    (
        client_end,
        Tap {
            log,
            task,
            host_closed,
        },
    )
}

/// Wait until `cl` is in and the host has seated `id`; returns its peer id.
fn connected(h: &HostHandle, cl: &ClientHandle, id: &Identity) -> PeerId {
    let ev = outcome(cl);
    let ClientEvent::Connected { path, .. } = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(path, PathKind::Virtual);
    let HostEvent::PeerJoined { peer, path, .. } = wait_host(
        h,
        10,
        |e| matches!(e, HostEvent::PeerJoined { pubkey, .. } if *pubkey == id.pubkey()),
    ) else {
        unreachable!()
    };
    assert_eq!(path, PathKind::Virtual);
    peer
}

/// (a) A virtual host and two virtual joiners connect exactly as LAN does:
/// proven identities and attestations both ways, messages, kicks.
#[test]
fn two_joiners_connect_over_virtual_links_with_identities_and_attestations() {
    let host_id = Identity::ephemeral().with_attestation("{\"host\":1}".into());
    let (h, links) = ready_host(&host_id, 4);
    assert_eq!(h.local_addr(), None, "a virtual host has no UDP address");

    let ids = [
        Identity::ephemeral().with_attestation("{\"joiner\":1}".into()),
        Identity::ephemeral().with_attestation("{\"joiner\":2}".into()),
    ];
    let mut clients = Vec::new();
    for (n, id) in ids.iter().enumerate() {
        let cl = join_virtual(&cfg(), id, dial(&links, &format!("BLE {n}")));
        let ev = outcome(&cl);
        let ClientEvent::Connected {
            path,
            host_name,
            host_pubkey,
            attestation,
            ..
        } = ev
        else {
            panic!("{ev:?}")
        };
        assert_eq!(path, PathKind::Virtual);
        assert_eq!(host_name, "BT room");
        assert_eq!(
            host_pubkey,
            host_id.pubkey(),
            "the joiner learns the host's proven key"
        );
        assert_eq!(
            attestation, None,
            "a virtual host's welcome withholds its persona (V2)"
        );
        let HostEvent::PeerJoined {
            peer,
            pubkey,
            path,
            attestation,
            ..
        } = wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
        else {
            unreachable!()
        };
        assert_eq!(
            pubkey,
            id.pubkey(),
            "the host learns the joiner's proven key"
        );
        assert_eq!(path, PathKind::Virtual);
        assert_eq!(
            attestation,
            Some(format!("{{\"joiner\":{}}}", n + 1)),
            "the joiner's own still goes"
        );
        clients.push((cl, peer));
    }
    assert_eq!(h.peer_count(), 2);

    // Reliable and lossy messages at their largest, both ways.
    let (cl, peer) = &clients[0];
    cl.send_reliable(Bytes::from(vec![7u8; crate::MAX_RELIABLE_LEN]));
    cl.send_lossy(Bytes::from(vec![8u8; crate::MAX_LOSSY_LEN]));
    let mut got = (false, false);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(got.0 && got.1) && Instant::now() < deadline {
        match h.poll() {
            Some(HostEvent::Reliable { peer: p, bytes }) if p == *peer => {
                got.0 = bytes.len() == crate::MAX_RELIABLE_LEN
            }
            Some(HostEvent::Lossy { peer: p, bytes }) if p == *peer => {
                got.1 = bytes.len() == crate::MAX_LOSSY_LEN
            }
            Some(_) => {}
            None => {
                if !got.1 {
                    cl.send_lossy(Bytes::from(vec![8u8; crate::MAX_LOSSY_LEN]));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    assert_eq!(
        got,
        (true, true),
        "max-size reliable and lossy messages cross the link"
    );
    h.send_reliable(*peer, Bytes::from_static(b"hi"));
    let ev = wait_client(cl, 10, |e| matches!(e, ClientEvent::Reliable(_)));
    assert!(
        matches!(ev, ClientEvent::Reliable(ref b) if &b[..] == b"hi"),
        "{ev:?}"
    );

    // A kick works as on LAN.
    let (cl2, peer2) = &clients[1];
    h.kick(*peer2);
    let ev = wait_client(cl2, 10, |e| matches!(e, ClientEvent::Disconnected { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::Kicked
            }
        ),
        "{ev:?}"
    );

    for (cl, _) in clients {
        cl.shutdown();
    }
    h.shutdown();
}

/// (b) A wrong token, a missing pre-frame, or a link that speaks before QUIC
/// is refused; the token rotates with the room as LAN's does.
#[test]
fn a_wrong_or_missing_preframe_is_refused() {
    let (h, links) = ready_host(&Identity::ephemeral(), 8);

    // The pre-frame is the host's current LAN token.
    let mut raw = dial(&links, "raw");
    let first = recv_within(&mut raw, 5).unwrap().expect("pre-frame");
    assert_eq!(first.len(), 33);
    assert_eq!(first[0], TAG_TOKEN);
    assert_eq!(hex::encode(&first[1..]), h.lan_token());

    // A joiner that sends anything but QUIC is dropped by the host.
    raw.tx.try_send(first.clone()).unwrap();
    let closed = recv_within(&mut raw, 5);
    assert!(
        matches!(closed, Ok(None)),
        "the host drops a link that sends a non-QUIC packet: {closed:?}"
    );

    // Wrong token: a middlebox flips the pre-frame's token. The hello's proof
    // fails, exactly as a stale LAN token does.
    let flip: Rewrite = Box::new(|dir, mut p| {
        if dir == Dir::Down && p.len() == 33 && p[0] == TAG_TOKEN {
            p[1] ^= 0xff;
        }
        Some(p)
    });
    let (link, _flip_tap) = tapped(&links, "flip", flip);
    let ev = outcome(&join_virtual(&cfg(), &Identity::ephemeral(), link));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                reason: FailReason::NotAdmitted,
                ..
            }
        ),
        "{ev:?}"
    );

    // Missing pre-frame: the first packet is QUIC-tagged, junk, or empty.
    for first in [vec![TAG_QUIC; 40], vec![0x00; 33], Vec::new()] {
        let (fake_host, client_end) = virtual_pair("fake host", "joiner", 16);
        fake_host.tx.try_send(first).unwrap();
        let ev = outcome(&join_virtual(&cfg(), &Identity::ephemeral(), client_end));
        assert!(
            matches!(
                ev,
                ClientEvent::Failed {
                    stage: JoinStage::Preparing,
                    reason: FailReason::NotAdmitted
                }
            ),
            "{ev:?}"
        );
        drop(fake_host);
    }

    // A link that closes before its pre-frame is a connect failure.
    let (fake_host, client_end) = virtual_pair("gone", "joiner", 16);
    drop(fake_host);
    let ev = outcome(&join_virtual(&cfg(), &Identity::ephemeral(), client_end));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Connecting,
                reason: FailReason::NoLinkAnswer
            }
        ),
        "{ev:?}"
    );

    // Rotation: closing and reopening the room changes the token new links
    // get, and a token captured earlier no longer admits.
    let old = h.lan_token();
    h.set_open(false);
    h.set_open(true);
    assert_ne!(old, h.lan_token());
    let mut raw = dial(&links, "after reopen");
    let fresh = recv_within(&mut raw, 5).unwrap().expect("pre-frame");
    assert_eq!(
        hex::encode(&fresh[1..]),
        h.lan_token(),
        "new links get the new token"
    );
    let old_bytes = hex::decode(&old).unwrap();
    let stale: Rewrite = Box::new(move |dir, p| {
        if dir == Dir::Down && p.len() == 33 && p[0] == TAG_TOKEN {
            let mut q = vec![TAG_TOKEN];
            q.extend_from_slice(&old_bytes);
            return Some(q);
        }
        Some(p)
    });
    let (link, _stale_tap) = tapped(&links, "stale", stale);
    let ev = outcome(&join_virtual(&cfg(), &Identity::ephemeral(), link));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                reason: FailReason::NotAdmitted,
                ..
            }
        ),
        "{ev:?}"
    );

    // And with the current token, in.
    let id = Identity::ephemeral();
    let cl = join_virtual(&cfg(), &id, dial(&links, "good"));
    connected(&h, &cl, &id);
    assert_eq!(h.peer_count(), 1);
    h.shutdown();
}

/// A host holds at most `MAX_LINKS` links; a newcomer displaces the oldest
/// link that never started QUIC.
#[test]
fn a_link_beyond_the_cap_displaces_the_oldest_silent_one() {
    let (h, links) = ready_host(&Identity::ephemeral(), 8);
    let mut raws = Vec::new();
    for n in 0..MAX_LINKS {
        let mut l = dial(&links, &format!("raw {n}"));
        let p = recv_within(&mut l, 5);
        assert!(
            matches!(p, Ok(Some(ref f)) if f.len() == 33),
            "link {n} gets its pre-frame: {p:?}"
        );
        raws.push(l);
    }
    let mut extra = dial(&links, "one too many");
    let p = recv_within(&mut extra, 5);
    assert!(
        matches!(p, Ok(Some(ref f)) if f.len() == 33),
        "the newcomer gets in: {p:?}"
    );
    let p = recv_within(&mut raws[0], 5);
    assert!(
        matches!(p, Ok(None)),
        "the oldest silent link made way: {p:?}"
    );
    for (n, r) in raws.iter_mut().enumerate().skip(1) {
        assert!(
            matches!(r.rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "link {n} kept"
        );
    }
    h.shutdown();
}

/// Fill the host's link table with silent links that got their pre-frame.
fn fill_with_silent_links(links: &VirtualLinkSender) -> Vec<VirtualLink> {
    (0..MAX_LINKS)
        .map(|n| {
            let mut l = dial(links, &format!("silent {n}"));
            let p = recv_within(&mut l, 5);
            assert!(
                matches!(p, Ok(Some(ref f)) if f.len() == 33),
                "link {n} gets its pre-frame: {p:?}"
            );
            l
        })
        .collect()
}

/// Mutant A: a link that closes is forgotten at once, so its slot is free
/// for the next one (nobody else has to make way).
#[test]
fn a_closed_link_frees_its_slot_at_once() {
    let (h, links) = ready_host(&Identity::ephemeral(), 8);
    let mut raws = fill_with_silent_links(&links);
    // Close only what the host reads (the half-close check must not be what
    // catches this): the host must still forget the link.
    let VirtualLink {
        tx,
        rx: _still_reading,
        ..
    } = raws.remove(5);
    drop(tx);
    std::thread::sleep(Duration::from_millis(300));
    let mut next = dial(&links, "next");
    let p = recv_within(&mut next, 5);
    assert!(
        matches!(p, Ok(Some(ref f)) if f.len() == 33),
        "the new link gets in: {p:?}"
    );
    std::thread::sleep(Duration::from_millis(300));
    for (n, r) in raws.iter_mut().enumerate() {
        assert!(
            matches!(r.rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "link {n} kept: the closed link's slot was reused, nobody was displaced"
        );
    }
    h.shutdown();
}

/// V1: links that never start QUIC are dropped after the setup deadline,
/// and a real joiner gets in afterwards.
#[test]
fn silent_links_are_dropped_after_the_deadline_and_a_joiner_gets_in() {
    let (h, links) = ready_host(&Identity::ephemeral(), 8);
    let filled = Instant::now();
    let mut raws = fill_with_silent_links(&links);
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        matches!(raws[0].rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "kept before the deadline"
    );
    std::thread::sleep(
        (LINK_SETUP_DEADLINE + Duration::from_millis(1500)).saturating_sub(filled.elapsed()),
    );
    for (n, r) in raws.iter_mut().enumerate() {
        assert!(
            matches!(recv_within(r, 2), Ok(None)),
            "silent link {n} dropped after the deadline"
        );
    }
    let id = Identity::ephemeral();
    let cl = join_virtual(&cfg(), &id, dial(&links, "real"));
    connected(&h, &cl, &id);
    h.shutdown();
}

/// V1: once a link's connection is over (here a kick), the host drops the
/// link, even though the radio would keep it open.
#[test]
fn a_finished_connection_frees_its_link() {
    let (h, links) = ready_host(&Identity::ephemeral(), 4);
    let id = Identity::ephemeral();
    let (link, tap) = tapped(&links, "kicked", Box::new(|_, p| Some(p)));
    let cl = join_virtual(&cfg(), &id, link);
    let peer = connected(&h, &cl, &id);
    h.kick(peer);
    let ev = wait_client(&cl, 10, |e| matches!(e, ClientEvent::Disconnected { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::Kicked
            }
        ),
        "{ev:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(4);
    while !tap.host_closed.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        tap.host_closed.load(Ordering::SeqCst),
        "the host dropped the finished link"
    );
    h.shutdown();
}

/// V5: a link whose peer stops reading (one channel closed) is dropped, on
/// the host and on the joiner.
#[test]
fn a_half_closed_link_is_dropped_on_both_sides() {
    let wait_closed = |tx: &mpsc::Sender<Vec<u8>>| {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !tx.is_closed() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        tx.is_closed()
    };
    // Host side: the joiner end stops reading after the pre-frame.
    let (h, links) = ready_host(&Identity::ephemeral(), 4);
    let mut raw = dial(&links, "half");
    assert!(matches!(recv_within(&mut raw, 5), Ok(Some(_))));
    let VirtualLink { tx, rx, .. } = raw;
    drop(rx);
    assert!(
        wait_closed(&tx),
        "the host dropped a link it can no longer send on"
    );
    h.shutdown();

    // Joiner side: the fake host sends a pre-frame, then stops reading.
    let (fake_host, client_end) = virtual_pair("fake host", "joiner", 16);
    fake_host.tx.try_send(preframe(&[1u8; 32])).unwrap();
    let VirtualLink { tx, rx, .. } = fake_host;
    drop(rx);
    let _cl = join_virtual(&cfg(), &Identity::ephemeral(), client_end);
    assert!(
        wait_closed(&tx),
        "the joiner dropped a link it can no longer send on"
    );
}

/// V2: the withholding is a `NetConfig` option: a virtual host can opt to
/// send its attestation, and a LAN host can opt to withhold it.
#[test]
fn withholding_the_host_attestation_is_configurable() {
    let host_id = Identity::ephemeral().with_attestation("{\"host\":1}".into());
    let mut c = cfg();
    c.withhold_host_attestation = Some(false);
    c.inbox_relays = vec!["wss://inbox.example".into()];
    let (links_tx, links_rx) = virtual_link_queue(4);
    let h = host_virtual(&c, &host_id, room(4), links_rx);
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let ev = outcome(&join_virtual(
        &cfg(),
        &Identity::ephemeral(),
        dial(&links_tx, "opt in"),
    ));
    assert!(
        matches!(
            ev,
            ClientEvent::Connected { attestation: Some(ref a), ref inbox_relays, .. }
                if a == "{\"host\":1}" && inbox_relays == &["wss://inbox.example".to_string()]
        ),
        "{ev:?}"
    );
    h.shutdown();

    let mut c = cfg();
    c.withhold_host_attestation = Some(true);
    c.inbox_relays = vec!["wss://inbox.example".into()];
    let h = crate::host(&c, &host_id, room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), h.local_addr().unwrap().port());
    let ev = outcome(&crate::join_addr(
        &cfg(),
        &Identity::ephemeral(),
        addr,
        &h.lan_token(),
    ));
    assert!(
        matches!(
            ev,
            ClientEvent::Connected {
                attestation: None,
                ref inbox_relays,
                ..
            } if inbox_relays.is_empty()
        ),
        "withheld with the attestation: {ev:?}"
    );
    h.shutdown();
}

/// (c) A link that drops (radio gone) ends in PeerLeft{TimedOut} on the host
/// and Disconnected{TimedOut} on the joiner, within the idle timeout.
#[test]
fn a_dropped_link_times_out_on_both_sides() {
    let (h, links) = ready_host(&Identity::ephemeral(), 4);
    let id = Identity::ephemeral();
    let (link, tap) = tapped(&links, "cut me", Box::new(|_, p| Some(p)));
    let cl = join_virtual(&cfg(), &id, link);
    let peer = connected(&h, &cl, &id);
    let cut = Instant::now();
    tap.task.abort();
    let limit = quic::IDLE_TIMEOUT.as_secs() + 4;
    let ev = wait_host(&h, limit, |e| matches!(e, HostEvent::PeerLeft { .. }));
    assert!(
        matches!(ev, HostEvent::PeerLeft { peer: p, reason: LeaveReason::TimedOut } if p == peer),
        "{ev:?}"
    );
    assert!(cut.elapsed() <= Duration::from_secs(limit));
    let ev = wait_client(&cl, limit, |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    });
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::TimedOut
            }
        ),
        "{ev:?}"
    );
    assert_eq!(h.peer_count(), 0);
    h.shutdown();
}

fn liveness_cfg(idle_ms: u64, keep_alive_ms: u64) -> NetConfig {
    let mut c = cfg();
    c.idle_timeout = Duration::from_millis(idle_ms);
    c.keep_alive = Duration::from_millis(keep_alive_ms);
    c
}

fn ready_host_with(c: &NetConfig, id: &Identity) -> (HostHandle, VirtualLinkSender) {
    let (links_tx, links_rx) = virtual_link_queue(64);
    let h = host_virtual(c, id, room(4), links_rx);
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    (h, links_tx)
}

/// A shorter configured idle timeout drops a silenced peer at that time, not
/// at the 6 s default.
#[test]
fn a_dropped_link_times_out_at_the_configured_idle_timeout() {
    let c = liveness_cfg(2000, 500);
    let id = Identity::ephemeral();
    let (h, links) = ready_host_with(&c, &Identity::ephemeral());
    let (link, tap) = tapped(&links, "cut me fast", Box::new(|_, p| Some(p)));
    let cl = join_virtual(&c, &id, link);
    let peer = connected(&h, &cl, &id);
    let cut = Instant::now();
    tap.task.abort();
    let ev = wait_host(&h, 5, |e| matches!(e, HostEvent::PeerLeft { .. }));
    let host_after = cut.elapsed();
    assert!(
        matches!(ev, HostEvent::PeerLeft { peer: p, reason: LeaveReason::TimedOut } if p == peer),
        "{ev:?}"
    );
    assert!(
        host_after >= Duration::from_millis(1500) && host_after < Duration::from_millis(4500),
        "host dropped the peer after {host_after:?}, expected about 2 s"
    );
    let ev = wait_client(&cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::TimedOut
            }
        ),
        "{ev:?}"
    );
    assert!(
        cut.elapsed() < Duration::from_millis(4500),
        "{:?}",
        cut.elapsed()
    );
    h.shutdown();
}

/// A long idle timeout with sparse keep-alives holds a live but quiet
/// connection open well past the 6 s default.
#[test]
fn a_quiet_peer_survives_past_the_default_idle_timeout_when_configured() {
    // A keep-alive every 8 s would not save a 6 s idle timeout.
    let c = liveness_cfg(12_000, 8_000);
    let id = Identity::ephemeral();
    let (h, links) = ready_host_with(&c, &Identity::ephemeral());
    let (link, tap) = tapped(&links, "quiet", Box::new(|_, p| Some(p)));
    let cl = join_virtual(&c, &id, link);
    let peer = connected(&h, &cl, &id);
    std::thread::sleep(Duration::from_secs(1));
    let quiet_from = tap.log.lock().unwrap().len();
    std::thread::sleep(Duration::from_secs(9));
    // The configured 8 s keep-alive is in use: the default 1 s one would put
    // some 35 packets on the link in that time.
    let quiet_packets = tap.log.lock().unwrap().len() - quiet_from;
    assert!(quiet_packets <= 12, "{quiet_packets} packets while quiet");
    while let Some(ev) = h.poll() {
        assert!(!matches!(ev, HostEvent::PeerLeft { .. }), "{ev:?}");
    }
    while let Some(ev) = cl.poll() {
        assert!(!matches!(ev, ClientEvent::Disconnected { .. }), "{ev:?}");
    }
    assert_eq!(h.peer_count(), 1);
    h.send_reliable(peer, Bytes::from_static(b"still here"));
    let ev = wait_client(&cl, 5, |e| matches!(e, ClientEvent::Reliable(_)));
    assert!(matches!(ev, ClientEvent::Reliable(b) if &b[..] == b"still here"));
    h.shutdown();
}

fn bad_liveness_pairs() -> Vec<(NetConfig, &'static str)> {
    vec![
        (liveness_cfg(6000, 0), "keep_alive"),
        (liveness_cfg(0, 500), "idle_timeout"),
        (liveness_cfg(0, 0), "idle_timeout"),
        (liveness_cfg(2000, 2000), "keep_alive"),
        (liveness_cfg(2000, 3000), "keep_alive"),
    ]
}

/// A bad liveness pair is refused by `host_virtual` and `join_virtual`.
#[test]
fn a_bad_liveness_pair_is_refused_on_virtual_links() {
    for (bad, word) in bad_liveness_pairs() {
        let (links_tx, links_rx) = virtual_link_queue(8);
        let h = host_virtual(&bad, &Identity::ephemeral(), room(4), links_rx);
        let ev = wait_host(&h, 5, |e| {
            matches!(e, HostEvent::Failed { .. } | HostEvent::Ready { .. })
        });
        assert!(
            matches!(&ev, HostEvent::Failed { reason } if reason.contains(word)),
            "{bad:?}: {ev:?}"
        );
        h.shutdown();
        drop(links_tx);

        let (_good_host, links) = ready_host(&Identity::ephemeral(), 4);
        let cl = join_virtual(&bad, &Identity::ephemeral(), dial(&links, "bad pair"));
        let ev = outcome(&cl);
        assert!(
            matches!(&ev, ClientEvent::Failed { reason: FailReason::Network(m), .. } if m.contains(word)),
            "{bad:?}: {ev:?}"
        );
    }
}

/// (e) Every packet on a link fits the frame budget: at most 1 + 1200 bytes,
/// never over `MAX_VIRTUAL_PACKET`; the joiner's first QUIC datagram (its
/// Initial) is padded to the full 1200, as QUIC requires.
#[test]
fn packets_on_a_link_respect_the_size_invariants() {
    const { assert!((VIRTUAL_MTU as usize) < MAX_VIRTUAL_PACKET) };
    let (h, links) = ready_host(&Identity::ephemeral(), 4);
    let id = Identity::ephemeral();
    let (link, tap) = tapped(&links, "sizes", Box::new(|_, p| Some(p)));
    let cl = join_virtual(&cfg(), &id, link);
    let peer = connected(&h, &cl, &id);
    // Bulk both ways, so full-size packets appear.
    for _ in 0..20 {
        cl.send_reliable(Bytes::from(vec![1u8; crate::MAX_RELIABLE_LEN]));
        cl.send_lossy(Bytes::from(vec![2u8; crate::MAX_LOSSY_LEN]));
        h.send_reliable(peer, Bytes::from(vec![3u8; crate::MAX_RELIABLE_LEN]));
        h.send_lossy(peer, Bytes::from(vec![4u8; crate::MAX_LOSSY_LEN]));
    }
    std::thread::sleep(Duration::from_millis(500));
    let log = tap.log.lock().unwrap().clone();
    assert!(log.len() > 20, "traffic flowed: {}", log.len());
    let (first_dir, first) = &log[0];
    assert_eq!(
        (*first_dir, first.len(), first[0]),
        (Dir::Down, 33, TAG_TOKEN),
        "the pre-frame comes first"
    );
    let up_first = log
        .iter()
        .find(|(d, _)| *d == Dir::Up)
        .expect("the joiner spoke");
    assert_eq!(up_first.1[0], TAG_QUIC);
    assert!(
        up_first.1.len() > VIRTUAL_MTU as usize,
        "the Initial is padded to 1200: {}",
        up_first.1.len() - 1
    );
    let mut biggest = 0;
    for (n, (_, p)) in log.iter().enumerate() {
        assert!(
            p.len() <= MAX_VIRTUAL_PACKET,
            "packet {n} is {} bytes",
            p.len()
        );
        if n > 0 {
            assert_eq!(p[0], TAG_QUIC, "packet {n}: only QUIC after the pre-frame");
            assert!(
                p.len() <= 1 + VIRTUAL_MTU as usize,
                "packet {n} is {} bytes",
                p.len()
            );
        }
        biggest = biggest.max(p.len());
    }
    assert_eq!(
        biggest,
        1 + VIRTUAL_MTU as usize,
        "full-size packets were seen"
    );
    cl.shutdown();
    h.shutdown();
}

#[test]
fn preframe_and_packet_parsing_is_exact() {
    let t = [9u8; 32];
    assert_eq!(parse_preframe(&preframe(&t)), Some(t));
    assert_eq!(parse_preframe(&preframe(&t)[..32]), None);
    let mut long = preframe(&t);
    long.push(0);
    assert_eq!(parse_preframe(&long), None);
    let mut wrong = preframe(&t);
    wrong[0] = TAG_QUIC;
    assert_eq!(parse_preframe(&wrong), None);
    assert_eq!(
        quic_payload(&[TAG_QUIC]),
        None,
        "an empty QUIC packet is garbage"
    );
    assert_eq!(quic_payload(&[TAG_QUIC, 1]), Some(&[1u8][..]));
    assert_eq!(quic_payload(&vec![TAG_QUIC; MAX_VIRTUAL_PACKET + 1]), None);
    assert_eq!(quic_payload(&preframe(&t)), None);
}

/// V4: no connection migration. An attacker who diverts one of a joiner's
/// packets onto its own link (connection ids travel in clear) must not get
/// the host to answer there: the packet is discarded, not a "move".
#[test]
fn a_diverted_packet_does_not_migrate_the_connection() {
    let (h, links) = ready_host(&Identity::ephemeral(), 4);
    let mut attacker = dial(&links, "attacker");
    assert!(
        matches!(recv_within(&mut attacker, 5), Ok(Some(_))),
        "the attacker's link is in"
    );
    let steal = Arc::new(AtomicBool::new(false));
    let (st, divert) = (Arc::clone(&steal), attacker.tx.clone());
    let rewrite: Rewrite = Box::new(move |dir, p| {
        // A short-header (1-RTT) packet from the joiner: send it down the
        // attacker's link instead of the joiner's.
        if dir == Dir::Up && p.len() > 1 && p[1] & 0x80 == 0 && st.swap(false, Ordering::SeqCst) {
            let _ = divert.try_send(p);
            return None;
        }
        Some(p)
    });
    let id = Identity::ephemeral();
    let (link, _tap) = tapped(&links, "victim", rewrite);
    let cl = join_virtual(&cfg(), &id, link);
    connected(&h, &cl, &id);
    steal.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(5);
    while steal.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!steal.load(Ordering::SeqCst), "a packet was diverted");
    let got = recv_within(&mut attacker, 2);
    assert!(
        got.is_err(),
        "the host must not answer on the attacker's link: {:?}",
        got.map(|p| p.map(|p| p.len()))
    );
    assert!(cl.is_connected(), "the joiner is unaffected");
    h.shutdown();
}

/// The app's exporter value matches on both ends of a virtual link too.
#[test]
fn a_virtual_link_gives_both_ends_the_same_app_value() {
    let mut c = cfg();
    c.app_binding_label = Some("EXPORTER-test-app-join-v1".into());
    let (links_tx, links_rx) = virtual_link_queue(64);
    let h = host_virtual(&c, &Identity::ephemeral(), room(4), links_rx);
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let cl = join_virtual(&c, &Identity::ephemeral(), dial(&links_tx, "BLE app"));
    let ev = outcome(&cl);
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    let HostEvent::PeerJoined { peer, .. } =
        wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    let mine = cl.app_binding().expect("client computes it");
    assert_eq!(h.app_binding(peer), Some(mine));
    assert_ne!(Some(mine), cl.tls_binding());
    h.shutdown();
}
