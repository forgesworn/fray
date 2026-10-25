//! One listener, one UDP port: many rooms of two apps (K2-1).

use super::*;
use crate::client::join_invite_with_relay;
use crate::quic::{self, close, Ended};
use crate::room::{derive_invite, utc_today, InviteId};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const APP_A: &str = "fray-k2-a";
const APP_B: &str = "fray-k2-b";

fn listener() -> Listener {
    Listener::bind(ListenerConfig {
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    })
    .unwrap()
}

fn app(tag: &str) -> NetConfig {
    let mut c = cfg();
    c.app_tag = tag.into();
    c
}

/// The listener's port on loopback.
fn addr(l: &Listener) -> SocketAddr {
    SocketAddr::new(
        std::net::Ipv4Addr::LOCALHOST.into(),
        l.local_addr().expect("bound").port(),
    )
}

/// A room of `tag` on `l`, answering codes and invites over `hub`.
fn open(l: &Listener, hub: &FakeRelayHub, tag: &str, id: &Identity) -> (HostHandle, String) {
    let h = l.host_with_relay(&app(tag), id, room(8), Some(Box::new(hub.client())));
    let code = wait_ready(&h);
    (h, code)
}

/// A LAN-only room of `tag` on `l`.
fn open_lan(l: &Listener, tag: &str) -> HostHandle {
    let h = l.host(&app(tag), &Identity::ephemeral(), room(8));
    wait_ready(&h);
    h
}

/// A room answers new codes and invites a moment after the change.
fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0xa5; 32];
    s[0] = n;
    s
}

fn lan(h: &HostHandle) -> [u8; 32] {
    hex::decode(h.lan_token()).unwrap().try_into().unwrap()
}

fn code_token(tag: &str, code: &str) -> [u8; 32] {
    derive(tag, code, utc_today()).unwrap().admit
}

/// The next join the room reports: (peer, key, how it was admitted).
fn joined(h: &HostHandle) -> (PeerId, PublicKey, Admission) {
    let HostEvent::PeerJoined {
        peer,
        pubkey,
        admitted_by,
        ..
    } = wait_host(h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    (peer, pubkey, admitted_by)
}

fn connected(cl: &ClientHandle) {
    let ev = join_outcome(cl);
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
}

fn no_answer(cl: &ClientHandle) {
    let ev = join_outcome(cl);
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::FindingHost,
                reason: FailReason::NoAnswer
            }
        ),
        "{ev:?}"
    );
}

/// Dial the listener as app `tag` and send a hello proving `token` only.
/// Whether a room welcomed us (only an admitted hello is), and how it ended.
fn raw_hello(tag: &str, addr: SocketAddr, token: [u8; 32]) -> (bool, Option<Ended>) {
    let welcomed = Arc::new(AtomicBool::new(false));
    let w = Arc::clone(&welcomed);
    let tag = tag.to_string();
    let ended = crate::runtime().block_on(async move {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let ep = quic::client_endpoint(socket, &tag, quic::Liveness::DEFAULT).unwrap();
        let conn = match ep.connect(addr, quic::SERVER_NAME).unwrap().await {
            Ok(c) => c,
            Err(e) => return Some(Ended::Error(e.to_string())),
        };
        let check: quic::HostCheck = Arc::new(move |_| {
            w.store(true, Ordering::Relaxed);
            Err("stop after the welcome".into())
        });
        let _ = quic::client_open(&conn, None, PathKind::Lan, &[token], &check).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.close_reason().map(|e| quic::ended_of(&e))
    });
    (welcomed.load(Ordering::Relaxed), ended)
}

fn refused(tag: &str, addr: SocketAddr, token: [u8; 32]) {
    let (welcomed, ended) = raw_hello(tag, addr, token);
    assert!(!welcomed);
    assert!(
        matches!(ended, Some(Ended::Remote(close::NOT_ADMITTED, _))),
        "{ended:?}"
    );
}

/// Exchange one reliable message each way between a seated peer and its room.
fn still_talking(h: &HostHandle, peer: PeerId, cl: &ClientHandle, tag: &'static [u8]) {
    cl.send_reliable(Bytes::from_static(tag));
    let ev = wait_host(h, 5, |e| matches!(e, HostEvent::Reliable { .. }));
    assert!(
        matches!(&ev, HostEvent::Reliable { peer: p, bytes } if *p == peer && &bytes[..] == tag),
        "{ev:?}"
    );
    h.send_reliable(peer, Bytes::from_static(tag));
    let ev = wait_client(cl, 5, |e| matches!(e, ClientEvent::Reliable(_)));
    assert!(
        matches!(&ev, ClientEvent::Reliable(b) if &b[..] == tag),
        "{ev:?}"
    );
}

/// Acceptance 2: apps A and B, two rooms each, one UDP port. Code, LAN-token
/// and invite joins land in the room whose token was proved; an A client
/// never reaches a B room, even with B's own tokens; an app the listener does
/// not host is refused; peer ids are unique on the endpoint.
#[test]
fn one_port_serves_two_apps_with_two_rooms_each_and_joins_land_where_they_proved() {
    let hub = FakeRelayHub::new();
    let l = listener();
    let host_id = Identity::ephemeral();
    let rooms: Vec<(&str, HostHandle, String)> = [APP_A, APP_A, APP_B, APP_B]
        .into_iter()
        .map(|tag| {
            let (h, code) = open(&l, &hub, tag, &host_id);
            (tag, h, code)
        })
        .collect();
    let port = l.local_addr().unwrap().port();
    for (_, h, _) in &rooms {
        assert_eq!(h.local_addr().unwrap().port(), port, "one UDP port");
    }
    assert_eq!(l.room_count(), 4);
    let codes: HashSet<&String> = rooms.iter().map(|(_, _, c)| c).collect();
    assert_eq!(codes.len(), 4);

    let mut peers = HashSet::new();
    let mut clients = Vec::new();
    // By code, over the relays.
    for (tag, h, code) in &rooms {
        let id = Identity::ephemeral();
        let cl = join_with_relay(&app(tag), &id, code, Box::new(hub.client()));
        connected(&cl);
        let (peer, pubkey, by) = joined(h);
        assert_eq!((pubkey, by), (id.pubkey(), Admission::Code));
        assert!(peers.insert(peer), "peer ids are unique on the endpoint");
        clients.push(cl);
    }
    // By LAN token, dialled straight at the one port.
    for (tag, h, _) in &rooms {
        let id = Identity::ephemeral();
        let cl = join_addr(&app(tag), &id, addr(&l), &h.lan_token());
        connected(&cl);
        let (peer, pubkey, by) = joined(h);
        assert_eq!((pubkey, by), (id.pubkey(), Admission::Lan));
        assert!(peers.insert(peer));
        clients.push(cl);
    }
    for (_, h, _) in &rooms {
        assert_eq!(h.peer_count(), 2, "each join landed in its own room");
    }

    // By a room's own invite.
    let (_, a1, _) = &rooms[0];
    let s = secret(1);
    let invite = a1.add_invite(s).unwrap();
    settle();
    let id = Identity::ephemeral();
    let cl = join_invite_with_relay(
        &app(APP_A),
        &id,
        &s,
        host_id.pubkey().to_bytes(),
        Box::new(hub.client()),
    );
    connected(&cl);
    let (peer, pubkey, by) = joined(a1);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Invite(invite)));
    assert!(peers.insert(peer));
    clients.push(cl);

    // An A client cannot reach a B room. With B's code it finds nobody (the
    // code's tags are the app's) ...
    let (_, b1, code_b1) = &rooms[2];
    let cl = join_with_relay(
        &app(APP_A),
        &Identity::ephemeral(),
        code_b1,
        Box::new(hub.client()),
    );
    no_answer(&cl);
    // ... and dialling the port with B's own tokens, it is not admitted: its
    // protocol picks app A, whose rooms hold none of them.
    let at = addr(&l);
    refused(APP_A, at, lan(b1));
    refused(APP_A, at, code_token(APP_B, code_b1));
    assert!(
        raw_hello(APP_B, at, code_token(APP_B, code_b1)).0,
        "control: the same proof as app B is welcomed"
    );
    let cl = join_addr(&app(APP_A), &Identity::ephemeral(), at, &b1.lan_token());
    let ev = join_outcome(&cl);
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
    // An app the listener does not host is refused at the handshake.
    let (welcomed, ended) = raw_hello("fray-k2-unknown", at, lan(b1));
    assert!(!welcomed);
    assert!(matches!(ended, Some(Ended::Error(_))), "{ended:?}");

    for (_, h, _) in &rooms {
        let want = if std::ptr::eq(h, a1) { 3 } else { 2 };
        assert_eq!(h.peer_count(), want, "nothing landed in the wrong room");
    }
    drop(clients);
    l.shutdown();
}

/// Acceptance 3: one room shuts down, the other three keep serving (their
/// peers stay and new joins land), and a new room opens on the same port.
#[test]
fn shutting_one_room_down_leaves_the_others_serving_and_a_new_room_opens() {
    let l = listener();
    let at = addr(&l);
    let mut rooms: Vec<(&str, HostHandle)> = [APP_A, APP_A, APP_B, APP_B]
        .into_iter()
        .map(|tag| (tag, open_lan(&l, tag)))
        .collect();
    let mut seated = Vec::new();
    for (tag, h) in &rooms {
        let cl = join_addr(&app(tag), &Identity::ephemeral(), at, &h.lan_token());
        connected(&cl);
        let (peer, _, _) = joined(h);
        seated.push((peer, cl));
    }

    let (_, gone) = rooms.remove(0);
    let (_, gone_client) = seated.remove(0);
    let gone_token = lan(&gone);
    gone.shutdown();
    let ev = wait_client(&gone_client, 5, |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    });
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::HostLeft
            }
        ),
        "{ev:?}"
    );
    refused(APP_A, at, gone_token);
    assert_eq!(l.room_count(), 3);

    for ((tag, h), (peer, cl)) in rooms.iter().zip(&seated) {
        still_talking(h, *peer, cl, b"still here");
        let late = join_addr(&app(tag), &Identity::ephemeral(), at, &h.lan_token());
        connected(&late);
        joined(h);
        assert_eq!(h.peer_count(), 2);
    }

    let fresh = open_lan(&l, APP_A);
    assert_eq!(fresh.local_addr().unwrap().port(), at.port());
    assert_eq!(l.room_count(), 4);
    let cl = join_addr(&app(APP_A), &Identity::ephemeral(), at, &fresh.lan_token());
    connected(&cl);
    joined(&fresh);

    // Shutting the listener down closes every room.
    l.shutdown();
    for (_, cl) in &seated {
        wait_client(cl, 5, |e| {
            matches!(
                e,
                ClientEvent::Disconnected {
                    reason: DisconnectReason::HostLeft
                }
            )
        });
    }
}

/// Acceptance 4: a new code keeps the peers in; the new code admits, the old
/// one is refused.
#[test]
fn rotate_code_keeps_peers_in_and_moves_new_joins_to_the_new_code() {
    let hub = FakeRelayHub::new();
    let l = listener();
    let at = addr(&l);
    let (mut h, old) = open(&l, &hub, APP_A, &Identity::ephemeral());
    // A second room of the app, which must never get the same code.
    let (_other, _) = open(&l, &hub, APP_A, &Identity::ephemeral());

    let first = join_with_relay(
        &app(APP_A),
        &Identity::ephemeral(),
        &old,
        Box::new(hub.client()),
    );
    connected(&first);
    let (peer, _, _) = joined(&h);
    still_talking(&h, peer, &first, b"before");

    let new = h.rotate_code().unwrap();
    assert_ne!(new, old);
    assert_eq!(h.code(), new);
    // At once: the old code's proof is refused.
    refused(APP_A, at, code_token(APP_A, &old));

    // The peer already in stays and keeps talking.
    still_talking(&h, peer, &first, b"after");

    settle();
    let id = Identity::ephemeral();
    let second = join_with_relay(&app(APP_A), &id, &new, Box::new(hub.client()));
    connected(&second);
    let (_, pubkey, by) = joined(&h);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Code));

    let late = join_with_relay(
        &app(APP_A),
        &Identity::ephemeral(),
        &old,
        Box::new(hub.client()),
    );
    no_answer(&late);
    assert!(raw_hello(APP_A, at, code_token(APP_A, &new)).0);

    still_talking(&h, peer, &first, b"later");
    assert_eq!(h.peer_count(), 2);
    while let Some(ev) = first.poll() {
        assert!(
            !matches!(ev, ClientEvent::Disconnected { .. }),
            "the first peer was dropped"
        );
    }
    l.shutdown();
}

/// `rotate_code` on a plain single-room host: the same promise, and the LAN
/// token rotates with the code.
#[test]
fn rotate_code_on_a_plain_host_keeps_peers_and_rotates_the_lan_token() {
    let hub = FakeRelayHub::new();
    let mut h = host_with_relay(
        &cfg(),
        &Identity::ephemeral(),
        room(8),
        Some(Box::new(hub.client())),
    );
    let old = wait_ready(&h);
    let at = local_addr_again(&h);
    let old_lan = lan(&h);
    let first = join_addr(&cfg(), &Identity::ephemeral(), at, &h.lan_token());
    connected(&first);
    let (peer, _, _) = joined(&h);

    let new = h.rotate_code().unwrap();
    assert_ne!(new, old);
    assert_ne!(lan(&h), old_lan);
    let raw = |token| {
        let (w, e) = raw_hello(TAG, at, token);
        (w, e)
    };
    for refused in [raw(old_lan), raw(code_token(TAG, &old))] {
        assert!(!refused.0);
        assert!(
            matches!(refused.1, Some(Ended::Remote(close::NOT_ADMITTED, _))),
            "{:?}",
            refused.1
        );
    }
    still_talking(&h, peer, &first, b"kept");
    settle();
    let second = join_with_relay(&cfg(), &Identity::ephemeral(), &new, Box::new(hub.client()));
    connected(&second);
    assert_eq!(joined(&h).2, Admission::Code);
    let third = join_addr(&cfg(), &Identity::ephemeral(), at, &h.lan_token());
    connected(&third);
    assert_eq!(joined(&h).2, Admission::Lan);
    h.shutdown();
}

/// Acceptance 5: a listener-level invite lands in its app's target room;
/// moving the target moves later invite joins; no target refuses.
#[test]
fn listener_invites_land_in_the_target_room_and_follow_it() {
    let hub = FakeRelayHub::new();
    let l = listener();
    let at = addr(&l);
    let host_id = Identity::ephemeral();
    let key = host_id.pubkey().to_bytes();
    let (a1, _) = open(&l, &hub, APP_A, &host_id);
    let (a2, _) = open(&l, &hub, APP_A, &host_id);
    let (b1, _) = open(&l, &hub, APP_B, &host_id);
    let s = secret(7);
    let invite = l.add_invite(APP_A, s).unwrap();
    assert_eq!(invite, InviteId::of(&s));
    assert_eq!(
        l.add_invite(APP_A, s).unwrap(),
        invite,
        "same secret, same id"
    );
    let proof = derive_invite(APP_A, &s, utc_today()).unwrap().admit;
    let join = || {
        let id = Identity::ephemeral();
        let cl = join_invite_with_relay(&app(APP_A), &id, &s, key, Box::new(hub.client()));
        (cl, id)
    };

    // No target room: refused as an invite that is not live.
    settle();
    let (cl, _) = join();
    no_answer(&cl);
    refused(APP_A, at, proof);

    // Target a1.
    a1.set_invite_target(true).unwrap();
    assert!(a1.is_invite_target() && !a2.is_invite_target());
    settle();
    let (cl1, id) = join();
    connected(&cl1);
    let (_, pubkey, by) = joined(&a1);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Invite(invite)));

    // Move it to a2: later invite joins land there.
    a2.set_invite_target(true).unwrap();
    assert!(a2.is_invite_target() && !a1.is_invite_target());
    // Another app's target leaves A's alone.
    b1.set_invite_target(true).unwrap();
    assert!(a2.is_invite_target());
    settle();
    let (cl2, id) = join();
    connected(&cl2);
    let (_, pubkey, by) = joined(&a2);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Invite(invite)));
    assert_eq!(
        (a1.peer_count(), a2.peer_count(), b1.peer_count()),
        (1, 1, 0)
    );

    // B's invite target does not take A's invite, even over B's protocol.
    refused(APP_B, at, proof);

    // Revoked: refused at once; the peers it admitted stay.
    assert!(l.remove_invite(APP_A, invite));
    assert!(!l.remove_invite(APP_A, invite), "already gone");
    refused(APP_A, at, proof);
    assert_eq!((a1.peer_count(), a2.peer_count()), (1, 1));

    // Live again, then the target cleared: no target refuses.
    l.add_invite(APP_A, s).unwrap();
    settle();
    assert!(raw_hello(APP_A, at, proof).0, "control: live in a2 again");
    a2.set_invite_target(false).unwrap();
    assert!(!a2.is_invite_target());
    refused(APP_A, at, proof);
    settle();
    let (cl, _) = join();
    no_answer(&cl);

    // A target that shuts down leaves no target behind.
    a1.set_invite_target(true).unwrap();
    settle();
    assert!(raw_hello(APP_A, at, proof).0);
    a1.shutdown();
    refused(APP_A, at, proof);
    assert!(!a2.is_invite_target());

    // A plain host has no listener invites.
    let plain = host(&cfg(), &Identity::ephemeral(), room(4));
    assert!(plain.set_invite_target(true).is_err());
    plain.shutdown();
    drop((cl1, cl2));
    l.shutdown();
}

/// Review: a room shut down while a handshake is parked before its seat
/// seats nobody; a code rotated meanwhile refuses the old proof at the seat.
#[test]
fn a_room_shut_down_or_rotated_mid_handshake_seats_nobody() {
    let l = listener();
    let at = addr(&l);
    let h = open_lan(&l, APP_A);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    h.pause_before_seating(Some(Arc::clone(&barrier)));
    let cl = join_addr(&app(APP_A), &Identity::ephemeral(), at, &h.lan_token());
    crate::runtime().block_on(barrier.wait());
    h.shutdown();
    crate::runtime().block_on(barrier.wait());
    let ev = join_outcome(&cl);
    assert!(!matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");

    let mut h = open_lan(&l, APP_A);
    h.pause_before_seating(Some(Arc::clone(&barrier)));
    let cl = join_addr(&app(APP_A), &Identity::ephemeral(), at, &h.lan_token());
    crate::runtime().block_on(barrier.wait());
    h.rotate_code().unwrap();
    crate::runtime().block_on(barrier.wait());
    let ev = join_outcome(&cl);
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
    h.pause_before_seating(None);
    let cl = join_addr(&app(APP_A), &Identity::ephemeral(), at, &h.lan_token());
    connected(&cl);
    assert_eq!(h.peer_count(), 1);
    l.shutdown();
}

/// Acceptance 6 (in-crate half): a room on a listener announces the
/// listener's candidates, and a plain host the ones it gathered; with
/// advertise-only that is exactly the configured list.
#[test]
fn announced_is_the_listeners_list_for_every_room() {
    let port = free_udp_port();
    let advertise = vec![
        sa(&format!("192.168.77.9:{port}")),
        sa(&format!("203.0.113.9:{port}")),
    ];
    let l = Listener::bind(ListenerConfig {
        quic_port: port,
        advertise: advertise.clone(),
        advertise_only: true,
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    });
    // 203.0.113/24 is documentation space: refused like a host's config.
    assert!(l.is_err());
    let advertise = vec![
        sa(&format!("192.168.77.9:{port}")),
        sa(&format!("100.64.7.9:{port}")),
    ];
    let l = Listener::bind(ListenerConfig {
        quic_port: port,
        advertise: advertise.clone(),
        advertise_only: true,
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    })
    .unwrap();
    let want = crate::nat::candidates::advertised_candidates(&advertise).unwrap();
    assert_eq!(l.announced(), want);
    let a = open_lan(&l, APP_A);
    let b = open_lan(&l, APP_B);
    assert_eq!(a.announced(), want);
    assert_eq!(b.announced(), want);
    assert_eq!(a.local_addr().unwrap().port(), port);
    l.shutdown();
}

// ─── Review fixes (K2-1): resource release, a closed room's last word, no
// migration on a listener, per-room policy, rotation and the day roll ───

/// The reason a join ended in `Failed`.
fn fail_reason(cl: &ClientHandle) -> FailReason {
    match join_outcome(cl) {
        ClientEvent::Failed { reason, .. } => reason,
        other => panic!("expected a refused join, got {other:?}"),
    }
}

/// Review S1: the UDP port is free once the listener has shut down, even while
/// a handle to one of its rooms is still held (a status table, a manager).
#[test]
fn the_port_is_free_after_the_listener_shuts_down_with_a_room_handle_alive() {
    let port = free_udp_port();
    let l = Listener::bind(ListenerConfig {
        quic_port: port,
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    })
    .unwrap();
    let h = open_lan(&l, APP_A);
    let _other = open_lan(&l, APP_B);
    let bind = || std::net::UdpSocket::bind(("0.0.0.0", port));
    assert!(bind().is_err(), "control: the listener holds the port");
    l.shutdown();
    let deadline = Instant::now() + Duration::from_secs(5);
    let freed = loop {
        match bind() {
            Ok(socket) => break socket,
            Err(e) => assert!(
                Instant::now() < deadline,
                "the port is still held with a room handle alive: {e}"
            ),
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(freed);
    // The handle is still usable as a handle: it knows it is closed.
    assert!(h.is_closed());
    // A new listener takes the port at once.
    let again = Listener::bind(ListenerConfig {
        quic_port: port,
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    })
    .unwrap();
    again.shutdown();
}

/// Review S2: a listener that closes its rooms tells their handles, once, with
/// `Failed`, and `is_closed` says so; shutdown and drop both do it.
#[test]
fn closing_the_listener_tells_every_room_handle_once() {
    for by_drop in [false, true] {
        let l = listener();
        let at = addr(&l);
        let a = open_lan(&l, APP_A);
        let b = open_lan(&l, APP_B);
        let cl = join_addr(&app(APP_A), &Identity::ephemeral(), at, &a.lan_token());
        connected(&cl);
        joined(&a);
        assert!(!a.is_closed() && !b.is_closed());
        if by_drop {
            drop(l);
        } else {
            l.shutdown();
        }
        for h in [&a, &b] {
            let ev = wait_host(h, 5, |e| matches!(e, HostEvent::Failed { .. }));
            assert!(
                matches!(&ev, HostEvent::Failed { reason } if reason.contains("listener")),
                "{ev:?}"
            );
            assert!(h.is_closed());
        }
        // Once, and nothing after it but the peers leaving.
        std::thread::sleep(Duration::from_millis(300));
        for h in [&a, &b] {
            while let Some(ev) = h.poll() {
                assert!(
                    matches!(ev, HostEvent::PeerLeft { .. }),
                    "unexpected after the close: {ev:?}"
                );
            }
        }
        let ev = wait_client(&cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
        assert!(
            matches!(
                ev,
                ClientEvent::Disconnected {
                    reason: DisconnectReason::HostLeft
                }
            ),
            "{ev:?}"
        );
    }
}

/// A room shut by its own handle leaves the listener's other rooms open and
/// untold.
#[test]
fn a_room_shut_by_its_own_handle_leaves_the_listeners_other_rooms_open() {
    let l = listener();
    let a = open_lan(&l, APP_A);
    let b = open_lan(&l, APP_A);
    a.shutdown();
    assert!(!b.is_closed());
    std::thread::sleep(Duration::from_millis(200));
    while let Some(ev) = b.poll() {
        assert!(!matches!(ev, HostEvent::Failed { .. }), "{ev:?}");
    }
    l.shutdown();
}

/// Review S3: a room on a listener does not migrate (its admission of a pinned
/// room is built on owning the endpoint), and stays an ordinary room.
#[test]
fn a_room_on_a_listener_refuses_to_pin_a_session_and_stays_ordinary() {
    use crate::migration::*;
    let l = listener();
    let at = addr(&l);
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let c = app(APP_A);
    let h = l.host(&c, &original, room(8));
    wait_ready(&h);
    let root = Root {
        session: fresh_session().unwrap(),
        app: c.app_tag.clone(),
        transport_version: 7,
        game_version: 13,
        checkpoint_version: 1,
        host: original.pubkey().to_bytes(),
        standby: standby.pubkey().to_bytes(),
        controller: original.pubkey().to_bytes(),
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
    let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let err = h.pin_session(descriptor).unwrap_err();
    assert!(err.contains("listener"), "{err}");
    // Still an ordinary, open room.
    let cl = join_addr(&c, &Identity::ephemeral(), at, &h.lan_token());
    connected(&cl);
    assert_eq!(h.peer_count(), 1);
    l.shutdown();
}

/// Review coverage: the open flag, the deny list and `max_peers` are each
/// per room on a listener.
#[test]
fn open_flag_deny_list_and_max_peers_are_per_room_on_a_listener() {
    let l = listener();
    let at = addr(&l);
    let mut c = app(APP_A);
    c.host_has_player = true;
    // a1: room for one peer (two players, the host one of them).
    let a1 = l.host(&c, &Identity::ephemeral(), room(2));
    wait_ready(&a1);
    let a2 = open_lan(&l, APP_A);
    let a3 = open_lan(&l, APP_A);
    let dial = |h: &HostHandle, id: &Identity| join_addr(&c, id, at, &h.lan_token());

    // max_peers: a1 is full after one peer, a2 and a3 take theirs.
    let first = Identity::ephemeral();
    let cl1 = dial(&a1, &first);
    connected(&cl1);
    joined(&a1);
    assert_eq!(
        fail_reason(&dial(&a1, &Identity::ephemeral())),
        FailReason::RoomFull
    );
    let cl2 = dial(&a2, &Identity::ephemeral());
    connected(&cl2);
    joined(&a2);

    // The open flag: a2 closed refuses, while a1 (full) and a3 answer as theirs.
    a2.set_open_keeping_token(false);
    assert_eq!(
        fail_reason(&dial(&a2, &Identity::ephemeral())),
        FailReason::RoomClosed
    );
    let kicked = Identity::ephemeral();
    let cl3 = dial(&a3, &kicked);
    connected(&cl3);
    let (peer, _, _) = joined(&a3);
    assert_eq!(
        fail_reason(&dial(&a1, &Identity::ephemeral())),
        FailReason::RoomFull
    );

    // The deny list: a key kicked from a3 is refused there, and seated in a2
    // once a2 opens again.
    a3.kick(peer);
    wait_host(&a3, 5, |e| matches!(e, HostEvent::PeerLeft { .. }));
    assert_eq!(fail_reason(&dial(&a3, &kicked)), FailReason::NotAdmitted);
    a2.set_open_keeping_token(true);
    let again = dial(&a2, &kicked);
    connected(&again);
    joined(&a2);
    assert_eq!(
        (a1.peer_count(), a2.peer_count(), a3.peer_count()),
        (1, 2, 0)
    );
    drop((cl1, cl2, cl3));
    l.shutdown();
}

/// Review coverage (93901d1): a room rotated before its first derivation
/// finishes reports the newest code in `Ready` and answers only that one.
#[test]
fn rotating_before_ready_answers_only_the_newest_code() {
    let hub = FakeRelayHub::new();
    let l = listener();
    let at = addr(&l);
    let id = Identity::ephemeral();
    let mut h = l.host_with_relay(&app(APP_A), &id, room(8), Some(Box::new(hub.client())));
    let c0 = h.code().to_string();
    let c1 = h.rotate_code().unwrap();
    let c2 = h.rotate_code().unwrap();
    assert!(c0 != c1 && c1 != c2 && c0 != c2);
    assert_eq!(wait_ready(&h), c2, "Ready reports the newest code");
    assert_eq!(h.code(), c2);
    settle();
    refused(APP_A, at, code_token(APP_A, &c0));
    refused(APP_A, at, code_token(APP_A, &c1));
    assert!(raw_hello(APP_A, at, code_token(APP_A, &c2)).0);
    let join = |code: &str| {
        join_with_relay(
            &app(APP_A),
            &Identity::ephemeral(),
            code,
            Box::new(hub.client()),
        )
    };
    no_answer(&join(&c0));
    no_answer(&join(&c1));
    let ok = join(&c2);
    connected(&ok);
    assert_eq!(joined(&h).2, Admission::Code);
    l.shutdown();
}

/// Review coverage: an invite handshake parked just before its seat is
/// refused when the target moves away, or the invite is revoked, meanwhile.
#[test]
fn an_invite_handshake_parked_before_its_seat_is_refused_when_the_target_moves() {
    let hub = FakeRelayHub::new();
    let l = listener();
    let host_id = Identity::ephemeral();
    let key = host_id.pubkey().to_bytes();
    let (a1, _) = open(&l, &hub, APP_A, &host_id);
    let (a2, _) = open(&l, &hub, APP_A, &host_id);
    let s = secret(9);
    let invite = l.add_invite(APP_A, s).unwrap();
    a1.set_invite_target(true).unwrap();
    settle();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let join = || {
        join_invite_with_relay(
            &app(APP_A),
            &Identity::ephemeral(),
            &s,
            key,
            Box::new(hub.client()),
        )
    };

    // Moved away while parked in a1.
    a1.pause_before_seating(Some(Arc::clone(&barrier)));
    let cl = join();
    crate::runtime().block_on(barrier.wait());
    a2.set_invite_target(true).unwrap();
    crate::runtime().block_on(barrier.wait());
    assert_eq!(fail_reason(&cl), FailReason::NotAdmitted);
    assert_eq!((a1.peer_count(), a2.peer_count()), (0, 0));
    a1.pause_before_seating(None);

    // Revoked while parked in a2.
    settle();
    a2.pause_before_seating(Some(Arc::clone(&barrier)));
    let cl = join();
    crate::runtime().block_on(barrier.wait());
    assert!(l.remove_invite(APP_A, invite));
    crate::runtime().block_on(barrier.wait());
    assert_eq!(fail_reason(&cl), FailReason::NotAdmitted);
    assert_eq!((a1.peer_count(), a2.peer_count()), (0, 0));
    a2.pause_before_seating(None);

    // Control: live again, the next one lands in the new target.
    l.add_invite(APP_A, s).unwrap();
    settle();
    let id = Identity::ephemeral();
    let cl = join_invite_with_relay(&app(APP_A), &id, &s, key, Box::new(hub.client()));
    connected(&cl);
    let (_, pubkey, by) = joined(&a2);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Invite(invite)));
    l.shutdown();
}

/// Review coverage: the UTC midnight roll on a room of a listener rolls its
/// code tags and the listener invites it carries, and only that room's.
#[test]
fn the_midnight_roll_on_a_listener_room_rolls_that_rooms_tags_only() {
    let hub = FakeRelayHub::new();
    let l = listener();
    let at = addr(&l);
    let host_id = Identity::ephemeral();
    let (a1, c1) = open(&l, &hub, APP_A, &host_id);
    let (_a2, c2) = open(&l, &hub, APP_A, &host_id);
    let s = secret(3);
    let invite = l.add_invite(APP_A, s).unwrap();
    a1.set_invite_target(true).unwrap();
    settle();
    let today = utc_today();
    let by_code = |code: &str, day: u64| derive(APP_A, code, day).unwrap().admit;
    let by_invite = |day: u64| derive_invite(APP_A, &s, day).unwrap().admit;
    let takes = |token| raw_hello(APP_A, at, token).0;

    // Before: today and yesterday, not tomorrow.
    assert!(takes(by_code(&c1, today)) && takes(by_code(&c1, today - 1)));
    assert!(!takes(by_code(&c1, today + 1)));
    assert!(takes(by_invite(today)) && !takes(by_invite(today + 1)));

    // Midnight passes on a1 only; the roll derives the code again first.
    a1.set_test_day(today + 1);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !(takes(by_code(&c1, today + 1)) && takes(by_invite(today + 1))) {
        assert!(Instant::now() < deadline, "the room never rolled");
    }
    assert!(takes(by_code(&c1, today)), "yesterday's still works");
    assert!(!takes(by_code(&c1, today - 1)), "the day before is dropped");
    assert!(takes(by_invite(today)), "yesterday's invite still works");
    assert!(
        !takes(by_invite(today - 1)),
        "the day before's invite is dropped"
    );

    // a2 did not roll.
    assert!(takes(by_code(&c2, today)) && takes(by_code(&c2, today - 1)));
    assert!(!takes(by_code(&c2, today + 1)));

    // A joiner on the real clock still finds the rolled room by code and by invite.
    let id = Identity::ephemeral();
    let cl = join_with_relay(&app(APP_A), &id, &c1, Box::new(hub.client()));
    connected(&cl);
    let (_, pubkey, by) = joined(&a1);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Code));
    let id = Identity::ephemeral();
    let cl = join_invite_with_relay(
        &app(APP_A),
        &id,
        &s,
        host_id.pubkey().to_bytes(),
        Box::new(hub.client()),
    );
    connected(&cl);
    let (_, pubkey, by) = joined(&a1);
    assert_eq!((pubkey, by), (id.pubkey(), Admission::Invite(invite)));

    // A rotation after the roll installs the new code for the new day.
    let mut a1 = a1;
    let new = a1.rotate_code().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !takes(by_code(&new, today + 1)) {
        assert!(Instant::now() < deadline, "the rotated code never came in");
    }
    assert!(!takes(by_code(&c1, today + 1)));
    l.shutdown();
}

// ─── Follow-ups (K2-1): asking the listener and the room why ───

/// `Listener::is_closed` and `HostHandle::closed_by_listener` tell a listener's
/// close from a room's own, without matching text.
#[test]
fn a_room_can_tell_a_listener_close_from_its_own() {
    let l = listener();
    assert!(!l.is_closed());
    let own = open_lan(&l, APP_A);
    let told = open_lan(&l, APP_A);
    own.shutdown();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!l.is_closed(), "a room closing does not close the listener");
    assert!(!told.closed_by_listener() && !told.is_closed());
    l.shutdown_inner(Duration::from_millis(1000));
    assert!(l.is_closed());
    let ev = wait_host(&told, 5, |e| matches!(e, HostEvent::Failed { .. }));
    assert!(
        matches!(&ev, HostEvent::Failed { reason } if reason == crate::LISTENER_SHUTDOWN_REASON),
        "{ev:?}"
    );
    assert!(told.closed_by_listener() && told.is_closed());
    // A room opened on the closed listener is told the same way.
    let late = l.host(&app(APP_A), &Identity::ephemeral(), room(8));
    let ev = wait_host(&late, 5, |e| matches!(e, HostEvent::Failed { .. }));
    assert!(
        matches!(&ev, HostEvent::Failed { reason } if reason == crate::LISTENER_SHUTDOWN_REASON),
        "{ev:?}"
    );
    assert!(late.closed_by_listener() && late.is_closed());
    // A room of its own is never closed by a listener.
    let alone = host(&cfg(), &Identity::ephemeral(), room(8));
    wait_ready(&alone);
    assert!(!alone.closed_by_listener() && !alone.is_closed());
    alone.shutdown();
}

/// Review R1: a room opened just before its listener goes (still deriving its
/// code, so its task is late) is told once, and says nothing after: no `Ready`
/// and no second `Failed` follow the listener's `Failed`.
#[test]
fn a_room_opened_just_before_the_listener_drops_says_nothing_after_its_failed() {
    for _ in 0..2 {
        let hub = FakeRelayHub::new();
        let l = listener();
        let rooms: Vec<HostHandle> = (0..24)
            .map(|_| {
                l.host_with_relay(
                    &app(APP_A),
                    &Identity::ephemeral(),
                    room(8),
                    Some(Box::new(hub.client())),
                )
            })
            .collect();
        drop(l);
        // Longer than the derivation, so a late `Ready` would show.
        std::thread::sleep(Duration::from_millis(3000));
        for h in &rooms {
            let mut failed = 0;
            while let Some(ev) = h.poll() {
                match ev {
                    HostEvent::Failed { reason } => {
                        assert_eq!(reason, crate::LISTENER_SHUTDOWN_REASON);
                        failed += 1;
                    }
                    HostEvent::Ready { .. } => assert_eq!(failed, 0, "Ready after Failed"),
                    HostEvent::PeerLeft { .. } => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(failed, 1, "told exactly once");
            assert!(h.closed_by_listener() && h.is_closed());
        }
    }
}
