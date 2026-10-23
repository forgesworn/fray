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
    assert_eq!(
        raw_hello(tag, addr, token),
        (false, Some(Ended::Remote(close::NOT_ADMITTED)))
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
    assert_eq!(
        raw(old_lan),
        (false, Some(Ended::Remote(close::NOT_ADMITTED)))
    );
    assert_eq!(
        raw(code_token(TAG, &old)),
        (false, Some(Ended::Remote(close::NOT_ADMITTED)))
    );
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
