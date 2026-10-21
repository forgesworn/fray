//! End-to-end tests over real QUIC on localhost. The rendezvous tests use the
//! in-memory relay, so nothing here needs the internet.

use std::time::{Duration, Instant};

use crate::client::{join_with_relay, join_with_relay_at_day};
use crate::host::{host_with_relay, host_with_relay_at_day};
use crate::relay::{FakeRelayHub, RendezvousRelay, TagFilter};
use crate::rendezvous::{open_offer, seal_answer, Answer, Candidate, KIND_JOIN_OFFER};
use crate::room::{derive, ROOM_TAG_LETTER};
use crate::*;

/// The app tag the room-code vectors were made with.
const TAG: &str = "twangthang";

fn cfg() -> NetConfig {
    let mut r = [0u8; 2];
    getrandom::fill(&mut r).unwrap();
    let mut c = NetConfig::new(std::env::temp_dir(), TAG).lan_only();
    // A private beacon port per test, so tests never hear each other.
    c.lan_port = 30000 + (u16::from_le_bytes(r) % 20000);
    c
}

fn room(max: u8) -> RoomInfo {
    RoomInfo {
        name: "Test room".into(),
        max_players: max,
    }
}

fn wait_host(h: &HostHandle, secs: u64, mut pred: impl FnMut(&HostEvent) -> bool) -> HostEvent {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        while let Some(ev) = h.poll() {
            if pred(&ev) {
                return ev;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("host event not seen within {secs}s");
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

fn local_addr(h: &HostHandle) -> std::net::SocketAddr {
    wait_host(h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let a = h.local_addr().expect("listening");
    std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), a.port())
}

/// Host + one client over the LAN path; returns (host, client, peer id).
fn connected_pair(max: u8) -> (HostHandle, ClientHandle, PeerId, Identity) {
    let c = cfg();
    let host_id = Identity::ephemeral();
    let h = host(&c, &host_id, room(max));
    let addr = local_addr(&h);
    let id = Identity::ephemeral();
    let cl = join_addr(&c, &id, addr, &h.lan_token());
    let ev = wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let ClientEvent::Connected {
        path,
        host_name,
        host_pubkey,
        attestation,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(attestation, None, "no persona attached");
    assert_eq!(path, PathKind::Lan);
    assert_eq!(
        host_name, "Test room",
        "the joiner learns the host's name before the lobby"
    );
    assert_eq!(host_pubkey, host_id.pubkey(), "... and its proven key");
    let HostEvent::PeerJoined {
        peer, pubkey, path, ..
    } = wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    assert_eq!(
        pubkey,
        id.pubkey(),
        "the host learns the joiner's proven identity"
    );
    assert_eq!(path, PathKind::Lan);
    (h, cl, peer, id)
}

/// Each side's persona attestation reaches the other with its proven key.
#[test]
fn attestations_are_exposed_on_peer_joined_and_connected() {
    let c = cfg();
    let host_id = Identity::ephemeral().with_attestation("{\"host\":1}".into());
    let h = host(&c, &host_id, room(4));
    let addr = local_addr(&h);
    let id = Identity::ephemeral().with_attestation("{\"joiner\":2}".into());
    let cl = join_addr(&c, &id, addr, &h.lan_token());
    let ev = wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let ClientEvent::Connected {
        host_pubkey,
        attestation,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(host_pubkey, host_id.pubkey());
    assert_eq!(
        attestation.as_deref(),
        Some("{\"host\":1}"),
        "the joiner gets the host's attestation"
    );
    let HostEvent::PeerJoined {
        pubkey,
        attestation,
        ..
    } = wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    assert_eq!(pubkey, id.pubkey());
    assert_eq!(
        attestation.as_deref(),
        Some("{\"joiner\":2}"),
        "the host gets the joiner's attestation"
    );
    cl.shutdown();
    h.shutdown();
}

#[test]
fn reliable_and_datagram_messages_flow_both_ways() {
    let (h, cl, peer, _) = connected_pair(4);

    for i in 0..50u8 {
        cl.send_reliable(Bytes::from(vec![i; 100]));
    }
    let mut got = Vec::new();
    while got.len() < 50 {
        if let HostEvent::Reliable { peer: p, bytes } =
            wait_host(&h, 5, |e| matches!(e, HostEvent::Reliable { .. }))
        {
            assert_eq!(p, peer);
            got.push(bytes[0]);
        }
    }
    assert_eq!(
        got,
        (0..50).collect::<Vec<u8>>(),
        "reliable is ordered and complete"
    );

    h.send_reliable(peer, Bytes::from_static(b"to client"));
    h.broadcast_reliable(Bytes::from_static(b"to all"));
    assert!(
        matches!(wait_client(&cl, 5, |e| matches!(e, ClientEvent::Reliable(_))),
        ClientEvent::Reliable(b) if &b[..] == b"to client")
    );
    assert!(
        matches!(wait_client(&cl, 5, |e| matches!(e, ClientEvent::Reliable(_))),
        ClientEvent::Reliable(b) if &b[..] == b"to all")
    );

    // Datagrams on localhost essentially never drop; send a few to be sure.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut host_got = false;
    let mut client_got = false;
    while Instant::now() < deadline && !(host_got && client_got) {
        cl.send_lossy(Bytes::from(vec![7u8; MAX_LOSSY_LEN]));
        h.send_lossy(peer, Bytes::from_static(b"snap"));
        std::thread::sleep(Duration::from_millis(20));
        while let Some(e) = h.poll() {
            if let HostEvent::Lossy { bytes, .. } = e {
                assert_eq!(bytes.len(), MAX_LOSSY_LEN, "a full 1 KiB datagram fits");
                host_got = true;
            }
        }
        while let Some(e) = cl.poll() {
            if let ClientEvent::Lossy(b) = e {
                assert_eq!(&b[..], b"snap");
                client_got = true;
            }
        }
    }
    assert!(
        host_got && client_got,
        "datagrams both ways (host {host_got}, client {client_got})"
    );
    assert!(cl.rtt_ms().is_some());
    assert!(h.rtt_ms(peer).is_some());
    h.shutdown();
}

#[test]
fn a_leaving_client_is_reported_to_the_host() {
    let (h, cl, peer, _) = connected_pair(4);
    cl.shutdown();
    let ev = wait_host(&h, 5, |e| matches!(e, HostEvent::PeerLeft { .. }));
    assert!(
        matches!(ev, HostEvent::PeerLeft { peer: p, reason: LeaveReason::Left } if p == peer),
        "{ev:?}"
    );
    assert_eq!(h.peer_count(), 0);
    h.shutdown();
}

#[test]
fn kick_disconnects_the_client_with_a_reason() {
    let (h, cl, peer, _) = connected_pair(4);
    h.kick(peer);
    let ev = wait_host(&h, 5, |e| matches!(e, HostEvent::PeerLeft { .. }));
    assert!(matches!(
        ev,
        HostEvent::PeerLeft {
            reason: LeaveReason::Kicked,
            ..
        }
    ));
    let ev = wait_client(&cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::Kicked
            }
        ),
        "{ev:?}"
    );
    // Exactly one PeerLeft.
    std::thread::sleep(Duration::from_millis(300));
    while let Some(e) = h.poll() {
        assert!(!matches!(e, HostEvent::PeerLeft { .. }), "duplicate {e:?}");
    }
    h.shutdown();
}

#[test]
fn host_shutdown_tells_clients_the_host_left() {
    let (h, cl, _, _) = connected_pair(4);
    h.shutdown();
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

#[test]
fn a_full_room_refuses_with_room_full() {
    let (h, _cl, _, _) = connected_pair(2); // host + 1 = full
    let addr = local_addr_again(&h);
    let late = join_addr(&cfg(), &Identity::ephemeral(), addr, &h.lan_token());
    let ev = wait_client(&late, 10, |e| matches!(e, ClientEvent::Failed { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::RoomFull
            }
        ),
        "{ev:?}"
    );
    h.shutdown();
}

#[test]
fn a_closed_room_refuses_with_room_closed() {
    let c = cfg();
    let h = host(&c, &Identity::ephemeral(), room(8));
    let addr = local_addr(&h);
    h.set_open(false);
    let cl = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
    let ev = wait_client(&cl, 10, |e| matches!(e, ClientEvent::Failed { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::RoomClosed
            }
        ),
        "{ev:?}"
    );
    h.set_open(true);
    let cl = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
    wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    h.shutdown();
}

fn local_addr_again(h: &HostHandle) -> std::net::SocketAddr {
    std::net::SocketAddr::new(
        std::net::Ipv4Addr::LOCALHOST.into(),
        h.local_addr().unwrap().port(),
    )
}

#[test]
fn lan_beacon_browse_then_join() {
    let c = cfg();
    let mut browser = lan_browse(&c);
    let h = host(&c, &Identity::ephemeral(), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let deadline = Instant::now() + Duration::from_secs(5);
    let found = loop {
        let rooms = browser.poll();
        if let Some(r) = rooms.into_iter().find(|r| r.code == h.code()) {
            break r;
        }
        assert!(Instant::now() < deadline, "beacon not heard");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(found.name, "Test room");
    assert_eq!(found.player_count, 1);
    let cl = join_lan(&c, &Identity::ephemeral(), &found);
    wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }));
    h.shutdown();
}

#[test]
fn room_code_rendezvous_end_to_end_over_the_fake_relay() {
    let hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
    );
    let HostEvent::Ready { code } = wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }))
    else {
        unreachable!()
    };
    assert_eq!(code, h.code());
    let id = Identity::ephemeral();
    // As a person types it from the screen: lower case, with the gap.
    let typed = crate::room::display_code(&code).to_lowercase();
    assert_eq!(typed.len(), 7);
    let cl = join_with_relay(&c, &id, &typed, Box::new(hub.client()));
    let mut stages = Vec::new();
    let ev = wait_client(&cl, 20, |e| {
        if let ClientEvent::Progress { stage } = e {
            stages.push(*stage);
        }
        matches!(
            e,
            ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
        )
    });
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    assert_eq!(
        stages,
        vec![
            JoinStage::Preparing,
            JoinStage::FindingHost,
            JoinStage::Connecting,
            JoinStage::Handshake
        ]
    );
    let ev = wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }));
    assert!(matches!(ev, HostEvent::PeerJoined { pubkey, .. } if pubkey == id.pubkey()));
    cl.send_reliable(Bytes::from_static(b"hi"));
    wait_host(&h, 5, |e| matches!(e, HostEvent::Reliable { .. }));

    // Once the match starts the code stops answering: a new joiner gets no answer
    // (the host unsubscribed), reported at the FindingHost stage.
    h.set_open(false);
    std::thread::sleep(Duration::from_millis(100));
    let late = join_with_relay(
        &c,
        &Identity::ephemeral(),
        &format!("{}-{}", &code[..3], &code[3..]),
        Box::new(hub.client()),
    );
    let ev = wait_client(&late, 20, |e| matches!(e, ClientEvent::Failed { .. }));
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
    h.shutdown();
}

/// Two websocket relays on both phones; the first one drops while the joiner is
/// finding the host. The other relay carries the join through.
#[test]
fn room_code_join_survives_a_relay_dropping_mid_join() {
    use crate::fake_ws::FakeWsRelay;
    use crate::relay::MultiRelay;
    use decented_relays::{RelayPool, Schedule};
    use std::sync::Arc;

    let (a, b) = (FakeWsRelay::start(), FakeWsRelay::start());
    let urls = vec![a.url.clone(), b.url.clone()];
    let ms = Duration::from_millis;
    let pool = Arc::new(RelayPool::with(
        vec![],
        Schedule::new(vec![ms(60), ms(120)], ms(200)),
    ));
    let c = cfg();
    let h = host_with_relay(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(MultiRelay::start_in(
            pool.clone(),
            urls.clone(),
            false,
        ))),
    );
    let code = wait_ready(&h);
    let id = Identity::ephemeral();
    let cl = join_with_relay(
        &c,
        &id,
        &code,
        Box::new(MultiRelay::start_in(pool.clone(), urls.clone(), false)),
    );
    wait_client(&cl, 10, |e| {
        matches!(
            e,
            ClientEvent::Progress {
                stage: JoinStage::FindingHost
            }
        )
    });
    a.kill();
    let ev = wait_client(&cl, 25, |e| {
        matches!(
            e,
            ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
        )
    });
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    let ev = wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }));
    assert!(matches!(ev, HostEvent::PeerJoined { pubkey, .. } if pubkey == id.pubkey()));
    assert!(
        pool.failing(&a.url),
        "the dropped relay is recorded as failing"
    );
    assert!(!pool.failing(&b.url));
    h.shutdown();
}

/// The top relay on the list is dead from the start: hosting and joining go
/// through the next ones.
#[test]
fn room_code_join_works_with_the_top_relay_dead_from_the_start() {
    use crate::fake_ws::FakeWsRelay;
    use crate::relay::MultiRelay;
    use decented_relays::{RelayPool, Schedule};
    use std::sync::Arc;

    let (a, b, d) = (
        FakeWsRelay::start(),
        FakeWsRelay::start(),
        FakeWsRelay::start(),
    );
    a.kill();
    let urls = vec![a.url.clone(), b.url.clone(), d.url.clone()];
    let ms = Duration::from_millis;
    let pool = Arc::new(RelayPool::with(
        vec![],
        Schedule::new(vec![ms(60), ms(120)], ms(200)),
    ));
    let c = cfg();
    let h = host_with_relay(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(MultiRelay::start_in(
            pool.clone(),
            urls.clone(),
            false,
        ))),
    );
    let code = wait_ready(&h);
    let cl = join_with_relay(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(MultiRelay::start_in(pool.clone(), urls, false)),
    );
    let ev = wait_client(&cl, 25, |e| {
        matches!(
            e,
            ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
        )
    });
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    assert!(
        !b.received().is_empty() && !d.received().is_empty(),
        "offers and answers used the next relays in order"
    );
    assert!(a.received().is_empty());
    h.shutdown();
}

#[test]
fn a_bad_code_fails_immediately() {
    let cl = join_with_relay(
        &cfg(),
        &Identity::ephemeral(),
        "AB0",
        Box::new(FakeRelayHub::new().client()),
    );
    let ev = wait_client(&cl, 5, |e| matches!(e, ClientEvent::Failed { .. }));
    assert!(matches!(
        ev,
        ClientEvent::Failed {
            stage: JoinStage::Preparing,
            reason: FailReason::BadCode
        }
    ));
}

#[test]
fn unreachable_relays_are_reported_as_such() {
    let mut c = cfg();
    // Nothing listens on port 9 of localhost: every dial is refused at once.
    c.relays = vec!["ws://127.0.0.1:9".into()];
    let cl = join(&c, &Identity::ephemeral(), "ABCDEF");
    let ev = wait_client(&cl, 20, |e| matches!(e, ClientEvent::Failed { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::FindingHost,
                reason: FailReason::RelayUnreachable
            }
        ),
        "{ev:?}"
    );
}

#[test]
fn a_dead_address_fails_at_connecting() {
    // A bound-but-silent UDP socket: QUIC never gets an answer.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let cl = join_addr(
        &cfg(),
        &Identity::ephemeral(),
        silent.local_addr().unwrap(),
        &"00".repeat(32),
    );
    let ev = wait_client(&cl, 15, |e| matches!(e, ClientEvent::Failed { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Connecting,
                reason: FailReason::PunchFailed
            }
        ),
        "{ev:?}"
    );
}

const DAY: u64 = 20_000;

fn wait_ready(h: &HostHandle) -> String {
    let HostEvent::Ready { code } = wait_host(h, 10, |e| matches!(e, HostEvent::Ready { .. }))
    else {
        unreachable!()
    };
    code
}

fn join_outcome(cl: &ClientHandle) -> ClientEvent {
    wait_client(cl, 25, |e| {
        matches!(
            e,
            ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
        )
    })
}

#[test]
fn a_joiner_past_midnight_still_finds_a_host_from_yesterday() {
    let hub = FakeRelayHub::new();
    let c = cfg();
    let host_id = Identity::ephemeral();
    let h = host_with_relay_at_day(&c, &host_id, room(4), Some(Box::new(hub.client())), DAY);
    let code = wait_ready(&h);
    // The joiner's clock says the next UTC day: today's tag misses, yesterday's hits.
    let typed = format!("{} {}", &code[..3], &code[3..]).to_lowercase();
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &typed,
        Box::new(hub.client()),
        DAY + 1,
    );
    let ev = join_outcome(&cl);
    assert!(
        matches!(&ev, ClientEvent::Connected { host_pubkey, .. } if *host_pubkey == host_id.pubkey()),
        "{ev:?}"
    );
    // A joiner one day behind the host also meets it (host listens on today + yesterday
    // is the host's side; the joiner's "today" is the host's yesterday).
    let cl2 = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
        DAY,
    );
    assert!(matches!(join_outcome(&cl2), ClientEvent::Connected { .. }));
    h.shutdown();
}

#[test]
fn a_joiner_two_days_out_gets_no_answer() {
    let hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
        DAY,
    );
    let code = wait_ready(&h);
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
        DAY + 2,
    );
    let ev = join_outcome(&cl);
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
    h.shutdown();
}

/// Someone who knows (swept) the code: reads offers off the relay and answers
/// them with its own key, pointing at `candidates`, after `delay`.
fn spawn_impostor(
    hub: &FakeRelayHub,
    code: &str,
    candidates: Vec<Candidate>,
    delay: Duration,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    spawn_impostor_with_junk(hub, code, nostr::Keys::generate(), candidates, delay, 0)
}

/// As [`spawn_impostor`], first flooding the joiner with `junk` bogus answers
/// (fresh keys, undecryptable) to push the real host's answer out of its queue.
fn spawn_impostor_with_junk(
    hub: &FakeRelayHub,
    code: &str,
    me: nostr::Keys,
    candidates: Vec<Candidate>,
    delay: Duration,
    junk: usize,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let relay = hub.client();
    let secrets = derive(TAG, code, DAY).unwrap();
    relay
        .subscribe(TagFilter::one(
            KIND_JOIN_OFFER,
            ROOM_TAG_LETTER,
            secrets.tag.clone(),
        ))
        .unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s = std::sync::Arc::clone(&stop);
    std::thread::spawn(move || {
        // One junk key, made before any offer: the junk must be cheap to make
        // once the offer arrives, or (under load) the impostor's answer lands
        // after the joiner's settle window and the test checks nothing about
        // junk (review-ipv6-1 I5). The fake hub has no per-author limit, so one
        // key floods exactly as well as many.
        let junk_key = nostr::Keys::generate();
        let mut answered = std::collections::HashSet::new();
        while !s.load(std::sync::atomic::Ordering::Relaxed) {
            while let Some(ev) = relay.try_recv() {
                let Ok(offer) = open_offer(&secrets.keys, &ev, unix_now()) else {
                    continue;
                };
                if !answered.insert(offer.session.clone()) {
                    continue;
                }
                // Signed on a few threads at once (the joiner's key is only
                // known now), then published in order, all before the answer.
                let joiner = ev.pubkey;
                let junk_events: Vec<nostr::Event> = std::thread::scope(|sc| {
                    let workers: Vec<_> = (0..4)
                        .map(|w| {
                            let k = &junk_key;
                            sc.spawn(move || {
                                (w..junk)
                                    .step_by(4)
                                    .map(|i| {
                                        nostr::EventBuilder::new(
                                            nostr::Kind::Custom(
                                                crate::rendezvous::KIND_JOIN_ANSWER,
                                            ),
                                            format!("junk {i}"),
                                        )
                                        .tags([nostr::Tag::public_key(joiner)])
                                        .sign_with_keys(k)
                                        .unwrap()
                                    })
                                    .collect::<Vec<_>>()
                            })
                        })
                        .collect();
                    workers
                        .into_iter()
                        .flat_map(|w| w.join().unwrap())
                        .collect()
                });
                for j in &junk_events {
                    relay.publish(j).unwrap();
                }
                std::thread::sleep(delay);
                let a = Answer {
                    v: NET_PROTOCOL_VERSION,
                    session: offer.session,
                    accepted: true,
                    reason: None,
                    candidates: candidates.clone(),
                    sent_at: unix_now(),
                    host_pubkey: me.public_key().to_hex(),
                };
                relay
                    .publish(&seal_answer(&me, &ev.pubkey, &a).unwrap())
                    .unwrap();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    stop
}

#[test]
fn a_host_whose_key_differs_from_the_answer_is_refused() {
    // The impostor knows the code and answers it, but points the joiner at
    // the real host (which never heard this offer: it is on another relay).
    // The real host admits the code, but its welcome names a different relay
    // key than the one that answered -> fail closed.
    let hub = FakeRelayHub::new();
    let other_hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(other_hub.client())),
        DAY,
    );
    let code = wait_ready(&h);
    let a = h.local_addr().expect("listening");
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), a.port());
    let stop = spawn_impostor(
        &hub,
        &code,
        vec![Candidate {
            kind: "lan".into(),
            addr: addr.to_string(),
        }],
        Duration::ZERO,
    );
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
        DAY,
    );
    let ev = join_outcome(&cl);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::HostUnverified
            }
        ),
        "{ev:?}"
    );
    h.shutdown();
}

#[test]
fn a_second_key_answering_the_code_makes_the_join_fail_closed() {
    // The real host answers first; an impostor who swept the code answers too.
    let hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
        DAY,
    );
    let code = wait_ready(&h);
    let stop = spawn_impostor(
        &hub,
        &code,
        vec![Candidate {
            kind: "lan".into(),
            addr: "127.0.0.1:9".into(),
        }],
        Duration::from_millis(100),
    );
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
        DAY,
    );
    let ev = join_outcome(&cl);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::HostConflict
            }
        ),
        "{ev:?}"
    );
    h.shutdown();
}

// ─── Review regressions (review-net-1) ──────────────────────────────────────

/// A logger that formats nothing but makes every `log!` evaluate its
/// arguments, as a real app logger would (H1 only panicked with logging on).
fn enable_logging() {
    struct Sink;
    impl log::Log for Sink {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, r: &log::Record) {
            let _ = format!("{}", r.args());
        }
        fn flush(&self) {}
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = log::set_logger(&Sink);
        log::set_max_level(log::LevelFilter::Trace);
    });
}

#[test]
fn h1_a_crafted_offer_session_cannot_panic_the_host() {
    enable_logging();
    let hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(8),
        Some(Box::new(hub.client())),
        DAY,
    );
    let code = wait_ready(&h);
    let secrets = derive(TAG, &code, DAY).unwrap();
    let atk = nostr::Keys::generate();
    for session in [
        "aaaaaaa\u{20AC}bbbb".to_string(),
        "x".repeat(2000),
        String::new(),
    ] {
        let offer = crate::rendezvous::Offer {
            v: NET_PROTOCOL_VERSION,
            session,
            pubkey: atk.public_key().to_hex(),
            candidates: vec![],
            sent_at: unix_now(),
        };
        let ev =
            crate::rendezvous::seal_offer(&atk, &secrets.keys.public_key(), &secrets.tag, &offer)
                .unwrap();
        hub.client().publish(&ev).unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    // The host still answers the code ...
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
        DAY,
    );
    assert!(matches!(join_outcome(&cl), ClientEvent::Connected { .. }));
    // ... and still tells its peers when it leaves.
    h.shutdown();
    let ev = wait_client(&cl, 8, |e| matches!(e, ClientEvent::Disconnected { .. }));
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

#[test]
fn m1_a_direct_dial_without_the_code_or_lan_token_is_refused() {
    let hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(8),
        Some(Box::new(hub.client())),
        DAY,
    );
    wait_ready(&h);
    let a = h.local_addr().unwrap();
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), a.port());
    for token in ["00".repeat(32), "not hex".to_string()] {
        let cl = join_addr(&c, &Identity::ephemeral(), addr, &token);
        let ev = wait_client(&cl, 10, |e| {
            matches!(
                e,
                ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
            )
        });
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
    }
    assert_eq!(h.peer_count(), 0);
    // The LAN token rotates when the room closes and reopens: an old one stops working.
    let old = h.lan_token();
    h.set_open(false);
    h.set_open(true);
    assert_ne!(old, h.lan_token());
    let cl = join_addr(&c, &Identity::ephemeral(), addr, &old);
    let ev = wait_client(&cl, 10, |e| {
        matches!(
            e,
            ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
        )
    });
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
    let cl = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
    assert!(matches!(
        wait_client(&cl, 10, |e| matches!(
            e,
            ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
        )),
        ClientEvent::Connected { .. }
    ));
    h.shutdown();
}

/// A game rolling back a failed switch closes or reopens its room without
/// rotating the LAN token, so its players can dial back in with the token the
/// switch gave them. Plain `set_open` still rotates.
#[test]
fn m1_reopening_while_keeping_the_token_admits_the_old_token() {
    let c = cfg();
    let h = host_with_relay_at_day(&c, &Identity::ephemeral(), room(8), None, DAY);
    wait_ready(&h);
    let a = h.local_addr().unwrap();
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), a.port());
    let connects = |token: &str| {
        let cl = join_addr(&c, &Identity::ephemeral(), addr, token);
        let ev = wait_client(&cl, 10, |e| {
            matches!(
                e,
                ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
            )
        });
        (matches!(ev, ClientEvent::Connected { .. }), cl)
    };
    let held = h.lan_token();
    h.set_open_keeping_token(false);
    assert!(!h.is_open());
    assert_eq!(held, h.lan_token());
    h.set_open_keeping_token(true);
    assert!(h.is_open());
    assert_eq!(held, h.lan_token());
    let (ok, _kept) = connects(&held);
    assert!(ok, "the held token must still admit after a keeping reopen");
    // Plain set_open still rotates, and the held token stops working.
    h.set_open(false);
    h.set_open(true);
    assert_ne!(held, h.lan_token());
    let (ok, _stale) = connects(&held);
    assert!(!ok, "a rotated-away token must be refused");
    let (ok, _fresh) = connects(&h.lan_token());
    assert!(ok);
    h.shutdown();
}

#[test]
fn m2_a_peer_that_floods_a_stalled_host_is_dropped_and_memory_stays_bounded() {
    let (h, cl, peer, _) = connected_pair(4);
    // The host app stops polling; the peer streams messages.
    for _ in 0..(crate::host::MAX_QUEUED_RELIABLE * 4) {
        cl.send_reliable(Bytes::from(vec![0xAA; 900]));
    }
    // Oversized messages never leave the sender.
    cl.send_reliable(Bytes::from(vec![0u8; MAX_RELIABLE_LEN + 1]));
    let ev = wait_client(&cl, 10, |e| matches!(e, ClientEvent::Disconnected { .. }));
    assert!(matches!(ev, ClientEvent::Disconnected { .. }), "{ev:?}");
    let (mut reliable, mut left) = (0usize, false);
    while let Some(ev) = h.poll() {
        match ev {
            HostEvent::Reliable { .. } => reliable += 1,
            HostEvent::PeerLeft { peer: p, .. } if p == peer => left = true,
            _ => {}
        }
    }
    assert!(
        reliable <= crate::host::MAX_QUEUED_RELIABLE,
        "{reliable} queued"
    );
    assert!(left, "the flooding peer was dropped");
    h.shutdown();
}

#[test]
fn l6_a_kicked_identity_cannot_dial_straight_back_in() {
    let (h, cl, peer, id) = connected_pair(4);
    h.kick(peer);
    wait_client(&cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
    let addr = local_addr_again(&h);
    let again = join_addr(&cfg(), &id, addr, &h.lan_token());
    let ev = wait_client(&again, 10, |e| {
        matches!(
            e,
            ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
        )
    });
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
    h.shutdown();
}

#[test]
fn a_disconnected_but_not_kicked_identity_may_dial_back_in() {
    let (h, cl, peer, id) = connected_pair(4);
    h.disconnect(peer);
    wait_client(&cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
    let addr = local_addr_again(&h);
    let again = join_addr(&cfg(), &id, addr, &h.lan_token());
    let ev = wait_client(&again, 10, |e| {
        matches!(
            e,
            ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
        )
    });
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    h.shutdown();
}

/// Records every event a relay client publishes or receives.
struct Spy {
    inner: crate::relay::FakeRelay,
    seen: std::sync::Arc<std::sync::Mutex<Vec<nostr::Event>>>,
}

impl RendezvousRelay for Spy {
    fn publish(&self, ev: &nostr::Event) -> Result<(), String> {
        self.seen.lock().unwrap().push(ev.clone());
        self.inner.publish(ev)
    }
    fn subscribe(&self, f: TagFilter) -> Result<(), String> {
        self.inner.subscribe(f)
    }
    fn unsubscribe(&self) -> Result<(), String> {
        self.inner.unsubscribe()
    }
    fn try_recv(&self) -> Option<nostr::Event> {
        let ev = self.inner.try_recv()?;
        self.seen.lock().unwrap().push(ev.clone());
        Some(ev)
    }
    fn connected(&self) -> (usize, usize) {
        self.inner.connected()
    }
    fn set_accept(&self, a: Option<crate::relay::AcceptFn>) {
        self.inner.set_accept(a)
    }
    fn overflowed(&self) -> bool {
        self.inner.overflowed()
    }
}

#[test]
fn m5_relays_never_see_either_identity_key() {
    let hub = FakeRelayHub::new();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let spy = |hub: &FakeRelayHub| {
        Box::new(Spy {
            inner: hub.client(),
            seen: std::sync::Arc::clone(&seen),
        })
    };
    let c = cfg();
    let (host_id, joiner_id) = (Identity::ephemeral(), Identity::ephemeral());
    let h = host_with_relay_at_day(&c, &host_id, room(4), Some(spy(&hub)), DAY);
    let code = wait_ready(&h);
    let cl = join_with_relay_at_day(&c, &joiner_id, &code, spy(&hub), DAY);
    let ev = join_outcome(&cl);
    let ClientEvent::Connected { host_pubkey, .. } = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(
        host_pubkey,
        host_id.pubkey(),
        "identity still proven inside QUIC"
    );
    let HostEvent::PeerJoined { pubkey, .. } =
        wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    assert_eq!(pubkey, joiner_id.pubkey());
    let seen = seen.lock().unwrap();
    assert!(
        seen.len() >= 2,
        "an offer and an answer went over the relay"
    );
    let ids = [host_id.pubkey().to_hex(), joiner_id.pubkey().to_hex()];
    for ev in seen.iter() {
        let json = serde_json::to_string(ev).unwrap();
        for id in &ids {
            assert!(
                !json.contains(id.as_str()),
                "identity key visible on the relay: {json}"
            );
        }
    }
    h.shutdown();
}

#[test]
fn m6_junk_answers_cannot_push_the_real_answer_out() {
    // An impostor who swept the code floods the joiner with junk (more than the
    // queue holds), then answers itself. The real host's answer must still be
    // seen, so the join fails closed as a conflict.
    let hub = FakeRelayHub::new();
    let c = cfg();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
        DAY,
    );
    let code = wait_ready(&h);
    // The impostor runs a host of its own that welcomes as its key. Whichever
    // answer the joiner takes first, it can connect and verify, so the only
    // way to pass is to see the *other* answer behind the junk: the test no
    // longer depends on the impostor answering second, and needs no delay
    // that load could stretch past the settle window (review-ipv6-1 I5).
    let me = nostr::Keys::generate();
    let impostor_host = spawn_on_path_host(c.app_tag.clone(), me.clone(), me.public_key());
    let stop = spawn_impostor_with_junk(
        &hub,
        &code,
        me,
        vec![Candidate {
            kind: "lan".into(),
            addr: impostor_host.to_string(),
        }],
        Duration::ZERO,
        // More than the queue holds, as before; +1 rather than x2 keeps the
        // flood's cost (each one is signed, verified and fails to decrypt)
        // well inside the joiner's settle window on a loaded machine.
        crate::relay::EVENT_QUEUE + 1,
    );
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
        DAY,
    );
    let ev = join_outcome(&cl);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::HostConflict
            }
        ),
        "{ev:?}"
    );
    h.shutdown();
}

// ─── Verification regressions (review-net-1, N1) ────────────────────────────

/// The real host's relay answer, as the joiner receives it: signed by the
/// room's throwaway key `relay`, naming `host` as the identity inside, pointing
/// at `candidates` (here: where an on-path attacker answers instead).
fn spawn_answerer(
    hub: &FakeRelayHub,
    code: &str,
    relay_keys: nostr::Keys,
    host: nostr::PublicKey,
    candidates: Vec<Candidate>,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let relay = hub.client();
    let secrets = derive(TAG, code, DAY).unwrap();
    relay
        .subscribe(TagFilter::one(
            KIND_JOIN_OFFER,
            ROOM_TAG_LETTER,
            secrets.tag.clone(),
        ))
        .unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s = std::sync::Arc::clone(&stop);
    std::thread::spawn(move || {
        let mut answered = std::collections::HashSet::new();
        while !s.load(std::sync::atomic::Ordering::Relaxed) {
            while let Some(ev) = relay.try_recv() {
                let Ok(offer) = open_offer(&secrets.keys, &ev, unix_now()) else {
                    continue;
                };
                if !answered.insert(offer.session.clone()) {
                    continue;
                }
                let a = Answer {
                    v: NET_PROTOCOL_VERSION,
                    session: offer.session,
                    accepted: true,
                    reason: None,
                    candidates: candidates.clone(),
                    sent_at: unix_now(),
                    host_pubkey: host.to_hex(),
                };
                relay
                    .publish(&seal_answer(&relay_keys, &ev.pubkey, &a).unwrap())
                    .unwrap();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    stop
}

/// An on-path attacker that never had the code (a device on the joiner's
/// Wi-Fi answering ARP for the host's LAN candidate, say): it terminates the
/// joiner's QUIC dial itself and welcomes it as `identity`, naming the real
/// host's relay key, which is public (it signed the answer on the relay).
fn spawn_on_path_host(
    app_tag: String,
    identity: nostr::Keys,
    real_relay: nostr::PublicKey,
) -> std::net::SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    crate::runtime().spawn(async move {
        let Ok(ep) = crate::quic::server_endpoint(socket, &app_tag, crate::quic::Liveness::DEFAULT)
        else {
            return;
        };
        while let Some(incoming) = ep.accept().await {
            let Ok(conn) = incoming.await else { continue };
            // No admission check: it has no code to check against.
            let Ok((mut send, _recv, hello)) = crate::quic::server_read_hello(&conn).await else {
                continue;
            };
            let session = hello.session.clone();
            let _ = crate::quic::server_send_welcome(
                &conn,
                &mut send,
                &identity,
                None,
                &[],
                "Mum",
                &real_relay,
                session.as_deref(),
                1,
            )
            .await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    addr
}

#[test]
fn n1_an_on_path_host_naming_the_real_relay_key_is_refused() {
    let hub = FakeRelayHub::new();
    let c = cfg();
    let code = "ABCDEF";
    let real_host = nostr::Keys::generate();
    let real_relay = nostr::Keys::generate();
    let attacker = spawn_on_path_host(
        c.app_tag.clone(),
        nostr::Keys::generate(),
        real_relay.public_key(),
    );
    let stop = spawn_answerer(
        &hub,
        code,
        real_relay,
        real_host.public_key(),
        vec![Candidate {
            kind: "lan".into(),
            addr: attacker.to_string(),
        }],
    );
    let cl = join_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        code,
        Box::new(hub.client()),
        DAY,
    );
    let ev = join_outcome(&cl);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::HostUnverified
            }
        ),
        "{ev:?}"
    );
}

#[test]
fn n3_a_confirm_timeout_reaches_the_joiner_as_its_own_reason_and_is_no_ban() {
    let (h, cl, peer, id) = connected_pair(4);
    h.confirm_timeout(peer);
    let ev = wait_client(&cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
    assert!(
        matches!(
            ev,
            ClientEvent::Disconnected {
                reason: DisconnectReason::ConfirmTimeout
            }
        ),
        "{ev:?}"
    );
    let addr = local_addr_again(&h);
    let again = join_addr(&cfg(), &id, addr, &h.lan_token());
    let ev = wait_client(&again, 10, |e| {
        matches!(
            e,
            ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
        )
    });
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    h.shutdown();
}

/// review-net-1 Verification 2: the reviewer's `review_v2` probes, ported to
/// protocol v4 (the scripted host now speaks the split handshake), plus the
/// N4 and N5 regression tests.
mod review_v2 {
    use super::*;
    use crate::quic::{self, sign_welcome, verify_welcome, Welcome};
    use crate::rendezvous::open_answer;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<nostr::Event>>>;

    /// Answers every offer on `code`, signed by `relay_keys`, with full control
    /// of the `host_pubkey` field. Records what it published.
    fn answerer(
        hub: &FakeRelayHub,
        code: &str,
        relay_keys: nostr::Keys,
        host_pubkey: String,
        candidates: Vec<Candidate>,
        log: Log,
    ) -> Arc<AtomicBool> {
        let relay = hub.client();
        let secrets = derive(TAG, code, DAY).unwrap();
        relay
            .subscribe(TagFilter::one(
                KIND_JOIN_OFFER,
                ROOM_TAG_LETTER,
                secrets.tag.clone(),
            ))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut answered = std::collections::HashSet::new();
            while !s.load(Ordering::Relaxed) {
                while let Some(ev) = relay.try_recv() {
                    let Ok(offer) = open_offer(&secrets.keys, &ev, unix_now()) else {
                        continue;
                    };
                    if !answered.insert(offer.session.clone()) {
                        continue;
                    }
                    let a = Answer {
                        v: NET_PROTOCOL_VERSION,
                        session: offer.session,
                        accepted: true,
                        reason: None,
                        candidates: candidates.clone(),
                        sent_at: unix_now(),
                        host_pubkey: host_pubkey.clone(),
                    };
                    let out = seal_answer(&relay_keys, &ev.pubkey, &a).unwrap();
                    log.lock().unwrap().push(out.clone());
                    relay.publish(&out).unwrap();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        stop
    }

    #[derive(Clone)]
    enum Mode {
        /// Sign over this connection (an honest host, or an attacker as itself).
        Own,
        /// A genuine signature by `identity` over some *other* connection's
        /// exporter (what forwarding a real host's welcome amounts to).
        Foreign,
        /// Signed by `identity` but claiming `PublicKey` in `host_pubkey`.
        Claim(nostr::PublicKey),
    }

    /// What a scripted host saw.
    #[derive(Default)]
    struct Seen {
        /// Every byte any joiner sent it on the handshake stream.
        bytes: Mutex<Vec<u8>>,
        /// Identity frames it received (one per joiner that trusted it).
        identities: AtomicUsize,
    }

    impl Seen {
        fn contains(&self, needle: &str) -> bool {
            let b = self.bytes.lock().unwrap();
            b.windows(needle.len()).any(|w| w == needle.as_bytes())
        }
    }

    /// A QUIC endpoint that skips admission and sends a welcome per `mode`
    /// after `delay`. If the joiner then identifies itself, it is seated
    /// (`Accepted`), as an honest host would. Records all it receives.
    fn welcomer(
        identity: nostr::Keys,
        relay: nostr::PublicKey,
        mode: Mode,
        delay: Duration,
    ) -> (std::net::SocketAddr, Arc<Seen>) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let app_tag = TAG.to_string();
        let seen = Arc::new(Seen::default());
        let s = Arc::clone(&seen);
        crate::runtime().spawn(async move {
            let Ok(ep) = quic::server_endpoint(socket, &app_tag, quic::Liveness::DEFAULT) else {
                return;
            };
            while let Some(incoming) = ep.accept().await {
                let (identity, mode, s) = (identity.clone(), mode.clone(), Arc::clone(&s));
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                        return;
                    };
                    let Ok(Some(frame)) =
                        quic::read_frame(&mut recv, quic::HANDSHAKE_FRAME_CAP).await
                    else {
                        return;
                    };
                    s.bytes.lock().unwrap().extend_from_slice(&frame);
                    let Ok(hello) = serde_json::from_slice::<quic::Hello>(&frame) else {
                        return;
                    };
                    tokio::time::sleep(delay).await;
                    let b = match mode {
                        Mode::Foreign => [7u8; 32],
                        _ => quic::binding(&conn).unwrap(),
                    };
                    let mut w: Welcome = sign_welcome(
                        &identity,
                        &b,
                        hello.session.as_deref(),
                        1,
                        "Mum",
                        &relay,
                        None,
                        &[],
                    );
                    if let Mode::Claim(pk) = &mode {
                        w.host_pubkey = pk.to_hex();
                    }
                    let json = serde_json::to_vec(&w).unwrap();
                    let _ = send.write_all(&quic::encode_frame(&json).unwrap()).await;
                    // Whatever comes next, up to the connection's end.
                    let rest = async {
                        if let Ok(Some(f)) =
                            quic::read_frame(&mut recv, quic::HANDSHAKE_FRAME_CAP).await
                        {
                            s.bytes.lock().unwrap().extend_from_slice(&f);
                            if serde_json::from_slice::<quic::Identify>(&f).is_ok() {
                                s.identities.fetch_add(1, Ordering::Relaxed);
                                let _ = quic::server_send_accepted(&mut send).await;
                            }
                        }
                        while let Ok(Some(chunk)) = recv.read_chunk(4096, true).await {
                            s.bytes.lock().unwrap().extend_from_slice(&chunk.bytes);
                        }
                    };
                    let _ = tokio::time::timeout(Duration::from_secs(5), rest).await;
                });
            }
        });
        (addr, seen)
    }

    fn lan(a: std::net::SocketAddr) -> Candidate {
        Candidate {
            kind: "lan".into(),
            addr: a.to_string(),
        }
    }

    /// One code join by `id` against a scripted answerer; returns the outcome.
    fn run_as(
        id: &Identity,
        host_pubkey: String,
        relay: nostr::Keys,
        cands: Vec<Candidate>,
        log: Log,
    ) -> ClientEvent {
        let hub = FakeRelayHub::new();
        let code = "ABCDEF";
        let stop = answerer(&hub, code, relay, host_pubkey, cands, log);
        let cl = join_with_relay_at_day(&cfg(), id, code, Box::new(hub.client()), DAY);
        let ev = join_outcome(&cl);
        stop.store(true, Ordering::Relaxed);
        ev
    }

    fn run(
        host_pubkey: String,
        relay: nostr::Keys,
        cands: Vec<Candidate>,
        log: Log,
    ) -> ClientEvent {
        run_as(&Identity::ephemeral(), host_pubkey, relay, cands, log)
    }

    fn unverified(ev: &ClientEvent) -> bool {
        matches!(
            ev,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::HostUnverified
            }
        )
    }

    const MARKER: &str = "ATTESTATION-MARKER-n5-7f3a";

    /// A joiner with an attestation, and the strings that would identify it.
    fn marked_joiner() -> (Identity, [String; 3]) {
        let id = Identity::ephemeral().with_attestation(MARKER.into());
        let tells = [id.pubkey().to_hex(), id.npub(), MARKER.to_string()];
        (id, tells)
    }

    fn assert_learned_nothing(what: &str, seen: &Seen, tells: &[String]) {
        assert!(
            !seen.bytes.lock().unwrap().is_empty(),
            "{what}: the fake host heard the hello"
        );
        for t in tells {
            assert!(!seen.contains(t), "{what}: the unverified host learned {t}");
        }
        assert_eq!(seen.identities.load(Ordering::Relaxed), 0, "{what}");
    }

    #[test]
    fn rv2_positive_control_and_relays_never_see_the_named_identity() {
        let (host, relay) = (nostr::Keys::generate(), nostr::Keys::generate());
        let log: Log = Arc::default();
        let (at, seen) = welcomer(host.clone(), relay.public_key(), Mode::Own, Duration::ZERO);
        let (id, tells) = marked_joiner();
        let ev = run_as(
            &id,
            host.public_key().to_hex(),
            relay,
            vec![lan(at)],
            Arc::clone(&log),
        );
        assert!(
            matches!(ev, ClientEvent::Connected { host_pubkey, .. } if host_pubkey == host.public_key()),
            "{ev:?}"
        );
        // The verified host does learn who joined (and the capture works).
        assert!(seen.contains(&tells[0]) && seen.contains(MARKER));
        assert_eq!(seen.identities.load(Ordering::Relaxed), 1);
        let log = log.lock().unwrap();
        assert!(!log.is_empty());
        for e in log.iter() {
            let j = serde_json::to_string(e).unwrap();
            assert!(
                !j.contains(&host.public_key().to_hex()),
                "identity on the relay: {j}"
            );
            assert!(!j.contains(&tells[0]), "joiner identity on the relay: {j}");
        }
    }

    /// N1 variants (each refused), and N5: none of them learns who the joiner is.
    #[test]
    fn rv2_on_path_variants_without_the_host_secret_are_refused_and_learn_nothing() {
        let real_host = nostr::Keys::generate();
        let attacker = nostr::Keys::generate();
        let cases: Vec<(&str, nostr::Keys, Mode)> = vec![
            (
                "attacker signs as itself, names real relay key (orig N1)",
                attacker.clone(),
                Mode::Own,
            ),
            (
                "attacker signs, claims the real host pubkey",
                attacker.clone(),
                Mode::Claim(real_host.public_key()),
            ),
            (
                "genuine real-host welcome forwarded from another connection",
                real_host.clone(),
                Mode::Foreign,
            ),
        ];
        for (what, signer, mode) in cases {
            let relay = nostr::Keys::generate();
            let (at, seen) = welcomer(signer, relay.public_key(), mode, Duration::ZERO);
            let (id, tells) = marked_joiner();
            let ev = run_as(
                &id,
                real_host.public_key().to_hex(),
                relay,
                vec![lan(at)],
                Arc::default(),
            );
            assert!(unverified(&ev), "{what}: {ev:?}");
            std::thread::sleep(Duration::from_millis(200));
            assert_learned_nothing(what, &seen, &tells);
        }
    }

    /// N5 on a LAN join: there is no answer to bind to, but a welcome that
    /// does not verify on this connection still gets nothing identifying.
    #[test]
    fn n5_a_lan_joiner_reveals_nothing_to_a_host_whose_welcome_does_not_verify() {
        for (what, mode) in [
            ("forwarded welcome", Mode::Foreign),
            (
                "claimed key",
                Mode::Claim(nostr::Keys::generate().public_key()),
            ),
        ] {
            let (at, seen) = welcomer(
                nostr::Keys::generate(),
                nostr::Keys::generate().public_key(),
                mode,
                Duration::ZERO,
            );
            let (id, tells) = marked_joiner();
            let cl = join_addr(&cfg(), &id, at, &"11".repeat(32));
            let ev = join_outcome(&cl);
            assert!(unverified(&ev), "{what}: {ev:?}");
            std::thread::sleep(Duration::from_millis(200));
            assert_learned_nothing(what, &seen, &tells);
        }
    }

    /// The host side of N5: a dial without the code or LAN token gets no
    /// welcome (nothing about the host), only `NOT_ADMITTED`.
    #[test]
    fn n5_an_unadmitted_dial_gets_no_welcome() {
        let c = cfg();
        let h = host(&c, &Identity::ephemeral(), room(4));
        let addr = local_addr(&h);
        let welcomed = Arc::new(AtomicBool::new(false));
        let w = Arc::clone(&welcomed);
        let out = crate::runtime().block_on(async move {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let ep = quic::client_endpoint(socket, &c.app_tag, quic::Liveness::DEFAULT).unwrap();
            let conn = ep.connect(addr, quic::SERVER_NAME).unwrap().await.unwrap();
            let check: quic::HostCheck = Arc::new(move |_| {
                w.store(true, Ordering::Relaxed);
                Ok(())
            });
            let r = quic::client_open(&conn, None, PathKind::Lan, &[[9u8; 32]], &check).await;
            (r.is_ok(), conn.close_reason().map(|e| quic::ended_of(&e)))
        });
        assert!(
            !out.0 && !welcomed.load(Ordering::Relaxed),
            "a welcome was sent"
        );
        assert_eq!(out.1, Some(quic::Ended::Remote(quic::close::NOT_ADMITTED)));
        assert_eq!(h.peer_count(), 0);
        h.shutdown();
    }

    #[test]
    fn rv2_accepted_answer_with_missing_or_bad_host_pubkey_fails_closed() {
        let host = nostr::Keys::generate();
        let npub = nostr::ToBech32::to_bech32(&host.public_key()).unwrap();
        for bad in [
            "".to_string(),
            "zz".to_string(),
            "00".repeat(32),
            npub,
            format!("02{}", host.public_key().to_hex()),
        ] {
            let relay = nostr::Keys::generate();
            let (at, seen) = welcomer(host.clone(), relay.public_key(), Mode::Own, Duration::ZERO);
            let ev = run(bad.clone(), relay, vec![lan(at)], Arc::default());
            assert!(unverified(&ev), "{bad:?}: {ev:?}");
            assert_eq!(seen.identities.load(Ordering::Relaxed), 0, "{bad:?}");
        }
    }

    /// N4 (was the reviewer's `rv2_a_lan_ip_squatter…`, which failed closed):
    /// a squatter on the first (LAN) candidate no longer ends the join; the
    /// real host on the next candidate is found, and the squatter learns nothing.
    #[test]
    fn n4_a_lan_ip_squatter_ahead_of_the_real_host_is_skipped() {
        let (host, attacker) = (nostr::Keys::generate(), nostr::Keys::generate());
        let relay = nostr::Keys::generate();
        let (real, real_seen) =
            welcomer(host.clone(), relay.public_key(), Mode::Own, Duration::ZERO);
        let (squat, squat_seen) = welcomer(attacker, relay.public_key(), Mode::Own, Duration::ZERO);
        let (id, tells) = marked_joiner();
        let ev = run_as(
            &id,
            host.public_key().to_hex(),
            relay,
            vec![lan(squat), lan(real)],
            Arc::default(),
        );
        assert!(
            matches!(ev, ClientEvent::Connected { host_pubkey, .. } if host_pubkey == host.public_key()),
            "{ev:?}"
        );
        assert_eq!(real_seen.identities.load(Ordering::Relaxed), 1);
        assert_learned_nothing("squatter", &squat_seen, &tells);
    }

    /// N4, the innocent version: an unrelated decented-net host sits at the
    /// first candidate's address (two homes on 192.168.1.x) and refuses us
    /// with `NOT_ADMITTED`; the real host on the next candidate still wins.
    #[test]
    fn n4_an_unrelated_host_at_the_first_candidate_is_skipped() {
        let c = cfg();
        let other = host(&c, &Identity::ephemeral(), room(4));
        let other_addr = local_addr(&other);
        let (host_keys, relay) = (nostr::Keys::generate(), nostr::Keys::generate());
        let (real, real_seen) = welcomer(
            host_keys.clone(),
            relay.public_key(),
            Mode::Own,
            Duration::ZERO,
        );
        let ev = run(
            host_keys.public_key().to_hex(),
            relay,
            vec![lan(other_addr), lan(real)],
            Arc::default(),
        );
        assert!(
            matches!(ev, ClientEvent::Connected { host_pubkey, .. } if host_pubkey == host_keys.public_key()),
            "{ev:?}"
        );
        assert_eq!(real_seen.identities.load(Ordering::Relaxed), 1);
        assert_eq!(other.peer_count(), 0);
        other.shutdown();
    }

    /// If every candidate is a wrong host, the join fails closed (and if any
    /// of them sent an unverifiable welcome, it says so).
    #[test]
    fn n4_with_no_verified_candidate_the_join_fails_closed() {
        let c = cfg();
        let other = host(&c, &Identity::ephemeral(), room(4));
        let other_addr = local_addr(&other);
        let relay = nostr::Keys::generate();
        let (squat, _) = welcomer(
            nostr::Keys::generate(),
            relay.public_key(),
            Mode::Own,
            Duration::ZERO,
        );
        let real = nostr::Keys::generate().public_key().to_hex();
        let ev = run(
            real.clone(),
            relay.clone(),
            vec![lan(other_addr), lan(squat)],
            Arc::default(),
        );
        assert!(unverified(&ev), "{ev:?}");
        // Only an unrelated host: refused, not admitted.
        let ev = run(real, relay, vec![lan(other_addr)], Arc::default());
        assert!(
            matches!(
                ev,
                ClientEvent::Failed {
                    stage: JoinStage::Handshake,
                    reason: FailReason::NotAdmitted
                }
            ),
            "{ev:?}"
        );
        other.shutdown();
    }

    /// Two candidates reaching the same host (LAN and STUN, say): both may get
    /// a welcome, but only the winner is told who the joiner is.
    #[test]
    fn n4_a_host_reached_on_two_paths_sees_one_join() {
        let (host, relay) = (nostr::Keys::generate(), nostr::Keys::generate());
        // The delay lets the second dial connect before the first is welcomed.
        let (at, seen) = welcomer(
            host.clone(),
            relay.public_key(),
            Mode::Own,
            Duration::from_millis(400),
        );
        let ev = run(
            host.public_key().to_hex(),
            relay,
            vec![lan(at), lan(at)],
            Arc::default(),
        );
        assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(seen.identities.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rv2_an_answer_replayed_from_an_earlier_session_is_ignored() {
        let (host, relay) = (nostr::Keys::generate(), nostr::Keys::generate());
        let log: Log = Arc::default();
        let (at, _) = welcomer(host.clone(), relay.public_key(), Mode::Own, Duration::ZERO);
        // Session 1: a genuine answer, captured.
        let ev = run(
            host.public_key().to_hex(),
            relay.clone(),
            vec![lan(at)],
            Arc::clone(&log),
        );
        assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
        let old = log.lock().unwrap()[0].clone();
        // Unit level: another joiner key / session can't open it.
        let k2 = nostr::Keys::generate();
        assert!(open_answer(&k2, &old, "s2", unix_now()).is_err());
        // Session 2: nobody answers; the old answer is replayed onto the hub.
        let hub = FakeRelayHub::new();
        let replayer = hub.client();
        let stop = Arc::new(AtomicBool::new(false));
        let s = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let _ = replayer.publish(&old);
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let cl = join_with_relay_at_day(
            &cfg(),
            &Identity::ephemeral(),
            "ABCDEF",
            Box::new(hub.client()),
            DAY,
        );
        let ev = join_outcome(&cl);
        stop.store(true, Ordering::Relaxed);
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
        // And a welcome signed by the real host but bound elsewhere never verifies.
        let w = sign_welcome(
            &host,
            &[1u8; 32],
            Some("s"),
            1,
            "Ava",
            &relay.public_key(),
            None,
            &[],
        );
        assert!(verify_welcome(&w, &[2u8; 32], Some("s")).is_err());
    }
}

// ─── IPv6 dual-stack (W3) ────────────────────────────────────────────────────

/// (a) A dual-stack host and a joiner dialling it over IPv6 loopback.
#[test]
fn w3_a_joiner_reaches_a_dual_stack_host_over_ipv6_loopback() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("no IPv6 loopback here; skipping");
        return;
    }
    let c = cfg();
    let h = host(&c, &Identity::ephemeral(), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let local = h.local_addr().expect("listening");
    assert!(local.is_ipv6(), "the host socket is dual-stack: {local}");
    let addr = std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), local.port());
    let id = Identity::ephemeral();
    let cl = join_addr(&c, &id, addr, &h.lan_token());
    let ev = wait_client(&cl, 10, |e| {
        matches!(
            e,
            ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
        )
    });
    assert!(matches!(ev, ClientEvent::Connected { .. }), "{ev:?}");
    let ev = wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }));
    assert!(matches!(ev, HostEvent::PeerJoined { pubkey, .. } if pubkey == id.pubkey()));
    cl.send_reliable(Bytes::from_static(b"over six"));
    wait_host(&h, 5, |e| matches!(e, HostEvent::Reliable { .. }));
    h.shutdown();
}

/// A host that runs on keys the app already holds is the key the joiner sees.
#[test]
fn a_host_built_from_existing_keys_presents_those_keys() {
    let keys = nostr::Keys::generate();
    let expected = keys.public_key();
    let c = cfg();
    let h = host(&c, &Identity::from_keys(keys), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let addr = std::net::SocketAddr::new(
        std::net::Ipv4Addr::LOCALHOST.into(),
        h.local_addr().expect("listening").port(),
    );
    let cl = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
    let ev = wait_client(&cl, 10, |e| {
        matches!(
            e,
            ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
        )
    });
    assert!(
        matches!(ev, ClientEvent::Connected { host_pubkey, .. } if host_pubkey == expected),
        "{ev:?}"
    );
    h.shutdown();
}

#[test]
fn liveness_defaults_equal_the_historic_constants() {
    for c in [
        NetConfig::new("d", "t"),
        NetConfig::new("d", "t").lan_only(),
    ] {
        assert_eq!(c.idle_timeout, Duration::from_secs(6));
        assert_eq!(c.keep_alive, Duration::from_secs(1));
    }
}

#[test]
fn an_idle_timeout_quic_would_send_as_none_is_refused() {
    // QUIC carries the idle timeout in whole milliseconds, and 0 means "never time out".
    let mut c = NetConfig::new("d", "t");
    c.idle_timeout = Duration::from_micros(500);
    c.keep_alive = Duration::from_micros(100);
    assert!(c.liveness().is_err(), "a 0.5 ms idle timeout would go out as no timeout at all");
    c.idle_timeout = Duration::from_millis(1);
    assert!(c.liveness().is_ok());
}

#[test]
fn a_bad_liveness_pair_is_refused_by_host_and_join() {
    let pairs = [
        (Duration::from_secs(6), Duration::ZERO, "keep_alive"),
        (Duration::ZERO, Duration::from_millis(500), "idle_timeout"),
        (Duration::ZERO, Duration::ZERO, "idle_timeout"),
        (Duration::from_secs(2), Duration::from_secs(2), "keep_alive"),
        (Duration::from_secs(2), Duration::from_secs(3), "keep_alive"),
    ];
    for (idle, ka, word) in pairs {
        let mut c = cfg();
        c.idle_timeout = idle;
        c.keep_alive = ka;
        let h = host(&c, &Identity::ephemeral(), room(4));
        let ev = wait_host(&h, 5, |e| {
            matches!(e, HostEvent::Failed { .. } | HostEvent::Ready { .. })
        });
        assert!(
            matches!(&ev, HostEvent::Failed { reason } if reason.contains(word)),
            "{idle:?}/{ka:?}: {ev:?}"
        );
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
        let cl = join_addr(&c, &Identity::ephemeral(), addr, &"0".repeat(64));
        let ev = wait_client(&cl, 5, |e| {
            matches!(
                e,
                ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
            )
        });
        assert!(
            matches!(&ev, ClientEvent::Failed { reason: FailReason::Network(m), .. } if m.contains(word)),
            "{idle:?}/{ka:?}: {ev:?}"
        );
    }
}

/// (b) An IPv4-only joiner and a dual-stack host: QUIC runs over the
/// v4-mapped path, and the host sees the joiner as `::ffff:127.0.0.1`.
#[test]
fn w3_an_ipv4_only_joiner_reaches_a_dual_stack_endpoint_via_a_mapped_address() {
    let server_sock = crate::nat::addr::bind_dual_stack(0).unwrap();
    assert!(crate::nat::addr::is_v6_socket(&server_sock));
    let port = server_sock.local_addr().unwrap().port();
    let client_sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let client_port = client_sock.local_addr().unwrap().port();
    let tag = cfg().app_tag;
    crate::runtime().block_on(async move {
        let server =
            crate::quic::server_endpoint(server_sock, &tag, crate::quic::Liveness::DEFAULT)
                .unwrap();
        let client =
            crate::quic::client_endpoint(client_sock, &tag, crate::quic::Liveness::DEFAULT)
                .unwrap();
        let target = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let dial = client.connect(target, crate::quic::SERVER_NAME).unwrap();
        let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
            .await
            .unwrap()
            .unwrap();
        let remote = incoming.remote_address();
        assert_eq!(
            remote,
            std::net::SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), client_port),
            "an IPv4 peer arrives v4-mapped on the dual-stack socket"
        );
        assert_eq!(
            crate::nat::addr::canonical(remote),
            std::net::SocketAddr::from(([127, 0, 0, 1], client_port))
        );
        let (accepted, dialled) = tokio::join!(incoming, dial);
        let (accepted, dialled) = (accepted.unwrap(), dialled.unwrap());
        assert!(
            dialled.remote_address().is_ipv4(),
            "the IPv4 client never sees a mapped address"
        );
        accepted.close(0u32.into(), b"done");
        dialled.close(0u32.into(), b"done");
    });
}

/// The app's LAN-socket hook (Android: bind to the Wi-Fi network so a VPN does
/// not swallow local traffic) runs on the sockets that talk to local peers: the
/// host's beacon and QUIC sockets, the browser, and a joiner dialling a LAN
/// room. A joiner dialling by room code keeps the default route.
#[test]
fn the_lan_socket_hook_binds_local_sockets_and_not_a_code_join() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let _g = crate::netbind::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let counted = || {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = Arc::clone(&n);
        (
            n,
            LanSocketHook::new(move |fd| {
                assert!(fd >= 0);
                n2.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        )
    };
    let (host_n, host_hook) = counted();
    let (browse_n, browse_hook) = counted();
    let (lan_n, lan_hook) = counted();
    let (code_n, code_hook) = counted();
    let hub = FakeRelayHub::new();
    let mut hc = cfg();
    hc.lan_socket_hook = Some(host_hook);
    let mut bc = hc.clone();
    bc.lan_socket_hook = Some(browse_hook);
    let mut browser = lan_browse(&bc);
    assert_eq!(browse_n.load(Ordering::SeqCst), 1, "the browser's socket");
    let h = host_with_relay(
        &hc,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
    );
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    // Beacon socket + QUIC socket.
    let deadline = Instant::now() + Duration::from_secs(5);
    while host_n.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < deadline,
            "host hook ran {} times",
            host_n.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let found = loop {
        if let Some(r) = browser.poll().into_iter().find(|r| r.code == h.code()) {
            break r;
        }
        assert!(Instant::now() < deadline, "beacon not heard");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut lc = hc.clone();
    lc.lan_socket_hook = Some(lan_hook);
    let lan = join_lan(&lc, &Identity::ephemeral(), &found);
    wait_client(&lan, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    assert_eq!(
        lan_n.load(Ordering::SeqCst),
        1,
        "a LAN join binds its QUIC socket once"
    );

    let mut cc = hc.clone();
    cc.lan_socket_hook = Some(code_hook);
    let by_code = join_with_relay(
        &cc,
        &Identity::ephemeral(),
        h.code(),
        Box::new(hub.client()),
    );
    wait_client(&by_code, 20, |e| matches!(e, ClientEvent::Connected { .. }));
    assert_eq!(
        code_n.load(Ordering::SeqCst),
        0,
        "a code join keeps the default route"
    );
    h.shutdown();
}

// ─── Host with a LAN socket hook: two endpoints ─────────────────────────────

/// A hook that records the local port of every socket it is run on.
fn recording_hook() -> (LanSocketHook, std::sync::Arc<std::sync::Mutex<Vec<u16>>>) {
    use std::os::fd::BorrowedFd;
    let ports = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let p = std::sync::Arc::clone(&ports);
    let hook = LanSocketHook::new(move |fd| {
        // SAFETY: the crate calls the hook with a socket it still owns, so the
        // descriptor is open for the duration of this call.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let port = socket2::SockRef::from(&borrowed)
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .map(|a| a.port())
            .unwrap_or(0);
        p.lock().unwrap().push(port);
        Ok(())
    });
    (hook, ports)
}

/// A UDP socket standing in for a STUN server: it never answers, it only
/// notes the port every datagram came from.
fn silent_stun_server() -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<u16>>>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let (s, st) = (std::sync::Arc::clone(&seen), std::sync::Arc::clone(&stop));
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while !st.load(Ordering::Relaxed) {
            if let Ok((_, from)) = sock.recv_from(&mut buf) {
                s.lock().unwrap().push(from.port());
            }
        }
    });
    (addr, seen, stop)
}

#[test]
fn a_hooked_host_runs_two_endpoints_and_only_the_lan_one_is_hooked() {
    let _g = crate::netbind::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (hook, hooked) = recording_hook();
    let (stun_addr, stun_seen, stop) = silent_stun_server();
    let mut c = cfg();
    c.lan_socket_hook = Some(hook);
    c.stun = vec![stun_addr];
    let h = host(&c, &Identity::ephemeral(), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let lan = h.local_addr().expect("lan endpoint").port();
    let online = h.online_addr().expect("online endpoint").port();
    assert_ne!(lan, online, "two endpoints, two sockets");

    // The hook ran on the LAN endpoint's socket and never on the online one
    // (it also ran on the beacon's socket, which is local traffic too).
    let hooked = hooked.lock().unwrap().clone();
    assert!(
        hooked.contains(&lan),
        "LAN endpoint hooked: {hooked:?} vs {lan}"
    );
    assert!(
        !hooked.contains(&online),
        "online endpoint never hooked: {hooked:?} vs {online}"
    );

    // STUN went out of the online socket (Ready is sent after gathering).
    let seen = stun_seen.lock().unwrap().clone();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(!seen.is_empty(), "the STUN server was asked");
    assert!(
        seen.iter().all(|p| *p == online),
        "STUN came from {seen:?}, online is {online}"
    );

    // A joiner (no hook) connects through each endpoint, into one session.
    let joiner = cfg();
    let lan_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), lan);
    let online_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), online);
    let (id_a, id_b) = (Identity::ephemeral(), Identity::ephemeral());
    let a = join_addr(&joiner, &id_a, lan_addr, &h.lan_token());
    wait_client(&a, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let b = join_addr(&joiner, &id_b, online_addr, &h.lan_token());
    wait_client(&b, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let mut joined = Vec::new();
    while joined.len() < 2 {
        let HostEvent::PeerJoined { peer, pubkey, .. } =
            wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
        else {
            unreachable!()
        };
        joined.push((peer, pubkey));
    }
    assert_ne!(joined[0].0, joined[1].0, "distinct seats in one session");
    assert_eq!(h.peer_count(), 2);
    let keys: Vec<_> = joined.iter().map(|j| j.1).collect();
    assert!(keys.contains(&id_a.pubkey()) && keys.contains(&id_b.pubkey()));

    // One broadcast reaches both, whichever endpoint they came through.
    h.broadcast_reliable(Bytes::from_static(b"hi"));
    for cl in [&a, &b] {
        let ev = wait_client(cl, 5, |e| matches!(e, ClientEvent::Reliable(_)));
        assert!(matches!(ev, ClientEvent::Reliable(ref m) if &m[..] == b"hi"));
    }

    // Shutdown closes both endpoints.
    h.shutdown();
    for cl in [&a, &b] {
        wait_client(cl, 5, |e| matches!(e, ClientEvent::Disconnected { .. }));
    }
}

#[test]
fn the_candidates_name_the_lan_port_for_lan_and_the_online_port_for_the_rest() {
    let _g = crate::netbind::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (hook, hooked) = recording_hook();
    let prep = futures_block(crate::host::prepare(0, false, Vec::new(), Some(hook))).unwrap();
    let lan = prep
        .lan_socket
        .as_ref()
        .expect("lan socket")
        .local_addr()
        .unwrap()
        .port();
    let online = prep.socket.local_addr().unwrap().port();
    assert_ne!(lan, online);
    assert_eq!(hooked.lock().unwrap().as_slice(), &[lan]);
    assert!(!prep.candidates.is_empty());
    for cand in &prep.candidates {
        let addr = cand.addr.parse::<std::net::SocketAddr>().unwrap();
        let port = addr.port();
        if cand.kind == "lan" {
            assert_eq!(port, lan, "{cand:?}");
            assert!(
                crate::nat::candidates::is_lan_ip(crate::nat::addr::canonical(addr).ip()),
                "a LAN candidate is never a public address: {cand:?}"
            );
        } else {
            assert_eq!(port, online, "{cand:?}");
        }
    }
    // Without a hook: one socket, as before.
    let prep = futures_block(crate::host::prepare(0, false, Vec::new(), None)).unwrap();
    assert!(prep.lan_socket.is_none() && prep.lan_punch_socket.is_none());
}

fn futures_block<F: std::future::Future>(f: F) -> F::Output {
    crate::runtime().block_on(f)
}

#[test]
fn a_host_without_a_hook_keeps_one_endpoint() {
    let c = cfg();
    let h = host(&c, &Identity::ephemeral(), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    assert_eq!(h.local_addr(), h.online_addr());
    h.shutdown();
}

// ─── Inbox relays in the identify frame and the welcome ────────────────────

#[test]
fn inbox_relays_travel_both_ways_beside_the_attestation() {
    let mut host_cfg = cfg();
    host_cfg.inbox_relays = vec!["wss://host-a.example".into(), "wss://host-b.example".into()];
    let h = host(
        &host_cfg,
        &Identity::ephemeral().with_attestation("{\"h\":1}".into()),
        room(4),
    );
    let addr = local_addr(&h);
    let mut join_cfg = cfg();
    join_cfg.inbox_relays = vec![
        "https://not-wss.example".into(),
        "wss://one.example".into(),
        "wss://two.example".into(),
        "wss://three.example".into(),
        "wss://four.example".into(),
    ];
    let id = Identity::ephemeral().with_attestation("{\"j\":1}".into());
    let cl = join_addr(&join_cfg, &id, addr, &h.lan_token());
    let ev = wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let ClientEvent::Connected {
        attestation,
        inbox_relays,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(attestation.as_deref(), Some("{\"h\":1}"));
    assert_eq!(
        inbox_relays,
        ["wss://host-a.example", "wss://host-b.example"]
    );
    let ev = wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }));
    let HostEvent::PeerJoined {
        attestation,
        inbox_relays,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(attestation.as_deref(), Some("{\"j\":1}"));
    // Bad entries dropped, three at most, in the player's order.
    assert_eq!(
        inbox_relays,
        [
            "wss://one.example",
            "wss://two.example",
            "wss://three.example"
        ]
    );
    h.shutdown();
}

#[test]
fn the_hooked_lan_endpoint_serves_local_sources_only() {
    let _g = crate::netbind::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (hook, _) = recording_hook();
    let mut c = cfg();
    c.lan_socket_hook = Some(hook);
    // Pretend loopback is not a local source, so the filter has something to refuse.
    c.lan_allow_loopback = false;
    let h = host(&c, &Identity::ephemeral(), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let loopback = |p: u16| std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), p);
    let lan = join_addr(
        &cfg(),
        &Identity::ephemeral(),
        loopback(h.local_addr().unwrap().port()),
        &h.lan_token(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert!(
            !matches!(lan.poll(), Some(ClientEvent::Connected { .. })),
            "the LAN endpoint must not serve a non-local source"
        );
        assert!(h
            .poll()
            .is_none_or(|e| !matches!(e, HostEvent::PeerJoined { .. })));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(h.peer_count(), 0);
    // The online endpoint takes the same source.
    let online = join_addr(
        &cfg(),
        &Identity::ephemeral(),
        loopback(h.online_addr().unwrap().port()),
        &h.lan_token(),
    );
    wait_client(&online, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    h.shutdown();
}

#[test]
fn no_upnp_while_a_vpn_is_active() {
    use crate::host::{prepare, upnp_wanted};
    assert!(upnp_wanted(true, false));
    assert!(!upnp_wanted(true, true), "a VPN: no mapping");
    assert!(!upnp_wanted(false, false), "a LAN-only host never asks");
    let mut c = cfg();
    c.vpn_active = true;
    // What HostTask::run passes to prepare for an online host on a VPN.
    let wanted = upnp_wanted(true, c.vpn_active);
    let prep = futures_block(prepare(0, wanted, Vec::new(), None)).unwrap();
    assert!(!prep.upnp_attempted && prep.mapping.is_none());
    assert!(prep.candidates.iter().all(|c| c.kind != "upnp"));
}

#[test]
fn punches_leave_from_the_socket_for_their_route() {
    use crate::host::Punchers;
    let sock = || std::sync::Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
    let (online, lan) = (sock(), sock());
    let port = |s: &std::sync::Arc<std::net::UdpSocket>| s.local_addr().unwrap().port();
    let a = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
    let targets = vec![
        a("192.168.1.50:40000"),
        a("10.0.0.5:40000"),
        a("169.254.3.3:40000"),
        a("[fd00::5]:40000"),
        a("81.2.69.160:40000"),
        a("[2a00:1450::1]:40000"),
        a("100.64.1.1:40000"),
    ];
    let split = Punchers {
        online: online.clone(),
        lan: Some(lan.clone()),
    };
    let routes = split.route(targets.clone());
    let to = |p: u16| -> Vec<std::net::SocketAddr> {
        routes
            .iter()
            .filter(|(s, _)| port(s) == p)
            .flat_map(|(_, t)| t.clone())
            .collect()
    };
    assert_eq!(
        to(port(&lan)),
        [
            a("192.168.1.50:40000"),
            a("10.0.0.5:40000"),
            a("169.254.3.3:40000"),
            a("[fd00::5]:40000")
        ]
    );
    assert_eq!(
        to(port(&online)),
        [
            a("81.2.69.160:40000"),
            a("[2a00:1450::1]:40000"),
            a("100.64.1.1:40000")
        ]
    );
    // One endpoint: everything leaves the one socket.
    let single = Punchers {
        online: online.clone(),
        lan: None,
    };
    let routes = single.route(targets.clone());
    assert_eq!(routes.len(), 1);
    assert_eq!(port(&routes[0].0), port(&online));
    assert_eq!(routes[0].1, targets);
}

#[test]
fn a_headless_room_advertises_zero_players_and_seats_eight_remote_clients() {
    let mut c = cfg();
    c.host_has_player = false;
    let mut browser = lan_browse(&c);
    let h = host(&c, &Identity::ephemeral(), room(8));
    let addr = local_addr(&h);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(found) = browser.poll().into_iter().find(|r| r.code == h.code()) {
            assert_eq!(found.player_count, 0);
            assert_eq!(found.max_players, 8);
            break;
        }
        assert!(Instant::now() < deadline, "headless beacon not heard");
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut clients = Vec::new();
    for _ in 0..8 {
        let client = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
        wait_client(&client, 10, |e| matches!(e, ClientEvent::Connected { .. }));
        wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }));
        clients.push(client);
    }
    let late = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
    let event = wait_client(&late, 10, |e| matches!(e, ClientEvent::Failed { .. }));
    assert!(
        matches!(
            event,
            ClientEvent::Failed {
                stage: JoinStage::Handshake,
                reason: FailReason::RoomFull,
            }
        ),
        "{event:?}"
    );
    h.shutdown();
    for client in clients {
        client.shutdown();
    }
    late.shutdown();
}

const APP_LABEL: &str = "EXPORTER-test-app-join-v1";

fn labelled() -> NetConfig {
    let mut c = cfg();
    c.app_binding_label = Some(APP_LABEL.into());
    c
}

/// Join `h` over loopback with `c`; returns the connected client and the host's id for it.
fn join_host(c: &NetConfig, h: &HostHandle, addr: std::net::SocketAddr) -> (ClientHandle, PeerId) {
    let cl = join_addr(c, &Identity::ephemeral(), addr, &h.lan_token());
    wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let HostEvent::PeerJoined { peer, .. } =
        wait_host(h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    (cl, peer)
}

#[test]
fn an_app_label_gives_both_ends_the_same_value_and_not_the_hello_binding() {
    let c = labelled();
    let h = host(&c, &Identity::ephemeral(), room(4));
    let (cl, peer) = join_host(&c, &h, local_addr(&h));
    let mine = cl.app_binding().expect("client computes it");
    assert_eq!(h.app_binding(peer), Some(mine), "both ends agree");
    assert_ne!(mine, [0u8; 32]);
    assert_ne!(
        Some(mine),
        cl.tls_binding(),
        "not the hello's own exporter value"
    );
    assert_eq!(h.app_binding(PeerId(9999)), None, "unknown peer");
    h.shutdown();
}

#[test]
fn two_connections_get_different_app_values() {
    let c = labelled();
    let h = host(&c, &Identity::ephemeral(), room(4));
    let addr = local_addr(&h);
    let (a, pa) = join_host(&c, &h, addr);
    let (b, pb) = join_host(&c, &h, addr);
    assert_ne!(pa, pb);
    assert_eq!(h.app_binding(pa), a.app_binding());
    assert_eq!(h.app_binding(pb), b.app_binding());
    assert!(a.app_binding().is_some() && b.app_binding().is_some());
    assert_ne!(
        a.app_binding(),
        b.app_binding(),
        "two TLS sessions never share a value"
    );
    assert_ne!(h.app_binding(pa), h.app_binding(pb));
    h.shutdown();
}

#[test]
fn without_a_label_there_is_no_app_value() {
    let c = cfg();
    assert_eq!(c.app_binding_label, None);
    let h = host(&c, &Identity::ephemeral(), room(4));
    let (cl, peer) = join_host(&c, &h, local_addr(&h));
    assert_eq!(cl.app_binding(), None);
    assert_eq!(h.app_binding(peer), None);
    assert!(cl.tls_binding().is_some());
    h.shutdown();
}

#[test]
fn a_bad_app_label_is_refused_by_host_and_join() {
    let bad = [
        ("no-prefix".to_string(), "EXPORTER-"),
        ("exporter-lowercase".to_string(), "EXPORTER-"),
        ("EXPORTER-decented-net-hello-v2".to_string(), "reserved"),
        (format!("EXPORTER-{}", "a".repeat(241)), "249"),
        (String::new(), "EXPORTER-"),
    ];
    assert_eq!(bad[3].0.len(), 250);
    for (label, word) in bad {
        let mut c = cfg();
        c.app_binding_label = Some(label.clone());
        let h = host(&c, &Identity::ephemeral(), room(4));
        let ev = wait_host(&h, 5, |e| {
            matches!(e, HostEvent::Failed { .. } | HostEvent::Ready { .. })
        });
        assert!(
            matches!(&ev, HostEvent::Failed { reason } if reason.contains("app_binding_label") && reason.contains(word)),
            "{label:?}: {ev:?}"
        );
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
        let cl = join_addr(&c, &Identity::ephemeral(), addr, &"0".repeat(64));
        let ev = wait_client(&cl, 5, |e| {
            matches!(
                e,
                ClientEvent::Failed { .. } | ClientEvent::Connected { .. }
            )
        });
        assert!(
            matches!(&ev, ClientEvent::Failed { reason: FailReason::Network(m), .. } if m.contains("app_binding_label")),
            "{label:?}: {ev:?}"
        );
    }
    // The longest allowed label (249 bytes: TLS 1.3 adds "tls13 " and caps the whole at 255) is accepted.
    let mut c = cfg();
    c.app_binding_label = Some(format!("EXPORTER-{}", "a".repeat(240)));
    assert!(c.checked().is_ok());
}

// ─── Announcing addresses the host is given (`advertise`) ──────────────────

/// A UDP port nothing holds right now (the caller sets `quic_port` to it, as
/// it would to the port a forward targets).
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A private LAN address of this machine, or `None` (the test then skips).
fn private_lan_ip() -> Option<std::net::Ipv4Addr> {
    let ip = crate::nat::candidates::local_outbound_v4().filter(|ip| ip.is_private());
    if ip.is_none() {
        eprintln!("skipped: this machine has no private LAN IPv4 address");
    }
    ip
}

/// Offer `offered` to the room `code` (hosted at [`DAY`]) as a stranger who
/// holds the code would, and return the answer the host sends back.
fn answer_to_offer(hub: &FakeRelayHub, code: &str, offered: Vec<Candidate>) -> Answer {
    let secrets = derive(TAG, code, DAY).unwrap();
    let me = nostr::Keys::generate();
    let relay = hub.client();
    relay
        .subscribe(TagFilter::one(
            crate::rendezvous::KIND_JOIN_ANSWER,
            'p',
            me.public_key().to_hex(),
        ))
        .unwrap();
    let session = "ab".repeat(16);
    let offer = crate::rendezvous::Offer {
        v: NET_PROTOCOL_VERSION,
        session: session.clone(),
        pubkey: me.public_key().to_hex(),
        candidates: offered,
        sent_at: unix_now(),
    };
    let ev = crate::rendezvous::seal_offer(&me, &secrets.keys.public_key(), &secrets.tag, &offer)
        .unwrap();
    hub.client().publish(&ev).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        while let Some(ev) = relay.try_recv() {
            if let Ok(a) = crate::rendezvous::open_answer(&me, &ev, &session, unix_now()) {
                return a;
            }
        }
        assert!(Instant::now() < deadline, "no answer");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn sa(s: &str) -> std::net::SocketAddr {
    s.parse().unwrap()
}

fn cand(kind: &str, addr: &str) -> Candidate {
    Candidate {
        kind: kind.into(),
        addr: addr.into(),
    }
}

#[test]
fn advertised_addresses_get_the_kind_a_joiner_accepts_for_them() {
    use crate::nat::candidates::{advertised_candidates, dialable};
    let given = [
        sa("192.168.1.20:40000"),      // RFC 1918: lan
        sa("10.1.2.3:40000"),          // RFC 1918: lan
        sa("172.16.0.9:40000"),        // RFC 1918: lan
        sa("100.64.0.7:40000"), // carrier-NAT / VPN overlay: lan (the joiner takes it as lan only)
        sa("[fd00::5]:40000"),  // unique-local: lan
        sa("81.2.69.160:40000"), // global v4: upnp
        sa("[2a00:1450::1]:40000"), // global v6: v6
        sa("[::ffff:10.0.0.4]:40001"), // v4-mapped: spelled as v4
    ];
    let got = advertised_candidates(&given).unwrap();
    let want = vec![
        cand("lan", "192.168.1.20:40000"),
        cand("lan", "10.1.2.3:40000"),
        cand("lan", "172.16.0.9:40000"),
        cand("lan", "100.64.0.7:40000"),
        cand("lan", "[fd00::5]:40000"),
        cand("upnp", "81.2.69.160:40000"),
        cand("v6", "[2a00:1450::1]:40000"),
        cand("lan", "10.0.0.4:40001"),
    ];
    assert_eq!(got, want);
    // The joiner's own filter keeps every one, in order.
    assert_eq!(dialable(&got), want);
    // A repeat (also in another spelling) is announced once.
    let twice =
        advertised_candidates(&[sa("10.1.2.3:40000"), sa("[::ffff:10.1.2.3]:40000")]).unwrap();
    assert_eq!(twice, vec![cand("lan", "10.1.2.3:40000")]);
}

#[test]
fn advertised_addresses_a_joiner_would_drop_are_refused() {
    use crate::nat::candidates::advertised_candidates;
    for bad in [
        "127.0.0.1:40000",
        "[::1]:40000",
        "0.0.0.0:40000",
        "[::]:40000",
        "192.168.1.20:1023", // below 1024
        "81.2.69.160:80",
        "192.168.1.20:0",
        "169.254.3.4:40000", // link-local: the joiner drops it even as lan
        "[fe80::1]:40000",
        "224.0.0.1:40000",
        "[ff02::1]:40000",
        "203.0.113.9:40000", // documentation
        "[2001:db8::1]:40000",
        "255.255.255.255:40000",
        "240.0.0.1:40000",
    ] {
        let err = advertised_candidates(&[sa(bad)]).expect_err(bad);
        assert!(err.contains(bad), "{bad}: {err}");
    }
    let nine: Vec<_> = (1..=9).map(|i| sa(&format!("81.2.69.{i}:40000"))).collect();
    assert!(advertised_candidates(&nine).is_err());
    assert_eq!(advertised_candidates(&nine[..8]).unwrap().len(), 8);
    assert!(advertised_candidates(&[]).unwrap().is_empty());
}

#[test]
fn a_host_config_with_bad_advertise_fails_at_start() {
    let cases: Vec<(NetConfig, &str)> = {
        let mut empty = cfg();
        empty.advertise_only = true;
        let mut loopback = cfg();
        loopback.advertise = vec![sa("127.0.0.1:40000")];
        let mut no_port = cfg();
        no_port.advertise = vec![sa("192.168.1.20:40000")];
        let mut cgnat_hooked = cfg();
        cgnat_hooked.quic_port = 40000;
        cgnat_hooked.advertise = vec![sa("100.64.0.7:40000")];
        cgnat_hooked.lan_socket_hook = Some(recording_hook().0);
        let mut low = cfg();
        low.advertise = vec![sa("192.168.1.20:443")];
        let mut only_loopback = cfg();
        only_loopback.advertise_only = true;
        only_loopback.advertise = vec![sa("[::1]:40000")];
        let mut hooked = cfg();
        hooked.quic_port = 40000;
        hooked.advertise = vec![sa("81.2.69.160:40000")];
        hooked.lan_socket_hook = Some(recording_hook().0);
        vec![
            (empty, "advertise is empty"),
            (loopback, "127.0.0.1:40000"),
            (no_port, "quic_port"),
            (cgnat_hooked, "100.64.0.7:40000"),
            (low, "1024"),
            (only_loopback, "::1"),
            (hooked, "lan_socket_hook"),
        ]
    };
    for (c, word) in cases {
        let h = host(&c, &Identity::ephemeral(), room(4));
        let ev = wait_host(&h, 5, |e| {
            matches!(e, HostEvent::Failed { .. } | HostEvent::Ready { .. })
        });
        assert!(
            matches!(&ev, HostEvent::Failed { reason } if reason.contains(word)),
            "{word}: {ev:?}"
        );
    }
    // A joiner never fails over a host-only setting.
    let mut c = cfg();
    c.advertise_only = true;
    assert!(c.checked().is_ok());
}

#[test]
fn advertise_is_appended_after_what_the_host_discovered() {
    use crate::host::{prepare_advertising, Advertise};
    let list = crate::nat::candidates::advertised_candidates(&[sa("81.2.69.160:40000")]).unwrap();
    let prep = futures_block(prepare_advertising(
        0,
        false,
        Vec::new(),
        None,
        Advertise {
            list: list.clone(),
            only: false,
        },
    ))
    .unwrap();
    assert!(
        !prep.candidates.is_empty(),
        "the host still gathers its own"
    );
    assert!(!prep.candidates.contains(&list[0]));
    let all = prep.announced();
    assert_eq!(all[..prep.candidates.len()], prep.candidates[..]);
    assert_eq!(all[prep.candidates.len()..], list[..]);
}

#[test]
fn advertise_only_announces_exactly_the_configured_set() {
    use crate::host::{current_candidates, prepare_advertising, Advertise};
    let list = crate::nat::candidates::advertised_candidates(&[
        sa("81.2.69.160:40000"),
        sa("192.168.1.20:40000"),
        sa("[2a00:1450::1]:40000"),
    ])
    .unwrap();
    // A STUN server and a UPnP request are given and must be ignored.
    let prep = futures_block(prepare_advertising(
        0,
        true,
        vec!["127.0.0.1:9".into()],
        None,
        Advertise {
            list: list.clone(),
            only: true,
        },
    ))
    .unwrap();
    assert!(prep.candidates.is_empty());
    assert!(prep.mapping.is_none() && !prep.upnp_attempted);
    assert_eq!(prep.announced(), list);
    // At answer time too, on a dual-stack socket whose kernel-side IPv6
    // address would otherwise be re-read, and on an IPv4 one.
    for bind in ["[::]:0", "0.0.0.0:0"] {
        let Ok(sock) = std::net::UdpSocket::bind(bind) else {
            continue;
        };
        let stale = vec![
            cand("v6", "[2a00:1450::99]:40000"),
            cand("lan", "10.9.9.9:40000"),
        ];
        assert_eq!(
            current_candidates(&stale, &list, true, &sock),
            list,
            "{bind}"
        );
        // Without advertise_only the gathered ones stay first, then the list.
        let mixed = current_candidates(&[cand("lan", "10.9.9.9:40000")], &list, false, &sock);
        let split = mixed.len() - list.len();
        assert!(
            mixed[..split].contains(&cand("lan", "10.9.9.9:40000")),
            "{bind}"
        );
        assert_eq!(mixed[split..], list[..], "{bind}");
    }
    // An advertised IPv6 address survives the IPv6 re-read on a dual-stack socket.
    if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
        let v6 = cand("v6", "[2a00:1450::1]:40000");
        let out = current_candidates(&[], std::slice::from_ref(&v6), false, &sock);
        assert!(out.contains(&v6), "{out:?}");
    }
    // Gathered entries give way before an advertised one is cut.
    let gathered: Vec<Candidate> = (1..=8)
        .map(|i| cand("stun", &format!("81.2.70.{i}:40000")))
        .collect();
    let out = crate::nat::candidates::append_advertised(gathered, &list);
    assert_eq!(out.len(), 8);
    assert_eq!(out[5..], list[..]);
}

#[test]
fn an_advertised_ipv6_address_needs_a_socket_that_can_answer_it() {
    use crate::host::check_advertise_family;
    let v6 = crate::nat::candidates::advertised_candidates(&[sa("[2a00:1450::1]:40000")]).unwrap();
    let v4 = crate::nat::candidates::advertised_candidates(&[sa("81.2.69.160:40000")]).unwrap();
    let both = [v4.clone(), v6.clone()].concat();
    // A dual-stack socket answers both families; an IPv4-only one only IPv4.
    assert!(check_advertise_family(sa("[::]:40000"), &both).is_ok());
    assert!(check_advertise_family(sa("0.0.0.0:40000"), &v4).is_ok());
    assert!(check_advertise_family(sa("0.0.0.0:40000"), &[]).is_ok());
    let e = check_advertise_family(sa("0.0.0.0:40000"), &both).unwrap_err();
    assert!(
        e.contains("[2a00:1450::1]:40000") && e.contains("IPv4-only"),
        "{e}"
    );
}

#[test]
fn an_advertise_only_host_sends_no_lan_beacon() {
    let mut c = cfg();
    c.advertise_only = true;
    c.quic_port = free_udp_port();
    c.advertise = vec![sa("10.1.2.3:40000")];
    let mut browser = lan_browse(&c);
    let h = host(&c, &Identity::ephemeral(), room(4));
    wait_host(&h, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let until = Instant::now() + Duration::from_millis(2500);
    while Instant::now() < until {
        assert!(browser.poll().is_empty(), "an advertise-only host beaconed");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Positive control: the same browser does hear an ordinary host.
    let mut plain = c.clone();
    plain.quic_port = 0;
    plain.advertise_only = false;
    plain.advertise.clear();
    let h2 = host(&plain, &Identity::ephemeral(), room(4));
    wait_host(&h2, 10, |e| matches!(e, HostEvent::Ready { .. }));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if browser.poll().iter().any(|r| r.code == h2.code()) {
            break;
        }
        assert!(Instant::now() < deadline, "control beacon not heard");
        std::thread::sleep(Duration::from_millis(50));
    }
    h.shutdown();
    h2.shutdown();
}

/// A joiner reaches an advertise-only host through the address it was told
/// to announce: the machine's own LAN address on the port it binds. (This
/// address is also what the host's own gather would find, so the test does not
/// tell the two apart; the answer's exact content and the absence of STUN and
/// punches are pinned by the tests below.)
#[test]
fn a_joiner_reaches_an_advertise_only_host_through_its_advertised_address() {
    let Some(lan_ip) = crate::nat::candidates::local_outbound_v4() else {
        eprintln!("skipped: this machine has no LAN IPv4 address");
        return;
    };
    // A free port for the host to bind (the caller sets quic_port to the port
    // a forward targets).
    let port = free_udp_port();
    let hub = FakeRelayHub::new();
    let joiner_cfg = cfg();
    let mut host_cfg = joiner_cfg.clone();
    host_cfg.quic_port = port;
    host_cfg.advertise_only = true;
    host_cfg.advertise = vec![std::net::SocketAddr::new(lan_ip.into(), port)];
    let h = host_with_relay(
        &host_cfg,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
    );
    let code = wait_ready(&h);
    assert_eq!(
        h.local_addr().unwrap().port(),
        port,
        "advertise does not change binding"
    );
    let cl = join_with_relay(
        &joiner_cfg,
        &Identity::ephemeral(),
        &code,
        Box::new(hub.client()),
    );
    let ev = join_outcome(&cl);
    let ClientEvent::Connected { path, .. } = ev else {
        panic!("{ev:?}");
    };
    assert_eq!(path, PathKind::Lan);
    wait_host(&h, 5, |e| matches!(e, HostEvent::PeerJoined { .. }));
    h.shutdown();
}

/// Datagrams that reach `sock` within `window`.
fn datagrams_within(sock: &std::net::UdpSocket, window: Duration) -> usize {
    let until = Instant::now() + window;
    let mut n = 0;
    let mut buf = [0u8; 2048];
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    while Instant::now() < until {
        if sock.recv_from(&mut buf).is_ok() {
            n += 1;
        }
    }
    n
}

#[test]
fn an_advertise_only_host_answers_with_exactly_its_list() {
    let Some(lan_ip) = private_lan_ip() else {
        return;
    };
    let mut c = cfg();
    c.quic_port = free_udp_port();
    // A global IPv4 entry no discovery of this machine would produce (STUN is
    // off), so the answer can only hold it if it came from `advertise`.
    c.advertise = vec![
        std::net::SocketAddr::new(lan_ip.into(), c.quic_port),
        sa(&format!("81.2.69.160:{}", c.quic_port)),
    ];
    c.advertise_only = true;
    let hub = FakeRelayHub::new();
    let h = host_with_relay_at_day(
        &c,
        &Identity::ephemeral(),
        room(4),
        Some(Box::new(hub.client())),
        DAY,
    );
    let code = wait_ready(&h);
    let answer = answer_to_offer(&hub, &code, vec![cand("lan", "10.9.9.9:40000")]);
    assert!(answer.accepted);
    assert_eq!(
        answer.candidates,
        vec![
            cand("lan", &c.advertise[0].to_string()),
            cand("upnp", &c.advertise[1].to_string()),
        ]
    );
    h.shutdown();
}

#[test]
fn an_advertise_only_host_sends_no_stun_query() {
    // A STUN "server" that only counts what reaches it.
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut c = cfg();
    c.stun = vec![server.local_addr().unwrap().to_string()];
    c.quic_port = free_udp_port();
    c.advertise = vec![sa(&format!("81.2.69.160:{}", c.quic_port))];
    c.advertise_only = true;
    let h = host_with_relay(&c, &Identity::ephemeral(), room(4), None);
    wait_ready(&h);
    assert_eq!(datagrams_within(&server, Duration::from_millis(1500)), 0);
    h.shutdown();
    // Positive control: without advertise_only the host does ask.
    c.advertise_only = false;
    c.advertise.clear();
    c.quic_port = 0;
    let h = host_with_relay(&c, &Identity::ephemeral(), room(4), None);
    wait_ready(&h);
    assert!(
        datagrams_within(&server, Duration::from_millis(500)) > 0,
        "control: an ordinary host sent no STUN query"
    );
    h.shutdown();
}

/// Joining by invite: a secret the host hands out, with its public key.
mod invites {
    use super::*;
    use crate::client::{join_invite_with_relay, join_invite_with_relay_at_day};
    use crate::quic;
    use crate::room::{derive_invite, utc_today, InviteId};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A distinct secret per `n`.
    fn secret(n: u8) -> [u8; 32] {
        let mut s = [0x5a; 32];
        s[0] = n;
        s
    }

    /// A relay-hosted room at the clock's day, with its code.
    fn hosted(hub: &FakeRelayHub, id: &Identity) -> (HostHandle, String) {
        let h = host_with_relay(&cfg(), id, room(8), Some(Box::new(hub.client())));
        let code = wait_ready(&h);
        (h, code)
    }

    /// The host's loopback address (its `Ready` was already taken).
    fn addr_of(h: &HostHandle) -> std::net::SocketAddr {
        let a = h.local_addr().expect("listening");
        std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), a.port())
    }

    /// The host listens on a new invite's tags a moment after `add_invite`.
    fn settle() {
        std::thread::sleep(Duration::from_millis(300));
    }

    fn join_by_invite(
        hub: &FakeRelayHub,
        secret: &[u8; 32],
        host_key: [u8; 32],
    ) -> (ClientHandle, Identity) {
        let id = Identity::ephemeral();
        let cl = join_invite_with_relay(&cfg(), &id, secret, host_key, Box::new(hub.client()));
        (cl, id)
    }

    fn joined(h: &HostHandle) -> (PublicKey, Admission) {
        let HostEvent::PeerJoined {
            pubkey,
            admitted_by,
            ..
        } = wait_host(h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
        else {
            unreachable!()
        };
        (pubkey, admitted_by)
    }

    /// Dial `addr` and send a hello proving `token` only. Whether the host
    /// welcomed us (it only does an admitted hello), and how it ended.
    fn raw_hello(addr: std::net::SocketAddr, token: [u8; 32]) -> (bool, Option<quic::Ended>) {
        let welcomed = Arc::new(AtomicBool::new(false));
        let w = Arc::clone(&welcomed);
        let ended = crate::runtime().block_on(async move {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let ep = quic::client_endpoint(socket, TAG, quic::Liveness::DEFAULT).unwrap();
            let conn = ep.connect(addr, quic::SERVER_NAME).unwrap().await.unwrap();
            let check: quic::HostCheck = Arc::new(move |_| {
                w.store(true, Ordering::Relaxed);
                Err("stop after the welcome".into())
            });
            let _ = quic::client_open(&conn, None, PathKind::Lan, &[token], &check).await;
            // Give a refusal time to arrive.
            tokio::time::sleep(Duration::from_millis(100)).await;
            conn.close_reason().map(|e| quic::ended_of(&e))
        });
        (welcomed.load(Ordering::Relaxed), ended)
    }

    #[test]
    fn a_joiner_gets_in_by_invite_and_the_host_sees_which() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, _code) = hosted(&hub, &host_id);
        let s = secret(1);
        let invite = h.add_invite(s).unwrap();
        assert_eq!(invite, InviteId::of(&s));
        assert_eq!(invite.to_string().len(), 32);
        settle();

        let (cl, id) = join_by_invite(&hub, &s, host_id.pubkey().to_bytes());
        let mut stages = Vec::new();
        let ev = wait_client(&cl, 25, |e| {
            if let ClientEvent::Progress { stage } = e {
                stages.push(*stage);
            }
            matches!(
                e,
                ClientEvent::Connected { .. } | ClientEvent::Failed { .. }
            )
        });
        assert!(
            matches!(&ev, ClientEvent::Connected { host_pubkey, .. } if *host_pubkey == host_id.pubkey()),
            "{ev:?}"
        );
        assert_eq!(
            stages,
            vec![
                JoinStage::Preparing,
                JoinStage::FindingHost,
                JoinStage::Connecting,
                JoinStage::Handshake
            ],
            "same flow as a code join"
        );
        let (pubkey, by) = joined(&h);
        assert_eq!(pubkey, id.pubkey());
        assert_eq!(by, Admission::Invite(invite));
        cl.send_reliable(Bytes::from_static(b"hi"));
        wait_host(&h, 5, |e| matches!(e, HostEvent::Reliable { .. }));
        h.shutdown();
    }

    #[test]
    fn invite_code_and_lan_joins_coexist_and_are_told_apart() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, code) = hosted(&hub, &host_id);
        let (a, b) = (secret(1), secret(2));
        let (ia, ib) = (h.add_invite(a).unwrap(), h.add_invite(b).unwrap());
        assert_ne!(ia, ib);
        settle();
        let addr = addr_of(&h);

        let c = cfg();
        let by_code = join_with_relay(&c, &Identity::ephemeral(), &code, Box::new(hub.client()));
        assert!(matches!(
            join_outcome(&by_code),
            ClientEvent::Connected { .. }
        ));
        assert_eq!(joined(&h).1, Admission::Code);

        let (inv_a, _) = join_by_invite(&hub, &a, host_id.pubkey().to_bytes());
        assert!(matches!(
            join_outcome(&inv_a),
            ClientEvent::Connected { .. }
        ));
        assert_eq!(joined(&h).1, Admission::Invite(ia));

        let (inv_b, _) = join_by_invite(&hub, &b, host_id.pubkey().to_bytes());
        assert!(matches!(
            join_outcome(&inv_b),
            ClientEvent::Connected { .. }
        ));
        assert_eq!(joined(&h).1, Admission::Invite(ib));

        let lan = join_addr(&c, &Identity::ephemeral(), addr, &h.lan_token());
        assert!(matches!(join_outcome(&lan), ClientEvent::Connected { .. }));
        assert_eq!(joined(&h).1, Admission::Lan);
        assert_eq!(h.peer_count(), 4);
        h.shutdown();
    }

    #[test]
    fn a_removed_invite_gets_no_answer_and_its_proof_is_refused() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, _code) = hosted(&hub, &host_id);
        let addr = addr_of(&h);
        let s = secret(3);
        let invite = h.add_invite(s).unwrap();
        settle();
        let today = utc_today();
        let proof_today = derive_invite(TAG, &s, today).unwrap().admit;
        let proof_yesterday = derive_invite(TAG, &s, today - 1).unwrap().admit;

        // Live: its proof is welcomed (the raw hello stops after the welcome).
        assert!(
            raw_hello(addr, proof_today).0,
            "a live invite's proof is admitted"
        );
        assert!(raw_hello(addr, proof_yesterday).0, "... and yesterday's");

        assert!(h.remove_invite(invite));
        assert!(!h.remove_invite(invite), "already gone");
        // At once, with no pause: the token is gone from admission.
        for proof in [proof_today, proof_yesterday] {
            let (welcomed, ended) = raw_hello(addr, proof);
            assert!(!welcomed, "a welcome was sent to a revoked invite");
            assert_eq!(ended, Some(quic::Ended::Remote(quic::close::NOT_ADMITTED)));
        }

        // And the host no longer answers offers on its tags.
        settle();
        let (cl, _) = join_by_invite(&hub, &s, host_id.pubkey().to_bytes());
        let ev = join_outcome(&cl);
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
        assert_eq!(h.peer_count(), 0);
        h.shutdown();
    }

    #[test]
    fn removing_an_invite_does_not_drop_a_connection_it_admitted() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, _) = hosted(&hub, &host_id);
        let s = secret(4);
        let invite = h.add_invite(s).unwrap();
        settle();
        let (cl, _) = join_by_invite(&hub, &s, host_id.pubkey().to_bytes());
        assert!(matches!(join_outcome(&cl), ClientEvent::Connected { .. }));
        let (_, by) = joined(&h);
        assert_eq!(by, Admission::Invite(invite));
        assert!(h.remove_invite(invite));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(h.peer_count(), 1, "the game decides about existing peers");
        cl.send_reliable(Bytes::from_static(b"still here"));
        wait_host(&h, 5, |e| matches!(e, HostEvent::Reliable { .. }));
        h.shutdown();
    }

    /// A code's proof is not an invite's and the other way round: each is
    /// credited only to its own kind, and never admits without its own token.
    #[test]
    fn a_code_proof_is_not_an_invite_proof_and_vice_versa() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, code) = hosted(&hub, &host_id);
        let addr = addr_of(&h);
        let today = utc_today();
        let code_proof = derive(TAG, &code, today).unwrap().admit;
        let s = secret(5);
        let invite_proof = derive_invite(TAG, &s, today).unwrap().admit;

        // Before the invite exists, its proof gets nothing; the code's gets in.
        assert!(!raw_hello(addr, invite_proof).0);
        assert!(raw_hello(addr, code_proof).0);

        // With it added both work, each for itself.
        h.add_invite(s).unwrap();
        settle();
        assert!(raw_hello(addr, invite_proof).0);
        assert!(raw_hello(addr, code_proof).0);

        // An invite built from the code's own derived token is a different
        // invite and a different room; it is not the code.
        let confused = derive_invite(TAG, &code_proof, today).unwrap();
        assert_ne!(confused.admit, code_proof);
        assert!(!raw_hello(addr, confused.admit).0);
        // A secret the host does not hold admits nobody.
        let other = derive_invite(TAG, &secret(6), today).unwrap().admit;
        assert!(!raw_hello(addr, other).0);
        h.shutdown();
    }

    #[test]
    fn an_invite_pins_the_host_key() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, _) = hosted(&hub, &host_id);
        let s = secret(7);
        h.add_invite(s).unwrap();
        settle();
        let wrong = Identity::ephemeral().pubkey().to_bytes();
        let (cl, _) = join_by_invite(&hub, &s, wrong);
        let ev = join_outcome(&cl);
        assert!(
            matches!(
                ev,
                ClientEvent::Failed {
                    reason: FailReason::HostUnverified,
                    ..
                }
            ),
            "{ev:?}"
        );
        assert_eq!(h.peer_count(), 0, "we never said who we are");
        while let Some(ev) = h.poll() {
            assert!(
                !matches!(ev, HostEvent::PeerJoined { .. }),
                "the host seated a joiner that refused it"
            );
        }
        // The right key, same secret: in.
        let (ok, _) = join_by_invite(&hub, &s, host_id.pubkey().to_bytes());
        assert!(matches!(join_outcome(&ok), ClientEvent::Connected { .. }));
        h.shutdown();
    }

    /// An imposter holding the secret (a leaked link) answers as itself: its
    /// welcome is signed by the wrong key, so the pinned joiner refuses it
    /// even though the answer, the tag and the admission all check out.
    #[test]
    fn a_host_other_than_the_pinned_one_is_refused_even_with_the_secret() {
        let hub = FakeRelayHub::new();
        let imposter_id = Identity::ephemeral();
        let (imposter, _) = hosted(&hub, &imposter_id);
        let s = secret(8);
        imposter.add_invite(s).unwrap();
        settle();
        let real = Identity::ephemeral().pubkey().to_bytes();
        let (cl, _) = join_by_invite(&hub, &s, real);
        let ev = join_outcome(&cl);
        assert!(
            matches!(
                ev,
                ClientEvent::Failed {
                    reason: FailReason::HostUnverified,
                    ..
                }
            ),
            "{ev:?}"
        );
        imposter.shutdown();
    }

    #[test]
    fn invites_overlap_across_utc_midnight_like_the_code() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let c = cfg();
        let h = host_with_relay_at_day(&c, &host_id, room(8), Some(Box::new(hub.client())), DAY);
        wait_ready(&h);
        let s = secret(9);
        let invite = h.add_invite(s).unwrap();
        settle();
        let key = host_id.pubkey().to_bytes();
        let at = |day| {
            join_invite_with_relay_at_day(
                &c,
                &Identity::ephemeral(),
                &s,
                key,
                Box::new(hub.client()),
                day,
            )
        };
        // Same day, a joiner a day ahead (host's yesterday), a day behind
        // (joiner's yesterday is the host's today): all meet.
        for day in [DAY, DAY + 1] {
            let cl = at(day);
            assert!(
                matches!(join_outcome(&cl), ClientEvent::Connected { .. }),
                "day {day}"
            );
            assert_eq!(joined(&h).1, Admission::Invite(invite));
        }
        // Two days out, nothing in common.
        let far = at(DAY + 2);
        assert!(matches!(
            join_outcome(&far),
            ClientEvent::Failed {
                stage: JoinStage::FindingHost,
                reason: FailReason::NoAnswer
            }
        ));
        h.shutdown();
    }

    #[test]
    fn invites_roll_to_the_new_day_with_the_code() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let c = cfg();
        let h = host_with_relay_at_day(&c, &host_id, room(8), Some(Box::new(hub.client())), DAY);
        let code = wait_ready(&h);
        let addr = addr_of(&h);
        let s = secret(10);
        let invite = h.add_invite(s).unwrap();
        settle();
        let key = host_id.pubkey().to_bytes();
        let day_proof = |d: u64| derive_invite(TAG, &s, d).unwrap().admit;
        assert!(raw_hello(addr, day_proof(DAY)).0);
        assert!(raw_hello(addr, day_proof(DAY - 1)).0);
        assert!(!raw_hello(addr, day_proof(DAY + 1)).0, "not yet");

        // Midnight UTC passes on the host: it listens on DAY + 1 and DAY.
        h.set_test_day(DAY + 1);
        std::thread::sleep(Duration::from_millis(500));
        assert!(raw_hello(addr, day_proof(DAY + 1)).0, "the new day's token");
        assert!(raw_hello(addr, day_proof(DAY)).0, "yesterday's still works");
        assert!(
            !raw_hello(addr, day_proof(DAY - 1)).0,
            "the day before yesterday's is dropped"
        );

        // A joiner on the new day and one still on the old day both find it.
        let join_at = |day| {
            join_invite_with_relay_at_day(
                &c,
                &Identity::ephemeral(),
                &s,
                key,
                Box::new(hub.client()),
                day,
            )
        };
        for day in [DAY + 1, DAY] {
            let cl = join_at(day);
            assert!(
                matches!(join_outcome(&cl), ClientEvent::Connected { .. }),
                "day {day}"
            );
            assert_eq!(joined(&h).1, Admission::Invite(invite));
        }
        // A joiner two days behind the host finds nothing.
        let behind = join_at(DAY - 1);
        assert!(matches!(
            join_outcome(&behind),
            ClientEvent::Failed {
                reason: FailReason::NoAnswer,
                ..
            }
        ));
        // The code rolled too, and an invite added after the roll is derived for the new day.
        let late = secret(11);
        h.add_invite(late).unwrap();
        settle();
        assert!(raw_hello(addr, derive_invite(TAG, &late, DAY + 1).unwrap().admit).0);
        assert!(raw_hello(addr, derive(TAG, &code, DAY + 1).unwrap().admit).0);
        h.shutdown();
    }

    #[test]
    fn the_257th_invite_is_refused() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, _) = hosted(&hub, &host_id);
        let secrets: Vec<[u8; 32]> = (0..=255u8)
            .map(|n| {
                let mut s = [0x33; 32];
                s[0] = n;
                s
            })
            .collect();
        assert_eq!(secrets.len(), crate::host::MAX_INVITES);
        let ids: Vec<InviteId> = secrets.iter().map(|s| h.add_invite(*s).unwrap()).collect();
        let extra = [0x77; 32];
        assert!(h.add_invite(extra).is_err(), "257th refused");
        // Adding one already held is not a new invite.
        assert_eq!(h.add_invite(secrets[0]).unwrap(), ids[0]);
        // Room frees up when one is revoked.
        assert!(h.remove_invite(ids[7]));
        assert_eq!(h.add_invite(extra).unwrap(), InviteId::of(&extra));
        assert!(h.add_invite(secrets[7]).is_err(), "full again");
        settle();
        // A full house still answers: the last one in gets through.
        let (cl, _) = join_by_invite(&hub, &secrets[255], host_id.pubkey().to_bytes());
        assert!(matches!(join_outcome(&cl), ClientEvent::Connected { .. }));
        assert_eq!(joined(&h).1, Admission::Invite(ids[255]));
        h.shutdown();
    }

    #[test]
    fn a_closed_room_does_not_answer_an_invite_and_an_open_one_does_again() {
        let hub = FakeRelayHub::new();
        let host_id = Identity::ephemeral();
        let (h, _) = hosted(&hub, &host_id);
        let s = secret(12);
        h.add_invite(s).unwrap();
        settle();
        h.set_open(false);
        settle();
        // Adding an invite to a closed room must not reopen the subscription.
        h.add_invite(secret(13)).unwrap();
        settle();
        let (late, _) = join_by_invite(&hub, &s, host_id.pubkey().to_bytes());
        assert!(matches!(
            join_outcome(&late),
            ClientEvent::Failed {
                reason: FailReason::NoAnswer,
                ..
            }
        ));
        h.set_open(true);
        settle();
        let (cl, _) = join_by_invite(&hub, &s, host_id.pubkey().to_bytes());
        assert!(matches!(join_outcome(&cl), ClientEvent::Connected { .. }));
        h.shutdown();
    }
}
