//! A1: the per-app reliable message cap and the byte-bounded queues, over real
//! QUIC on loopback.

use super::*;
use crate::quic::{self, close};
use std::net::UdpSocket;

const MARKER: &[u8] = b"marker";

/// An app that sends 65 537-byte messages (AxeNStax's frame size).
fn big_cfg() -> NetConfig {
    let mut c = cfg();
    c.max_reliable_len = 65_537;
    c.host_inbound = QueueBound {
        messages: 4096,
        bytes: 8 * 1024 * 1024,
    };
    c.client_inbound = c.host_inbound;
    c.outbound_queue_bytes = 8 * 1024 * 1024;
    c
}

/// Host + one client over the LAN path, each with its own config.
fn pair_with(hc: &NetConfig, cc: &NetConfig) -> (HostHandle, ClientHandle, PeerId) {
    let h = host(hc, &Identity::ephemeral(), room(4));
    let addr = local_addr(&h);
    let cl = join_addr(cc, &Identity::ephemeral(), addr, &h.lan_token());
    wait_client(&cl, 10, |e| matches!(e, ClientEvent::Connected { .. }));
    let HostEvent::PeerJoined { peer, .. } =
        wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    (h, cl, peer)
}

fn next_host_reliable(h: &HostHandle) -> Bytes {
    match wait_host(h, 10, |e| matches!(e, HostEvent::Reliable { .. })) {
        HostEvent::Reliable { bytes, .. } => bytes,
        _ => unreachable!(),
    }
}

fn next_client_reliable(c: &ClientHandle) -> Bytes {
    match wait_client(c, 10, |e| matches!(e, ClientEvent::Reliable(_))) {
        ClientEvent::Reliable(b) => b,
        _ => unreachable!(),
    }
}

fn pattern(len: usize, seed: u8) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect::<Vec<u8>>(),
    )
}

/// A joiner that completes the real handshake and then speaks raw frames.
struct Raw {
    _endpoint: quinn::Endpoint,
    opened: quic::Opened,
}

impl Raw {
    fn join(addr: std::net::SocketAddr, token_hex: &str, tag: &str) -> Raw {
        let token: [u8; 32] = hex::decode(token_hex).unwrap().try_into().unwrap();
        crate::runtime().block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let endpoint = quic::client_endpoint(socket, tag, quic::Liveness::DEFAULT).unwrap();
            let conn = endpoint
                .connect(addr, quic::SERVER_NAME)
                .unwrap()
                .await
                .unwrap();
            let check: quic::HostCheck = Arc::new(|_| Ok(()));
            let mut opened = quic::client_open(&conn, None, PathKind::Lan, &[token], &check)
                .await
                .unwrap();
            quic::client_identify(&mut opened, Identity::ephemeral().keys(), None, &[], None)
                .await
                .unwrap();
            Raw {
                _endpoint: endpoint,
                opened,
            }
        })
    }

    /// Write one frame whose length prefix and body are both `len`, with no
    /// cap applied on our side.
    fn write_raw(&mut self, len: usize) {
        let mut frame = (len as u32).to_le_bytes().to_vec();
        frame.extend(std::iter::repeat_n(7u8, len));
        crate::runtime()
            .block_on(self.opened.send.write_all(&frame))
            .unwrap();
    }

    fn wait_closed(&self) -> quinn::ConnectionError {
        let conn = self.opened.conn.clone();
        crate::runtime()
            .block_on(
                async move { tokio::time::timeout(Duration::from_secs(8), conn.closed()).await },
            )
            .expect("the host ended the connection")
    }
}

use std::sync::Arc;

fn host_saw_peer_leave(h: &HostHandle, peer: PeerId) {
    wait_host(
        h,
        10,
        |e| matches!(e, HostEvent::PeerLeft { peer: p, .. } if *p == peer),
    );
}

fn raw_peer_id(h: &HostHandle) -> PeerId {
    let HostEvent::PeerJoined { peer, .. } =
        wait_host(h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }))
    else {
        unreachable!()
    };
    peer
}

#[test]
fn a1_default_cap_is_1024_both_ways_and_defaults_equal_the_historic_constants() {
    let c = NetConfig::new("d", "t");
    assert_eq!(c.max_reliable_len, MAX_RELIABLE_LEN);
    assert_eq!(MAX_RELIABLE_LEN, 1024);
    assert_eq!(
        c.host_inbound,
        QueueBound {
            messages: 256,
            bytes: 256 * 1024
        }
    );
    assert_eq!(
        c.client_inbound,
        QueueBound {
            messages: 1024,
            bytes: 1024 * 1024
        }
    );
    assert_eq!(c.outbound_queue_bytes, 1024 * 1024);
    assert_eq!(c.host_inbound.messages, crate::host::MAX_QUEUED_RELIABLE);
    assert_eq!(
        c.client_inbound.messages,
        crate::client::MAX_QUEUED_RELIABLE
    );
    assert!(c.checked().is_ok());

    let (h, cl, peer, _) = connected_pair(4);
    let exact = pattern(1024, 1);
    cl.send_reliable(exact.clone());
    assert_eq!(next_host_reliable(&h), exact);
    h.send_reliable(peer, exact.clone());
    assert_eq!(next_client_reliable(&cl), exact);
    // 1025 is dropped on send, on both ends; the marker behind it still lands.
    cl.send_reliable(pattern(1025, 2));
    cl.send_reliable(Bytes::from_static(MARKER));
    assert_eq!(next_host_reliable(&h), MARKER);
    h.send_reliable(peer, pattern(1025, 3));
    h.send_reliable(peer, Bytes::from_static(MARKER));
    assert_eq!(next_client_reliable(&cl), MARKER);
    h.shutdown();
}

#[test]
fn a1_a_raw_1025_byte_frame_ends_a_default_connection() {
    let c = cfg();
    let h = host(&c, &Identity::ephemeral(), room(4));
    let addr = local_addr(&h);
    let mut ok = Raw::join(addr, &h.lan_token(), &c.app_tag);
    let peer = raw_peer_id(&h);
    // Control: a raw 1024-byte frame is accepted and delivered.
    ok.write_raw(1024);
    assert_eq!(next_host_reliable(&h).len(), 1024);
    ok.write_raw(1025);
    ok.wait_closed();
    host_saw_peer_leave(&h, peer);
    h.shutdown();
}

#[test]
fn a1_a_raised_cap_carries_whole_messages_both_ways() {
    let c = big_cfg();
    let (h, cl, peer) = pair_with(&c, &c);
    for (len, seed) in [(48 * 1024, 4u8), (65_537, 5)] {
        let up = pattern(len, seed);
        cl.send_reliable(up.clone());
        assert_eq!(next_host_reliable(&h), up, "client to host, {len}");
        let down = pattern(len, seed + 10);
        h.send_reliable(peer, down.clone());
        assert_eq!(next_client_reliable(&cl), down, "host to client, {len}");
    }
    // One byte over is dropped on send, each way; the marker behind it lands.
    cl.send_reliable(pattern(65_538, 6));
    cl.send_reliable(Bytes::from_static(MARKER));
    assert_eq!(next_host_reliable(&h), MARKER);
    h.send_reliable(peer, pattern(65_538, 7));
    h.send_reliable(peer, Bytes::from_static(MARKER));
    assert_eq!(next_client_reliable(&cl), MARKER);
    h.shutdown();
}

#[test]
fn a1_a_raw_frame_above_a_raised_cap_ends_the_connection() {
    let c = big_cfg();
    let h = host(&c, &Identity::ephemeral(), room(4));
    let addr = local_addr(&h);
    let mut raw = Raw::join(addr, &h.lan_token(), &c.app_tag);
    let peer = raw_peer_id(&h);
    // Control: exactly the cap is delivered, so the close below is the cap.
    raw.write_raw(65_537);
    assert_eq!(next_host_reliable(&h).len(), 65_537);
    raw.write_raw(65_538);
    raw.wait_closed();
    host_saw_peer_leave(&h, peer);
    h.shutdown();
}

/// Documented behaviour: the cap is per app and both ends must agree. A frame
/// above the receiver's cap is a protocol error, and the receiver ends the
/// connection (its reader stops, then it closes with the "left" code after
/// letting the peer's close arrive). Neither end panics or hangs.
#[test]
fn a1_mismatched_caps_end_the_connection_as_a_protocol_error() {
    let (hc, cc) = (big_cfg(), cfg());
    let (h, cl, peer) = pair_with(&hc, &cc);
    h.send_reliable(peer, pattern(2048, 8));
    let mut delivered = false;
    wait_client(&cl, 10, |e| {
        delivered |= matches!(e, ClientEvent::Reliable(_));
        matches!(e, ClientEvent::Disconnected { .. })
    });
    assert!(!delivered, "an oversize frame must not reach the app");
    host_saw_peer_leave(&h, peer);
    h.shutdown();
}

#[test]
fn a1_the_handshake_frame_cap_does_not_grow_with_the_app_cap() {
    assert_eq!(quic::HANDSHAKE_FRAME_CAP, 8192);
    let c = big_cfg();
    let h = host(&c, &Identity::ephemeral(), room(4));
    let addr = local_addr(&h);
    let over = quic::HANDSHAKE_FRAME_CAP + 1;
    // A well-formed, admitted hello padded with trailing spaces to `total`
    // bytes: welcomed at exactly the hello cap, refused one byte over.
    let token: [u8; 32] = hex::decode(h.lan_token()).unwrap().try_into().unwrap();
    let padded_hello = |total: usize| {
        crate::runtime().block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let ep = quic::client_endpoint(socket, &c.app_tag, quic::Liveness::DEFAULT).unwrap();
            let conn = ep.connect(addr, quic::SERVER_NAME).unwrap().await.unwrap();
            let b = quic::binding(&conn).unwrap();
            let hello = quic::Hello {
                v: NET_PROTOCOL_VERSION,
                migration: None,
                session: None,
                path: PathKind::Lan,
                admit: vec![hex::encode(quic::admit_proof(&token, &b))],
            };
            let mut json = serde_json::to_vec(&hello).unwrap();
            assert!(json.len() < total);
            json.resize(total, b' ');
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            let mut frame = (total as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(&json);
            send.write_all(&frame).await.unwrap();
            let welcomed = matches!(
                tokio::time::timeout(
                    Duration::from_secs(8),
                    quic::read_frame(&mut recv, quic::HANDSHAKE_FRAME_CAP)
                )
                .await,
                Ok(Ok(Some(_)))
            );
            let closed = if welcomed {
                true
            } else {
                tokio::time::timeout(Duration::from_secs(8), conn.closed())
                    .await
                    .is_ok()
            };
            drop(ep);
            (welcomed, closed)
        })
    };
    assert_eq!(padded_hello(quic::HELLO_FRAME_CAP), (true, true));
    assert_eq!(
        padded_hello(quic::HELLO_FRAME_CAP + 1),
        (false, true),
        "an admitted hello one byte over the hello cap must be refused"
    );
    // A joiner with a verified welcome whose signed identify frame is padded
    // to `total` bytes: seated at exactly the handshake cap, refused one byte
    // over (before admission, so nothing is buffered for a stranger).
    let padded_identify = |total: usize| {
        crate::runtime().block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let ep = quic::client_endpoint(socket, &c.app_tag, quic::Liveness::DEFAULT).unwrap();
            let conn = ep.connect(addr, quic::SERVER_NAME).unwrap().await.unwrap();
            let check: quic::HostCheck = Arc::new(|_| Ok(()));
            let mut opened = quic::client_open(&conn, None, PathKind::Lan, &[token], &check)
                .await
                .unwrap();
            let keys = Identity::ephemeral();
            let mut json = quic::identify_json(&opened, keys.keys(), None, &[], None).unwrap();
            assert!(json.len() < total);
            json.resize(total, b' ');
            let mut frame = (total as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(&json);
            opened.send.write_all(&frame).await.unwrap();
            let seated = matches!(
                tokio::time::timeout(
                    Duration::from_secs(8),
                    quic::read_frame(&mut opened.recv, quic::HANDSHAKE_FRAME_CAP)
                )
                .await,
                Ok(Ok(Some(_)))
            );
            let closed = seated
                || tokio::time::timeout(Duration::from_secs(8), conn.closed())
                    .await
                    .is_ok();
            drop(ep);
            (seated, closed)
        })
    };
    assert_eq!(
        padded_identify(over),
        (false, true),
        "a signed identify one byte over the handshake cap must be refused"
    );
    assert_eq!(padded_identify(quic::HANDSHAKE_FRAME_CAP), (true, true));
    // The one that was seated is the only peer that ever joined.
    wait_host(&h, 10, |e| matches!(e, HostEvent::PeerJoined { .. }));
    h.shutdown();
}

#[test]
fn a1_a_host_inbound_byte_bound_trips_before_the_count_bound() {
    let mut c = cfg();
    c.max_reliable_len = 16 * 1024;
    c.host_inbound = QueueBound {
        messages: 100_000,
        bytes: 64 * 1024,
    };
    let (h, cl, peer) = pair_with(&c, &c);
    // The host app stops polling; the peer sends 160 KiB in 4 KiB messages.
    for i in 0..40 {
        cl.send_reliable(pattern(4096, i));
    }
    wait_client(&cl, 10, |e| matches!(e, ClientEvent::Disconnected { .. }));
    let (mut count, mut bytes, mut left) = (0usize, 0usize, false);
    while let Some(ev) = h.poll() {
        match ev {
            HostEvent::Reliable { bytes: b, .. } => {
                count += 1;
                bytes += b.len();
            }
            HostEvent::PeerLeft { peer: p, .. } if p == peer => left = true,
            _ => {}
        }
    }
    assert!(left, "the peer past the byte bound was dropped");
    assert!(bytes <= 64 * 1024, "{bytes} bytes queued");
    assert!(count < 40 && count >= 1, "{count} queued of 40");
    h.shutdown();
}

#[test]
fn a1_a_client_inbound_byte_bound_trips_before_the_count_bound() {
    let mut c = cfg();
    c.max_reliable_len = 16 * 1024;
    c.client_inbound = QueueBound {
        messages: 100_000,
        bytes: 64 * 1024,
    };
    let (h, cl, peer) = pair_with(&c, &c);
    // The client app stops polling; the host sends 160 KiB in 4 KiB messages.
    for i in 0..40 {
        h.send_reliable(peer, pattern(4096, i));
    }
    host_saw_peer_leave(&h, peer);
    let (mut count, mut bytes, mut disconnected) = (0usize, 0usize, false);
    while let Some(ev) = cl.poll() {
        match ev {
            ClientEvent::Reliable(b) => {
                count += 1;
                bytes += b.len();
            }
            ClientEvent::Disconnected { .. } => disconnected = true,
            _ => {}
        }
    }
    assert!(disconnected, "the host past the byte bound was dropped");
    assert!(bytes <= 64 * 1024, "{bytes} bytes queued");
    assert!(count < 40 && count >= 1, "{count} queued of 40");
    h.shutdown();
}

/// Reliable bytes the host queues for a peer that is not reading.
fn flood_a_silent_peer(outbound: usize, messages: usize) -> (Raw, HostHandle) {
    let mut c = cfg();
    c.outbound_queue_bytes = outbound;
    let h = host(&c, &Identity::ephemeral(), room(4));
    let addr = local_addr(&h);
    // The raw peer completes the handshake and then never reads.
    let raw = Raw::join(addr, &h.lan_token(), &c.app_tag);
    let peer = raw_peer_id(&h);
    for i in 0..messages {
        h.send_reliable(peer, pattern(1024, i as u8));
    }
    (raw, h)
}

#[test]
fn a1_a_small_outbound_queue_bound_closes_a_slow_reader_as_too_slow() {
    // 6 MiB for a peer that reads nothing, against a 16 KiB bound.
    let (raw, h) = flood_a_silent_peer(16 * 1024, 6 * 1024);
    let ended = raw.wait_closed();
    assert!(
        matches!(&ended, quinn::ConnectionError::ApplicationClosed(c)
            if c.error_code == quinn::VarInt::from_u32(close::TOO_SLOW)),
        "{ended:?}"
    );
    h.shutdown();
}

#[test]
fn a1_a_large_outbound_queue_bound_lets_the_same_burst_queue() {
    // The same shape of load against a 8 MiB bound: queued, not closed.
    let (raw, h) = flood_a_silent_peer(8 * 1024 * 1024, 3 * 1024);
    std::thread::sleep(Duration::from_millis(500));
    assert!(raw.opened.conn.close_reason().is_none());
    h.shutdown();
}

#[test]
fn a1_every_bad_reliable_setting_is_refused_by_host_and_join() {
    type Tweak = fn(&mut NetConfig);
    let cases: [(&str, Tweak, &str); 13] = [
        (
            "cap below 1024",
            |c| c.max_reliable_len = 1023,
            "max_reliable_len",
        ),
        ("cap zero", |c| c.max_reliable_len = 0, "max_reliable_len"),
        (
            "cap above 1 MiB",
            |c| c.max_reliable_len = 1024 * 1024 + 1,
            "max_reliable_len",
        ),
        (
            "host messages zero",
            |c| c.host_inbound.messages = 0,
            "host_inbound",
        ),
        (
            "host bytes zero",
            |c| c.host_inbound.bytes = 0,
            "host_inbound",
        ),
        (
            "client messages zero",
            |c| c.client_inbound.messages = 0,
            "client_inbound",
        ),
        (
            "client bytes zero",
            |c| c.client_inbound.bytes = 0,
            "client_inbound",
        ),
        (
            "outbound zero",
            |c| c.outbound_queue_bytes = 0,
            "outbound_queue_bytes",
        ),
        (
            "host bytes below cap",
            |c| {
                c.max_reliable_len = 65_537;
                c.host_inbound.bytes = 65_536;
                c.client_inbound.bytes = 1 << 20;
                c.outbound_queue_bytes = 1 << 20;
            },
            "host_inbound",
        ),
        (
            "client bytes below cap",
            |c| {
                c.max_reliable_len = 65_537;
                c.host_inbound.bytes = 1 << 20;
                c.client_inbound.bytes = 65_536;
                c.outbound_queue_bytes = 1 << 20;
            },
            "client_inbound",
        ),
        (
            "outbound below cap",
            |c| {
                c.max_reliable_len = 65_537;
                c.host_inbound.bytes = 1 << 20;
                c.client_inbound.bytes = 1 << 20;
                c.outbound_queue_bytes = 65_536;
            },
            "outbound_queue_bytes",
        ),
        (
            "default bounds below a raised cap",
            |c| c.max_reliable_len = 512 * 1024 + 1,
            "host_inbound",
        ),
        (
            "outbound below the default cap",
            |c| c.outbound_queue_bytes = 1023,
            "outbound_queue_bytes",
        ),
    ];
    for (what, tweak, word) in cases {
        let mut c = cfg();
        tweak(&mut c);
        let err = c.checked().expect_err(what);
        assert!(err.contains(word), "{what}: {err}");
        let h = host(&c, &Identity::ephemeral(), room(4));
        let ev = wait_host(&h, 5, |e| {
            matches!(e, HostEvent::Failed { .. } | HostEvent::Ready { .. })
        });
        assert!(
            matches!(&ev, HostEvent::Failed { reason } if reason.contains(word)),
            "{what}: {ev:?}"
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
            "{what}: {ev:?}"
        );
    }
}

#[test]
fn a1_the_edges_of_the_allowed_range_are_accepted() {
    let mut c = cfg();
    assert!(c.checked().is_ok());
    // The smallest bounds that still fit one legal message.
    c.host_inbound = QueueBound {
        messages: 1,
        bytes: 1024,
    };
    c.client_inbound = c.host_inbound;
    c.outbound_queue_bytes = 1024;
    assert!(c.checked().is_ok());
    c.max_reliable_len = 1024 * 1024;
    c.host_inbound.bytes = 1024 * 1024;
    c.client_inbound.bytes = 1024 * 1024;
    c.outbound_queue_bytes = 1024 * 1024;
    assert!(c.checked().is_ok());
    assert!(big_cfg().checked().is_ok());
}
