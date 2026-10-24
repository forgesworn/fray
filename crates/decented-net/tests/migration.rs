//! Host-migration tests that run over a real QUIC connection. The tests that
//! need no sockets live in `fray-session`'s `tests/migration.rs`.

use fray_net::migration::*;
use fray_net::Keys;

fn marks(input: u64, ack: u64) -> Vec<Watermark> {
    vec![Watermark {
        player: 1,
        input,
        output_ack: ack,
        retired: false,
    }]
}

fn descriptor_fixture() -> (Descriptor, Keys, Keys, Keys) {
    let host = Keys::generate();
    let standby = Keys::generate();
    let player = Keys::generate();
    let root = Root {
        session: fresh_session().unwrap(),
        app: "migration-test".into(),
        transport_version: 7,
        game_version: 13,
        checkpoint_version: 1,
        host: host.public_key().to_bytes(),
        standby: standby.public_key().to_bytes(),
        controller: host.public_key().to_bytes(),
        code: room_code_hash("ABCDEF").unwrap(),
        created_day: 20741,
        roster_revision: 1,
        members: vec![
            Member {
                player: 1,
                seat: 0,
                key: Some(host.public_key().to_bytes()),
            },
            Member {
                player: 2,
                seat: 1,
                key: Some(player.public_key().to_bytes()),
            },
            Member {
                player: 3,
                seat: 2,
                key: None,
            },
        ],
        config: [11; 32],
        content: [12; 32],
        limits: ResourceLimits::default(),
    };
    (
        Descriptor::offer(root, &host).unwrap(),
        host,
        standby,
        player,
    )
}

fn wait_host_ready(host: &fray_net::HostHandle) -> std::net::SocketAddr {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        while let Some(event) = host.poll() {
            match event {
                fray_net::HostEvent::Ready { .. } => {
                    return std::net::SocketAddr::new(
                        std::net::Ipv4Addr::LOCALHOST.into(),
                        host.local_addr().unwrap().port(),
                    )
                }
                fray_net::HostEvent::Failed { reason } => panic!("host failed: {reason}"),
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    panic!("host did not become ready");
}
fn connected_metadata(client: &fray_net::ClientHandle) -> Option<(Option<String>, Vec<String>)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        while let Some(event) = client.poll() {
            match event {
                fray_net::ClientEvent::Connected {
                    attestation,
                    inbox_relays,
                    ..
                } => return Some((attestation, inbox_relays)),
                fray_net::ClientEvent::Failed { .. }
                | fray_net::ClientEvent::Disconnected { .. } => return None,
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    panic!("client had no terminal connection event");
}
fn wait_connected(client: &fray_net::ClientHandle) -> bool {
    connected_metadata(client).is_some()
}
#[test]
fn passive_standby_accepts_nine_bound_control_links_without_advertising_or_player_seats() {
    use fray_net::{host_standby, join_addr, join_session_addr, Identity, NetConfig};
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral().with_attestation("private standby persona".into());
    let outsider = Identity::ephemeral();
    let players: Vec<_> = (0..8).map(|_| Identity::ephemeral()).collect();
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-control-test").lan_only();
    cfg.lan_port = 0;
    cfg.withhold_host_attestation = Some(true);
    cfg.inbox_relays = vec!["wss://inbox.example".into()];
    let root = Root {
        session: fresh_session().unwrap(),
        app: cfg.app_tag.clone(),
        transport_version: 7,
        game_version: 13,
        checkpoint_version: 1,
        host: original.pubkey().to_bytes(),
        standby: standby.pubkey().to_bytes(),
        controller: original.pubkey().to_bytes(),
        code: room_code_hash("ABCDEF").unwrap(),
        created_day: 20741,
        roster_revision: 1,
        members: players
            .iter()
            .enumerate()
            .map(|(i, p)| Member {
                player: i as u64 + 1,
                seat: i as u8,
                key: Some(p.pubkey().to_bytes()),
            })
            .collect(),
        config: [11; 32],
        content: [12; 32],
        limits: ResourceLimits::default(),
    };
    let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let listener = host_standby(&cfg, &standby, "ABCDEF", descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    assert_eq!(listener.code(), "ABCDEF");
    assert!(!listener.is_open());
    listener.set_open(true);
    assert!(!listener.is_open());
    let mut binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let no_binding = join_addr(&cfg, &players[0], addr, &listener.lan_token());
    assert!(!wait_connected(&no_binding));
    let wrong_key = join_session_addr(
        &cfg,
        &outsider,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&wrong_key));
    let mut wrong_root = binding.clone();
    wrong_root.session[0] ^= 1;
    let stale = join_session_addr(
        &cfg,
        &players[0],
        addr,
        &listener.lan_token(),
        wrong_root,
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&stale));
    let mut clients = Vec::new();
    for player in &players {
        let client = join_session_addr(
            &cfg,
            player,
            addr,
            &listener.lan_token(),
            binding.clone(),
            standby.pubkey(),
        )
        .unwrap();
        assert_eq!(connected_metadata(&client), Some((None, vec![])));
        assert_eq!(client.connection_binding(), Some(binding.clone()));
        clients.push(client);
    }
    binding.client = LinkRole::Original;
    let primary = join_session_addr(
        &cfg,
        &original,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&primary));
    clients.push(primary);
    assert_eq!(listener.peer_count(), 9);
    let extra = join_session_addr(
        &cfg,
        &original,
        addr,
        &listener.lan_token(),
        binding,
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&extra));
    assert_eq!(listener.peer_count(), 9);
    assert_eq!(listener.relays_connected(), (0, 0));
    let mut links = 0;
    while let Some(event) = listener.poll() {
        if let fray_net::HostEvent::PeerJoined { peer, pubkey, .. } = event {
            let i = players
                .iter()
                .position(|p| p.pubkey() == pubkey)
                .unwrap_or(8);
            assert_eq!(
                listener.tls_binding(peer).unwrap(),
                clients[i].tls_binding().unwrap()
            );
            links += 1;
        }
    }
    assert_eq!(links, 9);

    listener.shutdown();
    drop(clients);
}
#[test]
fn certified_successor_reuses_code_and_accepts_only_bound_existing_roster_while_closed() {
    use fray_net::{join_addr, join_session_addr, resume_host, Identity, NetConfig, RoomInfo};
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral().with_attestation("private successor persona".into());
    let player = Identity::ephemeral();
    let stranger = Identity::ephemeral();
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-resume-test").lan_only();
    cfg.lan_port = 0;
    cfg.withhold_host_attestation = Some(true);
    cfg.inbox_relays = vec!["wss://inbox.example".into()];
    let root = Root {
        session: fresh_session().unwrap(),
        app: cfg.app_tag.clone(),
        transport_version: 7,
        game_version: 5,
        checkpoint_version: 1,
        host: original.pubkey().to_bytes(),
        standby: standby.pubkey().to_bytes(),
        controller: original.pubkey().to_bytes(),
        code: room_code_hash("ABCDEF").unwrap(),
        created_day: 20741,
        roster_revision: 1,
        members: vec![Member {
            player: 1,
            seat: 0,
            key: Some(player.pubkey().to_bytes()),
        }],
        config: [11; 32],
        content: [12; 32],
        limits: ResourceLimits::default(),
    };
    let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let mut sequencer = Sequencer::arm(
        descriptor.root.context().unwrap(),
        vec![0],
        0,
        marks(0, 0),
        standby.keys(),
    )
    .unwrap();
    let promotion = sequencer.promote(standby.keys()).unwrap();
    let listener = resume_host(
        &cfg,
        &standby,
        RoomInfo {
            name: "Resumed".into(),
            max_players: 8,
        },
        "ABCDEF",
        descriptor.clone(),
        promotion,
    )
    .unwrap();
    let addr = wait_host_ready(&listener);
    assert_eq!(listener.code(), "ABCDEF");
    assert!(!listener.is_open());
    let ordinary = join_addr(&cfg, &player, addr, &listener.lan_token());
    assert!(!wait_connected(&ordinary));
    let binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 1,
        client: LinkRole::ResumePlayer,
        server: LinkRole::Successor,
    };
    let unknown = join_session_addr(
        &cfg,
        &stranger,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&unknown));
    let resumed = join_session_addr(
        &cfg,
        &player,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert_eq!(connected_metadata(&resumed), Some((None, vec![])));
    assert_eq!(resumed.connection_binding(), Some(binding));
    assert_eq!(listener.peer_count(), 1);
    listener.shutdown();
}
#[test]
fn real_quic_membership_updates_retire_old_links_and_admit_only_committed_replacements() {
    use fray_net::{host_standby, join_session_addr, Identity, NetConfig};
    let host = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let old = Identity::ephemeral();
    let new = Identity::ephemeral();
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-membership-test").lan_only();
    cfg.lan_port = 0;
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.host = host.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.app = cfg.app_tag.clone();
    root.members[0].key = Some(root.host);
    root.members[1].key = Some(old.pubkey().to_bytes());
    let mut descriptor = Descriptor::offer(root, host.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let root = &descriptor.root;
    let mut image =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut sequencer =
        Sequencer::arm_session(root.clone(), image.clone(), standby.keys()).unwrap();
    let initial = sequencer.membership_certificate(standby.keys()).unwrap();
    let listener = host_standby(&cfg, &standby, "ABCDEF", descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    listener.update_session_membership(initial.clone()).unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let dial = |who: &Identity| {
        join_session_addr(
            &cfg,
            who,
            addr,
            &listener.lan_token(),
            binding.clone(),
            standby.pubkey(),
        )
        .unwrap()
    };
    let connected = dial(&old);
    assert!(wait_connected(&connected));
    assert_eq!(listener.peer_count(), 1);
    let uncommitted = dial(&new);
    assert!(!wait_connected(&uncommitted));
    image.members.remove(1);
    image.inputs.remove(&2);
    image.membership_revision += 1;
    let mut marks = sequencer.receipt().watermarks.clone();
    marks[1].retired = true;
    let candidate = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let token = sequencer.stage(candidate).unwrap();
    sequencer.install(token, standby.keys()).unwrap();
    listener
        .update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
        .unwrap();
    assert_eq!(listener.peer_count(), 0);
    assert!(!wait_connected(&connected));
    let retired = dial(&old);
    assert!(!wait_connected(&retired));
    image.members.push(SessionMember {
        player: 4,
        seat: 1,
        key: Some(new.pubkey().to_bytes()),
        logical_peer: 13,
    });
    image.inputs.insert(4, HandledInputs::default());
    image.membership_revision += 1;
    image.next_player = 5;
    let mut marks = sequencer.receipt().watermarks.clone();
    marks.retain(|m| !m.retired);
    marks.push(Watermark {
        player: 4,
        input: 0,
        output_ack: 0,
        retired: false,
    });
    let candidate = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let token = sequencer.stage(candidate).unwrap();
    let staged_only = dial(&new);
    assert!(!wait_connected(&staged_only));
    sequencer.install(token, standby.keys()).unwrap();
    listener
        .update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
        .unwrap();
    let replacement = dial(&new);
    assert!(wait_connected(&replacement));
    assert!(listener.update_session_membership(initial).is_err());
    assert_eq!(listener.peer_count(), 1);
    listener.shutdown();
}
#[test]
fn actual_quic_activation_stream_hands_the_same_live_channels_to_replication() {
    use fray_net::{Bytes, ClientEvent, HostEvent, Identity, NetConfig};
    let host = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.host = host.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.members[0].key = Some(root.host);
    root.members[1].key = Some(player.pubkey().to_bytes());
    let mut descriptor = Descriptor::offer(root.clone(), host.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let mut cfg = NetConfig::new(std::env::temp_dir(), root.app.clone()).lan_only();
    cfg.lan_port = 0;
    let listener = fray_net::host_standby(&cfg, &standby, "ABCDEF", descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let client = fray_net::join_session_addr(
        &cfg,
        &host,
        addr,
        &listener.lan_token(),
        binding,
        standby.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&client));
    let started = std::time::Instant::now();
    let peer = loop {
        if let Some(HostEvent::PeerJoined { peer, pubkey, .. }) = listener.poll() {
            assert_eq!(pubkey, host.pubkey());
            break peer;
        }
        assert!(started.elapsed().as_secs() < 5);
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let sending = client.migration_channel(&policy).unwrap();
    let receiving = listener.migration_channel(peer).unwrap();
    assert_eq!(sending.tls(), receiving.tls());
    let image = SessionImage::initial(
        &root,
        &[(1, 10), (2, 11), (3, 12)],
        vec![0; 128 * 1024],
        1,
        100,
    )
    .unwrap();
    let mut source = ActivationSource::new(descriptor.clone(), image.clone(), sending, 0).unwrap();
    let mut sink = ActivationSink::new(descriptor.clone(), receiving, 0).unwrap();
    for (id, identity) in [(1, &host), (2, &player)] {
        source
            .acknowledge(
                CapabilityAck::sign(
                    &root,
                    id,
                    source.initial_hash().unwrap(),
                    1,
                    identity.keys(),
                )
                .unwrap(),
                0,
            )
            .unwrap();
    }
    let started = std::time::Instant::now();
    let mut ingress = ReceiveQueue::default();
    loop {
        let now = started.elapsed().as_millis() as u64;
        assert!(now < 5000);
        while let Some(wire) = source.poll_send(now).unwrap() {
            client.send_reliable(Bytes::from(wire));
        }
        while let Some(event) = listener.poll() {
            if let HostEvent::Reliable { peer: id, bytes } = event {
                assert_eq!(peer, id);
                ingress.enqueue(bytes.to_vec()).unwrap();
            }
        }
        while ingress
            .poll(|wire| sink.receive(wire, now))
            .unwrap()
            .is_some()
        {}
        if sink.ready() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let now = started.elapsed().as_millis() as u64;
    let (seq, _, mut server) = sink
        .arm(standby.keys(), now, |bytes| Ok(bytes.to_vec()))
        .unwrap();
    let mut accepted = false;
    while !accepted {
        let now = started.elapsed().as_millis() as u64;
        assert!(now < 5000);
        while let Some(wire) = server.poll_send(now).unwrap() {
            listener.send_reliable(peer, Bytes::from(wire));
        }
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                accepted |= source.receive(&bytes, now).unwrap();
            }
        }
        if !accepted {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    let now = started.elapsed().as_millis() as u64;
    let (primary, sending) = source.finish(now).unwrap();
    let mut original =
        PrimaryActor::new(descriptor.clone(), primary, sending, Activity::Idle, now).unwrap();
    let mut replica = StandbyActor::new(descriptor, seq, server, now).unwrap();
    let mut post = image;
    post.game[0] = 1;
    post.logical_ms += 16;
    original
        .prepare(
            post.clone(),
            original.primary().receipt().watermarks.clone(),
            vec![],
        )
        .unwrap();
    let mut committed = false;
    let mut delta_frames = 0;
    while !committed {
        let now = started.elapsed().as_millis() as u64;
        assert!(now < 5000);
        while let Some(wire) = original.poll_send(now).unwrap() {
            assert_eq!(Frame::decode(&wire).unwrap().kind, PacketKind::Delta);
            delta_frames += 1;
            client.send_reliable(Bytes::from(wire));
        }
        while let Some(event) = listener.poll() {
            if let HostEvent::Reliable { peer: id, bytes } = event {
                assert_eq!(id, peer);
                ingress.enqueue(bytes.to_vec()).unwrap();
            }
        }
        while ingress
            .poll(|wire| {
                replica.receive(
                    wire,
                    now,
                    standby.keys(),
                    Activity::Advancing,
                    |candidate, _, _| Ok(candidate.image.clone()),
                )
            })
            .unwrap()
            .is_some()
        {}
        while let Some(wire) = replica.poll_send(now).unwrap() {
            listener.send_reliable(peer, Bytes::from(wire));
        }
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                committed |= matches!(
                    original.receive(&bytes, now, host.keys()).unwrap(),
                    Some(PrimaryEvent::Committed { .. })
                );
            }
        }
        if !committed {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    assert_eq!(
        original.primary().committed_image(),
        post.encode(&root).unwrap()
    );
    assert_eq!(replica.image(), original.primary().committed_image());
    assert!(delta_frames > 0 && delta_frames < 8);
    assert_eq!(listener.code(), "ABCDEF");
    client.shutdown();
    listener.shutdown();
}
#[test]
fn actual_quic_player_input_output_and_ack_use_handshake_channels_and_committed_journals() {
    use fray_net::{Bytes, ClientEvent, HostEvent, Identity, NetConfig, RoomInfo};
    use std::time::{Duration, Instant};
    fn until(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(Instant::now() < deadline, "QUIC framed test timeout");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-player-wire-test").lan_only();
    cfg.lan_port = 0;
    cfg.host_has_player = false;
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let host = fray_net::host(
        &cfg,
        &original,
        RoomInfo {
            name: "Original test".into(),
            max_players: 8,
        },
    );
    until(|| matches!(host.poll(), Some(HostEvent::Ready { .. })));
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.app = cfg.app_tag.clone();
    root.host = original.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.code = room_code_hash(host.code()).unwrap();
    root.members = vec![Member {
        player: 1,
        seat: 0,
        key: Some(player.pubkey().to_bytes()),
    }];
    let mut descriptor = Descriptor::offer(root.clone(), original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let mut image = SessionImage::initial(&root, &[(1, 99)], vec![0], 1, 0).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), standby.keys()).unwrap();
    let mut primary = Primary::armed(
        root.context().unwrap(),
        image.encode(&root).unwrap(),
        seq.receipt().clone(),
    )
    .unwrap();
    let certificate = seq.membership_certificate(standby.keys()).unwrap();
    host.pin_session(descriptor.clone()).unwrap();
    host.update_session_membership(certificate.clone()).unwrap();
    let addr = std::net::SocketAddr::new(
        std::net::Ipv4Addr::LOCALHOST.into(),
        host.local_addr().unwrap().port(),
    );
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let mut client = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &host.lan_token(),
        binding.clone(),
        original.pubkey(),
    )
    .unwrap();
    let mut connected = false;
    let mut peer = None;
    until(|| {
        while let Some(event) = client.poll() {
            match event {
                ClientEvent::Connected { host_pubkey, .. } => {
                    assert_eq!(host_pubkey, original.pubkey());
                    connected = true;
                }
                ClientEvent::Progress { .. } => {}
                other => panic!("unexpected connection event {other:?}"),
            }
        }
        while let Some(event) = host.poll() {
            if let HostEvent::PeerJoined {
                peer: id, pubkey, ..
            } = event
            {
                assert_eq!(pubkey, player.pubkey());
                peer = Some(id);
            }
        }
        connected && peer.is_some()
    });
    let mut peer = peer.unwrap();
    let mut policy = EndpointPolicy {
        descriptor,
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let mut sending = client.migration_channel(&policy).unwrap();
    let mut receiving = host.migration_channel(peer).unwrap();
    assert!(client.migration_channel(&policy).is_err());
    assert!(host.migration_channel(peer).is_err());
    assert_eq!(sending.tls(), receiving.tls());
    assert_eq!(sending.local_key(), Some(player.pubkey().to_bytes()));
    assert_eq!(receiving.local_key(), Some(original.pubkey().to_bytes()));
    assert_eq!(receiving.remote_key(), player.pubkey().to_bytes());
    let mut queue = primary
        .attach_player(&receiving, certificate.clone())
        .unwrap();
    let mut intents = IntentJournal::default();
    let payload = vec![0xa5; 1024];
    assert_eq!(intents.append_batch(&[payload.clone()]).unwrap(), vec![1]);
    let record = PlayerControl::sign(
        &root,
        &certificate,
        0,
        1,
        1,
        sending.tls(),
        PlayerAction::Intent {
            number: 1,
            bytes: payload.clone(),
        },
        player.keys(),
    )
    .unwrap();
    sending
        .enqueue(PacketKind::Control, &record.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut input = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { peer: id, bytes } = event {
                assert_eq!(id, peer);
                if let Some((kind, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert_eq!(kind, PacketKind::Control);
                    input = queue.receive(&bytes, &primary).unwrap();
                }
            }
        }
        input
    });
    assert_eq!(
        queue.pending().collect::<Vec<_>>(),
        vec![(1, payload.as_slice())]
    );
    assert_eq!(intents.pending().count(), 1);
    assert_eq!(seq.receipt().index, 0);
    image
        .inputs
        .get_mut(&1)
        .unwrap()
        .record(1, &payload)
        .unwrap();
    image.game = vec![1];
    let marks = vec![Watermark {
        player: 1,
        input: 1,
        output_ack: 0,
        retired: false,
    }];
    let token = seq
        .stage(
            primary
                .prepare(
                    image.encode(&root).unwrap(),
                    0,
                    marks,
                    vec![Output {
                        recipient: 1,
                        delivery: Delivery::Reliable,
                        sequence: 1,
                        bytes: payload.clone(),
                    }],
                )
                .unwrap()
                .clone(),
        )
        .unwrap();
    assert!(seq.outbox().next().is_none());
    let receipt = seq.install(token, standby.keys()).unwrap();
    assert_eq!(queue.pending().count(), 1);
    assert_eq!(primary.outbox().count(), 0);
    primary.acknowledge(receipt).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(queue.pending().count(), 0);
    let committed = primary.outbox().next().unwrap().clone();
    assert_eq!(&committed, &seq.publication()[0]);
    let mut delivery = DeliveryJournal::default();
    let mut applications = 0;
    for _ in 0..2 {
        receiving
            .enqueue(
                PacketKind::Output,
                &committed.encode(&root.context().unwrap()).unwrap(),
            )
            .unwrap();
        while let Some(wire) = receiving.poll_send(0).unwrap() {
            host.send_reliable(peer, Bytes::from(wire));
        }
        let mut seen = false;
        until(|| {
            while let Some(event) = client.poll() {
                if let ClientEvent::Reliable(bytes) = event {
                    if let Some((kind, _, bytes)) = sending.receive(&bytes, 0).unwrap() {
                        assert_eq!(kind, PacketKind::Output);
                        let output =
                            CertifiedOutput::decode(&root.context().unwrap(), &bytes).unwrap();
                        delivery
                            .apply_certified(&root.context().unwrap(), 1, &output, |bytes| {
                                assert_eq!(bytes, payload);
                                applications += 1;
                                Ok(())
                            })
                            .unwrap();
                        seen = true;
                    }
                }
            }
            seen
        });
    }
    assert_eq!(applications, 1);
    assert_eq!(delivery.applied(), 1);
    intents
        .acknowledge(committed.receipt.watermarks[0].input)
        .unwrap();
    assert!(intents.pending().next().is_none());
    let current = seq.membership_certificate(standby.keys()).unwrap();
    host.update_session_membership(current.clone()).unwrap();
    queue.refresh(&primary).unwrap();
    let previous_tls = sending.tls();
    let previous_peer = peer;
    client.shutdown();
    until(
        || matches!(host.poll(), Some(HostEvent::PeerLeft { peer, .. }) if peer == previous_peer),
    );
    policy.membership = Some(current.clone());
    client = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &host.lan_token(),
        binding,
        original.pubkey(),
    )
    .unwrap();
    connected = false;
    let mut next_peer = None;
    until(|| {
        while let Some(event) = client.poll() {
            match event {
                ClientEvent::Connected { host_pubkey, .. } => {
                    assert_eq!(host_pubkey, original.pubkey());
                    connected = true;
                }
                ClientEvent::Progress { .. } => {}
                other => panic!("unexpected reconnect event {other:?}"),
            }
        }
        while let Some(event) = host.poll() {
            if let HostEvent::PeerJoined { peer, pubkey, .. } = event {
                assert_eq!(pubkey, player.pubkey());
                next_peer = Some(peer);
            }
        }
        connected && next_peer.is_some()
    });
    peer = next_peer.unwrap();
    assert_ne!(peer, previous_peer);
    sending = client.migration_channel(&policy).unwrap();
    receiving = host.migration_channel(peer).unwrap();
    assert_ne!(sending.tls(), previous_tls);
    assert_eq!(sending.tls(), receiving.tls());
    let request = queue
        .begin_reconnect(&receiving, current.clone(), &primary, 0, original.keys())
        .unwrap();
    receiving
        .enqueue(PacketKind::Control, &request.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = receiving.poll_send(0).unwrap() {
        host.send_reliable(peer, Bytes::from(wire));
    }
    let mut challenge_seen = false;
    until(|| {
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                if let Some((kind, _, bytes)) = sending.receive(&bytes, 0).unwrap() {
                    assert_eq!(kind, PacketKind::Control);
                    let request = ReconnectChallenge::decode(&root, &bytes).unwrap();
                    let proof = PlayerControl::resume_connection(
                        &root,
                        &request,
                        sending.tls(),
                        &delivery,
                        &intents,
                        2,
                        player.keys(),
                    )
                    .unwrap();
                    sending
                        .enqueue(PacketKind::Control, &proof.encode(&root).unwrap())
                        .unwrap();
                    challenge_seen = true;
                }
            }
        }
        challenge_seen
    });
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut resumed = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { bytes, .. } = event {
                if let Some((kind, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert_eq!(kind, PacketKind::Control);
                    queue.finish_reconnect(&bytes, &primary, 0).unwrap();
                    resumed = true;
                }
            }
        }
        resumed
    });
    // A delayed original is re-signed under the fresh TLS exporter, keeping its
    // old game ID and bytes. The already committed action cannot run again.
    let replay = PlayerControl::sign(
        &root,
        &current,
        0,
        3,
        1,
        sending.tls(),
        PlayerAction::Intent {
            number: 1,
            bytes: payload.clone(),
        },
        player.keys(),
    )
    .unwrap();
    sending
        .enqueue(PacketKind::Control, &replay.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut replayed = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { bytes, .. } = event {
                if let Some((_, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert!(!queue.receive(&bytes, &primary).unwrap());
                    replayed = true;
                }
            }
        }
        replayed
    });
    assert_eq!(queue.pending().count(), 0);
    // Replay the exact proof from the retained primary log on the new socket.
    receiving
        .enqueue(
            PacketKind::Output,
            &primary
                .outbox()
                .next()
                .unwrap()
                .encode(&root.context().unwrap())
                .unwrap(),
        )
        .unwrap();
    while let Some(wire) = receiving.poll_send(0).unwrap() {
        host.send_reliable(peer, Bytes::from(wire));
    }
    replayed = false;
    until(|| {
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                if let Some((_, _, bytes)) = sending.receive(&bytes, 0).unwrap() {
                    let output = CertifiedOutput::decode(&root.context().unwrap(), &bytes).unwrap();
                    assert_eq!(output, committed);
                    assert!(!delivery
                        .apply_certified(&root.context().unwrap(), 1, &output, |_| {
                            applications += 1;
                            Ok(())
                        })
                        .unwrap());
                    replayed = true;
                }
            }
        }
        replayed
    });
    assert_eq!(applications, 1);
    let ack = PlayerControl::sign(
        &root,
        &current,
        0,
        4,
        1,
        sending.tls(),
        PlayerAction::Applied {
            output: delivery.applied(),
            tail: intents.tail(),
            cut: None,
        },
        player.keys(),
    )
    .unwrap();
    sending
        .enqueue(PacketKind::Control, &ack.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut applied = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { bytes, .. } = event {
                if let Some((_, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert!(!queue.receive(&bytes, &primary).unwrap());
                    applied = true;
                }
            }
        }
        applied
    });
    assert_eq!(queue.output_ack(), 1);
    assert_eq!(primary.outbox().count(), 1);
    assert_eq!(
        seq.outbox().count(),
        1,
        "network receipt cannot prune committed outbox"
    );
    let mut marks = seq.receipt().watermarks.clone();
    marks[0].output_ack = queue.output_ack();
    let token = seq
        .stage(
            primary
                .prepare(image.encode(&root).unwrap(), 0, marks, vec![])
                .unwrap()
                .clone(),
        )
        .unwrap();
    let receipt = seq.install(token, standby.keys()).unwrap();
    assert_eq!(primary.outbox().count(), 1);
    primary.acknowledge(receipt).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(primary.outbox().count(), 0);
    assert_eq!(seq.outbox().count(), 0);
    client.shutdown();
    host.shutdown();
}

#[test]
fn actual_quic_retained_recovery_resumes_over_the_prepared_warm_connection() {
    use fray_net::{Bytes, ClientEvent, HostEvent, Identity, NetConfig, RoomInfo};
    use std::time::{Duration, Instant};

    fn peer(host: &fray_net::HostHandle, key: [u8; 32]) -> fray_net::PeerId {
        let started = Instant::now();
        loop {
            while let Some(event) = host.poll() {
                if let HostEvent::PeerJoined { peer, pubkey, .. } = event {
                    assert_eq!(pubkey.to_bytes(), key);
                    return peer;
                }
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // This drives actual TLS-bound handles, framing, ingress backpressure and
    // real monotonic clocks. Native game/process-kill acceptance is separate.
    struct Wire {
        listener: fray_net::HostHandle,
        link: fray_net::ClientHandle,
        peer: fray_net::PeerId,
        server_ingress: ReceiveQueue,
        client_ingress: ReceiveQueue,
        started: Instant,
        client_transfer: u64,
    }
    impl Wire {
        fn now(&self) -> u64 {
            self.started.elapsed().as_millis() as u64
        }
        fn exchange(
            &mut self,
            server: &mut Channel,
            client: &mut PlayerRecovery,
            controls: usize,
            resume: bool,
        ) -> Vec<Vec<u8>> {
            let mut records = Vec::new();
            let mut resumed = false;
            loop {
                let now = self.now();
                assert!(now < 5000, "actual QUIC recovery deadline");
                while let Some(wire) = server.poll_send(now).unwrap() {
                    self.listener.send_reliable(self.peer, Bytes::from(wire));
                }
                while let Some(event) = self.link.poll() {
                    match event {
                        ClientEvent::Reliable(bytes) => {
                            self.client_ingress.enqueue(bytes.to_vec()).unwrap()
                        }
                        ClientEvent::Progress { .. } => {}
                        other => panic!("unexpected warm client event {other:?}"),
                    }
                }
                while let Some(event) = self
                    .client_ingress
                    .poll(|wire| {
                        client.receive(wire, now, |_, _, _| {
                            panic!("no game outputs in this fixture")
                        })
                    })
                    .unwrap()
                {
                    match event {
                        Some(RecoveryPlayerEvent::ClockCut { logical_ms }) => {
                            assert_eq!(logical_ms, 100);
                            client
                                .confirm_clock(0, now, |logical, delta| {
                                    assert_eq!((logical, delta), (100, 0));
                                    Ok(())
                                })
                                .unwrap();
                        }
                        Some(RecoveryPlayerEvent::Resumed) => resumed = true,
                        None => {}
                        other => panic!("unexpected recovery event {other:?}"),
                    }
                }
                while let Some(wire) = client.poll_send(now).unwrap() {
                    let frame = Frame::decode(&wire).unwrap();
                    if frame.ordinal == 0 {
                        assert!(
                            frame.transfer > self.client_transfer,
                            "recovery framing reset"
                        );
                        self.client_transfer = frame.transfer;
                    }
                    self.link.send_reliable(Bytes::from(wire));
                }
                while let Some(event) = self.listener.poll() {
                    match event {
                        HostEvent::Reliable { peer, bytes } => {
                            assert_eq!(peer, self.peer);
                            self.server_ingress.enqueue(bytes.to_vec()).unwrap();
                        }
                        other => panic!("unexpected warm server event {other:?}"),
                    }
                }
                while let Some(record) = self
                    .server_ingress
                    .poll(|wire| server.receive(wire, now))
                    .unwrap()
                {
                    if let Some((kind, _, bytes)) = record {
                        assert_eq!(kind, PacketKind::Control);
                        records.push(bytes);
                    }
                }
                if records.len() >= controls && resumed == resume {
                    assert_eq!(records.len(), controls);
                    return records;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    let mut cfg =
        NetConfig::new(std::env::temp_dir(), "migration-retained-recovery-test").lan_only();
    cfg.lan_port = 0;
    cfg.host_has_player = false;
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let host = fray_net::host(
        &cfg,
        &original,
        RoomInfo {
            name: "Original".into(),
            max_players: 8,
        },
    );
    let addr = wait_host_ready(&host);
    let code = host.code().to_owned();
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.session = fresh_session().unwrap();
    root.app = cfg.app_tag.clone();
    root.host = original.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.code = room_code_hash(host.code()).unwrap();
    root.members = vec![Member {
        player: 1,
        seat: 0,
        key: Some(player.pubkey().to_bytes()),
    }];
    let mut descriptor = Descriptor::offer(root.clone(), original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let image = SessionImage::initial(&root, &[(1, 99)], vec![0], 1, 100).unwrap();
    let capability = CapabilityAck::sign(
        &root,
        1,
        state_hash(&image.encode(&root).unwrap()).unwrap(),
        1,
        player.keys(),
    )
    .unwrap();
    let mut activation = Activation::new_session(descriptor.clone(), image).unwrap();
    activation.acknowledge(capability.clone()).unwrap();
    let (seq, armed) = activation
        .arm(standby.keys(), |bytes| Ok(bytes.to_vec()))
        .unwrap();
    let certificate = seq.membership_certificate(standby.keys()).unwrap();
    host.pin_session(descriptor.clone()).unwrap();
    host.update_session_membership(certificate.clone()).unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let normal = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &host.lan_token(),
        binding,
        original.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&normal));
    let normal_peer = peer(&host, player.pubkey().to_bytes());
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let channel = normal.migration_channel(&policy).unwrap();
    assert_eq!(
        channel.tls(),
        host.migration_channel(normal_peer).unwrap().tls()
    );
    let mut endpoint = PlayerEndpoint::new(
        descriptor.clone(),
        &armed,
        &capability,
        certificate.clone(),
        channel,
        player.keys().clone(),
    )
    .unwrap();
    let originals = (0..70).map(|n| vec![n as u8; 1024]).collect::<Vec<_>>();
    endpoint
        .intents_mut()
        .unwrap()
        .append_batch(&originals)
        .unwrap();

    let listener = fray_net::host_standby(&cfg, &standby, host.code(), descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    listener
        .update_session_membership(certificate.clone())
        .unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let link = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &listener.lan_token(),
        binding,
        standby.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&link));
    let warm_peer = peer(&listener, player.pubkey().to_bytes());
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: Some(certificate),
    };
    let mut warm = link.migration_channel(&policy).unwrap();
    let mut server = listener.migration_channel(warm_peer).unwrap();
    let tls = server.tls();
    assert_eq!(warm.tls(), tls);
    // Consume a real warm frame before takeover; neither framing nor TLS may
    // restart when the retained endpoint later moves into recovery.
    let probe = PulseProbe {
        term: 0,
        sequence: endpoint.sequence().allocate().unwrap(),
        nonce: [9; 32],
        tls,
    };
    warm.enqueue(PacketKind::Control, &probe.encode(&root).unwrap())
        .unwrap();
    let mut warm_transfer = 0;
    while let Some(wire) = warm.poll_send(0).unwrap() {
        warm_transfer = Frame::decode(&wire).unwrap().transfer;
        link.send_reliable(Bytes::from(wire));
    }
    assert!(warm_transfer > 0);
    let wait = Instant::now();
    let mut seen = false;
    while !seen {
        while let Some(event) = listener.poll() {
            if let HostEvent::Reliable { peer, bytes } = event {
                assert_eq!(peer, warm_peer);
                seen |= server.receive(&bytes, 0).unwrap().is_some();
            }
        }
        assert!(wait.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    normal.shutdown();
    host.shutdown();
    let started = Instant::now();
    let mut recovery = Recovery::begin_session(descriptor, seq, standby.keys(), 0).unwrap();
    let promotion = recovery.promotion().clone();
    server.promote(&promotion).unwrap();
    let mut client = endpoint.into_recovery(warm, promotion.clone(), 0).unwrap();
    let mut wire = Wire {
        listener,
        link,
        peer: warm_peer,
        server_ingress: ReceiveQueue::default(),
        client_ingress: ReceiveQueue::default(),
        started,
        client_transfer: warm_transfer,
    };
    let challenge = recovery
        .challenge(
            1,
            tls,
            1,
            player.pubkey().to_bytes(),
            standby.keys(),
            wire.now(),
        )
        .unwrap();
    server
        .enqueue(PacketKind::Control, &challenge.encode(&root).unwrap())
        .unwrap();
    let replies = wire.exchange(&mut server, &mut client, 1, false);
    recovery
        .accept(
            1,
            tls,
            &ResumeProof::decode(&root, &replies[0]).unwrap(),
            wire.now(),
        )
        .unwrap();
    assert!(recovery.seal(wire.now()).unwrap());
    recovery
        .revalidate_security(standby.keys(), wire.now(), |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    assert!(recovery.replay().unwrap().is_empty());
    for round in 0..2 {
        recovery.begin_round().unwrap();
        let request = recovery
            .issue_input_round(1, tls, standby.keys(), wire.now())
            .unwrap();
        server
            .enqueue(
                PacketKind::Control,
                &request.encode(&root, &promotion).unwrap(),
            )
            .unwrap();
        let replies = wire.exchange(
            &mut server,
            &mut client,
            if round == 0 { originals.len() + 1 } else { 1 },
            false,
        );
        for reply in replies {
            recovery
                .accept_player_control(
                    &PlayerControl::decode(&root, &reply).unwrap(),
                    tls,
                    wire.now(),
                )
                .unwrap();
        }
        if round == 0 {
            for (index, original) in originals.iter().enumerate() {
                let (_, number, bytes) = recovery.next_input().unwrap().unwrap();
                assert_eq!(number, index as u64 + 1);
                assert_eq!(bytes, original);
                let before = recovery.sequencer().image().to_vec();
                recovery
                    .apply_next(standby.keys(), |_, _, _, histories| {
                        let mut image = SessionImage::decode(&root, &before)?;
                        image.inputs = histories.clone();
                        image.game.push(number as u8);
                        Ok((image.encode(&root)?, vec![]))
                    })
                    .unwrap();
            }
            assert!(recovery.next_input().unwrap().is_none());
        } else {
            recovery
                .commit_departures(standby.keys(), |_, _, _| panic!("empty departure callback"))
                .unwrap();
        }
    }
    let mut barrier = RecoveryBarrier::new(recovery, standby.keys(), wire.now()).unwrap();
    let cut = barrier.issue(1, tls, standby.keys(), wire.now()).unwrap();
    server
        .enqueue(PacketKind::Control, &cut.encode(&root, &promotion).unwrap())
        .unwrap();
    let replies = wire.exchange(&mut server, &mut client, 1, false);
    let ready = RecoveryReady::decode(&root, &promotion, &cut, &replies[0]).unwrap();
    barrier.accept(&ready, tls, wire.now()).unwrap();
    let mut inbox = Some(PlayerInbox::new(&server, cut.membership.clone()).unwrap());
    let (mut successor, _, resume) = barrier.finish(standby.keys(), wire.now()).unwrap();
    let final_image = SessionImage::decode(&root, successor.primary().committed_image()).unwrap();
    assert_eq!(final_image.logical_ms, 100);
    assert_eq!(final_image.inputs[&1].handled(), 70);
    assert_eq!(final_image.game, (0..=70).collect::<Vec<u8>>());
    server
        .enqueue(
            PacketKind::Control,
            &resume.encode(&root, &promotion).unwrap(),
        )
        .unwrap();
    assert!(wire.exchange(&mut server, &mut client, 0, true).is_empty());
    let mut endpoint = client.into_endpoint().unwrap();
    assert_eq!(
        (
            endpoint.journals().1.tail(),
            endpoint.journals().1.acknowledged()
        ),
        (70, 70)
    );
    let mut queue = successor
        .attach_warm_player(&server, &mut inbox, standby.keys())
        .unwrap();
    assert_eq!(
        endpoint
            .intents_mut()
            .unwrap()
            .append_batch(&[vec![33]])
            .unwrap(),
        vec![71]
    );
    endpoint.queue_pending(MAX_BATCH).unwrap();
    let before_resume_input = wire.client_transfer;
    let wait = Instant::now();
    while queue.pending().next().is_none() {
        let now = wire.now();
        while let Some(bytes) = endpoint.poll_send(now).unwrap() {
            let frame = Frame::decode(&bytes).unwrap();
            if frame.ordinal == 0 {
                assert!(
                    frame.transfer > wire.client_transfer,
                    "resumed framing reset"
                );
                wire.client_transfer = frame.transfer;
            }
            wire.link.send_reliable(Bytes::from(bytes));
        }
        while let Some(event) = wire.listener.poll() {
            if let HostEvent::Reliable { peer, bytes } = event {
                assert_eq!(peer, warm_peer);
                wire.server_ingress.enqueue(bytes.to_vec()).unwrap();
            }
        }
        while let Some(record) = wire
            .server_ingress
            .poll(|bytes| server.receive(bytes, now))
            .unwrap()
        {
            if let Some((_, _, bytes)) = record {
                queue.receive(&bytes, successor.primary()).unwrap();
            }
        }
        assert!(wait.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(71, &[33][..])]);
    assert!(wire.client_transfer > before_resume_input);
    assert_eq!(wire.listener.code(), code);
    assert_eq!(wire.listener.tls_binding(warm_peer).unwrap(), tls);
    wire.link.shutdown();
    wire.listener.shutdown();
}
