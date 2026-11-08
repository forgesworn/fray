//! A host and a client in one process, talking over real QUIC on loopback.
//!
//! The setup follows the transport's own tests: start a host, wait for it to
//! be ready, then join its loopback address with its LAN token. The beacon is
//! off and nothing needs the internet. Each test uses its own temporary
//! data directories.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fray_net::{
    ClientEvent, DisconnectReason, FailReason, Identity, LeaveReason, NetConfig, RoomInfo,
};
use fray_starter::wire::PlayerState;
use fray_starter::{ClientNote, ClientSession, HostNote, HostSession, APP_TAG, HELLO_TIMEOUT};

const WAIT: Duration = Duration::from_secs(15);

/// A directory under the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fray-starter-{label}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create a temporary directory");
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(dir: &TempDir) -> NetConfig {
    let mut config = NetConfig::new(dir.path(), APP_TAG).lan_only();
    config.lan_beacon = false; // peers are joined by address here
    config
}

fn room(max_players: u8) -> RoomInfo {
    RoomInfo {
        name: "Test room".into(),
        max_players,
    }
}

/// A host session, started and ready, plus where to dial it.
struct Hosted {
    session: HostSession,
    addr: SocketAddr,
    token: String,
    notes: Vec<HostNote>,
    _dir: TempDir,
}

fn start_host(label: &str, edit: impl FnOnce(&mut NetConfig), max_players: u8) -> Hosted {
    start_host_with(label, edit, max_players, HELLO_TIMEOUT)
}

fn start_host_with(
    label: &str,
    edit: impl FnOnce(&mut NetConfig),
    max_players: u8,
    hello_timeout: Duration,
) -> Hosted {
    let dir = TempDir::new(label);
    let mut config = config(&dir);
    edit(&mut config);
    let identity = Identity::load_or_create(dir.path()).expect("identity");
    let mut session = HostSession::new(fray_net::host(&config, &identity, room(max_players)))
        .with_hello_timeout(hello_timeout);
    let mut notes = Vec::new();
    wait(WAIT, "host ready", || {
        notes.extend(session.poll(Instant::now()));
        notes.iter().any(|n| matches!(n, HostNote::Ready { .. }))
    });
    let port = session.handle().local_addr().expect("listening").port();
    let token = session.handle().lan_token();
    Hosted {
        session,
        addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        token,
        notes,
        _dir: dir,
    }
}

fn wait(limit: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("{what} not seen within {limit:?}");
}

/// A client session joined to `host`, plus the notes it has produced.
struct Joined {
    session: ClientSession,
    notes: Vec<ClientNote>,
    _dir: TempDir,
}

fn join(host: &Hosted, name: &str) -> Joined {
    let dir = TempDir::new("client");
    let identity = Identity::load_or_create(dir.path()).expect("identity");
    let handle = fray_net::join_addr(&config(&dir), &identity, host.addr, &host.token);
    Joined {
        session: ClientSession::new(handle, name),
        notes: Vec::new(),
        _dir: dir,
    }
}

/// Poll both sides each turn until `done` is satisfied.
fn pump(
    what: &str,
    host: &mut Hosted,
    clients: &mut [&mut Joined],
    mut done: impl FnMut(&mut Hosted, &mut [&mut Joined]) -> bool,
) {
    let deadline = Instant::now() + WAIT;
    loop {
        host.notes.extend(host.session.poll(Instant::now()));
        for c in clients.iter_mut() {
            let notes = c.session.poll();
            c.notes.extend(notes);
        }
        if done(host, clients) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what} not seen within {WAIT:?}; host saw {:?}; clients saw {:?}",
            host.notes,
            clients.iter().map(|c| &c.notes).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn welcomed(c: &Joined) -> bool {
    c.notes
        .iter()
        .any(|n| matches!(n, ClientNote::Welcome { .. }))
}

/// A host and one welcomed client.
fn connected(label: &str) -> (Hosted, Joined) {
    let mut host = start_host(label, |_| {}, 4);
    let mut client = join(&host, "Ada");
    pump("welcome", &mut host, &mut [&mut client], |_, c| {
        welcomed(c[0])
    });
    (host, client)
}

#[test]
fn a_client_joins_says_hello_and_is_welcomed() {
    let (host, client) = connected("join");
    assert!(client.notes.contains(&ClientNote::Connected {
        host_name: "Test room".into()
    }));
    assert!(client.notes.contains(&ClientNote::Welcome { player: 1 }));
    assert_eq!(client.session.player(), Some(1));
    assert!(host.notes.contains(&HostNote::PlayerJoined {
        player: 1,
        name: "Ada".into()
    }));
    let players = host.session.players();
    assert_eq!(players.len(), 1);
    assert_eq!(players[0].name, "Ada");
}

#[test]
fn players_are_numbered_from_one_and_numbers_are_reused() {
    let mut host = start_host("numbers", |_| {}, 4);
    let mut a = join(&host, "Ada");
    pump("first welcome", &mut host, &mut [&mut a], |_, c| {
        welcomed(c[0])
    });
    let mut b = join(&host, "Bo");
    pump(
        "second welcome",
        &mut host,
        &mut [&mut a, &mut b],
        |_, c| welcomed(c[1]),
    );
    assert_eq!(a.session.player(), Some(1));
    assert_eq!(b.session.player(), Some(2));

    a.session.shutdown();
    pump("player 1 leaves", &mut host, &mut [&mut b], |h, _| {
        h.session.players().len() == 1
    });
    let mut c = join(&host, "Cy");
    pump("third welcome", &mut host, &mut [&mut b, &mut c], |_, c| {
        welcomed(c[1])
    });
    assert_eq!(c.session.player(), Some(1), "the free number is reused");
}

#[test]
fn datagrams_carry_positions_both_ways() {
    let (mut host, mut client) = connected("datagrams");
    host.session.set_host_position(7, 8);
    // Datagrams can be lost, so keep sending until one gets through each way.
    let mut last_send = Instant::now() - Duration::from_secs(1);
    let mut heard_state = None;
    pump(
        "a position and a state",
        &mut host,
        &mut [&mut client],
        |h, c| {
            if last_send.elapsed() >= Duration::from_millis(20) {
                c[0].session.send_position(100, -5);
                h.session.broadcast_state();
                last_send = Instant::now();
            }
            heard_state = c[0].notes.iter().find_map(|n| match n {
                ClientNote::State { players, .. } => Some(players.clone()),
                _ => None,
            });
            let host_has_position = h.session.players().iter().any(|p| (p.x, p.y) == (100, -5));
            host_has_position && heard_state.is_some()
        },
    );
    let players = heard_state.expect("a state arrived");
    assert!(players.contains(&PlayerState {
        player: 0,
        x: 7,
        y: 8
    }));
    assert_eq!(players.iter().filter(|p| p.player == 1).count(), 1);
}

#[test]
fn a_dedicated_host_gives_every_seat_to_remote_players() {
    // Two seats. With the default (the host holds one) a second client would
    // be refused, as in the full-room test; a dedicated host seats both.
    let mut host = start_host("dedicated", |c| c.host_has_player = false, 2);
    let mut a = join(&host, "Ada");
    let mut b = join(&host, "Bo");
    pump("both welcomed", &mut host, &mut [&mut a, &mut b], |_, c| {
        welcomed(c[0]) && welcomed(c[1])
    });
    let mut numbers = vec![a.session.player(), b.session.player()];
    numbers.sort();
    assert_eq!(numbers, vec![Some(1), Some(2)]);
    assert_eq!(host.session.handle().peer_count(), 2);

    let mut last_send = Instant::now() - Duration::from_secs(1);
    pump("a state", &mut host, &mut [&mut a, &mut b], |h, c| {
        if last_send.elapsed() >= Duration::from_millis(20) {
            h.session.broadcast_state();
            last_send = Instant::now();
        }
        c[0].notes
            .iter()
            .any(|n| matches!(n, ClientNote::State { .. }))
    });
    for note in &a.notes {
        if let ClientNote::State { players, .. } = note {
            assert!(players.iter().all(|p| p.player != 0), "{players:?}");
        }
    }
}

#[test]
fn the_host_sees_a_client_leave() {
    let (mut host, client) = connected("leave");
    client.session.shutdown();
    pump("player left", &mut host, &mut [], |h, _| {
        h.notes
            .iter()
            .any(|n| matches!(n, HostNote::PlayerLeft { .. }))
    });
    assert!(host.notes.contains(&HostNote::PlayerLeft {
        player: 1,
        name: "Ada".into(),
        reason: LeaveReason::Left,
    }));
    assert!(host.session.players().is_empty());
}

#[test]
fn the_client_sees_the_host_shut_down() {
    let (host, mut client) = connected("host-gone");
    host.session.shutdown();
    let deadline = Instant::now() + WAIT;
    while !client.session.is_finished() {
        client.notes.extend(client.session.poll());
        assert!(
            Instant::now() < deadline,
            "no host-gone note: {:?}",
            client.notes
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let gone: Vec<_> = client
        .notes
        .iter()
        .filter(|n| matches!(n, ClientNote::HostGone(_)))
        .collect();
    assert_eq!(
        gone,
        vec![&ClientNote::HostGone("The host has gone.".into())]
    );
    assert_eq!(client.session.player(), None);
    assert!(
        !client.session.send_position(1, 1),
        "nothing is sent once finished"
    );
}

#[test]
fn a_full_room_is_refused_by_fray_and_reported_to_the_player() {
    let mut host = start_host("full", |_| {}, 2); // the host's seat plus one
    let mut first = join(&host, "Ada");
    pump("welcome", &mut host, &mut [&mut first], |_, c| {
        welcomed(c[0])
    });
    let mut late = join(&host, "Bo");
    pump(
        "a failed join",
        &mut host,
        &mut [&mut first, &mut late],
        |_, c| {
            c[1].notes
                .iter()
                .any(|n| matches!(n, ClientNote::JoinFailed(_)))
        },
    );
    assert!(late.session.is_finished());
    let text = late
        .notes
        .iter()
        .find_map(|n| match n {
            ClientNote::JoinFailed(t) => Some(t.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        text,
        format!(
            "Could not join (while the handshake): {}",
            FailReason::RoomFull
        )
    );
}

/// Join with a bare Fray client (no hello) and report its first
/// disconnection, while the host session keeps polling.
fn raw_client_until_disconnect(
    host: &mut Hosted,
    send_first: Option<fray_net::Bytes>,
) -> DisconnectReason {
    let dir = TempDir::new("raw");
    let identity = Identity::load_or_create(dir.path()).expect("identity");
    let client = fray_net::join_addr(&config(&dir), &identity, host.addr, &host.token);
    let deadline = Instant::now() + WAIT;
    let mut sent = false;
    loop {
        host.notes.extend(host.session.poll(Instant::now()));
        while let Some(ev) = client.poll() {
            match ev {
                ClientEvent::Connected { .. } if !sent => {
                    sent = true;
                    if let Some(bytes) = send_first.clone() {
                        client.send_reliable(bytes);
                    }
                }
                ClientEvent::Disconnected { reason } => return reason,
                ClientEvent::Failed { stage, reason } => {
                    panic!("raw join failed at {stage:?}: {reason}")
                }
                _ => {}
            }
        }
        assert!(
            Instant::now() < deadline,
            "no disconnect; host saw {:?}",
            host.notes
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_bad_hello_is_refused_with_a_reason() {
    let mut host = start_host("bad-hello", |_| {}, 4);
    // A hello for a protocol version this game does not speak.
    let reason = raw_client_until_disconnect(
        &mut host,
        Some(fray_net::Bytes::from_static(&[0x01, 99, 1, b'x'])),
    );
    assert_eq!(
        reason,
        DisconnectReason::KickedWith("Bad hello: protocol version 99, this game speaks 1.".into())
    );
    assert!(host
        .notes
        .iter()
        .any(|n| matches!(n, HostNote::Refused { .. })));
    assert!(host.session.players().is_empty());
}

#[test]
fn a_peer_that_never_says_hello_is_dropped() {
    let mut host = start_host_with("silent", |_| {}, 4, Duration::from_millis(300));
    let reason = raw_client_until_disconnect(&mut host, None);
    assert_eq!(
        reason,
        DisconnectReason::KickedWith("No hello received.".into())
    );
}

#[test]
fn a_peer_written_from_the_byte_table_is_welcomed() {
    // No `ClientSession` here: the hello is the literal bytes from the table
    // in `wire`, so a peer in another language needs nothing else.
    let mut host = start_host("bytes", |_| {}, 4);
    let dir = TempDir::new("bytes-client");
    let identity = Identity::load_or_create(dir.path()).expect("identity");
    let client = fray_net::join_addr(&config(&dir), &identity, host.addr, &host.token);
    let deadline = Instant::now() + WAIT;
    let mut welcome = None;
    while welcome.is_none() {
        host.notes.extend(host.session.poll(Instant::now()));
        while let Some(ev) = client.poll() {
            match ev {
                ClientEvent::Connected { .. } => {
                    client.send_reliable(fray_net::Bytes::from_static(&[0x01, 1, 2, b'A', b'l']))
                }
                ClientEvent::Reliable(bytes) => welcome = Some(bytes),
                _ => {}
            }
        }
        assert!(
            Instant::now() < deadline,
            "no welcome; host saw {:?}",
            host.notes
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(&welcome.unwrap()[..], &[0x02, 1]);
}
