//! Command line for the starter game: `host` and `join`.
//!
//! LAN only by default. `--code` switches to room codes over public Nostr
//! relays, which see the lookup (not the game messages).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fray_net::{ClientHandle, Identity, LanRoom, NetConfig, RoomInfo};
use fray_starter::{ClientNote, ClientSession, HostNote, HostSession, APP_TAG};

const USAGE: &str = "\
fray-starter: a tiny game that shows how to use Fray.

USAGE
  fray-starter host [OPTIONS]
  fray-starter join [OPTIONS]

COMMON OPTIONS
  --name NAME        Your player name, or the room name for a host (default: player)
  --data-dir DIR     Keep a persistent identity key in DIR (default: a new identity each run)
  --lan-port PORT    UDP port of the LAN beacon (default: Fray's default)
  --seconds N        Stop after N seconds (default: run until the other side goes)
  --code             Use room codes over PUBLIC Nostr relays instead of LAN only.
                     The relays you reach can see that a lookup happened and your
                     IP address, and so can the STUN servers asked for your public
                     address; they do not see game messages.

HOST OPTIONS
  --max-players N    Seats (2 to 8, default 4); the host's own seat counts unless --dedicated
  --dedicated        The host has no player of its own (all seats are for remote players)
  --until-empty      Stop once a player has joined and then everyone has left

JOIN OPTIONS
  --addr HOST:PORT   Join a host directly, with --token (skips LAN discovery)
  --token HEX        The LAN token the host printed
  --room-code CODE   With --code: the room code the host printed
  --find-seconds N   How long to look for a room on the LAN (default 10)
";

#[derive(Default)]
struct Options {
    name: Option<String>,
    data_dir: Option<PathBuf>,
    lan_port: Option<u16>,
    seconds: Option<u64>,
    public_relays: bool,
    max_players: Option<u8>,
    dedicated: bool,
    until_empty: bool,
    addr: Option<String>,
    token: Option<String>,
    room_code: Option<String>,
    find_seconds: Option<u64>,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options::default();
    while let Some(flag) = args.next() {
        let mut value = |what: &str| args.next().ok_or(format!("{flag} needs {what}"));
        match flag.as_str() {
            "--name" => o.name = Some(value("a name")?),
            "--data-dir" => o.data_dir = Some(PathBuf::from(value("a directory")?)),
            "--lan-port" => o.lan_port = Some(number(&flag, &value("a port")?)?),
            "--seconds" => o.seconds = Some(number(&flag, &value("a number")?)?),
            "--code" => o.public_relays = true,
            "--max-players" => o.max_players = Some(number(&flag, &value("a number")?)?),
            "--dedicated" => o.dedicated = true,
            "--until-empty" => o.until_empty = true,
            "--addr" => o.addr = Some(value("HOST:PORT")?),
            "--token" => o.token = Some(value("the token")?),
            "--room-code" => o.room_code = Some(value("the code")?),
            "--find-seconds" => o.find_seconds = Some(number(&flag, &value("a number")?)?),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(o)
}

fn number<T: std::str::FromStr>(flag: &str, text: &str) -> Result<T, String> {
    text.parse()
        .map_err(|_| format!("{flag}: '{text}' is not a valid number"))
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    let options = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match command.as_deref() {
        Some("host") => run_host(&options),
        Some("join") => run_join(&options),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// The config and identity both commands need.
fn setup(o: &Options) -> Result<(NetConfig, Identity), String> {
    let data_dir = o
        .data_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(APP_TAG));
    let mut config = NetConfig::new(data_dir, APP_TAG);
    if !o.public_relays {
        config = config.lan_only();
    }
    if let Some(port) = o.lan_port {
        config.lan_port = port;
    }
    // With a data directory the identity key is kept between runs; without
    // one, every run is a new, throwaway identity and nothing is written.
    let identity = match &o.data_dir {
        Some(dir) => Identity::load_or_create(dir)?,
        None => Identity::ephemeral(),
    };
    Ok((config, identity))
}

const FRAME: Duration = Duration::from_millis(16);
const STATE_EVERY: Duration = Duration::from_millis(50);
const POSITION_EVERY: Duration = Duration::from_millis(100);

fn run_host(o: &Options) -> Result<(), String> {
    let (mut config, identity) = setup(o)?;
    config.host_has_player = !o.dedicated;
    let name = o.name.clone().unwrap_or_else(|| "player".into());
    let room = RoomInfo {
        name: name.clone(),
        max_players: o.max_players.unwrap_or(4),
    };
    if o.public_relays {
        println!(
            "Room-code lookups go through public Nostr relays, which can see them and your IP address."
        );
    }
    let mut session = HostSession::new(fray_net::host(&config, &identity, room));
    let end = o.seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let started = Instant::now();
    let mut next_state = started;
    let mut next_report = started + Duration::from_secs(1);
    let mut ever_joined = false;
    let result = loop {
        let now = Instant::now();
        let mut failed = None;
        for note in session.poll(now) {
            match note {
                HostNote::Ready { code } => announce(&session, &code),
                HostNote::PlayerJoined { player, name } => {
                    ever_joined = true;
                    println!("player {player} joined: {name}");
                }
                HostNote::PlayerLeft {
                    player,
                    name,
                    reason,
                } => println!("player {player} left: {name} ({reason:?})"),
                HostNote::Refused { why } => println!("refused a peer: {why}"),
                HostNote::Failed { reason } => failed = Some(reason),
            }
        }
        if let Some(reason) = failed {
            break Err(format!("Hosting failed: {reason}"));
        }
        if !o.dedicated {
            // The host is player 0 and drifts along a line so there is
            // something to see.
            let t = (now - started).as_millis() as i64 / 100;
            session.set_host_position((t % 100 * 10) as i16, 0);
        }
        if now >= next_state {
            session.broadcast_state();
            next_state = now + STATE_EVERY;
        }
        if now >= next_report {
            next_report = now + Duration::from_secs(1);
            if let Some(view) = session.players().first() {
                println!("player {} is at ({}, {})", view.player, view.x, view.y);
            }
        }
        if end.is_some_and(|end| now >= end) {
            println!("Time is up; closing the room.");
            break Ok(());
        }
        if o.until_empty && ever_joined && session.players().is_empty() {
            println!("Everyone has left; closing the room.");
            break Ok(());
        }
        std::thread::sleep(FRAME);
    };
    session.shutdown();
    result
}

fn announce(session: &HostSession, code: &str) {
    let handle = session.handle();
    println!("Room code: {code}");
    if let Some(addr) = handle.local_addr() {
        println!("LAN port: {}", addr.port());
    }
    println!("LAN token: {}", handle.lan_token());
    println!(
        "Join from another terminal with: fray-starter join --addr 127.0.0.1:{} --token {}",
        handle.local_addr().map_or(0, |a| a.port()),
        handle.lan_token()
    );
}

fn start_join(
    o: &Options,
    config: &NetConfig,
    identity: &Identity,
) -> Result<ClientHandle, String> {
    if o.public_relays {
        let code = o
            .room_code
            .as_deref()
            .ok_or("--code needs --room-code CODE")?;
        return Ok(fray_net::join(config, identity, code));
    }
    if let Some(addr) = &o.addr {
        let addr = addr
            .parse()
            .map_err(|e| format!("'{addr}' is not HOST:PORT ({e})"))?;
        let token = o.token.as_deref().ok_or("--addr needs --token")?;
        return Ok(fray_net::join_addr(config, identity, addr, token));
    }
    let wait = Duration::from_secs(o.find_seconds.unwrap_or(10));
    let room = find_lan_room(config, wait).ok_or("No room found on the LAN.")?;
    println!("Found room {:?} ({})", room.name, room.code);
    Ok(fray_net::join_lan(config, identity, &room))
}

fn find_lan_room(config: &NetConfig, timeout: Duration) -> Option<LanRoom> {
    let mut browser = fray_net::lan_browse(config);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(room) = browser.poll().into_iter().next() {
            return Some(room);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn run_join(o: &Options) -> Result<(), String> {
    let (config, identity) = setup(o)?;
    let name = o.name.clone().unwrap_or_else(|| "player".into());
    let mut session = ClientSession::new(start_join(o, &config, &identity)?, &name);
    let end = o.seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let mut next_position = Instant::now();
    let (mut sent, mut states) = (0u32, 0u32);
    let result = loop {
        let now = Instant::now();
        for note in session.poll() {
            match note {
                ClientNote::Joining(stage) => println!("joining: {stage:?}"),
                ClientNote::Connected { host_name } => println!("connected to {host_name:?}"),
                ClientNote::Welcome { player } => println!("welcome: you are player {player}"),
                ClientNote::State { tick, players } => {
                    states += 1;
                    if states % 20 == 1 {
                        println!("state {tick}: {players:?}");
                    }
                }
                ClientNote::JoinFailed(text) => return Err(text),
                ClientNote::HostGone(text) => println!("{text}"),
                ClientNote::BadMessage(text) => println!("ignored a message: {text}"),
            }
        }
        if session.is_finished() {
            break Ok(());
        }
        if now >= next_position {
            let n = i16::try_from(sent % 100).unwrap_or(0) * 10;
            if session.send_position(n, i16::from(session.player().unwrap_or(0)) * 100) {
                sent += 1;
            }
            next_position = now + POSITION_EVERY;
        }
        if end.is_some_and(|end| now >= end) {
            println!("Time is up; leaving.");
            break Ok(());
        }
        std::thread::sleep(FRAME);
    };
    println!("sent {sent} positions, saw {states} states");
    session.shutdown();
    result
}
