//! A tiny game that shows how a game uses Fray.
//!
//! Fray carries messages, picks the host and keeps the session alive. The
//! game keeps its own protocol and rules. Here the protocol is four messages
//! encoded by hand in [`wire`], and the "rules" are that each player has a
//! position the host collects and sends back.
//!
//! * [`HostSession`] owns a [`fray_net::HostHandle`]. The game calls
//!   [`HostSession::poll`] once per frame and gets back [`HostNote`]s.
//! * [`ClientSession`] owns a [`fray_net::ClientHandle`]. The game calls
//!   [`ClientSession::poll`] once per frame and gets back [`ClientNote`]s.
//!
//! Nothing in this file blocks, sleeps or starts an async runtime, and nothing
//! touches the network except through the two Fray handles. The runtime stays
//! inside Fray.
//!
//! # The frame loop
//!
//! This is the whole shape of a host. The example is compiled by
//! `cargo test --doc` but not run, because running it would open a socket.
//!
//! ```no_run
//! use std::time::{Duration, Instant};
//!
//! use fray_net::{Identity, NetConfig, RoomInfo};
//! use fray_starter::{HostNote, HostSession, APP_TAG};
//!
//! fn main() {
//!     let config = NetConfig::new("my-game-data", APP_TAG).lan_only();
//!     let identity = Identity::ephemeral();
//!     let room = RoomInfo {
//!         name: "Doc room".into(),
//!         max_players: 4,
//!     };
//!     let mut session = HostSession::new(fray_net::host(&config, &identity, room));
//!     let mut next_state = Instant::now();
//!     loop {
//!         let now = Instant::now();
//!         for note in session.poll(now) {
//!             match note {
//!                 HostNote::Ready { code } => println!("Ready: {code}"),
//!                 HostNote::PlayerJoined { player, name } => println!("{name} is player {player}"),
//!                 HostNote::PlayerLeft { player, .. } => println!("Player {player} left"),
//!                 HostNote::Refused { why } => println!("Refused a peer: {why}"),
//!                 HostNote::Failed { reason } => {
//!                     eprintln!("Host failed: {reason}");
//!                     return;
//!                 }
//!             }
//!         }
//!         if now >= next_state {
//!             session.broadcast_state();
//!             next_state = now + Duration::from_millis(50);
//!         }
//!         std::thread::sleep(Duration::from_millis(16));
//!     }
//! }
//! ```
//!
//! A client has the same shape. It joins by address here; a game with a lobby
//! would use `fray_net::lan_browse` and `fray_net::join_lan` instead.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use fray_net::{Identity, NetConfig};
//! use fray_starter::{ClientNote, ClientSession, APP_TAG};
//!
//! fn main() {
//!     let config = NetConfig::new("my-game-data", APP_TAG).lan_only();
//!     let identity = Identity::ephemeral();
//!     let addr = "192.0.2.10:4000".parse().expect("an address");
//!     let join = fray_net::join_addr(&config, &identity, addr, "the-token-the-host-printed");
//!     let mut session = ClientSession::new(join, "Ada");
//!     while !session.is_finished() {
//!         for note in session.poll() {
//!             match note {
//!                 ClientNote::Joining(stage) => println!("Joining: {stage:?}"),
//!                 ClientNote::Connected { host_name } => println!("Connected to {host_name:?}"),
//!                 ClientNote::Welcome { player } => println!("You are player {player}"),
//!                 ClientNote::State { tick, players } => println!("State {tick}: {players:?}"),
//!                 ClientNote::JoinFailed(text) | ClientNote::HostGone(text) => println!("{text}"),
//!                 ClientNote::BadMessage(text) => println!("Ignored a message: {text}"),
//!             }
//!         }
//!         session.send_position(0, 0);
//!         std::thread::sleep(Duration::from_millis(16));
//!     }
//!     session.shutdown();
//! }
//! ```
//!
//! # Joining by invite
//!
//! A host that can reach relays can also admit people by invite. The host
//! makes a secret and shares it, with its runtime key, in a link. The joiner
//! needs both. This does not use `lan_only`: an invite is found over relays.
//!
//! ```no_run
//! use fray_net::{generate_invite_secret, Identity, NetConfig, RoomInfo};
//! use fray_starter::APP_TAG;
//!
//! fn main() {
//!     let config = NetConfig::new("my-game-data", APP_TAG);
//!     let identity = Identity::ephemeral();
//!     let room = RoomInfo {
//!         name: "Invite room".into(),
//!         max_players: 4,
//!     };
//!     let host = fray_net::host(&config, &identity, room);
//!     let secret = generate_invite_secret();
//!     let invite = host.add_invite(secret).expect("the host holds too many invites");
//!     let host_key = host.runtime_key().to_bytes();
//!     // Put `secret` and `host_key` in a link. The joiner then calls:
//!     let join = fray_net::join_invite(&config, &identity, &secret, host_key);
//!     // Later: revoke the invite, and leave.
//!     host.remove_invite(invite);
//!     join.shutdown();
//!     host.shutdown();
//! }
//! ```

pub mod wire;

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use fray_net::{
    ClientEvent, ClientHandle, DisconnectReason, FailReason, HostEvent, HostHandle, JoinStage,
    LeaveReason, PeerId,
};

use wire::{is_newer, Message, PlayerState};

/// This game's app tag. It namespaces room codes, the QUIC protocol name and
/// the LAN beacon, so this starter never meets a different game's rooms.
pub const APP_TAG: &str = "fray-starter";

/// How long a peer may stay connected without saying hello before the host
/// drops it. A peer Fray has seated is not yet a player of this game: the
/// game decides who plays.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// What the host's game tells its UI after a poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostNote {
    /// The room is up. `code` is the room code.
    Ready { code: String },
    /// The room ended without being asked to, or never started.
    Failed { reason: String },
    /// A peer said a good hello and now has a player number.
    PlayerJoined { player: u8, name: String },
    /// A player went away.
    PlayerLeft {
        player: u8,
        name: String,
        reason: LeaveReason,
    },
    /// The game disconnected a peer, and told it why.
    Refused { why: String },
}

/// A seated player as the host sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerView {
    pub player: u8,
    pub name: String,
    pub x: i16,
    pub y: i16,
}

struct Player {
    number: u8,
    name: String,
    x: i16,
    y: i16,
    last_seq: Option<u16>,
}

/// The host side of the starter game.
pub struct HostSession {
    host: HostHandle,
    /// Peers that have said a good hello.
    players: BTreeMap<PeerId, Player>,
    /// Peers Fray has seated that have not said hello yet, and when they arrived.
    waiting: HashMap<PeerId, Instant>,
    host_position: Option<(i16, i16)>,
    tick: u16,
    hello_timeout: Duration,
}

impl HostSession {
    /// Wrap a host that is starting (or has started).
    pub fn new(host: HostHandle) -> Self {
        HostSession {
            host,
            players: BTreeMap::new(),
            waiting: HashMap::new(),
            host_position: None,
            tick: 0,
            hello_timeout: HELLO_TIMEOUT,
        }
    }

    /// Change how long a silent peer is tolerated (tests use a short one).
    pub fn with_hello_timeout(mut self, timeout: Duration) -> Self {
        self.hello_timeout = timeout;
        self
    }

    /// The Fray handle, for what the game does not wrap (the room code, the
    /// listening address, the LAN token).
    pub fn handle(&self) -> &HostHandle {
        &self.host
    }

    /// Set the host's own position. A host with a local player (the Fray
    /// default) is player 0; a dedicated host never calls this.
    pub fn set_host_position(&mut self, x: i16, y: i16) {
        self.host_position = Some((x, y));
    }

    /// The players that have joined, in the order Fray numbered their peers.
    pub fn players(&self) -> Vec<PlayerView> {
        self.players
            .values()
            .map(|p| PlayerView {
                player: p.number,
                name: p.name.clone(),
                x: p.x,
                y: p.y,
            })
            .collect()
    }

    /// Drain Fray's events and react to each one. Never blocks; call it once
    /// per frame. `now` is the game's clock.
    pub fn poll(&mut self, now: Instant) -> Vec<HostNote> {
        let mut notes = Vec::new();
        while let Some(event) = self.host.poll() {
            match event {
                HostEvent::Ready { code } => notes.push(HostNote::Ready { code }),
                HostEvent::Failed { reason } => notes.push(HostNote::Failed { reason }),
                HostEvent::PeerJoined { peer, .. } => {
                    self.waiting.insert(peer, now);
                }
                HostEvent::PeerLeft { peer, reason } => {
                    self.waiting.remove(&peer);
                    if let Some(p) = self.players.remove(&peer) {
                        notes.push(HostNote::PlayerLeft {
                            player: p.number,
                            name: p.name,
                            reason,
                        });
                    }
                }
                HostEvent::Reliable { peer, bytes } => self.on_reliable(peer, &bytes, &mut notes),
                HostEvent::Lossy { peer, bytes } => self.on_lossy(peer, &bytes),
            }
        }
        let timeout = self.hello_timeout;
        let silent: Vec<PeerId> = self
            .waiting
            .iter()
            .filter(|(_, since)| now.saturating_duration_since(**since) >= timeout)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in silent {
            self.refuse(peer, "No hello received.", &mut notes);
        }
        notes
    }

    fn on_reliable(&mut self, peer: PeerId, bytes: &[u8], notes: &mut Vec<HostNote>) {
        if self.players.contains_key(&peer) {
            // The game defines no reliable message after the hello.
            self.refuse(peer, "Unexpected message.", notes);
        } else if self.waiting.contains_key(&peer) {
            match Message::decode(bytes) {
                Ok(Message::Hello { name }) => self.seat(peer, name, notes),
                Ok(_) => self.refuse(peer, "Say hello first.", notes),
                Err(e) => self.refuse(peer, &format!("Bad hello: {e}."), notes),
            }
        }
        // Otherwise the peer was already refused; its late bytes are dropped.
    }

    fn on_lossy(&mut self, peer: PeerId, bytes: &[u8]) {
        let Some(player) = self.players.get_mut(&peer) else {
            return;
        };
        // A malformed or unexpected datagram is simply dropped: they are lossy
        // by nature and one bad one is not worth disconnecting anybody.
        if let Ok(Message::Position { seq, x, y }) = Message::decode(bytes) {
            if player.last_seq.is_none_or(|last| is_newer(seq, last)) {
                player.last_seq = Some(seq);
                player.x = x;
                player.y = y;
            }
        }
    }

    fn seat(&mut self, peer: PeerId, name: String, notes: &mut Vec<HostNote>) {
        let Some(number) =
            (1..=fray_net::MAX_PLAYERS).find(|n| self.players.values().all(|p| p.number != *n))
        else {
            self.refuse(peer, "Room full.", notes);
            return;
        };
        self.waiting.remove(&peer);
        self.host
            .send_reliable(peer, Message::Welcome { player: number }.encode());
        self.players.insert(
            peer,
            Player {
                number,
                name: name.clone(),
                x: 0,
                y: 0,
                last_seq: None,
            },
        );
        notes.push(HostNote::PlayerJoined {
            player: number,
            name,
        });
    }

    /// Disconnect a peer and tell it why. Fray queues the reason ahead of the
    /// close; the peer's client reports it as `KickedWith`.
    fn refuse(&mut self, peer: PeerId, why: &str, notes: &mut Vec<HostNote>) {
        self.waiting.remove(&peer);
        self.host.disconnect_with_reason(peer, why);
        notes.push(HostNote::Refused {
            why: why.to_string(),
        });
    }

    /// Send every player the positions of everybody, as one datagram each.
    /// Call it at the game's own rate. A lost datagram is replaced by the next.
    pub fn broadcast_state(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        let mut players = Vec::new();
        if let Some((x, y)) = self.host_position {
            players.push(PlayerState { player: 0, x, y });
        }
        players.extend(self.players.values().map(|p| PlayerState {
            player: p.number,
            x: p.x,
            y: p.y,
        }));
        let bytes = Message::State {
            tick: self.tick,
            players,
        }
        .encode();
        for peer in self.players.keys() {
            self.host.send_lossy(*peer, bytes.clone());
        }
    }

    /// Close every connection. Peers see the host leave.
    pub fn shutdown(self) {
        self.host.shutdown();
    }
}

/// What the client's game tells its UI after a poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientNote {
    /// A stage of the join began.
    Joining(JoinStage),
    /// Connected to the host named `host_name`; the hello has been sent.
    Connected { host_name: String },
    /// The host seated us as this player.
    Welcome { player: u8 },
    /// A fresh snapshot of every player.
    State {
        tick: u16,
        players: Vec<PlayerState>,
    },
    /// The join did not work. The text is fit to show a player.
    JoinFailed(String),
    /// The host went away. The text is fit to show a player.
    HostGone(String),
    /// The host sent something this game does not understand.
    BadMessage(String),
}

/// The client side of the starter game.
pub struct ClientSession {
    client: ClientHandle,
    name: String,
    player: Option<u8>,
    seq: u16,
    last_tick: Option<u16>,
    finished: bool,
}

impl ClientSession {
    /// Wrap a client that is joining. `name` goes in the hello.
    pub fn new(client: ClientHandle, name: &str) -> Self {
        ClientSession {
            client,
            name: name.to_string(),
            player: None,
            seq: 0,
            last_tick: None,
            finished: false,
        }
    }

    /// Our player number, once the host has sent its welcome.
    pub fn player(&self) -> Option<u8> {
        self.player
    }

    /// The join failed or the host went away. Nothing more will happen.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Drain Fray's events and react to each one. Never blocks; call it once
    /// per frame.
    pub fn poll(&mut self) -> Vec<ClientNote> {
        let mut notes = Vec::new();
        while let Some(event) = self.client.poll() {
            match event {
                ClientEvent::Progress { stage } => notes.push(ClientNote::Joining(stage)),
                ClientEvent::Connected { host_name, .. } => {
                    let hello = Message::Hello {
                        name: self.name.clone(),
                    };
                    self.client.send_reliable(hello.encode());
                    notes.push(ClientNote::Connected { host_name });
                }
                ClientEvent::Failed { stage, reason } => {
                    self.finished = true;
                    notes.push(ClientNote::JoinFailed(failure_text(stage, &reason)));
                }
                ClientEvent::Reliable(bytes) => match Message::decode(&bytes) {
                    Ok(Message::Welcome { player }) if self.player.is_none() => {
                        self.player = Some(player);
                        notes.push(ClientNote::Welcome { player });
                    }
                    Ok(_) => notes.push(ClientNote::BadMessage("unexpected message".into())),
                    Err(e) => notes.push(ClientNote::BadMessage(e.to_string())),
                },
                ClientEvent::Lossy(bytes) => {
                    // Datagrams can arrive late, twice or not at all. Take only
                    // a snapshot newer than the last one, and drop junk quietly.
                    if let Ok(Message::State { tick, players }) = Message::decode(&bytes) {
                        if self.last_tick.is_none_or(|last| is_newer(tick, last)) {
                            self.last_tick = Some(tick);
                            notes.push(ClientNote::State { tick, players });
                        }
                    }
                }
                ClientEvent::Disconnected { reason } => {
                    self.finished = true;
                    self.player = None;
                    notes.push(ClientNote::HostGone(gone_text(&reason)));
                }
            }
        }
        notes
    }

    /// Tell the host where we are, as a datagram. Returns `false` (and sends
    /// nothing) until the host has welcomed us.
    pub fn send_position(&mut self, x: i16, y: i16) -> bool {
        if self.player.is_none() || self.finished {
            return false;
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.client
            .send_lossy(Message::Position { seq, x, y }.encode());
        true
    }

    /// Leave. The host sees this player leave.
    pub fn shutdown(self) {
        self.client.shutdown();
    }
}

/// Words for a player when a join fails. [`FailReason`]'s `Display` is
/// written for players; the stage says how far the join got.
pub fn failure_text(stage: JoinStage, reason: &FailReason) -> String {
    let stage = match stage {
        JoinStage::Preparing => "preparing",
        JoinStage::FindingHost => "finding the host",
        JoinStage::Connecting => "connecting",
        JoinStage::Handshake => "the handshake",
    };
    format!("Could not join (while {stage}): {reason}")
}

/// Words for a player when the host goes away.
pub fn gone_text(reason: &DisconnectReason) -> String {
    match reason {
        DisconnectReason::HostLeft => "The host has gone.".into(),
        DisconnectReason::Kicked => "The host removed you.".into(),
        DisconnectReason::KickedWith(why) => format!("The host removed you: {why}"),
        DisconnectReason::ConfirmTimeout => "You took too long to confirm.".into(),
        DisconnectReason::TimedOut => "The host stopped answering.".into(),
        DisconnectReason::Error(e) => format!("The connection broke: {e}"),
    }
}
