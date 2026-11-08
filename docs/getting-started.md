# Getting started

Fray is a poll-driven Rust transport for small realtime multiplayer games. It carries your game's messages, finds a host and keeps the connection alive. Your game keeps its own rules, message formats and simulation.

This guide has two halves. First, run the starter game and watch two processes talk. Then add the same loop to a game of your own.

The packages are not published. Use a path or a pinned git revision, as shown below. Nothing here makes Fray a standard, and nothing here promises a connection on every network.

## Run the starter on one machine

The starter is the package `fray-starter` in [`examples/starter`](../examples/starter). It is a tiny game with its own hand-written byte protocol: a client says hello with a name, the host answers with a player number, clients send their position as datagrams, and the host sends everyone's positions back. Both sides handle the other going away.

You need a Rust toolchain. The starter uses `Option::is_none_or`, which needs Rust 1.82 or later.

From the root of the Fray checkout, open two terminals. In the first:

```sh
cargo run -p fray-starter -- host --name Table
```

The host prints a room code, a LAN port and a LAN token:

```text
Room code: ABCDEF
LAN port: 45217
LAN token: <64 hex characters>
Join from another terminal with: fray-starter join --addr 127.0.0.1:45217 --token <64 hex characters>
```

In the second terminal, join. With no address, `join` listens for the host's LAN beacon and joins the first room it hears:

```sh
cargo run -p fray-starter -- join --name Ada
```

The client prints what it sees: the join stages, `welcome: you are player 1`, and snapshots of every player. The host prints `player 1 joined: Ada` and, once a second, where it last saw that player. Stop the client with `--seconds 5` (or let the host go): the host prints `player 1 left: Ada (Left)`. Add `--until-empty` to the host and it exits once its last player has gone.

If the beacon is not heard, join by address instead, using the line the host printed:

```sh
cargo run -p fray-starter -- join --name Ada --addr 127.0.0.1:45217 --token <token>
```

[`examples/starter/check-loopback.sh`](../examples/starter/check-loopback.sh) runs this as two real processes on loopback, under timeouts, and checks what each one printed. The integration tests in [`examples/starter/tests/loopback.rs`](../examples/starter/tests/loopback.rs) run a host and a client in one process. Neither needs the internet.

## Run it on two machines on one LAN

Build the starter on both machines. On the first:

```sh
cargo run -p fray-starter -- host --name Table
```

On the second, on the same network:

```sh
cargo run -p fray-starter -- join --name Ada
```

The host broadcasts a UDP beacon on port 7715 (`DEFAULT_LAN_PORT`) and the joiner listens for it. Pass `--lan-port` to both sides to use another port. A room disappears from the joiner's list if its beacon has not been heard for 5 seconds. Then the joiner dials the host's address over QUIC. The host picks a free UDP port for that when it starts and prints it as `LAN port`.

If the joiner finds nothing, check the usual causes: a firewall blocking UDP on either machine, Wi-Fi that isolates clients from each other, or a VPN that sends local traffic into its tunnel. Then join by address, with the host's LAN address and the token it printed. This example uses a documentation address:

```sh
cargo run -p fray-starter -- join --name Ada --addr 192.0.2.20:45217 --token <token>
```

The LAN token is what admits a LAN join, and it is also in the beacon, so anyone on the LAN can read it.

### If a VPN swallows local traffic

On a phone, a VPN can send LAN traffic into its tunnel, so the beacon and the QUIC dial never arrive. Fray handles this through a hook the app provides: `NetConfig::lan_socket_hook` binds each local socket to the Wi-Fi network. After the hook runs, `fray_net::lan_blocked()` is `true` if the platform refused. In that case show the player `fray_net::VPN_BLOCKS_LAN`. `fray_net::check_lan_binding(&config)` runs the hook once on a throwaway socket and returns the same answer, so you can check when a screen opens. The starter runs on a desktop and sets no hook.

## Add Fray to an existing game

### The dependency

The packages are not published. From a neighbouring checkout, use a path:

```toml
[dependencies]
fray-net = { path = "../fray/crates/decented-net" }
```

Or pin a git revision. Cargo finds the package named `fray-net` inside the repository:

```toml
[dependencies]
fray-net = { git = "https://github.com/forgesworn/fray", rev = "<a commit hash>" }
```

Import it as `fray_net`. Pin a revision rather than a branch, so an update is a choice you make.

### Poll from the frame loop

Fray's API is synchronous and does not wait on the network. The only calls that block are shutting a handle down and dropping one, covered below. Work that takes time happens on a runtime inside the crate and comes back as events from `poll`. Your game never starts that runtime, never enters it and never awaits anything from Fray.

The shape of a host is a loop that polls, reacts, and sleeps for the rest of the frame. This is the example at the top of [`examples/starter/src/lib.rs`](../examples/starter/src/lib.rs); `cargo test -p fray-starter --doc` compiles it.

```rust
use std::time::{Duration, Instant};

use fray_net::{Identity, NetConfig, RoomInfo};
use fray_starter::{HostNote, HostSession, APP_TAG};

fn main() {
    let config = NetConfig::new("my-game-data", APP_TAG).lan_only();
    let identity = Identity::ephemeral();
    let room = RoomInfo {
        name: "Doc room".into(),
        max_players: 4,
    };
    let mut session = HostSession::new(fray_net::host(&config, &identity, room));
    let mut next_state = Instant::now();
    loop {
        let now = Instant::now();
        for note in session.poll(now) {
            match note {
                HostNote::Ready { code } => println!("Ready: {code}"),
                HostNote::PlayerJoined { player, name } => println!("{name} is player {player}"),
                HostNote::PlayerLeft { player, .. } => println!("Player {player} left"),
                HostNote::Refused { why } => println!("Refused a peer: {why}"),
                HostNote::Failed { reason } => panic!("Host failed: {reason}"),
            }
        }
        if now >= next_state {
            session.broadcast_state();
            next_state = now + Duration::from_millis(50);
        }
        std::thread::sleep(Duration::from_millis(16));
    }
}
```

A client has the same shape and ends when `is_finished()` says the join failed or the host went away. `lan_browse` returns a `LanBrowser` that you poll from the same loop; `join_lan` takes a `LanRoom` from it.

`HostHandle::shutdown` blocks for up to about one second so the close reaches the peers, and `ClientHandle::shutdown` for up to about 300 milliseconds. Dropping a handle does the same with shorter waits. Call them when the player leaves, not from inside a frame.

### Map events to game actions

`HostHandle::poll` and `ClientHandle::poll` return `Option<HostEvent>` and `Option<ClientEvent>`. The starter turns each event into a game action in one `match`. This is the host's, from `HostSession::poll` in [`examples/starter/src/lib.rs`](../examples/starter/src/lib.rs):

```rust
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
```

| `HostEvent` | What the game does |
|---|---|
| `Ready { code }` | Show the room code. |
| `Failed { reason }` | The room ended or never started. Tell the player and stop hosting. |
| `PeerJoined { peer, pubkey, admitted_by, .. }` | A connection is seated, but it is not yet a player. Wait for the game's own hello and apply the game's admission policy. |
| `PeerLeft { peer, reason }` | Remove the player. `reason` is `Left`, `TimedOut`, `Kicked` or `Error`. |
| `Reliable { peer, bytes }` | Decode, validate, act. Bytes from a peer are untrusted. |
| `Lossy { peer, bytes }` | The same, but one may be lost, repeated or late. Drop what is stale. |

The client's, from `ClientSession::poll` in the same file:

```rust
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
```

| `ClientEvent` | What the game does |
|---|---|
| `Progress { stage }` | Show how far the join has got. |
| `Connected { host_name, host_pubkey, .. }` | Connected and the host's welcome verified. Send the game's hello. |
| `Failed { stage, reason }` | The join failed. Show the `FailReason` (its `Display` is written for players). |
| `Reliable(bytes)` / `Lossy(bytes)` | Decode, validate, act. The host's bytes are untrusted too. |
| `Disconnected { reason }` | The host has gone. Return to the menu and say why. |

Match every variant explicitly. The event enums are not marked `#[non_exhaustive]`, so a wildcard arm would hide a variant added later.

### Your messages are yours

Fray delivers opaque bytes. The starter encodes four messages by hand in [`examples/starter/src/wire.rs`](../examples/starter/src/wire.rs): a tag byte, then fixed little-endian fields. It decodes defensively (unknown tag, truncated frame and trailing bytes are all errors) and uses a sequence number so a late datagram is dropped. A hello carries a protocol version of the game's own, separate from Fray's.

Use whatever encoding suits your game. Version it, and treat every inbound frame as hostile input.

### Limits

| Limit | Value | What happens past it |
|---|---|---|
| `MAX_PLAYERS` | 8 seats | `RoomInfo::max_players` is clamped to 2 through 8 and includes the host's own seat. A joiner who arrives when every seat is taken fails with `FailReason::RoomFull`. The host's own seat counts while `host_has_player` is true. |
| `MAX_RELIABLE_LEN` | 1024 bytes by default | A larger `send_reliable` is dropped and logged; nothing is returned. A larger frame from a peer ends the connection. |
| `MAX_LOSSY_LEN` | 1024 bytes | A larger `send_lossy` is dropped and logged. |
| `MAX_DISCONNECT_REASON` | 200 bytes | A longer reason given to `disconnect_with_reason` is cut. |
| `MAX_INVITES` | 256 | `add_invite` returns an error. |

An app that needs bigger reliable messages can set `NetConfig::max_reliable_len`, from 1024 up to 1 MiB. Both ends must set the same value and there is no negotiation, so change your `app_tag` at the same time. Host migration only runs at the default size.

Datagrams give no promise of arrival, order or uniqueness. Send state you can afford to lose, and send a fresh copy soon.

Inbound queues are bounded. A host keeps up to 256 reliable messages (and 256 KiB) from each peer waiting for `poll`; a client keeps up to 1024 (and 1 MiB). One more disconnects the sender, so a game that stops polling loses its peers. Waiting datagrams are dropped once a host has 64 from a peer, or a client has 128.

### Namespacing with `app_tag`

`NetConfig::new(data_dir, app_tag)` takes your game's id. It namespaces room codes, the QUIC protocol name and the LAN beacon, so two apps built on Fray never find each other's rooms. There is no default. Choose a tag unique to your game, and change it when your own protocol changes in a way old builds cannot read. The starter uses `"fray-starter"`.

### Identity: ephemeral or persisted

Every peer has an `Identity`, a keypair that signs its side of the handshake. The host sees the joiner's public key in `PeerJoined`, and the joiner sees the host's in `Connected`.

- `Identity::ephemeral()` is new on every call and is never written anywhere. Each session, the player looks like a stranger.
- `Identity::load_or_create(&data_dir)` keeps the key in `data_dir/identity.key`, so a returning player has the same public key. Treat that file as a secret and keep it out of version control. The starter does this when you pass `--data-dir`.

A key proves that the peer holds it on this connection. It does not say who the person is. Persona attestations are carried with the identity, but Fray does not verify them: the game must.

## Ways to connect

| Path | Needs | Who can see it |
|---|---|---|
| LAN | Both devices on one network. Nothing from the internet. | Anyone on the LAN can hear the beacon: the room name, the code and the LAN token. |
| Room code | The host and the joiner can both reach Nostr relays. | The relays see the lookup (see below). |
| Invite | A host that can reach relays, and a link carrying a secret and the host's key. | The relays see the lookup, under tags derived from the secret. |

### LAN

`NetConfig::lan_only()` removes the relays and STUN servers, and relay fallback with them. The host then never touches the internet. This is the starter's default. On the host side, `lan_beacon` controls whether the beacon is sent at all.

### Room codes over public relays

Without `lan_only()`, a host answers a six-letter room code on Nostr relays. By default these are public relays. `NetConfig::relays` is the list to use instead, and `DEFAULT_RELAYS` is the built-in list when you give none. The starter's `--code` flag turns this on: the host prints a code, and `join --code --room-code ABCDEF` uses it.

**Third-party relays see the lookup.** Per [the security notes](../crates/decented-net/SECURITY.md), a relay operator can see the room tag, the signer keys, timestamps, message sizes and the IP address of every client connected to it. The offer and answer are encrypted, and game messages never pass through a relay: after the lookup, peers talk to the host directly over QUIC. The host may also ask STUN servers for its public address and try a router port mapping (UPnP), which `lan_only()` avoids. A set `vpn_active` skips the port mapping but not STUN.

Fray tries several candidate addresses and hole punching. It does not promise a connection on every network. `FailReason::PunchFailed` is what a failure looks like.

### Invites

A host that can reach relays can admit people by invite, next to its code. The host makes a secret, adds it, and puts the secret and its runtime key in a link. The joiner calls `join_invite` with both. The link holds no address, a revoked invite gets no answer, and a joiner only joins the host whose key is in the link. `HostEvent::PeerJoined` reports `admitted_by: Admission::Invite(id)`. Removing an invite does not drop anyone already in; the game decides whether to `kick` them. This example is from the top of [`examples/starter/src/lib.rs`](../examples/starter/src/lib.rs) and is compiled by `cargo test -p fray-starter --doc`:

```rust
use fray_net::{generate_invite_secret, Identity, NetConfig, RoomInfo};
use fray_starter::APP_TAG;

fn main() {
    let config = NetConfig::new("my-game-data", APP_TAG);
    let identity = Identity::ephemeral();
    let room = RoomInfo {
        name: "Invite room".into(),
        max_players: 4,
    };
    let host = fray_net::host(&config, &identity, room);
    let secret = generate_invite_secret();
    let invite = host.add_invite(secret).expect("the host holds too many invites");
    let host_key = host.runtime_key().to_bytes();
    // Put `secret` and `host_key` in a link. The joiner then calls:
    let join = fray_net::join_invite(&config, &identity, &secret, host_key);
    // Later: revoke the invite, and leave.
    host.remove_invite(invite);
    join.shutdown();
    host.shutdown();
}
```

An invite needs relays, so it does not work on a `lan_only()` host.

## Hosting choices

**A player host.** This is the default. The host's device runs the game and holds one of the seats (`host_has_player = true`, so seven remote players at most). If the host's process stops, clients see `Disconnected` and the session ends. Host migration state machines exist in `fray-session`, but this guide does not cover them.

**A dedicated host.** Set `NetConfig::host_has_player = false` and the host has no seat of its own. All eight seats are open to remote players, and an empty room advertises zero players. The code is otherwise the same. The starter's `host --dedicated` does this, and a test checks that no player 0 appears. A dedicated host still has to be reachable by one of the paths above.

**A Keep, hosted through Ingle.** Ingle is the reference runtime for hosting a game's authority in a Keep, a host run by a person or a community. It is still in qualification, and this guide promises nothing about it. What Fray has today is the joining side: `fray-keep` reads an invite link into the secret and host key that `join_invite` takes, and holds the saved-Keeps list. The README says where the Keep work stands.

## Troubleshooting

A failed join reports `ClientEvent::Failed { stage, reason }`. The `stage` says how far it got:

| `JoinStage` | What was happening |
|---|---|
| `Preparing` | Binding a socket and gathering our own addresses. |
| `FindingHost` | A room-code or invite join was reaching the relays and waiting for an answer. |
| `Connecting` | Trying the host's addresses, or dialling the LAN address directly. |
| `Handshake` | QUIC was up; verifying the host and waiting to be seated. |

| `FailReason` | What it means, and what to check |
|---|---|
| `BadCode` | Not six characters from the room-code alphabet. Case, spaces and hyphens do not matter. |
| `RelayUnreachable` | No relay could be reached. Check the internet connection, or the `relays` list. |
| `NoAnswer` | Relays were reached, but no host answered. Check the code, that the host has started and is open, and that both sides use the same `app_tag`. |
| `PunchFailed` | The host answered but no address connected. A network between the two may block it. |
| `RoomFull` | Every seat is taken. |
| `RoomClosed` | The host has closed the room to new players (`set_open(false)`). |
| `VersionMismatch` | The host runs an incompatible version. |
| `HostUnverified` | The host's signed welcome did not verify, or an invite's pinned key did not match. The join fails closed. |
| `HostConflict` | Two different keys answered one code. Someone else knows the code. Ask the host for a new one. |
| `NotAdmitted` | The host refused the code or LAN token, which may be stale after the room rotated it, or this key was kicked earlier. |
| `Network(text)` | A local socket, runtime or protocol problem. |
| `NoLinkAnswer` | A virtual (Bluetooth) link opened but the host did not answer. Only applies to virtual links. |

Once connected, the client's `DisconnectReason` says why the host went:

| `DisconnectReason` | Meaning |
|---|---|
| `HostLeft` | The host shut down or closed the connection. |
| `Kicked` | The host removed this player and gave no reason. |
| `KickedWith(text)` | The host removed this player with a short reason, already cleaned for display. The starter uses this to say why a bad hello was refused. |
| `ConfirmTimeout` | The player stayed on a confirm screen too long. |
| `TimedOut` | Nothing was heard from the host within the idle timeout (6 seconds by default, `NetConfig::idle_timeout`). |
| `Error(text)` | The connection broke another way. |

A host sees the same ends as `PeerLeft { reason }`: `Left`, `TimedOut`, `Kicked` or `Error(text)`.

A process that is killed, rather than shut down, cannot say goodbye. Its peers see `TimedOut` after the idle timeout instead of `Left`.

## Security

A room code is an invitation, not an identity. Anyone who knows the code can ask to join, and the host can only see the key they prove. The code space is six letters, and the code is stretched, but it is not a strong secret.

Admission policy belongs to the game. Fray authenticates the connection and the host; it does not decide who may play. The starter shows the shape of a policy: a peer that has joined at the transport level waits for a valid hello, and the host drops it with a reason if the hello is bad or does not come within five seconds. Your game might check a name list, a ticket, a persona attestation or a host prompt. Use `kick` to remove and ban a key for the life of the room, `disconnect` to remove without a ban, `set_open(false)` to close the room to newcomers, and `rotate_code` to retire a code that has spread.

Read [the security notes](../crates/decented-net/SECURITY.md) before you make claims to your players about privacy or identity.
