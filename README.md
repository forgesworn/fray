# Fray

> Join the fray.

Fray is a poll-driven Rust transport for small realtime multiplayer games. Games supply their own rules, simulation and messages. The initial implementation is extracted from the transport already shared by Twang and Stampede, with the same wire format, authentication, defaults and limits.

**Status: shared transport, with dedicated-host seat accounting.** Sessions, host election, migration, peer assistance, the authority interface, sandboxed Keep hosting and Godot bindings are future work. The transport supports up to 8 player seats and 1024-byte reliable messages or datagrams. Phone hosts reserve one local seat by default; a dedicated host can expose all eight seats to remote players. The broader 2–64-player scope is a development target.

## Packages

| Package | Directory | Responsibility |
|---|---|---|
| `fray-net` | `crates/decented-net` | QUIC reliable messages and datagrams, Nostr rendezvous, LAN discovery, NAT candidates and virtual links |
| `fray-relays` | `crates/decented-relays` | Relay ordering, health, retry schedules, fallback and a shared process-wide pool |

The legacy directory names preserve the existing source-layout tests. New applications import `fray_net` and `fray_relays`. Existing consumers can keep their source imports using Cargo dependency aliases.

## Try a LAN host

The packages are not published. From a neighbouring Rust project:

```toml
[dependencies]
fray-net = { path = "../fray/crates/decented-net" }
```

```rust
use fray_net::{HostEvent, Identity, NetConfig, RoomInfo};

fn main() {
    let config = NetConfig::new("test-data", "my-game").lan_only();
    let identity = Identity::ephemeral();
    let host = fray_net::host(&config, &identity, RoomInfo {
        name: "Test room".into(),
        max_players: 8,
    });
    loop {
        match host.poll() {
            Some(HostEvent::Ready { .. }) => println!("Ready: {}", host.code()),
            Some(HostEvent::Reliable { peer, bytes }) => host.send_reliable(peer, bytes),
            Some(HostEvent::Failed { reason }) => panic!("Host failed: {reason}"),
            _ => std::thread::sleep(std::time::Duration::from_millis(4)),
        }
    }
}
```

This creates a transport identity and echoes reliable bytes; it does not implement a game's admission policy or validate a persona credential. Configure the same app tag in compatible peers, discover the room through `lan_browse`, then use `join_lan`. APIs remain non-blocking; the network runtime stays inside the library.

See [transport v6](docs/transport-v6.md) for the compatibility inventory and [security notes](crates/decented-net/SECURITY.md) for room-code and identity limitations. A room code is an invitation mechanism, not proof of a friend's identity.

## Dedicated game host

Set `NetConfig::host_has_player = false` when the game authority has no local
player. This exposes eight remote connections and advertises zero players in
an empty room. The default remains `true`; authentication and wire v6 stay the same.

Stampede's `race-session` integration provides `stampede-headless`: an eight-bot
CPU benchmark, eight-client localhost QUIC smoke check and an explicitly selected,
bounded LAN test host. See the game's `docs/api/race-session.md` for commands.
It uses ephemeral synthetic signed credentials for tests. It is a native development
process, with no Keep control service, production credentials or sandbox.

## Development

```sh
cargo test --workspace --locked
cargo fmt --all --check
```

The copied transport tests include socket, rendezvous and virtual-link cases. Consumer acceptance also runs the games' unchanged tests and Twang's existing headless bot match. Test results do not establish real-phone NAT reachability or Keep sandbox security.

## Licence and contributions

MIT. The transport's [NOTICE](crates/decented-net/NOTICE) preserves its AxeNStax source lineage and licence. The relay package retains its [upstream licence](crates/decented-relays/LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md).
