# Fray rules for coding assistants

A rule sheet for an assistant that writes or reviews code using Fray (`fray-net`). It is short on purpose. For the reasons and the full picture, see [getting started](getting-started.md); for working code, see the starter in [`examples/starter`](../examples/starter).

These rules describe the code in this repository. Fray is unpublished and changes: check any name you are unsure of against the revision the game depends on, and do not invent functions, fields or options.

## Invariants

1. **Poll from the game loop and never block it.** Each frame, call `poll()` until it returns `None` (`while let Some(event) = handle.poll()`) and handle every event. It returns one event per call. Do not sleep, spin or wait for an event inside a frame. The only calls that block are `shutdown()` and dropping a handle (up to about one second for a host, 300 milliseconds for a client). Make them when the player leaves, not per frame.
2. **Never start or own the async runtime.** Fray runs its own runtime inside the crate. Do not add `tokio` for Fray, create a runtime, call `block_on`, or `.await` anything from Fray. The API is synchronous.
3. **Respect the size limits.** At most `MAX_PLAYERS` (8) seats. Reliable messages are at most `MAX_RELIABLE_LEN` (1024 bytes) unless `NetConfig::max_reliable_len` is raised on both ends together with a new `app_tag`. Datagrams are at most `MAX_LOSSY_LEN` (1024 bytes). An oversized send is dropped and logged, not returned as an error, so split large data yourself.
4. **The game owns its messages.** Fray carries opaque bytes. Define a versioned encoding in the game, validate every inbound frame (from the host as well as from clients), and use datagrams only for state that the next datagram can replace. Datagrams can be lost, repeated or reordered.
5. **Handle every failure and disconnect.** Match every `HostEvent` and `ClientEvent` variant explicitly, with no wildcard arm (the enums are not `#[non_exhaustive]`). `ClientEvent::Failed`, `ClientEvent::Disconnected`, `HostEvent::Failed` and `HostEvent::PeerLeft` must each reach the player and leave the game in a consistent state. Never `unwrap` or `panic!` on them.
6. **Use only API that exists.** Fray has no published release: depend on it by path or by a pinned git revision, never by a version number. Use the names `fray_net` exports at its root. Do not write calls from other networking libraries and assume Fray has them.

Also:

- `PeerJoined` seats a connection. It does not admit a player. Admission policy belongs to the game: wait for the game's own hello, and `kick` or `disconnect_with_reason` anyone who fails it.
- A room code is an invitation, not an identity.
- Choose one `app_tag` unique to the game. Use `NetConfig::lan_only()` unless the player has agreed to room codes over public relays, which can see the lookup.
- Do not log or commit an `identity.key`, a LAN token or an invite secret, outside a deliberate manual-join prompt (the starter prints a LAN token for that). Use loopback (`127.0.0.1`) or documentation addresses (`192.0.2.0/24`) in examples and tests, never real ones.
- Do not promise connectivity on every network, or host migration, or that Fray is a standard.

## Checklist

Before offering generated Fray code, check each item:

- [ ] The dependency is a path or a pinned git revision.
- [ ] One `NetConfig::new(data_dir, app_tag)` with the game's own tag; `lan_only()` unless public relays are intended and disclosed.
- [ ] An `Identity` is chosen on purpose: `ephemeral()` or `load_or_create(&data_dir)`.
- [ ] The host or client handle is created once, stored, and drained with `poll()` every frame.
- [ ] Every event variant is matched explicitly.
- [ ] Nothing waits inside the frame loop, and `shutdown()` runs on leaving.
- [ ] Reliable and lossy sends stay inside the limits.
- [ ] Inbound bytes are decoded defensively and stale datagrams are dropped.
- [ ] Join failure, host loss and peer loss show the player something and clean up.
- [ ] The game decides admission; `PeerJoined` alone does not seat a player.
- [ ] A test runs a host and a client in one process on loopback.

## The runnable check

From a Fray checkout at the revision the game pins:

```sh
cargo test -p fray-starter
cargo test -p fray-starter --doc
```

The first runs the starter's unit and integration tests: join, a reliable round trip, datagrams, the host seeing a client leave, the client seeing the host shut down, bad and missing hellos, and a docs test that checks every code excerpt and link in these guides. The second compiles the starter's doc examples. Passing shows that the revision and the documented behaviour agree for the behaviour these tests cover. It does not test the game's own code.

To check generated code, follow the pattern in [`examples/starter/tests/loopback.rs`](../examples/starter/tests/loopback.rs). Run the game's host and client in one process, join with `join_addr` and the host's `lan_token()`, turn the beacon off, use a temporary data directory, and need no internet. Assert the join, a reliable round trip, a datagram (send several and expect at least one), the host seeing the client leave, and the client seeing the host shut down. Then run the game's own tests.

[`examples/starter/check-loopback.sh`](../examples/starter/check-loopback.sh) shows the same check as two real processes under timeouts.

These checks use loopback. They say nothing about NAT traversal, relays or real networks.

## For the game's own `AGENTS.md`

Paste this into the game's `AGENTS.md`. It names no revision; add the one the game pins.

```markdown
## Networking (Fray)

This game uses Fray (`fray-net`) for multiplayer. Follow the rules in Fray's `docs/coding-assistants.md` at the revision this repository pins.

- Poll the Fray handle once per frame from the game loop. Never block the loop, and never start or own an async runtime for Fray.
- Keep sends within `MAX_RELIABLE_LEN` and `MAX_LOSSY_LEN`, and rooms within `MAX_PLAYERS`.
- The game owns its message format. Version it and validate every inbound frame, from the host too.
- Match every `HostEvent` and `ClientEvent` variant. Show failure and disconnect to the player.
- Admission is the game's job: a joined peer is not yet a player.
- Use only Fray API that exists at the pinned revision. Depend on it by path or git revision.
- Check changes with the game's own tests, and with `cargo test -p fray-starter` in a Fray checkout at the pinned revision. Do not weaken Fray's authentication to make a test pass.
```
