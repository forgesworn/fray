# Transport v6 inventory

The initial extraction preserves `NET_PROTOCOL_VERSION = 6`, independently of Rust package version `0.1.0` and each game's protocol. The implementation and its existing tests are the compatibility reference. This inventory is a starting point for a community protocol draft; it does not claim an independently implemented interoperable peer yet.

Sources below are relative to `crates/decented-net/src/`. Twang and Stampede keep their own payload formats and application admission policies.

| Surface | Existing contract | Source |
|---|---|---|
| Namespacing | Caller-supplied app tag; QUIC ALPN is `<app_tag>/dnet6`; rendezvous derivation and LAN filtering include the app tag | `lib.rs`, `quic.rs`, `room.rs`, `lan.rs` |
| Room codes | Six letters, alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ`; input normalisation ignores spaces/dashes | `room.rs` |
| Room derivation | Argon2id v0x13, 19 MiB, two passes, one lane, 32-byte output; salt `<app_tag>-room-v3:<UTC day>` | `room.rs` |
| Rendezvous | Nostr kinds 20910 and 20911; signed events, NIP-44 ciphertext; offer filtered by `t`, answer addressed by `p`; answer binds join session and host key | `rendezvous.rs`, `client.rs`, `host.rs` |
| Rendezvous bounds | Clock skew at most 120 seconds; ciphertext at most 16 KiB; session IDs are 32 lowercase hex characters; at most 8 candidates | `rendezvous.rs` |
| QUIC admission | Hello proves admission; signed Welcome proves the host on the TLS session; Identify proves the joiner's runtime key; Accepted seats the peer | `quic.rs` |
| Reliable frames | One stream per peer; little-endian u32 byte length followed by payload; application frame cap 1024 bytes, checked before allocating a received body | `quic.rs`, `lib.rs` |
| Lossy messages | QUIC datagrams with payload at most 1024 bytes; no game-level delivery or ordering guarantee | `quic.rs`, `lib.rs` |
| Room capacity | 2–8 configured players, including one local host seat; at most 7 remote connections in the initial extraction | `host.rs`, `lib.rs` |
| LAN discovery | Default UDP port 7715; fixed magic followed by JSON beacon; app/version filtering; browser entries expire after 5 seconds | `lan.rs`, `lib.rs` |
| LAN identity | Beacon token admits nearby joiners; dial uses the packet's source IP and advertised QUIC port, not an arbitrary address claimed inside JSON | `lan.rs`, `client.rs` |
| Identity metadata | Optional raw persona attestation, at most 2048 bytes; up to three sanitised public `wss://` inbox relay URLs, covered by connection proofs | `identity.rs`, `quic.rs` |
| Resource bounds | Reliable receive queue 256 messages per peer; lossy receive queue 64; overflow disconnects or drops according to delivery class | `host.rs`, `client.rs`, `quic.rs` |
| Virtual transport | Caller-supplied bounded byte links carry QUIC packets; used by the games' Bluetooth integration and tests | `virt.rs` |

The SHA-256 derivation labels remain `decented-net/room-v2/tag\0`, `decented-net/room-v2/key\0`, and `decented-net/room-v2/admit\0`, each followed by the 32-byte Argon2id master. The tag is the first 32 hexadecimal characters of its digest. Their legacy names remain deliberately unchanged by the package rename.

## Relay pool

`fray-relays` retains the original priority order, URL normalisation, health reporting, shared pool and retry intervals: 5 seconds, 15 seconds, 45 seconds, then 120 seconds. Configured relays are preferred; built-in fallback behaviour is unchanged. The defaults are `wss://relay.damus.io`, `wss://nos.lol`, and `wss://relay.primal.net`. Default STUN endpoints are `stun.l.google.com:19302` and `stun.cloudflare.com:3478`.

Applications can supply a `RendezvousRelay`; a Nostr rendezvous relay carries setup events, not game payloads. This is distinct from a future peer-assist data relay. All relay-pool consumers in one process must resolve the same package to share settings and health through `RelayPool::global()`.

## Authentication and privacy

Runtime-key authentication does not verify a persona attestation. Games must apply their own credential/admission checks before trusting metadata. Twang and Stampede retain their existing checks in this extraction.

LAN beacons and room names are discoverable on the local network. Knowing a room code permits an admission attempt; the memory-hard derivation raises guessing cost but does not turn the code into a high-entropy secret. Nostr observers can see setup metadata even though payloads are encrypted. Read the copied [security notes](../crates/decented-net/SECURITY.md) before making stronger privacy claims.

## Beyond the initial extraction

There is no host migration, reachability-based election, data relay, full-checkpoint transfer, authority component or Keep sandbox in this wire. Neither Link nor mesh is wire-compatible merely because it also connects peers. Any later change must specify its own negotiation/versioning, admission guarantees, bounds and failure cases, with fixtures and consumer acceptance.
