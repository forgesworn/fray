# Fray

> Join the fray.

**Realtime multiplayer sessions with no game server to run.** Fray is a Rust library that lets players find each other, connect directly and keep a match alive. It works on a phone, a desktop, a home server or a VPS, with no matchmaker, no operated relay and no central backend.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-native-orange)](https://www.rust-lang.org/)

Part of the [ForgeSworn](https://github.com/forgesworn) toolkit

> **Status: design stage.** There is no usable code here yet. This repo will hold the library once the design settles.

## The Problem

Peer-to-peer multiplayer usually fails in the same places:

- **Players can't connect.** Mobile carriers and strict routers block direct connections. The usual fix is a relay that somebody has to run and pay for.
- **The host leaves and the match dies.** One player's phone call or dropped Wi-Fi ends the game for everyone.
- **Whoever taps "Host" hosts**, even when another player has a far better connection.
- **Every game re-solves this** with its own lobby, room codes and NAT traversal.

## What Fray Will Do

| Layer | Responsibility |
|---|---|
| **Transport** | QUIC, NAT hole-punching (STUN, UPnP, IPv6), LAN discovery, optional Bluetooth links |
| **Sessions** | Rooms and room codes rendezvoused over [Nostr](https://nostr.com), presence, reachability scoring, host election |
| **Resilience** | Host migration from checkpoints; when a direct path fails, relay through a reachable peer the players trust |
| **Authority** | One trait a game implements for its host logic. The same code runs natively in a player's app or sandboxed (WASM) on a dedicated host |

The game keeps its own protocol: its snapshots, rules and simulation. Fray carries those messages, picks the host, and keeps the session alive.

Fray is **poll-driven**: the game calls it from its own frame loop. That suits any Rust engine, and Godot through [godot-rust](https://godot-rust.github.io/).

## Scope

Fray is for **sessions with one authority, roughly 2 to 64 players**, hosted on any device. That covers party games, racers, fighting games, small persistent worlds and community servers. **Leagues and ladders** are built on signed match results published as Nostr events.

It is **not** a backend for 100-player battle royales or MMO shards. Those need datacentre-scale servers and game-specific netcode.

## License

[MIT](LICENSE)
