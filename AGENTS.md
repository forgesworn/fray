# AGENTS.md

Instructions for coding agents working in this repo.

## Read first

Fray is at **design stage**. The plan lives in a private sibling checkout, `../fray-internal`. Before doing anything, read in this order:

1. `../fray-internal/AGENTS.md`: the build-session rules
2. `../fray-internal/ROADMAP.md`: what to build, in order, with acceptance checks
3. `../fray-internal/OPEN-QUESTIONS.md`: what is still undecided

If `../fray-internal` is missing, stop and say so. Don't guess the plan from this README.

## Conventions

- **Rust**, MIT licence.
- **Poll-driven API.** The game calls Fray from its own frame loop (`poll` / `send` / `events`). The async runtime (tokio, via quinn) stays inside the crate and never appears in the public API.
- **The game keeps its protocol.** Fray carries messages, picks the host and keeps the session alive. Game rules, snapshots and simulation stay in each game.
- **Grow from real consumers.** Every feature lands together with a game using it. Don't add speculative API.

## Rules

- **Don't settle open design questions in a build session.** Add them to `../fray-internal/OPEN-QUESTIONS.md` and carry on with what's decided.
- **Extraction changes nothing in behaviour.** When code moves into Fray, the consuming games' existing tests must pass unchanged.
- **Commits and docs contain no personal names and no absolute local paths.** A pre-commit hook blocks them. Never bypass it with `--no-verify`.
- **No force-push** and no rebase that could drop commits on shared branches.
