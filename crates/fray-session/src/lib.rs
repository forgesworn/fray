//! Fray's game-session state machines: the authority contract, room-code format
//! and host migration. Nothing here does I/O: no sockets and no async runtime. The
//! session time is passed in by the caller; the only clock read is
//! `std::time::Instant` timing two elapsed-work budgets in `migration`. The
//! transport (`fray-net`) drives these types and re-exports them, so a game can
//! keep importing them from there.
//!
//! Defaults retain session/migration support. An import-free game authority
//! selects `default-features = false, features = ["authority"]` to exclude
//! session signing, random sampling and migration's elapsed-work clock reads.

#[cfg(feature = "authority")]
pub mod authority;
#[cfg(feature = "session")]
pub mod code;
#[cfg(feature = "session")]
pub mod migration;

/// Default for `NetConfig::max_reliable_len` in `fray-net`: the largest
/// reliable message `send_reliable` will carry (and accept: a bigger frame from
/// a peer ends the connection). Host migration always uses this size.
pub const MAX_RELIABLE_LEN: usize = 1024;
