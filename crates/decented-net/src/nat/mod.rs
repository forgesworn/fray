//! Getting two machines to talk directly: gather the addresses this machine
//! might be reachable at, punch a hole through the router toward the peer's,
//! and race a QUIC connect across all of them.
//!
//! Copied from Axe'n'Stax `nat/` (MIT) with the app coupling removed.

pub mod addr;
pub mod candidates;
pub mod punch;
pub mod stun;
pub mod upnp;
