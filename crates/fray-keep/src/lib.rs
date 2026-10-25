//! What a game needs to join a Keep by invite link, kept in one place so each
//! game does not carry its own copy: the invite link and finding it in pasted
//! text ([`invite`]), the saved-Keeps list in `keeps.json` ([`keeps`]) and the
//! rule for believing a return pass ([`pass`]). The link prefix, the file's
//! location and the clock are all passed in by the caller, nothing here
//! touches the network, and secrets never reach `Debug` or a log line. Each
//! game keeps its own wire format for the pass message and its own words for
//! the screens: this crate has no player-facing text beyond the `Keep ab12cd`
//! fallback name and the `ago` phrases.

pub mod invite;
pub mod keeps;
pub mod pass;

pub use invite::{describe, format_invite_link, hex_encode, invite_in_text, is_link_word, keep_id, parse_hex32, parse_invite_link, Invite};
pub use keeps::{ago, display_name, display_name_hex, is_invisible, keep_id_hex, Keep, Keeps, MAX_KEEPS};
pub use pass::accept_pass;
