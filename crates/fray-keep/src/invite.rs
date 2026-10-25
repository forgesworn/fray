//! Invite links: how a Keep hands out a way in that holds no address.
//!
//! A link is the caller's prefix (for example `stampede://keep/`) followed by
//! the Keep's runtime public key and the invite's 32-byte secret, both as 64
//! lower-case hex characters:
//!
//! ```text
//! <prefix><64 hex: the Keep's runtime public key>/<64 hex: the secret>
//! ```
//!
//! Pass the two parts to the transport's invite join. Nothing here touches the
//! network.

/// The two halves of an invite link. `Debug` never prints the secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Invite {
    /// The Keep's runtime public key.
    pub host_key: [u8; 32],
    /// The invite's secret.
    pub secret: [u8; 32],
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invite(Keep {})", describe(&self.host_key))
    }
}

/// Lower-case hex of `bytes`.
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Exactly 64 hex characters (either case) as 32 bytes.
pub fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

/// The first six hex characters of a host key, lower-case: enough to tell Keeps
/// apart in a log. Never the secret.
pub fn describe(host_key: &[u8; 32]) -> String {
    hex_encode(&host_key[..3])
}

/// The Keep ID a player can read out: [`describe`], upper-cased.
pub fn keep_id(host_key: &[u8; 32]) -> String {
    describe(host_key).to_ascii_uppercase()
}

/// The link text for an invite to the Keep `host_key` with `secret`, under the
/// caller's `prefix`.
pub fn format_invite_link(prefix: &str, host_key: &[u8; 32], secret: &[u8; 32]) -> String {
    format!("{prefix}{}/{}", hex_encode(host_key), hex_encode(secret))
}

/// `text` starts with `prefix`, ignoring ASCII case.
fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Read a link pasted by a person. Leading and trailing whitespace is ignored,
/// the prefix is matched in either case and the hex may be in either case;
/// nothing else is tolerated (no extra path, fragment or second link).
/// `None` when it is not a whole invite under `prefix`.
pub fn parse_invite_link(prefix: &str, text: &str) -> Option<Invite> {
    let text = text.trim();
    if !starts_with_ci(text, prefix) {
        return None;
    }
    let rest = &text[prefix.len()..];
    let (host, secret) = rest.split_once('/')?;
    Some(Invite { host_key: parse_hex32(host)?, secret: parse_hex32(secret)? })
}

/// The longest pasted text searched for a link, in bytes. Longer text is not a
/// message with a link in it.
const MAX_TEXT: usize = 4096;

/// Is `word` a Keep link token: it starts with `prefix` (either case), or is
/// the prefix without its trailing slash (a link cut short, which the caller
/// should report as a bad link)?
fn is_link_word(prefix: &str, word: &str) -> bool {
    if starts_with_ci(word, prefix) {
        return true;
    }
    let bare = prefix.strip_suffix('/').unwrap_or(prefix);
    bare.len() < prefix.len() && word.eq_ignore_ascii_case(bare)
}

/// The first word of pasted text that starts with `prefix` (either case), so a
/// message like "Join my Keep: stampede://keep/..." works. Words end at
/// whitespace or at `<>"'()[]`, and sentence punctuation after the link
/// (`.,;:!?`) is not part of it. The word is returned as written, for
/// [`parse_invite_link`]: a word that is not a whole invite is returned too, so
/// the caller can say the link is bad. `None` when there is no such word, or
/// the text is longer than 4096 bytes.
pub fn invite_in_text<'a>(prefix: &str, text: &'a str) -> Option<&'a str> {
    if text.len() > MAX_TEXT {
        return None;
    }
    text.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '(' | ')' | '[' | ']'))
        .map(|w| w.trim_end_matches(['.', ',', ';', ':', '!', '?']))
        .find(|w| is_link_word(prefix, w))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "stampede://keep/";
    const HOST: [u8; 32] = [0xab; 32];
    const SECRET: [u8; 32] = [0x01; 32];

    fn link() -> String {
        format_invite_link(PREFIX, &HOST, &SECRET)
    }

    fn invite() -> Option<Invite> {
        Some(Invite { host_key: HOST, secret: SECRET })
    }

    #[test]
    fn a_link_round_trips() {
        assert_eq!(link(), format!("stampede://keep/{}/{}", "ab".repeat(32), "01".repeat(32)));
        assert_eq!(parse_invite_link(PREFIX, &link()), invite());
    }

    #[test]
    fn the_prefix_is_the_callers() {
        let other = format_invite_link("axenstax://keep/", &HOST, &SECRET);
        assert_eq!(other, format!("axenstax://keep/{}/{}", "ab".repeat(32), "01".repeat(32)));
        assert_eq!(parse_invite_link("axenstax://keep/", &other), invite());
        assert_eq!(parse_invite_link(PREFIX, &other), None);
        assert_eq!(parse_invite_link("axenstax://keep/", &link()), None);
    }

    #[test]
    fn whitespace_and_case_are_forgiven() {
        let upper = link().to_uppercase();
        assert_eq!(parse_invite_link(PREFIX, &format!("  \n{upper}\t \r\n")), invite());
        let mixed = link().replacen("stampede://keep", "StAmPeDe://KeEp", 1);
        assert_eq!(parse_invite_link(PREFIX, &mixed), invite());
    }

    #[test]
    fn a_bad_link_is_refused() {
        let good = link();
        let host = "ab".repeat(32);
        let secret = "01".repeat(32);
        let bad = [
            String::new(),
            "stampede://keep/".to_string(),
            good.replacen("stampede", "https", 1),
            good.replacen("keep", "room", 1),
            format!("stampede://keep/{host}"),
            format!("stampede://keep/{host}/"),
            format!("stampede://keep//{secret}"),
            format!("stampede://keep/{}/{secret}", &host[..62]),
            format!("stampede://keep/{host}/{}", &secret[..62]),
            format!("stampede://keep/{host}0/{secret}"),
            format!("stampede://keep/{}g/{secret}", &host[..63]),
            format!("stampede://keep/{host}/{}z", &secret[..63]),
            format!("{good}/extra"),
            format!("{good}#frag"),
            format!("{good} {good}"),
            format!("stampede://keep/{host}/{}\u{e9}", &secret[..62]),
            format!("twangthang://keep/{host}/{secret}"),
            "\u{e9}".repeat(18),
        ];
        for text in bad {
            assert_eq!(parse_invite_link(PREFIX, &text), None, "{text:?}");
        }
    }

    #[test]
    fn hex32_reads_either_case_and_nothing_else() {
        assert_eq!(parse_hex32(&"Ff".repeat(32)), Some([0xff; 32]));
        assert_eq!(parse_hex32(""), None);
        assert_eq!(parse_hex32(&"+1".repeat(32)), None);
        assert_eq!(parse_hex32(&"f".repeat(63)), None);
        assert_eq!(hex_encode(&[0, 15, 255]), "000fff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn an_invite_is_found_in_pasted_text() {
        let l = link();
        assert_eq!(invite_in_text(PREFIX, &l), Some(l.as_str()));
        assert_eq!(invite_in_text(PREFIX, &format!("\n {l}  \n")), Some(l.as_str()));
        assert_eq!(invite_in_text(PREFIX, &format!("Join my Keep: {l}.")), Some(l.as_str()));
        assert_eq!(invite_in_text(PREFIX, &format!("<{l}>")), Some(l.as_str()));
        assert_eq!(invite_in_text(PREFIX, &format!("(see {l})")), Some(l.as_str()));
        let upper = l.replacen("stampede://keep", "STAMPEDE://KEEP", 1);
        assert_eq!(invite_in_text(PREFIX, &format!("hi {upper}")), Some(upper.as_str()));
        // Whatever is found goes to the parser.
        assert_eq!(invite_in_text(PREFIX, &format!("Join my Keep: {l}.")).and_then(|w| parse_invite_link(PREFIX, w)), invite());
        // The first Keep link is the one read, even a bad one.
        let text = format!("try stampede://keep/short and then {l}");
        let first = invite_in_text(PREFIX, &text);
        assert_eq!(first, Some("stampede://keep/short"));
        assert_eq!(first.and_then(|w| parse_invite_link(PREFIX, w)), None);
        assert_eq!(invite_in_text(PREFIX, "stampede://keep/nope"), Some("stampede://keep/nope"));
        // A link cut short at the prefix is still a Keep link, so the caller can call it bad.
        assert_eq!(invite_in_text(PREFIX, "stampede://keep"), Some("stampede://keep"));
        assert_eq!(invite_in_text(PREFIX, "STAMPEDE://KEEP and more"), Some("STAMPEDE://KEEP"));
    }

    #[test]
    fn text_without_a_keep_link_finds_nothing() {
        for text in ["KWTQPM", "stampede://join#KWTQPM", "https://example.com/keeps", "stampede://keeper/x", "", "keep"] {
            assert_eq!(invite_in_text(PREFIX, text), None, "{text:?}");
        }
        let long = format!("{} {}", "x".repeat(5000), link());
        assert_eq!(invite_in_text(PREFIX, &long), None, "long text is not searched");
        // Non-ASCII text next to a prefix-sized slice does not panic.
        assert_eq!(invite_in_text(PREFIX, "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"), None);
    }

    #[test]
    fn a_prefix_without_a_trailing_slash_still_finds_links() {
        let p = "game:";
        let l = format_invite_link(p, &HOST, &SECRET);
        assert_eq!(invite_in_text(p, &format!("see {l}")), Some(l.as_str()));
        assert_eq!(parse_invite_link(p, &l), invite());
    }

    #[test]
    fn nothing_prints_the_secret() {
        let i = Invite { host_key: HOST, secret: SECRET };
        assert_eq!(format!("{i:?}"), "Invite(Keep ababab)");
        assert!(!format!("{i:?}").contains("0101"));
        assert_eq!(describe(&HOST), "ababab");
        assert_eq!(keep_id(&[0xab, 0xcd, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29]), "ABCDEF");
    }
}
