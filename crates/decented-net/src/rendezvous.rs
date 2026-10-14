//! Offer / answer types and their NIP-44 envelopes.
//!
//! - **Offer** (kind [`KIND_JOIN_OFFER`]): signed by the joiner's identity key,
//!   NIP-44 encrypted to the code-derived room key, tagged `#t = room tag`.
//!   Carries the joiner's pubkey, its candidates and the protocol version.
//! - **Answer** (kind [`KIND_JOIN_ANSWER`]): signed by the room's throwaway
//!   relay key, NIP-44 encrypted to the joiner's throwaway key, tagged
//!   `#p = joiner`. Carries the host's candidates, echoes the session id and,
//!   inside the ciphertext, names the host's identity key, which the joiner
//!   then requires to sign the welcome (so relays never see the identity).
//!
//! Relays only ever see these sealed setup events; app traffic never touches
//! them. Everything that comes off a relay is untrusted until `open_*` passed.
//!
//! Adapted from Axe'n'Stax `rendezvous/payload.rs` + `verify.rs` (MIT).

use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag};

pub const KIND_JOIN_OFFER: u16 = 20910;
pub const KIND_JOIN_ANSWER: u16 = 20911;
/// Offers/answers further than this from our clock are dropped.
pub const CLOCK_SKEW_SECS: u64 = 120;
/// Ciphertext larger than this is not even decrypted.
const MAX_CONTENT_LEN: usize = 16 * 1024;

/// One address a peer might be reachable at. `kind` is `lan | v6 | upnp | stun`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Candidate {
    pub kind: String,
    pub addr: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    /// Net protocol version ([`crate::NET_PROTOCOL_VERSION`]).
    pub v: u32,
    /// Joiner-chosen id for this join attempt; the answer echoes it.
    pub session: String,
    /// The joiner's pubkey (hex). Must equal the event's signer.
    pub pubkey: String,
    pub candidates: Vec<Candidate>,
    pub sent_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Answer {
    pub v: u32,
    pub session: String,
    pub accepted: bool,
    /// When refused: `full`, `closed` or `version`.
    pub reason: Option<String>,
    pub candidates: Vec<Candidate>,
    pub sent_at: u64,
    /// The host's long-term identity key (hex). Only the joiner can read it;
    /// a code joiner refuses a welcome signed by any other key, so whoever
    /// terminates its QUIC dial must hold this identity, not just name the
    /// (public) relay key. Defaults to empty so a v2 host's refusal still
    /// reads as a version mismatch; an accepted answer without a valid key
    /// fails the join closed (`HostUnverified`).
    #[serde(default)]
    pub host_pubkey: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RendezvousError {
    BadSignature,
    WrongKind,
    TooLarge,
    Decrypt(String),
    Parse(String),
    PubkeyMismatch,
    Stale(i128),
    WrongSession,
    /// The session id is not 32 lowercase hex characters.
    BadSession,
}

/// A session id is exactly 32 lowercase hex characters ([`new_session_id`]).
pub fn valid_session(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// At most this many candidates are read from an offer or answer.
pub const MAX_CANDIDATES: usize = 8;

/// 16 random bytes, hex.
pub fn new_session_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    hex::encode(b)
}

fn seal<T: serde::Serialize>(
    sender: &Keys,
    recipient: &PublicKey,
    kind: u16,
    tag: Tag,
    payload: &T,
) -> Result<Event, String> {
    let json = serde_json::to_string(payload).map_err(|e| format!("serialise payload: {e}"))?;
    let ciphertext = nostr::nips::nip44::encrypt(
        sender.secret_key(),
        recipient,
        json,
        nostr::nips::nip44::Version::V2,
    )
    .map_err(|e| format!("nip44 encrypt: {e}"))?;
    EventBuilder::new(Kind::Custom(kind), ciphertext)
        .tags([tag])
        .sign_with_keys(sender)
        .map_err(|e| format!("sign: {e}"))
}

fn open<T: serde::de::DeserializeOwned>(
    recipient: &Keys,
    ev: &Event,
    kind: u16,
) -> Result<T, RendezvousError> {
    if ev.kind != Kind::Custom(kind) {
        return Err(RendezvousError::WrongKind);
    }
    if ev.content.len() > MAX_CONTENT_LEN {
        return Err(RendezvousError::TooLarge);
    }
    if ev.verify().is_err() {
        return Err(RendezvousError::BadSignature);
    }
    let json = nostr::nips::nip44::decrypt(recipient.secret_key(), &ev.pubkey, &ev.content)
        .map_err(|e| RendezvousError::Decrypt(e.to_string()))?;
    serde_json::from_str(&json).map_err(|e| RendezvousError::Parse(e.to_string()))
}

fn fresh(sent_at: u64, now: u64) -> Result<(), RendezvousError> {
    // i128: `sent_at` is attacker-controlled and unbounded.
    let delta = sent_at as i128 - now as i128;
    if delta.abs() > CLOCK_SKEW_SECS as i128 {
        return Err(RendezvousError::Stale(delta));
    }
    Ok(())
}

pub fn seal_offer(
    joiner: &Keys,
    room_pubkey: &PublicKey,
    room_tag: &str,
    offer: &Offer,
) -> Result<Event, String> {
    let tag = Tag::parse([
        crate::room::ROOM_TAG_LETTER.to_string(),
        room_tag.to_string(),
    ])
    .map_err(|e| format!("tag: {e}"))?;
    seal(joiner, room_pubkey, KIND_JOIN_OFFER, tag, offer)
}

/// Verify, decrypt and check an offer addressed to the room key.
pub fn open_offer(room: &Keys, ev: &Event, now: u64) -> Result<Offer, RendezvousError> {
    let mut offer: Offer = open(room, ev, KIND_JOIN_OFFER)?;
    if offer.pubkey != ev.pubkey.to_hex() {
        return Err(RendezvousError::PubkeyMismatch);
    }
    if !valid_session(&offer.session) {
        return Err(RendezvousError::BadSession);
    }
    fresh(offer.sent_at, now)?;
    offer.candidates.truncate(MAX_CANDIDATES);
    Ok(offer)
}

pub fn seal_answer(host: &Keys, joiner: &PublicKey, answer: &Answer) -> Result<Event, String> {
    seal(
        host,
        joiner,
        KIND_JOIN_ANSWER,
        Tag::public_key(*joiner),
        answer,
    )
}

/// Verify, decrypt and check an answer to our offer `session`.
pub fn open_answer(
    joiner: &Keys,
    ev: &Event,
    session: &str,
    now: u64,
) -> Result<Answer, RendezvousError> {
    let mut answer: Answer = open(joiner, ev, KIND_JOIN_ANSWER)?;
    if answer.session != session {
        return Err(RendezvousError::WrongSession);
    }
    fresh(answer.sent_at, now)?;
    answer.candidates.truncate(MAX_CANDIDATES);
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::room::derive;

    fn offer(joiner: &Keys, now: u64) -> Offer {
        Offer {
            v: crate::NET_PROTOCOL_VERSION,
            session: new_session_id(),
            pubkey: joiner.public_key().to_hex(),
            candidates: vec![Candidate {
                kind: "lan".into(),
                addr: "192.168.1.2:5000".into(),
            }],
            sent_at: now,
        }
    }

    #[test]
    fn offer_seal_open_round_trip() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let secrets = derive("twangthang", "ABCDEF", 20_000).unwrap();
        let (room, tag) = (secrets.keys, secrets.tag);
        let o = offer(&joiner, now);
        let ev = seal_offer(&joiner, &room.public_key(), &tag, &o).unwrap();
        assert_eq!(ev.kind, Kind::Custom(20910));
        assert_eq!(ev.pubkey, joiner.public_key());
        // The tag is the single-letter `t` with the room tag value, and the
        // content is not plaintext.
        let t: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert_eq!(t, vec![vec!["t".to_string(), tag.clone()]]);
        assert!(!ev.content.contains("192.168"));
        assert_eq!(open_offer(&room, &ev, now).unwrap(), o);
    }

    #[test]
    fn an_offer_for_another_code_does_not_open() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let room = Keys::generate();
        let other = Keys::generate();
        let ev = seal_offer(&joiner, &room.public_key(), "x", &offer(&joiner, now)).unwrap();
        assert!(matches!(
            open_offer(&other, &ev, now),
            Err(RendezvousError::Decrypt(_))
        ));
    }

    #[test]
    fn an_offer_naming_someone_else_is_rejected() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let room = Keys::generate();
        let mut o = offer(&joiner, now);
        o.pubkey = Keys::generate().public_key().to_hex();
        let ev = seal_offer(&joiner, &room.public_key(), "x", &o).unwrap();
        assert_eq!(
            open_offer(&room, &ev, now),
            Err(RendezvousError::PubkeyMismatch)
        );
    }

    #[test]
    fn a_stale_offer_is_rejected() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let room = Keys::generate();
        let ev = seal_offer(&joiner, &room.public_key(), "x", &offer(&joiner, now - 600)).unwrap();
        assert!(matches!(
            open_offer(&room, &ev, now),
            Err(RendezvousError::Stale(_))
        ));
    }

    #[test]
    fn a_tampered_offer_fails_the_signature() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let room = Keys::generate();
        let ev = seal_offer(&joiner, &room.public_key(), "x", &offer(&joiner, now)).unwrap();
        let mut v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        v["content"] = serde_json::Value::String(format!("{}A", ev.content));
        let forged: Event = serde_json::from_value(v).unwrap();
        assert_eq!(
            open_offer(&room, &forged, now),
            Err(RendezvousError::BadSignature)
        );
    }

    #[test]
    fn answer_seal_open_round_trip_and_session_check() {
        let now = crate::unix_now();
        let host = Keys::generate();
        let joiner = Keys::generate();
        let a = Answer {
            v: crate::NET_PROTOCOL_VERSION,
            session: "s1".into(),
            accepted: true,
            reason: None,
            candidates: vec![Candidate {
                kind: "stun".into(),
                addr: "203.0.113.9:4000".into(),
            }],
            sent_at: now,
            host_pubkey: Keys::generate().public_key().to_hex(),
        };
        let ev = seal_answer(&host, &joiner.public_key(), &a).unwrap();
        assert_eq!(ev.kind, Kind::Custom(20911));
        let t: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert_eq!(t, vec![vec!["p".to_string(), joiner.public_key().to_hex()]]);
        assert_eq!(open_answer(&joiner, &ev, "s1", now).unwrap(), a);
        assert_eq!(
            open_answer(&joiner, &ev, "s2", now),
            Err(RendezvousError::WrongSession)
        );
        let eve = Keys::generate();
        assert!(matches!(
            open_answer(&eve, &ev, "s1", now),
            Err(RendezvousError::Decrypt(_))
        ));
        assert!(
            !ev.content.contains(&a.host_pubkey),
            "the host identity is inside the ciphertext"
        );
    }

    #[test]
    fn an_offer_with_a_malformed_session_is_rejected() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let room = Keys::generate();
        // A multi-byte char straddling byte 8 once panicked the host's log line.
        for bad in [
            "aaaaaaa\u{20AC}bbbb",
            "",
            "ABCDEF0123456789ABCDEF0123456789",
            &"a".repeat(33),
            &"a".repeat(2_000),
        ] {
            let mut o = offer(&joiner, now);
            o.session = bad.to_string();
            let ev = seal_offer(&joiner, &room.public_key(), "x", &o).unwrap();
            assert_eq!(
                open_offer(&room, &ev, now),
                Err(RendezvousError::BadSession),
                "{bad:.20}"
            );
        }
        assert!(valid_session(&new_session_id()));
    }

    /// (d) The longest candidate list a host can produce (every slot a full
    /// IPv6 address) seals into an answer the joiner opens whole: nothing is
    /// truncated and the ciphertext stays far inside the size limit.
    #[test]
    fn an_answer_full_of_v6_candidates_fits_and_opens_whole() {
        let now = crate::unix_now();
        let host = Keys::generate();
        let joiner = Keys::generate();
        let mut raw: Vec<Candidate> = (0..30)
            .map(|i| Candidate {
                kind: "v6".into(),
                addr: format!("[2a00:1450:4009:81f:ffff:ffff:ffff:{i:04x}]:65535"),
            })
            .collect();
        raw.push(Candidate {
            kind: "upnp".into(),
            addr: "255.255.255.254:65535".into(),
        });
        raw.push(Candidate {
            kind: "stun".into(),
            addr: "254.255.255.255:65535".into(),
        });
        raw.push(Candidate {
            kind: "stun".into(),
            addr: "[2a00:1450:4009:81f:ffff:ffff:fffe:ffff]:65535".into(),
        });
        raw.push(Candidate {
            kind: "lan".into(),
            addr: "192.168.255.255:65535".into(),
        });
        let candidates = crate::nat::candidates::sort_candidates(raw);
        assert!(candidates.len() <= MAX_CANDIDATES);
        let a = Answer {
            v: crate::NET_PROTOCOL_VERSION,
            session: new_session_id(),
            accepted: true,
            reason: None,
            candidates,
            sent_at: now,
            host_pubkey: Keys::generate().public_key().to_hex(),
        };
        let ev = seal_answer(&host, &joiner.public_key(), &a).unwrap();
        assert!(
            ev.content.len() < MAX_CONTENT_LEN / 4,
            "{} bytes",
            ev.content.len()
        );
        let opened = open_answer(&joiner, &ev, &a.session, now).unwrap();
        assert_eq!(
            opened.candidates, a.candidates,
            "nothing cut by the reader's cap"
        );
        let kinds: Vec<&str> = opened.candidates.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, vec!["lan", "v6", "v6", "upnp", "stun", "stun"]);
    }

    #[test]
    fn an_offer_is_not_an_answer() {
        let now = crate::unix_now();
        let joiner = Keys::generate();
        let room = Keys::generate();
        let ev = seal_offer(&joiner, &room.public_key(), "x", &offer(&joiner, now)).unwrap();
        assert_eq!(
            open_answer(&room, &ev, "s", now),
            Err(RendezvousError::WrongKind)
        );
    }
}
