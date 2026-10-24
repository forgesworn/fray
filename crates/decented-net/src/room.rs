//! Room codes and everything derived from them. The code format itself
//! (alphabet, generating, normalising, typing hints, display) lives in
//! `fray_session::code` and is re-exported here.
//!
//! A code is 6 letters from [`ALPHABET`] (24 letters: no I, no O, no digits),
//! shown as two groups of three (`KMT RWX`). From the code and a UTC day
//! number the crate derives, with **Argon2id** (19 MiB, t=2, p=1):
//!
//! ```text
//! master = Argon2id(password = code, salt = "<app_tag>-room-v3:<utc_day>", 32 bytes)
//! tag    = hex(sha256("decented-net/room-v2/tag\0" || master))[..32]
//! sk     = sha256("decented-net/room-v2/key\0" || master)
//! admit  = sha256("decented-net/room-v2/admit\0" || master)
//! ```
//!
//! - `tag` is the value of the single-letter `#t` tag a joiner's kind-20910
//!   offer carries and the host subscribes to;
//! - `sk` is the secret of the **room keypair** offers are NIP-44 encrypted to;
//! - `admit` is the code's **admission token**: a joiner proves it in its QUIC
//!   hello (bound to the TLS session, never sent in the clear), and the host
//!   admits nobody without a valid proof.
//!
//! The salt is `"<app_tag>-room-v3:" + utc_day_number`, with the app's own tag
//! (the app passes it; this crate has no default). (v3 changed the alphabet
//! and the salt; the sub-key labels below keep their `room-v2` names, which
//! only have to stay distinct from each other.)
//!
//! The memory-hard KDF plus the daily salt mean a relay observer who wants to
//! map tags back to codes must redo an expensive sweep of the whole code space
//! every day, instead of one sha256 pass for all time. See `SECURITY.md`.
//!
//! # Invites
//!
//! A host can also be reached by **invite**: a 32-byte random secret the host
//! hands out (in a link, next to its public key). It runs through the same
//! rendezvous as a code and is expanded by the same `tag` / `sk` / `admit`
//! step, but its master secret needs no memory-hard KDF, because the secret
//! is already high-entropy:
//!
//! ```text
//! master = sha256("<app_tag>-invite-v1:" || utc_day (decimal) || ":" || secret)
//! tag, sk, admit = the same sub-keys of `master` as for a code
//! ```
//!
//! A code's master is an Argon2id output and an invite's is a sha256 over a
//! different, labelled input, so one can never yield the other's tag, key or
//! admission token (the two inputs are disjoint, and a clash would be a
//! sha256 / Argon2id collision). The link carries the secret and the host's
//! key, never an address. See [`derive_invite`] and [`InviteId`].

use argon2::{Algorithm, Argon2, Params, Version};
use nostr::{Keys, SecretKey};
use sha2::{Digest, Sha256};

pub use fray_session::code::{
    display_code, generate_code, normalize_code, rejected_hint, typed_char, TypedChar, ALPHABET,
    CODE_LEN,
};

/// The single-letter tag name offers are filtered on.
pub const ROOM_TAG_LETTER: char = 't';

/// Argon2id memory cost in KiB (19 MiB).
pub const KDF_M_KIB: u32 = 19 * 1024;
/// Argon2id passes.
pub const KDF_T: u32 = 2;
/// Argon2id lanes.
pub const KDF_P: u32 = 1;

const SECS_PER_DAY: u64 = 86_400;
const TAG_LABEL: &[u8] = b"decented-net/room-v2/tag\0";
const KEY_LABEL: &[u8] = b"decented-net/room-v2/key\0";
const ADMIT_LABEL: &[u8] = b"decented-net/room-v2/admit\0";
const INVITE_ID_LABEL: &[u8] = b"decented-net/invite-v1/id\0";

/// A fresh invite secret: 32 bytes from the OS random number generator, the
/// only kind [`HostHandle::add_invite`](crate::HostHandle::add_invite) should
/// be given. Every relay tag, key and admission token of an invite is derived
/// from it with a plain hash (no stretching, unlike a code), so a secret that
/// is not uniformly random can be guessed offline.
pub fn generate_invite_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).expect("OS RNG unavailable");
    secret
}

/// Days since the Unix epoch, UTC.
pub fn utc_day_number(unix_secs: u64) -> u64 {
    unix_secs / SECS_PER_DAY
}

/// Today's UTC day number by the local clock.
pub fn utc_today() -> u64 {
    utc_day_number(crate::unix_now())
}

/// What a code yields on one UTC day.
#[derive(Clone, Debug)]
pub struct RoomSecrets {
    pub day: u64,
    /// The `#t` tag value.
    pub tag: String,
    /// The room keypair offers are encrypted to.
    pub keys: Keys,
    /// The admission token for this code and day.
    pub admit: [u8; 32],
}

/// The Argon2id master secret for `code` on `day`. `code` must already be
/// normalised. Deliberately slow: call it off the async threads.
fn master(app_tag: &str, code: &str, day: u64) -> Result<[u8; 32], String> {
    let params =
        Params::new(KDF_M_KIB, KDF_T, KDF_P, Some(32)).map_err(|e| format!("kdf params: {e}"))?;
    let salt = format!("{app_tag}-room-v3:{day}");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(code.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|e| format!("kdf: {e}"))?;
    Ok(out)
}

fn sub_key(label: &[u8], master: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(master);
    h.finalize().into()
}

/// Derive the room tag and room keypair for `code` on UTC `day`.
pub fn derive(app_tag: &str, code: &str, day: u64) -> Result<RoomSecrets, String> {
    expand(day, &master(app_tag, code, day)?)
}

/// The tag, room keypair and admission token of one master secret. Shared by
/// codes and invites, so both rendezvous the same way.
fn expand(day: u64, m: &[u8; 32]) -> Result<RoomSecrets, String> {
    let tag = hex::encode(sub_key(TAG_LABEL, m))[..32].to_string();
    // Fails only if the hash is zero or >= the curve order (probability ~2^-128).
    let sk = SecretKey::from_slice(&sub_key(KEY_LABEL, m)).map_err(|e| format!("room key: {e}"))?;
    Ok(RoomSecrets {
        day,
        tag,
        keys: Keys::new(sk),
        admit: sub_key(ADMIT_LABEL, m),
    })
}

/// Names an invite without revealing it: the first 16 bytes of
/// `sha256("decented-net/invite-v1/id\0" || secret)`. Safe to log, to keep in
/// a list and to show; it cannot be turned back into the secret and is not
/// used in any tag, key or token. Displays as 32 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InviteId(pub [u8; 16]);

impl InviteId {
    /// The id of the invite whose secret is `secret`.
    pub fn of(secret: &[u8; 32]) -> InviteId {
        let mut h = Sha256::new();
        h.update(INVITE_ID_LABEL);
        h.update(secret);
        let digest: [u8; 32] = h.finalize().into();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        InviteId(id)
    }
}

impl std::fmt::Display for InviteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::fmt::Debug for InviteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InviteId({})", hex::encode(self.0))
    }
}

/// The sha256 master secret for an invite on `day` (no KDF: the secret is
/// 256 random bits, so there is nothing to sweep).
fn invite_master(app_tag: &str, secret: &[u8; 32], day: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(app_tag.as_bytes());
    h.update(b"-invite-v1:");
    h.update(day.to_string().as_bytes());
    h.update(b":");
    h.update(secret);
    h.finalize().into()
}

/// The same tag / room keypair / admission token as [`derive()`] yields for a
/// code, from an invite's `secret` on UTC `day`. Cheap (a few hashes and one
/// key derivation), so it needs no thread of its own. Fails only if the room
/// key hash is zero or at least the curve order (probability about 2^-128).
pub fn derive_invite(app_tag: &str, secret: &[u8; 32], day: u64) -> Result<RoomSecrets, String> {
    expand(day, &invite_master(app_tag, secret, day))
}

/// [`derive_invite`] for `day` and `day - 1`. Today first.
pub(crate) fn derive_invite_days(
    app_tag: &str,
    secret: &[u8; 32],
    day: u64,
) -> Result<Vec<RoomSecrets>, String> {
    Ok(vec![
        derive_invite(app_tag, secret, day)?,
        derive_invite(app_tag, secret, day.saturating_sub(1))?,
    ])
}

/// [`derive`] for `day` and `day - 1`, off the async threads. Today first.
pub(crate) async fn derive_days(
    app_tag: &str,
    code: &str,
    day: u64,
) -> Result<Vec<RoomSecrets>, String> {
    let (app, c) = (app_tag.to_string(), code.to_string());
    tokio::task::spawn_blocking(move || {
        Ok(vec![
            derive(&app, &c, day)?,
            derive(&app, &c, day.saturating_sub(1))?,
        ])
    })
    .await
    .map_err(|e| format!("kdf task: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 20_000; // 2024-10-04

    // Computed independently with the reference C implementation (libargon2
    // via Python argon2-cffi, `hash_secret_raw(type=ID, version=19)`) plus
    // hashlib sha256 for the sub-keys, salt `"twangthang-room-v3:" + day`.
    // They pin the derivation: changing it would silently split builds onto
    // different tags.
    const VEC_TAG_KMTRWX: &str = "a35cd293777f51a50ab6eba108f871ec";
    const VEC_SK_KMTRWX: &str = "59c8b9b80a96e48fbf031cbb85a5d1254038c22e7ebd7f6f8e0376f716a59487";
    const VEC_ADMIT_KMTRWX: &str =
        "834eb63417d4ec180df4730e475a5226c4bdd6912b0dee7ce2eabcc0cfcb2e38";
    const VEC_TAG_ZZZZZZ: &str = "9ad05e7905debf1e5e0b8e3f24ab5c2a";
    const VEC_SK_ZZZZZZ: &str = "56b725e71a092757b848a4808c9ff078cb3a65245a2836bec8d9973b7b9b7fc5";

    #[test]
    fn kdf_vectors() {
        let s = derive("twangthang", "KMTRWX", DAY).unwrap();
        let z = derive("twangthang", "ZZZZZZ", DAY + 1).unwrap();
        assert_eq!(s.day, DAY);
        assert_eq!(s.tag, VEC_TAG_KMTRWX);
        assert_eq!(s.keys.secret_key().to_secret_hex(), VEC_SK_KMTRWX);
        assert_eq!(hex::encode(s.admit), VEC_ADMIT_KMTRWX);
        assert_eq!(z.tag, VEC_TAG_ZZZZZZ);
        assert_eq!(z.keys.secret_key().to_secret_hex(), VEC_SK_ZZZZZZ);
    }

    #[test]
    fn a_typed_code_derives_the_same_room_as_the_normalised_one() {
        let typed = normalize_code("kmt-rwx").unwrap();
        assert_eq!(
            derive("twangthang", &typed, DAY).unwrap().tag,
            VEC_TAG_KMTRWX
        );
    }

    #[test]
    fn the_day_the_app_tag_and_the_code_all_change_the_result() {
        let base = derive("twangthang", "KMTRWX", DAY).unwrap();
        for other in [
            derive("twangthang", "KMTRWX", DAY + 1).unwrap(),
            derive("other", "KMTRWX", DAY).unwrap(),
            derive("twangthang", "KMTRWY", DAY).unwrap(),
        ] {
            assert_ne!(base.tag, other.tag);
            assert_ne!(base.keys.public_key(), other.keys.public_key());
        }
        // Tag, key and admission token are domain-separated sub-keys.
        assert!(!base
            .keys
            .secret_key()
            .to_secret_hex()
            .starts_with(&base.tag));
        assert!(!hex::encode(base.admit).starts_with(&base.tag));
        assert_ne!(
            hex::encode(base.admit),
            base.keys.secret_key().to_secret_hex()
        );
        assert_eq!(base.tag.len(), 32);
    }

    // Computed independently with Python hashlib (sha256 only; no KDF), from
    // the secret bytes 0, 1, ..., 31 and app tag "twangthang". They pin the
    // invite derivation the same way the Argon2id vectors pin the code one.
    const INVITE_SECRET: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const VEC_INVITE_TAG: &str = "585946a782eccb636b97ec0faa661a41";
    const VEC_INVITE_SK: &str = "5b8a6da7953515232b268493befacaff41120fbe828372a5f36c40ca298c0128";
    const VEC_INVITE_ADMIT: &str =
        "2f23b1215969cfb4e2013a9813176f8f7eb31638481f9b0c59ceff2433232671";
    const VEC_INVITE_TAG_NEXT_DAY: &str = "276cbc5d94e959d344ec4086755570be";
    const VEC_INVITE_ID: &str = "874845c19fe6ecd329f42ecd01441c55";

    #[test]
    fn invite_vectors() {
        let s = derive_invite("twangthang", &INVITE_SECRET, DAY).unwrap();
        assert_eq!(s.day, DAY);
        assert_eq!(s.tag, VEC_INVITE_TAG);
        assert_eq!(s.keys.secret_key().to_secret_hex(), VEC_INVITE_SK);
        assert_eq!(hex::encode(s.admit), VEC_INVITE_ADMIT);
        let next = derive_invite("twangthang", &INVITE_SECRET, DAY + 1).unwrap();
        assert_eq!(next.tag, VEC_INVITE_TAG_NEXT_DAY);
        assert_eq!(InviteId::of(&INVITE_SECRET).to_string(), VEC_INVITE_ID);
        assert_eq!(
            format!("{:?}", InviteId::of(&INVITE_SECRET)),
            format!("InviteId({VEC_INVITE_ID})")
        );
    }

    #[test]
    fn invite_days_are_today_then_yesterday() {
        let d = derive_invite_days("twangthang", &INVITE_SECRET, DAY).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!((d[0].day, d[1].day), (DAY, DAY - 1));
        assert_eq!(d[0].tag, VEC_INVITE_TAG);
        assert_ne!(d[0].tag, d[1].tag);
    }

    #[test]
    fn an_invite_never_yields_a_code_rooms_tag_key_or_token() {
        let code = derive("twangthang", "KMTRWX", DAY).unwrap();
        // Whatever the invite secret: unrelated bytes, a code's own derived
        // values fed in as the secret, or the code's letters padded out.
        let mut padded = [0u8; 32];
        padded[..6].copy_from_slice(b"KMTRWX");
        for secret in [INVITE_SECRET, code.admit, padded, [0u8; 32], [0xff; 32]] {
            let inv = derive_invite("twangthang", &secret, DAY).unwrap();
            assert_ne!(inv.tag, code.tag);
            assert_ne!(inv.keys.public_key(), code.keys.public_key());
            assert_ne!(inv.admit, code.admit);
        }
    }

    #[test]
    fn the_day_the_app_tag_and_the_secret_all_change_an_invite() {
        let base = derive_invite("twangthang", &INVITE_SECRET, DAY).unwrap();
        let mut other_secret = INVITE_SECRET;
        other_secret[31] ^= 1;
        for other in [
            derive_invite("twangthang", &INVITE_SECRET, DAY + 1).unwrap(),
            derive_invite("other", &INVITE_SECRET, DAY).unwrap(),
            derive_invite("twangthang", &other_secret, DAY).unwrap(),
        ] {
            assert_ne!(base.tag, other.tag);
            assert_ne!(base.keys.public_key(), other.keys.public_key());
            assert_ne!(base.admit, other.admit);
        }
        // Tag, key and token are domain-separated sub-keys, as for a code.
        assert_ne!(
            hex::encode(base.admit),
            base.keys.secret_key().to_secret_hex()
        );
        assert!(!hex::encode(base.admit).starts_with(&base.tag));
    }

    #[test]
    fn an_invite_id_names_the_secret_and_reveals_nothing_of_it() {
        let a = InviteId::of(&INVITE_SECRET);
        assert_eq!(a, InviteId::of(&INVITE_SECRET));
        let mut other = INVITE_SECRET;
        other[0] ^= 1;
        assert_ne!(a, InviteId::of(&other));
        let rooms = derive_invite_days("twangthang", &INVITE_SECRET, DAY).unwrap();
        let shown = a.to_string();
        assert_eq!(shown.len(), 32);
        for r in &rooms {
            assert_ne!(shown, r.tag, "the id is not the tag");
            assert!(!hex::encode(r.admit).starts_with(&shown));
        }
        assert!(!shown.contains(&hex::encode(INVITE_SECRET)[..8]));
    }

    #[test]
    fn day_numbers_roll_at_utc_midnight() {
        assert_eq!(utc_day_number(0), 0);
        assert_eq!(utc_day_number(86_399), 0);
        assert_eq!(utc_day_number(86_400), 1);
        assert_eq!(utc_day_number(1_728_000_000), 20_000);
    }

    #[test]
    fn generated_invite_secrets_are_fresh_and_32_bytes() {
        let secrets: std::collections::HashSet<[u8; 32]> =
            (0..64).map(|_| generate_invite_secret()).collect();
        assert_eq!(secrets.len(), 64, "a repeated secret");
        assert!(secrets.iter().all(|s| s.iter().any(|b| *b != 0)));
        // Usable as an invite: it derives a room.
        let s = generate_invite_secret();
        assert!(derive_invite("t", &s, 20_000).is_ok());
    }

    /// Cost of one derivation on this machine. Run with
    /// `cargo test -p decented-net kdf_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn kdf_cost() {
        let n = 20;
        let t = std::time::Instant::now();
        for i in 0..n {
            derive("twangthang", "KMTRWX", DAY + i).unwrap();
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0 / n as f64;
        println!("KDF: {ms:.1} ms per derivation (Argon2id m={KDF_M_KIB} KiB t={KDF_T} p={KDF_P})");
    }
}
