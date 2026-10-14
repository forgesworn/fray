//! Room codes and everything derived from them.
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

use argon2::{Algorithm, Argon2, Params, Version};
use nostr::{Keys, SecretKey};
use sha2::{Digest, Sha256};

/// The 24 letters a room code may use: no I (looks like L or 1) and no O
/// (looks like 0), no digits.
pub const ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const ALPHABET_LEN: u8 = 24;
/// Largest multiple of the alphabet length that fits in a byte: 240 = 10 * 24.
const SAMPLE_LIMIT: u8 = 240;
const _: () = assert!(ALPHABET.len() == ALPHABET_LEN as usize);
const _: () =
    assert!(SAMPLE_LIMIT.is_multiple_of(ALPHABET_LEN) && 255 - SAMPLE_LIMIT < ALPHABET_LEN);
/// Characters in a room code.
pub const CODE_LEN: usize = 6;
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

/// A fresh random code.
pub fn generate_code() -> String {
    code_from_bytes(|| {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).expect("OS RNG unavailable");
        b[0]
    })
}

/// Build a code from a source of random bytes. Rejection sampling keeps every
/// letter equally likely: 240 = 10 * 24, so bytes 240..=255 are discarded.
fn code_from_bytes(mut next: impl FnMut() -> u8) -> String {
    let alphabet = ALPHABET.as_bytes();
    let mut out = String::with_capacity(CODE_LEN);
    while out.len() < CODE_LEN {
        let b = next();
        if b < SAMPLE_LIMIT {
            out.push(alphabet[(b % ALPHABET_LEN) as usize] as char);
        }
    }
    out
}

/// Upper-case and validate a typed code. Spaces and dashes anywhere are
/// ignored (codes are shown as `KMT RWX`). `None` if it is not a valid code.
pub fn normalize_code(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if code.chars().count() != CODE_LEN || !code.chars().all(|c| ALPHABET.contains(c)) {
        return None;
    }
    Some(code)
}

/// Why a typed character was not taken into a code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedChar {
    /// A letter of the alphabet, upper-cased.
    Letter(char),
    /// A space or hyphen: ignored without comment.
    Ignored,
    /// Not allowed in a code (I, O, a digit, anything else).
    Rejected,
}

/// Judge one typed character: case-insensitive, spaces and hyphens ignored,
/// anything outside [`ALPHABET`] rejected (so the player is told as they type).
pub fn typed_char(c: char) -> TypedChar {
    if c.is_whitespace() || c == '-' {
        return TypedChar::Ignored;
    }
    let u = c.to_ascii_uppercase();
    if ALPHABET.contains(u) {
        TypedChar::Letter(u)
    } else {
        TypedChar::Rejected
    }
}

/// The hint shown when a character is rejected as typed.
pub fn rejected_hint(c: char) -> String {
    match c.to_ascii_uppercase() {
        'I' | 'O' => format!("Codes never use {}. Try again.", c.to_ascii_uppercase()),
        d if d.is_ascii_digit() => "Codes are letters only, no numbers.".to_string(),
        _ => "Codes are letters only.".to_string(),
    }
}

/// A normalised code for display: `ABC 123`.
pub fn display_code(code: &str) -> String {
    match code.char_indices().nth(3) {
        Some((i, _)) => format!("{} {}", &code[..i], &code[i..]),
        None => code.to_string(),
    }
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
    let m = master(app_tag, code, day)?;
    let tag = hex::encode(sub_key(TAG_LABEL, &m))[..32].to_string();
    // Fails only if the hash is zero or >= the curve order (probability ~2^-128).
    let sk =
        SecretKey::from_slice(&sub_key(KEY_LABEL, &m)).map_err(|e| format!("room key: {e}"))?;
    Ok(RoomSecrets {
        day,
        tag,
        keys: Keys::new(sk),
        admit: sub_key(ADMIT_LABEL, &m),
    })
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

    #[test]
    fn day_numbers_roll_at_utc_midnight() {
        assert_eq!(utc_day_number(0), 0);
        assert_eq!(utc_day_number(86_399), 0);
        assert_eq!(utc_day_number(86_400), 1);
        assert_eq!(utc_day_number(1_728_000_000), 20_000);
    }

    #[test]
    fn generated_codes_are_six_letters_of_the_alphabet() {
        assert_eq!(ALPHABET.len(), 24);
        assert!(!ALPHABET.contains('I') && !ALPHABET.contains('O'));
        assert!(ALPHABET.chars().all(|c| c.is_ascii_uppercase()));
        for _ in 0..200 {
            let c = generate_code();
            assert_eq!(c.len(), CODE_LEN);
            assert!(c.chars().all(|ch| ALPHABET.contains(ch)), "{c}");
            assert_eq!(normalize_code(&c).as_deref(), Some(c.as_str()), "{c}");
        }
    }

    /// Rejection sampling: every byte below 240 maps to a letter exactly ten
    /// times, and 240..=255 are discarded, so the distribution is flat.
    #[test]
    fn the_sampler_is_flat_over_every_byte() {
        let mut counts = [0u32; 24];
        for b in 0u16..=255 {
            let mut fed = false;
            let code = code_from_bytes(|| {
                if !fed {
                    fed = true;
                    b as u8
                } else {
                    0 // 'A' fills the other five places
                }
            });
            if b < 240 {
                let first = code.as_bytes()[0];
                counts[ALPHABET
                    .as_bytes()
                    .iter()
                    .position(|&a| a == first)
                    .unwrap()] += 1;
            } else {
                assert_eq!(
                    code, "AAAAAA",
                    "byte {b} is rejected, then the next bytes are used"
                );
            }
        }
        assert!(counts.iter().all(|&n| n == 10), "{counts:?}");
    }

    #[test]
    fn the_real_generator_is_roughly_flat() {
        let mut counts = [0u32; 24];
        for _ in 0..4000 {
            for ch in generate_code().bytes() {
                counts[ALPHABET.as_bytes().iter().position(|&a| a == ch).unwrap()] += 1;
            }
        }
        // 24000 letters, mean 1000 each (sd about 31): a loose five-sigma band.
        assert!(
            counts.iter().all(|&n| (840..=1160).contains(&n)),
            "{counts:?}"
        );
    }

    #[test]
    fn normalize_accepts_lower_case_spaces_and_hyphens() {
        assert_eq!(normalize_code(" kmtrwx ").as_deref(), Some("KMTRWX"));
        assert_eq!(normalize_code("kmt rwx").as_deref(), Some("KMTRWX"));
        assert_eq!(normalize_code("KMT-RWX").as_deref(), Some("KMTRWX"));
        assert_eq!(normalize_code("k m t - r w x").as_deref(), Some("KMTRWX"));
    }

    #[test]
    fn normalize_rejects_bad_input() {
        assert_eq!(normalize_code("KMTRW"), None, "too short");
        assert_eq!(normalize_code("KMTRWXY"), None, "too long");
        assert_eq!(normalize_code("KMTRWI"), None, "I is not in the alphabet");
        assert_eq!(normalize_code("KMTRWO"), None, "O is not in the alphabet");
        assert_eq!(normalize_code("kmtrwo"), None, "lower-case o is still O");
        assert_eq!(normalize_code("KMTRW2"), None, "no digits");
        assert_eq!(normalize_code("KMTRW0"), None);
        assert_eq!(normalize_code("KMTRWÉ"), None);
        assert_eq!(normalize_code("KMTRW_"), None);
        assert_eq!(normalize_code(""), None);
        assert_eq!(normalize_code("   "), None);
        // The old 31-character alphabet's codes are simply invalid now.
        assert_eq!(normalize_code("K7W3QP"), None);
    }

    #[test]
    fn typing_is_judged_a_character_at_a_time() {
        assert_eq!(typed_char('k'), TypedChar::Letter('K'));
        assert_eq!(typed_char('K'), TypedChar::Letter('K'));
        assert_eq!(typed_char(' '), TypedChar::Ignored);
        assert_eq!(typed_char('-'), TypedChar::Ignored);
        for bad in ['I', 'i', 'O', 'o', '0', '1', '7', '!', 'é'] {
            assert_eq!(typed_char(bad), TypedChar::Rejected, "{bad}");
        }
        assert_eq!(rejected_hint('o'), "Codes never use O. Try again.");
        assert_eq!(rejected_hint('I'), "Codes never use I. Try again.");
        assert_eq!(rejected_hint('3'), "Codes are letters only, no numbers.");
        assert_eq!(rejected_hint('!'), "Codes are letters only.");
    }

    #[test]
    fn display_groups_in_threes() {
        assert_eq!(display_code("KMTRWX"), "KMT RWX");
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
