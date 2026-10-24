//! The room-code format: the 24-letter alphabet, generating a code, and
//! normalising, hinting and displaying a typed one. Pure functions; the keys
//! and secrets derived from a code live in `fray-net`'s `room` module.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
