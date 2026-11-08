//! The starter game's own byte protocol, encoded by hand.
//!
//! Fray carries opaque bytes. What they mean is the game's business, so this
//! module is the game's side of the contract: four messages, each a tag byte
//! followed by fixed little-endian fields.
//!
//! | Tag | Message | Channel | Direction | Layout after the tag |
//! |---|---|---|---|---|
//! | `0x01` | [`Message::Hello`] | reliable | client to host | version `u8`, name length `u8`, name bytes |
//! | `0x02` | [`Message::Welcome`] | reliable | host to client | player number `u8` |
//! | `0x10` | [`Message::Position`] | datagram | client to host | sequence `u16`, x `i16`, y `i16` |
//! | `0x11` | [`Message::State`] | datagram | host to client | tick `u16`, count `u8`, then per player: number `u8`, x `i16`, y `i16` |

use fray_net::Bytes;

/// Version of this game's protocol (not Fray's). Sent in every hello.
pub const PROTOCOL_VERSION: u8 = 1;
/// Longest player name, in bytes.
pub const MAX_NAME_LEN: usize = 32;

const TAG_HELLO: u8 = 0x01;
const TAG_WELCOME: u8 = 0x02;
const TAG_POSITION: u8 = 0x10;
const TAG_STATE: u8 = 0x11;

/// One player as the host reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlayerState {
    /// Player number. The host is 0; remote players count up from 1.
    pub player: u8,
    pub x: i16,
    pub y: i16,
}

/// Every message the game sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Hello {
        name: String,
    },
    Welcome {
        player: u8,
    },
    Position {
        seq: u16,
        x: i16,
        y: i16,
    },
    State {
        tick: u16,
        players: Vec<PlayerState>,
    },
}

/// Why a frame could not be read. Bytes from a peer are untrusted input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Empty,
    UnknownTag(u8),
    Truncated,
    TrailingBytes,
    /// The sender speaks a different version of the game's protocol.
    Version(u8),
    /// Empty, too long, not UTF-8, or containing control characters.
    BadName,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Empty => write!(f, "empty message"),
            DecodeError::UnknownTag(t) => write!(f, "unknown message tag {t:#04x}"),
            DecodeError::Truncated => write!(f, "message ends too soon"),
            DecodeError::TrailingBytes => write!(f, "message has extra bytes"),
            DecodeError::Version(v) => write!(
                f,
                "protocol version {v}, this game speaks {PROTOCOL_VERSION}"
            ),
            DecodeError::BadName => write!(f, "player name is not acceptable"),
        }
    }
}

/// A name the game accepts: 1 to [`MAX_NAME_LEN`] bytes, no control characters.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && !name.chars().any(char::is_control)
}

impl Message {
    /// The bytes to hand to Fray. A `Hello` with an unacceptable name is cut
    /// to the longest acceptable prefix, so encoding never produces a frame
    /// the other side refuses for its length.
    pub fn encode(&self) -> Bytes {
        let mut out = Vec::new();
        match self {
            Message::Hello { name } => {
                out.push(TAG_HELLO);
                out.push(PROTOCOL_VERSION);
                let mut end = name.len().min(MAX_NAME_LEN);
                while !name.is_char_boundary(end) {
                    end -= 1;
                }
                out.push(end as u8);
                out.extend_from_slice(&name.as_bytes()[..end]);
            }
            Message::Welcome { player } => {
                out.push(TAG_WELCOME);
                out.push(*player);
            }
            Message::Position { seq, x, y } => {
                out.push(TAG_POSITION);
                out.extend_from_slice(&seq.to_le_bytes());
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            Message::State { tick, players } => {
                out.push(TAG_STATE);
                out.extend_from_slice(&tick.to_le_bytes());
                // At most 9 players ever exist, so the count fits in a byte.
                out.push(players.len().min(usize::from(u8::MAX)) as u8);
                for p in players.iter().take(usize::from(u8::MAX)) {
                    out.push(p.player);
                    out.extend_from_slice(&p.x.to_le_bytes());
                    out.extend_from_slice(&p.y.to_le_bytes());
                }
            }
        }
        Bytes::from(out)
    }

    /// Read one frame. The whole slice must be consumed.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let mut r = Reader(bytes);
        let message = match r.u8().ok_or(DecodeError::Empty)? {
            TAG_HELLO => {
                let version = r.u8().ok_or(DecodeError::Truncated)?;
                if version != PROTOCOL_VERSION {
                    return Err(DecodeError::Version(version));
                }
                let len = usize::from(r.u8().ok_or(DecodeError::Truncated)?);
                let raw = r.take(len).ok_or(DecodeError::Truncated)?;
                let name = std::str::from_utf8(raw).map_err(|_| DecodeError::BadName)?;
                if !valid_name(name) {
                    return Err(DecodeError::BadName);
                }
                Message::Hello {
                    name: name.to_string(),
                }
            }
            TAG_WELCOME => Message::Welcome {
                player: r.u8().ok_or(DecodeError::Truncated)?,
            },
            TAG_POSITION => Message::Position {
                seq: r.u16().ok_or(DecodeError::Truncated)?,
                x: r.i16().ok_or(DecodeError::Truncated)?,
                y: r.i16().ok_or(DecodeError::Truncated)?,
            },
            TAG_STATE => {
                let tick = r.u16().ok_or(DecodeError::Truncated)?;
                let count = r.u8().ok_or(DecodeError::Truncated)?;
                let mut players = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    players.push(PlayerState {
                        player: r.u8().ok_or(DecodeError::Truncated)?,
                        x: r.i16().ok_or(DecodeError::Truncated)?,
                        y: r.i16().ok_or(DecodeError::Truncated)?,
                    });
                }
                Message::State { tick, players }
            }
            other => return Err(DecodeError::UnknownTag(other)),
        };
        if r.0.is_empty() {
            Ok(message)
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Whether `seq` is newer than `last` on a counter that wraps at 65536.
/// Datagrams can arrive late or out of order; a stale one is dropped.
pub fn is_newer(seq: u16, last: u16) -> bool {
    let ahead = seq.wrapping_sub(last);
    ahead != 0 && ahead < 0x8000
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn i16(&mut self) -> Option<i16> {
        self.take(2).map(|b| i16::from_le_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(m: Message) {
        assert_eq!(Message::decode(&m.encode()), Ok(m));
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(Message::Hello { name: "Ada".into() });
        round_trip(Message::Welcome { player: 3 });
        round_trip(Message::Position {
            seq: 65535,
            x: -300,
            y: 12,
        });
        round_trip(Message::State {
            tick: 7,
            players: vec![
                PlayerState {
                    player: 0,
                    x: 1,
                    y: -1,
                },
                PlayerState {
                    player: 2,
                    x: i16::MAX,
                    y: i16::MIN,
                },
            ],
        });
        round_trip(Message::State {
            tick: 0,
            players: vec![],
        });
    }

    #[test]
    fn bytes_are_exactly_as_documented() {
        assert_eq!(
            &Message::Hello { name: "Al".into() }.encode()[..],
            &[0x01, 1, 2, b'A', b'l']
        );
        assert_eq!(&Message::Welcome { player: 5 }.encode()[..], &[0x02, 5]);
        assert_eq!(
            &Message::Position {
                seq: 0x0102,
                x: 0x0304,
                y: -1
            }
            .encode()[..],
            &[0x10, 0x02, 0x01, 0x04, 0x03, 0xff, 0xff]
        );
    }

    #[test]
    fn bad_frames_are_refused_not_trusted() {
        assert_eq!(Message::decode(&[]), Err(DecodeError::Empty));
        assert_eq!(Message::decode(&[0x7f]), Err(DecodeError::UnknownTag(0x7f)));
        assert_eq!(Message::decode(&[0x02]), Err(DecodeError::Truncated));
        assert_eq!(
            Message::decode(&[0x02, 1, 0]),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(
            Message::decode(&[0x01, 9, 1, b'a']),
            Err(DecodeError::Version(9))
        );
        assert_eq!(
            Message::decode(&[0x01, 1, 0]),
            Err(DecodeError::BadName),
            "empty name"
        );
        assert_eq!(
            Message::decode(&[0x01, 1, 2, 0xff, 0xfe]),
            Err(DecodeError::BadName),
            "not UTF-8"
        );
        assert_eq!(
            Message::decode(&[0x01, 1, 2, b'a', 0x1b]),
            Err(DecodeError::BadName),
            "control character"
        );
        assert_eq!(
            Message::decode(&[0x01, 1, 5, b'a']),
            Err(DecodeError::Truncated)
        );
        // A state frame that promises two players but carries one.
        assert_eq!(
            Message::decode(&[0x11, 0, 0, 2, 1, 0, 0, 0, 0]),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn long_names_are_cut_on_a_character_boundary() {
        let name = "é".repeat(MAX_NAME_LEN); // two bytes each
        let Ok(Message::Hello { name: got }) = Message::decode(&Message::Hello { name }.encode())
        else {
            panic!("a cut name still decodes");
        };
        assert_eq!(got, "é".repeat(MAX_NAME_LEN / 2));
    }

    #[test]
    fn newer_handles_wrap_around() {
        assert!(is_newer(1, 0));
        assert!(!is_newer(0, 0));
        assert!(!is_newer(0, 1));
        assert!(is_newer(0, 65535), "wrapped past the end");
        assert!(!is_newer(65535, 0), "a stale one from before the wrap");
    }

    #[test]
    fn the_largest_state_fits_a_datagram() {
        let players = (0..=u8::MAX)
            .take(9)
            .map(|player| PlayerState { player, x: 0, y: 0 })
            .collect();
        let bytes = Message::State { tick: 0, players }.encode();
        assert!(bytes.len() <= fray_net::MAX_LOSSY_LEN);
    }
}
