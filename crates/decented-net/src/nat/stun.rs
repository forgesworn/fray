//! A minimal RFC 5389 STUN client: send a Binding Request, read
//! XOR-MAPPED-ADDRESS out of the Binding Success Response.
//!
//! Hand-rolled — about 120 lines against a stable 2008 wire format, versus a
//! dependency whose async runtime and ICE machinery we would not use. The codec
//! is pure and pinned to the RFC 5769 test vectors; only `reflexive_address`
//! touches a socket.
//!
//! **The request goes out on the socket quinn will later own**, so the mapping
//! the STUN server reports is the one QUIC traffic will actually use. Non-QUIC
//! datagrams arriving on a quinn socket are dropped, which is why this runs
//! *before* the endpoint is created.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// RFC 5389 §6. Present in every message; also what distinguishes STUN from
/// the older RFC 3489 framing.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
const HEADER_LEN: usize = 20;

/// Public STUN servers used to learn this machine's reflexive address. Two, so
/// one being down is not the end of it. Neither is ours and neither ever sees
/// app traffic.
pub const STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StunError {
    TooShort,
    BadCookie,
    /// A well-formed STUN message that is not a Binding Success Response.
    NotSuccess(u16),
    TxidMismatch,
    NoXorMappedAddress,
    /// An attribute ran past the end of the buffer, or had an impossible length.
    BadAttribute,
}

/// 96 bits of transaction id, as RFC 5389 §6 requires.
pub fn random_txid() -> [u8; 12] {
    let mut t = [0u8; 12];
    getrandom::fill(&mut t).expect("OS RNG unavailable");
    t
}

/// A Binding Request with no attributes — all we need, and all we send.
pub fn encode_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txid);
    buf
}

/// `(message type, attribute length, transaction id)`.
pub fn parse_header(buf: &[u8]) -> Result<(u16, u16, [u8; 12]), StunError> {
    if buf.len() < HEADER_LEN {
        return Err(StunError::TooShort);
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadCookie);
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    Ok((msg_type, len, txid))
}

/// Decode one XOR-MAPPED-ADDRESS value (RFC 5389 §15.2): the port is XORed
/// with the top 16 bits of the cookie, an IPv4 address with the cookie, an IPv6
/// address with cookie‖txid.
fn decode_xor_mapped(value: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::BadAttribute);
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
    let cookie = MAGIC_COOKIE.to_be_bytes();
    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::BadAttribute);
            }
            let mut o = [0u8; 4];
            for i in 0..4 {
                o[i] = value[4 + i] ^ cookie[i];
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::BadAttribute);
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(txid);
            let mut o = [0u8; 16];
            for i in 0..16 {
                o[i] = value[4 + i] ^ key[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => Err(StunError::BadAttribute),
    }
}

/// Pull the reflexive address out of a Binding Success Response.
///
/// Attributes we don't use (SOFTWARE, MESSAGE-INTEGRITY, FINGERPRINT) are
/// skipped, which is what makes the RFC 5769 vectors — full of them — parse.
pub fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, StunError> {
    let (msg_type, attr_len, got_txid) = parse_header(buf)?;
    if msg_type != BINDING_SUCCESS {
        return Err(StunError::NotSuccess(msg_type));
    }
    if &got_txid != txid {
        return Err(StunError::TxidMismatch);
    }
    let end = HEADER_LEN
        .checked_add(attr_len as usize)
        .filter(|e| *e <= buf.len())
        .ok_or(StunError::TooShort)?;

    let mut i = HEADER_LEN;
    while i + 4 <= end {
        let a_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let a_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let value_start = i + 4;
        let value_end = value_start
            .checked_add(a_len)
            .ok_or(StunError::BadAttribute)?;
        if value_end > end {
            return Err(StunError::BadAttribute);
        }
        if a_type == ATTR_XOR_MAPPED_ADDRESS {
            return decode_xor_mapped(&buf[value_start..value_end], txid);
        }
        // Attributes are padded to a 4-byte boundary.
        i = value_end + ((4 - (a_len % 4)) % 4);
    }
    Err(StunError::NoXorMappedAddress)
}

/// The whole of `reflexive_address`, however many packets arrive.
///
/// `timeout` alone bounds each individual `recv_from`, and a stray packet
/// restarts it — so a sender who keeps the socket fed with junk keeps the loop
/// running for ever. This runs inside the ≤3 s candidate-gathering budget on
/// the preparation worker, and anybody who learns the port (it is in a
/// candidate list) could otherwise stall a player's attempt to host by doing
/// nothing cleverer than sending UDP at it.
pub const RECV_BUDGET: Duration = Duration::from_millis(1500);

/// Once one family has answered, how much longer [`reflexive_addresses`] waits
/// for the other. A STUN round trip is tens of milliseconds; a family that has
/// not answered by then is usually a broken route (an IPv6 path that sends but
/// never delivers), and must not hold up the join by a whole read timeout.
pub const OTHER_FAMILY_GRACE: Duration = Duration::from_millis(400);

/// OWNER BOUNDARY (needs the internet). Ask one STUN server what address this
/// socket appears to come from (over whichever family answers first). Blocking,
/// with `timeout` as the per-read deadline and [`RECV_BUDGET`] as the ceiling on
/// the whole call; restores the socket's previous read timeout before returning.
pub fn reflexive_address(
    sock: &UdpSocket,
    server: &str,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let r = reflexive_addresses(sock, &[server.to_string()], timeout);
    r.v4.or(r.v6).ok_or_else(|| r.errors.join("; "))
}

/// What the STUN servers reported, one address per family at most.
#[derive(Debug, Default)]
pub struct Reflexive {
    pub v4: Option<SocketAddr>,
    pub v6: Option<SocketAddr>,
    /// Why nothing came back, per server/family that failed (for the log).
    pub errors: Vec<String>,
}

/// OWNER BOUNDARY (needs the internet). Ask every STUN server in `servers`
/// (`host:port`), over IPv4 and — when `sock` is dual-stack and the name has an
/// AAAA record — over IPv6, what address this socket appears to come from.
///
/// All requests go out at once, each with its own transaction id, and **one**
/// receive loop collects the answers: two loops on one socket would each eat
/// the other's replies. It returns as soon as every family that was asked has
/// an answer, at most [`OTHER_FAMILY_GRACE`] after the first family answered,
/// and never later than [`RECV_BUDGET`], however much junk arrives.
pub fn reflexive_addresses(sock: &UdpSocket, servers: &[String], timeout: Duration) -> Reflexive {
    use std::net::ToSocketAddrs;
    let v6_sock = crate::nat::addr::is_v6_socket(sock);
    let mut out = Reflexive::default();
    // (txid, asked over IPv6, server name)
    let mut asked: Vec<([u8; 12], bool, &str)> = Vec::new();
    for server in servers {
        let resolved: Vec<SocketAddr> = match server.as_str().to_socket_addrs() {
            Ok(a) => a.collect(),
            Err(e) => {
                out.errors.push(format!("stun {server}: resolve: {e}"));
                continue;
            }
        };
        for want_v6 in [false, true] {
            let Some(dst) = resolved
                .iter()
                .find(|a| crate::nat::addr::canonical(**a).is_ipv6() == want_v6)
            else {
                continue;
            };
            let Some(dst) = crate::nat::addr::for_socket(v6_sock, *dst) else {
                continue;
            };
            let txid = random_txid();
            match sock.send_to(&encode_binding_request(&txid), dst) {
                Ok(_) => asked.push((txid, want_v6, server.as_str())),
                // No IPv6 route is the common case: not worth more than debug.
                Err(e) => out
                    .errors
                    .push(format!("stun send to {server} ({dst}): {e}")),
            }
        }
    }
    if asked.is_empty() {
        return out;
    }
    let want_v4 = asked.iter().any(|a| !a.1);
    let want_v6 = asked.iter().any(|a| a.1);

    let previous = sock.read_timeout().ok().flatten();
    let mut deadline = Instant::now() + RECV_BUDGET;
    let mut buf = [0u8; 1500];
    loop {
        if out.v4.is_some() || out.v6.is_some() {
            deadline = deadline.min(Instant::now() + OTHER_FAMILY_GRACE);
        }
        if (!want_v4 || out.v4.is_some()) && (!want_v6 || out.v6.is_some()) {
            break;
        }
        // The per-read timeout, clipped to whatever is left of the overall
        // budget. A zero-length timeout means "block for ever" to the OS, so
        // running out is a `break`, never a `set_read_timeout(0)`.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let silent: Vec<&str> = [
                (want_v4 && out.v4.is_none(), "IPv4"),
                (want_v6 && out.v6.is_none(), "IPv6"),
            ]
            .into_iter()
            .filter_map(|(missing, fam)| missing.then_some(fam))
            .collect();
            out.errors
                .push(format!("stun: no {} answer in time", silent.join("/")));
            break;
        }
        if let Err(e) = sock.set_read_timeout(Some(remaining.min(timeout))) {
            out.errors.push(format!("stun set timeout: {e}"));
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _from)) => {
                // Not one of our transactions (or not STUN at all): keep reading
                // until the deadline rather than giving up on a stray packet.
                let Ok((_, _, txid)) = parse_header(&buf[..n]) else {
                    continue;
                };
                let Some(&(_, over_v6, _)) = asked.iter().find(|a| a.0 == txid) else {
                    continue;
                };
                let Ok(addr) = parse_binding_response(&buf[..n], &txid) else {
                    continue;
                };
                let addr = crate::nat::addr::canonical(addr);
                // Each family's answer must be an address of that family.
                match (over_v6, addr) {
                    (false, SocketAddr::V4(_)) if out.v4.is_none() => out.v4 = Some(addr),
                    (true, SocketAddr::V6(_)) if out.v6.is_none() => out.v6 = Some(addr),
                    _ => {}
                }
            }
            Err(e) => {
                out.errors.push(format!("stun recv: {e}"));
                break;
            }
        }
    }
    let _ = sock.set_read_timeout(previous);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// RFC 5769 §2.1 "Sample Request", byte for byte.
    ///
    /// ```text
    ///    00 01 00 58     Request type and message length
    ///    21 12 a4 42     Magic cookie
    ///    b7 e7 a7 01     }
    ///    bc 34 d6 86     |  Transaction ID
    ///    fa 87 df ae     }
    ///    80 22 00 10     SOFTWARE attribute header
    ///    53 54 55 4e     }
    ///    20 74 65 73     |  User-agent...
    ///    74 20 63 6c     |  ...name
    ///    69 65 6e 74     }
    ///    00 24 00 04     PRIORITY attribute header
    ///    6e 00 01 ff     ICE priority value
    ///    80 29 00 08     ICE-CONTROLLED attribute header
    ///    93 2f f9 b1     }  Pseudo-random tie breaker...
    ///    51 26 3b 36     }   ...for ICE control
    ///    00 06 00 09     USERNAME attribute header
    ///    65 76 74 6a     }
    ///    3a 68 36 76     |  Username value (9 bytes) and padding (3 bytes)
    ///    59 20 20 20     }
    ///    00 08 00 14     MESSAGE-INTEGRITY attribute header
    ///    9a ea a7 0c     }
    ///    bf d8 cb 56     |
    ///    78 1e f2 b5     |  HMAC-SHA1 fingerprint
    ///    b2 d3 f2 49     |
    ///    c1 b5 71 a2     }
    ///    80 28 00 04     FINGERPRINT attribute header
    ///    e5 7a 3b cf     CRC32 fingerprint
    /// ```
    const RFC5769_SAMPLE_REQUEST_HEX: &str = concat!(
        "000100582112a442b7e7a701bc34d686fa87dfae",
        "802200105354554e207465737420636c69656e74",
        "002400046e0001ff",
        "80290008932ff9b151263b36",
        "000600096576746a3a68367659202020",
        "000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2",
        "80280004e57a3bcf",
    );

    /// RFC 5769 §2.2 "Sample IPv4 Response", byte for byte.
    ///
    /// ```text
    ///    01 01 00 3c     Response type and message length
    ///    21 12 a4 42     Magic cookie
    ///    b7 e7 a7 01     }
    ///    bc 34 d6 86     |  Transaction ID
    ///    fa 87 df ae     }
    ///    80 22 00 0b     SOFTWARE attribute header
    ///    74 65 73 74     }
    ///    20 76 65 63     |  UTF-8 server name
    ///    74 6f 72 20     }
    ///    00 20 00 08     XOR-MAPPED-ADDRESS attribute header
    ///    00 01 a1 47     Address family (IPv4) and xor'd mapped port number
    ///    e1 12 a6 43     Xor'd mapped IPv4 address
    ///    00 08 00 14     MESSAGE-INTEGRITY attribute header
    ///    2b 91 f5 99     }
    ///    fd 9e 90 c3     |
    ///    8c 74 89 f9     |  HMAC-SHA1 fingerprint
    ///    2a f9 ba 53     |
    ///    f0 6b e7 d7     }
    ///    80 28 00 04     FINGERPRINT attribute header
    ///    c0 7d 4c 96     CRC32 fingerprint
    /// ```
    ///
    /// The XOR-MAPPED-ADDRESS decodes to **192.0.2.1:32853**.
    const RFC5769_SAMPLE_IPV4_RESPONSE_HEX: &str = concat!(
        "0101003c2112a442b7e7a701bc34d686fa87dfae",
        "8022000b7465737420766563746f7220",
        "002000080001a147e112a643",
        "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7",
        "80280004c07d4c96",
    );

    /// The transaction ID both RFC 5769 samples use.
    const RFC5769_TXID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    fn bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("test vector is valid hex")
    }

    #[test]
    fn rfc5769_sample_request_header_parses() {
        let buf = bytes(RFC5769_SAMPLE_REQUEST_HEX);
        assert_eq!(buf.len(), 108, "20-byte header + 88 bytes of attributes");
        let (msg_type, len, txid) = parse_header(&buf).unwrap();
        assert_eq!(msg_type, BINDING_REQUEST);
        assert_eq!(len, 0x58);
        assert_eq!(txid, RFC5769_TXID);
        assert_eq!(len as usize, buf.len() - 20, "length covers the attributes");
    }

    #[test]
    fn rfc5769_sample_request_is_not_a_success_response() {
        let buf = bytes(RFC5769_SAMPLE_REQUEST_HEX);
        assert_eq!(
            parse_binding_response(&buf, &RFC5769_TXID),
            Err(StunError::NotSuccess(BINDING_REQUEST))
        );
    }

    #[test]
    fn rfc5769_sample_ipv4_response_yields_192_0_2_1_port_32853() {
        let buf = bytes(RFC5769_SAMPLE_IPV4_RESPONSE_HEX);
        assert_eq!(buf.len(), 80, "20-byte header + 60 bytes of attributes");
        let addr = parse_binding_response(&buf, &RFC5769_TXID).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853)
        );
    }

    #[test]
    fn a_response_for_another_transaction_is_refused() {
        let buf = bytes(RFC5769_SAMPLE_IPV4_RESPONSE_HEX);
        assert_eq!(
            parse_binding_response(&buf, &[0u8; 12]),
            Err(StunError::TxidMismatch)
        );
    }

    #[test]
    fn a_response_with_a_wrong_magic_cookie_is_refused() {
        let mut buf = bytes(RFC5769_SAMPLE_IPV4_RESPONSE_HEX);
        buf[4] = 0x00;
        assert_eq!(
            parse_binding_response(&buf, &RFC5769_TXID),
            Err(StunError::BadCookie)
        );
    }

    #[test]
    fn a_truncated_datagram_is_refused_without_panicking() {
        let full = bytes(RFC5769_SAMPLE_IPV4_RESPONSE_HEX);
        for cut in 0..20 {
            assert_eq!(parse_header(&full[..cut]), Err(StunError::TooShort));
        }
        // Truncated mid-attribute: the parser must stop, not read past the end.
        assert!(parse_binding_response(&full[..30], &RFC5769_TXID).is_err());
    }

    #[test]
    fn a_success_response_without_xor_mapped_address_is_refused() {
        // Header only, length 0 — a well-formed but useless success response.
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&RFC5769_TXID);
        assert_eq!(
            parse_binding_response(&buf, &RFC5769_TXID),
            Err(StunError::NoXorMappedAddress)
        );
    }

    #[test]
    fn an_ipv6_xor_mapped_address_decodes() {
        // Built by XOR-ing a known address with cookie‖txid here in the test,
        // so this asserts the parser's arithmetic rather than a hand-copied
        // constant. The IPv4 path is pinned to the real RFC vector above.
        let want_ip = Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0x11, 0x2233, 0x4455, 0x6677);
        let want_port: u16 = 32853;

        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&RFC5769_TXID);
        let mut xored = want_ip.octets();
        for (b, k) in xored.iter_mut().zip(key.iter()) {
            *b ^= k;
        }
        let xport = want_port ^ (MAGIC_COOKIE >> 16) as u16;

        let mut attr = vec![0x00, 0x02]; // reserved byte + family IPv6
        attr.extend_from_slice(&xport.to_be_bytes());
        attr.extend_from_slice(&xored);

        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&((4 + attr.len()) as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&RFC5769_TXID);
        buf.extend_from_slice(&0x0020u16.to_be_bytes());
        buf.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        buf.extend_from_slice(&attr);

        assert_eq!(
            parse_binding_response(&buf, &RFC5769_TXID).unwrap(),
            SocketAddr::new(IpAddr::V6(want_ip), want_port)
        );
    }

    #[test]
    fn our_binding_request_is_a_bare_20_byte_header() {
        let txid = random_txid();
        let req = encode_binding_request(&txid);
        assert_eq!(req.len(), 20, "no attributes: type, length 0, cookie, txid");
        let (msg_type, len, got) = parse_header(&req).unwrap();
        assert_eq!(msg_type, BINDING_REQUEST);
        assert_eq!(len, 0);
        assert_eq!(got, txid);
        assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
    }

    #[test]
    fn transaction_ids_differ_between_requests() {
        assert_ne!(random_txid(), random_txid());
    }

    /// REGRESSION (whole-branch review, MINOR 9). The read loop only had a
    /// PER-CALL timeout, and every stray packet restarted it — so anybody who
    /// could send UDP at the socket could hold the preparation worker for as
    /// long as they cared to keep sending, and the player's world never came up.
    #[test]
    fn a_continuous_flood_of_junk_cannot_hold_the_call_past_the_budget() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let responder = UdpSocket::bind("127.0.0.1:0").expect("bind the fake server");
        let responder_addr = responder.local_addr().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the client");
        let client_addr = sock.local_addr().unwrap();

        // A "STUN server" that answers with a steady stream of things that are
        // not a Binding Success Response for our transaction.
        let stop = Arc::new(AtomicBool::new(false));
        let flooder_stop = Arc::clone(&stop);
        let flooder = std::thread::spawn(move || {
            while !flooder_stop.load(Ordering::Relaxed) {
                let _ = responder.send_to(b"not stun at all, not even close", client_addr);
                std::thread::sleep(Duration::from_millis(1));
            }
        });

        let started = Instant::now();
        let res = reflexive_address(
            &sock,
            &responder_addr.to_string(),
            // A per-read timeout longer than the budget, to prove the budget is
            // what ends this and not the per-read timeout.
            Duration::from_secs(30),
        );
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        let _ = flooder.join();

        assert!(res.is_err(), "junk must never parse as an address: {res:?}");
        assert!(
            elapsed < RECV_BUDGET + Duration::from_millis(750),
            "the flood held the call for {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(500),
            "it must still wait for a real answer, not give up at once: {elapsed:?}"
        );
        // The read timeout the caller had before is put back either way.
        assert_eq!(sock.read_timeout().unwrap(), None);
    }

    /// A Binding Success Response for `txid` reporting `addr`.
    fn success(txid: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut v = vec![0u8];
        let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
        match addr.ip() {
            IpAddr::V4(ip) => {
                v.push(FAMILY_IPV4);
                v.extend_from_slice(&port.to_be_bytes());
                v.extend(ip.octets().iter().zip(cookie).map(|(a, b)| a ^ b));
            }
            IpAddr::V6(ip) => {
                v.push(FAMILY_IPV6);
                v.extend_from_slice(&port.to_be_bytes());
                let key: Vec<u8> = cookie.iter().chain(txid.iter()).copied().collect();
                v.extend(ip.octets().iter().zip(key).map(|(a, b)| a ^ b));
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        m.extend_from_slice(&((4 + v.len()) as u16).to_be_bytes());
        m.extend_from_slice(&cookie);
        m.extend_from_slice(txid);
        m.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        m.extend_from_slice(&(v.len() as u16).to_be_bytes());
        m.extend_from_slice(&v);
        m
    }

    /// A fake STUN server on `bind` that answers every request truthfully, or
    /// (`silent`) never answers. Runs until the test process ends.
    fn fake_server(bind: &str, silent: bool) -> SocketAddr {
        let s = UdpSocket::bind(bind).unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                let Ok((BINDING_REQUEST, _, txid)) = parse_header(&buf[..n]) else {
                    continue;
                };
                if !silent {
                    let _ = s.send_to(&success(&txid, from), from);
                }
            }
        });
        addr
    }

    #[test]
    fn a_dual_stack_socket_learns_both_families_in_one_pass() {
        if UdpSocket::bind("[::1]:0").is_err() {
            return; // no IPv6 loopback here
        }
        let v4 = fake_server("127.0.0.1:0", false);
        let v6 = fake_server("[::1]:0", false);
        let sock = crate::nat::addr::bind_dual_stack(0).unwrap();
        let port = sock.local_addr().unwrap().port();
        let r = reflexive_addresses(
            &sock,
            &[v4.to_string(), v6.to_string()],
            Duration::from_secs(1),
        );
        assert_eq!(
            r.v4,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            "{r:?}"
        );
        assert_eq!(
            r.v6,
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)),
            "{r:?}"
        );
        // An IPv4-only socket never asks over IPv6.
        let sock4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let r = reflexive_addresses(
            &sock4,
            &[v6.to_string(), v4.to_string()],
            Duration::from_secs(1),
        );
        assert!(r.v4.is_some() && r.v6.is_none(), "{r:?}");
    }

    #[test]
    fn a_silent_family_costs_only_the_grace_window() {
        if UdpSocket::bind("[::1]:0").is_err() {
            return;
        }
        let v4 = fake_server("127.0.0.1:0", false);
        let dead_v6 = fake_server("[::1]:0", true);
        let sock = crate::nat::addr::bind_dual_stack(0).unwrap();
        let started = Instant::now();
        // A per-read timeout past the whole budget: without the grace window
        // the silent family would hold the call for all of RECV_BUDGET.
        let r = reflexive_addresses(
            &sock,
            &[v4.to_string(), dead_v6.to_string()],
            Duration::from_secs(5),
        );
        let took = started.elapsed();
        assert!(r.v4.is_some() && r.v6.is_none(), "{r:?}");
        // Slack for a loaded test machine, still well short of the budget.
        assert!(
            took < OTHER_FAMILY_GRACE + Duration::from_millis(700),
            "held for {took:?}"
        );
        assert!(OTHER_FAMILY_GRACE + Duration::from_millis(700) < RECV_BUDGET);
    }
}
