//! IPv4 and IPv6 on one socket.
//!
//! Every QUIC socket this crate binds is **dual-stack**: `[::]:port` with
//! `IPV6_V6ONLY` off, so IPv6 peers and IPv4 peers both reach the one port the
//! candidates name. On such a socket an IPv4 peer appears as a v4-mapped
//! address (`::ffff:a.b.c.d`), and IPv4 destinations must be written that way
//! too. If the dual-stack bind fails (a kernel with IPv6 disabled, a sandbox),
//! the socket falls back to plain `0.0.0.0:port` and IPv6 is simply not on
//! offer.
//!
//! quinn maps IPv4 targets itself when its socket is IPv6, and refuses IPv6
//! targets on an IPv4 socket; the raw senders here (STUN, punches) go through
//! [`for_socket`] to do the same. Anything compared or shown goes through
//! [`canonical`] first, so `::ffff:10.0.0.5` is judged as the IPv4 `10.0.0.5`
//! it is.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

/// Bind a dual-stack UDP socket on `port` (0 = ephemeral), falling back to
/// IPv4-only if the dual-stack bind fails.
pub fn bind_dual_stack(port: u16) -> std::io::Result<UdpSocket> {
    match bind_v6_any(port) {
        Ok(s) => Ok(s),
        Err(e) => {
            log::info!("[nat] dual-stack bind of port {port} failed ({e}); IPv4 only");
            UdpSocket::bind(("0.0.0.0", port))
        }
    }
}

fn bind_v6_any(port: u16) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(false)?;
    // A platform that accepts the option but ignores it would leave a v6-only
    // socket advertising IPv4 candidates it can never receive on.
    if s.only_v6()? {
        return Err(std::io::Error::other("IPV6_V6ONLY could not be cleared"));
    }
    s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    Ok(s.into())
}

/// Whether `sock` is an IPv6 (dual-stack) socket.
pub fn is_v6_socket(sock: &UdpSocket) -> bool {
    sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false)
}

/// `a` with a v4-mapped IPv6 address turned back into the IPv4 address it is.
pub fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

/// `a` spelled the way a socket of the given family can send to it: an IPv4
/// target becomes v4-mapped on an IPv6 socket; an IPv6 target on an IPv4 socket
/// is unreachable (`None`).
pub fn for_socket(sock_is_v6: bool, a: SocketAddr) -> Option<SocketAddr> {
    match (sock_is_v6, canonical(a)) {
        (true, SocketAddr::V4(v4)) => Some(SocketAddr::new(
            IpAddr::V6(v4.ip().to_ipv6_mapped()),
            v4.port(),
        )),
        (true, v6 @ SocketAddr::V6(_)) => Some(v6),
        (false, v4 @ SocketAddr::V4(_)) => Some(v4),
        (false, SocketAddr::V6(_)) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mapped_addresses_canonicalise_to_ipv4() {
        assert_eq!(canonical(sa("[::ffff:10.0.0.5]:4000")), sa("10.0.0.5:4000"));
        assert_eq!(canonical(sa("10.0.0.5:4000")), sa("10.0.0.5:4000"));
        assert_eq!(
            canonical(sa("[2a00:1450::1]:4000")),
            sa("[2a00:1450::1]:4000")
        );
    }

    #[test]
    fn targets_are_spelled_for_the_socket_family() {
        assert_eq!(
            for_socket(true, sa("1.2.3.4:5")),
            Some(sa("[::ffff:1.2.3.4]:5"))
        );
        assert_eq!(for_socket(true, sa("[2a00::1]:5")), Some(sa("[2a00::1]:5")));
        assert_eq!(for_socket(false, sa("1.2.3.4:5")), Some(sa("1.2.3.4:5")));
        assert_eq!(
            for_socket(false, sa("[::ffff:1.2.3.4]:5")),
            Some(sa("1.2.3.4:5"))
        );
        assert_eq!(for_socket(false, sa("[2a00::1]:5")), None);
    }

    #[test]
    fn the_dual_stack_socket_answers_ipv4_and_ipv6() {
        let s = bind_dual_stack(0).unwrap();
        assert!(is_v6_socket(&s), "this machine supports dual-stack");
        let port = s.local_addr().unwrap().port();
        s.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 16];
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        v4.send_to(b"four", ("127.0.0.1", port)).unwrap();
        let (n, from) = s.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"four");
        assert_eq!(
            from.ip(),
            "::ffff:127.0.0.1".parse::<IpAddr>().unwrap(),
            "arrives v4-mapped"
        );
        assert_eq!(canonical(from), v4.local_addr().unwrap());
        // And the reply goes back through `for_socket`.
        s.send_to(b"back", for_socket(true, v4.local_addr().unwrap()).unwrap())
            .unwrap();
        v4.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let (n, _) = v4.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"back");
        if let Ok(v6) = UdpSocket::bind("[::1]:0") {
            v6.send_to(b"six", ("::1", port)).unwrap();
            let (n, from) = s.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"six");
            assert_eq!(from, v6.local_addr().unwrap());
        }
    }
}
