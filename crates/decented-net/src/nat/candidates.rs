//! Every address this machine might be reachable at, in the order worth trying.
//!
//! All four kinds are gathered on **one already-bound UDP socket** — the socket
//! quinn will be handed — so the port a peer is told to dial is the port QUIC
//! will actually answer on. That is why `gather` takes a `&UdpSocket` rather
//! than binding its own.
//!
//! Addresses are personal data. They exist here, inside NIP-44 ciphertext on
//! the wire, and nowhere else.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::rendezvous::Candidate;

/// The four ways a peer might reach this machine.
///
/// **Declaration order is priority order** and `Ord` is derived from it: same
/// house first (fastest and always works), then a real global IPv6 (no NAT to
/// fight), then a mapping the router agreed to, then whatever the NAT is doing
/// today. Do not reorder these variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateKind {
    Lan,
    V6,
    Upnp,
    Stun,
}

impl CandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateKind::Lan => "lan",
            CandidateKind::V6 => "v6",
            CandidateKind::Upnp => "upnp",
            CandidateKind::Stun => "stun",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "lan" => Some(CandidateKind::Lan),
            "v6" => Some(CandidateKind::V6),
            "upnp" => Some(CandidateKind::Upnp),
            "stun" => Some(CandidateKind::Stun),
            _ => None,
        }
    }
}

/// At most this many candidates of any one kind are offered. With four kinds
/// that is exactly [`MAX_CANDIDATE_ADDRS`]: a machine with a pile of global
/// IPv6 addresses cannot push its own UPnP and STUN (IPv4) entries off the end
/// of the list the peer will read, which would cost the v4 fallback exactly the
/// carrier-NAT peers IPv6 is meant to help.
pub const MAX_PER_KIND: usize = 2;

// Every kind must keep its share of the list: a fifth kind (NAT-PMP) must
// lower MAX_PER_KIND or raise the cap, or `truncate` silently drops `stun`.
const _: () = assert!(MAX_PER_KIND * 4 <= MAX_CANDIDATE_ADDRS);

/// Priority order, de-duplicated by address (a v4-mapped spelling is the same
/// address as the plain IPv4 one), at most [`MAX_PER_KIND`] of each kind and
/// [`MAX_CANDIDATE_ADDRS`] in all, so the list fits what the peer will read.
///
/// An unrecognised kind sorts last rather than being dropped: a future build
/// may add one (NAT-PMP is the planned next), and an address we don't have a
/// name for is still an address worth trying.
pub fn sort_candidates(list: Vec<Candidate>) -> Vec<Candidate> {
    let mut list = list;
    list.sort_by_key(|c| {
        CandidateKind::parse(&c.kind)
            .map(|k| k as u8)
            .unwrap_or(u8::MAX)
    });
    for c in &mut list {
        if let Ok(a) = c.addr.parse::<SocketAddr>() {
            c.addr = crate::nat::addr::canonical(a).to_string();
        }
    }
    let mut seen: Vec<String> = Vec::new();
    let mut per_kind: Vec<(String, usize)> = Vec::new();
    list.retain(|c| {
        if seen.contains(&c.addr) {
            return false;
        }
        let n = match per_kind.iter_mut().find(|(k, _)| *k == c.kind) {
            Some((_, n)) => n,
            None => {
                per_kind.push((c.kind.clone(), 0));
                &mut per_kind.last_mut().expect("just pushed").1
            }
        };
        if *n >= MAX_PER_KIND {
            return false;
        }
        *n += 1;
        seen.push(c.addr.clone());
        true
    });
    list.truncate(MAX_CANDIDATE_ADDRS);
    list
}

/// Whether anything here could plausibly work from outside the house. Drives
/// a host-side "friends outside your network may not reach you" warning.
pub fn reachable_beyond_lan(list: &[Candidate]) -> bool {
    list.iter().any(|c| {
        matches!(
            CandidateKind::parse(&c.kind),
            Some(CandidateKind::V6 | CandidateKind::Upnp | CandidateKind::Stun)
        )
    })
}

/// How many of a peer's addresses are ever acted on.
///
/// The candidate list arrives inside somebody else's ciphertext, so its length
/// is chosen by them, not by us. Both sides then *send packets* to every
/// address in it — the host punches at them, the joiner dials them — which
/// makes an uncapped list a packet reflector: one offer naming ten thousand
/// addresses turns this machine into the source of ten thousand datagrams
/// aimed wherever the sender liked. Eight is comfortably more than the four
/// kinds [`CandidateKind`] can produce, and it is applied on both sides.
pub const MAX_CANDIDATE_ADDRS: usize = 8;

/// The dialable addresses, in order, at most [`MAX_CANDIDATE_ADDRS`] of them,
/// v4-mapped ones spelled as the IPv4 addresses they are. Unparseable entries
/// are skipped — one garbled candidate must not cost the peer the rest.
pub fn parse_addrs(list: &[Candidate]) -> Vec<SocketAddr> {
    list.iter()
        .filter_map(|c| c.addr.parse::<SocketAddr>().ok())
        .map(crate::nat::addr::canonical)
        .take(MAX_CANDIDATE_ADDRS)
        .collect()
}

/// Most IPv4 addresses the host will punch towards for one offer.
pub const MAX_PUNCH_TARGETS: usize = 4;
/// Most IPv6 addresses the host will punch towards for one offer, on top of
/// the IPv4 ones. A stateful IPv6 firewall (every mobile carrier, most home
/// routers) only lets the joiner's dial in once the host has sent outwards.
pub const MAX_PUNCH_TARGETS_V6: usize = 2;

/// Where it is safe to send unsolicited punch packets for a peer's candidate
/// list (which came from someone who merely knows the room code):
///
/// - v4-mapped addresses are judged as the IPv4 addresses they are;
/// - `lan` candidates only inside one of this machine's own IPv4 subnets;
/// - every other kind only to a globally routable IPv4 address, or a global
///   unicast IPv6 address ([`is_global_v6`]);
/// - never to a port below 1024 (QUIC sockets are ephemeral), and never more
///   than [`MAX_PUNCH_TARGETS`] IPv4 plus [`MAX_PUNCH_TARGETS_V6`] IPv6 of
///   them.
///
/// This keeps the host from being used to spray packets at its own router or
/// at third parties. The joiner dials the host anyway; punches only help NATs.
pub fn punch_targets(list: &[Candidate]) -> Vec<SocketAddr> {
    // Local interfaces only: a VPN's subnet is not "the same house".
    let subnets = crate::ifaces::subnets(&crate::ifaces::lan_interfaces());
    punch_targets_within(list, &subnets)
}

pub(crate) fn punch_targets_within(
    list: &[Candidate],
    subnets: &[(Ipv4Addr, Ipv4Addr)],
) -> Vec<SocketAddr> {
    let in_subnet = |ip: Ipv4Addr| {
        subnets.iter().any(|(net, mask)| {
            let m = u32::from(*mask);
            m != 0 && u32::from(ip) & m == u32::from(*net) & m && ip != *net
        })
    };
    let (mut v4s, mut v6s) = (0, 0);
    let mut out: Vec<SocketAddr> = Vec::new();
    for c in list {
        let Ok(a) = c.addr.parse::<SocketAddr>() else {
            continue;
        };
        // Canonical first: `[::ffff:10.0.0.5]` must meet the private-v4 rule.
        let a = crate::nat::addr::canonical(a);
        if a.port() < 1024 || out.contains(&a) {
            continue;
        }
        let lan = c.kind == CandidateKind::Lan.as_str();
        match a.ip() {
            IpAddr::V4(ip) => {
                let ok = if lan {
                    ip.is_private() && in_subnet(ip)
                } else {
                    is_global_v4(ip)
                };
                if ok && v4s < MAX_PUNCH_TARGETS {
                    v4s += 1;
                    out.push(a);
                }
            }
            IpAddr::V6(ip) => {
                if !lan && is_global_v6(ip) && v6s < MAX_PUNCH_TARGETS_V6 {
                    v6s += 1;
                    out.push(a);
                }
            }
        }
    }
    out
}

/// A global unicast IPv6 address a peer in another house could reach: inside
/// 2000::/3, and not one of the special-purpose blocks carved out of it —
/// 2001::/23 (Teredo, benchmarking, ORCHID, …), 2001:db8::/32 and 3fff::/20
/// (documentation), 2002::/16 (6to4). Everything outside 2000::/3 is out too:
/// loopback, unspecified, v4-mapped and NAT64 (`64:ff9b::/96`), link-local
/// fe80::/10, unique-local fc00::/7, site-local, multicast.
pub fn is_global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23 IETF protocol assignments (incl. Teredo)
        && !(s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        && s[0] != 0x2002 // 6to4
        && (s[0] & 0xfff0) != 0x3ff0 // 3fff::/20 documentation
}

/// Whether the interface identifier is a modified EUI-64 built from the
/// network card's MAC address (`…:xxff:fexx:…`). Such an address names the
/// hardware on every network it joins, so it is never offered.
pub fn is_eui64(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[11] == 0xff && o[12] == 0xfe
}

/// Whether `ip` is an address of the local network (or this device), the only
/// kind a LAN candidate may name and the only kind a hooked LAN endpoint
/// serves: IPv4 RFC 1918 and link-local 169.254/16; IPv6 fe80::/10 and
/// fc00::/7; loopback (the same device, never reachable from outside).
/// Public addresses and CGNAT (100.64/10) are not.
pub fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_lan_ip(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                (first & 0xffc0) == 0xfe80 || (first & 0xfe00) == 0xfc00 || v6.is_loopback()
            }
        },
    }
}

/// A unicast IPv4 address on the public internet.
pub fn is_global_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24 protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18)) // 198.18/15 benchmarking
}

/// The IPv4 address to offer as the `lan` candidate: a real local interface
/// (Wi-Fi or Ethernet), never a VPN's. With a VPN up the kernel's default route
/// (see [`routed_outbound_v4`]) sources from the tunnel, so that address is
/// only used when it belongs to a local interface; otherwise the best local
/// interface is picked ([`crate::ifaces::pick_lan_ip`]).
pub fn local_outbound_v4() -> Option<Ipv4Addr> {
    crate::ifaces::pick_lan_ip(&crate::ifaces::lan_interfaces(), routed_outbound_v4())
}

/// What the kernel's default route sources IPv4 from, by the routing-table
/// trick: `connect` a throwaway UDP socket at a public address (no packet is
/// sent) and read back which local address the kernel chose. Under a VPN this
/// is the tunnel's address, which is why it is not used on its own.
fn routed_outbound_v4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?; // TEST-NET-1: routable, never answers
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local() => {
            Some(v4)
        }
        _ => None,
    }
}

/// The same trick over IPv6, and the same rejection of anything that isn't a
/// real global address ([`is_global_v6`]) — a link-local, unique-local or
/// loopback answer is no use to a peer in another house.
///
/// This is the address the kernel **sources** traffic from (RFC 6724 source
/// selection), so it is the one our punches leave from and the one a stateful
/// firewall opens a pinhole for. Where privacy extensions are on (Android, and
/// Linux with `use_tempaddr = 2`) it is the rotating temporary address.
pub fn local_outbound_v6() -> Option<Ipv6Addr> {
    let s = UdpSocket::bind("[::]:0").ok()?;
    s.connect("[2001:db8::1]:9").ok()?; // documentation prefix: no packet is sent
    match s.local_addr().ok()?.ip() {
        IpAddr::V6(v6) if offerable_v6(v6) => Some(v6),
        _ => None,
    }
}

/// Whether this machine may offer `ip` to a peer: a global unicast address
/// ([`is_global_v6`]) that is not MAC-derived ([`is_eui64`]). Applied to
/// **every** IPv6 address we offer, whichever way it was learned (the routing
/// trick or a STUN server reflecting our source back).
pub fn offerable_v6(ip: Ipv6Addr) -> bool {
    is_global_v6(ip) && !is_eui64(ip)
}

/// The IPv6 candidates for a dual-stack socket on `port`, from the address the
/// kernel sources from (`outbound`, [`local_outbound_v6`]) and the address a
/// STUN server saw (`stun_v6`). Pure, so the filter is testable anywhere.
///
/// Only the outbound address is offered as `v6`: it is the one a stateful
/// firewall opens for, and any other interface address (a stable sibling in the
/// same /64, a deprecated temporary, another network's or a VPN's underlying
/// address) buys no connectivity and leaks something (review-ipv6-1 I2). The
/// STUN answer goes in only when it passes the same filter (I1); without NAT66
/// it equals the outbound address and de-duplicates away.
pub fn v6_candidates(
    outbound: Option<Ipv6Addr>,
    stun_v6: Option<SocketAddr>,
    port: u16,
) -> Vec<Candidate> {
    let mut out = Vec::new();
    if let Some(ip) = outbound.filter(|ip| offerable_v6(*ip)) {
        out.push(Candidate {
            kind: CandidateKind::V6.as_str().to_string(),
            addr: SocketAddr::new(IpAddr::V6(ip), port).to_string(),
        });
    }
    if let Some(a) = stun_v6 {
        if matches!(a.ip().to_canonical(), IpAddr::V6(ip) if offerable_v6(ip)) {
            out.push(Candidate {
                kind: CandidateKind::Stun.as_str().to_string(),
                addr: a.to_string(),
            });
        }
    }
    out
}

/// `list` with its `v6` entry replaced by the current `outbound` address
/// (review-ipv6-1 I3): temporary addresses rotate about daily, and after a
/// rotation the kernel sources (and punches) from the new one, so a room open
/// for hours must not keep advertising the old one. One `connect()` syscall
/// per answer; STUN is not re-run.
pub fn refresh_v6(list: &[Candidate], outbound: Option<Ipv6Addr>, port: u16) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = list
        .iter()
        .filter(|c| c.kind != CandidateKind::V6.as_str())
        .cloned()
        .collect();
    out.extend(v6_candidates(outbound, None, port));
    sort_candidates(out)
}

/// The answer's candidates the **joiner** will punch and dial
/// (review-ipv6-1 I4). The list comes from whoever answered the code first,
/// so it must not aim the joiner's packets anywhere it likes:
///
/// - never a port below 1024, multicast, broadcast, unspecified, link-local,
///   documentation or reserved addresses, in either family;
/// - private, carrier-NAT, unique-local and loopback addresses only as `lan`
///   candidates (the LAN path offered them: same house, or same machine);
/// - every other kind only to a globally routable address.
///
/// Returned canonical (v4-mapped spelled as IPv4) and capped at
/// [`MAX_CANDIDATE_ADDRS`], in the answer's order.
pub fn dialable(list: &[Candidate]) -> Vec<Candidate> {
    list.iter()
        .filter_map(|c| {
            let a = crate::nat::addr::canonical(c.addr.parse::<SocketAddr>().ok()?);
            let lan = c.kind == CandidateKind::Lan.as_str();
            let ok = a.port() >= 1024
                && match a.ip() {
                    IpAddr::V4(ip) => {
                        let o = ip.octets();
                        let local_only = ip.is_private()
                            || ip.is_loopback()
                            || (o[0] == 100 && (o[1] & 0xc0) == 64);
                        is_global_v4(ip) || (lan && local_only)
                    }
                    IpAddr::V6(ip) => {
                        let ula = (ip.octets()[0] & 0xfe) == 0xfc;
                        is_global_v6(ip) || (lan && (ula || ip.is_loopback()))
                    }
                };
            ok.then(|| Candidate {
                kind: c.kind.clone(),
                addr: a.to_string(),
            })
        })
        .take(MAX_CANDIDATE_ADDRS)
        .collect()
}

/// Gather every candidate for `sock`.
///
/// `upnp` is a mapping already obtained by [`crate::nat::upnp::map_port`] (the
/// caller owns it, because it must be renewed and removed on a schedule this
/// function knows nothing about). `stun` lists `host:port` servers, all asked
/// at once over IPv4 and (on a dual-stack socket) IPv6; the first answer per
/// family wins. `stun_timeout` is the per-read deadline.
///
/// IPv6 candidates are offered only when `sock` is dual-stack: an IPv4-only
/// socket could never answer them.
pub fn gather(
    sock: &UdpSocket,
    upnp: Option<SocketAddr>,
    stun: &[String],
    stun_timeout: Duration,
) -> Vec<Candidate> {
    let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut out: Vec<Candidate> = Vec::new();

    if let Some(v4) = local_outbound_v4() {
        out.push(Candidate {
            kind: CandidateKind::Lan.as_str().to_string(),
            addr: SocketAddr::new(IpAddr::V4(v4), port).to_string(),
        });
    } else if let Ok(local) = sock.local_addr() {
        // Loopback-bound (tests) or an unusual box: still name the socket, so a
        // same-machine or same-namespace peer has something to dial. A wildcard
        // bind is named as IPv4 loopback, which either kind of socket can dial.
        let local = crate::nat::addr::canonical(local);
        let ip = if local.ip().is_unspecified() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            local.ip()
        };
        out.push(Candidate {
            kind: CandidateKind::Lan.as_str().to_string(),
            addr: SocketAddr::new(ip, port).to_string(),
        });
    }

    let v6_sock = crate::nat::addr::is_v6_socket(sock);
    let outbound_v6 = if v6_sock { local_outbound_v6() } else { None };

    if let Some(mapped) = upnp {
        out.push(Candidate {
            kind: CandidateKind::Upnp.as_str().to_string(),
            addr: mapped.to_string(),
        });
    }

    if !stun.is_empty() {
        let r = crate::nat::stun::reflexive_addresses(sock, stun, stun_timeout);
        for e in &r.errors {
            log::debug!("[nat] {e}");
        }
        if let Some(addr) = r.v4 {
            out.push(Candidate {
                kind: CandidateKind::Stun.as_str().to_string(),
                addr: addr.to_string(),
            });
        }
        out.extend(v6_candidates(outbound_v6, r.v6, port));
    } else {
        out.extend(v6_candidates(outbound_v6, None, port));
    }

    sort_candidates(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn c(kind: &str, addr: &str) -> Candidate {
        Candidate {
            kind: kind.to_string(),
            addr: addr.to_string(),
        }
    }

    /// REGRESSION (whole-branch review, IMPORTANT 2). The candidate list comes
    /// out of somebody else's ciphertext and both sides send packets to every
    /// address in it, so an uncapped list is a packet reflector.
    #[test]
    fn a_flood_of_candidates_is_capped_before_anything_is_sent_to_them() {
        let flood: Vec<Candidate> = (0..9)
            .map(|i| c("stun", &format!("198.51.100.{i}:4000")))
            .collect();
        let addrs = parse_addrs(&flood);
        assert_eq!(addrs.len(), MAX_CANDIDATE_ADDRS);
        assert_eq!(addrs.len(), 8, "the cap the review asked for");
        // The cap keeps the FIRST eight — the list arrives in priority order,
        // so the ones worth trying are the ones kept.
        assert_eq!(addrs[0], "198.51.100.0:4000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn the_cap_counts_dialable_addresses_not_garbled_lines() {
        // Nine good addresses preceded by rubbish must still yield eight good
        // ones: a peer cannot spend our budget on unparseable entries.
        let mut list = vec![c("stun", "not-an-address"), c("stun", "")];
        list.extend((0..9).map(|i| c("stun", &format!("198.51.100.{i}:4000"))));
        assert_eq!(parse_addrs(&list).len(), 8);
    }

    #[test]
    fn link_local_v4_is_excluded_like_the_v6_case() {
        // 169.254/16 (APIPA/self-assigned) is same-link-only, exactly like the
        // fe80::/10 exclusion in local_outbound_v6 — local_outbound_v4 must
        // reject it too rather than handing a peer an address nobody outside
        // the segment can reach.
        assert!(Ipv4Addr::new(169, 254, 1, 1).is_link_local());
    }

    #[test]
    fn only_local_ranges_count_as_lan() {
        let yes = [
            "10.1.2.3",
            "172.16.0.9",
            "172.31.255.1",
            "192.168.1.5",
            "169.254.9.9",
            "127.0.0.1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "::1",
            "::ffff:192.168.1.5",
        ];
        let no = [
            "8.8.8.8",
            "81.2.69.160",
            "100.64.0.1",
            "100.127.255.255",
            "172.32.0.1",
            "11.0.0.1",
            "2a00:1450::1",
            "fec0::1",
            "::ffff:8.8.8.8",
            "203.0.113.9",
        ];
        for a in yes {
            assert!(is_lan_ip(a.parse().unwrap()), "{a} is local");
        }
        for a in no {
            assert!(!is_lan_ip(a.parse().unwrap()), "{a} is not local");
        }
    }

    #[test]
    fn punches_go_only_to_the_own_subnet_or_the_public_internet() {
        let subnets = [(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let list = vec![
            c("lan", "192.168.1.50:40000"), // same subnet: ok
            c("lan", "192.168.7.50:40000"), // other private subnet: no
            c("lan", "192.168.1.1:53"),     // router DNS: low port, no
            c("lan", "8.8.8.8:40000"),      // "lan" but public: no
            c("stun", "10.0.0.5:40000"),    // reflexive but private: no
            c("stun", "100.64.1.1:40000"),  // CGNAT: no
            c("stun", "127.0.0.1:40000"),   // loopback: no
            c("stun", "203.0.113.9:40000"), // documentation: no
            c("stun", "81.2.69.160:40000"), // public: ok
            c("upnp", "81.2.69.161:40001"), // public: ok
            // IPv6 (the sockets are dual-stack since W3): a global address is
            // punched, so the joiner's stateful firewall lets the host in.
            c("v6", "[2a00:1450::1]:40000"),         // global v6: ok
            c("stun", "[::ffff:10.0.0.5]:40000"),    // mapped private v4: no
            c("stun", "[::ffff:81.2.69.160]:40000"), // mapped duplicate of an earlier one: no
            c("v6", "[fe80::1]:40000"),              // link-local: no
            c("v6", "[fd00::1]:40000"),              // unique-local: no
            c("v6", "[2001:0:4136:e378::1]:40000"),  // Teredo: no
            c("lan", "[2a00:1450::2]:40000"),        // "lan" is IPv4-subnet only: no
            c("v6", "[2a00:1450::3]:80"),            // low port: no
        ];
        let got = punch_targets_within(&list, &subnets);
        let want: Vec<SocketAddr> = [
            "192.168.1.50:40000",
            "81.2.69.160:40000",
            "81.2.69.161:40001",
            "[2a00:1450::1]:40000",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(got, want);
        let many: Vec<Candidate> = (0..20)
            .map(|i| c("stun", &format!("81.2.69.{i}:40000")))
            .collect();
        assert_eq!(
            punch_targets_within(&many, &subnets).len(),
            MAX_PUNCH_TARGETS
        );
        // IPv6 has its own, smaller budget, and cannot crowd out the IPv4 one.
        let mut mixed: Vec<Candidate> = (0..10)
            .map(|i| c("v6", &format!("[2a00:1450::{i:x}]:40000")))
            .collect();
        mixed.extend((0..10).map(|i| c("stun", &format!("81.2.69.{i}:40000"))));
        let got = punch_targets_within(&mixed, &subnets);
        assert_eq!(
            got.iter().filter(|a| a.is_ipv6()).count(),
            MAX_PUNCH_TARGETS_V6
        );
        assert_eq!(
            got.iter().filter(|a| a.is_ipv4()).count(),
            MAX_PUNCH_TARGETS
        );
    }

    /// (c) Which IPv6 addresses count as reachable from another house.
    #[test]
    fn only_global_unicast_v6_counts_as_global() {
        let g = |s: &str| is_global_v6(s.parse().unwrap());
        assert!(g("2a00:1450:4009:81f::200e"), "ordinary global unicast");
        assert!(
            g("2001:4860:4860::8888"),
            "2001:4860 is outside the 2001::/23 carve-out"
        );
        assert!(g("2600:1700::1"));
        assert!(!g("fe80::1"), "link-local");
        assert!(!g("febf::1"), "link-local, top of the /10");
        assert!(!g("fd12:3456::1"), "unique-local");
        assert!(!g("fc00::1"), "unique-local");
        assert!(!g("::1"), "loopback");
        assert!(!g("::"), "unspecified");
        assert!(
            !g("::ffff:81.2.69.160"),
            "v4-mapped is IPv4, judged elsewhere"
        );
        assert!(!g("64:ff9b::81.2.69.160"), "NAT64");
        assert!(!g("2001:0:4136:e378:8000:63bf:3fff:fdd2"), "Teredo");
        assert!(!g("2002:c000:204::1"), "6to4");
        assert!(!g("2001:db8::1"), "documentation");
        assert!(!g("3fff::1"), "documentation (RFC 9637)");
        assert!(!g("ff02::1"), "multicast");
        assert!(!g("fec0::1"), "site-local");
    }

    #[test]
    fn mac_derived_v6_addresses_are_recognised() {
        assert!(is_eui64("2a00:1450::0211:22ff:fe33:4455".parse().unwrap()));
        assert!(!is_eui64("2a00:1450::8d3c:91a2:5e07:1b64".parse().unwrap()));
    }

    /// review-ipv6-1 I1/I2, on synthetic inputs (the machine needs no IPv6):
    /// a MAC-derived address is never offered, from either source, and only
    /// the outbound address becomes a `v6` candidate.
    #[test]
    fn v6_candidates_filter_every_source() {
        let eui: Ipv6Addr = "2a00:1450::0211:22ff:fe33:4455".parse().unwrap();
        let tmp: Ipv6Addr = "2a00:1450::8d3c:91a2:5e07:1b64".parse().unwrap();
        let sa = |ip: Ipv6Addr| SocketAddr::new(IpAddr::V6(ip), 7700);
        // An EUI-64 kernel source, reflected back by STUN: nothing offered.
        assert_eq!(v6_candidates(Some(eui), Some(sa(eui)), 7700), vec![]);
        // A good source with an EUI-64 STUN answer: only the source.
        assert_eq!(
            v6_candidates(Some(tmp), Some(sa(eui)), 7700),
            vec![c("v6", "[2a00:1450::8d3c:91a2:5e07:1b64]:7700")]
        );
        // Non-global STUN answers (ULA, link-local, Teredo, 6to4, docs, mapped): dropped.
        for bad in [
            "fd00::1",
            "fe80::1",
            "2001:0:4136:e378::1",
            "2002:c000:204::1",
            "2001:db8::1",
            "::ffff:81.2.69.160",
        ] {
            let got = v6_candidates(None, Some(sa(bad.parse().unwrap())), 7700);
            assert_eq!(got, vec![], "{bad}");
        }
        // NAT66 / a tunnel: the STUN answer differs and is offered as `stun`.
        let outside: Ipv6Addr = "2a02:6b8::5".parse().unwrap();
        assert_eq!(
            v6_candidates(Some(tmp), Some(sa(outside)), 7700),
            vec![
                c("v6", "[2a00:1450::8d3c:91a2:5e07:1b64]:7700"),
                c("stun", "[2a02:6b8::5]:7700")
            ]
        );
        // A VPN that sources from a ULA: no `v6`, only what the outside sees.
        assert_eq!(
            v6_candidates(None, Some(sa(outside)), 7700),
            vec![c("stun", "[2a02:6b8::5]:7700")]
        );
    }

    #[test]
    fn a_rotated_temporary_address_replaces_the_old_one_per_answer() {
        let old = vec![
            c("lan", "192.168.1.20:7700"),
            c("v6", "[2a00:1450::1111]:7700"),
            c("stun", "81.2.69.160:41234"),
        ];
        let new = refresh_v6(&old, Some("2a00:1450::2222".parse().unwrap()), 7700);
        assert_eq!(
            new,
            vec![
                c("lan", "192.168.1.20:7700"),
                c("v6", "[2a00:1450::2222]:7700"),
                c("stun", "81.2.69.160:41234")
            ]
        );
        // The source went away (or is now MAC-derived): no `v6` at all.
        let gone = refresh_v6(
            &old,
            Some("2a00:1450::0211:22ff:fe33:4455".parse().unwrap()),
            7700,
        );
        assert!(gone.iter().all(|x| x.kind != "v6"), "{gone:?}");
        assert_eq!(refresh_v6(&old, None, 7700).len(), 2);
    }

    /// review-ipv6-1 I4: what a joiner will punch and dial from an answer.
    #[test]
    fn the_joiner_only_dials_sane_answer_addresses() {
        let list = vec![
            c("lan", "192.168.1.50:40000"),       // private via LAN: ok
            c("lan", "127.0.0.1:40000"),          // same machine via LAN: ok
            c("lan", "[fd00::5]:40000"),          // ULA via LAN: ok
            c("lan", "[::ffff:10.0.0.7]:40000"),  // mapped private via LAN: ok, as IPv4
            c("stun", "81.2.69.160:40000"),       // public: ok
            c("v6", "[2a00:1450::1]:40000"),      // global v6: ok
            c("stun", "10.0.0.5:40000"),          // private, not LAN: no
            c("stun", "[::ffff:10.0.0.5]:40000"), // mapped private, not LAN: no
            c("v6", "[fd00::1]:40000"),           // ULA, not LAN: no
            c("stun", "127.0.0.1:40000"),         // loopback, not LAN: no
            c("v6", "[::1]:40000"),               // loopback v6, not LAN: no
            c("lan", "224.0.0.1:40000"),          // multicast: no
            c("lan", "[ff02::1]:40000"),          // all-nodes multicast: no
            c("lan", "0.0.0.0:40000"),            // unspecified: no
            c("lan", "[::]:40000"),               // unspecified v6: no
            c("lan", "255.255.255.255:40000"),    // broadcast: no
            c("lan", "169.254.1.1:40000"),        // link-local: no
            c("lan", "[fe80::1]:40000"),          // link-local v6: no
            c("upnp", "203.0.113.9:40000"),       // documentation: no
            c("v6", "[2001:db8::1]:40000"),       // documentation v6: no
            c("lan", "192.168.1.1:53"),           // low port: no
            c("lan", "garbage"),                  // unparseable: no
        ];
        let got: Vec<String> = dialable(&list)
            .into_iter()
            .map(|x| format!("{} {}", x.kind, x.addr))
            .collect();
        assert_eq!(
            got,
            vec![
                "lan 192.168.1.50:40000",
                "lan 127.0.0.1:40000",
                "lan [fd00::5]:40000",
                "lan 10.0.0.7:40000",
                "stun 81.2.69.160:40000",
                "v6 [2a00:1450::1]:40000",
            ]
        );
        let flood: Vec<Candidate> = (0..20)
            .map(|i| c("stun", &format!("81.2.69.{i}:40000")))
            .collect();
        assert_eq!(dialable(&flood).len(), MAX_CANDIDATE_ADDRS);
    }

    #[test]
    fn a_mapped_spelling_is_the_same_address_as_the_plain_one() {
        let sorted = sort_candidates(vec![
            c("lan", "[::ffff:192.168.1.20]:7700"),
            c("stun", "192.168.1.20:7700"),
        ]);
        assert_eq!(sorted, vec![c("lan", "192.168.1.20:7700")]);
    }

    /// (d) A machine with many global IPv6 addresses still offers its IPv4
    /// fallbacks, and the whole list fits what the peer will read.
    #[test]
    fn many_v6_addresses_cannot_crowd_out_upnp_and_stun() {
        let mut list: Vec<Candidate> = (0..20)
            .map(|i| c("v6", &format!("[2a00:1450::{i:x}]:7700")))
            .collect();
        list.push(c("stun", "81.2.69.160:41234"));
        list.push(c("stun", "[2a00:1450::ffff]:7700"));
        list.push(c("upnp", "81.2.69.161:7700"));
        list.push(c("lan", "192.168.1.20:7700"));
        let sorted = sort_candidates(list);
        assert!(sorted.len() <= MAX_CANDIDATE_ADDRS);
        assert!(sorted.len() <= crate::rendezvous::MAX_CANDIDATES);
        let kinds: Vec<&str> = sorted.iter().map(|x| x.kind.as_str()).collect();
        assert_eq!(kinds, vec!["lan", "v6", "v6", "upnp", "stun", "stun"]);
        // Every one of them survives the peer's own cap.
        assert_eq!(parse_addrs(&sorted).len(), sorted.len());
    }

    #[test]
    fn candidate_kinds_round_trip_their_wire_spelling() {
        for k in [
            CandidateKind::Lan,
            CandidateKind::V6,
            CandidateKind::Upnp,
            CandidateKind::Stun,
        ] {
            assert_eq!(CandidateKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(CandidateKind::parse("teredo"), None);
    }

    #[test]
    fn declaration_order_is_priority_order() {
        // Cheapest and most likely first: the same house, then a real global
        // address, then a mapping we asked the router for, then whatever the
        // NAT happens to be doing today.
        assert!(CandidateKind::Lan < CandidateKind::V6);
        assert!(CandidateKind::V6 < CandidateKind::Upnp);
        assert!(CandidateKind::Upnp < CandidateKind::Stun);
    }

    #[test]
    fn sort_puts_them_in_priority_order() {
        let sorted = sort_candidates(vec![
            c("stun", "203.0.113.9:41234"),
            c("upnp", "198.51.100.7:7700"),
            c("lan", "192.168.1.20:7700"),
            c("v6", "[2001:db8::1]:7700"),
        ]);
        let kinds: Vec<&str> = sorted.iter().map(|x| x.kind.as_str()).collect();
        assert_eq!(kinds, vec!["lan", "v6", "upnp", "stun"]);
    }

    #[test]
    fn sort_drops_duplicate_addresses_keeping_the_higher_priority_one() {
        let sorted = sort_candidates(vec![
            c("stun", "198.51.100.7:7700"),
            c("upnp", "198.51.100.7:7700"),
        ]);
        assert_eq!(sorted.len(), 1);
        assert_eq!(
            sorted[0].kind, "upnp",
            "the router mapping is the better bet"
        );
    }

    #[test]
    fn sort_keeps_an_unknown_kind_last_rather_than_dropping_it() {
        // Forwards compatibility: a future kind we don't understand is still an
        // address worth trying, just not one to try first.
        let sorted = sort_candidates(vec![
            c("natpmp", "198.51.100.9:7700"),
            c("lan", "192.168.1.20:7700"),
        ]);
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].kind, "lan");
        assert_eq!(sorted[1].kind, "natpmp");
    }

    #[test]
    fn reachable_beyond_lan_is_false_for_lan_only() {
        assert!(!reachable_beyond_lan(&[c("lan", "192.168.1.20:7700")]));
        assert!(!reachable_beyond_lan(&[]));
        assert!(reachable_beyond_lan(&[c("v6", "[2001:db8::1]:7700")]));
        assert!(reachable_beyond_lan(&[c("upnp", "198.51.100.7:7700")]));
        assert!(reachable_beyond_lan(&[c("stun", "203.0.113.9:41234")]));
    }

    #[test]
    fn parse_addrs_skips_anything_unparseable_without_failing_the_lot() {
        let got = parse_addrs(&[
            c("lan", "192.168.1.20:7700"),
            c("lan", "this is not an address"),
            c("v6", "[2001:db8::1]:7700"),
        ]);
        assert_eq!(
            got,
            vec![
                "192.168.1.20:7700".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:7700".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn gather_always_yields_at_least_the_bound_socket_on_loopback() {
        // No internet needed: bind loopback, gather with UPnP off and a 1ms
        // STUN budget. The LAN candidate must carry the socket's real port,
        // because that is the port the peer will be told to dial.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let got = gather(&sock, None, &[], std::time::Duration::from_millis(1));
        assert!(
            got.iter().any(|x| x.addr.ends_with(&format!(":{port}"))),
            "every candidate must name the bound port: {got:?}"
        );
        assert_eq!(
            got,
            sort_candidates(got.clone()),
            "gather returns them sorted"
        );
        assert!(
            got.iter().all(|x| x.kind != "v6"),
            "an IPv4-only socket offers no IPv6: {got:?}"
        );
    }

    #[test]
    fn gather_on_a_dual_stack_socket_names_its_port_and_no_wildcard() {
        let sock = crate::nat::addr::bind_dual_stack(0).unwrap();
        let port = sock.local_addr().unwrap().port();
        let got = gather(&sock, None, &[], std::time::Duration::from_millis(1));
        assert!(!got.is_empty());
        for x in &got {
            let a: SocketAddr = x.addr.parse().unwrap();
            assert_eq!(a.port(), port, "{got:?}");
            assert!(
                !a.ip().is_unspecified(),
                "a wildcard is no address to dial: {got:?}"
            );
            if x.kind == "v6" {
                let std::net::IpAddr::V6(ip) = a.ip() else {
                    panic!("{got:?}")
                };
                assert!(is_global_v6(ip), "{got:?}");
            }
        }
    }

    #[test]
    fn gather_includes_a_supplied_upnp_mapping() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mapped: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let got = gather(
            &sock,
            Some(mapped),
            &[],
            std::time::Duration::from_millis(1),
        );
        assert!(
            got.iter()
                .any(|x| x.kind == "upnp" && x.addr == "198.51.100.7:41000"),
            "{got:?}"
        );
    }
}
