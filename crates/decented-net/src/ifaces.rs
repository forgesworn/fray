//! Which network interfaces count as "local".
//!
//! A phone running a VPN has a default route through a `tun` interface, so the
//! usual "which address would the kernel send from" trick names the VPN's
//! address, and a broadcast sent to every interface reaches the VPN too. For
//! nearby play only real local links matter (Wi-Fi, Ethernet, a hotspot): the
//! LAN candidate, the LAN beacon's targets and the punch subnets are built
//! from [`lan_interfaces`], which leaves out
//!
//! - VPN and tunnel interfaces by name ([`is_vpn_interface`]: `tun*`, `tap*`,
//!   `ppp*`, `ipsec*`, `wg*`, `utun*`, `vpn*`, `tailscale*`, `zt*`);
//! - cellular interfaces ([`is_cellular_interface`]: `rmnet*`, `ccmni*`,
//!   `pdp*`, `v4-*` and similar): a carrier address is not a LAN;
//! - loopback, link-local (169.254/16) and unspecified addresses.
//!
//! On Android an interface name is all a native socket sees, so the VPN
//! `Network` itself (TRANSPORT_VPN) is kept out a second way: the app binds
//! the LAN sockets to the Wi-Fi `Network` ([`crate::netbind`]).
//!
//! Everything that decides is a pure function over [`Iface4`], tested with
//! made-up interface lists.

use std::net::Ipv4Addr;

/// One IPv4 address on one interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iface4 {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Option<Ipv4Addr>,
}

impl Iface4 {
    pub fn new(name: &str, ip: [u8; 4], netmask: [u8; 4], broadcast: Option<[u8; 4]>) -> Iface4 {
        Iface4 {
            name: name.to_string(),
            ip: ip.into(),
            netmask: netmask.into(),
            broadcast: broadcast.map(Ipv4Addr::from),
        }
    }
}

const VPN_PREFIXES: &[&str] = &[
    "tun",
    "tap",
    "ppp",
    "ipsec",
    "wg",
    "utun",
    "vpn",
    "tailscale",
    "zt",
    "nordlynx",
    "proton",
    "mullvad",
];
const CELLULAR_PREFIXES: &[&str] = &[
    "rmnet",
    "ccmni",
    "pdp",
    "v4-rmnet",
    "v4-ccmni",
    "wwan",
    "usb_rmnet",
    "seth",
    "ccinet",
];

/// A VPN or tunnel interface, by name (case-insensitive prefix).
pub fn is_vpn_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    VPN_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// A cellular data interface, by name (case-insensitive prefix).
pub fn is_cellular_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    CELLULAR_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// Wi-Fi and Ethernet names, which win over other local interfaces (a
/// container bridge, a hotspot) when there is a choice.
fn is_preferred_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["wlan", "wl", "eth", "en", "eno", "enp", "ens"]
        .iter()
        .any(|p| n.starts_with(p))
}

/// Whether an address on `name` may be offered or broadcast on as a LAN
/// address: not a VPN or cellular interface, and not loopback, link-local,
/// unspecified or broadcast.
pub fn is_lan_interface(name: &str, ip: Ipv4Addr) -> bool {
    !is_vpn_interface(name)
        && !is_cellular_interface(name)
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast()
}

/// `all` without the interfaces that are not a LAN, in the same order.
pub fn filter_lan(all: &[Iface4]) -> Vec<Iface4> {
    all.iter()
        .filter(|i| is_lan_interface(&i.name, i.ip))
        .cloned()
        .collect()
}

/// The address to offer as the `lan` candidate. `routed` is the address the
/// kernel's default route sources from (it is the right one on a multi-homed
/// machine with no VPN); it is used only if it belongs to one of the
/// `lan` interfaces, so a VPN's address is never picked. Otherwise the best
/// local interface: Wi-Fi/Ethernet names first, then private ranges, then the
/// first listed.
pub fn pick_lan_ip(lan: &[Iface4], routed: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    if let Some(r) = routed {
        if lan.iter().any(|i| i.ip == r) {
            return Some(r);
        }
    }
    lan.iter()
        .enumerate()
        .min_by_key(|(pos, i)| (!is_preferred_name(&i.name), !i.ip.is_private(), *pos))
        .map(|(_, i)| i.ip)
}

/// Directed-broadcast addresses to send the LAN beacon to: one per local
/// interface (deduplicated), in order.
pub fn broadcast_addrs(lan: &[Iface4]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for i in lan {
        if let Some(b) = i.broadcast {
            if !out.contains(&b) {
                out.push(b);
            }
        }
    }
    out
}

/// `(address, netmask)` of every local interface (the subnets a `lan`
/// candidate may sit in).
pub fn subnets(lan: &[Iface4]) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    lan.iter().map(|i| (i.ip, i.netmask)).collect()
}

/// Every IPv4 address on this machine, with its interface name.
pub fn all_v4() -> Vec<Iface4> {
    if_addrs::get_if_addrs()
        .map(|ifs| {
            ifs.into_iter()
                .filter_map(|i| match i.addr {
                    if_addrs::IfAddr::V4(v4) => Some(Iface4 {
                        name: i.name,
                        ip: v4.ip,
                        netmask: v4.netmask,
                        broadcast: v4.broadcast,
                    }),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The local (non-VPN, non-cellular) IPv4 interfaces of this machine now.
pub fn lan_interfaces() -> Vec<Iface4> {
    filter_lan(&all_v4())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A phone on Wi-Fi with a VPN up and cellular behind it.
    fn phone_with_vpn() -> Vec<Iface4> {
        vec![
            Iface4::new("lo", [127, 0, 0, 1], [255, 0, 0, 0], None),
            Iface4::new(
                "tun0",
                [10, 8, 0, 2],
                [255, 255, 255, 0],
                Some([10, 8, 0, 255]),
            ),
            Iface4::new(
                "wlan0",
                [192, 168, 1, 23],
                [255, 255, 255, 0],
                Some([192, 168, 1, 255]),
            ),
            Iface4::new("rmnet_data1", [100, 72, 3, 9], [255, 255, 255, 252], None),
        ]
    }

    #[test]
    fn vpn_and_tunnel_names_are_recognised() {
        for n in [
            "tun0",
            "tun1",
            "tap0",
            "ppp0",
            "ipsec0",
            "wg0",
            "wg-home",
            "utun3",
            "TUN0",
            "tailscale0",
            "zt5u4abc",
            "vpn0",
            "nordlynx",
        ] {
            assert!(is_vpn_interface(n), "{n}");
        }
        for n in [
            "wlan0", "wlan1", "eth0", "enp3s0", "wlp2s0", "en0", "ap0", "swlan0", "lo", "docker0",
            "br0", "rmnet0",
        ] {
            assert!(!is_vpn_interface(n), "{n}");
        }
    }

    #[test]
    fn cellular_names_are_recognised() {
        for n in [
            "rmnet0",
            "rmnet_data2",
            "ccmni1",
            "pdp0",
            "v4-rmnet_data0",
            "wwan0",
        ] {
            assert!(is_cellular_interface(n), "{n}");
        }
        assert!(!is_cellular_interface("wlan0"));
        assert!(!is_cellular_interface("eth0"));
    }

    #[test]
    fn addresses_that_are_never_a_lan_are_dropped() {
        let ip = |a, b, c, d| Ipv4Addr::new(a, b, c, d);
        assert!(!is_lan_interface("wlan0", ip(127, 0, 0, 1)));
        assert!(!is_lan_interface("wlan0", ip(169, 254, 3, 4)));
        assert!(!is_lan_interface("wlan0", ip(0, 0, 0, 0)));
        assert!(!is_lan_interface("tun0", ip(10, 8, 0, 2)));
        assert!(!is_lan_interface("rmnet_data0", ip(10, 20, 30, 40)));
        assert!(is_lan_interface("wlan0", ip(192, 168, 1, 23)));
        assert!(is_lan_interface("eth0", ip(10, 0, 0, 5)));
        assert!(
            is_lan_interface("ap0", ip(192, 168, 43, 1)),
            "a hotspot is a LAN"
        );
    }

    #[test]
    fn a_vpn_phone_keeps_only_its_wifi() {
        let lan = filter_lan(&phone_with_vpn());
        assert_eq!(lan.len(), 1);
        assert_eq!(lan[0].name, "wlan0");
    }

    #[test]
    fn the_lan_candidate_is_the_wifi_address_not_the_vpns() {
        let lan = filter_lan(&phone_with_vpn());
        // With a VPN the default route sources from the tunnel.
        let routed = Some(Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(
            pick_lan_ip(&lan, routed),
            Some(Ipv4Addr::new(192, 168, 1, 23))
        );
        // No route at all (airplane mode with Wi-Fi): still the Wi-Fi address.
        assert_eq!(
            pick_lan_ip(&lan, None),
            Some(Ipv4Addr::new(192, 168, 1, 23))
        );
    }

    #[test]
    fn the_routed_address_wins_on_a_machine_with_two_local_networks() {
        let lan = vec![
            Iface4::new(
                "docker0",
                [172, 17, 0, 1],
                [255, 255, 0, 0],
                Some([172, 17, 255, 255]),
            ),
            Iface4::new(
                "eth0",
                [192, 168, 0, 7],
                [255, 255, 255, 0],
                Some([192, 168, 0, 255]),
            ),
            Iface4::new(
                "wlan0",
                [192, 168, 1, 9],
                [255, 255, 255, 0],
                Some([192, 168, 1, 255]),
            ),
        ];
        assert_eq!(
            pick_lan_ip(&lan, Some(Ipv4Addr::new(192, 168, 1, 9))),
            Some(Ipv4Addr::new(192, 168, 1, 9))
        );
        // Without a route: a real link's name beats the container bridge.
        assert_eq!(pick_lan_ip(&lan, None), Some(Ipv4Addr::new(192, 168, 0, 7)));
        assert_eq!(
            pick_lan_ip(&lan[..1], None),
            Some(Ipv4Addr::new(172, 17, 0, 1))
        );
    }

    #[test]
    fn only_a_vpn_means_no_lan_candidate() {
        let only_vpn = vec![
            Iface4::new("lo", [127, 0, 0, 1], [255, 0, 0, 0], None),
            Iface4::new(
                "tun0",
                [10, 8, 0, 2],
                [255, 255, 255, 0],
                Some([10, 8, 0, 255]),
            ),
            Iface4::new("wg0", [10, 66, 0, 2], [255, 255, 255, 255], None),
        ];
        let lan = filter_lan(&only_vpn);
        assert!(lan.is_empty());
        assert_eq!(pick_lan_ip(&lan, Some(Ipv4Addr::new(10, 8, 0, 2))), None);
    }

    #[test]
    fn beacons_go_to_local_broadcasts_only() {
        let lan = filter_lan(&phone_with_vpn());
        assert_eq!(broadcast_addrs(&lan), vec![Ipv4Addr::new(192, 168, 1, 255)]);
        let dup = vec![lan[0].clone(), lan[0].clone()];
        assert_eq!(broadcast_addrs(&dup).len(), 1, "deduplicated");
        assert_eq!(
            subnets(&lan),
            vec![(
                Ipv4Addr::new(192, 168, 1, 23),
                Ipv4Addr::new(255, 255, 255, 0)
            )]
        );
    }

    #[test]
    fn this_machine_never_reports_a_vpn_as_local() {
        for i in lan_interfaces() {
            assert!(!is_vpn_interface(&i.name) && !i.ip.is_loopback(), "{i:?}");
        }
    }
}
