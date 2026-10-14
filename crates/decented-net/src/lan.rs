//! LAN discovery: the host broadcasts a small beacon once a second on UDP
//! `lan_port`; [`LanBrowser`] lists the rooms it hears.
//!
//! The beacon goes to the limited broadcast address *and* to the directed
//! broadcast address of every **local** IPv4 interface (a VPN default route
//! would otherwise swallow the limited broadcast; VPN, tunnel and cellular
//! interfaces are left out, see [`crate::ifaces`]), plus 127.0.0.1 for
//! same-machine testing. When the app supplies a [`crate::LanSocketHook`] the
//! beacon and browser sockets are bound to the local network with it, so the
//! packets leave by Wi-Fi even with a VPN on.
//! Browsers bind with `SO_REUSEADDR`, so several instances on one machine all
//! hear it. The dial address is the beacon's *source* IP with the advertised
//! QUIC port — the `addr` field inside is informational.
//!
//! Adapted from Axe'n'Stax `discovery.rs` (MIT).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::{LanRoom, NetConfig, NET_PROTOCOL_VERSION};

const MAGIC: &[u8; 4] = b"DNLB";
/// A room not heard for this long drops off the list.
const ROOM_TTL: Duration = Duration::from_secs(5);
const MAX_ROOMS: usize = 64;
const MAX_NAME_CHARS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Beacon {
    pub v: u32,
    pub app: String,
    pub name: String,
    pub code: String,
    pub player_count: u8,
    pub max_players: u8,
    /// The host's own idea of its address (informational).
    pub addr: String,
    pub port: u16,
    /// The room's LAN admission token (hex, 32 bytes). Being on the same
    /// network counts as being in the room; it rotates whenever the room
    /// opens or closes.
    pub token: String,
}

/// A 32-byte token from its hex form.
pub(crate) fn parse_token(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

pub(crate) fn encode(b: &Beacon) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&serde_json::to_vec(b).unwrap_or_default());
    out
}

pub(crate) fn decode(buf: &[u8]) -> Option<Beacon> {
    let body = buf.strip_prefix(MAGIC.as_slice())?;
    serde_json::from_slice(body).ok()
}

/// Strip control and invisible formatting characters (bidi overrides,
/// zero-width) and cap the length, so a hostile beacon can't spoof the list.
pub(crate) fn sanitize_name(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF)
        })
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Every address a beacon should go to.
fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    targets_for(&crate::ifaces::lan_interfaces(), port)
}

/// [`broadcast_targets`] over a given interface list (pure, tested).
fn targets_for(lan: &[crate::ifaces::Iface4], port: u16) -> Vec<SocketAddr> {
    let mut out = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port)];
    for b in crate::ifaces::broadcast_addrs(lan) {
        let t = SocketAddr::new(IpAddr::V4(b), port);
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    out
}

pub(crate) struct BeaconSender {
    socket: Option<UdpSocket>,
    targets: Vec<SocketAddr>,
    targets_at: Instant,
    port: u16,
    /// The socket was bound to the local network by the app's hook, so a send
    /// the system refuses may mean a VPN lockdown.
    bound: bool,
}

impl BeaconSender {
    pub fn new(port: u16, hook: Option<&crate::LanSocketHook>) -> Self {
        let mut bound = false;
        let socket = UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
            s.set_broadcast(true).ok()?;
            s.set_nonblocking(true).ok()?;
            bound = hook.is_some() && crate::netbind::bind_lan(hook, &s).is_ok();
            Some(s)
        });
        if socket.is_none() {
            log::warn!("[lan] could not create the beacon socket");
        }
        BeaconSender {
            socket,
            targets: broadcast_targets(port),
            targets_at: Instant::now(),
            port,
            bound,
        }
    }

    pub fn send(&mut self, b: &Beacon) {
        let Some(sock) = &self.socket else { return };
        // Interfaces come and go (Wi-Fi joins); refresh the list now and then.
        if self.targets_at.elapsed() > Duration::from_secs(10) {
            self.targets = broadcast_targets(self.port);
            self.targets_at = Instant::now();
        }
        let data = encode(b);
        let mut failed = Vec::new();
        for t in &self.targets {
            // Non-fatal: some targets are unreachable offline.
            if let Err(e) = sock.send_to(&data, t) {
                log::trace!("[lan] beacon to {t}: {e}");
                failed.push(e);
            }
        }
        // Every target refused the way a VPN lockdown refuses: say so.
        if failed.len() == self.targets.len() {
            if let Some(e) = failed.iter().find(|e| crate::netbind::is_lockdown_error(e)) {
                crate::netbind::note_send_error(self.bound, e);
            }
        }
    }
}

/// Lists rooms heard on the LAN. Call [`LanBrowser::poll`] every frame or so.
pub struct LanBrowser {
    socket: Option<UdpSocket>,
    app_tag: String,
    rooms: HashMap<String, (LanRoom, Instant)>,
}

/// Start listening for beacons on `cfg.lan_port`.
pub fn lan_browse(cfg: &NetConfig) -> LanBrowser {
    let socket = bind_reuse(cfg.lan_port, cfg.lan_socket_hook.as_ref())
        .map_err(|e| log::warn!("[lan] cannot listen on {}: {e}", cfg.lan_port))
        .ok();
    LanBrowser {
        socket,
        app_tag: cfg.app_tag.clone(),
        rooms: HashMap::new(),
    }
}

fn bind_reuse(port: u16, hook: Option<&crate::LanSocketHook>) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    // Before the bind, so the socket listens on the local network from the start.
    let _ = crate::netbind::bind_lan(hook, &s);
    s.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

impl LanBrowser {
    /// Whether the beacon port could be bound.
    pub fn is_listening(&self) -> bool {
        self.socket.is_some()
    }

    /// Drain received beacons and return every room heard recently, sorted by name.
    pub fn poll(&mut self) -> Vec<LanRoom> {
        if let Some(sock) = &self.socket {
            let mut buf = [0u8; 2048];
            for _ in 0..64 {
                let Ok((n, from)) = sock.recv_from(&mut buf) else {
                    break;
                };
                let Some(b) = decode(&buf[..n]) else { continue };
                if b.app != self.app_tag || b.v != NET_PROTOCOL_VERSION {
                    continue;
                }
                let Some(code) = crate::room::normalize_code(&b.code) else {
                    continue;
                };
                if parse_token(&b.token).is_none() {
                    continue;
                }
                let room = LanRoom {
                    name: sanitize_name(&b.name),
                    code: code.clone(),
                    player_count: b.player_count,
                    max_players: b.max_players,
                    addr: SocketAddr::new(from.ip(), b.port),
                    token: b.token.to_ascii_lowercase(),
                };
                // The first (ip, port) heard for a code owns it until it goes
                // quiet for ROOM_TTL: the same beacon arriving via another
                // interface, or a spoofer sending the same code, can't take
                // over the dial address or the token.
                self.rooms.retain(|_, (_, seen)| seen.elapsed() < ROOM_TTL);
                match self.rooms.get_mut(&code) {
                    Some((r, seen)) if r.addr == room.addr => {
                        *r = room;
                        *seen = Instant::now();
                    }
                    Some(_) => {}
                    None => {
                        if self.rooms.len() < MAX_ROOMS {
                            self.rooms.insert(code, (room, Instant::now()));
                        }
                    }
                }
            }
        }
        self.rooms.retain(|_, (_, seen)| seen.elapsed() < ROOM_TTL);
        let mut out: Vec<LanRoom> = self.rooms.values().map(|(r, _)| r.clone()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.code.cmp(&b.code)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon() -> Beacon {
        Beacon {
            v: NET_PROTOCOL_VERSION,
            app: "test-app".into(),
            name: "Otter".into(),
            code: "ABCDEF".into(),
            player_count: 2,
            max_players: 8,
            addr: "192.168.1.5:4000".into(),
            port: 4000,
            token: "ab".repeat(32),
        }
    }

    #[test]
    fn beacon_round_trip_and_garbage_rejected() {
        let b = beacon();
        assert_eq!(decode(&encode(&b)), Some(b));
        assert_eq!(decode(b"DNLBnot json"), None);
        assert_eq!(decode(b"XXXX{}"), None);
        assert_eq!(decode(b""), None);
    }

    #[test]
    fn beacon_targets_leave_out_the_vpn_and_cellular() {
        use crate::ifaces::{filter_lan, Iface4};
        let all = vec![
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
            Iface4::new(
                "rmnet_data1",
                [100, 72, 3, 9],
                [255, 255, 255, 0],
                Some([100, 72, 3, 255]),
            ),
        ];
        let t = targets_for(&filter_lan(&all), 7715);
        let ips: Vec<String> = t.iter().map(|a| a.ip().to_string()).collect();
        assert_eq!(ips, ["255.255.255.255", "192.168.1.255", "127.0.0.1"]);
        assert!(t.iter().all(|a| a.port() == 7715));
    }

    #[test]
    fn names_are_sanitised() {
        assert_eq!(sanitize_name("  Bob\u{202E}gnaw\u{200B} "), "Bobgnaw");
        assert_eq!(sanitize_name(&"x".repeat(100)).len(), MAX_NAME_CHARS);
        assert_eq!(sanitize_name("a\nb"), "ab");
    }

    #[test]
    fn browser_hears_a_beacon_and_two_browsers_share_the_port() {
        // A random high port so parallel tests and real games don't collide.
        let mut r = [0u8; 2];
        getrandom::fill(&mut r).unwrap();
        let port = 30000 + (u16::from_le_bytes(r) % 20000);
        let mut cfg = NetConfig::new("unused", "test-app");
        cfg.lan_port = port;
        let mut a = lan_browse(&cfg);
        let mut b = lan_browse(&cfg);
        assert!(
            a.is_listening() && b.is_listening(),
            "SO_REUSEADDR lets both bind"
        );
        let mut sender = BeaconSender::new(port, None);
        let mut other_app = beacon();
        other_app.app = "someone-else".into();
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        while Instant::now() < deadline && (got_a.is_empty() || got_b.is_empty()) {
            sender.send(&beacon());
            sender.send(&other_app);
            std::thread::sleep(Duration::from_millis(50));
            got_a = a.poll();
            got_b = b.poll();
        }
        assert_eq!(got_a.len(), 1, "{got_a:?}");
        assert_eq!(got_a[0].code, "ABCDEF");
        assert_eq!(got_a[0].addr.port(), 4000);
        assert_eq!(got_a[0].token, "ab".repeat(32));
        assert_eq!(got_b.len(), 1, "{got_b:?}");

        // A spoofed beacon for the same code (another port, another token)
        // can't take the room over while the real one is live.
        let mut spoof = beacon();
        spoof.port = 5000;
        spoof.token = "cd".repeat(32);
        for _ in 0..5 {
            sender.send(&spoof);
            sender.send(&beacon());
            std::thread::sleep(Duration::from_millis(30));
        }
        let got = a.poll();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].addr.port(), 4000);
        assert_eq!(got[0].token, "ab".repeat(32));
    }

    #[test]
    fn a_beacon_without_a_valid_token_is_ignored() {
        let mut b = beacon();
        b.token = "xyz".into();
        assert!(parse_token(&b.token).is_none());
        assert!(parse_token(&"ab".repeat(32)).is_some());
        assert!(parse_token(&"ab".repeat(31)).is_none());
    }
}
