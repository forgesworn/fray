//! What a room announces is what the `listening on` log line prints (K2-1
//! acceptance 6). Its own test binary: it installs the process's logger.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fray_net::{
    host, HostEvent, HostHandle, Identity, Listener, ListenerConfig, NetConfig, RoomInfo,
};

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;
impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        let line = format!("{}", r.args());
        if line.contains("listening on") {
            LINES.lock().unwrap().push(line);
        }
    }
    fn flush(&self) {}
}

fn capture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        log::set_logger(&Capture).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
}

fn ready(h: &HostHandle) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(HostEvent::Ready { code }) = h.poll() {
            return code;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("not ready");
}

/// The candidates printed on the line that names `needle`.
fn printed(prefix: &str, needle: &str) -> String {
    let lines = LINES.lock().unwrap();
    let line = lines
        .iter()
        .find(|l| l.starts_with(prefix) && l.contains(needle))
        .unwrap_or_else(|| panic!("no {prefix} line with {needle} in {lines:?}"));
    line.split("candidates ").nth(1).unwrap().to_string()
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn room() -> RoomInfo {
    RoomInfo {
        name: "Log room".into(),
        max_players: 4,
    }
}

#[test]
fn announced_matches_the_candidates_the_log_line_prints() {
    capture();
    let dir = std::env::temp_dir();

    // A listener that gathers (LAN and IPv6; no STUN, no router), two rooms.
    let gathering = Listener::bind(ListenerConfig {
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    })
    .unwrap();
    let port = gathering.local_addr().unwrap().port();
    let mut cfg = NetConfig::new(&dir, "fray-log-a").lan_only();
    cfg.lan_port = 0;
    let a = gathering.host(&cfg, &Identity::ephemeral(), room());
    let code_a = ready(&a);
    let want = format!("{:?}", gathering.announced());
    assert_eq!(
        printed("[listener] listening on", &format!(":{port}")),
        want
    );
    assert_eq!(
        printed("[host] listening on", &format!("code {code_a}")),
        want
    );
    assert_eq!(format!("{:?}", a.announced()), want);

    // Advertise-only: exactly the configured list.
    let fixed = free_port();
    let advertise: Vec<SocketAddr> = vec![
        format!("192.168.77.9:{fixed}").parse().unwrap(),
        format!("100.64.7.9:{fixed}").parse().unwrap(),
    ];
    let only = Listener::bind(ListenerConfig {
        quic_port: fixed,
        advertise: advertise.clone(),
        advertise_only: true,
        stun: Vec::new(),
        upnp: false,
        ..ListenerConfig::new()
    })
    .unwrap();
    let mut cfg_b = NetConfig::new(&dir, "fray-log-b").lan_only();
    cfg_b.lan_port = 0;
    let b = only.host(&cfg_b, &Identity::ephemeral(), room());
    let code_b = ready(&b);
    assert_eq!(b.announced().len(), 2);
    let want = format!("{:?}", b.announced());
    assert_eq!(
        printed("[host] listening on", &format!("code {code_b}")),
        want
    );
    assert_eq!(format!("{:?}", only.announced()), want);

    // A plain host: the same promise.
    let plain = host(&cfg, &Identity::ephemeral(), room());
    let code_p = ready(&plain);
    assert_eq!(
        printed("[host] listening on", &format!("code {code_p}")),
        format!("{:?}", plain.announced())
    );
    plain.shutdown();
    gathering.shutdown();
    only.shutdown();
}
