//! Keeping local play off a VPN.
//!
//! On a phone with a VPN on, an ordinary socket's traffic follows the VPN's
//! default route, so a LAN beacon, a LAN browser or a QUIC dial to the phone
//! next to you goes into the tunnel and never arrives. The platform can bind a
//! socket to one specific network (Android: `android_setsocknetwork` on the
//! Wi-Fi `Network`), and this crate cannot see Java, so the app hands it a
//! [`LanSocketHook`] in [`crate::NetConfig`] and the crate calls it on every
//! socket that talks to local peers, right after the bind:
//!
//! - the LAN beacon's sending socket and the browser's listening socket;
//! - the QUIC socket of a host (it serves local joiners, so it must answer on
//!   the Wi-Fi link) and of a joiner dialling a LAN room or a known address.
//!
//! Relay WebSockets, and a joiner dialling by room code, keep the default
//! route (they may go through the VPN).
//!
//! The hook says how it went:
//!
//! - `Ok`: the socket is bound to the local network (or there is nothing to
//!   do);
//! - `Err(Blocked)`: a VPN is up and the bypass is refused (Android's "Block
//!   connections without VPN" lockdown). The app is told through
//!   [`lan_blocked`] so it can say so, instead of failing silently;
//! - `Err(Failed)`: anything else (no Wi-Fi network, JNI trouble). The socket
//!   keeps the default route and the crate carries on.
//!
//! Sends that fail the way a lockdown fails them (`EPERM`, `ENETUNREACH`)
//! on a socket the hook bound also flag [`lan_blocked`] ([`note_send_error`]).

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Why the hook could not bind a socket to the local network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LanBindError {
    /// A VPN is up and refuses local connections ("Block connections without VPN").
    Blocked(String),
    /// Any other reason; the socket keeps the default route.
    Failed(String),
}

type HookFn = dyn Fn(i32) -> Result<(), LanBindError> + Send + Sync;

/// A function that binds the socket with this file descriptor to the local
/// (Wi-Fi/Ethernet) network. Cheap to clone.
#[derive(Clone)]
pub struct LanSocketHook(Arc<HookFn>);

impl LanSocketHook {
    pub fn new(
        f: impl Fn(i32) -> Result<(), LanBindError> + Send + Sync + 'static,
    ) -> LanSocketHook {
        LanSocketHook(Arc::new(f))
    }
}

impl fmt::Debug for LanSocketHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanSocketHook")
    }
}

/// The player-facing text for a blocked VPN (spec 2.1).
pub const VPN_BLOCKS_LAN: &str =
    "Your VPN blocks local connections; turn it off or allow LAN to play nearby";

static BLOCKED: AtomicBool = AtomicBool::new(false);

/// Whether the last attempt to keep a local socket off the VPN was refused.
pub fn lan_blocked() -> bool {
    BLOCKED.load(Ordering::Relaxed)
}

/// What a bind attempt did to the blocked flag: the flag follows the latest
/// bind, so turning the VPN's lockdown off clears the message.
pub(crate) fn record(result: &Result<(), LanBindError>) {
    match result {
        Ok(()) => BLOCKED.store(false, Ordering::Relaxed),
        Err(LanBindError::Blocked(why)) => {
            log::warn!("[net] the VPN blocks local connections: {why}");
            BLOCKED.store(true, Ordering::Relaxed);
        }
        Err(LanBindError::Failed(why)) => {
            log::info!("[net] local socket left on the default route: {why}")
        }
    }
}

/// Run the hook (if any) on `sock`.
#[cfg(unix)]
pub(crate) fn bind_lan(
    hook: Option<&LanSocketHook>,
    sock: &impl std::os::fd::AsRawFd,
) -> Result<(), LanBindError> {
    let Some(h) = hook else { return Ok(()) };
    let r = (h.0)(sock.as_raw_fd());
    record(&r);
    r
}

#[cfg(not(unix))]
pub(crate) fn bind_lan<S>(_hook: Option<&LanSocketHook>, _sock: &S) -> Result<(), LanBindError> {
    Ok(())
}

/// Whether a failed send looks like a lockdown refusing the bypass.
pub fn is_lockdown_error(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(e.raw_os_error(), Some(1) | Some(13) | Some(101))
}

/// A send on a hook-bound socket failed: flag a lockdown if it looks like one.
pub(crate) fn note_send_error(bound_by_hook: bool, e: &std::io::Error) {
    if bound_by_hook && is_lockdown_error(e) {
        log::warn!("[net] a local send was refused ({e}): a VPN lockdown?");
        BLOCKED.store(true, Ordering::Relaxed);
    }
}

/// Bind a throwaway UDP socket and run the hook on it, to learn now whether
/// local sockets can bypass the VPN (Nearby and Join call this when they open).
/// Returns [`lan_blocked`].
pub fn check_lan_binding(cfg: &crate::NetConfig) -> bool {
    if cfg.lan_socket_hook.is_some() {
        if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
            let _ = bind_lan(cfg.lan_socket_hook.as_ref(), &s);
        }
    }
    lan_blocked()
}

#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    #[test]
    fn the_hook_sees_the_sockets_fd_and_the_blocked_flag_follows_the_latest_bind() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let seen = Arc::new(AtomicI32::new(-1));
        let fail = Arc::new(AtomicBool::new(false));
        let (s2, f2) = (Arc::clone(&seen), Arc::clone(&fail));
        let hook = LanSocketHook::new(move |fd| {
            s2.store(fd, Ordering::Relaxed);
            if f2.load(Ordering::Relaxed) {
                Err(LanBindError::Blocked("lockdown".into()))
            } else {
                Ok(())
            }
        });
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        use std::os::fd::AsRawFd;
        assert!(bind_lan(Some(&hook), &sock).is_ok());
        assert_eq!(seen.load(Ordering::Relaxed), sock.as_raw_fd());
        assert!(!lan_blocked());
        fail.store(true, Ordering::Relaxed);
        assert_eq!(
            bind_lan(Some(&hook), &sock),
            Err(LanBindError::Blocked("lockdown".into()))
        );
        assert!(lan_blocked(), "a refused bypass is reported");
        fail.store(false, Ordering::Relaxed);
        assert!(bind_lan(Some(&hook), &sock).is_ok());
        assert!(
            !lan_blocked(),
            "the flag clears when the bypass works again"
        );
        // No hook: nothing to do, nothing flagged.
        assert!(bind_lan(None, &sock).is_ok());
    }

    #[test]
    fn a_failed_bind_that_is_not_a_lockdown_does_not_flag_it() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        BLOCKED.store(false, Ordering::Relaxed);
        let hook = LanSocketHook::new(|_| Err(LanBindError::Failed("no Wi-Fi network".into())));
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(bind_lan(Some(&hook), &sock).is_err());
        assert!(!lan_blocked());
    }

    #[test]
    fn lockdown_like_send_errors_are_recognised_only_on_bound_sockets() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        BLOCKED.store(false, Ordering::Relaxed);
        let eperm = std::io::Error::from_raw_os_error(1);
        let unreach = std::io::Error::from_raw_os_error(101);
        let other = std::io::Error::from_raw_os_error(11);
        assert!(
            is_lockdown_error(&eperm) && is_lockdown_error(&unreach) && !is_lockdown_error(&other)
        );
        note_send_error(false, &eperm);
        assert!(
            !lan_blocked(),
            "an unbound socket's failure is not a lockdown"
        );
        note_send_error(true, &other);
        assert!(!lan_blocked());
        note_send_error(true, &eperm);
        assert!(lan_blocked());
        BLOCKED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn checking_the_binding_runs_the_hook_on_a_fresh_socket() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut cfg = crate::NetConfig::new("unused", "test-app");
        assert!(!check_lan_binding(&cfg), "no hook, nothing blocked");
        cfg.lan_socket_hook = Some(LanSocketHook::new(|_| {
            Err(LanBindError::Blocked("lockdown".into()))
        }));
        assert!(check_lan_binding(&cfg));
        cfg.lan_socket_hook = Some(LanSocketHook::new(|_| Ok(())));
        assert!(!check_lan_binding(&cfg));
    }
}
