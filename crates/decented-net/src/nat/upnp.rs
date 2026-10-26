//! Asking the home router to forward the online-play UDP port.
//!
//! Most consumer routers speak UPnP IGD and will agree to this without anyone
//! opening a router admin page — which is the whole point: "no port forwarding
//! for most homes". A router that refuses is not an error, it is one
//! fewer candidate; the joiner still has IPv6 and STUN to try, and the host is
//! told plainly if none of them worked.
//!
//! The lease is **finite and renewed**, never infinite: an app that leaves a
//! permanent hole in somebody's router after it exits is not a good guest.
//! `PortMapping::remove` is called when hosting stops.
//!
//! Blocking API on purpose — this runs on a worker thread during the ≤3 s
//! candidate-gathering budget, so `igd-next`'s `aio_tokio` feature is off and
//! no async stack comes with it.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use igd_next::{search_gateway, Gateway, PortMappingProtocol, SearchOptions};

/// Lease length asked of the router. Two hours: long enough that a missed
/// renewal is survivable, short enough that a crashed app's mapping expires by
/// itself.
pub const LEASE_SECS: u32 = 7200;
/// How often a live mapping is re-asserted while hosting.
pub const RENEW_EVERY: Duration = Duration::from_secs(3600);
/// How long to wait for a router to answer the SSDP search. Kept tight — this
/// sits inside the candidate-gathering budget, and a router that hasn't
/// answered in two seconds is not going to.
pub const SEARCH_TIMEOUT: Duration = Duration::from_secs(2);
/// What the router's admin page will show. Deliberately just the crate's name:
/// no player name, no npub, no room (anyone on the network can read it).
pub const MAPPING_DESCRIPTION: &str = "decented-net";

/// Whether a mapping made/renewed at `last_renew` is due again at `now`. Pure,
/// so the schedule is testable without a router.
pub fn renew_due(last_renew: Instant, now: Instant) -> bool {
    now.duration_since(last_renew) >= RENEW_EVERY
}

/// A one-shot latch: the first `take` is the release that happens, every one
/// after it is a no-op.
///
/// Pure, and separate from [`PortMapping`], so "an explicit `remove` followed
/// by the `Drop` releases exactly once" is provable without a router.
#[derive(Debug, Default)]
struct ReleaseOnce(bool);

impl ReleaseOnce {
    /// `true` exactly once, for the caller that should do the release.
    fn take(&mut self) -> bool {
        if self.0 {
            false
        } else {
            self.0 = true;
            true
        }
    }

    fn released(&self) -> bool {
        self.0
    }
}

/// A live UDP port mapping on the home router.
///
/// Releasing is tied to the value's lifetime, not to remembering to call
/// [`PortMapping::remove`]: a mapping that is simply dropped — the app closed,
/// the preparation timed out and its worker's `send` found nobody listening —
/// still hands the port back, best effort. A hole left open in somebody's
/// router by a game that has exited is not acceptable, even for the two hours a
/// lease takes to lapse.
pub struct PortMapping {
    gateway: Gateway,
    external: SocketAddr,
    local: SocketAddr,
    last_renew: Instant,
    released: ReleaseOnce,
}

impl PortMapping {
    /// The address a peer outside the house should dial.
    pub fn external_addr(&self) -> SocketAddr {
        self.external
    }

    /// Re-assert the mapping. No-op until [`renew_due`]; call it on a timer
    /// while hosting.
    pub fn renew(&mut self, now: Instant) -> Result<(), String> {
        if !renew_due(self.last_renew, now) {
            return Ok(());
        }
        self.gateway
            .add_port(
                PortMappingProtocol::UDP,
                self.external.port(),
                self.local,
                LEASE_SECS,
                MAPPING_DESCRIPTION,
            )
            .map_err(|e| format!("upnp renew: {e}"))?;
        self.last_renew = now;
        Ok(())
    }

    /// Give the port back. Best-effort: a router that has already forgotten the
    /// mapping (rebooted, lease lapsed) is not a failure worth surfacing.
    ///
    /// Blocking (a SOAP round-trip), so callers on the frame thread go through
    /// `online_prep::LeaseKeeper::release`, which does it on a worker.
    pub fn remove(mut self) {
        self.release_once();
    }

    /// The release itself, guarded so it happens at most once however it is
    /// reached — `remove` and then `Drop`, or `Drop` alone.
    fn release_once(&mut self) {
        if !self.released.take() {
            return;
        }
        if let Err(e) = self
            .gateway
            .remove_port(PortMappingProtocol::UDP, self.external.port())
        {
            log::debug!(
                "[nat] releasing the port mapping: {}",
                crate::quic::log_detail(&e)
            );
        }
    }
}

impl Drop for PortMapping {
    /// The safety net. `remove` has usually already run, and then this does
    /// nothing; the cases it catches are the ones nobody wrote a call for — an
    /// abandoned preparation whose worker could not hand its result back, and
    /// the app being closed.
    fn drop(&mut self) {
        if self.released.released() {
            return;
        }
        log::debug!("[nat] a port mapping was dropped un-released — giving it back");
        self.release_once();
    }
}

/// Ask the router to forward some external UDP port to `local`.
///
/// `add_any_port` lets the router pick, which succeeds far more often than
/// demanding a specific one (the port may already be claimed, and some firmware
/// refuses `AddPortMapping` outright while accepting `AddAnyPortMapping`).
pub fn map_port(local: SocketAddr, search_timeout: Duration) -> Result<PortMapping, String> {
    let gateway = search_gateway(SearchOptions {
        timeout: Some(search_timeout),
        ..Default::default()
    })
    .map_err(|e| format!("no UPnP router found: {e}"))?;

    let external_ip = gateway
        .get_external_ip()
        .map_err(|e| format!("router would not report its external address: {e}"))?;

    let external_port = gateway
        .add_any_port(
            PortMappingProtocol::UDP,
            local,
            LEASE_SECS,
            MAPPING_DESCRIPTION,
        )
        .map_err(|e| format!("router refused a port mapping: {e}"))?;

    Ok(PortMapping {
        gateway,
        external: SocketAddr::new(external_ip, external_port),
        local,
        last_renew: Instant::now(),
        released: ReleaseOnce::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// REGRESSION (whole-branch review, IMPORTANT 4). A mapping only released
    /// through `remove(self)`, so every path that merely dropped one — the app
    /// closing, a preparation timing out, the worker's `send` finding nobody —
    /// left a hole open in the player's router. `Drop` now releases too, and
    /// this latch is what stops the pair doing it twice.
    #[test]
    fn a_release_happens_exactly_once_however_it_is_reached() {
        let mut once = ReleaseOnce::default();
        assert!(!once.released());
        assert!(once.take(), "the first caller does the release");
        assert!(once.released());
        assert!(!once.take(), "and the Drop that follows must not repeat it");
        assert!(!once.take());
    }

    /// The other direction: a mapping nobody called `remove` on is NOT already
    /// released, so its `Drop` does the work.
    #[test]
    fn an_untouched_mapping_still_has_its_release_to_do() {
        let once = ReleaseOnce::default();
        assert!(!once.released(), "Drop must still hand the port back");
    }

    /// A `PortMapping` built on a gateway that is not there, marked released,
    /// and dropped: the guard means `Drop` makes no request at all, so this
    /// returns immediately instead of waiting out an HTTP timeout.
    #[test]
    fn dropping_an_already_released_mapping_touches_no_router() {
        let gateway = Gateway {
            // TEST-NET-1: routable, never answers. If the guard leaked, this
            // test would hang on the SOAP request rather than fail.
            addr: "192.0.2.1:1900".parse().unwrap(),
            root_url: String::new(),
            control_url: String::new(),
            control_schema_url: String::new(),
            control_schema: Default::default(),
        };
        let mut m = PortMapping {
            gateway,
            external: "192.0.2.1:40000".parse().unwrap(),
            local: "192.0.2.2:40000".parse().unwrap(),
            last_renew: Instant::now(),
            released: ReleaseOnce::default(),
        };
        assert!(m.released.take(), "stand in for an explicit remove()");
        let started = Instant::now();
        drop(m);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "Drop went to the router after an explicit release"
        );
    }

    #[test]
    fn renewal_is_due_after_an_hour_and_not_before() {
        let t0 = Instant::now();
        assert!(!renew_due(t0, t0));
        assert!(!renew_due(t0, t0 + RENEW_EVERY - Duration::from_secs(1)));
        assert!(renew_due(t0, t0 + RENEW_EVERY));
        assert!(renew_due(t0, t0 + RENEW_EVERY + Duration::from_secs(1)));
    }

    #[test]
    fn the_lease_outlives_two_renewal_periods() {
        // If the lease were shorter than the renewal interval, a mapping would
        // lapse between renewals and friends would drop out for no visible
        // reason. Two periods of headroom absorbs a missed renewal.
        assert!(
            u64::from(LEASE_SECS) >= 2 * RENEW_EVERY.as_secs(),
            "lease {LEASE_SECS}s must cover two {}s renewal periods",
            RENEW_EVERY.as_secs()
        );
    }

    #[test]
    fn the_mapping_description_names_the_crate_and_nothing_private() {
        // This string shows up in the router's admin page, where anyone on the
        // network can read it. It must not carry a player name, npub or world.
        assert_eq!(MAPPING_DESCRIPTION, "decented-net");
        assert!(!MAPPING_DESCRIPTION.contains("npub"));
    }

    /// OWNER BOUNDARY (needs a real IGD router) — not run in CI.
    /// Run manually on a home network:
    /// `cargo test --lib nat::upnp -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_router_accepts_and_releases_a_mapping() {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let local = std::net::SocketAddr::new(
            std::net::IpAddr::V4(crate::nat::candidates::local_outbound_v4().unwrap()),
            sock.local_addr().unwrap().port(),
        );
        let m = map_port(local, SEARCH_TIMEOUT).expect("router should accept a UDP mapping");
        println!("mapped to {}", m.external_addr());
        m.remove();
    }
}
