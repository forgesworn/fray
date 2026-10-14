//! One relay pool, shared by everything that talks to Nostr relays.
//!
//! The player's list (Settings) is the priority order. Every relay in the
//! pool has a [`Health`] record: successes, failures, the last error, a
//! rolling latency and a backoff state. A relay that fails is left alone for
//! 5 s, then 15 s, then 45 s, then 2 min between quiet re-probes, and
//! returns to normal the first time it works again.
//!
//! The pool is plain state, in memory only. Time is passed in (`*_at`
//! methods take an [`Instant`]) so the schedule is tested without sleeping;
//! the plain methods use [`Instant::now`].
//!
//! Used by `decented-net` (room-code rendezvous) and `decented-signet`
//! (sign-in, contacts, invites, attestations, update checks). Neither
//! depends on the other, hence this small crate.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Relays used when the player has none, and as a last resort when every
/// relay on their list is down.
pub const DEFAULT_RELAYS: [&str; 3] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

/// Shown (once) when the defaults stand in for an unreachable list.
pub const FALLBACK_NOTICE: &str = "Your relays are unreachable; using defaults";

/// A write goes to at least this many healthy relays (when that many are healthy).
pub const WRITE_MIN: usize = 3;
/// ...and to at most this many.
pub const WRITE_FANOUT: usize = 5;

/// A rolling latency above this reads as slow (amber).
pub const SLOW: Duration = Duration::from_millis(1500);

/// How many recent attempts and latency samples a relay's record keeps.
pub const WINDOW: usize = 5;

/// A relay URL as a comparison key: scheme and host in lower case, no default
/// port (`:443` for `wss`/`https`, `:80` for `ws`/`http`), no trailing `/`.
/// `wss://Nos.Lol`, `wss://nos.lol:443` and `wss://nos.lol/` are one relay.
pub fn normalize_relay_url(url: &str) -> String {
    let url = url.trim();
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.trim_end_matches('/').to_ascii_lowercase();
    };
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut authority = authority.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "wss" | "https" => ":443",
        "ws" | "http" => ":80",
        _ => "",
    };
    if !default_port.is_empty() && authority.ends_with(default_port) {
        authority.truncate(authority.len() - default_port.len());
    }
    format!("{scheme}://{authority}{}", path.trim_end_matches('/'))
}

/// The wait after the `n`th failure in a row.
#[derive(Clone, Debug)]
pub struct Schedule {
    steps: Vec<Duration>,
    steady: Duration,
}

impl Default for Schedule {
    /// 5 s, 15 s, 45 s, then every 2 min.
    fn default() -> Self {
        Schedule {
            steps: vec![
                Duration::from_secs(5),
                Duration::from_secs(15),
                Duration::from_secs(45),
            ],
            steady: Duration::from_secs(120),
        }
    }
}

impl Schedule {
    /// A custom schedule (tests use milliseconds).
    pub fn new(steps: Vec<Duration>, steady: Duration) -> Self {
        Schedule { steps, steady }
    }

    /// The wait after `consecutive` failures in a row (1 = the first failure).
    pub fn wait(&self, consecutive: u32) -> Duration {
        let i = consecutive.saturating_sub(1) as usize;
        self.steps.get(i).copied().unwrap_or(self.steady)
    }
}

/// What a relay's dot shows in Settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dot {
    /// Not tried yet this run (neutral grey).
    Unknown,
    /// Working.
    Green,
    /// Slow (rolling latency over [`SLOW`]) or flaky (a failure in the last [`WINDOW`] attempts).
    Amber,
    /// Failing: in backoff, or being re-probed after a failure.
    Red,
}

/// One relay's record.
#[derive(Clone, Debug, Default)]
pub struct Health {
    pub successes: u64,
    pub failures: u64,
    /// Failures since the last success.
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    /// The last [`WINDOW`] attempts, `true` = it worked.
    recent: VecDeque<bool>,
    /// The last [`WINDOW`] response times.
    latencies: VecDeque<Duration>,
    retry_at: Option<Instant>,
}

fn push_window<T>(q: &mut VecDeque<T>, v: T) {
    if q.len() >= WINDOW {
        q.pop_front();
    }
    q.push_back(v);
}

impl Health {
    /// A good attempt. Returns whether this ended a run of failures.
    fn success(&mut self, latency: Option<Duration>) -> bool {
        let recovered = self.consecutive_failures > 0;
        self.successes += 1;
        self.consecutive_failures = 0;
        self.retry_at = None;
        push_window(&mut self.recent, true);
        if let Some(l) = latency {
            push_window(&mut self.latencies, l);
        }
        recovered
    }

    /// A failed attempt. Returns the wait before the next one.
    fn failure(&mut self, now: Instant, why: &str, schedule: &Schedule) -> Duration {
        self.failures += 1;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_error = Some(why.to_string());
        push_window(&mut self.recent, false);
        let wait = schedule.wait(self.consecutive_failures);
        self.retry_at = Some(now + wait);
        wait
    }

    /// The rolling response time (mean of the last [`WINDOW`] samples).
    pub fn latency(&self) -> Option<Duration> {
        if self.latencies.is_empty() {
            return None;
        }
        let total: Duration = self.latencies.iter().sum();
        Some(total / self.latencies.len() as u32)
    }

    /// Whether the relay may be tried at `now` (its backoff, if any, is over).
    pub fn eligible(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|t| now >= t)
    }

    pub fn attempts(&self) -> usize {
        self.recent.len()
    }

    /// Classify (see [`Dot`]).
    pub fn dot(&self) -> Dot {
        if self.recent.is_empty() {
            return Dot::Unknown;
        }
        if self.consecutive_failures > 0 {
            return Dot::Red;
        }
        if self.recent.iter().any(|ok| !ok) || self.latency().is_some_and(|l| l > SLOW) {
            return Dot::Amber;
        }
        Dot::Green
    }
}

/// A relay as Settings shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayView {
    pub dot: Dot,
    pub last_error: Option<String>,
    pub successes: u64,
    pub failures: u64,
    pub latency: Option<Duration>,
    /// Time until the next re-probe, while backed off.
    pub retry_in: Option<Duration>,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Health>,
}

/// The shared record of every relay's health, plus the built-in defaults.
pub struct RelayPool {
    inner: Mutex<Inner>,
    defaults: Vec<String>,
    schedule: Schedule,
    /// The defaults are standing in for an unreachable list right now.
    fallback: AtomicBool,
}

impl Default for RelayPool {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayPool {
    pub fn new() -> Self {
        Self::with(
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            Schedule::default(),
        )
    }

    /// A pool with its own defaults and schedule (tests).
    pub fn with(defaults: Vec<String>, schedule: Schedule) -> Self {
        RelayPool {
            inner: Mutex::new(Inner::default()),
            defaults,
            schedule,
            fallback: AtomicBool::new(false),
        }
    }

    /// The process-wide pool (the app, the rendezvous and Signet all use it).
    pub fn global() -> Arc<RelayPool> {
        static POOL: OnceLock<Arc<RelayPool>> = OnceLock::new();
        Arc::clone(POOL.get_or_init(|| Arc::new(RelayPool::new())))
    }

    pub fn defaults(&self) -> &[String] {
        &self.defaults
    }

    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── Reporting ──

    /// A relay connected or answered. `latency` is how long that took, when known.
    pub fn record_success(&self, url: &str, latency: Option<Duration>) {
        let key = normalize_relay_url(url);
        let recovered = self.lock().map.entry(key).or_default().success(latency);
        if recovered {
            log::info!("[relays] {url} recovered");
        }
    }

    /// Add a response-time sample without counting an attempt (a REQ to its EOSE).
    pub fn record_latency(&self, url: &str, latency: Duration) {
        let key = normalize_relay_url(url);
        push_window(
            &mut self.lock().map.entry(key).or_default().latencies,
            latency,
        );
    }

    /// A relay failed to connect, dropped, or refused. Starts (or lengthens) its backoff.
    pub fn record_failure(&self, url: &str, why: &str) {
        self.record_failure_at(Instant::now(), url, why);
    }

    pub fn record_failure_at(&self, now: Instant, url: &str, why: &str) {
        let key = normalize_relay_url(url);
        let (wait, n) = {
            let mut g = self.lock();
            let h = g.map.entry(key).or_default();
            let wait = h.failure(now, why, &self.schedule);
            (wait, h.consecutive_failures)
        };
        // The first failure and each step up are news; the steady 2-minute probes are not.
        if n <= self.schedule_len() as u32 + 1 {
            log::info!(
                "[relays] {url} failed ({why}); backing off {}s",
                wait.as_secs_f32()
            );
        } else {
            log::debug!(
                "[relays] {url} still failing ({why}); next probe in {}s",
                wait.as_secs()
            );
        }
    }

    fn schedule_len(&self) -> usize {
        self.schedule.steps.len()
    }

    // ── Asking ──

    /// When the relay may next be tried: `None` = now.
    pub fn retry_at(&self, url: &str) -> Option<Instant> {
        self.lock()
            .map
            .get(&normalize_relay_url(url))
            .and_then(|h| h.retry_at)
    }

    /// How long until the relay may be tried (zero = now).
    pub fn wait_for(&self, url: &str) -> Duration {
        self.wait_for_at(Instant::now(), url)
    }

    pub fn wait_for_at(&self, now: Instant, url: &str) -> Duration {
        self.retry_at(url)
            .map_or(Duration::ZERO, |t| t.saturating_duration_since(now))
    }

    pub fn eligible(&self, url: &str) -> bool {
        self.eligible_at(Instant::now(), url)
    }

    pub fn eligible_at(&self, now: Instant, url: &str) -> bool {
        self.lock()
            .map
            .get(&normalize_relay_url(url))
            .is_none_or(|h| h.eligible(now))
    }

    /// Whether the relay has failed and not worked since (backed off or being re-probed).
    pub fn failing(&self, url: &str) -> bool {
        self.lock()
            .map
            .get(&normalize_relay_url(url))
            .is_some_and(|h| h.consecutive_failures > 0)
    }

    pub fn dot(&self, url: &str) -> Dot {
        self.lock()
            .map
            .get(&normalize_relay_url(url))
            .map_or(Dot::Unknown, Health::dot)
    }

    pub fn last_error(&self, url: &str) -> Option<String> {
        self.lock()
            .map
            .get(&normalize_relay_url(url))
            .and_then(|h| h.last_error.clone())
    }

    pub fn view(&self, url: &str) -> RelayView {
        self.view_at(Instant::now(), url)
    }

    pub fn view_at(&self, now: Instant, url: &str) -> RelayView {
        let g = self.lock();
        match g.map.get(&normalize_relay_url(url)) {
            None => RelayView {
                dot: Dot::Unknown,
                last_error: None,
                successes: 0,
                failures: 0,
                latency: None,
                retry_in: None,
            },
            Some(h) => RelayView {
                dot: h.dot(),
                last_error: h.last_error.clone(),
                successes: h.successes,
                failures: h.failures,
                latency: h.latency(),
                retry_in: h
                    .retry_at
                    .map(|t| t.saturating_duration_since(now))
                    .filter(|d| !d.is_zero()),
            },
        }
    }

    // ── Choosing ──

    /// `urls` in the player's order, each relay once (by normalised address).
    pub fn order(&self, urls: &[String]) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let mut out = Vec::new();
        for u in urls {
            let k = normalize_relay_url(u);
            if !seen.contains(&k) {
                seen.push(k);
                out.push(u.clone());
            }
        }
        out
    }

    /// The relays that may be tried now, in order (not backed off).
    pub fn ready(&self, urls: &[String]) -> Vec<String> {
        self.ready_at(Instant::now(), urls)
    }

    pub fn ready_at(&self, now: Instant, urls: &[String]) -> Vec<String> {
        self.order(urls)
            .into_iter()
            .filter(|u| self.eligible_at(now, u))
            .collect()
    }

    /// Where a write goes: the top healthy relays in order, at most
    /// [`WRITE_FANOUT`] (so at least [`WRITE_MIN`] whenever that many are healthy).
    pub fn writers(&self, urls: &[String]) -> Vec<String> {
        self.writers_at(Instant::now(), urls)
    }

    pub fn writers_at(&self, now: Instant, urls: &[String]) -> Vec<String> {
        let mut r = self.ready_at(now, urls);
        r.truncate(WRITE_FANOUT.max(WRITE_MIN));
        r
    }

    /// The first relay in order, among those `usable`, that is not backed off;
    /// if all are, the first usable one anyway (it is the best guess).
    pub fn first_healthy(&self, urls: &[String], usable: impl Fn(&str) -> bool) -> Option<String> {
        let ordered: Vec<String> = self.order(urls).into_iter().filter(|u| usable(u)).collect();
        ordered
            .iter()
            .find(|u| !self.failing(u))
            .or_else(|| ordered.first())
            .cloned()
    }

    /// Every relay on the list is failing (and there is a list).
    pub fn all_failing(&self, urls: &[String]) -> bool {
        let o = self.order(urls);
        !o.is_empty() && o.iter().all(|u| self.failing(u))
    }

    /// The built-in defaults that are not already on `urls`: the last-resort
    /// extras, but only when every relay listed is failing. Empty otherwise.
    pub fn fallback_extras(&self, urls: &[String]) -> Vec<String> {
        if !self.all_failing(urls) {
            return Vec::new();
        }
        let listed: Vec<String> = urls.iter().map(|u| normalize_relay_url(u)).collect();
        self.defaults
            .iter()
            .filter(|d| !listed.contains(&normalize_relay_url(d)))
            .cloned()
            .collect()
    }

    /// `urls`, in order, and when all of them are failing, the defaults after
    /// them. The bool says the defaults were added.
    pub fn plan(&self, urls: &[String]) -> (Vec<String>, bool) {
        let mut out = self.order(urls);
        let extras = self.fallback_extras(urls);
        let used = !extras.is_empty();
        out.extend(extras);
        (out, used)
    }

    // ── The notice ──

    /// The defaults are (or are no longer) standing in for the player's list.
    pub fn set_fallback(&self, active: bool) {
        if self.fallback.swap(active, Ordering::Relaxed) != active {
            if active {
                log::warn!("[relays] every listed relay is unreachable; using the defaults");
            } else {
                log::info!(
                    "[relays] the listed relays are back; the defaults are no longer needed"
                );
            }
        }
    }

    /// Work out from `urls` whether the defaults are needed now, record it
    /// (and log a change), and return it. The app calls this on its own relay
    /// list to keep the notice truthful.
    pub fn refresh_fallback(&self, urls: &[String]) -> bool {
        let on = !self.fallback_extras(urls).is_empty();
        self.set_fallback(on);
        on
    }

    pub fn fallback_active(&self) -> bool {
        self.fallback.load(Ordering::Relaxed)
    }

    /// [`FALLBACK_NOTICE`] while the defaults are in use.
    pub fn notice(&self) -> Option<&'static str> {
        self.fallback_active().then_some(FALLBACK_NOTICE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn backoff_is_5_15_45_then_every_2_minutes() {
        let sch = Schedule::default();
        let waits: Vec<u64> = (1..=7).map(|n| sch.wait(n).as_secs()).collect();
        assert_eq!(waits, vec![5, 15, 45, 120, 120, 120, 120]);
    }

    #[test]
    fn a_failure_backs_the_relay_off_until_its_time_and_a_success_ends_it() {
        let pool = RelayPool::new();
        let t0 = Instant::now();
        let u = "wss://a.example";
        assert!(pool.eligible_at(t0, u), "untried relays are tried");
        pool.record_failure_at(t0, u, "refused");
        assert!(!pool.eligible_at(t0 + Duration::from_secs(4), u));
        assert!(pool.eligible_at(t0 + Duration::from_secs(5), u));
        // Second failure in a row: 15 s from the failure.
        let t1 = t0 + Duration::from_secs(5);
        pool.record_failure_at(t1, u, "refused");
        assert!(!pool.eligible_at(t1 + Duration::from_secs(14), u));
        assert!(pool.eligible_at(t1 + Duration::from_secs(15), u));
        let t2 = t1 + Duration::from_secs(15);
        pool.record_failure_at(t2, u, "timed out");
        assert_eq!(pool.wait_for_at(t2, u), Duration::from_secs(45));
        let t3 = t2 + Duration::from_secs(45);
        pool.record_failure_at(t3, u, "timed out");
        assert_eq!(pool.wait_for_at(t3, u), Duration::from_secs(120));
        pool.record_failure_at(t3 + Duration::from_secs(120), u, "timed out");
        assert_eq!(
            pool.wait_for_at(t3 + Duration::from_secs(120), u),
            Duration::from_secs(120),
            "steady"
        );
        // Recovery clears the backoff and the next failure starts again at 5 s.
        pool.record_success(u, Some(ms(80)));
        assert!(pool.eligible(u));
        assert!(!pool.failing(u));
        let t4 = Instant::now();
        pool.record_failure_at(t4, u, "reset");
        assert_eq!(pool.wait_for_at(t4, u), Duration::from_secs(5));
    }

    #[test]
    fn the_health_record_counts_and_keeps_the_last_error() {
        let pool = RelayPool::new();
        let u = "wss://a.example";
        pool.record_success(u, Some(ms(100)));
        pool.record_failure(u, "connection reset");
        pool.record_failure(u, "timed out");
        let v = pool.view(u);
        assert_eq!((v.successes, v.failures), (1, 2));
        assert_eq!(v.last_error.as_deref(), Some("timed out"));
        assert_eq!(v.latency, Some(ms(100)));
        assert!(v.retry_in.is_some());
        // A different spelling is the same relay.
        assert_eq!(pool.view("WSS://A.example:443/").failures, 2);
    }

    #[test]
    fn dots_are_green_amber_red_and_grey_for_untried() {
        let pool = RelayPool::new();
        assert_eq!(pool.dot("wss://new.example"), Dot::Unknown);
        // Green: working, quick.
        pool.record_success("wss://g.example", Some(ms(200)));
        assert_eq!(pool.dot("wss://g.example"), Dot::Green);
        // Amber: slow rolling latency.
        pool.record_success("wss://s.example", Some(ms(2000)));
        pool.record_success("wss://s.example", Some(ms(1800)));
        assert_eq!(pool.dot("wss://s.example"), Dot::Amber);
        // Not slow at exactly the limit.
        pool.record_success("wss://e.example", Some(SLOW));
        assert_eq!(pool.dot("wss://e.example"), Dot::Green);
        // Amber: flaky (a failure in the last 5 attempts) though working now.
        let f = "wss://f.example";
        pool.record_success(f, Some(ms(100)));
        pool.record_failure(f, "dropped");
        pool.record_success(f, Some(ms(100)));
        assert_eq!(pool.dot(f), Dot::Amber);
        // ...and green again once the failure leaves the 5-attempt window.
        for _ in 0..WINDOW {
            pool.record_success(f, Some(ms(100)));
        }
        assert_eq!(pool.dot(f), Dot::Green);
        // Red: failing now.
        pool.record_success("wss://r.example", Some(ms(100)));
        pool.record_failure("wss://r.example", "refused");
        assert_eq!(pool.dot("wss://r.example"), Dot::Red);
        // The rolling latency forgets old samples.
        let q = "wss://q.example";
        pool.record_success(q, Some(ms(3000)));
        for _ in 0..WINDOW {
            pool.record_latency(q, ms(100));
        }
        assert_eq!(pool.dot(q), Dot::Green);
    }

    #[test]
    fn order_is_the_players_order_with_each_relay_once() {
        let pool = RelayPool::new();
        let got = pool.order(&s(&[
            "wss://b.example",
            "wss://A.example",
            "wss://b.example/",
            "wss://c.example:443",
        ]));
        assert_eq!(
            got,
            s(&["wss://b.example", "wss://A.example", "wss://c.example:443"])
        );
    }

    #[test]
    fn writers_are_the_top_healthy_relays_in_order_at_least_three() {
        let pool = RelayPool::new();
        let list = s(&[
            "wss://1.x",
            "wss://2.x",
            "wss://3.x",
            "wss://4.x",
            "wss://5.x",
            "wss://6.x",
            "wss://7.x",
        ]);
        assert_eq!(
            pool.writers(&list),
            s(&[
                "wss://1.x",
                "wss://2.x",
                "wss://3.x",
                "wss://4.x",
                "wss://5.x"
            ])
        );
        // The top one is down: the next healthy ones take its place, order kept.
        pool.record_failure("wss://1.x", "refused");
        pool.record_failure("wss://3.x", "refused");
        assert_eq!(
            pool.writers(&list),
            s(&[
                "wss://2.x",
                "wss://4.x",
                "wss://5.x",
                "wss://6.x",
                "wss://7.x"
            ])
        );
        // Fewer healthy than the minimum: all the healthy ones (never the dead).
        let short = s(&["wss://1.x", "wss://2.x", "wss://3.x"]);
        assert_eq!(pool.writers(&short), s(&["wss://2.x"]));
        // A short list is used whole.
        assert_eq!(
            pool.writers(&s(&["wss://8.x", "wss://9.x"])),
            s(&["wss://8.x", "wss://9.x"])
        );
    }

    #[test]
    fn first_healthy_prefers_order_then_health() {
        let pool = RelayPool::new();
        let list = s(&["ws://plain.x", "wss://a.x", "wss://b.x"]);
        let wss = |u: &str| u.starts_with("wss://");
        assert_eq!(pool.first_healthy(&list, wss).as_deref(), Some("wss://a.x"));
        pool.record_failure("wss://a.x", "refused");
        assert_eq!(pool.first_healthy(&list, wss).as_deref(), Some("wss://b.x"));
        pool.record_failure("wss://b.x", "refused");
        assert_eq!(
            pool.first_healthy(&list, wss).as_deref(),
            Some("wss://a.x"),
            "all down: still the top one"
        );
        assert_eq!(pool.first_healthy(&list, |_| false), None);
    }

    #[test]
    fn the_defaults_are_the_last_resort_when_every_listed_relay_is_failing() {
        let pool = RelayPool::with(s(&["wss://d1.x", "wss://d2.x"]), Schedule::default());
        let list = s(&["wss://mine.x", "wss://d2.x/"]);
        assert!(!pool.all_failing(&list));
        assert_eq!(pool.plan(&list), (list.clone(), false));
        pool.record_failure("wss://mine.x", "refused");
        assert!(!pool.all_failing(&list), "one is still fine");
        assert!(pool.fallback_extras(&list).is_empty());
        pool.record_failure("wss://d2.x", "refused");
        assert!(pool.all_failing(&list));
        // Defaults come after the list; one already on the list is not repeated.
        assert_eq!(pool.fallback_extras(&list), s(&["wss://d1.x"]));
        assert_eq!(
            pool.plan(&list),
            (s(&["wss://mine.x", "wss://d2.x/", "wss://d1.x"]), true)
        );
        // A listed relay coming back ends the fallback.
        pool.record_success("wss://mine.x", None);
        assert_eq!(pool.plan(&list), (list.clone(), false));
        // No list at all is not a failure of the list.
        assert!(!pool.all_failing(&[]));
    }

    #[test]
    fn the_notice_follows_the_fallback() {
        let pool = RelayPool::new();
        assert_eq!(pool.notice(), None);
        pool.set_fallback(true);
        assert_eq!(
            pool.notice(),
            Some("Your relays are unreachable; using defaults")
        );
        pool.set_fallback(false);
        assert_eq!(pool.notice(), None);
    }

    #[test]
    fn the_normaliser_folds_case_default_ports_and_trailing_slashes() {
        let one = normalize_relay_url("wss://nos.lol");
        for same in [
            "wss://Nos.Lol",
            "wss://nos.lol:443",
            "wss://nos.lol/",
            " WSS://NOS.LOL:443/ ",
        ] {
            assert_eq!(normalize_relay_url(same), one, "{same}");
        }
        assert_eq!(
            normalize_relay_url("ws://relay.test:80/"),
            normalize_relay_url("ws://relay.test")
        );
        for other in ["wss://nos.lol:444", "wss://nos.lol/x", "ws://nos.lol"] {
            assert_ne!(normalize_relay_url(other), one, "{other}");
        }
        assert_eq!(normalize_relay_url("wss://a.b/Path/"), "wss://a.b/Path");
    }
}
