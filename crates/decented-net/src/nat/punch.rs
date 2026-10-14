//! Opening the hole, and racing across it.
//!
//! **The punch.** A home router will forward an inbound packet from an address
//! it has recently seen an outbound packet *to*. So both sides send a few
//! throwaway datagrams at each of the peer's candidate addresses before either
//! tries to connect. Nothing is expected back — the datagrams exist to teach
//! each router that this conversation is wanted.
//!
//! Punch datagrams are plain and unauthenticated on purpose: they carry no
//! secret, and forging one achieves nothing an attacker could not achieve by
//! sending any UDP packet. They arrive on the socket quinn owns, which drops
//! them as not-QUIC — so punching from a `try_clone()` of the server socket
//! (which is what makes the source port match the one quinn will connect from)
//! is harmless to the QUIC endpoint.
//!
//! **Nothing reads a punch.** Neither side has a receive path for them: quinn
//! owns the socket and discards anything that is not QUIC, which is exactly
//! what should happen to an unauthenticated datagram. The session id is in the
//! payload so a punch is recognisable in a packet capture, not so that code can
//! act on it — a parser here would be a parser for attacker-chosen bytes with
//! nothing to decide.
//!
//! **The race.** There is no way to know in advance which candidate will work,
//! so all of them are dialled, staggered 150 ms apart in priority order, and
//! the first to complete the ALPN handshake wins. [`ConnectRace`] is that
//! decision as a pure state machine — no sockets, no clock of its own — so
//! "first success wins, everything else is aborted, and there is never a second
//! winner" is provable in a unit test rather than hoped for at a playtest.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Prefix that marks a datagram as ours. Chosen so it cannot collide with a
/// QUIC long header (whose first byte always has the high bit set).
pub const PUNCH_MAGIC: &[u8; 10] = b"DCNT-PUNCH";
/// How many punches per target. Three is enough to survive ordinary loss
/// without looking like a flood to anybody's router.
pub const PUNCH_COUNT: usize = 3;
/// Gap between successive punch rounds.
pub const PUNCH_GAP: Duration = Duration::from_millis(100);
/// Gap between successive connect attempts, best candidate first.
pub const CONNECT_STAGGER: Duration = Duration::from_millis(150);
/// Overall budget for the connect race. Past this the joiner shows the
/// "couldn't reach" copy.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(8);

/// `DCNT-PUNCH` followed by the session id, so a stray punch from an unrelated
/// attempt is recognisable in a log.
pub fn punch_datagram(session: &str) -> Vec<u8> {
    let mut d = PUNCH_MAGIC.to_vec();
    d.extend_from_slice(session.as_bytes());
    d
}

/// Send [`PUNCH_COUNT`] datagrams to every target, [`PUNCH_GAP`] apart.
///
/// `sock` must be the socket the QUIC connect will come from — in practice a
/// `try_clone()` of the endpoint's socket — because a router only forwards the
/// reply to the **source port** it saw go out. Punching from a fresh socket
/// opens a hole for a port nothing will ever use.
///
/// Blocking (it sleeps between rounds — about 200 ms total), so call it from a
/// worker thread, never the app loop. Send errors are logged and skipped: an
/// unreachable candidate is exactly the case this exists to work around.
pub fn send_punches(sock: &UdpSocket, targets: &[SocketAddr], session: &str) {
    let d = punch_datagram(session);
    // Spelled for this socket's family: v4-mapped on a dual-stack socket, and
    // an IPv6 target dropped on an IPv4-only one.
    let v6 = crate::nat::addr::is_v6_socket(sock);
    let targets: Vec<SocketAddr> = targets
        .iter()
        .filter_map(|t| crate::nat::addr::for_socket(v6, *t))
        .collect();
    for round in 0..PUNCH_COUNT {
        for t in &targets {
            if let Err(e) = sock.send_to(&d, t) {
                log::debug!("[nat] punch {round} to {t}: {e}");
            }
        }
        if round + 1 < PUNCH_COUNT {
            std::thread::sleep(PUNCH_GAP);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaceOutcome {
    /// This candidate index completed the handshake first.
    Won(usize),
    /// Every candidate was tried and every one failed.
    AllFailed,
    /// The 8 s budget ran out with dials still outstanding.
    TimedOut,
}

/// The parallel-connect decision, as pure state.
///
/// Candidate indices are positions in the caller's priority-ordered candidate
/// list (`nat::candidates`), so index 0 is the best one. Task 14 drives this
/// with real quinn connects; here it is deliberately sockets-free.
///
/// # Panics
///
/// [`Self::on_connected`] and [`Self::on_failed`] index the candidate list, so
/// they panic on an `idx >= n`. Only ever feed them an index that came back
/// from [`Self::advance`].
pub struct ConnectRace {
    n: usize,
    dialed: usize,
    failed: usize,
    in_flight: Vec<bool>,
    outcome: Option<RaceOutcome>,
}

impl ConnectRace {
    pub fn new(n: usize) -> Self {
        ConnectRace {
            n,
            dialed: 0,
            failed: 0,
            in_flight: vec![false; n],
            // Nothing to try is a loss, immediately — not a wait for the
            // deadline. The joiner gets the right message eight seconds sooner.
            outcome: (n == 0).then_some(RaceOutcome::AllFailed),
        }
    }

    /// Advance the clock to `elapsed` since the race started. Returns every
    /// candidate index whose stagger slot has arrived and which must be dialled
    /// now — a list, not one index, so a caller that is a tick late catches up
    /// rather than skipping candidates.
    pub fn advance(&mut self, elapsed: Duration) -> Vec<usize> {
        if self.outcome.is_some() {
            return Vec::new();
        }
        if elapsed >= CONNECT_DEADLINE {
            self.outcome = Some(RaceOutcome::TimedOut);
            return Vec::new();
        }
        let due = (elapsed.as_millis() / CONNECT_STAGGER.as_millis()) as usize + 1;
        let due = due.min(self.n);
        let mut start = Vec::new();
        while self.dialed < due {
            self.in_flight[self.dialed] = true;
            start.push(self.dialed);
            self.dialed += 1;
        }
        start
    }

    /// Candidate `idx` completed its handshake. Returns the indices to abort:
    /// every OTHER dial still in flight. A second success after a winner is
    /// ignored and returns an empty list — there is exactly one connection.
    pub fn on_connected(&mut self, idx: usize) -> Vec<usize> {
        if self.outcome.is_some() {
            return Vec::new();
        }
        self.outcome = Some(RaceOutcome::Won(idx));
        let abort: Vec<usize> = (0..self.n)
            .filter(|i| *i != idx && self.in_flight[*i])
            .collect();
        for i in &abort {
            self.in_flight[*i] = false;
        }
        self.in_flight[idx] = false;
        abort
    }

    /// Candidate `idx` failed. Only ends the race once every candidate has been
    /// dialled and every one has failed — and never overrides a win.
    pub fn on_failed(&mut self, idx: usize) {
        if self.outcome.is_some() || !self.in_flight[idx] {
            return;
        }
        self.in_flight[idx] = false;
        self.failed += 1;
        if self.failed == self.n {
            self.outcome = Some(RaceOutcome::AllFailed);
        }
    }

    /// `None` while the race is still running.
    pub fn outcome(&self) -> Option<RaceOutcome> {
        self.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const S: &str = "0123456789abcdef0123456789abcdef";

    /// The inverse of [`punch_datagram`], for the tests only.
    ///
    /// It used to be shipped as `punch::is_punch`, and nothing ever called it —
    /// there is no receive path (see the module docs), so a parser for
    /// attacker-chosen bytes with nothing to decide had no business being in
    /// the binary. The properties it proves about the datagram's SHAPE are
    /// worth keeping, so it lives here instead.
    fn is_punch(buf: &[u8]) -> Option<String> {
        let tail = buf.strip_prefix(PUNCH_MAGIC.as_slice())?;
        std::str::from_utf8(tail).ok().map(str::to_string)
    }

    #[test]
    fn a_punch_datagram_is_recognisable_and_carries_its_session() {
        let d = punch_datagram(S);
        assert!(d.starts_with(PUNCH_MAGIC));
        assert_eq!(is_punch(&d).as_deref(), Some(S));
    }

    #[test]
    fn anything_else_is_not_a_punch() {
        assert_eq!(is_punch(b"hello"), None);
        assert_eq!(is_punch(&[]), None);
        assert_eq!(
            is_punch(b"DCNT-PUNC"),
            None,
            "a truncated magic is not a match"
        );
        // A QUIC Initial-looking datagram must never be read as a punch.
        assert_eq!(is_punch(&[0xc0, 0x00, 0x00, 0x00, 0x01]), None);
    }

    #[test]
    fn a_punch_with_a_non_utf8_tail_is_rejected_rather_than_lossy_decoded() {
        let mut d = PUNCH_MAGIC.to_vec();
        d.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(is_punch(&d), None);
    }

    #[test]
    fn dials_are_staggered_one_per_150ms_in_priority_order() {
        let mut r = ConnectRace::new(3);
        assert_eq!(
            r.advance(Duration::ZERO),
            vec![0],
            "the best candidate goes first"
        );
        assert_eq!(r.advance(Duration::from_millis(149)), Vec::<usize>::new());
        assert_eq!(r.advance(Duration::from_millis(150)), vec![1]);
        assert_eq!(r.advance(Duration::from_millis(300)), vec![2]);
        assert_eq!(r.advance(Duration::from_millis(450)), Vec::<usize>::new());
        assert!(r.outcome().is_none(), "still racing");
    }

    #[test]
    fn a_late_advance_catches_up_every_due_dial_at_once() {
        // The caller may be a tick behind; nothing should be skipped.
        let mut r = ConnectRace::new(4);
        assert_eq!(r.advance(Duration::from_millis(500)), vec![0, 1, 2, 3]);
    }

    #[test]
    fn the_first_success_wins_and_the_others_are_aborted() {
        let mut r = ConnectRace::new(3);
        r.advance(Duration::from_millis(500));
        assert_eq!(
            r.on_connected(1),
            vec![0, 2],
            "every OTHER in-flight dial is aborted"
        );
        assert_eq!(r.outcome(), Some(RaceOutcome::Won(1)));
    }

    #[test]
    fn a_second_success_after_a_winner_is_ignored() {
        // Two candidates can complete within microseconds of each other; only
        // one connection may be handed to the app.
        let mut r = ConnectRace::new(3);
        r.advance(Duration::from_millis(500));
        r.on_connected(1);
        assert_eq!(
            r.on_connected(2),
            Vec::<usize>::new(),
            "no second abort list"
        );
        assert_eq!(
            r.outcome(),
            Some(RaceOutcome::Won(1)),
            "the first winner stands"
        );
    }

    #[test]
    fn a_failed_candidate_does_not_end_the_race_until_all_have_failed() {
        let mut r = ConnectRace::new(2);
        r.advance(Duration::from_millis(500));
        r.on_failed(0);
        assert!(r.outcome().is_none(), "one left to try");
        r.on_failed(1);
        assert_eq!(r.outcome(), Some(RaceOutcome::AllFailed));
    }

    #[test]
    fn a_failure_after_a_win_cannot_turn_a_win_into_a_loss() {
        let mut r = ConnectRace::new(2);
        r.advance(Duration::from_millis(500));
        r.on_connected(0);
        r.on_failed(1);
        assert_eq!(r.outcome(), Some(RaceOutcome::Won(0)));
    }

    #[test]
    fn the_deadline_fires_at_eight_seconds() {
        let mut r = ConnectRace::new(2);
        r.advance(Duration::from_millis(500));
        assert!(r.outcome().is_none());
        r.advance(CONNECT_DEADLINE);
        assert_eq!(r.outcome(), Some(RaceOutcome::TimedOut));
        assert_eq!(
            r.advance(CONNECT_DEADLINE + Duration::from_secs(1)),
            Vec::<usize>::new(),
            "a finished race dials nothing more"
        );
    }

    #[test]
    fn a_race_with_no_candidates_fails_immediately() {
        let mut r = ConnectRace::new(0);
        assert_eq!(r.advance(Duration::ZERO), Vec::<usize>::new());
        assert_eq!(r.outcome(), Some(RaceOutcome::AllFailed));
    }

    #[test]
    fn send_punches_writes_three_datagrams_per_target() {
        // Two loopback sockets stand in for two houses. No timing assertion —
        // just that every target receives PUNCH_COUNT datagrams carrying the
        // session.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let target = receiver.local_addr().unwrap();

        send_punches(&sender, &[target], S);

        let mut buf = [0u8; 256];
        let mut got = 0;
        while got < PUNCH_COUNT {
            let (n, from) = receiver
                .recv_from(&mut buf)
                .unwrap_or_else(|e| panic!("punch {got} should arrive: {e}"));
            // A reused ephemeral port can catch a stray datagram from another
            // process's earlier socket: only ours count.
            if from != sender.local_addr().unwrap() {
                continue;
            }
            assert_eq!(is_punch(&buf[..n]).as_deref(), Some(S));
            got += 1;
        }
    }

    #[test]
    fn a_dual_stack_socket_punches_ipv4_and_ipv6_targets() {
        let sender = crate::nat::addr::bind_dual_stack(0).unwrap();
        let v4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut targets = vec![v4.local_addr().unwrap()];
        let v6 = std::net::UdpSocket::bind("[::1]:0").ok();
        if let Some(v6) = &v6 {
            targets.push(v6.local_addr().unwrap());
        }
        send_punches(&sender, &targets, "s6");
        let mut receivers = vec![v4];
        receivers.extend(v6);
        for r in receivers {
            r.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 64];
            let (n, _) = r.recv_from(&mut buf).expect("the punch arrived");
            assert_eq!(&buf[..n], punch_datagram("s6").as_slice());
        }
    }
}
