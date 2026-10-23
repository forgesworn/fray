//! Talking to Nostr relays, behind a trait so every state machine above it is
//! testable with no network.
//!
//! [`MultiRelay`] is a worker (on the crate runtime) holding one websocket per
//! relay, in the player's order. Which relay may be dialled, and when, comes from
//! the shared [`RelayPool`] (5 s, 15 s, 45 s, then every 2 min after a failure),
//! except that each relay's first dial from a new worker (a join or host
//! start) goes out at once, whatever backoff built up while nothing was waiting;
//! reads (the standing subscription) go to every connected relay, writes to the
//! top healthy few in order. When every listed relay is failing, the pool's
//! built-in defaults are dialled as a last resort. [`FakeRelayHub`] is an
//! in-memory bus that applies the same `kind` + single-letter-tag filter a real
//! relay applies.
//!
//! This layer is a pipe, not a gate: the same event arrives once per relay
//! that delivers it (dedupe by id above), and nothing out of `try_recv` is
//! trusted until `rendezvous::open_*` has passed on it.
//!
//! Adapted from Axe'n'Stax `rendezvous/relay_client.rs` and
//! `native_mailbox/relay.rs` (MIT).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use decented_relays::{RelayPool, WRITE_FANOUT};
use futures_util::{SinkExt, StreamExt};
use nostr::Event;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;

/// A standing subscription: one event kind, one single-letter tag, any of
/// `values` (a host listens on today's and yesterday's room tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagFilter {
    pub kind: u16,
    pub letter: char,
    pub values: Vec<String>,
}

impl TagFilter {
    pub fn one(kind: u16, letter: char, value: impl Into<String>) -> Self {
        TagFilter {
            kind,
            letter,
            values: vec![value.into()],
        }
    }
}

/// A pre-queue check run on every received event: only events it accepts take
/// a slot in the bounded receive queue (so junk can never push out the one
/// event that matters).
pub type AcceptFn = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

pub trait RendezvousRelay: Send + Sync {
    /// Queue `ev` for every relay (including ones that connect later, until it
    /// is too old to matter).
    fn publish(&self, ev: &Event) -> Result<(), String>;
    /// Replace the standing subscription.
    fn subscribe(&self, filter: TagFilter) -> Result<(), String>;
    /// Drop the standing subscription.
    fn unsubscribe(&self) -> Result<(), String>;
    /// Next received event, if any. Never blocks.
    fn try_recv(&self) -> Option<Event>;
    /// `(connected, configured)` relay counts.
    fn connected(&self) -> (usize, usize);
    /// Install (or clear) the pre-queue check.
    fn set_accept(&self, _accept: Option<AcceptFn>) {}
    /// Whether an accepted event was ever dropped because the queue was full.
    fn overflowed(&self) -> bool {
        false
    }
}

// ─── Frames (plain NIP-01 arrays) ───────────────────────────────────────────

const SUB_ID: &str = "rz";

#[derive(Debug)]
pub enum Frame {
    Event(Box<Event>),
    Eose,
    Ok { id: String, accepted: bool },
    Other,
}

pub fn req_frame(sub_id: &str, f: &TagFilter, since: u64) -> String {
    let mut filter = serde_json::Map::new();
    filter.insert("kinds".into(), json!([f.kind]));
    filter.insert(format!("#{}", f.letter), json!(f.values));
    filter.insert("since".into(), json!(since));
    json!(["REQ", sub_id, filter]).to_string()
}

/// Most tag values one relay `REQ` carries. A longer standing subscription
/// (a room holding many invites) goes out as several `REQ`s of at most this
/// many, on every relay; one with this many or fewer is a single `REQ`, as
/// ever.
pub const MAX_TAGS_PER_REQ: usize = 16;

/// The subscription id of the `i`th `REQ` of the standing subscription: the
/// first is [`SUB_ID`] itself, so a small subscription is unchanged.
fn chunk_sub_id(i: usize) -> String {
    if i == 0 {
        SUB_ID.to_string()
    } else {
        format!("{SUB_ID}{i}")
    }
}

/// Whether `id` names one of the standing subscription's `REQ`s.
fn is_standing_sub_id(id: &str) -> bool {
    id.strip_prefix(SUB_ID)
        .is_some_and(|rest| rest.is_empty() || rest.bytes().all(|b| b.is_ascii_digit()))
}

/// How many `REQ`s a filter with `values` tag values takes (never fewer than one).
fn req_count(values: usize) -> usize {
    values.div_ceil(MAX_TAGS_PER_REQ).max(1)
}

/// The `(sub id, REQ frame)` pairs for a standing filter: its values split
/// into chunks of at most [`MAX_TAGS_PER_REQ`].
fn req_frames(f: &TagFilter, since: u64) -> Vec<(String, String)> {
    (0..req_count(f.values.len()))
        .map(|i| {
            let part = TagFilter {
                kind: f.kind,
                letter: f.letter,
                values: f
                    .values
                    .iter()
                    .skip(i * MAX_TAGS_PER_REQ)
                    .take(MAX_TAGS_PER_REQ)
                    .cloned()
                    .collect(),
            };
            let id = chunk_sub_id(i);
            let frame = req_frame(&id, &part, since);
            (id, frame)
        })
        .collect()
}

pub fn close_frame(sub_id: &str) -> String {
    json!(["CLOSE", sub_id]).to_string()
}

pub fn event_frame(ev: &Event) -> String {
    json!(["EVENT", ev]).to_string()
}

pub fn parse_frame(text: &str, sub_id: &str) -> Frame {
    parse_frame_where(text, |id| id == sub_id)
}

fn parse_frame_where(text: &str, ours: impl Fn(&str) -> bool) -> Frame {
    let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(text) else {
        return Frame::Other;
    };
    let s = |i: usize| arr.get(i).and_then(|x| x.as_str());
    match arr.first().and_then(|x| x.as_str()) {
        Some("EVENT") if s(1).is_some_and(&ours) => match arr.get(2) {
            Some(v) => match serde_json::from_value::<Event>(v.clone()) {
                Ok(ev) => Frame::Event(Box::new(ev)),
                Err(_) => Frame::Other,
            },
            None => Frame::Other,
        },
        Some("EOSE") if s(1).is_some_and(&ours) => Frame::Eose,
        Some("OK") => Frame::Ok {
            id: s(1).unwrap_or_default().to_string(),
            accepted: arr.get(2).and_then(|x| x.as_bool()).unwrap_or(false),
        },
        _ => Frame::Other,
    }
}

fn sub_since() -> u64 {
    crate::unix_now().saturating_sub(crate::rendezvous::CLOCK_SKEW_SECS)
}

fn tag_matches(ev: &Event, f: &TagFilter) -> bool {
    let letter = f.letter.to_string();
    ev.kind == nostr::Kind::Custom(f.kind)
        && ev.tags.iter().any(|t| {
            let s = t.as_slice();
            s.len() >= 2 && s[0] == letter && f.values.iter().any(|v| *v == s[1])
        })
}

// ─── In-memory fake ─────────────────────────────────────────────────────────

struct HubInner {
    subs: Vec<Option<TagFilter>>,
    inboxes: Vec<VecDeque<Event>>,
    accepts: Vec<Option<AcceptFn>>,
    overflow: Vec<bool>,
}

/// An in-memory relay several clients share. Applies the real filter.
#[derive(Clone)]
pub struct FakeRelayHub {
    inner: Arc<Mutex<HubInner>>,
}

impl Default for FakeRelayHub {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRelayHub {
    pub fn new() -> Self {
        FakeRelayHub {
            inner: Arc::new(Mutex::new(HubInner {
                subs: Vec::new(),
                inboxes: Vec::new(),
                accepts: Vec::new(),
                overflow: Vec::new(),
            })),
        }
    }

    pub fn client(&self) -> FakeRelay {
        let mut g = self.inner.lock().expect("hub mutex");
        g.inboxes.push(VecDeque::new());
        g.subs.push(None);
        g.accepts.push(None);
        g.overflow.push(false);
        FakeRelay {
            inner: Arc::clone(&self.inner),
            id: g.inboxes.len() - 1,
        }
    }
}

pub struct FakeRelay {
    inner: Arc<Mutex<HubInner>>,
    id: usize,
}

impl RendezvousRelay for FakeRelay {
    fn publish(&self, ev: &Event) -> Result<(), String> {
        let mut g = self.inner.lock().map_err(|_| "hub mutex".to_string())?;
        let targets: Vec<usize> = g
            .subs
            .iter()
            .enumerate()
            .filter(|(_, f)| f.as_ref().is_some_and(|f| tag_matches(ev, f)))
            .map(|(i, _)| i)
            .collect();
        // Same rules as the live worker: the pre-queue check, then a bounded
        // inbox that records overflow instead of growing.
        for t in targets {
            if g.accepts[t].as_ref().is_some_and(|a| !a(ev)) {
                continue;
            }
            if g.inboxes[t].len() >= EVENT_QUEUE {
                g.overflow[t] = true;
                continue;
            }
            g.inboxes[t].push_back(ev.clone());
        }
        Ok(())
    }

    fn subscribe(&self, filter: TagFilter) -> Result<(), String> {
        let mut g = self.inner.lock().map_err(|_| "hub mutex".to_string())?;
        g.subs[self.id] = Some(filter);
        Ok(())
    }

    fn unsubscribe(&self) -> Result<(), String> {
        let mut g = self.inner.lock().map_err(|_| "hub mutex".to_string())?;
        g.subs[self.id] = None;
        Ok(())
    }

    fn try_recv(&self) -> Option<Event> {
        self.inner
            .lock()
            .ok()?
            .inboxes
            .get_mut(self.id)?
            .pop_front()
    }

    fn connected(&self) -> (usize, usize) {
        (1, 1)
    }

    fn set_accept(&self, accept: Option<AcceptFn>) {
        if let Ok(mut g) = self.inner.lock() {
            g.accepts[self.id] = accept;
        }
    }

    fn overflowed(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.overflow[self.id])
            .unwrap_or(true)
    }
}

/// Dedup by id, cap per author, verify the signature: in that order, cheapest
/// first. `true` = this event may be queued.
fn admit_event(
    ev: &Event,
    seen: &mut std::collections::HashSet<nostr::EventId>,
    per_author: &mut std::collections::HashMap<nostr::PublicKey, (u32, Instant)>,
) -> bool {
    if seen.len() > 4096 {
        seen.clear();
    }
    if !seen.insert(ev.id) {
        return false;
    }
    if per_author.len() > 4096 {
        per_author.retain(|_, (_, t)| t.elapsed() < AUTHOR_WINDOW);
    }
    let slot = per_author.entry(ev.pubkey).or_insert((0, Instant::now()));
    if slot.1.elapsed() >= AUTHOR_WINDOW {
        *slot = (0, Instant::now());
    }
    slot.0 += 1;
    if slot.0 > PER_AUTHOR_MAX {
        return false;
    }
    ev.verify().is_ok()
}

// ─── The live worker ────────────────────────────────────────────────────────

enum Cmd {
    Publish(Box<Event>),
    Subscribe(TagFilter),
    Unsubscribe,
    SetAccept(Option<AcceptFn>),
}

type RelaySocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const MAX_PENDING_PUBLISH: usize = 8;
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const READ_POLL: Duration = Duration::from_millis(30);
const MAX_READS_PER_TURN: usize = 32;
/// Bound on received-but-unread events: a flooding relay drops, never grows.
pub const EVENT_QUEUE: usize = 256;
/// Events queued per author (signing key) per [`AUTHOR_WINDOW`]; more are dropped.
pub const PER_AUTHOR_MAX: u32 = 16;
const AUTHOR_WINDOW: Duration = Duration::from_secs(10);
/// A relay that stops reading must not wedge the worker.
const SEND_TIMEOUT: Duration = Duration::from_secs(3);
/// Largest websocket message / frame accepted from a relay.
const MAX_WS_MESSAGE: usize = 64 * 1024;

async fn send_text(ws: &mut RelaySocket, text: String) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, ws.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

struct PendingPublish {
    frame: String,
    sent: Vec<bool>,
    expires: Instant,
}

/// One websocket per relay, on the crate runtime. Dropping it stops the worker.
pub struct MultiRelay {
    cmd_tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
    ev_rx: Mutex<mpsc::Receiver<Event>>,
    connected: Arc<AtomicUsize>,
    total: usize,
    shutdown: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
}

impl MultiRelay {
    /// Dial `urls` (the player's order) on the process-wide pool, with the
    /// built-in defaults as the last resort.
    pub fn start(urls: Vec<String>) -> MultiRelay {
        Self::start_in(RelayPool::global(), urls, true)
    }

    /// [`MultiRelay::start`] on a pool of its own; `fallback` = may the pool's
    /// defaults stand in while every listed relay is failing.
    pub fn start_in(pool: Arc<RelayPool>, urls: Vec<String>, fallback: bool) -> MultiRelay {
        // rustls needs a process-wide crypto provider for wss://. Installing
        // one fails harmlessly when the app (or another crate) already did.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
        let (ev_tx, ev_rx) = mpsc::sync_channel::<Event>(EVENT_QUEUE);
        let connected = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let overflow = Arc::new(AtomicBool::new(false));
        let listed = pool.order(&urls);
        let total = listed.len();
        let worker = relay_worker(
            pool,
            listed,
            fallback,
            cmd_rx,
            ev_tx,
            Arc::clone(&connected),
            Arc::clone(&shutdown),
            Arc::clone(&overflow),
        );
        crate::runtime().spawn(async move {
            use futures_util::FutureExt;
            if std::panic::AssertUnwindSafe(worker)
                .catch_unwind()
                .await
                .is_err()
            {
                log::error!("[relay] worker panicked; relays are down");
            }
        });
        MultiRelay {
            cmd_tx,
            ev_rx: Mutex::new(ev_rx),
            connected,
            total,
            shutdown,
            overflow,
        }
    }
}

impl Drop for MultiRelay {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl RendezvousRelay for MultiRelay {
    fn publish(&self, ev: &Event) -> Result<(), String> {
        self.cmd_tx
            .send(Cmd::Publish(Box::new(ev.clone())))
            .map_err(|_| "relay worker is gone".into())
    }

    fn subscribe(&self, filter: TagFilter) -> Result<(), String> {
        self.cmd_tx
            .send(Cmd::Subscribe(filter))
            .map_err(|_| "relay worker is gone".into())
    }

    fn unsubscribe(&self) -> Result<(), String> {
        self.cmd_tx
            .send(Cmd::Unsubscribe)
            .map_err(|_| "relay worker is gone".into())
    }

    fn try_recv(&self) -> Option<Event> {
        self.ev_rx.lock().ok()?.try_recv().ok()
    }

    fn connected(&self) -> (usize, usize) {
        (self.connected.load(Ordering::Relaxed), self.total)
    }

    fn set_accept(&self, accept: Option<AcceptFn>) {
        let _ = self.cmd_tx.send(Cmd::SetAccept(accept));
    }

    fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::Relaxed)
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_worker(
    pool: Arc<RelayPool>,
    listed: Vec<String>,
    fallback: bool,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    ev_tx: mpsc::SyncSender<Event>,
    connected: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
) {
    // The listed relays, in the player's order; then the defaults, which are
    // dialled only while every listed relay is failing.
    let listed_n = listed.len();
    let mut urls = listed.clone();
    if fallback {
        let known: Vec<String> = urls
            .iter()
            .map(|u| decented_relays::normalize_relay_url(u))
            .collect();
        urls.extend(
            pool.defaults()
                .iter()
                .filter(|d| !known.contains(&decented_relays::normalize_relay_url(d)))
                .cloned(),
        );
    }
    let n = urls.len();
    let mut sockets: Vec<Option<RelaySocket>> = (0..n).map(|_| None).collect();
    let mut dialing = vec![false; n];
    // Each relay's first dial in this worker ignores the pool's backoff: a
    // join or host start is somebody waiting now, and the backoff may have
    // grown while nothing was waiting (the app in the background). Only that
    // first dial is free; a failure starts or lengthens the backoff as usual,
    // and every later automatic redial obeys it.
    let mut first_dial = vec![true; n];
    let (dial_tx, mut dial_rx) =
        tokio::sync::mpsc::unbounded_channel::<(usize, Result<RelaySocket, String>, Duration)>();
    let mut standing: Option<TagFilter> = None;
    let mut pending: Vec<PendingPublish> = Vec::new();
    let publish_ttl = Duration::from_secs(crate::rendezvous::CLOCK_SKEW_SECS);
    let mut dropped = 0usize;
    let mut accept: Option<AcceptFn> = None;
    // The same event arrives once per relay; queue it once.
    let mut seen_ids: std::collections::HashSet<nostr::EventId> = std::collections::HashSet::new();
    let mut per_author: std::collections::HashMap<nostr::PublicKey, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut using_defaults = false;

    while !shutdown.load(Ordering::Relaxed) {
        // 0. Are the defaults needed? Only while every listed relay is failing.
        let want_defaults = fallback && n > listed_n && pool.all_failing(&listed);
        if want_defaults != using_defaults {
            using_defaults = want_defaults;
            pool.set_fallback(want_defaults);
            if !want_defaults {
                // A listed relay is back: the stand-ins hang up.
                for (i, s) in sockets.iter_mut().enumerate().skip(listed_n) {
                    if s.take().is_some() {
                        log::info!("[relays] {} no longer needed", urls[i]);
                    }
                }
            }
        }

        // 1. (Re)connect everything that is down and allowed (its backoff is
        //    over), each dial on its own task so one black-hole relay never
        //    delays the others. The dial after a backoff is the quiet re-probe.
        //    A relay's first dial from this worker goes out whatever its backoff.
        for i in 0..n {
            if sockets[i].is_some()
                || dialing[i]
                || (i >= listed_n && !using_defaults)
                || (!first_dial[i] && !pool.eligible(&urls[i]))
            {
                continue;
            }
            first_dial[i] = false;
            dialing[i] = true;
            let url = urls[i].clone();
            let tx = dial_tx.clone();
            tokio::spawn(async move {
                let ws_cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                    .max_message_size(Some(MAX_WS_MESSAGE))
                    .max_frame_size(Some(MAX_WS_MESSAGE));
                let started = Instant::now();
                let dial = tokio_tungstenite::connect_async_with_config(url, Some(ws_cfg), false);
                let r = tokio::time::timeout(DIAL_TIMEOUT, dial)
                    .await
                    .map_err(|_| "timed out".to_string())
                    .and_then(|r| {
                        r.map_err(|e| e.to_string().chars().take(120).collect::<String>())
                    })
                    .map(|(ws, _)| ws);
                let _ = tx.send((i, r, started.elapsed()));
            });
        }
        while let Ok((i, dial, took)) = dial_rx.try_recv() {
            dialing[i] = false;
            match dial {
                Ok(mut ws) => {
                    log::info!("[relays] connected {} in {} ms", urls[i], took.as_millis());
                    pool.record_success(&urls[i], Some(took));
                    if let Some(f) = standing.as_ref() {
                        for (_, frame) in req_frames(f, sub_since()) {
                            let _ = send_text(&mut ws, frame).await;
                        }
                    }
                    sockets[i] = Some(ws);
                }
                Err(why) => pool.record_failure(&urls[i], &why),
            }
        }
        connected.store(
            sockets.iter().filter(|s| s.is_some()).count(),
            Ordering::Relaxed,
        );

        // 2. Commands. Publishes are queued; 2b sends them to whoever lacks them.
        loop {
            let cmd = match cmd_rx.try_recv() {
                Ok(c) => c,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                // Owner dropped without setting shutdown (cannot happen, but be safe).
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    shutdown.store(true, Ordering::Relaxed);
                    break;
                }
            };
            match cmd {
                Cmd::Subscribe(f) => {
                    let frames = req_frames(&f, sub_since());
                    // REQs this one replaces by id; ids past the new count
                    // are closed.
                    let old_n = standing
                        .as_ref()
                        .map_or(0, |old| req_count(old.values.len()));
                    let stale: Vec<String> = (frames.len()..old_n).map(chunk_sub_id).collect();
                    for ws in sockets.iter_mut().flatten() {
                        for (_, frame) in &frames {
                            let _ = send_text(ws, frame.clone()).await;
                        }
                        for id in &stale {
                            let _ = send_text(ws, close_frame(id)).await;
                        }
                    }
                    standing = Some(f);
                }
                Cmd::Unsubscribe => {
                    if let Some(old) = standing.take() {
                        let ids: Vec<String> = (0..req_count(old.values.len()))
                            .map(chunk_sub_id)
                            .collect();
                        for ws in sockets.iter_mut().flatten() {
                            for id in &ids {
                                let _ = send_text(ws, close_frame(id)).await;
                            }
                        }
                    }
                }
                Cmd::SetAccept(a) => accept = a,
                Cmd::Publish(ev) => {
                    pending.push(PendingPublish {
                        frame: event_frame(&ev),
                        sent: vec![false; n],
                        expires: Instant::now() + publish_ttl,
                    });
                    if pending.len() > MAX_PENDING_PUBLISH {
                        pending.remove(0);
                    }
                }
            }
        }

        // 2b. Each pending publish goes to the top connected relays, in the
        //     player's order, until WRITE_FANOUT have it. A relay that is down
        //     is skipped, so the next one in the list takes its place; one that
        //     connects later still gets the event until it is too old to matter.
        if !pending.is_empty() {
            for p in pending.iter_mut() {
                let mut have = p.sent.iter().filter(|&&s| s).count();
                for (i, socket) in sockets.iter_mut().enumerate() {
                    if have >= WRITE_FANOUT {
                        break;
                    }
                    if p.sent[i] {
                        continue;
                    }
                    let Some(ws) = socket.as_mut() else { continue };
                    if send_text(ws, p.frame.clone()).await {
                        p.sent[i] = true;
                        have += 1;
                    }
                }
            }
            let now = Instant::now();
            pending.retain(|p| {
                let have = p.sent.iter().filter(|&&s| s).count();
                !(have >= WRITE_FANOUT || have == p.sent.len() || now >= p.expires)
            });
        }

        // 3. Drain whatever arrived.
        let mut read_any = false;
        for i in 0..n {
            for _ in 0..MAX_READS_PER_TURN {
                let Some(ws) = sockets[i].as_mut() else { break };
                match tokio::time::timeout(READ_POLL, ws.next()).await {
                    Ok(Some(Ok(Message::Text(t)))) => {
                        read_any = true;
                        match parse_frame_where(&t, is_standing_sub_id) {
                            Frame::Event(ev) => {
                                // Only what we asked for; a relay may send anything.
                                let wanted = standing.as_ref().is_some_and(|f| tag_matches(&ev, f));
                                if !wanted || !admit_event(&ev, &mut seen_ids, &mut per_author) {
                                    continue;
                                }
                                if accept.as_ref().is_some_and(|a| !a(&ev)) {
                                    continue;
                                }
                                if ev_tx.try_send(*ev).is_err() {
                                    overflow.store(true, Ordering::Relaxed);
                                    dropped += 1;
                                    if dropped == 1 || dropped.is_multiple_of(EVENT_QUEUE) {
                                        log::warn!("[relay] event queue full — {dropped} dropped");
                                    }
                                }
                            }
                            Frame::Ok {
                                id,
                                accepted: false,
                            } => {
                                log::warn!("[relay] {} rejected event {id}", urls[i]);
                            }
                            Frame::Ok { .. } | Frame::Eose | Frame::Other => {}
                        }
                    }
                    Ok(Some(Err(_)) | None) => {
                        // Dropped: back off, then reconnect and re-send the subscription.
                        pool.record_failure(&urls[i], "connection closed");
                        sockets[i] = None;
                        break;
                    }
                    Ok(Some(Ok(_))) => read_any = true,
                    Err(_) => break,
                }
            }
        }
        if !read_any {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    for ws in sockets.iter_mut().flatten() {
        let _ = ws.close(None).await;
    }
    connected.store(0, Ordering::Relaxed);
    if using_defaults {
        pool.set_fallback(false);
    }
    log::info!("[relay] worker stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn ev(kind: u16, letter: &str, value: &str) -> Event {
        EventBuilder::new(Kind::Custom(kind), "x")
            .tags([Tag::parse([letter, value]).unwrap()])
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    #[test]
    fn req_frame_uses_the_requested_tag_letter() {
        let f = TagFilter {
            kind: 20910,
            letter: 't',
            values: vec!["abc".into(), "def".into()],
        };
        let v: serde_json::Value = serde_json::from_str(&req_frame("rz", &f, 7)).unwrap();
        assert_eq!(v[0], "REQ");
        assert_eq!(v[1], "rz");
        assert_eq!(v[2]["kinds"][0], 20910);
        assert_eq!(v[2]["#t"], serde_json::json!(["abc", "def"]));
        assert_eq!(v[2]["since"], 7);
        let c: serde_json::Value = serde_json::from_str(&close_frame("rz")).unwrap();
        assert_eq!(c, serde_json::json!(["CLOSE", "rz"]));
    }

    #[test]
    fn frames_round_trip() {
        let e = ev(1, "t", "a");
        match parse_frame(
            &format!("[\"EVENT\",\"rz\",{}]", serde_json::to_string(&e).unwrap()),
            "rz",
        ) {
            Frame::Event(got) => assert_eq!(got.id, e.id),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_frame("[\"EOSE\",\"rz\"]", "rz"),
            Frame::Eose
        ));
        assert!(matches!(
            parse_frame("[\"EOSE\",\"zz\"]", "rz"),
            Frame::Other
        ));
        assert!(matches!(parse_frame("garbage", "rz"), Frame::Other));
        let v: serde_json::Value = serde_json::from_str(&event_frame(&e)).unwrap();
        assert_eq!(v[0], "EVENT");
    }

    #[test]
    fn fake_hub_applies_kind_and_tag_filter() {
        let hub = FakeRelayHub::new();
        let a = hub.client();
        let b = hub.client();
        a.subscribe(TagFilter {
            kind: 20910,
            letter: 't',
            values: vec!["room".into(), "room2".into()],
        })
        .unwrap();
        b.publish(&ev(20910, "t", "other")).unwrap();
        b.publish(&ev(20911, "t", "room")).unwrap();
        b.publish(&ev(20910, "p", "room")).unwrap();
        assert!(a.try_recv().is_none());
        b.publish(&ev(20910, "t", "room")).unwrap();
        assert!(a.try_recv().is_some());
        b.publish(&ev(20910, "t", "room2")).unwrap();
        assert!(a.try_recv().is_some(), "either listed value matches");
        a.unsubscribe().unwrap();
        b.publish(&ev(20910, "t", "room")).unwrap();
        assert!(a.try_recv().is_none());
    }

    #[test]
    fn the_worker_queues_each_event_once_caps_each_author_and_drops_forgeries() {
        let mut seen = std::collections::HashSet::new();
        let mut per = std::collections::HashMap::new();
        let e = ev(20911, "p", "x");
        assert!(admit_event(&e, &mut seen, &mut per));
        assert!(
            !admit_event(&e, &mut seen, &mut per),
            "same id from a second relay"
        );
        let k = Keys::generate();
        let mut ok = 0;
        for i in 0..(PER_AUTHOR_MAX + 10) {
            let e = EventBuilder::new(Kind::Custom(20911), format!("{i}"))
                .sign_with_keys(&k)
                .unwrap();
            ok += admit_event(&e, &mut seen, &mut per) as u32;
        }
        assert_eq!(ok, PER_AUTHOR_MAX);
        let mut v: serde_json::Value = serde_json::to_value(ev(20911, "p", "y")).unwrap();
        v["content"] = serde_json::Value::String("tampered".into());
        let forged: Event = serde_json::from_value(v).unwrap();
        assert!(!admit_event(&forged, &mut seen, &mut per));
    }

    #[test]
    fn the_fake_hub_applies_the_accept_check_and_a_bounded_inbox() {
        let hub = FakeRelayHub::new();
        let a = hub.client();
        let b = hub.client();
        a.subscribe(TagFilter::one(20911, 'p', "me")).unwrap();
        a.set_accept(Some(Arc::new(|e: &Event| e.content == "good")));
        for _ in 0..(EVENT_QUEUE * 2) {
            b.publish(
                &EventBuilder::new(Kind::Custom(20911), "junk")
                    .tags([Tag::parse(["p", "me"]).unwrap()])
                    .sign_with_keys(&Keys::generate())
                    .unwrap(),
            )
            .unwrap();
        }
        assert!(!a.overflowed(), "junk never took a slot");
        b.publish(
            &EventBuilder::new(Kind::Custom(20911), "good")
                .tags([Tag::parse(["p", "me"]).unwrap()])
                .sign_with_keys(&Keys::generate())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(a.try_recv().map(|e| e.content), Some("good".to_string()));
        a.set_accept(None);
        for _ in 0..(EVENT_QUEUE + 1) {
            b.publish(&ev(20911, "p", "me")).unwrap();
        }
        assert!(
            a.overflowed(),
            "a full inbox is reported, not silently grown"
        );
    }

    // ── MultiRelay over in-process websocket relays ──

    use crate::fake_ws::FakeWsRelay;
    use decented_relays::Schedule;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A pool with a backoff of 60 ms, 120 ms, then 200 ms, and its own defaults.
    fn fast_pool(defaults: Vec<String>) -> Arc<RelayPool> {
        Arc::new(RelayPool::with(
            defaults,
            Schedule::new(vec![ms(60), ms(120)], ms(200)),
        ))
    }

    fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(v) = f() {
                return v;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(ms(10));
        }
    }

    fn drain(m: &MultiRelay, settle: Duration) -> Vec<Event> {
        let mut out = Vec::new();
        let until = Instant::now() + settle;
        while Instant::now() < until {
            while let Some(e) = m.try_recv() {
                out.push(e);
            }
            std::thread::sleep(ms(10));
        }
        out
    }

    fn tagged(content: &str) -> Event {
        EventBuilder::new(Kind::Custom(20911), content)
            .tags([Tag::parse(["p", "me"]).unwrap()])
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    #[test]
    fn reads_go_to_every_relay_at_once_and_merge_without_duplicates() {
        let (a, b) = (FakeWsRelay::start(), FakeWsRelay::start());
        let m = MultiRelay::start_in(fast_pool(vec![]), vec![a.url.clone(), b.url.clone()], false);
        m.subscribe(TagFilter::one(20911, 'p', "me")).unwrap();
        eventually("both relays carry the subscription", || {
            (a.reqs() == 1 && b.reqs() == 1).then_some(())
        });
        assert_eq!(m.connected(), (2, 2));
        let (both, only_b) = (tagged("both"), tagged("only b"));
        a.inject(&both);
        b.inject(&both);
        b.inject(&only_b);
        let got = drain(&m, ms(600));
        let mut ids: Vec<_> = got.iter().map(|e| e.id).collect();
        ids.sort();
        let mut want = vec![both.id, only_b.id];
        want.sort();
        assert_eq!(
            ids, want,
            "the event both relays carried arrives once, the other too"
        );
    }

    fn tagged_with(value: &str) -> Event {
        EventBuilder::new(Kind::Custom(20911), "x")
            .tags([Tag::parse(["p", value]).unwrap()])
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    fn many(n: usize) -> TagFilter {
        TagFilter {
            kind: 20911,
            letter: 'p',
            values: (0..n).map(|i| format!("tag-{i}")).collect(),
        }
    }

    #[test]
    fn a_small_subscription_is_one_unchanged_req() {
        // 0 and up to MAX_TAGS_PER_REQ values: one frame, identical to the
        // single-REQ frame.
        for n in [0, 1, MAX_TAGS_PER_REQ] {
            let f = many(n);
            let frames = req_frames(&f, 7);
            assert_eq!(frames.len(), 1, "{n} tags");
            assert_eq!(frames[0].0, SUB_ID);
            assert_eq!(frames[0].1, req_frame(SUB_ID, &f, 7), "{n} tags");
        }
        assert_eq!(req_frames(&many(MAX_TAGS_PER_REQ + 1), 7).len(), 2);
        assert!(is_standing_sub_id("rz") && is_standing_sub_id("rz4"));
        assert!(!is_standing_sub_id("rzx") && !is_standing_sub_id("other"));
    }

    #[test]
    fn seventy_tags_go_out_as_five_reqs_per_relay_and_every_tag_is_answered() {
        let (a, b) = (FakeWsRelay::start(), FakeWsRelay::start());
        let m = MultiRelay::start_in(fast_pool(vec![]), vec![a.url.clone(), b.url.clone()], false);
        m.subscribe(many(70)).unwrap();
        eventually("five REQs on each relay", || {
            (a.reqs() == 5 && b.reqs() == 5).then_some(())
        });
        std::thread::sleep(ms(200));
        assert_eq!((a.reqs(), b.reqs()), (5, 5), "no more than five");
        // One event per tag, each from its own key; relay a carries the even
        // ones, relay b the odd ones.
        let mut want = Vec::new();
        for i in 0..70 {
            let e = tagged_with(&format!("tag-{i}"));
            want.push(e.id);
            if i % 2 == 0 { &a } else { &b }.inject(&e);
        }
        let got = drain(&m, ms(1500));
        let mut ids: Vec<_> = got.iter().map(|e| e.id).collect();
        ids.sort();
        want.sort();
        assert_eq!(ids, want, "every tag, across the chunks, is answered");
        // An event for a tag nobody asked for is not queued.
        a.inject(&tagged_with("not-asked"));
        assert!(drain(&m, ms(300)).is_empty());
    }

    #[test]
    fn a_long_subscription_is_resent_whole_on_reconnect_and_shrinking_closes_the_extras() {
        let a = FakeWsRelay::start();
        let pool = fast_pool(vec![]);
        let m = MultiRelay::start_in(pool, vec![a.url.clone()], false);
        m.subscribe(many(70)).unwrap();
        eventually("five REQs", || (a.reqs() == 5).then_some(()));
        a.kill();
        eventually("the drop", || (m.connected().0 == 0).then_some(()));
        a.revive();
        eventually("all five again after the reconnect", || {
            (m.connected().0 == 1 && a.reqs() == 10).then_some(())
        });
        // Shrinking to two chunks replaces rz and rz1 and closes rz2..rz4.
        m.subscribe(many(20)).unwrap();
        eventually("the three extras closed", || {
            (a.reqs() == 12 && a.closes() == 3).then_some(())
        });
        m.unsubscribe().unwrap();
        eventually("the rest closed", || (a.closes() == 5).then_some(()));
    }

    #[test]
    fn writes_go_to_the_top_healthy_relays_in_the_players_order() {
        let relays: Vec<FakeWsRelay> = (0..7).map(|_| FakeWsRelay::start()).collect();
        relays[0].kill();
        let urls: Vec<String> = relays.iter().map(|r| r.url.clone()).collect();
        let pool = fast_pool(vec![]);
        let m = MultiRelay::start_in(pool.clone(), urls.clone(), false);
        eventually("the six live relays to connect", || {
            (m.connected().0 == 6).then_some(())
        });
        assert!(
            pool.failing(&urls[0]),
            "the dead top relay is recorded as failing"
        );
        m.publish(&tagged("offer")).unwrap();
        eventually("the top five healthy relays have it", || {
            relays[1..=5]
                .iter()
                .all(|r| r.received().len() == 1)
                .then_some(())
        });
        std::thread::sleep(ms(300));
        assert!(
            relays[0].received().is_empty(),
            "the dead relay got nothing"
        );
        assert!(
            relays[6].received().is_empty(),
            "the sixth healthy relay is past the fan-out"
        );
    }

    #[test]
    fn a_dropped_relay_reconnects_with_backoff_and_resubscribes() {
        let a = FakeWsRelay::start();
        let pool = fast_pool(vec![]);
        let m = MultiRelay::start_in(pool.clone(), vec![a.url.clone()], false);
        m.subscribe(TagFilter::one(20911, 'p', "me")).unwrap();
        eventually("the first REQ", || {
            (a.reqs() == 1 && m.connected().0 == 1).then_some(())
        });
        a.kill();
        eventually("the drop to be noticed", || {
            (m.connected().0 == 0 && pool.failing(&a.url)).then_some(())
        });
        std::thread::sleep(ms(300)); // a few failed re-probes while it is down
        assert_eq!(m.connected().0, 0);
        a.revive();
        eventually("a reconnect that re-sends the subscription", || {
            (m.connected().0 == 1 && a.reqs() == 2).then_some(())
        });
        assert!(!pool.failing(&a.url), "working again");
        assert_eq!(
            pool.dot(&a.url),
            decented_relays::Dot::Amber,
            "flaky: a failure in the last five attempts"
        );
        let e = tagged("after");
        a.inject(&e);
        eventually("the event published after the reconnect", || {
            m.try_recv().filter(|x| x.id == e.id)
        });
    }

    #[test]
    fn the_defaults_stand_in_while_every_listed_relay_is_down_and_hang_up_when_one_returns() {
        let (l1, l2, d) = (
            FakeWsRelay::start(),
            FakeWsRelay::start(),
            FakeWsRelay::start(),
        );
        l1.kill();
        l2.kill();
        let pool = fast_pool(vec![d.url.clone()]);
        let m = MultiRelay::start_in(pool.clone(), vec![l1.url.clone(), l2.url.clone()], true);
        m.subscribe(TagFilter::one(20911, 'p', "me")).unwrap();
        eventually("the defaults to connect", || {
            (pool.fallback_active() && m.connected().0 == 1).then_some(())
        });
        assert_eq!(
            pool.notice(),
            Some("Your relays are unreachable; using defaults")
        );
        assert_eq!(m.connected().1, 2, "the count shown is the player's list");
        let e = tagged("via defaults");
        eventually("the subscription on the default relay", || {
            (d.reqs() >= 1).then_some(())
        });
        d.inject(&e);
        eventually("an event through the defaults", || {
            m.try_recv().filter(|x| x.id == e.id)
        });
        // A listed relay comes back: the defaults are no longer needed.
        l1.revive();
        eventually(
            "the listed relay to return and the defaults to hang up",
            || {
                (!pool.fallback_active()
                    && m.connected().0 == 1
                    && d.connections() == 0
                    && l1.connections() == 1)
                    .then_some(())
            },
        );
        assert_eq!(pool.notice(), None);
    }

    #[test]
    fn with_fallback_off_the_defaults_are_never_dialled() {
        let (l, d) = (FakeWsRelay::start(), FakeWsRelay::start());
        l.kill();
        let pool = fast_pool(vec![d.url.clone()]);
        let m = MultiRelay::start_in(pool.clone(), vec![l.url.clone()], false);
        eventually("the listed relay to be marked failing", || {
            pool.failing(&l.url).then_some(())
        });
        std::thread::sleep(ms(400));
        assert_eq!(m.connected().0, 0);
        assert_eq!(d.connections(), 0);
        assert!(!pool.fallback_active());
    }

    /// A pool whose relays have been failing for a long while: one failure
    /// already recorded, so the next wait is a minute.
    fn pool_in_long_backoff(url: &str) -> Arc<RelayPool> {
        let pool = Arc::new(RelayPool::with(
            vec![],
            Schedule::new(vec![Duration::from_secs(60)], Duration::from_secs(60)),
        ));
        pool.record_failure(url, "network went away in the background");
        assert!(!pool.eligible(url), "set up: the relay is in backoff");
        pool
    }

    #[test]
    fn a_new_start_dials_a_relay_in_long_backoff_at_once() {
        let a = FakeWsRelay::start();
        let pool = pool_in_long_backoff(&a.url);
        let m = MultiRelay::start_in(pool.clone(), vec![a.url.clone()], false);
        m.subscribe(TagFilter::one(20911, 'p', "me")).unwrap();
        eventually("the relay to be dialled despite its backoff", || {
            (m.connected().0 == 1 && a.reqs() == 1).then_some(())
        });
        assert!(
            !pool.failing(&a.url),
            "the dial worked, so the backoff is cleared"
        );
    }

    #[test]
    fn the_free_first_dial_is_the_only_one_a_relay_that_keeps_failing_gets() {
        let a = FakeWsRelay::start();
        a.kill();
        let pool = pool_in_long_backoff(&a.url);
        assert_eq!(a.attempts(), 0);
        let m = MultiRelay::start_in(pool.clone(), vec![a.url.clone()], false);
        eventually("the one free dial", || (a.attempts() == 1).then_some(()));
        eventually("its failure to be recorded", || {
            (pool.view(&a.url).failures == 2).then_some(())
        });
        std::thread::sleep(ms(600));
        assert_eq!(a.attempts(), 1, "no redial storm: the backoff holds again");
        assert_eq!(pool.view(&a.url).failures, 2);
        assert!(
            !pool.eligible(&a.url),
            "still backed off after the free dial failed"
        );
        assert_eq!(m.connected().0, 0);
    }

    #[test]
    fn a_relay_dropped_after_the_free_dial_waits_out_its_backoff_as_before() {
        let a = FakeWsRelay::start();
        let pool = pool_in_long_backoff(&a.url);
        let m = MultiRelay::start_in(pool.clone(), vec![a.url.clone()], false);
        eventually("the free dial to connect", || {
            (m.connected().0 == 1).then_some(())
        });
        a.kill();
        eventually("the drop to be noticed", || {
            (m.connected().0 == 0 && pool.failing(&a.url)).then_some(())
        });
        a.revive();
        std::thread::sleep(ms(600));
        assert_eq!(
            m.connected().0,
            0,
            "a steady-state redial still obeys the backoff"
        );
        assert_eq!(
            a.attempts(),
            1,
            "only the free dial went out; the kill refused none"
        );
    }
}
