//! A tiny in-process websocket relay for tests: speaks just enough NIP-01
//! (`REQ` / `EVENT` / `CLOSE`, `EOSE` / `OK`) on 127.0.0.1, fans events out to
//! every matching subscriber, and can be killed (all connections dropped and
//! new ones refused) and revived, to test dropped and returning relays.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use nostr::Event;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use crate::relay::TagFilter;

struct State {
    down: AtomicBool,
    /// Bumped to drop every open connection.
    kill: tokio::sync::watch::Sender<u64>,
    bus: tokio::sync::broadcast::Sender<Event>,
    reqs: AtomicUsize,
    closes: AtomicUsize,
    conns: AtomicUsize,
    tries: AtomicUsize,
    received: Mutex<Vec<Event>>,
}

#[derive(Clone)]
pub struct FakeWsRelay {
    pub url: String,
    state: Arc<State>,
}

fn parse_filter(v: &Value) -> Option<TagFilter> {
    let kind = v.get("kinds")?.as_array()?.first()?.as_u64()? as u16;
    let (key, vals) = v.as_object()?.iter().find(|(k, _)| k.starts_with('#'))?;
    let letter = key.chars().nth(1)?;
    let values = vals
        .as_array()?
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    Some(TagFilter {
        kind,
        letter,
        values,
    })
}

fn matches(ev: &Event, f: &TagFilter) -> bool {
    ev.kind == nostr::Kind::Custom(f.kind)
        && ev.tags.iter().any(|t| {
            let s = t.as_slice();
            s.len() >= 2 && s[0] == f.letter.to_string() && f.values.iter().any(|v| *v == s[1])
        })
}

impl FakeWsRelay {
    pub fn start() -> FakeWsRelay {
        let listener = crate::runtime()
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        let (kill, _) = tokio::sync::watch::channel(0u64);
        let (bus, _) = tokio::sync::broadcast::channel(256);
        let state = Arc::new(State {
            down: AtomicBool::new(false),
            kill,
            bus,
            reqs: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            conns: AtomicUsize::new(0),
            tries: AtomicUsize::new(0),
            received: Mutex::new(Vec::new()),
        });
        let st = Arc::clone(&state);
        crate::runtime().spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                st.tries.fetch_add(1, Ordering::Relaxed);
                if st.down.load(Ordering::Relaxed) {
                    drop(tcp);
                    continue;
                }
                let st = Arc::clone(&st);
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                    st.conns.fetch_add(1, Ordering::Relaxed);
                    let (mut sink, mut stream) = ws.split();
                    let mut subs: Vec<(String, TagFilter)> = Vec::new();
                    let mut bus = st.bus.subscribe();
                    let mut kill = st.kill.subscribe();
                    loop {
                        tokio::select! {
                            _ = kill.changed() => break,
                            ev = bus.recv() => {
                                let Ok(ev) = ev else { continue };
                                for (sid, f) in &subs {
                                    if matches(&ev, f) {
                                        let _ = sink.send(Message::Text(json!(["EVENT", sid, ev]).to_string().into())).await;
                                    }
                                }
                            }
                            msg = stream.next() => {
                                let Some(Ok(Message::Text(t))) = msg else { break };
                                let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) else { continue };
                                match a.first().and_then(|v| v.as_str()) {
                                    Some("REQ") => {
                                        st.reqs.fetch_add(1, Ordering::Relaxed);
                                        let sid = a.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
                                        if let Some(f) = a.get(2).and_then(parse_filter) {
                                            subs.retain(|(s, _)| *s != sid);
                                            subs.push((sid.clone(), f));
                                        }
                                        let _ = sink.send(Message::Text(json!(["EOSE", sid]).to_string().into())).await;
                                    }
                                    Some("CLOSE") => {
                                        st.closes.fetch_add(1, Ordering::Relaxed);
                                        let sid = a.get(1).and_then(|v| v.as_str()).unwrap_or("");
                                        subs.retain(|(s, _)| s != sid);
                                    }
                                    Some("EVENT") => {
                                        let Some(Ok(ev)) = a.get(1).map(|v| serde_json::from_value::<Event>(v.clone())) else { continue };
                                        let id = ev.id.to_hex();
                                        st.received.lock().expect("received").push(ev.clone());
                                        let _ = st.bus.send(ev);
                                        let _ = sink.send(Message::Text(json!(["OK", id, true, ""]).to_string().into())).await;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    st.conns.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
        FakeWsRelay { url, state }
    }

    /// Drop every connection and refuse new ones.
    pub fn kill(&self) {
        self.state.down.store(true, Ordering::Relaxed);
        self.state.kill.send_modify(|n| *n += 1);
    }

    /// Accept connections again.
    pub fn revive(&self) {
        self.state.down.store(false, Ordering::Relaxed);
    }

    /// Hand `ev` to every matching subscriber, as if another client had published it.
    pub fn inject(&self, ev: &Event) {
        let _ = self.state.bus.send(ev.clone());
    }

    /// `REQ`s received so far (a resubscription after a reconnect adds one).
    pub fn reqs(&self) -> usize {
        self.state.reqs.load(Ordering::Relaxed)
    }

    /// `CLOSE`s received so far.
    pub fn closes(&self) -> usize {
        self.state.closes.load(Ordering::Relaxed)
    }

    /// TCP connection attempts so far, refused ones included.
    pub fn attempts(&self) -> usize {
        self.state.tries.load(Ordering::Relaxed)
    }

    /// Open connections right now.
    pub fn connections(&self) -> usize {
        self.state.conns.load(Ordering::Relaxed)
    }

    /// Events clients published to this relay.
    pub fn received(&self) -> Vec<Event> {
        self.state.received.lock().expect("received").clone()
    }
}
