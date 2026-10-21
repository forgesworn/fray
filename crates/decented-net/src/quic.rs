//! QUIC plumbing shared by host and client: configs, stream framing, the
//! hello/welcome handshake, the connect race and the pump that moves bytes
//! between a live connection and the app's channels.
//!
//! Every reliable message rides ONE ordered bidirectional stream per
//! connection (`u32` LE length + payload); lossy messages are QUIC datagrams.
//!
//! Adapted from Axe'n'Stax `network.rs` (MIT); datagrams re-enabled.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use nostr::secp256k1::{schnorr::Signature, Message};
use nostr::{Keys, PublicKey};
use sha2::{Digest, Sha256};

use crate::{PathKind, MAX_LOSSY_LEN, MAX_RELIABLE_LEN, NET_PROTOCOL_VERSION};

/// TLS server name. Certificates are self-signed and not verified: the trust
/// anchors are the identity signatures in the hello (joiner) and the welcome
/// (host), both bound to this TLS session.
pub(crate) const SERVER_NAME: &str = "decented-net";
/// RFC 5705 exporter label for the hello's channel binding.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-decented-net-hello-v2";
/// Idle timeout: a peer that vanishes (kill -9, Wi-Fi off) is noticed this fast.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(6);
pub(crate) const KEEP_ALIVE: Duration = Duration::from_secs(1);

/// A checked idle-timeout / keep-alive pair (see [`crate::NetConfig::idle_timeout`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Liveness {
    idle_timeout: Duration,
    keep_alive: Duration,
}

impl Liveness {
    /// Today's constants (tests that build endpoints without a config).
    #[cfg(test)]
    pub(crate) const DEFAULT: Liveness = Liveness {
        idle_timeout: IDLE_TIMEOUT,
        keep_alive: KEEP_ALIVE,
    };

    /// Both non-zero, and the keep-alive shorter than the idle timeout (or it
    /// could never keep a quiet connection open). QUIC carries the idle timeout
    /// in whole milliseconds and reads 0 as "never", so it is at least 1 ms.
    pub(crate) fn new(idle_timeout: Duration, keep_alive: Duration) -> Result<Liveness, String> {
        if idle_timeout < Duration::from_millis(1) {
            return Err(format!(
                "idle_timeout ({idle_timeout:?}) must be at least 1 ms"
            ));
        }
        if keep_alive.is_zero() {
            return Err("keep_alive must not be zero".into());
        }
        if keep_alive >= idle_timeout {
            return Err(format!(
                "keep_alive ({keep_alive:?}) must be shorter than idle_timeout ({idle_timeout:?})"
            ));
        }
        if quinn::IdleTimeout::try_from(idle_timeout).is_err() {
            return Err(format!("idle_timeout ({idle_timeout:?}) is too long"));
        }
        Ok(Liveness {
            idle_timeout,
            keep_alive,
        })
    }
}
/// QUIC handshake + stream open + hello must finish within this.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// A session-bound (pinned-listener) handshake attempt has this one overall
/// deadline instead of staged timeouts: the joiner from dial start to an
/// accepted, bound session; the pinned host from accept to an authenticated
/// binding, so a stalled peer frees its pending-handshake slot by then.
pub(crate) const SESSION_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
/// Bytes queued for one peer before it is declared too slow and dropped.
pub(crate) const MAX_OUTBOUND_QUEUE_BYTES: usize = 1024 * 1024;

/// Application close codes.
pub(crate) mod close {
    pub const LEAVE: u32 = 0;
    pub const HOST_SHUTDOWN: u32 = 1;
    pub const KICKED: u32 = 2;
    pub const FULL: u32 = 3;
    pub const CLOSED: u32 = 4;
    pub const VERSION: u32 = 5;
    pub const BAD_HELLO: u32 = 6;
    pub const TOO_SLOW: u32 = 7;
    /// The joiner refused the host: its welcome did not verify, or its key
    /// did not match the one that answered the room code.
    pub const HOST_UNVERIFIED: u32 = 8;
    /// The hello carried no valid admission proof (no code / LAN token).
    pub const NOT_ADMITTED: u32 = 9;
    /// The peer sent more than we could take: dropped.
    pub const FLOOD: u32 = 10;
    /// The joiner sat on the confirm screen too long: dropped, not banned.
    pub const CONFIRM_TIMEOUT: u32 = 11;
}

/// Hello and welcome frames may be larger than an app message.
pub(crate) const HANDSHAKE_FRAME_CAP: usize = 8192;
/// The first frame (hello) is read before the joiner is admitted, so it gets
/// a much smaller cap: 3 proofs of 64 hex characters plus a few fields.
pub(crate) const HELLO_FRAME_CAP: usize = 2048;
/// At most this many admission proofs in one hello (today + yesterday).
pub(crate) const MAX_ADMIT_PROOFS: usize = 3;

/// Longest host display name carried in a welcome (bytes).
pub(crate) const MAX_HOST_NAME: usize = 64;

pub(crate) fn alpn(app_tag: &str) -> Vec<u8> {
    format!("{app_tag}/dnet{NET_PROTOCOL_VERSION}").into_bytes()
}

/// The transport settings every endpoint shares (a virtual link adds its MTU
/// pins on top; see `virt`).
pub(crate) fn base_transport(live: Liveness) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(
        live.idle_timeout.try_into().expect("checked by Liveness"),
    ));
    t.keep_alive_interval(Some(live.keep_alive));
    t.datagram_receive_buffer_size(Some(256 * 1024));
    t.datagram_send_buffer_size(256 * 1024);
    t
}

fn transport_config(live: Liveness) -> Arc<quinn::TransportConfig> {
    Arc::new(base_transport(live))
}

pub(crate) fn server_config(app_tag: &str, live: Liveness) -> Result<quinn::ServerConfig, String> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .map_err(|e| format!("certificate: {e}"))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| format!("key: {e}"))?;
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| format!("tls: {e}"))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key)
    .map_err(|e| format!("tls: {e}"))?;
    crypto.alpn_protocols = vec![alpn(app_tag)];
    let qc = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| format!("quic tls: {e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(qc));
    cfg.transport_config(transport_config(live));
    Ok(cfg)
}

pub(crate) fn client_config(app_tag: &str, live: Liveness) -> Result<quinn::ClientConfig, String> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| format!("tls: {e}"))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn(app_tag)];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| format!("quic tls: {e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
    cfg.transport_config(transport_config(live));
    Ok(cfg)
}

/// A server endpoint on an already-bound socket (so candidates gathered on it
/// name the port QUIC answers on). Must run inside the runtime.
pub(crate) fn server_endpoint(
    socket: std::net::UdpSocket,
    app_tag: &str,
    live: Liveness,
) -> Result<quinn::Endpoint, String> {
    let runtime = quinn::default_runtime().ok_or("no async runtime")?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config(app_tag, live)?),
        socket,
        runtime,
    )
    .map_err(|e| format!("endpoint: {e}"))
}

pub(crate) fn client_endpoint(
    socket: std::net::UdpSocket,
    app_tag: &str,
    live: Liveness,
) -> Result<quinn::Endpoint, String> {
    let runtime = quinn::default_runtime().ok_or("no async runtime")?;
    let mut ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(|e| format!("endpoint: {e}"))?;
    ep.set_default_client_config(client_config(app_tag, live)?);
    Ok(ep)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─── Framing ────────────────────────────────────────────────────────────────

pub(crate) fn encode_frame(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > HANDSHAKE_FRAME_CAP.max(MAX_RELIABLE_LEN) {
        return None;
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// One frame. `Ok(None)` is a clean end of stream between frames. The length
/// is checked before any body byte is buffered.
pub(crate) async fn read_frame(
    recv: &mut quinn::RecvStream,
    cap: usize,
) -> Result<Option<Bytes>, String> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(format!("frame header: {e}")),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > cap {
        return Err(format!("frame of {len} bytes exceeds the cap"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| format!("frame body: {e}"))?;
    Ok(Some(Bytes::from(buf)))
}

async fn write_frame(send: &mut quinn::SendStream, payload: &[u8]) -> Result<(), String> {
    let frame = encode_frame(payload).ok_or("frame too large")?;
    send.write_all(&frame)
        .await
        .map_err(|e| format!("write: {e}"))
}

// ─── Handshake ──────────────────────────────────────────────────────────────
//
// Protocol v4: four frames on the connection's one stream.
//
// 1. joiner → host [`Hello`]: version, join session, path and admission
//    proofs. Nothing in it identifies the joiner: the proofs are bound to this
//    TLS session, and the identity key is not sent yet (review-net-1 N5).
// 2. host → joiner [`Welcome`]: signed by the host identity over this TLS
//    session. Sent only to an admitted hello, so a dial without the code (or
//    the LAN token) learns nothing about the host.
// 3. joiner → host [`Identify`]: the joiner's identity key, its signature over
//    this TLS session and the host key it verified, and any attestation. Sent
//    only once the welcome verified and, for a code join, matched the answer.
// 4. host → joiner [`Accepted`]: the joiner has a seat (the kick deny-list and
//    the seat count are checked once the host knows who it is).

/// First frame from the joiner: proof of admission, and nothing identifying.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Hello {
    pub v: u32,
    #[serde(default)]
    pub migration: Option<crate::migration::ConnectionBinding>,
    pub session: Option<String>,
    pub path: PathKind,
    /// Proofs of an admission token (code-derived or the LAN beacon's), each
    /// `hex(sha256(label || token || tls_binding))`: the token itself never
    /// crosses the wire, so a fake host can't harvest it.
    pub admit: Vec<String>,
}

/// Third frame, from the joiner: who it is. Sent only to a verified host.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Identify {
    pub pubkey: String,
    /// Over this TLS session, the join session, the verified host key and the
    /// attestation (so it can't be replayed on another connection or to
    /// another host).
    pub sig: String,
    /// Optional persona attestation for `pubkey`, covered by `sig`. Handed
    /// to the app as is (this crate does not verify it).
    #[serde(default)]
    pub attestation: Option<String>,
    /// The joiner's inbox relays (at most 3 `wss://` URLs), covered by `sig`.
    #[serde(default)]
    pub inbox_relays: Vec<String>,
}

/// Last frame, from the host: the joiner is seated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Accepted {
    pub v: u32,
}

/// The host's reply to an admitted hello. Signed by the host identity over
/// this TLS session, so the joiner learns who it is really talking to.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Welcome {
    pub v: u32,
    #[serde(default)]
    pub challenge: [u8; 32],
    #[serde(default)]
    pub migration: Option<crate::migration::ConnectionBinding>,
    pub peer: u32,
    pub host_pubkey: String,
    pub host_name: String,
    /// The throwaway key this host signs its relay answers with (hex). A code
    /// joiner checks it equals the key that answered its offer. On its own
    /// this proves nothing (the relay key is public); the binding is that the
    /// encrypted answer names `host_pubkey`, the key that signs this welcome.
    pub relay_key: String,
    /// Optional persona attestation for `host_pubkey`, covered by `sig`.
    /// Handed to the app as is (this crate does not verify it).
    #[serde(default)]
    pub attestation: Option<String>,
    /// The host's inbox relays (at most 3 `wss://` URLs), covered by `sig`.
    #[serde(default)]
    pub inbox_relays: Vec<String>,
    pub sig: String,
}

/// The host, as proven by a verified welcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostProof {
    pub challenge: [u8; 32],
    pub migration: Option<crate::migration::ConnectionBinding>,
    pub peer: u32,
    pub pubkey: PublicKey,
    pub name: String,
    pub relay_key: PublicKey,
    pub attestation: Option<String>,
    pub inbox_relays: Vec<String>,
}

/// Every exporter label Fray uses itself; an app label may not be one.
const FRAY_EXPORTER_LABELS: &[&[u8]] = &[EXPORTER_LABEL];

/// An app exporter label: `EXPORTER-` prefix (RFC 8446 7.5), at most 249
/// bytes (TLS 1.3 prefixes "tls13 " and caps the whole label at 255), and none
/// of Fray's own.
pub(crate) fn check_app_label(label: &str) -> Result<(), String> {
    if !label.starts_with("EXPORTER-") {
        return Err(format!(
            "app_binding_label ({label:?}) must start with EXPORTER-"
        ));
    }
    if label.len() > 249 {
        return Err(format!(
            "app_binding_label is {} bytes; at most 249 are allowed",
            label.len()
        ));
    }
    if FRAY_EXPORTER_LABELS.contains(&label.as_bytes()) {
        return Err(format!(
            "app_binding_label ({label:?}) is reserved for Fray's own use"
        ));
    }
    Ok(())
}

/// The app's exporter value for this connection (32 bytes, empty context).
/// `None` without a label, or if the exporter fails (the app decides).
pub(crate) fn app_binding(conn: &quinn::Connection, label: Option<&str>) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, label?.as_bytes(), b"")
        .ok()?;
    Some(out)
}

pub(crate) fn binding(conn: &quinn::Connection) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|e| format!("exporter: {e:?}"))?;
    Ok(out)
}

fn identify_digest(
    binding: &[u8; 32],
    session: Option<&str>,
    host: &PublicKey,
    attestation: Option<&str>,
    inbox_relays: &[String],
) -> [u8; 32] {
    let session = session.unwrap_or("");
    let mut h = Sha256::new();
    h.update(b"decented-net-identify-v5");
    h.update(binding);
    h.update((session.len() as u32).to_le_bytes());
    h.update(session.as_bytes());
    h.update(host.to_bytes());
    let a = attestation.unwrap_or("");
    h.update((a.len() as u32).to_le_bytes());
    h.update(a.as_bytes());
    update_inbox_relays(&mut h, inbox_relays);
    h.finalize().into()
}

fn transcript_digest(
    base: [u8; 32],
    challenge: &[u8; 32],
    migration: Option<&crate::migration::ConnectionBinding>,
) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    h.update(b"fray/net/transcript/v7\0");
    h.update(base);
    h.update(challenge);
    match migration {
        None => h.update([0]),
        Some(binding) => {
            h.update([1]);
            h.update(binding.canonical().map_err(|e| e.to_string())?);
        }
    }
    Ok(h.finalize().into())
}

/// Length-prefixed list, so no entry can bleed into the next.
fn update_inbox_relays(h: &mut Sha256, relays: &[String]) {
    h.update((relays.len() as u32).to_le_bytes());
    for r in relays {
        h.update((r.len() as u32).to_le_bytes());
        h.update(r.as_bytes());
    }
}

/// Proof of knowing admission `token` on the connection with exporter `binding`.
pub(crate) fn admit_proof(token: &[u8; 32], binding: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"decented-net-admit-v2");
    h.update(token);
    h.update(binding);
    h.finalize().into()
}

/// Which of `tokens` (by index) `hello` proves on this connection, if any. A
/// hello may carry several proofs (a code joiner sends one per day); the
/// lowest index that matches wins. Every token is checked against every proof
/// (no early exit), so the time taken does not say which token was proved.
pub(crate) fn admitted_which(
    hello: &Hello,
    binding: &[u8; 32],
    tokens: &[[u8; 32]],
) -> Option<usize> {
    let proofs: Vec<&str> = hello
        .admit
        .iter()
        .take(MAX_ADMIT_PROOFS)
        .map(String::as_str)
        .collect();
    let mut found: Option<usize> = None;
    for (i, t) in tokens.iter().enumerate() {
        let want = hex::encode(admit_proof(t, binding));
        let mut hit = false;
        for p in &proofs {
            hit |= ct_str_eq(p, &want);
        }
        if hit && found.is_none() {
            found = Some(i);
        }
    }
    found
}

/// Equality of two strings without stopping at the first difference (the
/// lengths are not secret: a proof is always 64 hex characters).
fn ct_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn welcome_digest(
    binding: &[u8; 32],
    session: Option<&str>,
    peer: u32,
    name: &str,
    relay_key: &str,
    attestation: Option<&str>,
    inbox_relays: &[String],
) -> [u8; 32] {
    let session = session.unwrap_or("");
    let mut h = Sha256::new();
    h.update(b"decented-net-welcome-v3");
    h.update(binding);
    h.update((session.len() as u32).to_le_bytes());
    h.update(session.as_bytes());
    h.update(peer.to_le_bytes());
    h.update((name.len() as u32).to_le_bytes());
    h.update(name.as_bytes());
    h.update((relay_key.len() as u32).to_le_bytes());
    h.update(relay_key.as_bytes());
    let a = attestation.unwrap_or("");
    h.update((a.len() as u32).to_le_bytes());
    h.update(a.as_bytes());
    update_inbox_relays(&mut h, inbox_relays);
    h.finalize().into()
}

/// Build the host's signed welcome for this connection.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_welcome(
    host: &Keys,
    binding: &[u8; 32],
    session: Option<&str>,
    peer: u32,
    name: &str,
    relay_key: &PublicKey,
    attestation: Option<&str>,
    inbox_relays: &[String],
) -> Welcome {
    sign_welcome_bound(
        host,
        binding,
        session,
        peer,
        name,
        relay_key,
        attestation,
        inbox_relays,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_welcome_bound(
    host: &Keys,
    binding: &[u8; 32],
    session: Option<&str>,
    peer: u32,
    name: &str,
    relay_key: &PublicKey,
    attestation: Option<&str>,
    inbox_relays: &[String],
    migration: Option<crate::migration::ConnectionBinding>,
) -> Welcome {
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).expect("OS RNG unavailable");
    let mut end = name.len().min(MAX_HOST_NAME);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let name = &name[..end];
    let relay_key = relay_key.to_hex();
    let attestation = attestation.filter(|a| a.len() <= crate::identity::MAX_ATTESTATION_LEN);
    let inbox_relays = crate::identity::sanitize_inbox_relays(inbox_relays);
    let base = welcome_digest(
        binding,
        session,
        peer,
        name,
        &relay_key,
        attestation,
        &inbox_relays,
    );
    let msg = Message::from_digest(
        transcript_digest(base, &challenge, migration.as_ref())
            .expect("validated migration binding"),
    );
    Welcome {
        v: NET_PROTOCOL_VERSION,
        challenge,
        migration,
        peer,
        host_pubkey: host.public_key().to_hex(),
        host_name: name.to_string(),
        relay_key,
        attestation: attestation.map(str::to_string),
        inbox_relays,
        sig: host.sign_schnorr(&msg).to_string(),
    }
}

/// Check a welcome against this connection. Any failure means: not the host
/// it claims to be (or a replay from another connection).
pub(crate) fn verify_welcome(
    w: &Welcome,
    binding: &[u8; 32],
    session: Option<&str>,
) -> Result<HostProof, String> {
    if w.v != NET_PROTOCOL_VERSION {
        return Err(format!("welcome version {}", w.v));
    }
    if w.host_name.len() > MAX_HOST_NAME {
        return Err("host name too long".into());
    }
    crate::identity::check_inbox_relays(&w.inbox_relays).map_err(|e| format!("welcome: {e}"))?;
    let pk = PublicKey::from_hex(&w.host_pubkey).map_err(|e| format!("host pubkey: {e}"))?;
    let xonly = pk.xonly().map_err(|e| format!("host pubkey: {e}"))?;
    let relay_key = PublicKey::from_hex(&w.relay_key).map_err(|e| format!("relay key: {e}"))?;
    let sig: Signature = w
        .sig
        .parse()
        .map_err(|e| format!("welcome signature: {e}"))?;
    let base = welcome_digest(
        binding,
        session,
        w.peer,
        &w.host_name,
        &w.relay_key,
        w.attestation.as_deref(),
        &w.inbox_relays,
    );
    let msg = Message::from_digest(transcript_digest(base, &w.challenge, w.migration.as_ref())?);
    nostr::SECP256K1
        .verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| "bad welcome signature".to_string())?;
    Ok(HostProof {
        challenge: w.challenge,
        migration: w.migration.clone(),
        peer: w.peer,
        pubkey: pk,
        name: crate::lan::sanitize_name(&w.host_name),
        relay_key,
        attestation: w
            .attestation
            .clone()
            .filter(|a| a.len() <= crate::identity::MAX_ATTESTATION_LEN),
        inbox_relays: w.inbox_relays.clone(),
    })
}

/// What a joiner requires of a verified welcome beyond its signature (for a
/// code join: the identity and relay key the answer named).
pub(crate) type HostCheck = Arc<dyn Fn(&HostProof) -> Result<(), String> + Send + Sync>;

/// A connection whose host proved who it is, before the joiner said who it is.
pub(crate) struct Opened {
    pub conn: quinn::Connection,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub binding: [u8; 32],
    pub proof: HostProof,
}

/// Joiner, phase 1: open the stream, prove admission, then read the welcome,
/// verify it and run `check`. Nothing identifying the joiner is sent.
pub(crate) async fn client_open(
    conn: &quinn::Connection,
    session: Option<&str>,
    path: PathKind,
    tokens: &[[u8; 32]],
    check: &HostCheck,
) -> Result<Opened, HandshakeError> {
    client_open_bound(conn, session, path, tokens, check, None).await
}
pub(crate) async fn client_open_bound(
    conn: &quinn::Connection,
    session: Option<&str>,
    path: PathKind,
    tokens: &[[u8; 32]],
    check: &HostCheck,
    expected: Option<&crate::migration::ConnectionBinding>,
) -> Result<Opened, HandshakeError> {
    if let Some(binding) = expected {
        binding.validate().map_err(|e| e.to_string())?;
    }
    let b = binding(conn)?;
    let hello = Hello {
        v: NET_PROTOCOL_VERSION,
        migration: expected.cloned(),
        session: session.map(str::to_string),
        path,
        admit: tokens
            .iter()
            .take(MAX_ADMIT_PROOFS)
            .map(|t| hex::encode(admit_proof(t, &b)))
            .collect(),
    };
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open stream: {e}"))?;
    let json = serde_json::to_vec(&hello).map_err(|e| e.to_string())?;
    write_frame(&mut send, &json).await?;
    let frame = read_frame(&mut recv, HANDSHAKE_FRAME_CAP)
        .await?
        .ok_or("host closed the stream")?;
    let w: Welcome = serde_json::from_slice(&frame)
        .map_err(|e| HandshakeError::Unverified(format!("welcome: {e}")))?;
    let proof = verify_welcome(&w, &b, session).map_err(HandshakeError::Unverified)?;
    if proof.migration.as_ref() != expected {
        return Err(HandshakeError::Unverified(
            "session/role binding mismatch".into(),
        ));
    }
    check(&proof).map_err(HandshakeError::Unverified)?;
    Ok(Opened {
        conn: conn.clone(),
        send,
        recv,
        binding: b,
        proof,
    })
}

/// Joiner, phase 2: say who we are to the verified host, and wait to be seated.
pub(crate) async fn client_identify(
    opened: &mut Opened,
    keys: &Keys,
    attestation: Option<&str>,
    inbox_relays: &[String],
    session: Option<&str>,
) -> Result<(), HandshakeError> {
    let attestation = attestation.filter(|a| a.len() <= crate::identity::MAX_ATTESTATION_LEN);
    let inbox_relays = crate::identity::sanitize_inbox_relays(inbox_relays);
    let base = identify_digest(
        &opened.binding,
        session,
        &opened.proof.pubkey,
        attestation,
        &inbox_relays,
    );
    let msg = Message::from_digest(transcript_digest(
        base,
        &opened.proof.challenge,
        opened.proof.migration.as_ref(),
    )?);
    let id = Identify {
        pubkey: keys.public_key().to_hex(),
        sig: keys.sign_schnorr(&msg).to_string(),
        attestation: attestation.map(str::to_string),
        inbox_relays,
    };
    let json = serde_json::to_vec(&id).map_err(|e| e.to_string())?;
    write_frame(&mut opened.send, &json).await?;
    let frame = read_frame(&mut opened.recv, HANDSHAKE_FRAME_CAP)
        .await?
        .ok_or("host closed the stream")?;
    let a: Accepted = serde_json::from_slice(&frame).map_err(|e| format!("accepted: {e}"))?;
    if a.v != NET_PROTOCOL_VERSION {
        return Err(HandshakeError::Io(format!("accepted version {}", a.v)));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum HandshakeError {
    /// The connection or stream broke (or the host refused us).
    Io(String),
    /// The host's welcome did not prove who it is.
    Unverified(String),
}

impl From<String> for HandshakeError {
    fn from(e: String) -> Self {
        HandshakeError::Io(e)
    }
}

impl From<&str> for HandshakeError {
    fn from(e: &str) -> Self {
        HandshakeError::Io(e.to_string())
    }
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Io(e) => write!(f, "{e}"),
            HandshakeError::Unverified(e) => write!(f, "host not verified: {e}"),
        }
    }
}

/// Host, phase 1: accept the stream and read the hello. The caller checks
/// admission before answering it.
pub(crate) async fn server_read_hello(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream, Hello), (u32, String)> {
    let (send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| (close::BAD_HELLO, format!("accept stream: {e}")))?;
    let frame = read_frame(&mut recv, HELLO_FRAME_CAP)
        .await
        .map_err(|e| (close::BAD_HELLO, e))?
        .ok_or((close::BAD_HELLO, "no hello".to_string()))?;
    let hello: Hello =
        serde_json::from_slice(&frame).map_err(|e| (close::BAD_HELLO, format!("hello: {e}")))?;
    if hello.v != NET_PROTOCOL_VERSION {
        return Err((close::VERSION, format!("version {}", hello.v)));
    }
    Ok((send, recv, hello))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn server_send_welcome(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    host: &Keys,
    attestation: Option<&str>,
    inbox_relays: &[String],
    name: &str,
    relay_key: &PublicKey,
    session: Option<&str>,
    peer: u32,
) -> Result<HostProof, String> {
    server_send_welcome_bound(
        conn,
        send,
        host,
        attestation,
        inbox_relays,
        name,
        relay_key,
        session,
        peer,
        None,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn server_send_welcome_bound(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    host: &Keys,
    attestation: Option<&str>,
    inbox_relays: &[String],
    name: &str,
    relay_key: &PublicKey,
    session: Option<&str>,
    peer: u32,
    migration: Option<crate::migration::ConnectionBinding>,
) -> Result<HostProof, String> {
    if let Some(binding) = &migration {
        binding.validate().map_err(|e| e.to_string())?;
    }
    let b = binding(conn)?;
    let w = sign_welcome_bound(
        host,
        &b,
        session,
        peer,
        name,
        relay_key,
        attestation,
        inbox_relays,
        migration,
    );
    let json = serde_json::to_vec(&w).map_err(|e| e.to_string())?;
    write_frame(send, &json).await?;
    verify_welcome(&w, &b, session)
}

/// Host, phase 2: read and verify the joiner's identity (signed over this
/// TLS session, the join session and `host`, our own identity key).
pub(crate) async fn server_read_identify(
    conn: &quinn::Connection,
    recv: &mut quinn::RecvStream,
    session: Option<&str>,
    host: &PublicKey,
    transcript: &HostProof,
) -> Result<(PublicKey, Option<String>, Vec<String>), (u32, String)> {
    let frame = read_frame(recv, HANDSHAKE_FRAME_CAP)
        .await
        .map_err(|e| (close::BAD_HELLO, e))?
        .ok_or((close::BAD_HELLO, "no identity".to_string()))?;
    let id: Identify =
        serde_json::from_slice(&frame).map_err(|e| (close::BAD_HELLO, format!("identity: {e}")))?;
    let pk = PublicKey::from_hex(&id.pubkey).map_err(|e| (close::BAD_HELLO, e.to_string()))?;
    let xonly = pk.xonly().map_err(|e| (close::BAD_HELLO, e.to_string()))?;
    let sig: Signature = id
        .sig
        .parse()
        .map_err(|e| (close::BAD_HELLO, format!("signature: {e}")))?;
    if id
        .attestation
        .as_ref()
        .is_some_and(|a| a.len() > crate::identity::MAX_ATTESTATION_LEN)
    {
        return Err((close::BAD_HELLO, "attestation too long".to_string()));
    }
    crate::identity::check_inbox_relays(&id.inbox_relays).map_err(|e| (close::BAD_HELLO, e))?;
    let b = binding(conn).map_err(|e| (close::BAD_HELLO, e))?;
    let base = identify_digest(
        &b,
        session,
        host,
        id.attestation.as_deref(),
        &id.inbox_relays,
    );
    let msg = Message::from_digest(
        transcript_digest(base, &transcript.challenge, transcript.migration.as_ref())
            .map_err(|e| (close::BAD_HELLO, e))?,
    );
    nostr::SECP256K1
        .verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| (close::BAD_HELLO, "bad identity signature".to_string()))?;
    Ok((pk, id.attestation, id.inbox_relays))
}

/// Host, last frame: the joiner is seated.
pub(crate) async fn server_send_accepted(send: &mut quinn::SendStream) -> Result<(), String> {
    let json = serde_json::to_vec(&Accepted {
        v: NET_PROTOCOL_VERSION,
    })
    .map_err(|e| e.to_string())?;
    write_frame(send, &json).await
}

// ─── Sending ────────────────────────────────────────────────────────────────

/// The app-facing half of a live connection.
#[derive(Clone)]
pub(crate) struct Link {
    pub session_key: Option<[u8; 32]>,
    pub session_player: Option<u64>,
    pub session_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub session_channel_claimed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub conn: quinn::Connection,
    pub migration: Option<crate::migration::ConnectionBinding>,
    /// The app's exporter value for this connection ([`app_binding`]).
    pub app_binding: Option<[u8; 32]>,
    pub generation: u64,
    pub tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    pub queued: Arc<AtomicUsize>,
}

impl Link {
    pub fn new(conn: quinn::Connection) -> (Link, tokio::sync::mpsc::UnboundedReceiver<Bytes>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Link {
                session_key: None,
                session_player: None,
                conn,
                migration: None,
                app_binding: None,
                generation: 0,
                session_live: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                session_channel_claimed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                    false,
                )),
                tx,
                queued: Arc::new(AtomicUsize::new(0)),
            },
            rx,
        )
    }

    pub fn send_reliable(&self, bytes: Bytes) {
        if bytes.len() > MAX_RELIABLE_LEN {
            log::warn!(
                "[net] dropping a {}-byte reliable message (cap {MAX_RELIABLE_LEN})",
                bytes.len()
            );
            return;
        }
        let q = self.queued.fetch_add(bytes.len(), Ordering::Relaxed) + bytes.len();
        if q > MAX_OUTBOUND_QUEUE_BYTES {
            log::warn!("[net] {q} bytes queued for a peer that isn't reading; closing");
            self.conn.close(close::TOO_SLOW.into(), b"too slow");
            return;
        }
        let _ = self.tx.send(bytes);
    }

    pub fn send_lossy(&self, bytes: Bytes) {
        if bytes.len() > MAX_LOSSY_LEN {
            log::warn!(
                "[net] dropping a {}-byte lossy message (cap {MAX_LOSSY_LEN})",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.conn.send_datagram(bytes) {
            log::debug!("[net] datagram dropped: {e}");
        }
    }

    pub fn rtt_ms(&self) -> u32 {
        self.conn.rtt().as_millis().min(u32::MAX as u128) as u32
    }
}

// ─── The pump ───────────────────────────────────────────────────────────────

/// How a connection ended, as seen by the pump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ended {
    /// Closed by the other side with an application code.
    Remote(u32),
    TimedOut,
    /// Closed by us (kick, shutdown, too slow).
    Local,
    Error(String),
}

pub(crate) fn ended_of(err: &quinn::ConnectionError) -> Ended {
    match err {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            Ended::Remote(u32::try_from(ac.error_code.into_inner()).unwrap_or(u32::MAX))
        }
        quinn::ConnectionError::TimedOut => Ended::TimedOut,
        quinn::ConnectionError::LocallyClosed => Ended::Local,
        other => Ended::Error(other.to_string()),
    }
}

/// Move bytes until the connection ends. Reliable frames go to `on_reliable`,
/// datagrams to `on_lossy`; `out` feeds the stream. Returns how it ended.
pub(crate) async fn pump(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mut out: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    queued: Arc<AtomicUsize>,
    on_reliable: impl Fn(Bytes) -> bool + Send,
    on_lossy: impl Fn(Bytes) + Send,
) -> Ended {
    let reader = async {
        loop {
            match read_frame(&mut recv, MAX_RELIABLE_LEN).await {
                Ok(Some(p)) => {
                    if !on_reliable(p) {
                        // The app can't keep up with this peer: drop it rather
                        // than buffer without limit.
                        log::warn!("[net] peer flooded reliable messages; closing");
                        conn.close(close::FLOOD.into(), b"flood");
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    log::debug!("[net] read ended: {e}");
                    break;
                }
            }
        }
    };
    let datagrams = async {
        while let Ok(d) = conn.read_datagram().await {
            if d.len() <= MAX_LOSSY_LEN {
                on_lossy(d);
            }
        }
    };
    let writer = async {
        while let Some(data) = out.recv().await {
            queued.fetch_sub(data.len(), Ordering::Relaxed);
            if let Err(e) = write_frame(&mut send, &data).await {
                log::debug!("[net] write ended: {e}");
                return;
            }
        }
        // Our side let go: wait forever; whoever dropped the sender closes.
        std::future::pending::<()>().await;
    };
    tokio::select! {
        _ = reader => {}
        _ = datagrams => {}
        _ = writer => {}
    }
    // Whatever stopped the loop, the connection is (or is about to be) done.
    let err = match conn.close_reason() {
        Some(e) => e,
        None => {
            // The stream ended but the connection did not: the peer finished
            // its stream, which only happens when it is leaving. Give its
            // CONNECTION_CLOSE a moment to arrive, then close ourselves.
            match tokio::time::timeout(Duration::from_millis(500), conn.closed()).await {
                Ok(e) => e,
                Err(_) => {
                    conn.close(close::LEAVE.into(), b"stream ended");
                    return Ended::Remote(close::LEAVE);
                }
            }
        }
    };
    ended_of(&err)
}

// ─── Connect race ───────────────────────────────────────────────────────────

/// How long one candidate gets to complete its QUIC handshake.
const ATTEMPT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a connected candidate gets to send a verifiable welcome. A
/// candidate that connects and then stalls can't hold up the others, which
/// race in parallel; the whole race is bounded by
/// [`crate::nat::punch::CONNECT_DEADLINE`] (8 s).
const ATTEMPT_OPEN_TIMEOUT: Duration = Duration::from_secs(4);

/// Why one race attempt did not produce a verified host.
#[derive(Debug)]
pub(crate) enum AttemptError {
    /// No QUIC connection.
    Connect,
    /// Connected, but no verified welcome: how it failed, and the peer's close
    /// code if it closed the connection on us (a refusal).
    Open(HandshakeError, Option<Ended>),
}

/// Every attempt failed (or the deadline passed) without a verified host.
#[derive(Debug)]
pub(crate) struct RaceFailure {
    /// Each candidate's failure, as far as it got.
    pub errors: Vec<AttemptError>,
    /// Some candidate completed a QUIC handshake.
    pub connected: bool,
}

/// Dial every candidate, staggered in priority order. Each attempt runs
/// [`client_open`]: the first candidate whose welcome verifies (and passes
/// `check`) wins. A candidate whose welcome does not verify, or that refuses
/// us, is only that candidate's failure: the rest keep racing (review-net-1
/// N4: a squatter on the first candidate must not end the join). The losers
/// are closed before the caller sends anything identifying.
pub(crate) async fn race_open(
    endpoint: &quinn::Endpoint,
    candidates: &[SocketAddr],
    paths: &[PathKind],
    session: Option<&str>,
    tokens: &[[u8; 32]],
    check: &HostCheck,
) -> Result<(Opened, usize), RaceFailure> {
    use crate::nat::punch::{ConnectRace, RaceOutcome};
    use std::sync::atomic::AtomicBool;

    let mut race = ConnectRace::new(candidates.len());
    let started = tokio::time::Instant::now();
    let mut attempts = tokio::task::JoinSet::new();
    let mut task_idx = std::collections::HashMap::new();
    let mut winner: Option<(Opened, usize)> = None;
    let mut errors = Vec::new();
    let connected = Arc::new(AtomicBool::new(false));
    // Every connection made, so the losers can be closed explicitly.
    let live: Arc<std::sync::Mutex<Vec<quinn::Connection>>> = Arc::default();

    while race.outcome().is_none() {
        for idx in race.advance(started.elapsed()) {
            let addr = candidates[idx];
            match endpoint.connect(addr, SERVER_NAME) {
                Ok(connecting) => {
                    let path = paths.get(idx).copied().unwrap_or(PathKind::Direct);
                    let (session, tokens, check) = (
                        session.map(str::to_string),
                        tokens.to_vec(),
                        Arc::clone(check),
                    );
                    let (connected, live) = (Arc::clone(&connected), Arc::clone(&live));
                    let h = attempts.spawn(async move {
                        let conn =
                            match tokio::time::timeout(ATTEMPT_CONNECT_TIMEOUT, connecting).await {
                                Ok(Ok(c)) => c,
                                Ok(Err(e)) => {
                                    log::debug!("[net] candidate {addr}: {e}");
                                    return (idx, Err(AttemptError::Connect));
                                }
                                Err(_) => {
                                    log::debug!("[net] candidate {addr}: no answer");
                                    return (idx, Err(AttemptError::Connect));
                                }
                            };
                        connected.store(true, Ordering::Relaxed);
                        if let Ok(mut l) = live.lock() {
                            l.push(conn.clone());
                        }
                        let opened = tokio::time::timeout(
                            ATTEMPT_OPEN_TIMEOUT,
                            client_open(&conn, session.as_deref(), path, &tokens, &check),
                        )
                        .await
                        .unwrap_or_else(|_| Err(HandshakeError::Io("no welcome in time".into())));
                        match opened {
                            Ok(o) => (idx, Ok(o)),
                            Err(e) => {
                                let ended = conn.close_reason().map(|r| ended_of(&r));
                                let code = match e {
                                    HandshakeError::Unverified(_) => close::HOST_UNVERIFIED,
                                    HandshakeError::Io(_) => close::LEAVE,
                                };
                                conn.close(code.into(), b"not this candidate");
                                (idx, Err(AttemptError::Open(e, ended)))
                            }
                        }
                    });
                    task_idx.insert(h.id(), idx);
                }
                Err(e) => {
                    log::debug!("[net] candidate {addr}: {e}");
                    errors.push(AttemptError::Connect);
                    race.on_failed(idx);
                }
            }
        }
        tokio::select! {
            Some(joined) = attempts.join_next_with_id(), if !attempts.is_empty() => {
                match joined {
                    Ok((id, (idx, result))) => {
                        task_idx.remove(&id);
                        match result {
                            Ok(opened) => {
                                if race.outcome().is_none() {
                                    race.on_connected(idx);
                                    winner = Some((opened, idx));
                                } else {
                                    opened.conn.close(close::LEAVE.into(), b"race already decided");
                                }
                            }
                            Err(e) => {
                                log::info!("[net] candidate {}: {e:?}", candidates[idx]);
                                errors.push(e);
                                race.on_failed(idx);
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(idx) = task_idx.remove(&e.id()) {
                            race.on_failed(idx);
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    attempts.shutdown().await;
    // Close every connection but the winner's: a host reachable on two paths
    // must see one join, and no loser ever gets the joiner's identity.
    let keep = winner.as_ref().map(|(o, _)| o.conn.stable_id());
    if let Ok(l) = live.lock() {
        for c in l.iter().filter(|c| Some(c.stable_id()) != keep) {
            c.close(close::LEAVE.into(), b"race already decided");
        }
    }
    match (race.outcome(), winner) {
        (Some(RaceOutcome::Won(_)), Some(w)) => Ok(w),
        _ => Err(RaceFailure {
            errors,
            connected: connected.load(Ordering::Relaxed),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relays(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn inbox_relays_are_signed_in_the_welcome_and_checked_on_receipt() {
        let host = Keys::generate();
        let relay = Keys::generate();
        let b = [7u8; 32];
        let list = relays(&["wss://a.example", "wss://b.example/x"]);
        let w = sign_welcome(&host, &b, None, 1, "Ava", &relay.public_key(), None, &list);
        assert_eq!(verify_welcome(&w, &b, None).unwrap().inbox_relays, list);
        // Swapped or added after signing: the signature no longer covers them.
        let mut swapped = w.clone();
        swapped.inbox_relays = relays(&["wss://evil.example"]);
        assert!(verify_welcome(&swapped, &b, None).is_err());
        let mut dropped = w.clone();
        dropped.inbox_relays.clear();
        assert!(verify_welcome(&dropped, &b, None).is_err());
        // A sender sanitises its own list: bad entries are dropped, 3 at most.
        let messy = relays(&[
            "ws://plain.example",
            "wss://1",
            "wss://2",
            "wss://3",
            "wss://4",
            "",
        ]);
        let w = sign_welcome(&host, &b, None, 1, "Ava", &relay.public_key(), None, &messy);
        assert_eq!(w.inbox_relays, relays(&["wss://1", "wss://2", "wss://3"]));
        // A receiver refuses a bad list whole, even if validly signed.
        for bad in [
            relays(&["wss://1", "wss://2", "wss://3", "wss://4"]),
            relays(&["https://not-wss.example"]),
            relays(&["wss://"]),
            relays(&["wss://has space.example"]),
            vec![format!("wss://{}", "a".repeat(251))],
        ] {
            let mut forged = w.clone();
            forged.inbox_relays = bad.clone();
            let msg = Message::from_digest(welcome_digest(
                &b,
                None,
                forged.peer,
                &forged.host_name,
                &forged.relay_key,
                None,
                &bad,
            ));
            forged.sig = host.sign_schnorr(&msg).to_string();
            assert!(verify_welcome(&forged, &b, None).is_err(), "{bad:?}");
        }
        let edge = vec![format!("wss://{}", "a".repeat(250))];
        assert_eq!(edge[0].len(), 256);
        assert!(crate::identity::check_inbox_relays(&edge).is_ok());
        assert!(crate::identity::check_inbox_relays(&[]).is_ok());
    }

    #[test]
    fn the_identify_signature_covers_the_inbox_relays() {
        let (b, host) = ([3u8; 32], Keys::generate().public_key());
        let digest = |list: &[&str]| identify_digest(&b, None, &host, Some("{}"), &relays(list));
        let base = digest(&["wss://a.example"]);
        assert_ne!(base, digest(&["wss://b.example"]));
        assert_ne!(base, digest(&[]));
        assert_ne!(base, digest(&["wss://a.example", "wss://a.example"]));
        // Entries are length-prefixed: moving a boundary changes the digest.
        assert_ne!(
            digest(&["wss://ab", "wss://c"]),
            digest(&["wss://a", "wss://bwss://c"])
        );
        assert_eq!(base, digest(&["wss://a.example"]));
    }

    #[test]
    fn a_welcome_without_the_field_deserialises_with_no_inbox_relays() {
        let json =
            r#"{"v":6,"peer":1,"host_pubkey":"00","host_name":"x","relay_key":"00","sig":"00"}"#;
        let w: Welcome = serde_json::from_str(json).unwrap();
        assert!(w.inbox_relays.is_empty());
    }

    #[test]
    fn a_welcome_verifies_only_on_its_own_connection_and_session() {
        let host = Keys::generate();
        let relay = Keys::generate();
        let b = [7u8; 32];
        let w = sign_welcome(
            &host,
            &b,
            Some("s1"),
            3,
            "Ava",
            &relay.public_key(),
            None,
            &[],
        );
        let proof = verify_welcome(&w, &b, Some("s1")).unwrap();
        assert_eq!(
            proof,
            HostProof {
                challenge: w.challenge,
                migration: None,
                peer: 3,
                pubkey: host.public_key(),
                name: "Ava".into(),
                relay_key: relay.public_key(),
                attestation: None,
                inbox_relays: Vec::new(),
            }
        );
        assert!(
            verify_welcome(&w, &[8u8; 32], Some("s1")).is_err(),
            "other TLS session"
        );
        assert!(
            verify_welcome(&w, &b, Some("s2")).is_err(),
            "other join session"
        );
        assert!(verify_welcome(&w, &b, None).is_err());
    }

    #[test]
    fn a_tampered_welcome_fails() {
        let host = Keys::generate();
        let relay = Keys::generate();
        let b = [7u8; 32];
        let w = sign_welcome(&host, &b, None, 1, "Ava", &relay.public_key(), None, &[]);
        let mut renamed = w.clone();
        renamed.host_name = "Mum".into();
        assert!(verify_welcome(&renamed, &b, None).is_err());
        let mut repeer = w.clone();
        repeer.peer = 2;
        assert!(verify_welcome(&repeer, &b, None).is_err());
        let attested = sign_welcome(
            &host,
            &b,
            None,
            1,
            "Ava",
            &relay.public_key(),
            Some("{}"),
            &[],
        );
        assert_eq!(
            verify_welcome(&attested, &b, None)
                .unwrap()
                .attestation
                .as_deref(),
            Some("{}")
        );
        let mut swapped = attested.clone();
        swapped.attestation = Some("{\"other\":1}".into());
        assert!(
            verify_welcome(&swapped, &b, None).is_err(),
            "the attestation is signed too"
        );
        let mut relayed = w.clone();
        relayed.relay_key = Keys::generate().public_key().to_hex();
        assert!(
            verify_welcome(&relayed, &b, None).is_err(),
            "relay key is signed too"
        );
        let mut rekeyed = w.clone();
        rekeyed.host_pubkey = Keys::generate().public_key().to_hex();
        assert!(verify_welcome(&rekeyed, &b, None).is_err());
    }

    #[test]
    fn long_host_names_are_cut_on_a_char_boundary() {
        let host = Keys::generate();
        let relay = Keys::generate();
        let b = [1u8; 32];
        let name = "é".repeat(40); // 80 bytes
        let w = sign_welcome(&host, &b, None, 1, &name, &relay.public_key(), None, &[]);
        assert!(w.host_name.len() <= MAX_HOST_NAME);
        assert!(verify_welcome(&w, &b, None).is_ok());
    }

    #[test]
    fn an_admission_proof_is_bound_to_the_token_and_the_connection() {
        let token = [3u8; 32];
        let b = [9u8; 32];
        let hello = |admit: Vec<String>| Hello {
            v: NET_PROTOCOL_VERSION,
            migration: None,
            session: None,
            path: PathKind::Lan,
            admit,
        };
        let good = hex::encode(admit_proof(&token, &b));
        assert_eq!(
            admitted_which(&hello(vec![good.clone()]), &b, &[[1u8; 32], token]),
            Some(1),
            "the index of the token that was proved"
        );
        assert!(
            admitted_which(&hello(vec![good.clone()]), &[8u8; 32], &[token]).is_none(),
            "other connection"
        );
        assert!(
            admitted_which(&hello(vec![good.clone()]), &b, &[[4u8; 32]]).is_none(),
            "other token"
        );
        assert!(
            admitted_which(&hello(vec![]), &b, &[token]).is_none(),
            "no proof"
        );
        assert!(
            admitted_which(&hello(vec![hex::encode(token)]), &b, &[token]).is_none(),
            "the raw token is not a proof"
        );
        // Several tokens proved: the earliest in the list wins; proofs beyond
        // the cap are ignored.
        let other = hex::encode(admit_proof(&[5u8; 32], &b));
        assert_eq!(
            admitted_which(
                &hello(vec![other.clone(), good.clone()]),
                &b,
                &[token, [5u8; 32]]
            ),
            Some(0)
        );
        let junk = || "0".repeat(64);
        assert!(
            admitted_which(&hello(vec![junk(), junk(), junk(), good]), &b, &[token]).is_none(),
            "a fourth proof is past the cap"
        );
        assert!(!ct_str_eq("abc", "abd") && !ct_str_eq("abc", "ab") && ct_str_eq("abc", "abc"));
    }
}
