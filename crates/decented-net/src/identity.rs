//! The install's own Nostr key. Generated on first run, stored as hex at
//! `data_dir/identity.key` with mode 0600. No external signer is involved.

use std::path::Path;

use nostr::{Keys, PublicKey, SecretKey, ToBech32};

const FILE_NAME: &str = "identity.key";

/// This install's key pair.
#[derive(Clone)]
pub struct Identity {
    keys: Keys,
    /// Optional persona attestation for this runtime key (seam for a My
    /// Signet persona, kind 30420). Carried opaque and unverified for now.
    attestation: Option<String>,
    /// Inbox relays presented next to the attestation (set from
    /// [`crate::NetConfig::inbox_relays`] by the host; already sanitised).
    inbox_relays: Vec<String>,
}

/// Longest attestation carried in a hello or welcome (bytes).
pub const MAX_ATTESTATION_LEN: usize = 2048;
/// Most inbox relays carried in an identify frame or welcome.
pub const MAX_INBOX_RELAYS: usize = 3;
/// Longest inbox relay URL (bytes).
pub const MAX_INBOX_RELAY_LEN: usize = 256;

/// Whether `url` may travel as an inbox relay: `wss://`, a host after it, at
/// most [`MAX_INBOX_RELAY_LEN`] bytes, no whitespace or control characters.
pub(crate) fn valid_inbox_relay(url: &str) -> bool {
    if url.len() > MAX_INBOX_RELAY_LEN || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some(rest) = url.strip_prefix("wss://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // No credentials in the URL.
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    // The host, without a port.
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    if host.is_empty() {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return false;
    }
    // An IP literal must be a public address: an inbox relay is on the
    // internet, never a service on the local network or this device.
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => crate::nat::candidates::is_global_v4(ip),
        Ok(std::net::IpAddr::V6(ip)) => crate::nat::candidates::is_global_v6(ip),
        Err(_) => true,
    }
}

/// Check a list received from a peer. Anything out of range is rejected
/// whole (the frame is refused), not trimmed.
pub(crate) fn check_inbox_relays(list: &[String]) -> Result<(), String> {
    if list.len() > MAX_INBOX_RELAYS {
        return Err(format!(
            "{} inbox relays (at most {MAX_INBOX_RELAYS})",
            list.len()
        ));
    }
    match list.iter().find(|u| !valid_inbox_relay(u)) {
        Some(_) => Err("an inbox relay is not a wss:// URL of at most 256 characters".into()),
        None => Ok(()),
    }
}

/// Our own list, made fit to send: valid entries only, first 3, no repeats.
pub(crate) fn sanitize_inbox_relays(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in list {
        if valid_inbox_relay(u) && !out.contains(u) {
            out.push(u.clone());
        }
        if out.len() == MAX_INBOX_RELAYS {
            break;
        }
    }
    out
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("Identity")
            .field("pubkey", &self.keys.public_key().to_hex())
            .finish()
    }
}

impl Identity {
    /// Load `data_dir/identity.key`, or create it (and `data_dir`) if missing.
    pub fn load_or_create(data_dir: &Path) -> Result<Identity, String> {
        let path = data_dir.join(FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let sk = SecretKey::from_hex(text.trim())
                    .map_err(|e| format!("{FILE_NAME} is not a valid key: {e}"))?;
                Ok(Identity {
                    keys: Keys::new(sk),
                    attestation: None,
                    inbox_relays: Vec::new(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(data_dir)
                    .map_err(|e| format!("could not create the data directory: {e}"))?;
                let keys = Keys::generate();
                write_0600(&path, keys.secret_key().to_secret_hex().as_bytes())?;
                Ok(Identity {
                    keys,
                    attestation: None,
                    inbox_relays: Vec::new(),
                })
            }
            Err(e) => Err(format!("could not read {FILE_NAME}: {e}")),
        }
    }

    /// A throwaway identity that is never written anywhere (tests, practice).
    pub fn ephemeral() -> Identity {
        Identity {
            keys: Keys::generate(),
            attestation: None,
            inbox_relays: Vec::new(),
        }
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn npub(&self) -> String {
        self.keys.public_key().to_bech32().unwrap_or_default()
    }

    /// Attach a persona attestation (a signed event, as JSON) for this
    /// install's key. It rides in the QUIC identify frame (sent only to a
    /// verified host) or welcome, covered by the connection-bound signature. **Not verified yet** — the app must not
    /// display anything from it until persona verification lands. Over
    /// [`MAX_ATTESTATION_LEN`] bytes it is dropped.
    pub fn with_attestation(mut self, attestation: String) -> Identity {
        self.attestation = (attestation.len() <= MAX_ATTESTATION_LEN).then_some(attestation);
        self
    }

    pub fn attestation(&self) -> Option<&str> {
        self.attestation.as_deref()
    }

    /// This identity with no attestation and no inbox relays (a host
    /// withholding its persona from the welcome).
    pub(crate) fn without_attestation(&self) -> Identity {
        Identity {
            keys: self.keys.clone(),
            attestation: None,
            inbox_relays: Vec::new(),
        }
    }

    /// This identity presenting `relays` (sanitised) as its inbox relays.
    pub(crate) fn with_inbox_relays(mut self, relays: &[String]) -> Identity {
        self.inbox_relays = sanitize_inbox_relays(relays);
        self
    }

    pub(crate) fn inbox_relays(&self) -> &[String] {
        &self.inbox_relays
    }

    /// The install's runtime key pair (for example to hand to a persona
    /// signer that attests it). Holds the secret key: never log or send it.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }
}

/// Write `bytes` to `path` so that only the owner can ever read it: the file is
/// created 0600 (not chmodded after the fact) and replaced atomically.
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension("key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("could not create the key file: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("could not write the key file: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("could not flush the key file: {e}"))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("could not install the key file: {e}"))
}

/// The bech32 `npub1…` form of any public key.
pub fn npub_of(pk: &PublicKey) -> String {
    pk.to_bech32().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        std::env::temp_dir().join(format!("dnet-id-{tag}-{}", hex::encode(b)))
    }

    #[test]
    fn inbox_relay_urls_are_wss_hosts_on_the_internet() {
        for ok in [
            "wss://relay.example",
            "wss://relay.example:443/x?y=1",
            "wss://81.2.69.160",
            "wss://[2a00:1450::1]:443",
        ] {
            assert!(valid_inbox_relay(ok), "{ok}");
        }
        for bad in [
            "ws://relay.example",
            "wss://",
            "wss://user:pass@relay.example",
            "wss://localhost",
            "wss://foo.localhost/x",
            "wss://127.0.0.1",
            "wss://192.168.1.1:22",
            "wss://[::1]",
            "wss://[fd00::1]",
            "wss://100.64.0.1",
            "wss://:443",
            "wss://a b.example",
        ] {
            assert!(!valid_inbox_relay(bad), "{bad}");
        }
    }

    #[test]
    fn creates_once_then_loads_the_same_key() {
        let dir = temp_dir("persist");
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.pubkey(), b.pubkey());
        assert!(a.npub().starts_with("npub1"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        Identity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(FILE_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_corrupt_key_file_is_an_error_not_a_new_identity() {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE_NAME), "not hex").unwrap();
        assert!(Identity::load_or_create(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let id = Identity::ephemeral();
        let dbg = format!("{id:?}");
        assert!(!dbg.contains(&id.keys().secret_key().to_secret_hex()));
    }
}
