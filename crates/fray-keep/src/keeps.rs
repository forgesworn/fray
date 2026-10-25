//! The Keeps a player has been let into, saved so the player can return with
//! no link and no room code.
//!
//! The list lives in one file the caller names (a game uses `keeps.json` in its
//! data directory). The secrets in it are the way in, so the file is private to
//! the app (mode 0600 where the platform has modes) and is replaced atomically:
//! written to `<file>.tmp`, synced, then renamed over. A file that cannot be
//! read as a list is kept as `<file>.bad` and reads as empty, never lost.
//!
//! The file is a JSON array of
//! `{ "host_key": "<64 hex>", "secret": "<64 hex>", "name": "<string>", "last_joined": <unix secs> }`.
//! One [`Keeps`] should own a file at a time: it holds the list in memory and
//! does not re-read the file.

use crate::invite::{describe, hex_encode, parse_hex32};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The list keeps this many Keeps; joining a new one drops the one played longest ago.
pub const MAX_KEEPS: usize = 20;
/// Longest name kept (characters). The name is the host's own choice.
const MAX_NAME: usize = 40;

/// One saved Keep. `Debug` never prints the secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keep {
    /// The Keep's runtime public key, 64 lower-case hex characters.
    pub host_key: String,
    /// The invite's (or pass's) secret, 64 lower-case hex characters.
    pub secret: String,
    /// The host's display name, or `Keep ab12cd` when it gave none.
    pub name: String,
    /// When the player last got in, seconds since the Unix epoch.
    pub last_joined: u64,
}

impl std::fmt::Debug for Keep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keep")
            .field("host_key", &self.host_key.get(..6).unwrap_or(""))
            .field("name", &self.name)
            .field("last_joined", &self.last_joined)
            .finish_non_exhaustive()
    }
}

impl Keep {
    /// A Keep from the two halves of an invite link.
    pub fn new(host_key: &[u8; 32], secret: &[u8; 32], host_name: Option<&str>, last_joined: u64) -> Keep {
        Keep { name: display_name(host_name, host_key), host_key: hex_encode(host_key), secret: hex_encode(secret), last_joined }
    }

    /// The two halves, if both are really 32 bytes of hex.
    pub fn keys(&self) -> Option<([u8; 32], [u8; 32])> {
        Some((parse_hex32(&self.host_key)?, parse_hex32(&self.secret)?))
    }
}

/// Format characters that draw nothing or reorder text (bidi overrides,
/// zero-width joiners, the byte-order mark): a host's name may not carry them.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{ad}' | '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// The name to show for a Keep: the host's own, with control and invisible or
/// bidi characters stripped, trimmed and cut to 40 characters; else `Keep `
/// and the first six hex characters of the key (`Keep ab12cd`).
pub fn display_name(host_name: Option<&str>, host_key: &[u8; 32]) -> String {
    let clean: String = host_name.unwrap_or("").chars().filter(|c| !c.is_control() && !is_invisible(*c)).collect();
    let clean = clean.trim();
    if clean.is_empty() {
        format!("Keep {}", describe(host_key))
    } else {
        clean.chars().take(MAX_NAME).collect()
    }
}

/// "just now", "5 min ago", "3 h ago", "yesterday", "4 d ago", "3 mo ago".
/// `then` and `now` are seconds since the Unix epoch; a `then` after `now` (a
/// clock that went back) reads "just now".
pub fn ago(then: u64, now: u64) -> String {
    let s = now.saturating_sub(then);
    match s {
        0..=89 => "just now".into(),
        90..=3599 => format!("{} min ago", (s + 30) / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        86_400..=172_799 => "yesterday".into(),
        172_800..=5_183_999 => format!("{} d ago", s / 86_400),
        _ => format!("{} mo ago", s / 2_592_000),
    }
}

/// `<file>` with `suffix` added to its name, in the same directory.
fn sibling(file: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = file.file_name().map(OsString::from).unwrap_or_default();
    name.push(suffix);
    file.with_file_name(name)
}

/// The saved Keeps, newest play first, kept in memory and in one file.
#[derive(Clone, Debug)]
pub struct Keeps {
    path: PathBuf,
    list: Vec<Keep>,
}

impl Keeps {
    /// Read the saved Keeps from `path`. A missing or unreadable file is an
    /// empty list. A file that is not a list is renamed to `<file>.bad` (never
    /// lost) and reads as empty. Entries whose keys are not hex are dropped,
    /// hex is lower-cased, names are cleaned as [`display_name`] does, and the
    /// list is newest first and at most [`MAX_KEEPS`] long.
    pub fn load(path: impl Into<PathBuf>) -> Keeps {
        let path = path.into();
        let list = match std::fs::read(&path) {
            Err(_) => Vec::new(),
            Ok(bytes) => match serde_json::from_slice::<Vec<Keep>>(&bytes) {
                Ok(mut list) => {
                    list.retain(|k| k.keys().is_some());
                    for k in &mut list {
                        k.host_key = k.host_key.to_ascii_lowercase();
                        k.secret = k.secret.to_ascii_lowercase();
                        if let Some((host_key, _)) = k.keys() {
                            k.name = display_name(Some(&k.name), &host_key);
                        }
                    }
                    list.sort_by_key(|k| std::cmp::Reverse(k.last_joined));
                    list.truncate(MAX_KEEPS);
                    list
                }
                Err(_) => {
                    let _ = std::fs::rename(&path, sibling(&path, ".bad"));
                    Vec::new()
                }
            },
        };
        Keeps { path, list }
    }

    /// The file this list is saved in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The saved Keeps, newest play first.
    pub fn list(&self) -> &[Keep] {
        &self.list
    }

    /// `host_key` is in the list.
    pub fn contains(&self, host_key: &[u8; 32]) -> bool {
        let hex = hex_encode(host_key);
        self.list.iter().any(|k| k.host_key == hex)
    }

    /// Write the list to `<file>.tmp` (mode 0600 on unix), sync it, and rename
    /// it over the file.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(&self.list).map_err(std::io::Error::other)?;
        let tmp = sibling(&self.path, ".tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
    }

    /// Put a Keep in the list (in memory; [`save`](Keeps::save) writes it): one
    /// entry per host key, a new secret replacing the old, the newest play
    /// first and only [`MAX_KEEPS`] kept, the oldest dropped. `host_name` is
    /// cleaned by [`display_name`].
    pub fn remember(&mut self, host_key: &[u8; 32], secret: &[u8; 32], host_name: Option<&str>, now_secs: u64) {
        let keep = Keep::new(host_key, secret, host_name, now_secs);
        self.list.retain(|k| k.host_key != keep.host_key);
        self.list.push(keep);
        // Stable: equal times keep their order, the new one last of its time, so it is dropped first.
        self.list.sort_by_key(|k| std::cmp::Reverse(k.last_joined));
        self.list.truncate(MAX_KEEPS);
    }

    /// Note a successful join: [`remember`](Keeps::remember), then save, unless
    /// the list came out as it already was and the file exists. `Ok(true)` when
    /// the file was written, `Ok(false)` when nothing needed writing. The error
    /// is for the log: a Keep that could not be saved does not stop the game.
    pub fn record_join(&mut self, host_key: &[u8; 32], secret: &[u8; 32], host_name: Option<&str>, now_secs: u64) -> std::io::Result<bool> {
        let before = self.list.clone();
        self.remember(host_key, secret, host_name, now_secs);
        if self.list == before && self.path.exists() {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }

    /// Take the Keep with `host_key` out of the list and save. `Ok(true)` if it
    /// was there; an absent Keep changes nothing and writes nothing.
    pub fn forget(&mut self, host_key: &[u8; 32]) -> std::io::Result<bool> {
        let hex = hex_encode(host_key);
        let before = self.list.len();
        self.list.retain(|k| k.host_key != hex);
        if self.list.len() == before {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: [u8; 32] = [0xab; 32];
    const SECRET: [u8; 32] = [0x01; 32];

    /// A fresh directory for one test.
    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fray-keep-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn file(d: &Path) -> PathBuf {
        d.join("keeps.json")
    }

    fn keep(n: u8, at: u64) -> Keep {
        Keep::new(&[n; 32], &[n.wrapping_add(1); 32], Some(&format!("Keep number {n}")), at)
    }

    fn hex_of(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    /// Put `keeps` in a list as if loaded.
    fn with(d: &Path, keeps: Vec<Keep>) -> Keeps {
        Keeps { path: file(d), list: keeps }
    }

    #[test]
    fn a_keep_without_a_name_is_named_after_its_key() {
        assert_eq!(Keep::new(&HOST, &SECRET, None, 5).name, "Keep ababab");
        assert_eq!(Keep::new(&HOST, &SECRET, Some("  \n"), 5).name, "Keep ababab");
        assert_eq!(Keep::new(&HOST, &SECRET, Some(" Cousin's \u{7}Keep "), 5).name, "Cousin's Keep");
        assert_eq!(Keep::new(&HOST, &SECRET, Some(&"x".repeat(200)), 5).name.chars().count(), MAX_NAME);
        let k = Keep::new(&HOST, &SECRET, Some("Cousin"), 9);
        assert_eq!(k.host_key, "ab".repeat(32));
        assert_eq!(k.secret, "01".repeat(32));
        assert_eq!(k.keys(), Some((HOST, SECRET)));
    }

    #[test]
    fn a_host_name_loses_bidi_and_zero_width_characters() {
        assert_eq!(display_name(Some("Co\u{202e}us\u{200b}in\u{feff}"), &HOST), "Cousin");
        assert_eq!(display_name(Some("\u{202e}\u{200b}"), &HOST), "Keep ababab");
        assert_eq!(display_name(Some("a\u{61c}b\u{2066}c\u{2069}d\u{ad}e"), &HOST), "abcde");
        assert_eq!(display_name(None, &[0x0f; 32]), "Keep 0f0f0f");
        // Forty characters, not forty bytes.
        assert_eq!(display_name(Some(&"\u{e9}".repeat(60)), &HOST).chars().count(), 40);
    }

    #[test]
    fn saved_keeps_load_back_and_a_missing_file_is_empty() {
        let d = dir("roundtrip");
        assert!(Keeps::load(file(&d)).list().is_empty());
        let list = vec![keep(2, 200), keep(1, 100)];
        with(&d, list.clone()).save().unwrap();
        assert_eq!(Keeps::load(file(&d)).list(), list.as_slice());
        assert!(!d.join("keeps.json.tmp").exists(), "the temp file is renamed away");
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_after_every_save() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("mode");
        let mut keeps = Keeps::load(file(&d));
        keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap();
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(file(&d)), 0o600, "the file holds secrets");
        keeps.record_join(&[3; 32], &[4; 32], Some("Two"), 20).unwrap();
        assert_eq!(mode(file(&d)), 0o600, "still private after a second save");
        assert!(!d.join("keeps.json.tmp").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_file_in_a_missing_directory_is_made_and_a_bare_file_name_works() {
        let d = dir("nested");
        let mut keeps = Keeps::load(d.join("a").join("b").join("keeps.json"));
        assert!(keeps.record_join(&[1; 32], &[2; 32], None, 1).unwrap());
        assert_eq!(Keeps::load(d.join("a").join("b").join("keeps.json")).list().len(), 1);
        assert_eq!(keeps.path(), d.join("a").join("b").join("keeps.json"));
        assert_eq!(sibling(Path::new("keeps.json"), ".tmp"), PathBuf::from("keeps.json.tmp"));
        let _ = std::fs::remove_dir_all(d);
    }

    /// What Stampede's and Twang Thang's own `keeps.rs` write: `serde_json::to_vec_pretty`
    /// of a `Vec<Keep>` with these four fields in this order, no trailing newline.
    fn old_file_text() -> String {
        let one = |n: &str, secret: &str, name: &str, at: u64| {
            format!("  {{\n    \"host_key\": \"{n}\",\n    \"secret\": \"{secret}\",\n    \"name\": \"{name}\",\n    \"last_joined\": {at}\n  }}")
        };
        format!("[\n{},\n{}\n]", one(&"ab".repeat(32), &"01".repeat(32), "Cousin's Keep", 1_790_000_200), one(&"02".repeat(32), &"03".repeat(32), "Keep 020202", 1_790_000_100))
    }

    #[test]
    fn a_file_written_by_the_old_game_code_reads_back_identically() {
        let d = dir("oldshape");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(file(&d), old_file_text()).unwrap();
        let keeps = Keeps::load(file(&d));
        assert_eq!(
            keeps.list(),
            [Keep::new(&HOST, &SECRET, Some("Cousin's Keep"), 1_790_000_200), Keep::new(&[2; 32], &[3; 32], None, 1_790_000_100)].as_slice()
        );
        assert_eq!(keeps.list()[0].keys(), Some((HOST, SECRET)));
        // And this crate writes the same bytes the old code did.
        keeps.save().unwrap();
        assert_eq!(std::fs::read_to_string(file(&d)).unwrap(), old_file_text());
        // An old file with no change to make is not rewritten by a repeated join.
        let mut keeps = Keeps::load(file(&d));
        assert!(!(keeps.record_join(&HOST, &SECRET, Some("Cousin's Keep"), 1_790_000_200).unwrap()));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn load_cleans_what_it_reads() {
        let d = dir("clean");
        std::fs::create_dir_all(&d).unwrap();
        let text = format!(
            "[{{\"host_key\":\"{}\",\"secret\":\"{}\",\"name\":\"Co\\u202eus\\u200bin\",\"last_joined\":7}}]",
            "AB".repeat(32),
            "0A".repeat(32)
        );
        std::fs::write(file(&d), text).unwrap();
        let keeps = Keeps::load(file(&d));
        assert_eq!(keeps.list().len(), 1);
        assert_eq!(keeps.list()[0].host_key, "ab".repeat(32), "hex is lower-cased");
        assert_eq!(keeps.list()[0].secret, "0a".repeat(32));
        assert_eq!(keeps.list()[0].name, "Cousin");
        assert!(keeps.contains(&HOST));
        // An empty name falls back to the key.
        let text = format!(r#"[{{"host_key":"{}","secret":"{}","name":"","last_joined":7}}]"#, "ab".repeat(32), "01".repeat(32));
        std::fs::write(file(&d), text).unwrap();
        assert_eq!(Keeps::load(file(&d)).list()[0].name, "Keep ababab");
        // More than the cap, out of order: newest first, twenty kept.
        let many: Vec<Keep> = (0..30u8).map(|i| keep(i, 1000 + u64::from((i * 7) % 30))).collect();
        std::fs::write(file(&d), serde_json::to_vec(&many).unwrap()).unwrap();
        let loaded = Keeps::load(file(&d));
        assert_eq!(loaded.list().len(), MAX_KEEPS);
        assert!(loaded.list().windows(2).all(|w| w[0].last_joined >= w[1].last_joined));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_same_keep_with_a_new_secret_replaces_the_old_entry() {
        let d = dir("replace");
        let mut keeps = with(&d, vec![keep(2, 200), keep(1, 100)]);
        keeps.remember(&[1; 32], &[9; 32], Some("Renamed"), 300);
        assert_eq!(keeps.list().len(), 2);
        assert_eq!(keeps.list()[0], Keep::new(&[1; 32], &[9; 32], Some("Renamed"), 300), "newest first");
        assert_eq!(keeps.list()[1], keep(2, 200));
        assert_eq!(keeps.list().iter().filter(|k| k.host_key == hex_of(1)).count(), 1);
    }

    #[test]
    fn the_list_holds_twenty_and_drops_the_oldest() {
        let d = dir("cap");
        let mut keeps = with(&d, Vec::new());
        for i in 0..MAX_KEEPS as u8 {
            keeps.remember(&[i; 32], &[i.wrapping_add(1); 32], Some(&format!("Keep number {i}")), 1000 + u64::from(i));
        }
        assert_eq!(keeps.list().len(), MAX_KEEPS);
        keeps.remember(&[100; 32], &[101; 32], Some("Keep number 100"), 5000);
        assert_eq!(keeps.list().len(), MAX_KEEPS);
        assert_eq!(keeps.list()[0], keep(100, 5000));
        assert!(!keeps.contains(&[0; 32]), "the oldest, played at 1000, is gone");
        assert!(keeps.contains(&[1; 32]));
        // A new Keep older than all twenty does not push a newer one out.
        keeps.remember(&[101; 32], &[102; 32], None, 1);
        assert_eq!(keeps.list().len(), MAX_KEEPS);
        assert!(!keeps.contains(&[101; 32]));
        assert!(keeps.contains(&[100; 32]));
    }

    #[test]
    fn forgetting_removes_one_keep_and_saves() {
        let d = dir("forget");
        let mut keeps = Keeps::load(file(&d));
        keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap();
        keeps.record_join(&[3; 32], &[4; 32], None, 20).unwrap();
        assert_eq!(Keeps::load(file(&d)).list().len(), 2);
        assert!(keeps.forget(&[1; 32]).unwrap());
        let left = Keeps::load(file(&d));
        assert_eq!(left.list().len(), 1);
        assert_eq!(left.list()[0].name, "Keep 030303");
        assert!(!(keeps.forget(&[1; 32]).unwrap()), "forgetting an absent Keep changes nothing");
        assert_eq!(Keeps::load(file(&d)).list(), left.list());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_join_that_changes_nothing_does_not_rewrite_the_file() {
        let d = dir("rewrite");
        let mut keeps = Keeps::load(file(&d));
        assert!(keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap());
        let first = std::fs::read(file(&d)).unwrap();
        // Replace the file with an identical copy so its modified time is known.
        std::fs::remove_file(file(&d)).unwrap();
        std::fs::write(file(&d), &first).unwrap();
        let mtime = std::fs::metadata(file(&d)).unwrap().modified().unwrap();
        // Same Keep, same secret, same second: the list is as it was.
        assert!(!(keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap()));
        assert_eq!(std::fs::metadata(file(&d)).unwrap().modified().unwrap(), mtime);
        assert_eq!(std::fs::read(file(&d)).unwrap(), first);
        // A later play, or a new secret, is a change.
        assert!(keeps.record_join(&[1; 32], &[2; 32], Some("One"), 11).unwrap());
        assert!(keeps.record_join(&[1; 32], &[3; 32], Some("One"), 11).unwrap());
        // An unchanged list whose file has gone is written again.
        std::fs::remove_file(file(&d)).unwrap();
        assert!(keeps.record_join(&[1; 32], &[3; 32], Some("One"), 11).unwrap());
        assert!(file(&d).exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_broken_file_is_set_aside_and_bad_entries_are_dropped() {
        let d = dir("broken");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(file(&d), "not json").unwrap();
        assert!(Keeps::load(file(&d)).list().is_empty());
        assert!(!file(&d).exists(), "the bad file is moved, not left in place");
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad")).unwrap(), "not json", "and never lost");
        // Not UTF-8 is also not a list.
        std::fs::write(file(&d), [0xff, 0xfe, 0x00]).unwrap();
        assert!(Keeps::load(file(&d)).list().is_empty());
        assert_eq!(std::fs::read(d.join("keeps.json.bad")).unwrap(), vec![0xff, 0xfe, 0x00]);
        // A JSON value that is not an array of Keeps.
        std::fs::write(file(&d), r#"{"host_key":"x"}"#).unwrap();
        assert!(Keeps::load(file(&d)).list().is_empty());
        assert!(!file(&d).exists());
        // Bad entries are dropped, good ones stay.
        let good = keep(1, 5);
        let mut bad = keep(2, 6);
        bad.secret = "zz".into();
        let mut short = keep(3, 7);
        short.host_key = "ab".into();
        std::fs::write(file(&d), serde_json::to_vec(&vec![bad, good.clone(), short]).unwrap()).unwrap();
        assert_eq!(Keeps::load(file(&d)).list(), [good].as_slice());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_bad_file_does_not_stop_the_next_join_from_saving() {
        let d = dir("recover");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(file(&d), "{{{").unwrap();
        let mut keeps = Keeps::load(file(&d));
        assert!(keeps.record_join(&[1; 32], &[2; 32], None, 1).unwrap());
        assert_eq!(Keeps::load(file(&d)).list().len(), 1);
        assert!(d.join("keeps.json.bad").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn times_read_in_plain_words() {
        let now = 10_000_000;
        assert_eq!(ago(now, now), "just now");
        assert_eq!(ago(now - 600, now), "10 min ago");
        assert_eq!(ago(now - 3 * 3600, now), "3 h ago");
        assert_eq!(ago(now - 86_400, now), "yesterday");
        assert_eq!(ago(now - 4 * 86_400, now), "4 d ago");
        assert_eq!(ago(now - 90 * 86_400, now), "3 mo ago");
        assert_eq!(ago(now + 50, now), "just now", "a clock that went back");
    }

    #[test]
    fn nothing_prints_a_secret() {
        let k = Keep::new(&HOST, &SECRET, Some("Cousin"), 9);
        let shown = format!("{k:?}");
        assert!(!shown.contains("0101"), "{shown}");
        assert!(shown.contains("Cousin"));
        let d = dir("debug");
        let keeps = with(&d, vec![k]);
        assert!(!format!("{keeps:?}").contains("0101"));
    }
}
