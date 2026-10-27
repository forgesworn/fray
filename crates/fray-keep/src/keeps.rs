//! The Keeps a player has been let into, saved so the player can return with
//! no link and no room code.
//!
//! The list lives in one file the caller names (a game uses `keeps.json` in its
//! data directory). The secrets in it are the way in, so the file is private to
//! the app (mode 0600 where the platform has modes) and is replaced atomically:
//! written to a fresh `<file>.tmp`, synced, then renamed over.
//!
//! The file is a JSON array of
//! `{ "host_key": "<64 hex>", "secret": "<64 hex>", "name": "<string>", "last_joined": <unix secs> }`.
//! Reading it: an entry that is not a whole Keep with hex keys is dropped, hex
//! is lower-cased, names are cleaned, there is one entry per host key (the
//! newest kept), newest first, at most [`MAX_KEEPS`]. A file that is not a JSON
//! array at all is moved aside and reads as empty. It goes to the first of
//! `<file>.bad`, `<file>.bad.2` ... `<file>.bad.10` that does not exist, so the
//! first nine are never replaced, and [`Keeps::set_aside`] says where it went.
//! Once all ten names are taken, `<file>.bad.10` holds the newest: the
//! file replaces it there, so the first nine are kept and a game can always save
//! again. If it cannot be moved (the folder is read-only, or `.bad.10` is not a
//! plain file), that is an error and it stays where it is. A file that cannot be
//! read for any reason but being absent is an error, and nothing is ever saved
//! over it.
//!
//! [`Keeps`] changes the list by reading the file again, changing what is
//! there and saving, so a `Keeps` that has gone stale (a second one saved a
//! Keep meanwhile) never erases an entry another one saved. [`Keeps::list`] is
//! a snapshot from the last load or change. The free functions on a
//! `Vec<Keep>` are the same rules without the file.
//!
//! One writer at a time: two threads or processes saving the same file at once
//! can lose an update, or leave a half-written file that the next read sets
//! aside. A game saves from its one frame loop. Setting a corrupt file aside does
//! not need that: the name is reserved atomically, so two writers never replace
//! a set-aside file before all ten names are taken.

use crate::invite::{hex_encode, parse_hex32};
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

/// Format characters that draw nothing, reorder text or break a line (bidi
/// overrides, zero-width joiners, the byte-order mark, line and paragraph
/// separators, the Hangul fillers, the combining grapheme joiner, the Mongolian
/// vowel separator, interlinear annotation marks, musical formatting controls,
/// tag characters and variation selectors): a
/// host's name may not carry them. Runs of combining marks are not limited.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

/// The first six hex characters of a host key (as hex text), upper-cased: the
/// Keep ID a player can read out.
pub fn keep_id_hex(host_hex: &str) -> String {
    host_hex.get(..6).unwrap_or(host_hex).to_ascii_uppercase()
}

/// The name to show for a Keep whose key is hex text: the host's own, with
/// control and invisible or bidi characters stripped, trimmed and cut to 40
/// characters; else `Keep ` and the first six hex characters of the key
/// (`Keep ab12cd`).
pub fn display_name_hex(host_name: Option<&str>, host_hex: &str) -> String {
    let clean: String = host_name.unwrap_or("").chars().filter(|c| !c.is_control() && !is_invisible(*c)).collect();
    let clean = clean.trim();
    if clean.is_empty() {
        format!("Keep {}", host_hex.get(..6).unwrap_or(host_hex))
    } else {
        // Trim again: the cut can land just after a space.
        clean.chars().take(MAX_NAME).collect::<String>().trim_end().to_string()
    }
}

/// [`display_name_hex`] for a key as bytes.
pub fn display_name(host_name: Option<&str>, host_key: &[u8; 32]) -> String {
    display_name_hex(host_name, &hex_encode(host_key))
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

/// Put `keep` in the list: a Keep already there under the same host key is
/// replaced (a new secret supersedes the old), the newest play comes first and
/// only [`MAX_KEEPS`] stay, the oldest dropped.
pub fn remember(list: &mut Vec<Keep>, keep: Keep) {
    list.retain(|k| !k.host_key.eq_ignore_ascii_case(&keep.host_key));
    list.push(keep);
    // Stable: equal times keep their order, the new one last of its time, so it is dropped first.
    list.sort_by_key(|k| std::cmp::Reverse(k.last_joined));
    list.truncate(MAX_KEEPS);
}

/// Take the Keep with `host_key` (hex) out of the list. True if it was there.
pub fn forget(list: &mut Vec<Keep>, host_key: &str) -> bool {
    let before = list.len();
    list.retain(|k| !k.host_key.eq_ignore_ascii_case(host_key));
    list.len() != before
}

/// `host_key` (hex) is in the list.
pub fn contains(list: &[Keep], host_key: &str) -> bool {
    list.iter().any(|k| k.host_key.eq_ignore_ascii_case(host_key))
}

/// `<file>` with `suffix` added to its name, in the same directory.
fn sibling(file: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = file.file_name().map(OsString::from).unwrap_or_default();
    name.push(suffix);
    file.with_file_name(name)
}

/// How many names a corrupt file can be set aside under: `<file>.bad`, then
/// `<file>.bad.2` to `<file>.bad.10`.
const MAX_SET_ASIDE: u32 = 10;

/// Move the corrupt file at `path` to the first free `.bad` name and return it.
/// A name is reserved by creating an empty file there with `create_new`, which
/// fails if anything is there (a directory or a dangling link counts), and the
/// corrupt file is then renamed over that placeholder. Two writers can no
/// longer replace a set-aside file: whoever loses the race for a name moves on
/// to the next one. With no free name the file replaces the last name, but only
/// when a plain file is there. If that is not so, or the move fails (the
/// placeholder is removed, best effort), the file stays where it is and this is
/// an error.
fn set_aside(path: &Path) -> std::io::Result<PathBuf> {
    for n in 1..=MAX_SET_ASIDE {
        let target = if n == 1 { sibling(path, ".bad") } else { sibling(path, &format!(".bad.{n}")) };
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&target) {
            Ok(placeholder) => {
                drop(placeholder);
                if let Err(e) = std::fs::rename(path, &target) {
                    // Only our empty placeholder: a writer that found all ten names
                    // taken may have moved its corrupt file here meanwhile.
                    if std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_file() && m.len() == 0) {
                        let _ = std::fs::remove_file(&target);
                    }
                    return Err(e);
                }
                return Ok(target);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let last = sibling(path, &format!(".bad.{MAX_SET_ASIDE}"));
    if !std::fs::symlink_metadata(&last).is_ok_and(|m| m.is_file()) {
        return Err(std::io::Error::other(format!(
            "all {MAX_SET_ASIDE} set-aside names for a corrupt keeps file are taken, and the last is not a plain file"
        )));
    }
    std::fs::rename(path, &last)?;
    Ok(last)
}

/// Read the file as the module docs say, and say where a corrupt file was set
/// aside, if it was. Only a missing file is an empty list without being an error.
fn read_list_noting(path: &Path) -> std::io::Result<(Vec<Keep>, Option<PathBuf>)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
        Err(e) => return Err(e),
    };
    let Ok(serde_json::Value::Array(items)) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        // The corrupt file is moved aside so a save cannot overwrite it. If it
        // cannot be moved it is still in place, so this is a read error: the
        // caller must not save over it.
        let moved = set_aside(path)?;
        return Ok((Vec::new(), Some(moved)));
    };
    let mut list: Vec<Keep> = items.into_iter().filter_map(|v| serde_json::from_value::<Keep>(v).ok()).collect();
    list.retain(|k| k.keys().is_some());
    for k in &mut list {
        k.host_key = k.host_key.to_ascii_lowercase();
        k.secret = k.secret.to_ascii_lowercase();
        k.name = display_name_hex(Some(&k.name), &k.host_key);
    }
    list.sort_by_key(|k| std::cmp::Reverse(k.last_joined));
    // One entry per host key: the newest, which sorted first.
    let mut seen = std::collections::HashSet::new();
    list.retain(|k| seen.insert(k.host_key.clone()));
    list.truncate(MAX_KEEPS);
    Ok((list, None))
}

/// Write `list` to a fresh `<file>.tmp` (mode 0600 from creation on unix), sync
/// it and rename it over the file. A temp file left behind, whatever its mode or
/// kind of link, is removed first, so the file written is always private.
fn write_list(path: &Path, list: &[Keep]) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(list).map_err(std::io::Error::other)?;
    let tmp = sibling(path, ".tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    let written = f.write_all(&json).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path)
}

/// Write `list` to the file at `path` as it stands, privately and atomically
/// like every save here. It does not read the file first, so a caller keeping
/// its own copy of the list saves that copy; the [`Keeps`] calls that change
/// the list are the ones that keep another writer's entries.
pub fn save_list(path: &Path, list: &[Keep]) -> std::io::Result<()> {
    write_list(path, list)
}

/// The saved Keeps, newest play first, kept in one file.
#[derive(Clone, Debug)]
pub struct Keeps {
    path: PathBuf,
    list: Vec<Keep>,
    set_aside: Option<PathBuf>,
}

impl Keeps {
    /// Read the saved Keeps from `path`; see the module docs for what is
    /// dropped and what is moved aside (see [`set_aside`](Keeps::set_aside)). A
    /// missing file is an empty list. Any other failure to read it, or to move a
    /// corrupt file aside, is an error: the file is left alone.
    pub fn load(path: impl Into<PathBuf>) -> std::io::Result<Keeps> {
        let path = path.into();
        let (list, set_aside) = read_list_noting(&path)?;
        Ok(Keeps { path, list, set_aside })
    }

    /// Read the file again into [`list`](Keeps::list).
    pub fn reload(&mut self) -> std::io::Result<()> {
        let (list, set_aside) = read_list_noting(&self.path)?;
        self.list = list;
        self.note_set_aside(set_aside);
        Ok(())
    }

    /// Where the most recent read that found a corrupt file put it (`<file>.bad`,
    /// the next free `<file>.bad.N`, or `<file>.bad.10` once all ten are taken),
    /// or `None` if no read of this `Keeps`
    /// has had to. A later read that finds a good file does not clear it. For
    /// the log: a game says where the player's old list went.
    pub fn set_aside(&self) -> Option<&Path> {
        self.set_aside.as_deref()
    }

    fn note_set_aside(&mut self, moved: Option<PathBuf>) {
        if moved.is_some() {
            self.set_aside = moved;
        }
    }

    /// The file this list is saved in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The saved Keeps, newest play first, as of the last load or change.
    pub fn list(&self) -> &[Keep] {
        &self.list
    }

    /// `host_key` is in the list ([`list`](Keeps::list)).
    pub fn contains(&self, host_key: &[u8; 32]) -> bool {
        contains(&self.list, &hex_encode(host_key))
    }

    /// Write the snapshot [`list`](Keeps::list) to the file, as it stands. The
    /// changing calls below read the file first; this one does not, so use
    /// them rather than this to change a list.
    pub fn save(&self) -> std::io::Result<()> {
        write_list(&self.path, &self.list)
    }

    /// Put a Keep in the file: read it, apply [`remember`]'s rule (one entry
    /// per host key, a new secret replacing the old, newest first, at most
    /// [`MAX_KEEPS`]), save. `host_name` is cleaned by [`display_name`]. The
    /// snapshot is updated once the file is written.
    pub fn remember(&mut self, host_key: &[u8; 32], secret: &[u8; 32], host_name: Option<&str>, now_secs: u64) -> std::io::Result<()> {
        let (mut list, moved) = read_list_noting(&self.path)?;
        self.note_set_aside(moved);
        remember(&mut list, Keep::new(host_key, secret, host_name, now_secs));
        write_list(&self.path, &list)?;
        self.list = list;
        Ok(())
    }

    /// Note a successful join: like [`remember`](Keeps::remember), but the file
    /// is not rewritten when the list comes out as it already was and the file
    /// exists. `Ok(true)` when the file was written, `Ok(false)` when nothing
    /// needed writing. The error is for the log: a Keep that could not be saved
    /// does not stop the game.
    pub fn record_join(&mut self, host_key: &[u8; 32], secret: &[u8; 32], host_name: Option<&str>, now_secs: u64) -> std::io::Result<bool> {
        let (before, moved) = read_list_noting(&self.path)?;
        self.note_set_aside(moved);
        let mut list = before.clone();
        remember(&mut list, Keep::new(host_key, secret, host_name, now_secs));
        let write = list != before || !self.path.exists();
        if write {
            write_list(&self.path, &list)?;
        }
        self.list = list;
        Ok(write)
    }

    /// Take the Keep with `host_key` out of the file: read it, remove, save.
    /// `Ok(true)` if it was there; an absent Keep writes nothing.
    pub fn forget(&mut self, host_key: &[u8; 32]) -> std::io::Result<bool> {
        let (mut list, moved) = read_list_noting(&self.path)?;
        self.note_set_aside(moved);
        let was_there = forget(&mut list, &hex_encode(host_key));
        if was_there {
            write_list(&self.path, &list)?;
        }
        self.list = list;
        Ok(was_there)
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

    fn load(d: &Path) -> Keeps {
        Keeps::load(file(d)).unwrap()
    }

    /// Write `list` to the file straight, as a game's older code might have.
    fn write(d: &Path, list: &[Keep]) {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(file(d), serde_json::to_vec_pretty(list).unwrap()).unwrap();
    }

    #[test]
    fn a_list_saved_as_it_stands_loads_back_the_same_and_private() {
        let d = dir("save-list");
        let list = vec![keep(3, 30), keep(2, 20)];
        save_list(&file(&d), &list).unwrap();
        assert_eq!(load(&d).list(), &list[..]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(file(&d)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        save_list(&file(&d), &[]).unwrap();
        assert!(load(&d).list().is_empty());
        let _ = std::fs::remove_dir_all(&d);
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
        // The hex forms, as the games' own tests call them.
        assert_eq!(display_name_hex(Some("Co\u{202e}us\u{200b}in\u{feff}"), "abcdef0123"), "Cousin");
        assert_eq!(display_name_hex(Some("\u{202e}\u{200b}"), "abcdef0123"), "Keep abcdef");
        assert_eq!(keep_id_hex("abcdef0123"), "ABCDEF");
        assert_eq!(keep_id_hex("abc"), "ABC");
        assert!(is_invisible('\u{202e}') && is_invisible('\u{feff}') && !is_invisible('a') && !is_invisible('\u{e9}'));
        // Tag characters and variation selectors draw nothing and can smuggle text or marks.
        for c in ['\u{e0000}', '\u{e0041}', '\u{e007f}', '\u{fe00}', '\u{fe0f}', '\u{e0100}', '\u{e01ef}'] {
            assert!(is_invisible(c), "{c:?}");
        }
        // Other characters that draw nothing: the combining grapheme joiner, the Mongolian vowel separator, interlinear
        // annotation anchors and musical formatting controls.
        for c in ['\u{34f}', '\u{180e}', '\u{fff9}', '\u{fffa}', '\u{fffb}', '\u{1d173}', '\u{1d17a}'] {
            assert!(is_invisible(c), "{c:?}");
        }
        // Their neighbours are ordinary characters.
        for c in ['\u{dfff0}', '\u{e0080}', '\u{fdff}', '\u{fe10}', '\u{e00ff}', '\u{e01f0}', '\u{301}', '\u{34e}', '\u{350}', '\u{180d}', '\u{180f}', '\u{fff8}', '\u{fffc}', '\u{1d172}', '\u{1d17b}'] {
            assert!(!is_invisible(c), "{c:?}");
        }
    }

    #[test]
    fn line_breaks_and_hangul_fillers_are_stripped_from_names() {
        assert_eq!(display_name(Some("a\u{2028}b\u{2029}c"), &HOST), "abc");
        assert_eq!(display_name(Some("\u{3164}\u{115f}\u{1160}\u{ffa0}"), &HOST), "Keep ababab", "an invisible name is no name");
        assert_eq!(display_name(Some("Mo\u{3164}use"), &HOST), "Mouse");
    }

    #[test]
    fn the_cut_to_forty_does_not_leave_a_trailing_space() {
        let name = format!("{} b", "a".repeat(39));
        assert_eq!(display_name(Some(&name), &HOST), "a".repeat(39));
        assert_eq!(display_name_hex(Some(&name), "abcdef"), "a".repeat(39));
    }

    #[test]
    fn saved_keeps_load_back_and_a_missing_file_is_empty() {
        let d = dir("roundtrip");
        assert!(load(&d).list().is_empty());
        let list = vec![keep(2, 200), keep(1, 100)];
        write(&d, &list);
        let keeps = load(&d);
        assert_eq!(keeps.list(), list.as_slice());
        keeps.save().unwrap();
        assert_eq!(load(&d).list(), list.as_slice());
        assert!(!d.join("keeps.json.tmp").exists(), "the temp file is renamed away");
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_after_every_save() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("mode");
        let mut keeps = load(&d);
        keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap();
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(file(&d)), 0o600, "the file holds secrets");
        keeps.record_join(&[3; 32], &[4; 32], Some("Two"), 20).unwrap();
        assert_eq!(mode(file(&d)), 0o600, "still private after a second save");
        keeps.remember(&[5; 32], &[6; 32], None, 30).unwrap();
        assert_eq!(mode(file(&d)), 0o600);
        keeps.forget(&[5; 32]).unwrap();
        assert_eq!(mode(file(&d)), 0o600);
        assert!(!d.join("keeps.json.tmp").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_wide_open_temp_file_does_not_widen_the_saved_file() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("staletmp");
        std::fs::create_dir_all(&d).unwrap();
        let tmp = d.join("keeps.json.tmp");
        std::fs::write(&tmp, "left behind by a restore").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut keeps = load(&d);
        assert!(keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap());
        let mode = std::fs::metadata(file(&d)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "whatever was left behind");
        assert!(!tmp.exists());
        assert_eq!(load(&d).list().len(), 1);
        // A symlink left at the temp name is replaced, never written through.
        let target = d.join("elsewhere");
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &tmp).unwrap();
        keeps.remember(&[3; 32], &[4; 32], None, 20).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        assert_eq!(std::fs::metadata(file(&d)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load(&d).list().len(), 2);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_file_in_a_missing_directory_is_made_and_a_bare_file_name_works() {
        let d = dir("nested");
        let path = d.join("a").join("b").join("keeps.json");
        let mut keeps = Keeps::load(&path).unwrap();
        assert!(keeps.record_join(&[1; 32], &[2; 32], None, 1).unwrap());
        assert_eq!(Keeps::load(&path).unwrap().list().len(), 1);
        assert_eq!(keeps.path(), path);
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
        let keeps = load(&d);
        assert_eq!(
            keeps.list(),
            [Keep::new(&HOST, &SECRET, Some("Cousin's Keep"), 1_790_000_200), Keep::new(&[2; 32], &[3; 32], None, 1_790_000_100)].as_slice()
        );
        assert_eq!(keeps.list()[0].keys(), Some((HOST, SECRET)));
        // And this crate writes the same bytes the old code did.
        keeps.save().unwrap();
        assert_eq!(std::fs::read_to_string(file(&d)).unwrap(), old_file_text());
        // An old file with no change to make is not rewritten by a repeated join.
        let mut keeps = load(&d);
        assert!(!keeps.record_join(&HOST, &SECRET, Some("Cousin's Keep"), 1_790_000_200).unwrap());
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
        let keeps = load(&d);
        assert_eq!(keeps.list().len(), 1);
        assert_eq!(keeps.list()[0].host_key, "ab".repeat(32), "hex is lower-cased");
        assert_eq!(keeps.list()[0].secret, "0a".repeat(32));
        assert_eq!(keeps.list()[0].name, "Cousin");
        assert!(keeps.contains(&HOST));
        // An empty name falls back to the key.
        let text = format!(r#"[{{"host_key":"{}","secret":"{}","name":"","last_joined":7}}]"#, "ab".repeat(32), "01".repeat(32));
        std::fs::write(file(&d), text).unwrap();
        assert_eq!(load(&d).list()[0].name, "Keep ababab");
        // More than the cap, out of order: newest first, twenty kept.
        let many: Vec<Keep> = (0..30u8).map(|i| keep(i, 1000 + u64::from((i * 7) % 30))).collect();
        std::fs::write(file(&d), serde_json::to_vec(&many).unwrap()).unwrap();
        let loaded = load(&d);
        assert_eq!(loaded.list().len(), MAX_KEEPS);
        assert!(loaded.list().windows(2).all(|w| w[0].last_joined >= w[1].last_joined));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_host_key_in_two_cases_is_one_entry_and_the_newest_stays() {
        let d = dir("dedupe");
        std::fs::create_dir_all(&d).unwrap();
        let entry = |host: String, secret: &str, at: u64| {
            format!("{{\"host_key\":\"{host}\",\"secret\":\"{}\",\"name\":\"N{at}\",\"last_joined\":{at}}}", secret.repeat(32))
        };
        let text = format!("[{},{},{}]", entry("AB".repeat(32), "01", 5), entry("ab".repeat(32), "02", 9), entry("cd".repeat(32), "03", 1));
        std::fs::write(file(&d), text).unwrap();
        let keeps = load(&d);
        assert_eq!(keeps.list().len(), 2);
        assert_eq!(keeps.list()[0].host_key, "ab".repeat(32));
        assert_eq!(keeps.list()[0].secret, "02".repeat(32), "the newest play of the Keep");
        assert_eq!(keeps.list()[0].last_joined, 9);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_same_keep_with_a_new_secret_replaces_the_old_entry() {
        let mut list = vec![keep(2, 200), keep(1, 100)];
        let again = Keep::new(&[1; 32], &[9; 32], Some("Renamed"), 300);
        remember(&mut list, again.clone());
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], again, "newest first");
        assert_eq!(list[1], keep(2, 200));
        assert_eq!(list.iter().filter(|k| k.host_key == hex_of(1)).count(), 1);
    }

    #[test]
    fn the_list_holds_twenty_and_drops_the_oldest() {
        let mut list = Vec::new();
        for i in 0..MAX_KEEPS as u8 {
            remember(&mut list, keep(i, 1000 + u64::from(i)));
        }
        assert_eq!(list.len(), MAX_KEEPS);
        remember(&mut list, keep(100, 5000));
        assert_eq!(list.len(), MAX_KEEPS);
        assert_eq!(list[0], keep(100, 5000));
        assert!(!contains(&list, &hex_of(0)), "the oldest, played at 1000, is gone");
        assert!(contains(&list, &hex_of(1)));
        // A new Keep older than all twenty does not push a newer one out.
        remember(&mut list, keep(101, 1));
        assert_eq!(list.len(), MAX_KEEPS);
        assert!(!contains(&list, &hex_of(101)));
        assert!(contains(&list, &hex_of(100)));
    }

    #[test]
    fn the_list_helpers_ignore_hex_case() {
        let mut list = vec![keep(0xab, 5)];
        assert!(contains(&list, &hex_of(0xab).to_uppercase()));
        assert!(forget(&mut list, &hex_of(0xab).to_uppercase()));
        assert!(!forget(&mut list, &hex_of(0xab)));
        assert!(list.is_empty());
    }

    #[test]
    fn the_file_holds_twenty_through_remember_too() {
        let d = dir("filecap");
        let mut keeps = load(&d);
        for i in 0..(MAX_KEEPS as u8 + 3) {
            keeps.remember(&[i; 32], &[i.wrapping_add(1); 32], None, 1000 + u64::from(i)).unwrap();
        }
        assert_eq!(keeps.list().len(), MAX_KEEPS);
        assert_eq!(load(&d).list().len(), MAX_KEEPS);
        assert!(!keeps.contains(&[0; 32]));
        assert!(keeps.contains(&[22; 32]));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn forgetting_removes_one_keep_and_saves() {
        let d = dir("forget");
        let mut keeps = load(&d);
        keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap();
        keeps.record_join(&[3; 32], &[4; 32], None, 20).unwrap();
        assert_eq!(load(&d).list().len(), 2);
        assert!(keeps.forget(&[1; 32]).unwrap());
        let left = load(&d);
        assert_eq!(left.list().len(), 1);
        assert_eq!(left.list()[0].name, "Keep 030303");
        assert!(!keeps.forget(&[1; 32]).unwrap(), "forgetting an absent Keep changes nothing");
        assert_eq!(load(&d).list(), left.list());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_stale_keeps_cannot_erase_what_another_saved() {
        // The reviewer's probe: A loads, B joins Keep 9, then A forgets a different Keep.
        let d = dir("stale");
        let mut seed = load(&d);
        seed.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap();
        seed.record_join(&[3; 32], &[4; 32], Some("Three"), 20).unwrap();
        let mut a = load(&d);
        let mut b = load(&d);
        b.record_join(&[9; 32], &[8; 32], Some("Nine"), 30).unwrap();
        assert_eq!(a.list().len(), 2, "A's snapshot is stale");
        assert!(a.forget(&[1; 32]).unwrap());
        let on_disk = load(&d);
        assert!(on_disk.contains(&[9; 32]), "B's Keep survived A's forget");
        assert!(on_disk.contains(&[3; 32]));
        assert!(!on_disk.contains(&[1; 32]));
        assert_eq!(a.list(), on_disk.list(), "and A's snapshot caught up");
        // The same through record_join and remember.
        b.record_join(&[10; 32], &[11; 32], None, 40).unwrap();
        a.record_join(&[12; 32], &[13; 32], None, 50).unwrap();
        a.remember(&[14; 32], &[15; 32], None, 60).unwrap();
        let on_disk = load(&d);
        for n in [3u8, 9, 10, 12, 14] {
            assert!(on_disk.contains(&[n; 32]), "{n}");
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_join_that_changes_nothing_does_not_rewrite_the_file() {
        let d = dir("rewrite");
        let mut keeps = load(&d);
        assert!(keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap());
        let first = std::fs::read(file(&d)).unwrap();
        // Replace the file with an identical copy so its modified time is known.
        std::fs::remove_file(file(&d)).unwrap();
        std::fs::write(file(&d), &first).unwrap();
        let mtime = std::fs::metadata(file(&d)).unwrap().modified().unwrap();
        // Same Keep, same secret, same second: the list is as it was.
        assert!(!keeps.record_join(&[1; 32], &[2; 32], Some("One"), 10).unwrap());
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
    fn a_file_that_is_not_a_list_is_set_aside() {
        let d = dir("broken");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(file(&d), "not json").unwrap();
        assert!(load(&d).list().is_empty());
        assert!(!file(&d).exists(), "the bad file is moved, not left in place");
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad")).unwrap(), "not json", "and never lost");
        // Not UTF-8 is also not a list.
        std::fs::write(file(&d), [0xff, 0xfe, 0x00]).unwrap();
        assert!(load(&d).list().is_empty());
        assert_eq!(std::fs::read(d.join("keeps.json.bad.2")).unwrap(), vec![0xff, 0xfe, 0x00], "the earlier one is not replaced");
        // A JSON value that is not an array.
        std::fs::write(file(&d), r#"{"host_key":"x"}"#).unwrap();
        assert!(load(&d).list().is_empty());
        assert!(!file(&d).exists());
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad.3")).unwrap(), r#"{"host_key":"x"}"#);
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad")).unwrap(), "not json");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn one_bad_entry_is_dropped_and_the_rest_stay() {
        let d = dir("badentry");
        std::fs::create_dir_all(&d).unwrap();
        let good = keep(1, 5);
        let mut bad_secret = keep(2, 6);
        bad_secret.secret = "zz".into();
        let mut short = keep(3, 7);
        short.host_key = "ab".into();
        let mut text = serde_json::to_string(&vec![bad_secret, good.clone(), short]).unwrap();
        // An entry with no last_joined, one of the wrong type, and a stray number.
        text.pop();
        text.push_str(&format!(
            ",{{\"host_key\":\"{}\",\"secret\":\"{}\",\"name\":\"x\"}},{{\"host_key\":5}},7]",
            hex_of(4),
            hex_of(5)
        ));
        std::fs::write(file(&d), text).unwrap();
        assert_eq!(load(&d).list(), [good.clone()].as_slice());
        assert!(!d.join("keeps.json.bad").exists(), "a few bad entries are not a bad file");
        assert!(file(&d).exists());
        // Saving after such a load keeps the good one.
        let mut keeps = load(&d);
        keeps.record_join(&[6; 32], &[7; 32], None, 99).unwrap();
        assert_eq!(load(&d).list().len(), 2);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_bad_file_does_not_stop_the_next_join_from_saving() {
        let d = dir("recover");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(file(&d), "{{{").unwrap();
        let mut keeps = load(&d);
        assert!(keeps.record_join(&[1; 32], &[2; 32], None, 1).unwrap());
        assert_eq!(load(&d).list().len(), 1);
        assert!(d.join("keeps.json.bad").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_and_is_never_overwritten() {
        // A directory where the file should be: reading it fails, and it is not "missing".
        let d = dir("unreadable");
        std::fs::create_dir_all(file(&d)).unwrap();
        std::fs::write(file(&d).join("keep-me"), "x").unwrap();
        assert!(Keeps::load(file(&d)).is_err());
        let mut keeps = Keeps { path: file(&d), list: vec![keep(1, 1)], set_aside: None };
        assert!(keeps.record_join(&[2; 32], &[3; 32], None, 5).is_err());
        assert!(keeps.remember(&[2; 32], &[3; 32], None, 5).is_err());
        assert!(keeps.forget(&[1; 32]).is_err());
        assert!(keeps.reload().is_err());
        assert!(file(&d).is_dir(), "nothing was saved over it");
        assert!(file(&d).join("keep-me").exists());
        assert_eq!(keeps.list().len(), 1, "the snapshot is left as it was");
        assert!(!d.join("keeps.json.tmp").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    /// `<file>.bad` for 1, then `<file>.bad.2` ... `<file>.bad.10`.
    fn bad_name(n: u32) -> String {
        if n == 1 { "keeps.json.bad".into() } else { format!("keeps.json.bad.{n}") }
    }

    #[test]
    fn a_corrupt_file_that_cannot_be_set_aside_is_an_error_and_is_kept() {
        // Directories at all ten names make the rename impossible, so the corrupt file stays put.
        let d = dir("badrename");
        for n in 1..=10 {
            std::fs::create_dir_all(d.join(bad_name(n))).unwrap();
        }
        std::fs::write(file(&d), "{{{").unwrap();
        assert!(Keeps::load(file(&d)).is_err());
        let mut keeps = Keeps { path: file(&d), list: Vec::new(), set_aside: None };
        assert!(keeps.record_join(&[2; 32], &[3; 32], None, 5).is_err());
        assert!(keeps.remember(&[2; 32], &[3; 32], None, 5).is_err());
        assert!(keeps.forget(&[1; 32]).is_err());
        assert!(keeps.reload().is_err());
        assert!(keeps.set_aside().is_none());
        assert_eq!(std::fs::read_to_string(file(&d)).unwrap(), "{{{", "the corrupt bytes are still there");
        for n in 1..=10 {
            assert!(d.join(bad_name(n)).is_dir(), "{} is untouched", bad_name(n));
        }
        assert!(!d.join("keeps.json.bad.11").exists());
        assert!(!d.join("keeps.json.tmp").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_second_corrupt_file_does_not_replace_the_first() {
        let d = dir("twobad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(file(&d), "first").unwrap();
        let first = Keeps::load(file(&d)).unwrap();
        assert_eq!(first.set_aside(), Some(d.join("keeps.json.bad").as_path()));
        std::fs::write(file(&d), "second").unwrap();
        let second = Keeps::load(file(&d)).unwrap();
        assert_eq!(second.set_aside(), Some(d.join("keeps.json.bad.2").as_path()));
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad")).unwrap(), "first");
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad.2")).unwrap(), "second");
        assert!(!file(&d).exists());
        // On one instance, a good file read after a set-aside does not clear where it went.
        std::fs::write(file(&d), "third").unwrap();
        let mut keeps = Keeps::load(file(&d)).unwrap();
        let third = d.join("keeps.json.bad.3");
        assert_eq!(keeps.set_aside(), Some(third.as_path()));
        keeps.remember(&[1; 32], &[2; 32], None, 3).unwrap();
        keeps.reload().unwrap();
        assert_eq!(keeps.list().len(), 1, "the good list was read");
        assert_eq!(keeps.set_aside(), Some(third.as_path()), "a good read leaves the last set-aside in place");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_name_that_is_already_taken_is_never_replaced() {
        let d = dir("foreign");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("keeps.json.bad"), "").unwrap();
        std::fs::write(d.join("keeps.json.bad.2"), "foreign").unwrap();
        std::fs::write(file(&d), "corrupt").unwrap();
        let keeps = Keeps::load(file(&d)).unwrap();
        assert_eq!(keeps.set_aside(), Some(d.join("keeps.json.bad.3").as_path()));
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad")).unwrap(), "", "the empty file is untouched");
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad.2")).unwrap(), "foreign");
        assert_eq!(std::fs::read_to_string(d.join("keeps.json.bad.3")).unwrap(), "corrupt");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn corrupt_files_use_all_ten_names_in_order_then_replace_the_last() {
        let d = dir("tenbad");
        std::fs::create_dir_all(&d).unwrap();
        for n in 1..=10u32 {
            std::fs::write(file(&d), format!("corrupt {n}")).unwrap();
            let keeps = Keeps::load(file(&d)).unwrap();
            assert_eq!(keeps.set_aside(), Some(d.join(bad_name(n)).as_path()));
        }
        for n in 1..=10u32 {
            assert_eq!(std::fs::read_to_string(d.join(bad_name(n))).unwrap(), format!("corrupt {n}"));
        }
        for n in 11..=12u32 {
            std::fs::write(file(&d), format!("corrupt {n}")).unwrap();
            let mut keeps = Keeps::load(file(&d)).unwrap();
            assert_eq!(keeps.set_aside(), Some(d.join(bad_name(10)).as_path()));
            assert!(!file(&d).exists());
            keeps.remember(&[1; 32], &[2; 32], None, 3).unwrap();
            std::fs::remove_file(file(&d)).unwrap();
        }
        for n in 1..=9u32 {
            assert_eq!(std::fs::read_to_string(d.join(bad_name(n))).unwrap(), format!("corrupt {n}"), "{} is kept", bad_name(n));
        }
        assert_eq!(std::fs::read_to_string(d.join(bad_name(10))).unwrap(), "corrupt 12", "the last name holds the newest");
        assert!(!d.join("keeps.json.bad.11").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_at_the_last_name_is_never_replaced() {
        let d = dir("lastlink");
        std::fs::create_dir_all(&d).unwrap();
        for n in 1..=9u32 {
            std::fs::write(d.join(bad_name(n)), format!("corrupt {n}")).unwrap();
        }
        let elsewhere = d.join("elsewhere");
        std::fs::write(&elsewhere, "not ours").unwrap();
        std::os::unix::fs::symlink(&elsewhere, d.join(bad_name(10))).unwrap();
        std::fs::write(file(&d), "corrupt 10").unwrap();
        assert!(Keeps::load(file(&d)).is_err());
        assert_eq!(std::fs::read_to_string(file(&d)).unwrap(), "corrupt 10", "left in place");
        assert!(std::fs::symlink_metadata(d.join(bad_name(10))).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "not ours");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_change_that_finds_a_corrupt_file_says_where_it_went() {
        let d = dir("changebad");
        std::fs::create_dir_all(&d).unwrap();
        let mut keeps = Keeps::load(file(&d)).unwrap();
        assert!(keeps.set_aside().is_none());
        std::fs::write(file(&d), "{{{").unwrap();
        assert!(keeps.record_join(&[1; 32], &[2; 32], None, 1).unwrap());
        assert_eq!(keeps.set_aside(), Some(d.join("keeps.json.bad").as_path()));
        std::fs::write(file(&d), "[[").unwrap();
        keeps.remember(&[3; 32], &[4; 32], None, 2).unwrap();
        assert_eq!(keeps.set_aside(), Some(d.join("keeps.json.bad.2").as_path()));
        std::fs::write(file(&d), "((").unwrap();
        keeps.forget(&[3; 32]).unwrap();
        assert_eq!(keeps.set_aside(), Some(d.join("keeps.json.bad.3").as_path()));
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_with_no_read_permission_is_an_error_and_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("noperm");
        write(&d, &[keep(1, 5)]);
        std::fs::set_permissions(file(&d), std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads anything, so only check when the read really fails.
        if std::fs::read(file(&d)).is_err() {
            assert!(Keeps::load(file(&d)).is_err());
            let mut keeps = Keeps { path: file(&d), list: Vec::new(), set_aside: None };
            assert!(keeps.record_join(&[2; 32], &[3; 32], None, 5).is_err());
            std::fs::set_permissions(file(&d), std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(load(&d).list(), [keep(1, 5)].as_slice(), "the saved Keep is still there");
        }
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
        let keeps = Keeps { path: PathBuf::from("keeps.json"), list: vec![k], set_aside: None };
        assert!(!format!("{keeps:?}").contains("0101"));
    }
}
