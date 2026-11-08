#![cfg(feature = "authority")]
//! Tier-L stored-authority surface: the separate WIT package, the native types
//! and trait, and the batch validator. These tests prove the shape only. The
//! commit, the store, the quota, the `get` budgets and the stop and interval
//! rules belong to the runner and are not tested here.

use fray_session::authority::{
    validate_persist_batch, AuthorityError, Command, Delivery, ErrorCode, PersistBatch, Player,
    PlayerId, RecordReader, StoredAuthority, StoredEvent, StoredLimits, StoredRecord, Target,
    TickOutput, Time, MAX_PERSIST_BATCH_BYTES, MAX_PERSIST_BATCH_ENTRIES, MAX_STORED_KEY_BYTES,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn stored_debug_reports_lengths_and_counts_only() {
    let record = StoredRecord {
        key: b"private-key-marker".to_vec(),
        value: b"private-value-marker".to_vec(),
    };
    assert_eq!(
        format!("{record:?}"),
        "StoredRecord { key_len: 18, value_len: 20 }"
    );
    let batch = PersistBatch {
        records: vec![record],
        removed: vec![b"private-removed-marker".to_vec()],
        last: false,
    };
    assert_eq!(
        format!("{batch:?}"),
        "PersistBatch { records: 1, record_bytes: 38, removed: 1, last: false }"
    );
}

#[test]
fn stored_debug_stays_short_for_large_payloads_and_nested_outputs() {
    let marker = b"private-record-marker";
    let numeric_marker = format!("{:?}", marker);
    let numeric_marker = numeric_marker.trim_matches(['[', ']']);
    for count in [0, 1, 4096] {
        let batch = PersistBatch {
            records: vec![
                StoredRecord {
                    key: marker.to_vec(),
                    value: marker.repeat(16),
                };
                count
            ],
            removed: vec![marker.to_vec(); count],
            last: true,
        };
        let record = StoredRecord {
            key: marker.repeat(count),
            value: marker.repeat(count),
        };
        let output = TickOutput {
            commands: vec![],
            persist: Some(batch.clone()),
        };
        for text in [
            format!("{record:?}"),
            format!("{record:#?}"),
            format!("{batch:?}"),
            format!("{batch:#?}"),
            format!("{output:?}"),
            format!("{output:#?}"),
        ] {
            assert!(!text.contains(std::str::from_utf8(marker).unwrap()));
            assert!(!text.contains(numeric_marker));
            assert!(
                text.len() < 512,
                "debug output grew to {} bytes",
                text.len()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The WIT packages
// ---------------------------------------------------------------------------

const STORED_WIT: &str = include_str!("../wit-stored/stored-authority.wit");
const FROZEN_WIT: &str = include_str!("../wit/authority.wit");

#[test]
fn stored_wit_is_pinned() {
    assert_eq!(
        hex_sha256(STORED_WIT.as_bytes()),
        "f4d3b661bf1513771a02df8dccf444b595a99c1b5ffef81954c805ed398d0e8e"
    );
}

#[test]
fn stored_wit_is_its_own_package_with_exactly_one_import() {
    assert!(STORED_WIT.starts_with("package fray:stored-authority@0.1.0;\n"));
    assert!(!STORED_WIT.contains("fray:authority"));
    // The world imports `storage` and nothing else, and no interface pulls in
    // another through `use`, which would inject an import into the closure.
    let imports: Vec<&str> = STORED_WIT
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("import ") || line.starts_with("use "))
        .collect();
    assert_eq!(imports, ["import storage;"]);
    assert_eq!(STORED_WIT.matches("world ").count(), 1);
    assert!(STORED_WIT.contains("world stored-game-authority {"));
    assert!(STORED_WIT.contains("export stored-authority;"));
    // The only function the host provides is the restore-only read.
    assert!(STORED_WIT.contains("get: func(key: list<u8>) -> option<list<u8>>;"));
}

#[test]
fn stored_wit_declares_the_staged_batch_and_stopping() {
    for text in [
        "stopping,",
        "record persist-batch {",
        "records: list<stored-record>,",
        "removed: list<list<u8>>,",
        "last: bool,",
        "record tick-output {",
        "persist: option<persist-batch>,",
        "init: func(config: list<u8>, seed: list<u8>) -> result<_, authority-error>;",
        "tick: func(time: time) -> result<tick-output, authority-error>;",
        "restore: func(config: list<u8>, checkpoint: list<u8>) -> result<_, authority-error>;",
    ] {
        assert!(STORED_WIT.contains(text), "missing {text}");
    }
    // The command variant is the S and M one: no persistence case.
    assert!(STORED_WIT
        .contains("variant command { send(send-command), disconnect(leave), set-open(bool) }"));
}

#[test]
fn frozen_s_and_m_wit_is_unchanged_and_import_free() {
    // The pin lives in tests/authority.rs too; repeating it here keeps this
    // file self-checking about the frozen package.
    assert_eq!(
        hex_sha256(FROZEN_WIT.as_bytes()),
        "bf769f074945476a4da4c66fa0be4be39a9cc05269d6e3d3e0442b2d58a95900"
    );
    assert!(FROZEN_WIT.starts_with("package fray:authority@0.1.0;\n"));
    assert!(!FROZEN_WIT.contains("import "));
    assert!(!FROZEN_WIT.contains("storage"));
    assert!(!FROZEN_WIT.contains("stopping"));
    assert!(!FROZEN_WIT.contains("persist"));
}

#[test]
fn frozen_wit_directory_holds_only_the_frozen_world() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("wit");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["authority.wit"]);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("wit-stored");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["stored-authority.wit"]);
}

// ---------------------------------------------------------------------------
// S and M surface: the Command enum keeps its three cases
// ---------------------------------------------------------------------------

#[test]
fn command_enum_has_no_persistence_case() {
    // Stampede and Ingle match `Command` exhaustively. A new variant would stop
    // this match compiling, which is the point.
    fn arm(command: &Command) -> &'static str {
        match command {
            Command::Send { .. } => "send",
            Command::Disconnect { .. } => "disconnect",
            Command::SetOpen(_) => "set-open",
        }
    }
    assert_eq!(arm(&Command::SetOpen(true)), "set-open");
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

fn record(key: &[u8], value: &[u8]) -> StoredRecord {
    StoredRecord {
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

fn batch(records: Vec<StoredRecord>, removed: Vec<Vec<u8>>, last: bool) -> PersistBatch {
    PersistBatch {
        records,
        removed,
        last,
    }
}

fn ceilings() -> StoredLimits {
    StoredLimits {
        key_bytes: MAX_STORED_KEY_BYTES,
        batch_bytes: MAX_PERSIST_BATCH_BYTES,
        batch_entries: MAX_PERSIST_BATCH_ENTRIES,
    }
}

#[test]
fn initial_limit_values() {
    // Initial values, pending measurement on the slowest target.
    assert_eq!(MAX_STORED_KEY_BYTES, 128);
    assert_eq!(MAX_PERSIST_BATCH_BYTES, 1024 * 1024);
    assert_eq!(MAX_PERSIST_BATCH_ENTRIES, 4096);
}

#[test]
fn stored_types_are_plain_comparable_values() {
    let one = batch(vec![record(b"a", b"1")], vec![b"b".to_vec()], true);
    assert_eq!(one.clone(), one);
    let output = TickOutput {
        commands: vec![Command::Send {
            target: Target::Broadcast,
            delivery: Delivery::Lossy,
            bytes: vec![1],
        }],
        persist: Some(one),
    };
    assert_eq!(output.clone(), output);
    assert_eq!(StoredEvent::Stopping, StoredEvent::Stopping);
    assert_ne!(StoredEvent::Control(vec![1]), StoredEvent::Control(vec![2]));
    let joined = StoredEvent::Joined(Player {
        id: PlayerId(1),
        identity: None,
        metadata: Vec::new(),
    });
    assert_eq!(joined.clone(), joined);
    let left = StoredEvent::Left {
        player: PlayerId(1),
        reason: String::new(),
    };
    assert_eq!(left.clone(), left);
    assert_ne!(left, StoredEvent::Stopping);
    let message = StoredEvent::Message {
        player: PlayerId(1),
        delivery: Delivery::Reliable,
        bytes: Vec::new(),
    };
    assert_eq!(message.clone(), message);
    assert_ne!(message, left);
}

// ---------------------------------------------------------------------------
// Batch validator
// ---------------------------------------------------------------------------

fn fault(result: Result<(), AuthorityError>) -> String {
    let error = result.expect_err("expected a module fault");
    assert_eq!(error.code, ErrorCode::Fault);
    error.message
}

#[test]
fn a_last_batch_with_no_records_is_valid() {
    validate_persist_batch(&batch(Vec::new(), Vec::new(), true), ceilings()).unwrap();
    validate_persist_batch(&batch(Vec::new(), Vec::new(), false), ceilings()).unwrap();
}

#[test]
fn staged_and_last_batches_share_one_set_of_limits() {
    for last in [false, true] {
        // At the limits: valid.
        let key = vec![7u8; MAX_STORED_KEY_BYTES];
        validate_persist_batch(
            &batch(
                vec![record(&key, &vec![0; MAX_PERSIST_BATCH_BYTES - key.len()])],
                Vec::new(),
                last,
            ),
            ceilings(),
        )
        .unwrap();
        // One byte over the batch cap.
        fault(validate_persist_batch(
            &batch(
                vec![record(
                    &key,
                    &vec![0; MAX_PERSIST_BATCH_BYTES - key.len() + 1],
                )],
                Vec::new(),
                last,
            ),
            ceilings(),
        ));
        // Exactly the entry cap, records and removals together.
        let records: Vec<_> = (0..MAX_PERSIST_BATCH_ENTRIES / 2)
            .map(|i| record(&(i as u32).to_be_bytes(), b""))
            .collect();
        let removed: Vec<_> = (0..MAX_PERSIST_BATCH_ENTRIES / 2)
            .map(|i| (1_000_000 + i as u32).to_be_bytes().to_vec())
            .collect();
        validate_persist_batch(&batch(records.clone(), removed.clone(), last), ceilings()).unwrap();
        // One more removal pushes records plus removals past the cap.
        let mut removed = removed;
        removed.push(2_000_000u32.to_be_bytes().to_vec());
        fault(validate_persist_batch(
            &batch(records, removed, last),
            ceilings(),
        ));
    }
}

#[test]
fn entry_count_is_checked_over_records_and_removals_together() {
    let removed: Vec<_> = (0..=MAX_PERSIST_BATCH_ENTRIES)
        .map(|i| (i as u32).to_be_bytes().to_vec())
        .collect();
    let message = fault(validate_persist_batch(
        &batch(Vec::new(), removed, true),
        ceilings(),
    ));
    assert!(message.contains("entries"), "{message}");
    // Records and removals together: each list is under the cap, the sum is not.
    let records: Vec<_> = (0..MAX_PERSIST_BATCH_ENTRIES / 2 + 1)
        .map(|i| record(&(i as u32).to_be_bytes(), b""))
        .collect();
    let removed: Vec<_> = (0..MAX_PERSIST_BATCH_ENTRIES / 2)
        .map(|i| (1_000_000 + i as u32).to_be_bytes().to_vec())
        .collect();
    let message = fault(validate_persist_batch(
        &batch(records, removed, true),
        ceilings(),
    ));
    assert!(message.contains("entries"), "{message}");
}

#[test]
fn batch_bytes_count_keys_values_and_removed_keys() {
    // Keys of 100 bytes: 1 record of 100 + value, plus 1 removal of 100.
    let key = vec![1u8; 100];
    let removed = vec![vec![2u8; 100]];
    let value_room = MAX_PERSIST_BATCH_BYTES - 200;
    validate_persist_batch(
        &batch(
            vec![record(&key, &vec![0; value_room])],
            removed.clone(),
            true,
        ),
        ceilings(),
    )
    .unwrap();
    let message = fault(validate_persist_batch(
        &batch(vec![record(&key, &vec![0; value_room + 1])], removed, true),
        ceilings(),
    ));
    assert!(message.contains("bytes"), "{message}");
}

#[test]
fn a_single_value_larger_than_a_batch_is_a_fault() {
    let message = fault(validate_persist_batch(
        &batch(
            vec![record(b"k", &vec![0; MAX_PERSIST_BATCH_BYTES + 1])],
            Vec::new(),
            false,
        ),
        ceilings(),
    ));
    assert!(message.contains("value"), "{message}");
}

#[test]
fn over_long_keys_are_faults_in_records_and_in_removed() {
    let long = vec![9u8; MAX_STORED_KEY_BYTES + 1];
    let exact = vec![9u8; MAX_STORED_KEY_BYTES];
    validate_persist_batch(
        &batch(
            vec![record(&exact, b"v")],
            vec![vec![8u8; MAX_STORED_KEY_BYTES]],
            true,
        ),
        ceilings(),
    )
    .unwrap();
    let message = fault(validate_persist_batch(
        &batch(vec![record(&long, b"v")], Vec::new(), true),
        ceilings(),
    ));
    assert!(message.contains("key"), "{message}");
    let message = fault(validate_persist_batch(
        &batch(Vec::new(), vec![long], false),
        ceilings(),
    ));
    assert!(message.contains("key"), "{message}");
}

#[test]
fn duplicate_keys_are_faults() {
    let message = fault(validate_persist_batch(
        &batch(
            vec![record(b"a", b"1"), record(b"b", b"2"), record(b"a", b"3")],
            Vec::new(),
            true,
        ),
        ceilings(),
    ));
    assert!(message.contains("duplicate"), "{message}");
    let message = fault(validate_persist_batch(
        &batch(Vec::new(), vec![b"a".to_vec(), b"a".to_vec()], false),
        ceilings(),
    ));
    assert!(message.contains("duplicate"), "{message}");
}

#[test]
fn a_key_in_both_records_and_removed_is_a_fault() {
    let message = fault(validate_persist_batch(
        &batch(vec![record(b"a", b"1")], vec![b"a".to_vec()], true),
        ceilings(),
    ));
    assert!(message.contains("both"), "{message}");
    // Distinct keys across the two lists are fine.
    validate_persist_batch(
        &batch(vec![record(b"a", b"1")], vec![b"b".to_vec()], true),
        ceilings(),
    )
    .unwrap();
}

#[test]
fn a_profile_may_declare_less_but_never_more_than_the_ceilings() {
    let small = StoredLimits {
        key_bytes: 4,
        batch_bytes: 16,
        batch_entries: 2,
    };
    validate_persist_batch(
        &batch(vec![record(b"abcd", b"0123456789ab")], Vec::new(), true),
        small,
    )
    .unwrap();
    fault(validate_persist_batch(
        &batch(vec![record(b"abcde", b"")], Vec::new(), true),
        small,
    ));
    fault(validate_persist_batch(
        &batch(vec![record(b"a", b"0123456789abcdef")], Vec::new(), true),
        small,
    ));
    fault(validate_persist_batch(
        &batch(
            vec![record(b"a", b""), record(b"b", b"")],
            vec![b"c".to_vec()],
            true,
        ),
        small,
    ));
    // The profile's key limit also applies to removed keys.
    fault(validate_persist_batch(
        &batch(Vec::new(), vec![b"abcde".to_vec()], true),
        small,
    ));
    // Limits above the ceilings are clamped to them.
    let huge = StoredLimits {
        key_bytes: usize::MAX,
        batch_bytes: usize::MAX,
        batch_entries: usize::MAX,
    };
    fault(validate_persist_batch(
        &batch(
            vec![record(&vec![0; MAX_STORED_KEY_BYTES + 1], b"")],
            Vec::new(),
            true,
        ),
        huge,
    ));
    fault(validate_persist_batch(
        &batch(
            vec![record(b"k", &vec![0; MAX_PERSIST_BATCH_BYTES])],
            Vec::new(),
            true,
        ),
        huge,
    ));
    fault(validate_persist_batch(
        &batch(
            Vec::new(),
            (0..=MAX_PERSIST_BATCH_ENTRIES)
                .map(|i| (i as u32).to_be_bytes().to_vec())
                .collect(),
            true,
        ),
        huge,
    ));
}

#[test]
fn an_empty_key_is_valid_and_counts_no_bytes() {
    validate_persist_batch(
        &batch(
            vec![record(b"", &vec![0; MAX_PERSIST_BATCH_BYTES])],
            Vec::new(),
            false,
        ),
        ceilings(),
    )
    .unwrap();
    validate_persist_batch(&batch(Vec::new(), vec![Vec::new()], true), ceilings()).unwrap();
}

#[test]
fn validate_persist_batch_does_not_touch_command_validation() {
    // `validate_command_batch` keeps its shape: slice, membership closure,
    // limits. A call written against the old signature still compiles.
    use fray_session::authority::{validate_command_batch, CommandLimits};
    validate_command_batch(
        &[Command::SetOpen(false)],
        |_| true,
        CommandLimits {
            commands: 1,
            message_bytes: 1,
            batch_bytes: 1,
            reason_bytes: 1,
        },
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// The trait, exercised by a minimal test authority (no runner, no store)
// ---------------------------------------------------------------------------

struct MapReader(BTreeMap<Vec<u8>, Vec<u8>>);

impl RecordReader for MapReader {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AuthorityError> {
        Ok(self.0.get(key).cloned())
    }
}

struct FailingReader;

impl RecordReader for FailingReader {
    fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, AuthorityError> {
        Err(AuthorityError::fault("storage read failed"))
    }
}

/// Holds one stored record. The checkpoint binds it by key and SHA-256 digest
/// of its stored bytes. `restore` verifies the digest before it parses.
///
/// It shows the seed rule: `init` derives a value from the seed under a domain
/// label and keeps only that value. The raw seed is never stored, and the
/// derived value travels in the checkpoint, so `restore` needs no seed.
#[derive(Debug, PartialEq, Eq)]
struct Notebook {
    tick: u64,
    page: u32,
    derived: [u8; 32],
    dirty: bool,
    stopping: bool,
}

const KEY: &[u8] = b"page";
const DERIVE_LABEL: &[u8] = b"notebook/derived/v1\0";

fn derive(seed: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DERIVE_LABEL);
    hash.update(seed);
    hash.finalize().into()
}

impl Notebook {
    fn stored_page(&self) -> Vec<u8> {
        self.page.to_be_bytes().to_vec()
    }
}

impl StoredAuthority for Notebook {
    fn init(_config: &[u8], seed: &[u8; 32]) -> Result<Self, AuthorityError> {
        Ok(Self {
            tick: 0,
            page: 0,
            derived: derive(seed),
            dirty: false,
            stopping: false,
        })
    }

    fn on_event(
        &mut self,
        _time: Time,
        event: StoredEvent,
    ) -> Result<Vec<Command>, AuthorityError> {
        match event {
            StoredEvent::Control(bytes) => {
                self.page = u32::from(bytes.first().copied().unwrap_or(0));
                self.dirty = true;
            }
            StoredEvent::Stopping => self.stopping = true,
            StoredEvent::Joined(_) | StoredEvent::Left { .. } | StoredEvent::Message { .. } => {}
        }
        Ok(Vec::new())
    }

    fn tick(&mut self, time: Time) -> Result<TickOutput, AuthorityError> {
        self.tick = time.tick;
        let persist = if self.dirty || self.stopping {
            self.dirty = false;
            Some(PersistBatch {
                records: vec![StoredRecord {
                    key: KEY.to_vec(),
                    value: self.stored_page(),
                }],
                removed: Vec::new(),
                last: true,
            })
        } else {
            None
        };
        Ok(TickOutput {
            commands: Vec::new(),
            persist,
        })
    }

    fn checkpoint(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut out = self.tick.to_be_bytes().to_vec();
        out.extend_from_slice(&Sha256::digest(self.stored_page()));
        out.extend_from_slice(&self.derived);
        Ok(out)
    }

    fn restore(
        _config: &[u8],
        checkpoint: &[u8],
        records: &dyn RecordReader,
    ) -> Result<Self, AuthorityError> {
        let invalid = |what| AuthorityError::new(ErrorCode::InvalidCheckpoint, what);
        if checkpoint.len() != 72 {
            return Err(invalid("checkpoint length"));
        }
        let tick = u64::from_be_bytes(checkpoint[..8].try_into().unwrap());
        let bound = &checkpoint[8..40];
        let derived: [u8; 32] = checkpoint[40..].try_into().unwrap();
        // A reader error is the runner's, and goes back unchanged.
        let stored = records
            .get(KEY)?
            .ok_or_else(|| invalid("bound record is absent"))?;
        if Sha256::digest(&stored).as_slice() != bound {
            return Err(invalid("bound record digest mismatch"));
        }
        let page = u32::from_be_bytes(
            stored
                .as_slice()
                .try_into()
                .map_err(|_| invalid("record length"))?,
        );
        Ok(Self {
            tick,
            page,
            derived,
            dirty: false,
            stopping: false,
        })
    }

    fn state_hash(&self) -> Result<[u8; 32], AuthorityError> {
        fray_session::authority::checkpoint_hash(&self.checkpoint()?)
    }
}

fn time(tick: u64) -> Time {
    Time::at_tick(tick, 60).unwrap()
}

fn committed(authority: &Notebook, batch: &PersistBatch) -> (Vec<u8>, MapReader) {
    let mut store = BTreeMap::new();
    for record in &batch.records {
        store.insert(record.key.clone(), record.value.clone());
    }
    (authority.checkpoint().unwrap(), MapReader(store))
}

#[test]
fn tick_returns_an_optional_batch() {
    let seed = [7u8; 32];
    let mut authority = Notebook::init(b"", &seed).unwrap();
    assert_eq!(authority.tick(time(1)).unwrap().persist, None);
    authority
        .on_event(time(2), StoredEvent::Control(vec![5]))
        .unwrap();
    let output = authority.tick(time(2)).unwrap();
    let persist = output.persist.expect("batch");
    assert!(persist.last);
    validate_persist_batch(&persist, ceilings()).unwrap();
}

#[test]
fn stopping_leads_to_a_last_batch() {
    let mut authority = Notebook::init(b"", &[0; 32]).unwrap();
    assert_eq!(
        authority.on_event(time(1), StoredEvent::Stopping).unwrap(),
        Vec::new()
    );
    let output = authority.tick(time(1)).unwrap();
    assert!(output.persist.expect("last batch on stop").last);
}

#[test]
fn restore_round_trips_through_the_record_reader() {
    let mut authority = Notebook::init(b"", &[1; 32]).unwrap();
    authority
        .on_event(time(1), StoredEvent::Control(vec![9]))
        .unwrap();
    let persist = authority.tick(time(1)).unwrap().persist.unwrap();
    let (checkpoint, reader) = committed(&authority, &persist);
    let restored = Notebook::restore(b"", &checkpoint, &reader).unwrap();
    assert_eq!(restored.page, 9);
    assert_eq!(restored.tick, 1);
    assert_eq!(
        restored.state_hash().unwrap(),
        authority.state_hash().unwrap()
    );
    // The derived value comes back from the checkpoint; there is no seed.
    assert_eq!(restored.derived, authority.derived);
}

#[test]
fn the_seed_is_derived_from_and_forgotten() {
    let seed = [0x5au8; 32];
    let authority = Notebook::init(b"", &seed).unwrap();
    // The kept value is neither the seed nor a prefix of it.
    assert_ne!(authority.derived, seed);
    assert_ne!(authority.derived[..16], seed[..16]);
    // It depends on the seed, and a different seed gives a different value.
    assert_ne!(
        authority.derived,
        Notebook::init(b"", &[0x5bu8; 32]).unwrap().derived
    );
    // The checkpoint carries the derived value and never the raw seed.
    let checkpoint = authority.checkpoint().unwrap();
    assert!(checkpoint.windows(32).any(|w| w == authority.derived));
    assert!(!checkpoint.windows(32).any(|w| w == seed));
}

fn committed_root() -> (Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>) {
    let mut authority = Notebook::init(b"", &[1; 32]).unwrap();
    authority
        .on_event(time(1), StoredEvent::Control(vec![9]))
        .unwrap();
    let persist = authority.tick(time(1)).unwrap().persist.unwrap();
    let (checkpoint, reader) = committed(&authority, &persist);
    (checkpoint, reader.0)
}

#[test]
fn restore_verifies_digests_before_using_a_record() {
    // A flipped byte: wrong digest. The record is also the wrong length, so a
    // parse-first restore would report a length error; the digest comes first.
    let (checkpoint, mut store) = committed_root();
    store.insert(KEY.to_vec(), vec![0xff; 9]);
    let error = Notebook::restore(b"", &checkpoint, &MapReader(store)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidCheckpoint);
    assert!(error.message.contains("digest"), "{}", error.message);

    // Same length, one byte flipped.
    let (checkpoint, mut store) = committed_root();
    store.get_mut(KEY).unwrap()[3] ^= 1;
    let error = Notebook::restore(b"", &checkpoint, &MapReader(store)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidCheckpoint);

    // An older valid value of the same key.
    let (checkpoint, mut store) = committed_root();
    store.insert(KEY.to_vec(), 1u32.to_be_bytes().to_vec());
    let error = Notebook::restore(b"", &checkpoint, &MapReader(store)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidCheckpoint);

    // The bound key is absent and a valid record sits under another key. (A
    // single-key fixture cannot swap two bound records.)
    let (checkpoint, mut store) = committed_root();
    let valid = store.remove(KEY).unwrap();
    store.insert(b"other".to_vec(), valid);
    let error = Notebook::restore(b"", &checkpoint, &MapReader(store)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidCheckpoint);
}

#[test]
fn an_absent_record_is_invalid_checkpoint_not_a_storage_failure() {
    let (checkpoint, _) = committed_root();
    let error = Notebook::restore(b"", &checkpoint, &MapReader(BTreeMap::new())).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidCheckpoint);
    assert!(error.message.contains("absent"), "{}", error.message);
}

#[test]
fn a_reader_error_is_returned_unchanged() {
    let (checkpoint, _) = committed_root();
    let error = Notebook::restore(b"", &checkpoint, &FailingReader).unwrap_err();
    assert_eq!(error, AuthorityError::fault("storage read failed"));
    assert_ne!(error.code, ErrorCode::InvalidCheckpoint);
}
