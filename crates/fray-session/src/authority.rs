//! The synchronous `fray:authority@0.1.0` contract, import-free for tiers S and
//! M, and the separate tier-L stored-authority surface.
//!
//! Tier L is a different package, `fray:stored-authority@0.1.0`
//! (`wit-stored/stored-authority.wit`). Its world imports `storage.get`, a
//! restore-only read of the game's own records, and nothing else. The S and M
//! package, its `Authority` trait and its `Command` enum are unchanged.
//!
//! Game adapters own rules, seeded randomness and canonical checkpoints. The
//! host authenticates input, records ordering and validates a complete command
//! batch before publishing it. No helper here authenticates an identity, rolls
//! back a failed call or enforces allocation, fuel or platform confinement.
//! Security time and protocol signing belong to the trusted host shell.

use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fmt;

pub use crate::checkpoint::{MAX_BATCH as MAX_COMMANDS, MAX_IMAGE as MAX_CHECKPOINT_BYTES};
pub const STATE_HASH_DOMAIN: &[u8] = b"fray/authority-state/v1\0";

/// Session-stable identity assigned by the host, never a connection-local ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlayerId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
    pub tick: u64,
    pub elapsed_us: u64,
}

impl Time {
    /// Exact logical time, with wide intermediate arithmetic and no clock read.
    pub fn at_tick(tick: u64, tick_hz: u32) -> Result<Self, AuthorityError> {
        if tick_hz == 0 {
            return Err(AuthorityError::new(
                ErrorCode::InvalidConfig,
                "zero tick rate",
            ));
        }
        let elapsed = u128::from(tick) * 1_000_000 / u128::from(tick_hz);
        let elapsed_us =
            u64::try_from(elapsed).map_err(|_| AuthorityError::fault("logical time overflow"))?;
        Ok(Self { tick, elapsed_us })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Reliable,
    Lossy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Player {
    pub id: PlayerId,
    pub identity: Option<[u8; 32]>,
    pub metadata: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Joined(Player),
    Left {
        player: PlayerId,
        reason: String,
    },
    Message {
        player: PlayerId,
        delivery: Delivery,
        bytes: Vec<u8>,
    },
    /// Only the authorised host/controller may construct this event.
    Control(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Player(PlayerId),
    Broadcast,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Send {
        target: Target,
        delivery: Delivery,
        bytes: Vec<u8>,
    },
    /// The host follows this with an ordered `Left`; membership does not change
    /// while the current command batch is being checked.
    Disconnect {
        player: PlayerId,
        reason: String,
    },
    SetOpen(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidConfig,
    InvalidCheckpoint,
    UnsupportedVersion,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityError {
    pub code: ErrorCode,
    pub message: String,
}

impl AuthorityError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn fault(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Fault, message)
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authority {:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthorityError {}

/// One session, synchronous calls, no hidden I/O or background work.
///
/// Construct a fresh instance through exactly one of `init` or `restore`.
/// Apply each step's events in recorded order, then `tick` once with the same
/// time. Checkpoint only after the tick. An error invalidates the instance;
/// discard tentative commands, even if earlier calls in that step succeeded.
pub trait Authority: Send {
    fn init(config: &[u8], seed: u64) -> Result<Self, AuthorityError>
    where
        Self: Sized;
    fn on_event(&mut self, time: Time, event: Event) -> Result<Vec<Command>, AuthorityError>;
    fn tick(&mut self, time: Time) -> Result<Vec<Command>, AuthorityError>;
    fn checkpoint(&self) -> Result<Vec<u8>, AuthorityError>;
    fn restore(config: &[u8], checkpoint: &[u8]) -> Result<Self, AuthorityError>
    where
        Self: Sized;
    fn state_hash(&self) -> Result<[u8; 32], AuthorityError>;
}

/// Validate the WIT semantic length without allocating another buffer.
pub fn identity_from_bytes(bytes: Option<&[u8]>) -> Result<Option<[u8; 32]>, AuthorityError> {
    bytes
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| AuthorityError::fault("identity length"))
        })
        .transpose()
}

/// Hash complete canonical bytes. Games must retain their own config/schema
/// binding; this domain is distinct from migration's state hash.
pub fn checkpoint_hash(bytes: &[u8]) -> Result<[u8; 32], AuthorityError> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(AuthorityError::fault("checkpoint exceeds session limit"));
    }
    let mut hash = Sha256::new();
    hash.update(STATE_HASH_DOMAIN);
    hash.update(bytes);
    Ok(hash.finalize().into())
}

/// Shared adapter call ordering. Serialize the completed tick with game state;
/// restore it only after validating the complete config-bound checkpoint.
/// Initialization itself is enforced by native construction and the component
/// bindings. This helper owns no membership or authenticated connection map.
#[derive(Debug)]
pub struct StepOrder {
    tick_hz: u32,
    completed_tick: u64,
    pending_events: bool,
    faulted: Cell<bool>,
}

impl StepOrder {
    pub fn new(tick_hz: u32) -> Result<Self, AuthorityError> {
        Self::after_tick(tick_hz, 0)
    }

    pub fn after_tick(tick_hz: u32, completed_tick: u64) -> Result<Self, AuthorityError> {
        Time::at_tick(0, tick_hz)?;
        let next = completed_tick.checked_add(1).ok_or_else(|| {
            AuthorityError::new(ErrorCode::InvalidCheckpoint, "completed tick overflow")
        })?;
        Time::at_tick(next, tick_hz).map_err(|_| {
            AuthorityError::new(ErrorCode::InvalidCheckpoint, "completed time overflow")
        })?;
        Ok(Self {
            tick_hz,
            completed_tick,
            pending_events: false,
            faulted: Cell::new(false),
        })
    }

    fn check_next(&self, time: Time) -> Result<(), AuthorityError> {
        if self.faulted.get() {
            return Err(AuthorityError::fault("instance is faulted"));
        }
        let expected = self
            .completed_tick
            .checked_add(1)
            .and_then(|tick| Time::at_tick(tick, self.tick_hz).ok());
        if expected != Some(time) {
            self.fault();
            return Err(AuthorityError::fault("event or tick is out of order"));
        }
        Ok(())
    }

    pub fn on_event(&mut self, time: Time) -> Result<(), AuthorityError> {
        self.check_next(time)?;
        self.pending_events = true;
        Ok(())
    }

    /// Call after successful game execution and complete output validation.
    /// A game error must instead call `fault` and discard all step outputs.
    pub fn finish_tick(&mut self, time: Time) -> Result<(), AuthorityError> {
        self.check_next(time)?;
        self.completed_tick = time.tick;
        self.pending_events = false;
        Ok(())
    }

    pub fn checkpoint_tick(&self) -> Result<u64, AuthorityError> {
        if self.faulted.get() || self.pending_events {
            self.fault();
            return Err(AuthorityError::fault(
                "checkpoint is not at a completed step",
            ));
        }
        Ok(self.completed_tick)
    }

    pub fn fault(&self) {
        self.faulted.set(true);
    }
}

/// Per-game bounds; existing smaller message and output caps must win.
#[derive(Clone, Copy, Debug)]
pub struct CommandLimits {
    pub commands: usize,
    pub message_bytes: usize,
    pub batch_bytes: usize,
    pub reason_bytes: usize,
}

/// Validate every command before the caller publishes any of them. Membership
/// is host-owned and fixed throughout validation; disconnects do not mutate it.
/// Native buffers already exist here: pre-lifting allocation bounds belong to
/// the component runtime, not this post-lifting semantic check.
pub fn validate_command_batch(
    commands: &[Command],
    player_exists: impl Fn(PlayerId) -> bool,
    limits: CommandLimits,
) -> Result<(), AuthorityError> {
    if commands.len() > limits.commands.min(MAX_COMMANDS) {
        return Err(AuthorityError::fault("command count exceeds limit"));
    }
    let mut total = 0usize;
    for command in commands {
        let bytes = match command {
            Command::Send { target, bytes, .. } => {
                if matches!(target, Target::Player(player) if !player_exists(*player)) {
                    return Err(AuthorityError::fault("unknown send target"));
                }
                if bytes.len() > limits.message_bytes.min(crate::MAX_RELIABLE_LEN) {
                    return Err(AuthorityError::fault("message exceeds limit"));
                }
                bytes.len()
            }
            Command::Disconnect { player, reason } => {
                if !player_exists(*player) {
                    return Err(AuthorityError::fault("unknown disconnect target"));
                }
                if reason.len() > limits.reason_bytes {
                    return Err(AuthorityError::fault("disconnect reason exceeds limit"));
                }
                reason.len()
            }
            Command::SetOpen(_) => 0,
        };
        total = total
            .checked_add(bytes)
            .filter(|&total| total <= limits.batch_bytes)
            .ok_or_else(|| AuthorityError::fault("command bytes exceed limit"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier L: stored authority
// ---------------------------------------------------------------------------
//
// The types below are the native surface of `fray:stored-authority@0.1.0`.
// They add to this module; no S or M item changes. `Command` gains no case.

/// An event delivered to a tier-L authority: the S and M events plus
/// `Stopping`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredEvent {
    Joined(Player),
    Left {
        player: PlayerId,
        reason: String,
    },
    Message {
        player: PlayerId,
        delivery: Delivery,
        bytes: Vec<u8>,
    },
    /// Only the authorised host/controller may construct this event.
    Control(Vec<u8>),
    /// The room is closed. The runner keeps stepping and exits after the next
    /// commit or at the end of the profile's stop budget, whichever is first.
    Stopping,
}

/// One stored record. `key` is game-defined, opaque to the runner, unique
/// within a batch, at most [`MAX_STORED_KEY_BYTES`] bytes, and should carry no
/// persona identifier. `value` is the record's complete canonical bytes; a
/// later write to the same key replaces it entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A batch of record writes and removals, returned from `tick`.
///
/// `last = false` stages the batch: it is made durable or discarded on a
/// crash, and is not a restore point. `last = true` commits everything staged
/// since the previous commit, this batch, the checkpoint taken after the same
/// tick and the runner's own session record as one durable root. Within a
/// staged set the latest write or removal of a key wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistBatch {
    pub records: Vec<StoredRecord>,
    /// Keys to remove from the store at the next commit.
    pub removed: Vec<Vec<u8>>,
    pub last: bool,
}

/// What a tier-L `tick` returns: the commands, and at most one persist batch.
/// `on_event` cannot persist, by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickOutput {
    pub commands: Vec<Command>,
    pub persist: Option<PersistBatch>,
}

/// Supplied by the runner for the duration of one `restore`. An `Err` is the
/// runner's own read failure; the authority returns it unchanged and the
/// runner reports a storage failure, not an invalid checkpoint.
///
/// `get` returns the committed bytes of the record the checkpoint being
/// restored was committed with, or `None` if the key is not in the store.
/// `restore` must verify every record it reads against the checkpoint's
/// binding before using it, and return `invalid-checkpoint` on a mismatch or
/// an absent record.
pub trait RecordReader {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AuthorityError>;
}

/// The tier-L authority: [`Authority`] with a 32-byte runner seed, a staged
/// persist batch in `tick`'s output, a `Stopping` event and a restore that
/// reads its records through a [`RecordReader`].
///
/// The same call ordering and error rules as [`Authority`] apply. A tier-L
/// runner calls `checkpoint` and `state_hash` only at a step whose tick
/// returned a `last` batch, so an authority withholds `last` on a tick it
/// cannot checkpoint rather than returning an error.
///
/// `seed` is 32 bytes of OS randomness drawn by the runner and passed once. It
/// must not be logged, persisted or copied into a checkpoint, a stored record
/// or any value sent to a player; derive each value from it through a one-way
/// function under the game's own domain label. After a `restore` there is no
/// seed.
pub trait StoredAuthority: Send {
    fn init(config: &[u8], seed: &[u8; 32]) -> Result<Self, AuthorityError>
    where
        Self: Sized;
    fn on_event(&mut self, time: Time, event: StoredEvent) -> Result<Vec<Command>, AuthorityError>;
    fn tick(&mut self, time: Time) -> Result<TickOutput, AuthorityError>;
    fn checkpoint(&self) -> Result<Vec<u8>, AuthorityError>;
    fn restore(
        config: &[u8],
        checkpoint: &[u8],
        records: &dyn RecordReader,
    ) -> Result<Self, AuthorityError>
    where
        Self: Sized;
    fn state_hash(&self) -> Result<[u8; 32], AuthorityError>;
}

// The three ceilings below are initial values for tier L v1. They are
// placeholders until the measurement gate (batch, checkpoint and commit time
// at the bench sizes, in WASM, on the slowest target) sets them; the
// mechanisms are firm, the numbers are not.

/// Longest record key, in a batch, in `removed` or on `get`. Initial value,
/// pending measurement.
pub const MAX_STORED_KEY_BYTES: usize = 128;
/// Largest batch payload: the keys and values of its records plus its removed
/// keys. A record value must fit one batch. Initial value, pending
/// measurement.
pub const MAX_PERSIST_BATCH_BYTES: usize = 1024 * 1024;
/// Most records plus removals in one batch. Initial value, pending
/// measurement.
pub const MAX_PERSIST_BATCH_ENTRIES: usize = 4096;

/// Per-profile bounds for one persist batch. A profile may declare less than
/// the ceilings above and never more.
#[derive(Clone, Copy, Debug)]
pub struct StoredLimits {
    pub key_bytes: usize,
    pub batch_bytes: usize,
    pub batch_entries: usize,
}

/// Validate one persist batch, staged or `last`, before the caller accepts any
/// of it. A violation is a module fault. This checks only the batch itself:
/// total stored bytes and keys, the commit, and the number of batches per tick
/// belong to the runner, which knows the store.
///
/// Keys must be unique within `records` and within `removed`, and no key may be
/// in both: the order of a write and a removal of one key inside a single batch
/// is not defined. Across batches the latest write or removal wins.
pub fn validate_persist_batch(
    batch: &PersistBatch,
    limits: StoredLimits,
) -> Result<(), AuthorityError> {
    let key_bytes = limits.key_bytes.min(MAX_STORED_KEY_BYTES);
    let batch_bytes = limits.batch_bytes.min(MAX_PERSIST_BATCH_BYTES);
    let batch_entries = limits.batch_entries.min(MAX_PERSIST_BATCH_ENTRIES);
    let entries = batch.records.len().saturating_add(batch.removed.len());
    if entries > batch_entries {
        return Err(AuthorityError::fault("batch entries exceed limit"));
    }
    let mut total = 0usize;
    let mut written = std::collections::HashSet::with_capacity(batch.records.len());
    for record in &batch.records {
        if record.key.len() > key_bytes {
            return Err(AuthorityError::fault("record key exceeds limit"));
        }
        if record.value.len() > batch_bytes {
            return Err(AuthorityError::fault("record value exceeds batch limit"));
        }
        if !written.insert(record.key.as_slice()) {
            return Err(AuthorityError::fault("duplicate record key"));
        }
        total = add_batch_bytes(total, record.key.len(), batch_bytes)?;
        total = add_batch_bytes(total, record.value.len(), batch_bytes)?;
    }
    let mut removed = std::collections::HashSet::with_capacity(batch.removed.len());
    for key in &batch.removed {
        if key.len() > key_bytes {
            return Err(AuthorityError::fault("removed key exceeds limit"));
        }
        if !removed.insert(key.as_slice()) {
            return Err(AuthorityError::fault("duplicate removed key"));
        }
        if written.contains(key.as_slice()) {
            return Err(AuthorityError::fault("key in both records and removed"));
        }
        total = add_batch_bytes(total, key.len(), batch_bytes)?;
    }
    Ok(())
}

fn add_batch_bytes(total: usize, add: usize, limit: usize) -> Result<usize, AuthorityError> {
    total
        .checked_add(add)
        .filter(|&total| total <= limit)
        .ok_or_else(|| AuthorityError::fault("batch bytes exceed limit"))
}
