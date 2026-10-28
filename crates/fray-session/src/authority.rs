//! The synchronous, import-free `fray:authority@0.1.0` contract.
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
