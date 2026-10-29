#![cfg(feature = "authority")]

use fray_session::authority::{
    checkpoint_hash, identity_from_bytes, validate_command_batch, AuthorityError, Command,
    CommandLimits, Delivery, ErrorCode, PlayerId, StepOrder, Target, Time, MAX_CHECKPOINT_BYTES,
    MAX_COMMANDS,
};
use sha2::{Digest, Sha256};

fn time(tick: u64) -> Time {
    Time::at_tick(tick, 60).unwrap()
}

fn limits() -> CommandLimits {
    CommandLimits {
        commands: MAX_COMMANDS,
        message_bytes: 1024,
        batch_bytes: 2048,
        reason_bytes: 64,
    }
}

fn send(player: u64, len: usize) -> Command {
    Command::Send {
        target: Target::Player(PlayerId(player)),
        delivery: Delivery::Reliable,
        bytes: vec![0; len],
    }
}

#[test]
fn contract_copy_keeps_the_canonical_world() {
    let digest = Sha256::digest(include_bytes!("../wit/authority.wit"));
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "bf769f074945476a4da4c66fa0be4be39a9cc05269d6e3d3e0442b2d58a95900"
    );
}

#[test]
fn logical_time_uses_exact_wide_arithmetic() {
    assert_eq!(
        time(1),
        Time {
            tick: 1,
            elapsed_us: 16_666
        }
    );
    assert_eq!(time(2).elapsed_us, 33_333);
    assert_eq!(time(60).elapsed_us, 1_000_000);
    assert_eq!(
        Time::at_tick(u64::MAX, 1_000_000).unwrap().elapsed_us,
        u64::MAX
    );
    assert!(Time::at_tick(u64::MAX, 60).is_err());
    assert_eq!(
        Time::at_tick(1, 0).unwrap_err().code,
        ErrorCode::InvalidConfig
    );
}

#[test]
fn events_share_one_step_then_exactly_one_tick_completes_it() {
    let mut order = StepOrder::new(60).unwrap();
    assert_eq!(order.checkpoint_tick().unwrap(), 0);
    order.on_event(time(1)).unwrap();
    order.on_event(time(1)).unwrap();
    order.finish_tick(time(1)).unwrap();
    assert_eq!(order.checkpoint_tick().unwrap(), 1);
    // Empty-event steps still have a tick.
    order.finish_tick(time(2)).unwrap();
    assert_eq!(order.checkpoint_tick().unwrap(), 2);
    assert!(order.finish_tick(time(2)).is_err());
    assert!(
        order.finish_tick(time(3)).is_err(),
        "an ordering fault stays latched"
    );
}

#[test]
fn skipped_steps_wrong_elapsed_time_and_early_checkpoint_fault_the_instance() {
    let mut skipped = StepOrder::new(60).unwrap();
    assert!(skipped.on_event(time(2)).is_err());
    assert!(skipped.on_event(time(1)).is_err());
    let mut wrong = StepOrder::new(60).unwrap();
    assert!(wrong
        .on_event(Time {
            tick: 1,
            elapsed_us: 16_667
        })
        .is_err());
    let mut unfinished = StepOrder::new(60).unwrap();
    unfinished.on_event(time(1)).unwrap();
    assert!(unfinished.checkpoint_tick().is_err());
    assert!(unfinished.finish_tick(time(1)).is_err());
}

#[test]
fn restored_order_continues_at_the_next_tick_and_faults_are_terminal() {
    let mut order = StepOrder::after_tick(60, 179).unwrap();
    order.on_event(time(180)).unwrap();
    order.finish_tick(time(180)).unwrap();
    assert_eq!(order.checkpoint_tick().unwrap(), 180);
    order.fault();
    assert!(order.checkpoint_tick().is_err());
    assert!(order.on_event(time(181)).is_err());
    assert_eq!(
        StepOrder::after_tick(60, u64::MAX).unwrap_err().code,
        ErrorCode::InvalidCheckpoint
    );
    assert!(StepOrder::after_tick(60, u64::MAX / 2).is_err());
}

#[test]
fn runtime_identity_is_absent_or_exactly_32_bytes() {
    assert_eq!(identity_from_bytes(None).unwrap(), None);
    assert_eq!(identity_from_bytes(Some(&[7; 32])).unwrap(), Some([7; 32]));
    for len in [0, 1, 31, 33, 1024] {
        assert!(identity_from_bytes(Some(&vec![7; len])).is_err());
    }
}

#[test]
fn checkpoint_hash_has_the_specified_domain_and_hard_size_bound() {
    let digest = checkpoint_hash(b"canonical\0checkpoint").unwrap();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    // Independently calculated with a SHA-256 implementation outside this crate.
    assert_eq!(
        hex,
        "bbf3d49d870f61eb9fff7b2197c0e97c9e5c8f5919e873b9d3aadda3da9590a2"
    );
    assert_eq!(digest, checkpoint_hash(b"canonical\0checkpoint").unwrap());
    assert_ne!(digest, checkpoint_hash(b"canonical\0checkpoint!").unwrap());
    assert!(checkpoint_hash(&vec![0; MAX_CHECKPOINT_BYTES]).is_ok());
    assert!(checkpoint_hash(&vec![0; MAX_CHECKPOINT_BYTES + 1]).is_err());
    #[cfg(feature = "session")]
    assert_ne!(
        digest,
        fray_session::migration::state_hash(b"canonical\0checkpoint").unwrap()
    );
}

#[test]
fn every_command_target_is_checked_before_publication() {
    let present = |id: PlayerId| matches!(id.0, 7 | 12);
    let valid = vec![
        send(7, 1024),
        Command::Disconnect {
            player: PlayerId(12),
            reason: "left".into(),
        },
        send(12, 1),
        Command::SetOpen(false),
    ];
    validate_command_batch(&valid, present, limits()).unwrap();
    let invalid_tail = vec![send(7, 1), send(12, 1), send(99, 1)];
    assert!(validate_command_batch(&invalid_tail, present, limits()).is_err());
    assert!(validate_command_batch(
        &[Command::Disconnect {
            player: PlayerId(99),
            reason: String::new()
        }],
        present,
        limits()
    )
    .is_err());
    validate_command_batch(
        &[Command::Send {
            target: Target::Broadcast,
            delivery: Delivery::Lossy,
            bytes: vec![0; 1],
        }],
        |_| false,
        limits(),
    )
    .unwrap();
}

#[test]
fn smaller_configured_limits_and_existing_session_caps_win() {
    let mut cap = limits();
    cap.commands = 1;
    assert!(validate_command_batch(&[send(1, 1), send(1, 1)], |_| true, cap).is_err());
    cap.commands = usize::MAX;
    assert!(validate_command_batch(
        &vec![Command::SetOpen(true); MAX_COMMANDS + 1],
        |_| true,
        cap
    )
    .is_err());
    cap.message_bytes = 2;
    assert!(validate_command_batch(&[send(1, 3)], |_| true, cap).is_err());
    cap.message_bytes = usize::MAX;
    assert!(validate_command_batch(&[send(1, 1025)], |_| true, cap).is_err());
    cap.batch_bytes = 3;
    assert!(validate_command_batch(&[send(1, 2), send(1, 2)], |_| true, cap).is_err());
    cap.reason_bytes = 2;
    assert!(validate_command_batch(
        &[Command::Disconnect {
            player: PlayerId(1),
            reason: "too long".into()
        }],
        |_| true,
        cap
    )
    .is_err());
    // UTF-8 byte counts, including reasons, contribute to the cumulative bound.
    cap.reason_bytes = 4;
    cap.batch_bytes = 3;
    assert!(validate_command_batch(
        &[
            send(1, 1),
            Command::Disconnect {
                player: PlayerId(1),
                reason: "éé".into()
            }
        ],
        |_| true,
        cap
    )
    .is_err());
}

#[test]
fn errors_keep_the_contract_code() {
    let error = AuthorityError::new(ErrorCode::UnsupportedVersion, "checkpoint schema");
    assert_eq!(error.code, ErrorCode::UnsupportedVersion);
    assert!(error.to_string().contains("checkpoint schema"));
}

#[test]
fn pure_image_helpers_keep_the_existing_domain_and_numeric_bounds() {
    use fray_session::checkpoint::{bounded_vec, state_hash, validate_finite, Error};
    let image_hash = state_hash(b"canonical\0checkpoint").unwrap();
    let hex: String = image_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex,
        "320946aa607a40ad26f47a6ef87f89245b443762ce375ae381a194b33bccac0c"
    );
    assert_ne!(
        image_hash,
        checkpoint_hash(b"canonical\0checkpoint").unwrap()
    );
    validate_finite(&(Some(vec![1.0f64, -2.0]), [0.0f32, 3.0])).unwrap();
    assert_eq!(
        validate_finite(&[f64::NAN]),
        Err(Error::Invalid("nonfinite checkpoint number"))
    );
    assert!(validate_finite(&(vec![Some(f32::INFINITY)],)).is_err());
    let values = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(0u8..3);
    assert!(bounded_vec::<_, u8, 2>(values).is_err());
    let values = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(0u8..2);
    assert_eq!(bounded_vec::<_, u8, 2>(values).unwrap(), vec![0, 1]);
    assert!(state_hash(&vec![0; MAX_CHECKPOINT_BYTES + 1]).is_err());
    #[cfg(feature = "session")]
    {
        let error: fray_session::migration::Error = Error::Bounds;
        assert_eq!(error, fray_session::migration::Error::Bounds);
        assert_eq!(
            image_hash,
            fray_session::migration::state_hash(b"canonical\0checkpoint").unwrap()
        );
    }
}

#[cfg(feature = "session")]
#[test]
fn authority_limits_retain_the_existing_session_ceilings() {
    assert_eq!(MAX_CHECKPOINT_BYTES, fray_session::migration::MAX_IMAGE);
    assert_eq!(MAX_COMMANDS, fray_session::migration::MAX_BATCH);
}
