use fray_net::migration::*;
use fray_net::Keys;

fn pair() -> (Context, Keys) {
    let host = Keys::generate();
    let standby = Keys::generate();
    (
        Context {
            session: [17; 16],
            descriptor: [29; 32],
            host: host.public_key().to_bytes(),
            standby: standby.public_key().to_bytes(),
        },
        standby,
    )
}
fn marks(input: u64, ack: u64) -> Vec<Watermark> {
    vec![Watermark {
        player: 1,
        input,
        output_ack: ack,
        retired: false,
    }]
}
fn output(sequence: u64) -> Output {
    Output {
        recipient: 1,
        delivery: Delivery::Reliable,
        sequence,
        bytes: vec![sequence as u8; 4],
    }
}
fn armed() -> (Sequencer, Keys) {
    let (context, signer) = pair();
    (
        Sequencer::arm(context, vec![0], 0, marks(0, 0), &signer).unwrap(),
        signer,
    )
}

#[test]
fn closed_epoch_discards_previously_validated_candidate() {
    let (mut standby, key) = armed();
    let candidate = standby
        .next(vec![1], 50, marks(1, 0), vec![output(1)])
        .unwrap();
    let staged = standby.stage(candidate).unwrap();
    let promotion = standby.promote(&key).unwrap();
    promotion.verify(standby.context()).unwrap();
    assert_eq!(standby.install(staged, &key), Err(Error::Closed));
    assert_eq!(standby.receipt().index, 0);
    assert_eq!(standby.image(), &[0]);
    assert_eq!(standby.outbox().count(), 0);
}

#[test]
fn installed_state_and_outbox_survive_receipt_loss_and_promotion() {
    let (mut standby, key) = armed();
    let candidate = standby
        .next(vec![1, 2, 3], 50, marks(1, 0), vec![output(1)])
        .unwrap();
    let staged = standby.stage(candidate).unwrap();
    let receipt = standby.install(staged, &key).unwrap();
    // Simulate the primary dying before it receives this receipt.
    let promotion = standby.promote(&key).unwrap();
    assert_eq!(promotion.final_receipt, receipt);
    assert_eq!(standby.image(), &[1, 2, 3]);
    let pending = standby.outbox().next().unwrap();
    pending.verify(standby.context()).unwrap();
    let bytes = pending.encode(standby.context()).unwrap();
    assert_eq!(
        CertifiedOutput::decode(standby.context(), &bytes).unwrap(),
        *pending
    );
    assert_eq!(standby.promote(&key).unwrap(), promotion);
    let next = standby
        .next(vec![4], 50, marks(2, 0), vec![output(2)])
        .unwrap();
    assert_eq!(next.term, 1);
    let staged = standby.stage(next).unwrap();
    let installed = standby.install(staged, &key).unwrap();
    assert_eq!(installed.index, 2);
    assert_eq!(installed.parent, receipt.digest(standby.context()).unwrap());
    assert_eq!(standby.outbox().count(), 2);
}

#[test]
fn stale_validation_cannot_overwrite_a_newer_installed_base() {
    let (mut standby, key) = armed();
    let candidate = standby
        .next(vec![1], 50, marks(1, 0), vec![output(1)])
        .unwrap();
    let first = standby.stage(candidate.clone()).unwrap();
    let duplicate = standby.stage(candidate).unwrap();
    standby.install(first, &key).unwrap();
    assert_eq!(
        standby.install(duplicate, &key).unwrap(),
        *standby.receipt()
    );
    assert_eq!(standby.outbox().count(), 1);
}

#[test]
fn acknowledgements_and_retirement_prune_only_on_install() {
    let (mut standby, key) = armed();
    let first = standby
        .next(vec![1], 50, marks(1, 0), vec![output(1)])
        .unwrap();
    let staged = standby.stage(first).unwrap();
    standby.install(staged, &key).unwrap();
    let ack = standby.next(vec![2], 50, marks(1, 1), vec![]).unwrap();
    let staged = standby.stage(ack).unwrap();
    assert_eq!(standby.outbox().count(), 1);
    standby.install(staged, &key).unwrap();
    assert_eq!(standby.outbox().count(), 0);
    let second = standby
        .next(vec![3], 50, marks(2, 1), vec![output(2)])
        .unwrap();
    let staged = standby.stage(second).unwrap();
    standby.install(staged, &key).unwrap();
    let mut retired = marks(2, 1);
    retired[0].retired = true;
    let leave = standby.next(vec![4], 50, retired, vec![]).unwrap();
    let staged = standby.stage(leave).unwrap();
    standby.install(staged, &key).unwrap();
    assert_eq!(standby.outbox().count(), 0);
    let revive = standby.next(vec![5], 50, marks(2, 1), vec![]).unwrap();
    assert!(standby.stage(revive).is_err());
}

#[test]
fn bad_recipient_sequences_acks_and_wrong_signer_do_not_mutate_state() {
    let (mut standby, key) = armed();
    let mut bad = standby
        .next(vec![1], 50, marks(1, 1), vec![output(1)])
        .unwrap();
    assert!(
        standby.stage(bad.clone()).is_err(),
        "cannot ACK speculative output"
    );
    bad.watermarks = marks(1, 0);
    bad.outputs[0].sequence = 2;
    assert!(standby.stage(bad.clone()).is_err());
    bad.outputs[0] = output(1);
    bad.outputs[0].recipient = 2;
    assert!(standby.stage(bad.clone()).is_err());
    bad.outputs[0] = output(1);
    let staged = standby.stage(bad).unwrap();
    assert_eq!(
        standby.install(staged, &Keys::generate()),
        Err(Error::Unauthorized)
    );
    assert_eq!(standby.image(), &[0]);
    assert_eq!(standby.receipt().index, 0);
    assert_eq!(standby.promote(&Keys::generate()), Err(Error::Unauthorized));
    assert_eq!(standby.promote(&key).unwrap().final_receipt.index, 0);
}

#[test]
fn merkle_proofs_bind_every_output_field_and_session() {
    for count in [1, 2, 3, 7, 64, 256] {
        let (context, key) = pair();
        let mut standby = Sequencer::arm(context.clone(), vec![], 0, marks(0, 0), &key).unwrap();
        let outputs = (1..=count).map(output).collect();
        let candidate = standby.next(vec![5], 50, marks(1, 0), outputs).unwrap();
        let staged = standby.stage(candidate).unwrap();
        standby.install(staged, &key).unwrap();
        for certified in standby.outbox() {
            certified.verify(&context).unwrap();
            let mut changed = certified.clone();
            changed.output.bytes[0] ^= 1;
            assert!(changed.verify(&context).is_err());
            let mut changed = certified.clone();
            changed.output.sequence += 1;
            assert!(changed.verify(&context).is_err());
            let mut changed = certified.clone();
            changed.ordinal = certified.receipt.outputs_count;
            assert!(changed.verify(&context).is_err());
            let mut other = context.clone();
            other.session[0] ^= 1;
            assert!(certified.verify(&other).is_err());
        }
    }
}

#[test]
fn receipt_codec_is_canonical_and_rejects_truncation_tampering_and_trailing_bytes() {
    let (standby, _) = armed();
    let original = standby.receipt().encode(standby.context()).unwrap();
    assert_eq!(
        Receipt::decode(standby.context(), &original).unwrap(),
        *standby.receipt()
    );
    for len in 0..original.len() {
        assert!(Receipt::decode(standby.context(), &original[..len]).is_err());
    }
    for at in 0..original.len() {
        let mut bad = original.clone();
        bad[at] ^= 1;
        assert!(
            Receipt::decode(standby.context(), &bad).is_err(),
            "byte {at}"
        );
    }
    let mut extra = original;
    extra.push(0);
    assert!(Receipt::decode(standby.context(), &extra).is_err());
}

#[test]
fn bounded_patch_roundtrips_and_rejects_wrong_base_corrupt_target_and_overflow() {
    let inputs: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"abc",
        b"abcXdef",
        b"abcYdef",
        b"123456789",
    ];
    for base in inputs {
        for target in inputs {
            let patch = Patch::between(base, target).unwrap();
            assert_eq!(patch.apply(base).unwrap(), *target);
            let mut bad = patch.clone();
            bad.target[0] ^= 1;
            assert!(bad.apply(base).is_err());
            let mut bad = patch.clone();
            bad.remove = u32::MAX;
            assert!(bad.apply(base).is_err());
        }
    }
    assert!(Patch::between(&[], &vec![1; MAX_PATCH + 1]).is_err());
    assert!(state_hash(&vec![0; MAX_IMAGE + 1]).is_err());
}

#[test]
fn partial_mixed_conflicting_and_oversized_transfers_never_replace_committed_state() {
    let bytes = vec![7; CHUNK_PAYLOAD * 2 + 3];
    let digest = state_hash(&bytes).unwrap();
    assert!(Transfer::begin([1; 16], 0, 1, MAX_IMAGE + 1, 1, digest).is_err());
    assert!(Transfer::begin([1; 16], 0, 1, bytes.len(), usize::MAX, digest).is_err());
    let mut transfer = Transfer::begin([1; 16], 0, 1, bytes.len(), 3, digest).unwrap();
    assert!(transfer
        .chunk([2; 16], 0, 1, 0, &bytes[..CHUNK_PAYLOAD])
        .is_err());
    assert!(transfer
        .chunk([1; 16], 1, 1, 0, &bytes[..CHUNK_PAYLOAD])
        .is_err());
    assert!(transfer
        .chunk([1; 16], 0, 2, 0, &bytes[..CHUNK_PAYLOAD])
        .is_err());
    transfer
        .chunk([1; 16], 0, 1, 0, &bytes[..CHUNK_PAYLOAD])
        .unwrap();
    transfer
        .chunk([1; 16], 0, 1, 0, &bytes[..CHUNK_PAYLOAD])
        .unwrap();
    assert_eq!(
        transfer.chunk([1; 16], 0, 1, 0, &vec![8; CHUNK_PAYLOAD]),
        Err(Error::Conflict)
    );
    assert_eq!(transfer.finish(), Err(Error::Gap));
    let mut transfer = Transfer::begin([1; 16], 0, 1, bytes.len(), 3, digest).unwrap();
    for (i, chunk) in bytes.chunks(CHUNK_PAYLOAD).enumerate().rev() {
        transfer.chunk([1; 16], 0, 1, i, chunk).unwrap();
    }
    assert_eq!(transfer.finish().unwrap(), bytes);
}

#[test]
fn intent_capacity_is_atomic_and_only_committed_watermarks_release_it() {
    let mut journal = IntentJournal::default();
    let full = vec![vec![7; 512]; MAX_JOURNAL_RECORDS];
    assert_eq!(
        journal.append_batch(&full).unwrap().len(),
        MAX_JOURNAL_RECORDS
    );
    assert!(!journal.can_reserve(1, 1));
    let tail = journal.tail();
    assert_eq!(journal.append_batch(&[vec![8]]), Err(Error::Bounds));
    assert_eq!(journal.tail(), tail);
    assert_eq!(journal.pending().count(), MAX_JOURNAL_RECORDS);
    assert!(journal.acknowledge(tail + 1).is_err());
    journal.acknowledge(100).unwrap();
    assert_eq!(journal.pending().next().unwrap().0, 101);
    assert_eq!(journal.append_batch(&[vec![8]]).unwrap(), vec![tail + 1]);
    assert!(journal.acknowledge(99).is_err());
}

#[test]
fn applied_output_survives_reconnect_and_lost_ack_without_reapplying() {
    let mut journal = DeliveryJournal::default();
    let mut applied = 0;
    assert!(journal.apply(2, b"second", |_| Ok(())).is_err());
    assert!(journal
        .apply(1, b"ball enter", |_| {
            applied += 1;
            Ok(())
        })
        .unwrap());
    assert!(!journal
        .apply(1, b"ball enter", |_| {
            applied += 1;
            Ok(())
        })
        .unwrap());
    assert_eq!(applied, 1);
    assert_eq!(
        journal.apply(1, b"different", |_| Ok(())),
        Err(Error::Conflict)
    );
    assert!(journal
        .apply(2, b"next", |_| Err(Error::Invalid("application failure")))
        .is_err());
    assert_eq!(journal.applied(), 1);
    assert_eq!(journal.apply(2, b"next", |_| Ok(())), Err(Error::Closed));
}

#[test]
fn identical_candidate_retry_returns_the_original_receipt_after_ack_loss() {
    let (mut standby, key) = armed();
    let candidate = standby
        .next(vec![1], 50, marks(1, 0), vec![output(1)])
        .unwrap();
    let staged = standby.stage(candidate.clone()).unwrap();
    let original = standby.install(staged, &key).unwrap();
    let retry = standby.stage(candidate.clone()).unwrap();
    assert_eq!(standby.install(retry, &key).unwrap(), original);
    assert_eq!(standby.outbox().count(), 1);
    let mut conflicting = candidate.clone();
    conflicting.image.push(9);
    assert!(standby.stage(conflicting).is_err());
    standby.promote(&key).unwrap();
    let retry = standby.stage(candidate).unwrap();
    assert_eq!(standby.install(retry, &key).unwrap(), original);
    assert_eq!(
        standby.next(vec![2], 50, marks(2, 0), vec![]).unwrap().term,
        1
    );
}

#[test]
fn committed_lossy_views_have_proofs_but_do_not_fill_the_reliable_outbox() {
    let (mut standby, key) = armed();
    let mut lossy = output(1);
    lossy.delivery = Delivery::Lossy;
    let candidate = standby.next(vec![1], 50, marks(0, 0), vec![lossy]).unwrap();
    let staged = standby.stage(candidate).unwrap();
    standby.install(staged, &key).unwrap();
    assert_eq!(standby.outbox().count(), 0);
    assert_eq!(standby.publication().len(), 1);
    let proof = &standby.publication()[0];
    proof
        .verify_for(standby.context(), 1, Delivery::Lossy)
        .unwrap();
    assert_eq!(
        proof.verify_for(standby.context(), 2, Delivery::Lossy),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        proof.verify_for(standby.context(), 1, Delivery::Reliable),
        Err(Error::Unauthorized)
    );
}

#[test]
fn effect_panic_poisoning_prevents_duplicate_partially_applied_work() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let mut journal = DeliveryJournal::default();
    let mut mutations = 0;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = journal.apply(1, b"ball", |_| {
            mutations += 1;
            panic!("fault after mutation");
        });
    }));
    assert!(result.is_err());
    assert_eq!(
        journal.apply(1, b"ball", |_| {
            mutations += 1;
            Ok(())
        }),
        Err(Error::Closed)
    );
    assert_eq!(mutations, 1);
}

#[test]
fn replacing_players_does_not_exhaust_the_eight_concurrent_seats() {
    let (context, key) = pair();
    let mut standby = Sequencer::arm(context, vec![], 0, vec![], &key).unwrap();
    for player in 1..=16 {
        let mark = Watermark {
            player,
            input: 0,
            output_ack: 0,
            retired: false,
        };
        let next = standby
            .next(vec![player as u8], 0, vec![mark.clone()], vec![])
            .unwrap();
        let staged = standby.stage(next).unwrap();
        standby.install(staged, &key).unwrap();
        let mut retired = mark;
        retired.retired = true;
        let next = standby
            .next(vec![player as u8], 0, vec![retired], vec![])
            .unwrap();
        let staged = standby.stage(next).unwrap();
        standby.install(staged, &key).unwrap();
    }
    let resurrection = standby
        .next(
            vec![],
            0,
            vec![Watermark {
                player: 1,
                input: 0,
                output_ack: 0,
                retired: false,
            }],
            vec![],
        )
        .unwrap();
    assert!(standby.stage(resurrection).is_err());
}

#[test]
fn arming_rejects_a_state_without_room_for_its_own_metadata() {
    let (context, key) = pair();
    assert!(matches!(
        Sequencer::arm(context, vec![0; MAX_IMAGE], 0, marks(0, 0), &key),
        Err(Error::Bounds)
    ));
}

#[test]
fn late_resource_failure_is_atomic_and_does_not_consume_output_ids() {
    let (mut standby, key) = armed();
    let mut batch: Vec<_> = (1..=256).map(output).collect();
    for o in &mut batch {
        o.bytes = vec![0; 1024];
    }
    let first = standby.next(vec![1], 50, marks(1, 0), batch).unwrap();
    let staged = standby.stage(first).unwrap();
    standby.install(staged, &key).unwrap();
    let before = standby.receipt().clone();
    let bad = standby
        .next(vec![2], 100, marks(2, 0), vec![output(257)])
        .unwrap();
    let staged = standby.stage(bad).unwrap();
    assert_eq!(standby.install(staged, &key), Err(Error::Bounds));
    assert_eq!(standby.receipt(), &before);
    assert_eq!(standby.image(), &[1]);
    assert_eq!(standby.outbox().count(), 256);
    assert_eq!(standby.publication().len(), 256);
    let valid = standby
        .next(vec![2], 100, marks(2, 1), vec![output(257)])
        .unwrap();
    let staged = standby.stage(valid).unwrap();
    standby.install(staged, &key).unwrap();
    assert_eq!(standby.receipt().index, before.index + 1);
}

#[test]
fn candidate_codec_and_fragmented_transport_roundtrip_without_oversized_frames() {
    let (standby, _) = armed();
    let candidate = standby
        .next(
            vec![11; CHUNK_PAYLOAD * 3 + 5],
            50,
            marks(1, 0),
            vec![output(1)],
        )
        .unwrap();
    let bytes = candidate.encode(standby.context()).unwrap();
    let decoded = Candidate::decode(standby.context(), &bytes).unwrap();
    assert_eq!(decoded.image, candidate.image);
    let frames = Frame::split(
        standby.context().session,
        0,
        1,
        PacketKind::Candidate,
        &bytes,
    )
    .unwrap();
    let mut receiver = PacketReceiver::new(standby.context().session, 0).unwrap();
    let mut restored = None;
    for frame in frames.iter().rev() {
        let wire = frame.encode().unwrap();
        assert!(wire.len() <= 1024);
        assert_eq!(Frame::decode(&wire).unwrap(), *frame);
        if let Some((kind, id, payload)) = receiver.receive(&wire, 1).unwrap() {
            assert_eq!(kind, PacketKind::Candidate);
            assert_eq!(id, 1);
            restored = Some(payload);
        }
    }
    assert_eq!(restored.unwrap(), bytes);
    for frame in &frames {
        assert!(receiver
            .receive(&frame.encode().unwrap(), 2)
            .unwrap()
            .is_none());
    }
    let conflict = Frame::split(
        standby.context().session,
        0,
        1,
        PacketKind::Candidate,
        b"different",
    )
    .unwrap();
    assert_eq!(
        receiver.receive(&conflict[0].encode().unwrap(), 3),
        Err(Error::Conflict)
    );
}

#[test]
fn fragment_headers_timeouts_term_changes_and_pressure_are_bounded() {
    let (context, _) = pair();
    let frames = Frame::split(
        context.session,
        0,
        1,
        PacketKind::Control,
        &vec![1; CHUNK_PAYLOAD + 1],
    )
    .unwrap();
    let mut receiver = PacketReceiver::new(context.session, 0).unwrap();
    let wire = frames[0].encode().unwrap();
    for len in 0..wire.len() {
        assert!(Frame::decode(&wire[..len]).is_err());
    }
    assert!(receiver.receive(&wire, 10).unwrap().is_none());
    assert_eq!(receiver.expire(510), Err(Error::Stale));
    assert!(receiver.receive(&wire, 511).unwrap().is_none());
    receiver.advance_term(1).unwrap();
    assert!(receiver.receive(&wire, 512).is_err());
    assert!(receiver.advance_term(0).is_err());
    assert!(receiver.advance_term(2).is_err());
    let mut receiver = PacketReceiver::new(context.session, 0).unwrap();
    for id in 1..=8 {
        let f = Frame::split(
            context.session,
            0,
            id,
            PacketKind::Candidate,
            &vec![1; CHUNK_PAYLOAD + 1],
        )
        .unwrap();
        assert!(receiver
            .receive(&f[0].encode().unwrap(), 0)
            .unwrap()
            .is_none());
    }
    let ninth = Frame::split(context.session, 0, 9, PacketKind::Candidate, b"next").unwrap();
    assert_eq!(
        receiver.receive(&ninth[0].encode().unwrap(), 0),
        Err(Error::Bounds)
    );
}

#[test]
fn primary_cannot_publish_speculative_state_or_use_an_unrelated_receipt() {
    let (mut standby, key) = armed();
    let mut primary = Primary::armed(
        standby.context().clone(),
        standby.image().to_vec(),
        standby.receipt().clone(),
    )
    .unwrap();
    let candidate = primary
        .prepare(vec![8], 50, marks(1, 0), vec![output(1)])
        .unwrap()
        .clone();
    assert_eq!(primary.committed_image(), &[0]);
    assert!(primary.prepare(vec![9], 60, marks(2, 0), vec![]).is_err());
    let mut conflicting = candidate.clone();
    conflicting.image = vec![9];
    let staged = standby.stage(conflicting).unwrap();
    let receipt = standby.install(staged, &key).unwrap();
    assert_eq!(primary.acknowledge(receipt), Err(Error::Conflict));
    assert_eq!(primary.committed_image(), &[0]);
    assert!(primary.pending().is_some());
}

#[test]
fn primary_releases_once_after_commit_and_closes_on_lost_ack_promotion() {
    let (mut standby, key) = armed();
    let mut primary = Primary::armed(
        standby.context().clone(),
        standby.image().to_vec(),
        standby.receipt().clone(),
    )
    .unwrap();
    let candidate = primary
        .prepare(vec![8], 50, marks(1, 0), vec![output(1)])
        .unwrap()
        .clone();
    let staged = standby.stage(candidate).unwrap();
    let receipt = standby.install(staged, &key).unwrap();
    let outputs = primary.acknowledge(receipt.clone()).unwrap();
    assert_eq!(outputs.len(), 1);
    outputs[0]
        .verify_for(standby.context(), 1, Delivery::Reliable)
        .unwrap();
    assert!(primary.acknowledge(receipt).unwrap().is_empty());
    let next = primary
        .prepare(vec![9], 100, marks(2, 0), vec![output(2)])
        .unwrap()
        .clone();
    let staged = standby.stage(next).unwrap();
    standby.install(staged, &key).unwrap();
    let promotion = standby.promote(&key).unwrap();
    primary.close(&promotion).unwrap();
    assert_eq!(primary.committed_image(), &[9]);
    assert!(primary.prepare(vec![], 100, marks(2, 0), vec![]).is_err());
    assert!(primary.acknowledge(standby.receipt().clone()).is_err());
}

#[test]
fn primary_reconnect_outbox_matches_installed_proofs_and_prunes_only_committed_acks() {
    let (mut standby, key) = armed();
    let mut primary = Primary::armed(
        standby.context().clone(),
        standby.image().to_vec(),
        standby.receipt().clone(),
    )
    .unwrap();
    for number in 1..=2 {
        let candidate = primary
            .prepare(
                vec![number as u8],
                number * 10,
                marks(number, 0),
                vec![output(number)],
            )
            .unwrap()
            .clone();
        assert_eq!(primary.outbox().count(), (number - 1) as usize);
        let staged = standby.stage(candidate).unwrap();
        let receipt = standby.install(staged, &key).unwrap();
        // Installation at the standby cannot expose effects at the primary.
        assert_eq!(primary.outbox().count(), (number - 1) as usize);
        primary.acknowledge(receipt.clone()).unwrap();
        assert_eq!(
            primary.outbox().collect::<Vec<_>>(),
            standby.outbox().collect::<Vec<_>>()
        );
        assert!(primary.acknowledge(receipt).unwrap().is_empty());
        assert_eq!(primary.outbox().count(), number as usize);
    }
    let retained = primary.outbox().cloned().collect::<Vec<_>>();
    let candidate = primary
        .prepare(vec![3], 30, marks(2, 1), vec![])
        .unwrap()
        .clone();
    assert_eq!(primary.outbox().cloned().collect::<Vec<_>>(), retained);
    let staged = standby.stage(candidate).unwrap();
    let receipt = standby.install(staged, &key).unwrap();
    assert_eq!(primary.outbox().cloned().collect::<Vec<_>>(), retained);
    primary.acknowledge(receipt).unwrap();
    assert_eq!(primary.outbox().cloned().collect::<Vec<_>>(), retained[1..]);
    // A replacement transport sends the original signed proof, not a new output.
    let mut delivery = DeliveryJournal::default();
    delivery
        .apply_certified(standby.context(), 1, &retained[0], |_| Ok(()))
        .unwrap();
    let replay = primary.outbox().next().unwrap();
    assert_eq!(replay, &retained[1]);
    assert!(delivery
        .apply_certified(standby.context(), 1, replay, |_| Ok(()))
        .unwrap());
    assert!(!delivery
        .apply_certified(standby.context(), 1, replay, |_| Ok(()))
        .unwrap());
    let mut retired = marks(2, 1);
    retired[0].retired = true;
    let candidate = primary
        .prepare(vec![4], 40, retired, vec![])
        .unwrap()
        .clone();
    let staged = standby.stage(candidate).unwrap();
    let receipt = standby.install(staged, &key).unwrap();
    assert_eq!(primary.outbox().count(), 1);
    primary.acknowledge(receipt).unwrap();
    assert_eq!(primary.outbox().count(), 0);
    assert_eq!(primary.outbox().count(), standby.outbox().count());
}

#[test]
fn byte_patches_preserve_shifted_vectors_and_distant_changed_regions_exactly() {
    for seed in 1u64..=24 {
        let mut random = seed;
        let base = (0..128 * 1024)
            .map(|_| {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                (random >> 32) as u8
            })
            .collect::<Vec<_>>();
        let mut target = base.clone();
        for edit in 0..12 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let offset = (random as usize) % (target.len() - 64);
            target.splice(
                offset..offset + edit % 7,
                (0..edit % 17 + 1).map(|n| (seed + n as u64) as u8),
            );
        }
        target[0] ^= 1;
        let last = target.len() - 1;
        target[last] ^= 1;
        let patch = BytePatch::between(&base, &target).unwrap();
        let bytes = patch.encode().unwrap();
        assert!(
            bytes.len() < 4096,
            "small distant edits copied a whole image"
        );
        assert_eq!(
            BytePatch::between(&base, &target)
                .unwrap()
                .encode()
                .unwrap(),
            bytes
        );
        assert_eq!(BytePatch::decode(&bytes).unwrap(), patch);
        assert_eq!(patch.apply(&base).unwrap(), target);
        assert!(patch.apply(&target).is_err());
        for end in [0, 1, 5, 37, 69, 73, 76, bytes.len() - 1] {
            assert!(BytePatch::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(BytePatch::decode(&trailing).is_err());
    }
}

#[test]
fn byte_patch_budget_includes_header_operations_and_exact_literal_boundary() {
    for (base, target) in [
        (vec![], vec![]),
        (vec![3; 64], vec![]),
        (vec![], vec![3; 17]),
        (vec![4; MAX_IMAGE], vec![4; MAX_IMAGE]),
    ] {
        let patch = BytePatch::between(&base, &target).unwrap();
        assert_eq!(
            BytePatch::decode(&patch.encode().unwrap())
                .unwrap()
                .apply(&base)
                .unwrap(),
            target
        );
    }
    let literal = vec![3; MAX_PATCH - 82];
    let patch = BytePatch::between(&[], &literal).unwrap();
    assert_eq!(patch.encoded_len().unwrap(), MAX_PATCH);
    assert_eq!(patch.encode().unwrap().len(), MAX_PATCH);
    assert_eq!(patch.apply(&[]).unwrap(), literal);
    assert_eq!(
        BytePatch::between(&[], &vec![3; MAX_PATCH - 81]),
        Err(Error::Bounds)
    );
    assert_eq!(
        BytePatch::between(&vec![0; MAX_IMAGE + 1], &[]),
        Err(Error::Bounds)
    );
    assert_eq!(
        BytePatch::between(&[], &vec![0; MAX_IMAGE + 1]),
        Err(Error::Bounds)
    );
}

#[test]
fn byte_patch_decode_rejects_allocation_bombs_bad_ranges_versions_and_target_hashes() {
    let base = vec![7; 32];
    let wire = BytePatch::between(&base, &base).unwrap().encode().unwrap();
    assert_eq!(wire.len(), 86);
    for range in [69..73, 73..77, 78..82, 82..86] {
        let mut altered = wire.clone();
        altered[range].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(BytePatch::decode(&altered).is_err());
    }
    for (index, value) in [(0, 0), (4, 2), (77, 255)] {
        let mut altered = wire.clone();
        altered[index] = value;
        assert!(BytePatch::decode(&altered).is_err());
    }
    let mut outside = wire.clone();
    outside[78..82].copy_from_slice(&32u32.to_be_bytes());
    assert_eq!(
        BytePatch::decode(&outside).unwrap().apply(&base),
        Err(Error::Bounds)
    );
    let mut wrong_target = wire;
    wrong_target[37] ^= 1;
    assert!(BytePatch::decode(&wrong_target)
        .unwrap()
        .apply(&base)
        .is_err());
}

#[test]
fn pacing_bounds_burst_and_shared_rate_while_prioritizing_control() {
    let frames = Frame::split([1; 16], 0, 1, PacketKind::Candidate, &vec![0; 256 * 1024]).unwrap();
    let mut queue = SendQueue::default();
    queue.enqueue(frames).unwrap();
    let ctrl = Frame::split([1; 16], 0, 2, PacketKind::Control, b"promotion").unwrap();
    queue.enqueue(ctrl).unwrap();
    let first = Frame::decode(&queue.poll(0).unwrap().unwrap()).unwrap();
    assert_eq!(first.kind, PacketKind::Control);
    let mut sent = first.encode().unwrap().len();
    while let Some(bytes) = queue.poll(0).unwrap() {
        sent += bytes.len();
    }
    assert!(sent <= 64 * 1024);
    assert!(queue.queued_bytes() > 0);
    let before = queue.queued_bytes();
    let mut second = 0;
    while let Some(bytes) = queue.poll(1).unwrap() {
        second += bytes.len();
    }
    // Unused burst credit carries into the next millisecond. Bound cumulative
    // traffic, including that credit, rather than only the second poll group.
    assert!(sent + second <= 64 * 1024 + (4 * 1024 * 1024 / 1000));
    assert!(second > 0);
    assert_eq!(before - queue.queued_bytes(), second);
    assert!(queue.poll(0).is_err());
    queue.retain_term(1);
    assert_eq!(queue.queued_bytes(), 0);
}

#[test]
fn queue_limit_rejection_keeps_the_accepted_message_intact() {
    let mut queue = SendQueue::default();
    let first = Frame::split(
        [1; 16],
        0,
        1,
        PacketKind::Candidate,
        &vec![0; MAX_IMAGE - 1024],
    )
    .unwrap();
    queue.enqueue(first).unwrap();
    let accepted = queue.queued_bytes();
    let second = Frame::split(
        [1; 16],
        0,
        2,
        PacketKind::Candidate,
        &vec![0; MAX_IMAGE - 1024],
    )
    .unwrap();
    assert_eq!(queue.enqueue(second), Err(Error::Bounds));
    assert_eq!(queue.queued_bytes(), accepted);
    let mut total = 0;
    for tick in 0..2000 {
        while let Some(bytes) = queue.poll(tick).unwrap() {
            total += bytes.len();
        }
        if queue.queued_bytes() == 0 {
            break;
        }
    }
    assert_eq!(total, accepted);
    assert_eq!(queue.queued_bytes(), 0);
}

#[test]
fn survivor_routes_preserve_logical_security_state_without_a_missing_host_connection() {
    let mut routes = PeerBindings::new([
        (1, 10, false),
        (2, 11, false),
        (3, 12, false),
        (4, 0x8000_0001, true),
    ])
    .unwrap();
    // Host player1 is absent. Player2 receives its former physical number10;
    // the retained logical game ID and associated strike history remain11.
    routes.bind_survivors(&[(2, 10), (3, 11)]).unwrap();
    assert_eq!(routes.incoming(10), Some((2, 11)));
    assert_eq!(routes.outgoing(11), Some(10));
    assert_eq!(routes.outgoing(10), None);
    assert_eq!(routes.logical(1), Some(10));
    assert_eq!(routes.logical(4), Some(0x8000_0001));
    assert_eq!(routes.outgoing(0x8000_0001), None);
    let old = routes.clone();
    assert!(routes.bind_survivors(&[(2, 10), (3, 10)]).is_err());
    assert_eq!(routes, old);
    assert!(routes.bind_survivors(&[(4, 10)]).is_err());
    assert_eq!(routes, old);
    assert!(routes.bind_survivors(&[(999, 10)]).is_err());
    assert_eq!(routes, old);
    routes.bind_survivors(&[(3, 10), (2, 11)]).unwrap();
    assert_eq!(routes.incoming(10), Some((3, 12)));
    assert_eq!(routes.incoming(11), Some((2, 11)));
}

#[test]
fn checkpoint_number_audit_rejects_nested_nonfinite_values_and_accepts_option_sentinels() {
    #[derive(serde::Serialize)]
    struct Nested {
        values: Vec<Option<f64>>,
    }
    assert!(validate_finite(&Nested {
        values: vec![None, Some(1.0)]
    })
    .is_ok());
    for bad in [f64::NAN, f64::NEG_INFINITY, f64::INFINITY] {
        assert!(validate_finite(&Nested {
            values: vec![None, Some(bad)]
        })
        .is_err());
    }
}

fn descriptor_fixture() -> (Descriptor, Keys, Keys, Keys) {
    let host = Keys::generate();
    let standby = Keys::generate();
    let player = Keys::generate();
    let root = Root {
        session: fresh_session().unwrap(),
        app: "migration-test".into(),
        transport_version: 7,
        game_version: 13,
        checkpoint_version: 1,
        host: host.public_key().to_bytes(),
        standby: standby.public_key().to_bytes(),
        controller: host.public_key().to_bytes(),
        code: room_code_hash("ABCDEF").unwrap(),
        created_day: 20741,
        roster_revision: 1,
        members: vec![
            Member {
                player: 1,
                seat: 0,
                key: Some(host.public_key().to_bytes()),
            },
            Member {
                player: 2,
                seat: 1,
                key: Some(player.public_key().to_bytes()),
            },
            Member {
                player: 3,
                seat: 2,
                key: None,
            },
        ],
        config: [11; 32],
        content: [12; 32],
        limits: ResourceLimits::default(),
    };
    (
        Descriptor::offer(root, &host).unwrap(),
        host,
        standby,
        player,
    )
}
#[test]
fn root_descriptor_requires_exact_pair_consent_and_binds_every_policy_field() {
    let (mut descriptor, host, standby, _) = descriptor_fixture();
    assert!(descriptor.verify().is_err());
    assert!(Descriptor::decode(&descriptor.encode().unwrap())
        .unwrap()
        .verify()
        .is_err());
    let outsider = Keys::generate();
    assert!(descriptor.consent(&outsider).is_err());
    descriptor.consent(&standby).unwrap();
    descriptor.verify().unwrap();
    let encoded = descriptor.encode().unwrap();
    assert_eq!(Descriptor::decode(&encoded).unwrap(), descriptor);
    for cut in [0, 1, 100, encoded.len() - 1] {
        assert!(Descriptor::decode(&encoded[..cut]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Descriptor::decode(&trailing).is_err());
    for field in 0..11 {
        let mut changed = descriptor.clone();
        match field {
            0 => changed.root.session[0] ^= 1,
            1 => changed.root.controller = outsider.public_key().to_bytes(),
            2 => changed.root.code[0] ^= 1,
            3 => changed.root.config[0] ^= 1,
            4 => changed.root.content[0] ^= 1,
            5 => changed.root.created_day += 1,
            6 => changed.root.roster_revision += 1,
            7 => changed.root.game_version += 1,
            8 => changed.root.members[0].seat = 7,
            9 => changed.root.app.push('x'),
            10 => changed.root.limits.image += 1,
            _ => unreachable!(),
        }
        assert!(changed.verify().is_err(), "field {field}");
    }
    let mut duplicate = descriptor.root.clone();
    duplicate.members[1].player = 1;
    assert!(Descriptor::offer(duplicate, &host).is_err());
    let mut duplicate = descriptor.root.clone();
    duplicate.members[1].seat = 0;
    assert!(Descriptor::offer(duplicate, &host).is_err());
    assert_eq!(room_code_hash("abcdef").unwrap(), descriptor.root.code);
}
#[test]
fn activation_requires_all_human_capabilities_and_actual_initial_restore_equivalence() {
    let (mut descriptor, host, standby, player) = descriptor_fixture();
    descriptor.consent(&standby).unwrap();
    let image = vec![3, 4, 5];
    let initial = state_hash(&image).unwrap();
    let mut activation = Activation::new(descriptor.clone(), image.clone(), 0).unwrap();
    assert!(!activation.ready());
    let host_ack = CapabilityAck::sign(&descriptor.root, 1, initial, 1, &host).unwrap();
    assert_eq!(
        CapabilityAck::decode(
            &descriptor.root,
            &host_ack.encode(&descriptor.root).unwrap()
        )
        .unwrap(),
        host_ack
    );
    activation.acknowledge(host_ack.clone()).unwrap();
    activation.acknowledge(host_ack).unwrap();
    assert!(!activation.ready());
    assert!(CapabilityAck::sign(&descriptor.root, 3, initial, 1, &player).is_err());
    let wrong = CapabilityAck::sign(&descriptor.root, 2, [0; 32], 1, &player).unwrap();
    assert_eq!(activation.acknowledge(wrong), Err(Error::Conflict));
    activation
        .acknowledge(CapabilityAck::sign(&descriptor.root, 2, initial, 1, &player).unwrap())
        .unwrap();
    assert!(activation.ready());
    let (sequencer, armed) = activation
        .arm(&standby, |bytes| Ok(bytes.to_vec()))
        .unwrap();
    assert_eq!(sequencer.image(), &image);
    armed.verify(sequencer.context()).unwrap();
    armed.verify_initial(&descriptor.root, initial, 0).unwrap();
    assert!(armed.verify_initial(&descriptor.root, [0; 32], 0).is_err());
    assert!(armed.verify_initial(&descriptor.root, initial, 1).is_err());
    let bytes = armed.encode(sequencer.context()).unwrap();
    assert_eq!(Armed::decode(sequencer.context(), &bytes).unwrap(), armed);
    for end in 0..bytes.len() {
        assert!(Armed::decode(sequencer.context(), &bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Armed::decode(sequencer.context(), &trailing).is_err());
    let mut tampered = bytes;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(Armed::decode(sequencer.context(), &tampered).is_err());
    let mut wrong_context = sequencer.context().clone();
    wrong_context.session[0] ^= 1;
    assert!(armed.verify(&wrong_context).is_err());
    let mut bad = Activation::new(descriptor.clone(), image, 0).unwrap();
    bad.acknowledge(CapabilityAck::sign(&descriptor.root, 1, initial, 1, &host).unwrap())
        .unwrap();
    bad.acknowledge(CapabilityAck::sign(&descriptor.root, 2, initial, 1, &player).unwrap())
        .unwrap();
    assert!(bad.arm(&standby, |_| Ok(vec![9])).is_err());
    let missing = Activation::new(descriptor, vec![3, 4, 5], 0).unwrap();
    assert!(missing.arm(&standby, |b| Ok(b.to_vec())).is_err());
}

fn wait_host_ready(host: &fray_net::HostHandle) -> std::net::SocketAddr {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        while let Some(event) = host.poll() {
            match event {
                fray_net::HostEvent::Ready { .. } => {
                    return std::net::SocketAddr::new(
                        std::net::Ipv4Addr::LOCALHOST.into(),
                        host.local_addr().unwrap().port(),
                    )
                }
                fray_net::HostEvent::Failed { reason } => panic!("host failed: {reason}"),
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    panic!("host did not become ready");
}
fn connected_metadata(client: &fray_net::ClientHandle) -> Option<(Option<String>, Vec<String>)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        while let Some(event) = client.poll() {
            match event {
                fray_net::ClientEvent::Connected {
                    attestation,
                    inbox_relays,
                    ..
                } => return Some((attestation, inbox_relays)),
                fray_net::ClientEvent::Failed { .. }
                | fray_net::ClientEvent::Disconnected { .. } => return None,
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    panic!("client had no terminal connection event");
}
fn wait_connected(client: &fray_net::ClientHandle) -> bool {
    connected_metadata(client).is_some()
}
#[test]
fn passive_standby_accepts_nine_bound_control_links_without_advertising_or_player_seats() {
    use fray_net::{host_standby, join_addr, join_session_addr, Identity, NetConfig};
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral().with_attestation("private standby persona".into());
    let outsider = Identity::ephemeral();
    let players: Vec<_> = (0..8).map(|_| Identity::ephemeral()).collect();
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-control-test").lan_only();
    cfg.lan_port = 0;
    cfg.withhold_host_attestation = Some(true);
    cfg.inbox_relays = vec!["wss://inbox.example".into()];
    let root = Root {
        session: fresh_session().unwrap(),
        app: cfg.app_tag.clone(),
        transport_version: 7,
        game_version: 13,
        checkpoint_version: 1,
        host: original.pubkey().to_bytes(),
        standby: standby.pubkey().to_bytes(),
        controller: original.pubkey().to_bytes(),
        code: room_code_hash("ABCDEF").unwrap(),
        created_day: 20741,
        roster_revision: 1,
        members: players
            .iter()
            .enumerate()
            .map(|(i, p)| Member {
                player: i as u64 + 1,
                seat: i as u8,
                key: Some(p.pubkey().to_bytes()),
            })
            .collect(),
        config: [11; 32],
        content: [12; 32],
        limits: ResourceLimits::default(),
    };
    let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let listener = host_standby(&cfg, &standby, "ABCDEF", descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    assert_eq!(listener.code(), "ABCDEF");
    assert!(!listener.is_open());
    listener.set_open(true);
    assert!(!listener.is_open());
    let mut binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let no_binding = join_addr(&cfg, &players[0], addr, &listener.lan_token());
    assert!(!wait_connected(&no_binding));
    let wrong_key = join_session_addr(
        &cfg,
        &outsider,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&wrong_key));
    let mut wrong_root = binding.clone();
    wrong_root.session[0] ^= 1;
    let stale = join_session_addr(
        &cfg,
        &players[0],
        addr,
        &listener.lan_token(),
        wrong_root,
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&stale));
    let mut clients = Vec::new();
    for player in &players {
        let client = join_session_addr(
            &cfg,
            player,
            addr,
            &listener.lan_token(),
            binding.clone(),
            standby.pubkey(),
        )
        .unwrap();
        assert_eq!(connected_metadata(&client), Some((None, vec![])));
        assert_eq!(client.connection_binding(), Some(binding.clone()));
        clients.push(client);
    }
    binding.client = LinkRole::Original;
    let primary = join_session_addr(
        &cfg,
        &original,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&primary));
    clients.push(primary);
    assert_eq!(listener.peer_count(), 9);
    let extra = join_session_addr(
        &cfg,
        &original,
        addr,
        &listener.lan_token(),
        binding,
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&extra));
    assert_eq!(listener.peer_count(), 9);
    assert_eq!(listener.relays_connected(), (0, 0));
    let mut links = 0;
    while let Some(event) = listener.poll() {
        if let fray_net::HostEvent::PeerJoined { peer, pubkey, .. } = event {
            let i = players
                .iter()
                .position(|p| p.pubkey() == pubkey)
                .unwrap_or(8);
            assert_eq!(
                listener.tls_binding(peer).unwrap(),
                clients[i].tls_binding().unwrap()
            );
            links += 1;
        }
    }
    assert_eq!(links, 9);

    listener.shutdown();
    drop(clients);
}
#[test]
fn certified_successor_reuses_code_and_accepts_only_bound_existing_roster_while_closed() {
    use fray_net::{join_addr, join_session_addr, resume_host, Identity, NetConfig, RoomInfo};
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral().with_attestation("private successor persona".into());
    let player = Identity::ephemeral();
    let stranger = Identity::ephemeral();
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-resume-test").lan_only();
    cfg.lan_port = 0;
    cfg.withhold_host_attestation = Some(true);
    cfg.inbox_relays = vec!["wss://inbox.example".into()];
    let root = Root {
        session: fresh_session().unwrap(),
        app: cfg.app_tag.clone(),
        transport_version: 7,
        game_version: 5,
        checkpoint_version: 1,
        host: original.pubkey().to_bytes(),
        standby: standby.pubkey().to_bytes(),
        controller: original.pubkey().to_bytes(),
        code: room_code_hash("ABCDEF").unwrap(),
        created_day: 20741,
        roster_revision: 1,
        members: vec![Member {
            player: 1,
            seat: 0,
            key: Some(player.pubkey().to_bytes()),
        }],
        config: [11; 32],
        content: [12; 32],
        limits: ResourceLimits::default(),
    };
    let mut descriptor = Descriptor::offer(root, original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let mut sequencer = Sequencer::arm(
        descriptor.root.context().unwrap(),
        vec![0],
        0,
        marks(0, 0),
        standby.keys(),
    )
    .unwrap();
    let promotion = sequencer.promote(standby.keys()).unwrap();
    let listener = resume_host(
        &cfg,
        &standby,
        RoomInfo {
            name: "Resumed".into(),
            max_players: 8,
        },
        "ABCDEF",
        descriptor.clone(),
        promotion,
    )
    .unwrap();
    let addr = wait_host_ready(&listener);
    assert_eq!(listener.code(), "ABCDEF");
    assert!(!listener.is_open());
    let ordinary = join_addr(&cfg, &player, addr, &listener.lan_token());
    assert!(!wait_connected(&ordinary));
    let binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 1,
        client: LinkRole::ResumePlayer,
        server: LinkRole::Successor,
    };
    let unknown = join_session_addr(
        &cfg,
        &stranger,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert!(!wait_connected(&unknown));
    let resumed = join_session_addr(
        &cfg,
        &player,
        addr,
        &listener.lan_token(),
        binding.clone(),
        standby.pubkey(),
    )
    .unwrap();
    assert_eq!(connected_metadata(&resumed), Some((None, vec![])));
    assert_eq!(resumed.connection_binding(), Some(binding));
    assert_eq!(listener.peer_count(), 1);
    listener.shutdown();
}

#[test]
fn phone_primary_shares_its_original_link_for_replication_and_player_control() {
    let (mut descriptor, host, standby, _) = descriptor_fixture();
    descriptor.consent(&standby).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let mut binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    assert!(policy
        .authorize(&binding, host.public_key().to_bytes())
        .is_err());
    binding.client = LinkRole::Original;
    policy
        .authorize(&binding, host.public_key().to_bytes())
        .unwrap();
}

#[test]
fn reconnect_proof_is_single_use_and_binds_connection_frontier_key_and_retained_cuts() {
    let (mut descriptor, host, standby, player) = descriptor_fixture();
    descriptor.consent(&standby).unwrap();
    let marks = descriptor
        .root
        .members
        .iter()
        .map(|m| Watermark {
            player: m.player,
            input: 0,
            output_ack: 0,
            retired: false,
        })
        .collect();
    let mut sequencer = Sequencer::arm(
        descriptor.root.context().unwrap(),
        vec![0],
        0,
        marks,
        &standby,
    )
    .unwrap();
    let promotion = sequencer.promote(&standby).unwrap();
    let mut gate = ResumeGate::new(descriptor.clone(), promotion).unwrap();
    assert!(gate
        .issue(
            10,
            [5; 32],
            2,
            host.public_key().to_bytes(),
            &sequencer,
            0,
            &standby
        )
        .is_err());
    let challenge = gate
        .issue(
            10,
            [5; 32],
            2,
            player.public_key().to_bytes(),
            &sequencer,
            0,
            &standby,
        )
        .unwrap();
    assert_eq!(
        ResumeChallenge::decode(
            &descriptor.root,
            &challenge.encode(&descriptor.root).unwrap()
        )
        .unwrap(),
        challenge
    );
    assert!(ResumeProof::sign(&descriptor.root, &challenge, [5; 32], 0, 1, 1, &host).is_err());
    assert!(ResumeProof::sign(&descriptor.root, &challenge, [9; 32], 0, 1, 1, &player).is_err());
    let proof = ResumeProof::sign(&descriptor.root, &challenge, [5; 32], 0, 1, 1, &player).unwrap();
    assert_eq!(
        ResumeProof::decode(&descriptor.root, &proof.encode(&descriptor.root).unwrap()).unwrap(),
        proof
    );
    assert!(gate.consume(11, [5; 32], &proof, &sequencer, 10).is_err());
    assert!(gate.consume(10, [6; 32], &proof, &sequencer, 10).is_err());
    let mut changed = proof.clone();
    changed.input_tail = 2;
    assert!(gate.consume(10, [5; 32], &changed, &sequencer, 10).is_err());
    gate.consume(10, [5; 32], &proof, &sequencer, 20).unwrap();
    assert!(gate.consume(10, [5; 32], &proof, &sequencer, 20).is_err());
    let challenge2 = gate
        .issue(
            11,
            [6; 32],
            2,
            player.public_key().to_bytes(),
            &sequencer,
            30,
            &standby,
        )
        .unwrap();
    assert_ne!(challenge.nonce, challenge2.nonce);
    assert!(gate.consume(11, [6; 32], &proof, &sequencer, 40).is_err());
    let future_ack =
        ResumeProof::sign(&descriptor.root, &challenge2, [6; 32], 1, 1, 2, &player).unwrap();
    assert!(gate
        .consume(11, [6; 32], &future_ack, &sequencer, 40)
        .is_err());
    let overflow =
        ResumeProof::sign(&descriptor.root, &challenge2, [6; 32], 0, 513, 2, &player).unwrap();
    assert!(gate
        .consume(11, [6; 32], &overflow, &sequencer, 40)
        .is_err());
    let valid =
        ResumeProof::sign(&descriptor.root, &challenge2, [6; 32], 0, 1, 2, &player).unwrap();
    assert!(gate.consume(11, [6; 32], &valid, &sequencer, 5030).is_err());
    assert!(
        gate.issue(
            12,
            [7; 32],
            2,
            player.public_key().to_bytes(),
            &sequencer,
            40,
            &standby
        )
        .is_err(),
        "backwards security time"
    );
}

#[test]
fn reconnect_challenge_cannot_outlive_its_commit_frontier_or_regress_previously_accepted_cuts() {
    let (mut descriptor, _host, standby, player) = descriptor_fixture();
    descriptor.consent(&standby).unwrap();
    let marks = descriptor
        .root
        .members
        .iter()
        .map(|m| Watermark {
            player: m.player,
            input: 0,
            output_ack: 0,
            retired: false,
        })
        .collect();
    let mut sequencer = Sequencer::arm(
        descriptor.root.context().unwrap(),
        vec![0],
        0,
        marks,
        &standby,
    )
    .unwrap();
    let promotion = sequencer.promote(&standby).unwrap();
    let mut gate = ResumeGate::new(descriptor.clone(), promotion).unwrap();
    let challenge = gate
        .issue(
            10,
            [5; 32],
            2,
            player.public_key().to_bytes(),
            &sequencer,
            0,
            &standby,
        )
        .unwrap();
    let proof = ResumeProof::sign(&descriptor.root, &challenge, [5; 32], 0, 1, 1, &player).unwrap();
    let mut marks = sequencer.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
    let candidate = sequencer.next(vec![1], 0, marks, vec![]).unwrap();
    let staged = sequencer.stage(candidate).unwrap();
    sequencer.install(staged, &standby).unwrap();
    assert_eq!(
        gate.consume(10, [5; 32], &proof, &sequencer, 10),
        Err(Error::Stale)
    );
    let outputs = (1..=5)
        .map(|sequence| Output {
            recipient: 2,
            delivery: Delivery::Reliable,
            sequence,
            bytes: vec![1],
        })
        .collect();
    let candidate = sequencer
        .next(vec![2], 0, sequencer.receipt().watermarks.clone(), outputs)
        .unwrap();
    let staged = sequencer.stage(candidate).unwrap();
    sequencer.install(staged, &standby).unwrap();
    let challenge = gate
        .issue(
            11,
            [6; 32],
            2,
            player.public_key().to_bytes(),
            &sequencer,
            20,
            &standby,
        )
        .unwrap();
    let proof =
        ResumeProof::sign(&descriptor.root, &challenge, [6; 32], 5, 10, 2, &player).unwrap();
    gate.consume(11, [6; 32], &proof, &sequencer, 30).unwrap();
    let challenge = gate
        .issue(
            12,
            [7; 32],
            2,
            player.public_key().to_bytes(),
            &sequencer,
            40,
            &standby,
        )
        .unwrap();
    let lost = ResumeProof::sign(&descriptor.root, &challenge, [7; 32], 0, 1, 3, &player).unwrap();
    assert!(gate.consume(12, [7; 32], &lost, &sequencer, 50).is_err());
    let retained =
        ResumeProof::sign(&descriptor.root, &challenge, [7; 32], 5, 10, 3, &player).unwrap();
    gate.consume(12, [7; 32], &retained, &sequencer, 60)
        .unwrap();
}

#[test]
fn forgotten_restored_bot_cannot_be_treated_as_a_departed_remote_player() {
    let (mut descriptor, _, key, _) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let marks = descriptor
        .root
        .members
        .iter()
        .map(|m| Watermark {
            player: m.player,
            input: 0,
            output_ack: 0,
            retired: false,
        })
        .collect();
    let sequencer = Sequencer::arm(
        descriptor.root.context().unwrap(),
        vec![0],
        100,
        marks,
        &key,
    )
    .unwrap();
    let histories = descriptor
        .root
        .members
        .iter()
        .map(|m| (m.player, HandledInputs::default()))
        .collect();
    let mut recovery = Recovery::begin(descriptor, sequencer, histories, &key, 0).unwrap();
    assert!(recovery.seal(250).is_err());
    assert_eq!(recovery.phase(), RecoveryPhase::Failed);
}

#[test]
fn session_image_binds_routes_histories_versions_and_retired_ids_to_one_canonical_image() {
    let (descriptor, _, _, _) = descriptor_fixture();
    let root = &descriptor.root;
    let initial =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![1, 2, 3], 9, 100).unwrap();
    let bytes = initial.encode(root).unwrap();
    assert_eq!(SessionImage::decode(root, &bytes).unwrap(), initial);
    for len in [0, 4, bytes.len() - 1] {
        assert!(SessionImage::decode(root, &bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SessionImage::decode(root, &trailing).is_err());
    let mut other = root.clone();
    other.session[0] ^= 1;
    assert!(SessionImage::decode(&other, &bytes).is_err());
    let mut next = initial.clone();
    next.inputs.get_mut(&2).unwrap().record(1, &[7]).unwrap();
    next.logical_ms = 101;
    let mut marks: Vec<_> = root
        .members
        .iter()
        .map(|m| Watermark {
            player: m.player,
            input: if m.player == 2 { 1 } else { 0 },
            output_ack: 0,
            retired: false,
        })
        .collect();
    next.validate_successor(root, &initial, &marks, next.logical_ms)
        .unwrap();
    let mut conflict = next.clone();
    conflict
        .inputs
        .get_mut(&2)
        .unwrap()
        .record(2, &[8])
        .unwrap();
    let mut wrong = initial.clone();
    wrong.inputs.get_mut(&2).unwrap().record(1, &[9]).unwrap();
    marks[1].input = 2;
    assert!(conflict
        .validate_successor(root, &wrong, &marks, conflict.logical_ms)
        .is_err());
    marks[1].input = 1;
    next.members.remove(0);
    next.inputs.remove(&1);
    next.membership_revision += 1;
    assert!(next
        .validate_successor(root, &initial, &marks, next.logical_ms)
        .is_err());
    marks[0].retired = true;
    next.validate_successor(root, &initial, &marks, next.logical_ms)
        .unwrap();
    let retired = next.clone();
    next.members.insert(0, initial.members[0].clone());
    next.inputs.insert(1, HandledInputs::default());
    next.membership_revision += 1;
    marks[0].retired = false;
    assert!(next
        .validate_successor(root, &retired, &marks, next.logical_ms)
        .is_err());
    let mut oversized = initial.clone();
    oversized.game = vec![0; MAX_IMAGE];
    assert_eq!(oversized.encode(root), Err(Error::Bounds));
}

#[test]
fn typed_sequencer_rejects_clock_mismatch_prehandled_admission_and_untyped_stage_tokens() {
    let (descriptor, _, key, _) = descriptor_fixture();
    let root = &descriptor.root;
    let initial =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 9, 100).unwrap();
    let mut sequencer = Sequencer::arm_session(root.clone(), initial.clone(), &key).unwrap();
    let mut untyped = Sequencer::arm(
        root.context().unwrap(),
        sequencer.image().to_vec(),
        100,
        sequencer.receipt().watermarks.clone(),
        &key,
    )
    .unwrap();
    let bad = untyped
        .next(vec![42], 100, untyped.receipt().watermarks.clone(), vec![])
        .unwrap();
    let token = untyped.stage(bad).unwrap();
    let before = sequencer.receipt().clone();
    assert!(sequencer.install(token, &key).is_err());
    assert_eq!(sequencer.receipt(), &before);
    let next = sequencer
        .next(
            initial.encode(root).unwrap(),
            101,
            before.watermarks.clone(),
            vec![],
        )
        .unwrap();
    assert!(sequencer.stage(next).is_err());
    let mut added = initial.clone();
    let newcomer = Keys::generate();
    added.membership_revision += 1;
    added.next_player = 5;
    added.members.push(SessionMember {
        player: 4,
        seat: 3,
        key: Some(newcomer.public_key().to_bytes()),
        logical_peer: 13,
    });
    added.inputs.insert(4, HandledInputs::default());
    added.inputs.get_mut(&4).unwrap().record(1, &[7]).unwrap();
    let mut marks = before.watermarks.clone();
    marks.push(Watermark {
        player: 4,
        input: 1,
        output_ack: 0,
        retired: false,
    });
    let next = sequencer
        .next(added.encode(root).unwrap(), 100, marks.clone(), vec![])
        .unwrap();
    assert!(sequencer.stage(next).is_err());
    added.inputs.insert(4, HandledInputs::default());
    marks.last_mut().unwrap().input = 0;
    let next = sequencer
        .next(added.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let token = sequencer.stage(next).unwrap();
    assert!(untyped.install(token, &key).is_err());
}

#[test]
fn membership_certificates_expose_only_installed_tables_and_reject_rollback_or_tampering() {
    let (descriptor, _, key, _) = descriptor_fixture();
    let root = &descriptor.root;
    let mut image =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 9, 100).unwrap();
    let mut sequencer = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let initial = sequencer.membership_certificate(&key).unwrap();
    assert_eq!(
        MembershipCertificate::decode(root, &initial.encode(root).unwrap()).unwrap(),
        initial
    );
    image.members.remove(1);
    image.inputs.remove(&2);
    image.membership_revision += 1;
    let mut marks = sequencer.receipt().watermarks.clone();
    marks[1].retired = true;
    let next = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let staged = sequencer.stage(next).unwrap();
    let pending = sequencer.membership_certificate(&key).unwrap();
    assert_eq!(
        pending.members, initial.members,
        "staged membership is not authorized"
    );
    assert_eq!(pending.receipt, initial.receipt);
    pending.follows(root, &initial).unwrap();
    sequencer.install(staged, &key).unwrap();
    let retired = sequencer.membership_certificate(&key).unwrap();
    retired.follows(root, &initial).unwrap();
    assert!(initial.follows(root, &retired).is_err());
    let newcomer = Keys::generate();
    image.members.push(SessionMember {
        player: 4,
        seat: 1,
        key: Some(newcomer.public_key().to_bytes()),
        logical_peer: 13,
    });
    image.inputs.insert(4, HandledInputs::default());
    image.next_player = 5;
    image.membership_revision += 1;
    let mut marks = sequencer.receipt().watermarks.clone();
    marks.retain(|m| !m.retired);
    marks.push(Watermark {
        player: 4,
        input: 0,
        output_ack: 0,
        retired: false,
    });
    let next = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let staged = sequencer.stage(next).unwrap();
    sequencer.install(staged, &key).unwrap();
    let current = sequencer.membership_certificate(&key).unwrap();
    current.follows(root, &initial).unwrap();
    current.follows(root, &retired).unwrap();
    let encoded = current.encode(root).unwrap();
    assert_eq!(
        MembershipCertificate::decode(root, &encoded).unwrap(),
        current
    );
    for n in [0, 49, encoded.len() - 1] {
        assert!(MembershipCertificate::decode(root, &encoded[..n]).is_err());
    }
    let mut tampered = encoded.clone();
    let end = tampered.len() - 1;
    tampered[end] ^= 1;
    assert!(MembershipCertificate::decode(root, &tampered).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(MembershipCertificate::decode(root, &trailing).is_err());
    assert!(sequencer.membership_certificate(&newcomer).is_err());
}

#[test]
fn real_quic_membership_updates_retire_old_links_and_admit_only_committed_replacements() {
    use fray_net::{host_standby, join_session_addr, Identity, NetConfig};
    let host = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let old = Identity::ephemeral();
    let new = Identity::ephemeral();
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-membership-test").lan_only();
    cfg.lan_port = 0;
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.host = host.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.app = cfg.app_tag.clone();
    root.members[0].key = Some(root.host);
    root.members[1].key = Some(old.pubkey().to_bytes());
    let mut descriptor = Descriptor::offer(root, host.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let root = &descriptor.root;
    let mut image =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut sequencer =
        Sequencer::arm_session(root.clone(), image.clone(), standby.keys()).unwrap();
    let initial = sequencer.membership_certificate(standby.keys()).unwrap();
    let listener = host_standby(&cfg, &standby, "ABCDEF", descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    listener.update_session_membership(initial.clone()).unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let dial = |who: &Identity| {
        join_session_addr(
            &cfg,
            who,
            addr,
            &listener.lan_token(),
            binding.clone(),
            standby.pubkey(),
        )
        .unwrap()
    };
    let connected = dial(&old);
    assert!(wait_connected(&connected));
    assert_eq!(listener.peer_count(), 1);
    let uncommitted = dial(&new);
    assert!(!wait_connected(&uncommitted));
    image.members.remove(1);
    image.inputs.remove(&2);
    image.membership_revision += 1;
    let mut marks = sequencer.receipt().watermarks.clone();
    marks[1].retired = true;
    let candidate = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let token = sequencer.stage(candidate).unwrap();
    sequencer.install(token, standby.keys()).unwrap();
    listener
        .update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
        .unwrap();
    assert_eq!(listener.peer_count(), 0);
    assert!(!wait_connected(&connected));
    let retired = dial(&old);
    assert!(!wait_connected(&retired));
    image.members.push(SessionMember {
        player: 4,
        seat: 1,
        key: Some(new.pubkey().to_bytes()),
        logical_peer: 13,
    });
    image.inputs.insert(4, HandledInputs::default());
    image.membership_revision += 1;
    image.next_player = 5;
    let mut marks = sequencer.receipt().watermarks.clone();
    marks.retain(|m| !m.retired);
    marks.push(Watermark {
        player: 4,
        input: 0,
        output_ack: 0,
        retired: false,
    });
    let candidate = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let token = sequencer.stage(candidate).unwrap();
    let staged_only = dial(&new);
    assert!(!wait_connected(&staged_only));
    sequencer.install(token, standby.keys()).unwrap();
    listener
        .update_session_membership(sequencer.membership_certificate(standby.keys()).unwrap())
        .unwrap();
    let replacement = dial(&new);
    assert!(wait_connected(&replacement));
    assert!(listener.update_session_membership(initial).is_err());
    assert_eq!(listener.peer_count(), 1);
    listener.shutdown();
}

#[test]
fn authenticated_channel_filters_role_and_manifest_size_before_reassembly_allocation() {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    assert!(Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Server,
        host.public_key().to_bytes(),
        [1; 32]
    )
    .is_err());
    let mut channel = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [1; 32],
    )
    .unwrap();
    let malicious = Frame::split(
        binding.session,
        0,
        1,
        PacketKind::Candidate,
        &vec![1; MAX_IMAGE],
    )
    .unwrap();
    for transfer in 1..=10 {
        let mut frame = malicious[0].clone();
        frame.transfer = transfer;
        assert_eq!(
            channel.receive(&frame.encode().unwrap(), 0),
            Err(Error::Unauthorized)
        );
        frame.kind = PacketKind::Control;
        assert_eq!(
            channel.receive(&frame.encode().unwrap(), 0),
            Err(Error::Bounds)
        );
    }
    let frames = Frame::split(binding.session, 0, 11, PacketKind::Control, &vec![7; 4096]).unwrap();
    let mut received = None;
    for frame in frames {
        let wire = frame.encode().unwrap();
        assert!(wire.len() <= 1024);
        if let Some(message) = channel.receive(&wire, 0).unwrap() {
            received = Some(message);
        }
    }
    assert_eq!(received, Some((PacketKind::Control, 11, vec![7; 4096])));
    assert!(channel.enqueue(PacketKind::Candidate, &[1]).is_err());
    assert!(channel.enqueue(PacketKind::Output, &[1]).is_err());
}

#[test]
fn authenticated_replication_channel_paces_full_images_and_closes_candidates_on_signed_promotion() {
    let (mut descriptor, host, key, _) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let mut primary = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        key.public_key().to_bytes(),
        [8; 32],
    )
    .unwrap();
    let mut standby = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Server,
        host.public_key().to_bytes(),
        [8; 32],
    )
    .unwrap();
    let candidate = Candidate {
        sequence: 1,
        term: 0,
        index: 1,
        parent: [5; 32],
        logical_ms: 10,
        image: vec![4; 200_000],
        watermarks: vec![],
        outputs: vec![],
    };
    let payload = candidate
        .encode(&descriptor.root.context().unwrap())
        .unwrap();
    assert_eq!(primary.enqueue(PacketKind::Candidate, &payload).unwrap(), 1);
    let mut complete = 0;
    for now in 0..=250 {
        while let Some(wire) = primary.poll_send(now).unwrap() {
            assert!(wire.len() <= 1024);
            if let Some((kind, id, bytes)) = standby.receive(&wire, now).unwrap() {
                assert_eq!((kind, id), (PacketKind::Candidate, 1));
                assert_eq!(bytes, payload);
                complete += 1;
            }
        }
    }
    assert_eq!(complete, 1);
    primary.enqueue(PacketKind::Candidate, &payload).unwrap();
    let mut sequencer =
        Sequencer::arm(descriptor.root.context().unwrap(), vec![0], 0, vec![], &key).unwrap();
    let promotion = sequencer.promote(&key).unwrap();
    let (other, otherkey) = pair();
    let mut unrelated = Sequencer::arm(other, vec![0], 0, vec![], &otherkey).unwrap();
    assert!(standby
        .promote(&unrelated.promote(&otherkey).unwrap())
        .is_err());
    primary.promote(&promotion).unwrap();
    standby.promote(&promotion).unwrap();
    assert!(primary.poll_send(251).unwrap().is_none());
    assert!(primary.enqueue(PacketKind::Candidate, &[1]).is_err());
    assert!(standby.enqueue(PacketKind::Receipt, &[1]).is_err());
    assert!(standby.promote(&promotion).is_err());
    standby.enqueue(PacketKind::Output, &[9]).unwrap();
    let wire = standby.poll_send(251).unwrap().unwrap();
    assert_eq!(
        primary.receive(&wire, 251).unwrap(),
        Some((PacketKind::Output, 1, vec![9]))
    );
    assert_eq!(primary.tls(), [8; 32]);
    assert_eq!(primary.binding(), &binding);
}

#[test]
fn channel_ingress_counts_duplicates_against_the_shared_burst_and_rejects_backwards_time() {
    let (mut descriptor, _, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let mut channel = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [1; 32],
    )
    .unwrap();
    let wire = Frame::split(binding.session, 0, 1, PacketKind::Control, &vec![3; 768]).unwrap()[0]
        .encode()
        .unwrap();
    let mut bytes = 0;
    loop {
        match channel.receive(&wire, 0) {
            Ok(_) => bytes += wire.len(),
            Err(Error::RateLimited) => break,
            other => panic!("unexpected ingress result {other:?}"),
        }
    }
    assert!(bytes <= 64 * 1024);
    assert!(bytes + wire.len() > 64 * 1024);
    assert!(channel.receive(&wire, 1).is_ok());
    assert!(matches!(
        channel.receive(&wire, 0),
        Err(Error::Invalid("backwards ingress clock"))
    ));
}

#[test]
fn channel_ingress_budget_also_charges_malformed_and_disallowed_frames() {
    let (mut descriptor, _, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: descriptor.root.session,
        descriptor: descriptor.root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let disallowed = Frame::split(binding.session, 0, 1, PacketKind::Candidate, &vec![0; 768])
        .unwrap()[0]
        .encode()
        .unwrap();
    for wire in [vec![0; 1024], disallowed] {
        let mut channel = Channel::new(
            &policy,
            binding.clone(),
            ChannelSide::Server,
            player.public_key().to_bytes(),
            [1; 32],
        )
        .unwrap();
        let mut charged = 0;
        loop {
            match channel.receive(&wire, 0) {
                Err(Error::Invalid(_) | Error::Unauthorized) => charged += wire.len(),
                Err(Error::RateLimited) => break,
                other => panic!("unexpected invalid-frame result {other:?}"),
            }
        }
        assert!(charged > 0);
        assert!(charged <= 64 * 1024);
        assert!(charged + wire.len() > 64 * 1024);
    }
}

#[test]
fn receive_queue_defers_unconsumed_frames_and_bounds_bytes_and_record_count() {
    let mut queue = ReceiveQueue::default();
    queue.enqueue(vec![1; 1024]).unwrap();
    queue.enqueue(vec![2; 1024]).unwrap();
    assert_eq!(
        queue.poll::<()>(|wire| {
            assert_eq!(wire, &[1; 1024]);
            Err(Error::RateLimited)
        }),
        Ok(None)
    );
    assert_eq!(queue.queued_bytes(), 2048);
    assert_eq!(
        queue.poll(|wire| {
            assert_eq!(wire, &[1; 1024]);
            Ok(7)
        }),
        Ok(Some(7))
    );
    assert_eq!(
        queue.poll::<()>(|wire| {
            assert_eq!(wire, &[2; 1024]);
            Err(Error::Invalid("bad frame"))
        }),
        Err(Error::Invalid("bad frame"))
    );
    assert_eq!(queue.queued_bytes(), 0);
    assert_eq!(
        queue.poll::<()>(|_| panic!("empty queue invoked receiver")),
        Ok(None)
    );
    assert_eq!(queue.enqueue(vec![]), Err(Error::Bounds));
    assert_eq!(queue.enqueue(vec![0; 1025]), Err(Error::Bounds));
    for size in [1, 1024] {
        let mut queue = ReceiveQueue::default();
        let capacity = 4096.min(2 * MAX_IMAGE / size);
        for _ in 0..capacity {
            queue.enqueue(vec![0; size]).unwrap();
        }
        assert_eq!(queue.enqueue(vec![0; size]), Err(Error::Bounds));
        assert_eq!(queue.queued_bytes(), capacity * size);
        queue.poll(|_| Ok(())).unwrap();
        queue.enqueue(vec![0; size]).unwrap();
        assert_eq!(queue.queued_bytes(), capacity * size);
    }
}

#[test]
fn deferred_ingress_does_not_extend_the_existing_transfer_deadline() {
    let (descriptor, _, _, _, image, mut source, mut sink) = activation_wire_pair(1024);
    let mut queue = ReceiveQueue::default();
    let mut first = true;
    let mut repeated = Vec::new();
    while let Some(wire) = source.poll_send(0).unwrap() {
        if first {
            sink.receive(&wire, 0).unwrap();
            repeated = wire;
            first = false;
        } else {
            queue.enqueue(wire).unwrap();
        }
    }
    assert!(queue.queued_bytes() > 0);
    assert!(!sink.ready());
    loop {
        match sink.receive(&repeated, 0) {
            Ok(_) => {}
            Err(Error::RateLimited) => break,
            other => panic!("unexpected debit result: {other:?}"),
        }
    }
    let before = queue.queued_bytes();
    assert_eq!(queue.poll(|wire| sink.receive(wire, 0)), Ok(None));
    assert_eq!(queue.queued_bytes(), before);
    let result = queue.poll(|wire| sink.receive(wire, 501));
    assert!(
        result.is_err(),
        "a queued chunk revived an expired transfer: {result:?}"
    );
    assert!(
        SessionImage::decode(&descriptor.root, &image.encode(&descriptor.root).unwrap()).is_ok()
    );
    let (_, _, _, _, _, mut source, mut sink) = activation_wire_pair(1);
    let mut queue = ReceiveQueue::default();
    while let Some(wire) = source.poll_send(0).unwrap() {
        queue.enqueue(wire).unwrap();
    }
    assert_eq!(
        queue.poll(|wire| sink.receive(wire, 5000)),
        Err(Error::Closed)
    );
    assert_eq!(queue.poll(|wire| sink.receive(wire, 5001)), Ok(None));
    assert!(!sink.ready());
}

#[test]
fn candidate_and_delta_channels_bind_schema_base_index_and_target_before_and_after_assembly() {
    for kind in [PacketKind::Candidate, PacketKind::Delta] {
        let (mut descriptor, host, key, _) = descriptor_fixture();
        descriptor.consent(&key).unwrap();
        let policy = EndpointPolicy {
            descriptor: descriptor.clone(),
            role: LinkRole::Standby,
            promotion: None,
            membership: None,
        };
        let binding = ConnectionBinding {
            session: descriptor.root.session,
            descriptor: descriptor.root.digest().unwrap(),
            term: 0,
            client: LinkRole::Original,
            server: LinkRole::Standby,
        };
        let candidate = Candidate {
            sequence: 1,
            term: 0,
            index: 1,
            parent: [5; 32],
            logical_ms: 10,
            image: vec![4; 1000],
            watermarks: vec![],
            outputs: vec![],
        };
        let bytes = if kind == PacketKind::Delta {
            CandidateDelta::between(&vec![2; 1000], &candidate)
                .unwrap()
                .encode(&descriptor.root.context().unwrap())
                .unwrap()
        } else {
            candidate
                .encode(&descriptor.root.context().unwrap())
                .unwrap()
        };
        let mut source = Channel::new(
            &policy,
            binding.clone(),
            ChannelSide::Client,
            key.public_key().to_bytes(),
            [8; 32],
        )
        .unwrap();
        source.enqueue(kind, &bytes).unwrap();
        let mut frames = Vec::new();
        while let Some(wire) = source.poll_send(0).unwrap() {
            assert!(wire.len() <= 1024);
            frames.push(Frame::decode(&wire).unwrap());
        }
        assert_eq!(frames.len(), 2);
        let receiver = || {
            Channel::new(
                &policy,
                binding.clone(),
                ChannelSide::Server,
                host.public_key().to_bytes(),
                [8; 32],
            )
            .unwrap()
        };
        let mut channel = receiver();
        let mut bad = frames[0].clone();
        bad.candidate.as_mut().unwrap().schema += 1;
        assert_eq!(
            channel.receive(&bad.encode().unwrap(), 0),
            Err(Error::Unauthorized)
        );
        bad.candidate = None;
        assert!(channel.receive(&bad.encode().unwrap(), 0).is_err());
        assert!(channel
            .receive(&frames[0].encode().unwrap(), 0)
            .unwrap()
            .is_none());
        let mut mixed = frames[1].clone();
        mixed.candidate.as_mut().unwrap().base = [6; 32];
        assert_eq!(
            channel.receive(&mixed.encode().unwrap(), 0),
            Err(Error::Conflict)
        );
        let mut channel = receiver();
        let mut forged = frames.clone();
        for frame in &mut forged {
            frame.candidate.as_mut().unwrap().target = [7; 32];
        }
        assert!(channel
            .receive(&forged[0].encode().unwrap(), 0)
            .unwrap()
            .is_none());
        assert_eq!(
            channel.receive(&forged[1].encode().unwrap(), 0),
            Err(Error::Conflict)
        );
        let mut channel = receiver();
        assert!(channel
            .receive(&frames[0].encode().unwrap(), 0)
            .unwrap()
            .is_none());
        assert_eq!(
            channel.receive(&frames[1].encode().unwrap(), 0).unwrap(),
            Some((kind, 1, bytes))
        );
    }
}

#[test]
fn recovery_uses_committed_membership_for_later_humans_and_restored_bots() {
    let (mut descriptor, _, key, _) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = &descriptor.root;
    let newcomer = Keys::generate();
    let mut image =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut sequencer = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let old = sequencer.membership_certificate(&key).unwrap();
    image.members.extend([
        SessionMember {
            player: 4,
            seat: 3,
            key: Some(newcomer.public_key().to_bytes()),
            logical_peer: 13,
        },
        SessionMember {
            player: 5,
            seat: 4,
            key: None,
            logical_peer: 14,
        },
    ]);
    image.inputs.insert(4, HandledInputs::default());
    image.inputs.insert(5, HandledInputs::default());
    image.membership_revision += 1;
    image.next_player = 6;
    let mut marks = sequencer.receipt().watermarks.clone();
    for player in [4, 5] {
        marks.push(Watermark {
            player,
            input: 0,
            output_ack: 0,
            retired: false,
        });
    }
    let candidate = sequencer
        .next(image.encode(root).unwrap(), 100, marks, vec![])
        .unwrap();
    let token = sequencer.stage(candidate).unwrap();
    sequencer.install(token, &key).unwrap();
    let certificate = sequencer.membership_certificate(&key).unwrap();
    let mut recovery =
        Recovery::begin(descriptor.clone(), sequencer, image.inputs, &key, 0).unwrap();
    assert!(
        ResumeGate::with_certificate(descriptor.clone(), recovery.promotion().clone(), old)
            .is_err()
    );
    recovery.retain_local(3, 0, 0, 0).unwrap();
    recovery.retain_local(5, 0, 0, 0).unwrap();
    assert!(recovery.retain_local(4, 0, 0, 0).is_err());
    let challenge = recovery
        .challenge(4, [4; 32], 4, newcomer.public_key().to_bytes(), &key, 0)
        .unwrap();
    let challenge = ResumeChallenge::decode(root, &challenge.encode(root).unwrap()).unwrap();
    assert!(ResumeProof::sign(root, &challenge, [4; 32], 0, 0, 1, &newcomer).is_err());
    let proof = ResumeProof::sign_with_certificate(
        root,
        &certificate,
        &challenge,
        [4; 32],
        0,
        0,
        1,
        &newcomer,
    )
    .unwrap();
    let bytes = proof.encode_with_certificate(root, &certificate).unwrap();
    assert!(ResumeProof::decode(root, &bytes).is_err());
    assert_eq!(
        ResumeProof::decode_with_certificate(root, &certificate, &bytes).unwrap(),
        proof
    );
    recovery.accept(4, [4; 32], &proof, 0).unwrap();
    recovery.seal(250).unwrap();
    recovery
        .revalidate_security(&key, 250, |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    recovery.begin_round().unwrap();
    for player in [3, 4, 5] {
        seal_test_inputs(&mut recovery, player, 0, &key, &newcomer, 250);
    }
    assert_eq!(recovery.absent().unwrap(), vec![1, 2]);
}

#[test]
fn a_resume_certificate_cannot_select_a_conflicting_same_index_state() {
    let (mut descriptor, _, key, _) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = &descriptor.root;
    let initial =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let newcomer = Keys::generate();
    let mut sequencers = Vec::new();
    for logical_peer in [13, 14] {
        let mut sequencer = Sequencer::arm_session(root.clone(), initial.clone(), &key).unwrap();
        let mut image = initial.clone();
        image.members.push(SessionMember {
            player: 4,
            seat: 3,
            key: Some(newcomer.public_key().to_bytes()),
            logical_peer,
        });
        image.inputs.insert(4, HandledInputs::default());
        image.membership_revision += 1;
        image.next_player = 5;
        let mut marks = sequencer.receipt().watermarks.clone();
        marks.push(Watermark {
            player: 4,
            input: 0,
            output_ack: 0,
            retired: false,
        });
        let candidate = sequencer
            .next(image.encode(root).unwrap(), 100, marks, vec![])
            .unwrap();
        let token = sequencer.stage(candidate).unwrap();
        sequencer.install(token, &key).unwrap();
        sequencers.push(sequencer);
    }
    let conflicting = sequencers[1].membership_certificate(&key).unwrap();
    let selected = sequencers.remove(0);
    let good = selected.membership_certificate(&key).unwrap();
    let mut recovery = Recovery::begin_session(descriptor.clone(), selected, &key, 0).unwrap();
    let challenge = recovery
        .challenge(4, [4; 32], 4, newcomer.public_key().to_bytes(), &key, 0)
        .unwrap();
    assert_eq!(
        ResumeProof::sign_with_certificate(
            root,
            &conflicting,
            &challenge,
            [4; 32],
            0,
            0,
            1,
            &newcomer
        ),
        Err(Error::Conflict)
    );
    ResumeProof::sign_with_certificate(root, &good, &challenge, [4; 32], 0, 0, 1, &newcomer)
        .unwrap();
}

#[test]
fn typed_recovery_uses_the_committed_input_hashes_not_just_matching_watermarks() {
    let (mut descriptor, _, key, _) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = &descriptor.root;
    let initial =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let fixture = || {
        let mut sequencer = Sequencer::arm_session(root.clone(), initial.clone(), &key).unwrap();
        let mut image = initial.clone();
        image.inputs.get_mut(&2).unwrap().record(1, &[7]).unwrap();
        let mut marks = sequencer.receipt().watermarks.clone();
        marks[1].input = 1;
        let candidate = sequencer
            .next(image.encode(root).unwrap(), 100, marks, vec![])
            .unwrap();
        let token = sequencer.stage(candidate).unwrap();
        sequencer.install(token, &key).unwrap();
        (sequencer, image.inputs)
    };
    let (sequencer, mut histories) = fixture();
    let mut wrong = HandledInputs::default();
    wrong.record(1, &[8]).unwrap();
    histories.insert(2, wrong);
    assert!(matches!(
        Recovery::begin(descriptor.clone(), sequencer, histories, &key, 0),
        Err(Error::Conflict)
    ));
    let (sequencer, histories) = fixture();
    let recovery = Recovery::begin_session(descriptor, sequencer, &key, 0).unwrap();
    assert_eq!(recovery.histories(), &histories);
}

fn pulse_fixture(activity: Activity) -> (Root, Sequencer, Keys, ProgressWatch) {
    let (descriptor, _, key, _) = descriptor_fixture();
    let root = descriptor.root;
    let seq = Sequencer::arm(root.context().unwrap(), vec![0], 100, marks(0, 0), &key).unwrap();
    let watch =
        ProgressWatch::new(root.clone(), seq.receipt().clone(), activity, [9; 32], 0).unwrap();
    (root, seq, key, watch)
}

#[test]
fn idle_liveness_requires_fresh_challenges_on_the_current_tls_connection() {
    let (root, seq, key, mut watch) = pulse_fixture(Activity::Idle);
    let first = watch.probe(50).unwrap();
    let bytes = first.encode(&root).unwrap();
    assert_eq!(PulseProbe::decode(&root, &bytes).unwrap(), first);
    assert!(Pulse::respond(&root, &seq, &first, [8; 32], Activity::Idle, 1, &key).is_err());
    let pulse = Pulse::respond(&root, &seq, &first, [9; 32], Activity::Idle, 1, &key).unwrap();
    let bytes = pulse.encode(&root).unwrap();
    assert_eq!(Pulse::decode(&root, &bytes).unwrap(), pulse);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Pulse::decode(&root, &trailing).is_err());
    let mut forged = pulse.clone();
    forged.activity = Activity::Advancing;
    assert!(watch.pulse(&forged, 60).is_err());
    watch.pulse(&pulse, 60).unwrap();
    assert_eq!(watch.status(259).unwrap(), WatchStatus::Live);
    assert!(watch.pulse(&pulse, 260).is_err());
    assert_eq!(watch.status(260).unwrap(), WatchStatus::Paused);

    let second = watch.probe(260).unwrap();
    assert_ne!(first.nonce, second.nonce);
    assert!(watch.pulse(&pulse, 261).is_err());
    let fresh = Pulse::respond(&root, &seq, &second, [9; 32], Activity::Idle, 2, &key).unwrap();
    watch.pulse(&fresh, 262).unwrap();
    assert_eq!(watch.status(262).unwrap(), WatchStatus::Live);
    let late_probe = watch.probe(312).unwrap();
    let late = Pulse::respond(&root, &seq, &late_probe, [9; 32], Activity::Idle, 3, &key).unwrap();
    assert!(watch.pulse(&late, 512).is_err());
    assert_eq!(watch.status(512).unwrap(), WatchStatus::Paused);
    assert!(watch.status(511).is_err());
}

#[test]
fn live_pulses_and_ack_only_commits_cannot_mask_an_active_game_stall() {
    let (root, mut seq, key, mut watch) = pulse_fixture(Activity::Advancing);
    for (index, now) in [50, 100, 150, 200].into_iter().enumerate() {
        let candidate = seq
            .next(vec![index as u8], 100, marks(0, 0), vec![])
            .unwrap();
        let staged = seq.stage(candidate).unwrap();
        seq.install(staged, &key).unwrap();
        watch.committed(seq.receipt(), now).unwrap();
        let probe = watch.probe(now).unwrap();
        let pulse = Pulse::respond(
            &root,
            &seq,
            &probe,
            [9; 32],
            Activity::Idle,
            index as u64 + 1,
            &key,
        )
        .unwrap();
        watch.pulse(&pulse, now).unwrap();
    }
    assert_eq!(watch.status(200).unwrap(), WatchStatus::Paused);
    let candidate = seq.next(vec![5], 150, marks(0, 0), vec![]).unwrap();
    let staged = seq.stage(candidate).unwrap();
    seq.install(staged, &key).unwrap();
    watch.committed(seq.receipt(), 201).unwrap();
    assert_eq!(watch.status(400).unwrap(), WatchStatus::Live);
    watch.committed(seq.receipt(), 401).unwrap();
    assert_eq!(watch.status(401).unwrap(), WatchStatus::Paused);
    watch.set_activity(Activity::Idle).unwrap();
    let probe = watch.probe(402).unwrap();
    let pulse = Pulse::respond(&root, &seq, &probe, [9; 32], Activity::Advancing, 5, &key).unwrap();
    watch.pulse(&pulse, 402).unwrap();
    assert_eq!(watch.status(402).unwrap(), WatchStatus::Paused);
}

#[test]
fn signed_promotion_fences_old_pulses_and_never_itself_unfreezes_recovery() {
    let (root, mut seq, key, mut watch) = pulse_fixture(Activity::Idle);
    let old_probe = watch.probe(50).unwrap();
    let old = Pulse::respond(&root, &seq, &old_probe, [9; 32], Activity::Idle, 1, &key).unwrap();
    let promotion = seq.promote(&key).unwrap();
    watch.promote(&promotion, 60).unwrap();
    assert_eq!(watch.status(60).unwrap(), WatchStatus::Recovering);
    assert!(watch.pulse(&old, 61).is_err());
    assert!(watch.promote(&promotion, 62).is_err());
    let probe = watch.probe(100).unwrap();
    assert_eq!(probe.term, 1);
    let pulse = Pulse::respond(&root, &seq, &probe, [9; 32], Activity::Idle, 2, &key).unwrap();
    watch.pulse(&pulse, 100).unwrap();
    watch.set_activity(Activity::Idle).unwrap();
    assert_eq!(watch.status(5059).unwrap(), WatchStatus::Recovering);
    assert_eq!(watch.status(5060).unwrap(), WatchStatus::Paused);
    assert!(watch.set_activity(Activity::Recovering).is_err());
    assert!(Pulse::respond(&root, &seq, &probe, [9; 32], Activity::Idle, 0, &key).is_err());
}

#[test]
fn periodic_probes_allow_responses_with_longer_than_one_probe_interval_rtt() {
    for rtt in [100, 150] {
        let (root, seq, key, mut watch) = pulse_fixture(Activity::Idle);
        let mut inflight = std::collections::VecDeque::new();
        for now in (0..=1000).step_by(50) {
            let probe = watch.probe(now).unwrap();
            let pulse = Pulse::respond(
                &root,
                &seq,
                &probe,
                [9; 32],
                Activity::Idle,
                probe.sequence,
                &key,
            )
            .unwrap();
            inflight.push_back((now + rtt, pulse));
            while inflight.front().is_some_and(|(due, _)| *due <= now) {
                let (_, pulse) = inflight.pop_front().unwrap();
                watch.pulse(&pulse, now).unwrap();
                assert!(watch.pulse(&pulse, now).is_err());
            }
            assert_eq!(watch.status(now).unwrap(), WatchStatus::Live);
        }
    }
}

#[test]
fn standby_primary_watch_accepts_fresh_responses_but_replay_cannot_delay_fencing() {
    let (descriptor, host_key, standby_key, _) = descriptor_fixture();
    let root = descriptor.root;
    let mut seq = Sequencer::arm(
        root.context().unwrap(),
        vec![0],
        100,
        marks(0, 0),
        &standby_key,
    )
    .unwrap();
    let primary = Primary::armed(
        root.context().unwrap(),
        seq.image().to_vec(),
        seq.receipt().clone(),
    )
    .unwrap();
    let mut watch = PrimaryWatch::new(root.clone(), &seq, [3; 32], 0).unwrap();
    let first = watch.probe(0).unwrap();
    assert!(PrimaryAlive::respond(&root, &primary, &first, [4; 32], 1, &host_key).is_err());
    let response = PrimaryAlive::respond(&root, &primary, &first, [3; 32], 1, &host_key).unwrap();
    assert_eq!(
        PrimaryAlive::decode(&root, &response.encode(&root).unwrap()).unwrap(),
        response
    );
    watch.probe(50).unwrap();
    watch.probe(100).unwrap();
    watch.response(&seq, &response, 150).unwrap();
    assert!(!watch.expired(&seq, 349).unwrap());
    assert!(watch.response(&seq, &response, 350).is_err());
    assert!(watch.expired(&seq, 350).unwrap());
    let staged = seq
        .stage(seq.next(vec![1], 150, marks(0, 0), vec![]).unwrap())
        .unwrap();
    let promotion = seq.promote(&standby_key).unwrap();
    assert_eq!(promotion.final_receipt.index, 0);
    assert_eq!(seq.install(staged, &standby_key), Err(Error::Closed));
    assert_eq!(watch.response(&seq, &response, 351), Err(Error::Closed));
}

#[test]
fn only_new_installed_proposals_refresh_primary_freshness_and_close_is_atomic() {
    let (descriptor, _, key, _) = descriptor_fixture();
    let root = descriptor.root;
    let mut seq = Sequencer::arm(root.context().unwrap(), vec![0], 100, marks(0, 0), &key).unwrap();
    let mut watch = PrimaryWatch::new(root, &seq, [3; 32], 0).unwrap();
    let candidate = seq.next(vec![1], 150, marks(0, 0), vec![]).unwrap();
    let staged = seq.stage(candidate.clone()).unwrap();
    // Validated but uninstalled work has no effect on failure detection.
    watch.installed(&seq, 199).unwrap();
    assert!(watch.expired(&seq, 200).unwrap());
    seq.install(staged, &key).unwrap();
    watch.installed(&seq, 200).unwrap();
    assert!(!watch.expired(&seq, 399).unwrap());
    let duplicate = seq.stage(candidate).unwrap();
    seq.install(duplicate, &key).unwrap();
    watch.installed(&seq, 400).unwrap();
    assert!(watch.expired(&seq, 400).unwrap());
    let promotion = seq.promote(&key).unwrap();
    assert_eq!(promotion.final_receipt.index, 1);

    let (_, _, key, _, standby, _) = replication_actors();
    let (recovery, _) = standby.begin_recovery(&key, 2, true).unwrap();
    assert_eq!(recovery.phase(), RecoveryPhase::Collecting);
    assert_eq!(recovery.promotion().final_receipt.index, 0);
}

#[test]
fn buffered_same_clock_receipts_cannot_replace_fresh_idle_challenges() {
    let (_, mut seq, key, mut watch) = pulse_fixture(Activity::Idle);
    for (index, now) in [150, 300, 450].into_iter().enumerate() {
        let candidate = seq
            .next(vec![index as u8], 100, marks(0, 0), vec![])
            .unwrap();
        let staged = seq.stage(candidate).unwrap();
        seq.install(staged, &key).unwrap();
        watch.committed(seq.receipt(), now).unwrap();
    }
    assert_eq!(watch.status(450).unwrap(), WatchStatus::Paused);
}

fn activation_wire_pair(
    size: usize,
) -> (
    Descriptor,
    Keys,
    Keys,
    Keys,
    SessionImage,
    ActivationSource,
    ActivationSink,
) {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = &descriptor.root;
    let image =
        SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0; size], 1, 100).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let sending = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.standby,
        [7; 32],
    )
    .unwrap();
    let receiving =
        Channel::new(&policy, binding, ChannelSide::Server, root.host, [7; 32]).unwrap();
    let source = ActivationSource::new(descriptor.clone(), image.clone(), sending, 0).unwrap();
    let sink = ActivationSink::new(descriptor.clone(), receiving, 0).unwrap();
    (descriptor, host, key, player, image, source, sink)
}

#[test]
fn frozen_activation_transfers_only_to_consented_pair_and_keeps_channel_counters() {
    let (descriptor, host, key, player, image, mut source, mut sink) =
        activation_wire_pair(128 * 1024);
    let root = &descriptor.root;
    let initial = source.initial_hash().unwrap();
    assert!(!sink.ready());
    assert!(CapabilityAck::sign(root, 3, initial, 1, &player).is_err());
    let first = CapabilityAck::sign(root, 1, initial, 1, &host).unwrap();
    source.acknowledge(first.clone(), 0).unwrap();
    source.acknowledge(first, 0).unwrap();
    source
        .acknowledge(
            CapabilityAck::sign(root, 2, initial, 1, &player).unwrap(),
            0,
        )
        .unwrap();
    let mut frames = 0;
    let mut last = 0;
    for now in 0..500 {
        while let Some(wire) = source.poll_send(now).unwrap() {
            let frame = Frame::decode(&wire).unwrap();
            assert!(wire.len() <= 1024);
            if frames == 0 {
                assert_eq!(frame.kind, PacketKind::Control);
            }
            frames += 1;
            sink.receive(&wire, now).unwrap();
        }
        last = now;
        if sink.ready() {
            break;
        }
    }
    assert!(sink.ready());
    assert!(frames > 128);
    assert!(last > 0);
    let mut attempts = 0;
    let (seq, armed, mut server) = sink
        .arm(&key, last, |bytes| {
            attempts += 1;
            assert_eq!(SessionImage::decode(root, bytes).unwrap(), image);
            if attempts == 1 {
                return Err(Error::Invalid("transient native restore"));
            }
            Ok(bytes.to_vec())
        })
        .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(seq.image(), image.encode(root).unwrap());
    assert_eq!(armed.receipt.index, 0);
    let mut accepted = false;
    while let Some(wire) = server.poll_send(last).unwrap() {
        accepted |= source.receive(&wire, last).unwrap();
    }
    assert!(accepted);
    let (primary, client) = source.finish(last).unwrap();
    let mut original =
        PrimaryActor::new(descriptor.clone(), primary, client, Activity::Idle, last).unwrap();
    let mut standby = StandbyActor::new(descriptor.clone(), seq, server, last).unwrap();
    let mut post = image;
    post.game[0] = 1;
    post.logical_ms += 16;
    original
        .prepare(
            post.clone(),
            original.primary().receipt().watermarks.clone(),
            vec![],
        )
        .unwrap();
    let mut installed = false;
    for now in last..last + 500 {
        while let Some(wire) = original.poll_send(now).unwrap() {
            assert!(
                Frame::decode(&wire).unwrap().transfer > 3,
                "initial transfer and both ACK cursors must survive"
            );
            installed |= standby
                .receive(&wire, now, &key, Activity::Advancing, |candidate, _, _| {
                    Ok(candidate.image.clone())
                })
                .unwrap()
                .is_some();
        }
        if installed {
            last = now;
            break;
        }
    }
    assert!(installed);
    let mut acknowledged = false;
    while let Some(wire) = standby.poll_send(last).unwrap() {
        assert!(
            Frame::decode(&wire).unwrap().transfer > 1,
            "Armed framing cursor must survive"
        );
        acknowledged |= matches!(
            original.receive(&wire, last, &host).unwrap(),
            Some(PrimaryEvent::Committed { .. })
        );
    }
    assert!(acknowledged);
    assert_eq!(
        original.primary().committed_image(),
        post.encode(root).unwrap()
    );
    // A roster warm control channel has no authority-image transfer privilege.
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let client = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.standby,
        [8; 32],
    )
    .unwrap();
    assert!(ActivationSource::new(descriptor.clone(), post.clone(), client, 0).is_err());
    let mut server = Channel::new(
        &policy,
        binding,
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [8; 32],
    )
    .unwrap();
    for frame in Frame::split(
        root.session,
        0,
        1,
        PacketKind::InitialImage,
        &post.encode(root).unwrap(),
    )
    .unwrap()
    .into_iter()
    .take(1)
    {
        assert_eq!(
            server.receive(&frame.encode().unwrap(), 0),
            Err(Error::Unauthorized)
        );
    }
}

#[test]
fn activation_restore_wall_cost_cannot_overrun_the_original_arming_deadline() {
    let (descriptor, host, key, player, _, mut source, mut sink) = activation_wire_pair(1);
    let initial = source.initial_hash().unwrap();
    for (id, signer) in [(1, &host), (2, &player)] {
        source
            .acknowledge(
                CapabilityAck::sign(&descriptor.root, id, initial, 1, signer).unwrap(),
                0,
            )
            .unwrap();
    }
    while let Some(wire) = source.poll_send(0).unwrap() {
        sink.receive(&wire, 0).unwrap();
    }
    assert!(sink.ready());
    let mut attempts = 0;
    let result = sink.arm(&key, 4990, |bytes| {
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(20));
        Ok(bytes.to_vec())
    });
    assert!(matches!(result, Err(Error::Closed)));
    assert_eq!(attempts, 1);
}

#[test]
fn activation_sink_polls_expire_quiet_partial_transfers_and_the_original_deadline() {
    let (_, _, key, _, _, _, mut empty) = activation_wire_pair(1);
    assert_eq!(empty.poll(4999), Ok(()));
    assert_eq!(empty.poll(5000), Err(Error::Closed));
    assert!(matches!(
        empty.arm(&key, 5000, |bytes| Ok(bytes.to_vec())),
        Err(Error::Closed)
    ));
    let (_, _, _, _, _, mut source, mut partial) = activation_wire_pair(4096);
    let first = source.poll_send(0).unwrap().unwrap();
    assert_eq!(
        Frame::decode(&first).unwrap().kind,
        PacketKind::InitialImage
    );
    assert!(!partial.receive(&first, 0).unwrap());
    assert_eq!(partial.poll(499), Ok(()));
    assert_eq!(partial.poll(500), Err(Error::Stale));
    assert!(!partial.ready());
}

#[test]
fn activation_native_restore_cannot_hide_expiry_of_another_partial_control() {
    let (descriptor, host, key, player, _, mut source, mut sink) = activation_wire_pair(1);
    let root = &descriptor.root;
    let initial = source.initial_hash().unwrap();
    for (id, signer) in [(1, &host), (2, &player)] {
        source
            .acknowledge(
                CapabilityAck::sign(root, id, initial, 1, signer).unwrap(),
                0,
            )
            .unwrap();
    }
    let mut highest = 0;
    while let Some(wire) = source.poll_send(0).unwrap() {
        highest = highest.max(Frame::decode(&wire).unwrap().transfer);
        sink.receive(&wire, 0).unwrap();
    }
    assert!(sink.ready());
    let partial = Frame::split(
        root.session,
        0,
        highest + 1,
        PacketKind::Control,
        &[0; 2048],
    )
    .unwrap();
    sink.receive(&partial[0].encode().unwrap(), 0).unwrap();
    let result = sink.arm(&key, 490, |bytes| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        Ok(bytes.to_vec())
    });
    assert!(matches!(result, Err(Error::Stale)));
}

#[test]
fn activation_retries_cross_normal_actor_handoff_without_native_work_or_liveness() {
    for case in ["exact", "unknown", "conflict"] {
        let (descriptor, host, key, player, mut image, mut source, mut sink) =
            activation_wire_pair(1);
        let root = &descriptor.root;
        let initial = source.initial_hash().unwrap();
        let ack = CapabilityAck::sign(root, 1, initial, 1, &host).unwrap();
        source.acknowledge(ack.clone(), 0).unwrap();
        source
            .acknowledge(
                CapabilityAck::sign(root, 2, initial, 1, &player).unwrap(),
                0,
            )
            .unwrap();
        while let Some(wire) = source.poll_send(0).unwrap() {
            sink.receive(&wire, 0).unwrap();
        }
        let (seq, armed, mut server) = sink.arm(&key, 0, |bytes| Ok(bytes.to_vec())).unwrap();
        while let Some(wire) = server.poll_send(0).unwrap() {
            source.receive(&wire, 0).unwrap();
        }
        assert_eq!(source.armed(), Some(&armed));
        let (primary, mut client) = source.finish(0).unwrap();
        let retry = match case {
            "unknown" => CapabilityAck::sign(root, 1, initial, 99, &host).unwrap(),
            "conflict" => CapabilityAck::sign(root, 1, [42; 32], 1, &host).unwrap(),
            _ => ack,
        };
        client
            .enqueue(PacketKind::Control, &retry.encode(root).unwrap())
            .unwrap();
        server
            .enqueue(
                PacketKind::Control,
                &armed.encode(&root.context().unwrap()).unwrap(),
            )
            .unwrap();
        let mut original =
            PrimaryActor::new(descriptor.clone(), primary, client, Activity::Idle, 0).unwrap();
        let mut replica = StandbyActor::new(descriptor.clone(), seq, server, 0).unwrap();
        let before = replica.receipt().clone();
        let wire = original.poll_send(0).unwrap().unwrap();
        let result = replica.receive(&wire, 1000, &key, Activity::Idle, |_, _, _| {
            panic!("obsolete ACK cannot restore/tick")
        });
        match case {
            "unknown" => {
                assert_eq!(result, Err(Error::Unauthorized));
                continue;
            }
            "conflict" => {
                assert_eq!(result, Err(Error::Conflict));
                assert_eq!(replica.poll_send(1000), Err(Error::Closed));
                continue;
            }
            _ => assert_eq!(result, Ok(None)),
        }
        assert_eq!(replica.receipt(), &before);
        assert!(replica.expired(1000).unwrap());
        while let Some(wire) = replica.poll_send(1000).unwrap() {
            assert_eq!(original.receive(&wire, 1000, &host).unwrap(), None);
        }
        assert_eq!(original.primary().receipt(), &before);
        assert_eq!(original.status(1000).unwrap(), WatchStatus::Paused);
        // The retained initial framing and sender namespaces can still commit
        // a real next batch after obsolete controls have drained.
        image.logical_ms += 16;
        image.game[0] = 1;
        original
            .prepare(image.clone(), before.watermarks, vec![])
            .unwrap();
        let mut installed = false;
        while let Some(wire) = original.poll_send(1000).unwrap() {
            installed |= replica
                .receive(&wire, 1000, &key, Activity::Advancing, |candidate, _, _| {
                    Ok(candidate.image.clone())
                })
                .unwrap()
                .is_some();
        }
        assert!(installed);
        let mut committed = false;
        while let Some(wire) = replica.poll_send(1000).unwrap() {
            committed |= matches!(
                original.receive(&wire, 1000, &host).unwrap(),
                Some(PrimaryEvent::Committed { .. })
            );
        }
        assert!(committed);
        assert_eq!(
            original.primary().committed_image(),
            image.encode(root).unwrap()
        );
    }
}

#[test]
fn actual_quic_activation_stream_hands_the_same_live_channels_to_replication() {
    use fray_net::{Bytes, ClientEvent, HostEvent, Identity, NetConfig};
    let host = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.host = host.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.members[0].key = Some(root.host);
    root.members[1].key = Some(player.pubkey().to_bytes());
    let mut descriptor = Descriptor::offer(root.clone(), host.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let mut cfg = NetConfig::new(std::env::temp_dir(), root.app.clone()).lan_only();
    cfg.lan_port = 0;
    let listener = fray_net::host_standby(&cfg, &standby, "ABCDEF", descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let client = fray_net::join_session_addr(
        &cfg,
        &host,
        addr,
        &listener.lan_token(),
        binding,
        standby.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&client));
    let started = std::time::Instant::now();
    let peer = loop {
        if let Some(HostEvent::PeerJoined { peer, pubkey, .. }) = listener.poll() {
            assert_eq!(pubkey, host.pubkey());
            break peer;
        }
        assert!(started.elapsed().as_secs() < 5);
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let sending = client.migration_channel(&policy).unwrap();
    let receiving = listener.migration_channel(peer).unwrap();
    assert_eq!(sending.tls(), receiving.tls());
    let image = SessionImage::initial(
        &root,
        &[(1, 10), (2, 11), (3, 12)],
        vec![0; 128 * 1024],
        1,
        100,
    )
    .unwrap();
    let mut source = ActivationSource::new(descriptor.clone(), image.clone(), sending, 0).unwrap();
    let mut sink = ActivationSink::new(descriptor.clone(), receiving, 0).unwrap();
    for (id, identity) in [(1, &host), (2, &player)] {
        source
            .acknowledge(
                CapabilityAck::sign(
                    &root,
                    id,
                    source.initial_hash().unwrap(),
                    1,
                    identity.keys(),
                )
                .unwrap(),
                0,
            )
            .unwrap();
    }
    let started = std::time::Instant::now();
    let mut ingress = ReceiveQueue::default();
    loop {
        let now = started.elapsed().as_millis() as u64;
        assert!(now < 5000);
        while let Some(wire) = source.poll_send(now).unwrap() {
            client.send_reliable(Bytes::from(wire));
        }
        while let Some(event) = listener.poll() {
            if let HostEvent::Reliable { peer: id, bytes } = event {
                assert_eq!(peer, id);
                ingress.enqueue(bytes.to_vec()).unwrap();
            }
        }
        while ingress
            .poll(|wire| sink.receive(wire, now))
            .unwrap()
            .is_some()
        {}
        if sink.ready() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let now = started.elapsed().as_millis() as u64;
    let (seq, _, mut server) = sink
        .arm(standby.keys(), now, |bytes| Ok(bytes.to_vec()))
        .unwrap();
    let mut accepted = false;
    while !accepted {
        let now = started.elapsed().as_millis() as u64;
        assert!(now < 5000);
        while let Some(wire) = server.poll_send(now).unwrap() {
            listener.send_reliable(peer, Bytes::from(wire));
        }
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                accepted |= source.receive(&bytes, now).unwrap();
            }
        }
        if !accepted {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    let now = started.elapsed().as_millis() as u64;
    let (primary, sending) = source.finish(now).unwrap();
    let mut original =
        PrimaryActor::new(descriptor.clone(), primary, sending, Activity::Idle, now).unwrap();
    let mut replica = StandbyActor::new(descriptor, seq, server, now).unwrap();
    let mut post = image;
    post.game[0] = 1;
    post.logical_ms += 16;
    original
        .prepare(
            post.clone(),
            original.primary().receipt().watermarks.clone(),
            vec![],
        )
        .unwrap();
    let mut committed = false;
    let mut delta_frames = 0;
    while !committed {
        let now = started.elapsed().as_millis() as u64;
        assert!(now < 5000);
        while let Some(wire) = original.poll_send(now).unwrap() {
            assert_eq!(Frame::decode(&wire).unwrap().kind, PacketKind::Delta);
            delta_frames += 1;
            client.send_reliable(Bytes::from(wire));
        }
        while let Some(event) = listener.poll() {
            if let HostEvent::Reliable { peer: id, bytes } = event {
                assert_eq!(id, peer);
                ingress.enqueue(bytes.to_vec()).unwrap();
            }
        }
        while ingress
            .poll(|wire| {
                replica.receive(
                    wire,
                    now,
                    standby.keys(),
                    Activity::Advancing,
                    |candidate, _, _| Ok(candidate.image.clone()),
                )
            })
            .unwrap()
            .is_some()
        {}
        while let Some(wire) = replica.poll_send(now).unwrap() {
            listener.send_reliable(peer, Bytes::from(wire));
        }
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                committed |= matches!(
                    original.receive(&bytes, now, host.keys()).unwrap(),
                    Some(PrimaryEvent::Committed { .. })
                );
            }
        }
        if !committed {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    assert_eq!(
        original.primary().committed_image(),
        post.encode(&root).unwrap()
    );
    assert_eq!(replica.image(), original.primary().committed_image());
    assert!(delta_frames > 0 && delta_frames < 8);
    assert_eq!(listener.code(), "ABCDEF");
    client.shutdown();
    listener.shutdown();
}

#[test]
fn incomplete_failed_and_expired_activation_cannot_produce_an_armed_authority() {
    for case in ["missing", "restore", "timeout", "clock", "bad_hash"] {
        let (descriptor, host, key, player, _, mut source, mut sink) = activation_wire_pair(1);
        let root = &descriptor.root;
        let initial = source.initial_hash().unwrap();
        source
            .acknowledge(CapabilityAck::sign(root, 1, initial, 1, &host).unwrap(), 0)
            .unwrap();
        if case != "missing" {
            source
                .acknowledge(
                    CapabilityAck::sign(root, 2, initial, 1, &player).unwrap(),
                    0,
                )
                .unwrap();
        }
        while let Some(wire) = source.poll_send(0).unwrap() {
            sink.receive(&wire, 0).unwrap();
        }
        if case == "bad_hash" {
            assert!(source
                .acknowledge(
                    CapabilityAck::sign(root, 2, [42; 32], 2, &player).unwrap(),
                    0
                )
                .is_err());
            continue;
        }
        let now = if case == "timeout" { 5000 } else { 0 };
        if case == "clock" {
            source.poll_send(1).unwrap();
            assert!(source.poll_send(0).is_err());
            assert!(source.poll_send(2).is_err());
            continue;
        }
        let mut attempts = 0;
        let result = sink.arm(&key, now, |bytes| {
            attempts += 1;
            if case == "restore" {
                Err(Error::Invalid("persistent restore"))
            } else {
                Ok(bytes.to_vec())
            }
        });
        assert!(result.is_err(), "armed {case}");
        assert_eq!(attempts, if case == "restore" { 2 } else { 0 });
        if case == "timeout" {
            assert!(source.poll_send(now).is_err());
            assert!(source.poll_send(now + 1).is_err());
        }
    }
}

fn replication_actors_with_player() -> (
    Root,
    Keys,
    Keys,
    PrimaryActor,
    StandbyActor,
    SessionImage,
    Keys,
) {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let primary = Primary::armed(
        root.context().unwrap(),
        seq.image().to_vec(),
        seq.receipt().clone(),
    )
    .unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let client = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.standby,
        [7; 32],
    )
    .unwrap();
    let server = Channel::new(&policy, binding, ChannelSide::Server, root.host, [7; 32]).unwrap();
    let original =
        PrimaryActor::new(descriptor.clone(), primary, client, Activity::Advancing, 0).unwrap();
    let standby = StandbyActor::new(descriptor, seq, server, 0).unwrap();
    (root, host, key, original, standby, image, player)
}
fn replication_actors() -> (Root, Keys, Keys, PrimaryActor, StandbyActor, SessionImage) {
    let (root, host, key, original, standby, image, _) = replication_actors_with_player();
    (root, host, key, original, standby, image)
}

#[test]
fn authority_and_human_sender_ids_share_activation_links_and_promotion_without_resigning() {
    let (fixture, host, standby, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.members[1].key = Some(root.standby);
    let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&standby).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let client = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.standby,
        [7; 32],
    )
    .unwrap();
    let server = Channel::new(&policy, binding, ChannelSide::Server, root.host, [7; 32]).unwrap();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut source = ActivationSource::new(descriptor.clone(), image.clone(), client, 0).unwrap();
    let mut sink = ActivationSink::new(descriptor.clone(), server, 0).unwrap();
    let initial = source.initial_hash().unwrap();
    let human = CapabilityAck::sign(&root, 2, initial, 11, &standby).unwrap();
    source
        .acknowledge(CapabilityAck::sign(&root, 1, initial, 7, &host).unwrap(), 0)
        .unwrap();
    source.acknowledge(human.clone(), 0).unwrap();
    while let Some(wire) = source.poll_send(0).unwrap() {
        sink.receive(&wire, 0).unwrap();
    }
    let (seq, armed, mut server) = sink.arm(&standby, 0, |bytes| Ok(bytes.to_vec())).unwrap();
    while let Some(wire) = server.poll_send(0).unwrap() {
        source.receive(&wire, 0).unwrap();
    }
    let (primary, client) = source.finish(0).unwrap();
    let certificate = seq.membership_certificate(&standby).unwrap();
    let certificate_bytes = certificate.encode(&root).unwrap();
    assert_eq!(
        seq.membership_certificate(&standby)
            .unwrap()
            .encode(&root)
            .unwrap(),
        certificate_bytes
    );
    let mut ids = vec![seq.receipt().sequence, certificate.sequence, armed.sequence];
    assert!(ids[0] > human.sequence && ids.windows(2).all(|pair| pair[0] < pair[1]));
    let shared = seq.sender_sequence();
    let normal_policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let normal_binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let normal_client = Channel::new_bound(
        &normal_policy,
        normal_binding.clone(),
        ChannelSide::Client,
        root.standby,
        root.host,
        [8; 32],
    )
    .unwrap();
    let mut normal_server = Channel::new(
        &normal_policy,
        normal_binding,
        ChannelSide::Server,
        root.standby,
        [8; 32],
    )
    .unwrap();
    let mut human_endpoint = PlayerEndpoint::new_with_sender(
        descriptor.clone(),
        &armed,
        &human,
        certificate,
        normal_client,
        standby.clone(),
        shared.clone(),
    )
    .unwrap();
    human_endpoint.queue_view(vec![1]).unwrap();
    while let Some(wire) = human_endpoint.poll_send(0).unwrap() {
        if let Some((_, _, bytes)) = normal_server.receive(&wire, 0).unwrap() {
            ids.push(PlayerControl::decode(&root, &bytes).unwrap().sequence);
        }
    }
    let mut original =
        PrimaryActor::new(descriptor.clone(), primary, client, Activity::Idle, 0).unwrap();
    let mut replica = StandbyActor::new(descriptor, seq, server, 0).unwrap();
    replica.probe(0).unwrap();
    while let Some(wire) = replica.poll_send(0).unwrap() {
        let frame = Frame::decode(&wire).unwrap();
        assert_eq!(frame.count, 1);
        ids.push(PulseProbe::decode(&root, &frame.payload).unwrap().sequence);
        original.receive(&wire, 0, &host).unwrap();
        let mut retry = frame;
        retry.transfer += 1000;
        original
            .receive(&retry.encode().unwrap(), 0, &host)
            .unwrap();
    }
    let mut alive_responses = 0;
    while let Some(wire) = original.poll_send(0).unwrap() {
        alive_responses += 1;
        let frame = Frame::decode(&wire).unwrap();
        assert!(
            PrimaryAlive::decode(&root, &frame.payload)
                .unwrap()
                .sequence
                > 7
        );
        replica
            .receive(&wire, 0, &standby, Activity::Idle, |_, _, _| {
                panic!("probe is not a game batch")
            })
            .unwrap();
    }
    assert_eq!(alive_responses, 1);
    original.probe(0).unwrap();
    while let Some(wire) = original.poll_send(0).unwrap() {
        replica
            .receive(&wire, 0, &standby, Activity::Idle, |_, _, _| {
                panic!("probe is not a game batch")
            })
            .unwrap();
        let mut retry = Frame::decode(&wire).unwrap();
        retry.transfer += 1000;
        replica
            .receive(
                &retry.encode().unwrap(),
                0,
                &standby,
                Activity::Idle,
                |_, _, _| panic!("duplicate probe is not a game batch"),
            )
            .unwrap();
    }
    let mut pulse_responses = 0;
    while let Some(wire) = replica.poll_send(0).unwrap() {
        pulse_responses += 1;
        let frame = Frame::decode(&wire).unwrap();
        ids.push(Pulse::decode(&root, &frame.payload).unwrap().sequence);
        original.receive(&wire, 0, &host).unwrap();
    }
    assert_eq!(pulse_responses, 1);
    let (mut recovery, _) = replica.begin_recovery(&standby, 0, true).unwrap();
    ids.push(recovery.promotion().sequence);
    let challenge = recovery
        .challenge(1, [9; 32], 1, root.host, &standby, 0)
        .unwrap();
    ids.push(challenge.sequence);
    ids.push(shared.allocate().unwrap());
    ids.push(human_endpoint.sequence().allocate().unwrap());
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
    assert_eq!(
        recovery
            .sequencer()
            .membership_certificate(&standby)
            .unwrap()
            .encode(&root)
            .unwrap(),
        certificate_bytes
    );
}

#[test]
fn delta_codec_binds_context_exact_base_and_target_and_rejects_noncanonical_lengths() {
    let (context, _) = pair();
    let base = vec![3; 200_000];
    let mut candidate = Candidate {
        sequence: 1,
        term: 0,
        index: 1,
        parent: [5; 32],
        logical_ms: 50,
        image: base.clone(),
        watermarks: marks(0, 0),
        outputs: vec![output(1)],
    };
    candidate.image.splice(1000..1002, [4, 5, 6]);
    candidate.image[190_000] = 7;
    let delta = CandidateDelta::between(&base, &candidate).unwrap();
    let wire = delta.encode(&context).unwrap();
    assert!(wire.len() < 2048);
    assert_eq!(CandidateDelta::decode(&context, &wire).unwrap(), delta);
    assert_eq!(
        delta.expand(&base).unwrap().encode(&context).unwrap(),
        candidate.encode(&context).unwrap()
    );
    assert!(delta.expand(&vec![4; base.len()]).is_err());
    let mut wrong = context.clone();
    wrong.descriptor[0] ^= 1;
    assert!(CandidateDelta::decode(&wrong, &wire).is_err());
    for length in [0, 1, wire.len() - 1] {
        assert!(CandidateDelta::decode(&context, &wire[..length]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(CandidateDelta::decode(&context, &trailing).is_err());
    let mut corrupt = delta.clone();
    corrupt.patch.target[0] ^= 1;
    assert!(corrupt.expand(&base).is_err());
    let mut oversized = delta;
    oversized.outputs = vec![output(1); MAX_BATCH + 1];
    assert_eq!(oversized.encode(&context), Err(Error::Bounds));
}

#[test]
fn delta_replication_retries_after_lost_ack_materializes_before_receipt_and_periodically_sends_full(
) {
    fn run(attack: Option<u64>) {
        let (root, host, key, mut original, mut standby, mut image) = replication_actors();
        let mut wire_ms = 0;
        let mut ingress = ReceiveQueue::default();
        // The first large update cannot fit a patch. Later shifts and distant edits
        // should be compact, until the full-image interval reaches 250 game ms.
        image.game = vec![3; 200_000];
        for (clock, expected) in [
            (150, PacketKind::Candidate),
            (166, PacketKind::Delta),
            (399, PacketKind::Delta),
            (400, PacketKind::Candidate),
            (416, PacketKind::Delta),
        ] {
            image.logical_ms = clock;
            image.game.splice(1000..1002, [clock as u8, 5, 6]);
            image.game[190_000] = clock as u8;
            original
                .prepare(
                    image.clone(),
                    original.primary().receipt().watermarks.clone(),
                    vec![],
                )
                .unwrap();
            let pending = original.primary().pending().unwrap().clone();
            let mut kinds = Vec::new();
            let mut bytes = 0;
            while standby.receipt().index < pending.index {
                while let Some(wire) = original.poll_send(wire_ms).unwrap() {
                    bytes += wire.len();
                    assert!(wire.len() <= 1024);
                    kinds.push(Frame::decode(&wire).unwrap().kind);
                    ingress.enqueue(wire).unwrap();
                }
                while ingress
                    .poll(|wire| {
                        standby.receive(
                            wire,
                            wire_ms,
                            &key,
                            Activity::Advancing,
                            |candidate, decoded, _| {
                                assert_eq!(candidate.image, image.encode(&root).unwrap());
                                assert_eq!(decoded.game, image.game);
                                Ok(candidate.image.clone())
                            },
                        )
                    })
                    .unwrap()
                    .is_some()
                {}
                wire_ms += 1;
                assert!(wire_ms < 1000);
            }
            assert!(!kinds.is_empty());
            assert!(kinds.iter().all(|kind| *kind == expected));
            if expected == PacketKind::Delta {
                assert!(bytes < 4096);
            }
            assert_eq!(standby.image(), image.encode(&root).unwrap());
            assert_eq!(
                original.primary().receipt().index + 1,
                standby.receipt().index
            );
            if clock == 166 {
                let receipt = standby.receipt().clone();
                // Lose the receipt, not the installed image. Retrying the delta
                // against that image must not apply its edits for a second time.
                while standby.poll_send(wire_ms).unwrap().is_some() {}
                // Matching index/target is not enough: only the exact installed
                // delta may be re-ACKed, even if another patch yields that target.
                if let Some(attack) = attack {
                    let mut delta =
                        CandidateDelta::between(original.primary().committed_image(), &pending)
                            .unwrap();
                    match attack {
                        0 => delta.patch.base[0] ^= 1,
                        1 => delta.parent[0] ^= 1,
                        _ => {
                            delta.patch =
                                BytePatch::between(standby.image(), standby.image()).unwrap()
                        }
                    }
                    let bytes = delta.encode(&root.context().unwrap()).unwrap();
                    let mut frames =
                        Frame::split(root.session, 0, 100 + attack, PacketKind::Delta, &bytes)
                            .unwrap();
                    for frame in &mut frames {
                        frame.candidate = Some(CandidateManifest {
                            descriptor: root.digest().unwrap(),
                            schema: root.checkpoint_version,
                            index: delta.index,
                            base: delta.parent,
                            target: delta.patch.target,
                        });
                    }
                    let mut rejected = false;
                    for frame in frames {
                        match standby.receive(
                            &frame.encode().unwrap(),
                            wire_ms,
                            &key,
                            Activity::Advancing,
                            |_, _, _| panic!("changed duplicate must not reach native validation"),
                        ) {
                            Ok(None) => {}
                            Err(Error::Conflict) => rejected = true,
                            other => panic!("unexpected duplicate delta result: {other:?}"),
                        }
                    }
                    assert!(rejected);
                    assert_eq!(standby.receipt(), &receipt);
                    assert!(matches!(standby.poll_send(wire_ms), Err(Error::Closed)));
                    assert!(matches!(
                        standby.begin_recovery(&key, wire_ms, true),
                        Err(Error::Closed)
                    ));
                    return;
                }
                original.retry().unwrap();
                let mut repeated = false;
                while !repeated {
                    while let Some(wire) = original.poll_send(wire_ms).unwrap() {
                        assert_eq!(Frame::decode(&wire).unwrap().kind, PacketKind::Delta);
                        ingress.enqueue(wire).unwrap();
                    }
                    while let Some(receipt) = ingress
                        .poll(|wire| {
                            standby.receive(wire, wire_ms, &key, Activity::Advancing, |_, _, _| {
                                panic!(
                                    "identical installed delta retry must not restore native state"
                                )
                            })
                        })
                        .unwrap()
                    {
                        repeated |= receipt.is_some();
                    }
                    wire_ms += 1;
                    assert!(wire_ms < 1000);
                }
                assert!(repeated);
                assert_eq!(standby.receipt(), &receipt);
                assert_eq!(standby.image(), image.encode(&root).unwrap());
            }
            let mut committed = 0;
            while let Some(wire) = standby.poll_send(wire_ms).unwrap() {
                if matches!(
                    original.receive(&wire, wire_ms, &host).unwrap(),
                    Some(PrimaryEvent::Committed { .. })
                ) {
                    committed += 1;
                }
            }
            assert_eq!(committed, 1);
            original
                .claim_adoption(&original.primary().receipt().clone())
                .unwrap();
        }
        let final_image = standby.image().to_vec();
        let (recovery, _) = standby.begin_recovery(&key, wire_ms, true).unwrap();
        assert_eq!(recovery.sequencer().image(), final_image);
        assert_eq!(recovery.logical_ms(), 416);
    }
    for attack in [None, Some(0), Some(1), Some(2)] {
        run(attack);
    }
}

#[test]
fn recovery_security_age_includes_pre_promotion_stall_and_ignores_ack_only_commits() {
    let (_, host, key, mut original, mut standby, mut image) = replication_actors();
    for (now, clock) in [(10, 150), (100, 150)] {
        image.logical_ms = clock;
        image.game = vec![now as u8];
        original
            .prepare(
                image.clone(),
                original.primary().receipt().watermarks.clone(),
                vec![],
            )
            .unwrap();
        while let Some(wire) = original.poll_send(now).unwrap() {
            standby
                .receive(&wire, now, &key, Activity::Advancing, |candidate, _, _| {
                    Ok(candidate.image.clone())
                })
                .unwrap();
        }
        while let Some(wire) = standby.poll_send(now).unwrap() {
            original.receive(&wire, now, &host).unwrap();
        }
        original
            .claim_adoption(&original.primary().receipt().clone())
            .unwrap();
    }
    original.probe(150).unwrap();
    while let Some(wire) = original.poll_send(150).unwrap() {
        standby
            .receive(&wire, 150, &key, Activity::Idle, |_, _, _| {
                panic!("probe is not a commit")
            })
            .unwrap();
    }
    while let Some(wire) = standby.poll_send(150).unwrap() {
        original.receive(&wire, 150, &host).unwrap();
    }
    let (mut recovery, _) = standby.begin_recovery(&key, 200, true).unwrap();
    assert_eq!(recovery.elapsed_ms(), 0);
    assert_eq!(recovery.security_elapsed_ms(), 190);
    recovery.poll(250).unwrap();
    assert_eq!(recovery.elapsed_ms(), 50);
    assert_eq!(recovery.security_elapsed_ms(), 240);
    assert_eq!(recovery.sequencer().receipt().logical_ms, 150);
}

#[test]
fn replication_actors_install_before_receipt_and_publish_exactly_once_after_ack() {
    let (_, host, key, mut original, mut standby, mut image) = replication_actors();
    image.logical_ms = 150;
    image.game = vec![1];
    let marks = original.primary().receipt().watermarks.clone();
    original.prepare(image, marks, vec![output(1)]).unwrap();
    assert_eq!(original.primary().receipt().index, 0);
    while let Some(wire) = original.poll_send(0).unwrap() {
        standby
            .receive(&wire, 0, &key, Activity::Advancing, |candidate, _, _| {
                Ok(candidate.image.clone())
            })
            .unwrap();
    }
    assert_eq!(standby.receipt().index, 1);
    assert_eq!(original.primary().receipt().index, 0);
    let mut published = Vec::new();
    while let Some(wire) = standby.poll_send(0).unwrap() {
        if let Some(PrimaryEvent::Committed { receipt, outputs }) =
            original.receive(&wire, 0, &host).unwrap()
        {
            assert_eq!(receipt, *standby.receipt());
            published.extend(outputs);
        }
    }
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].output, output(1));
    let receipt = original.primary().receipt().clone();
    original.claim_adoption(&receipt).unwrap();
    assert!(original.claim_adoption(&receipt).is_err());
    assert!(original.retry().is_err());
}

#[test]
fn replica_retries_one_restore_fault_without_releasing_uncommitted_effects() {
    let (_, host, key, mut original, mut standby, mut image) = replication_actors();
    image.logical_ms = 150;
    image.game = vec![1];
    original
        .prepare(
            image,
            original.primary().receipt().watermarks.clone(),
            vec![output(1)],
        )
        .unwrap();
    let mut calls = 0;
    while let Some(wire) = original.poll_send(0).unwrap() {
        standby
            .receive(&wire, 0, &key, Activity::Advancing, |candidate, _, _| {
                calls += 1;
                if calls == 1 {
                    Err(Error::Invalid("restore fault"))
                } else {
                    Ok(candidate.image.clone())
                }
            })
            .unwrap();
    }
    assert_eq!(calls, 2);
    assert!(standby.failure().is_none());
    let mut effects = 0;
    while let Some(wire) = standby.poll_send(0).unwrap() {
        if let Some(PrimaryEvent::Committed { outputs, .. }) =
            original.receive(&wire, 0, &host).unwrap()
        {
            effects += outputs.len();
        }
    }
    assert_eq!(effects, 1);
}

#[test]
fn actor_promotion_after_lost_receipt_hands_the_exact_closed_frontier_to_recovery() {
    let (root, host, key, mut original, mut standby, mut image) = replication_actors();
    image.logical_ms = 150;
    image.game = vec![1];
    original
        .prepare(
            image.clone(),
            original.primary().receipt().watermarks.clone(),
            vec![output(1)],
        )
        .unwrap();
    while let Some(wire) = original.poll_send(0).unwrap() {
        standby
            .receive(&wire, 0, &key, Activity::Advancing, |candidate, _, _| {
                Ok(candidate.image.clone())
            })
            .unwrap();
    }
    let mut lost_receipt = Vec::new();
    while let Some(wire) = standby.poll_send(0).unwrap() {
        lost_receipt.push(wire);
    }
    assert!(standby.expired(200).unwrap());
    let (recovery, mut warm) = standby.begin_recovery(&key, 200, false).unwrap();
    assert_eq!(recovery.sequencer().image(), image.encode(&root).unwrap());
    assert_eq!(recovery.promotion().final_receipt.index, 1);
    assert_eq!(recovery.logical_ms(), 150);
    assert_eq!(recovery.phase(), RecoveryPhase::Collecting);
    let promotion = recovery.promotion().clone();
    assert_eq!(
        Promotion::decode(
            &root.context().unwrap(),
            &promotion.encode(&root.context().unwrap()).unwrap()
        )
        .unwrap(),
        promotion
    );
    let mut promoted = false;
    while let Some(wire) = warm.poll_send(200).unwrap() {
        if let Some(PrimaryEvent::Promoted(record)) = original.receive(&wire, 200, &host).unwrap() {
            assert_eq!(record, promotion);
            promoted = true;
        }
    }
    assert!(promoted);
    assert!(original.primary().is_closed());
    assert_eq!(original.status(200).unwrap(), WatchStatus::Recovering);
    for wire in lost_receipt {
        assert!(original.receive(&wire, 201, &host).is_err());
    }
    assert!(original.retry().is_err());
    assert_eq!(recovery.sequencer().outbox().count(), 1);
}

#[test]
fn replica_game_validator_sees_the_full_output_batch_and_persistent_faults_pause() {
    for bad in [
        vec![],
        vec![Output {
            bytes: vec![2],
            ..output(1)
        }],
    ] {
        let (_, _, key, mut original, mut standby, mut image) = replication_actors();
        image.logical_ms = 150;
        image.game = vec![1];
        original
            .prepare(image, original.primary().receipt().watermarks.clone(), bad)
            .unwrap();
        let mut calls = 0;
        while let Some(wire) = original.poll_send(0).unwrap() {
            assert!(standby
                .receive(
                    &wire,
                    0,
                    &key,
                    Activity::Advancing,
                    |candidate, image, _| {
                        calls += 1;
                        assert_eq!(image.game, vec![1]);
                        if candidate.outputs != vec![output(1)] {
                            return Err(Error::Conflict);
                        }
                        Ok(candidate.image.clone())
                    }
                )
                .is_err());
        }
        assert_eq!(calls, 2);
        assert_eq!(standby.receipt().index, 0);
        assert!(standby.failure().is_some());
        assert!(standby.poll_send(0).unwrap().is_none());
        original.retry().unwrap();
        while let Some(wire) = original.poll_send(1).unwrap() {
            assert_eq!(
                standby.receive(&wire, 1, &key, Activity::Advancing, |_, _, _| panic!(
                    "failed replica must not restore again"
                )),
                Err(Error::Closed)
            );
        }
        assert_eq!(standby.probe(50), Err(Error::Closed));
        assert!(standby.begin_recovery(&key, 200, true).is_err());
    }
}

#[test]
fn primary_adoption_error_or_panic_stays_paused_but_can_accept_the_signed_fence() {
    for panic_after_claim in [false, true] {
        let (_, host, key, mut original, mut standby, mut image) = replication_actors();
        image.logical_ms = 150;
        image.game = vec![1];
        original
            .prepare(
                image.clone(),
                original.primary().receipt().watermarks.clone(),
                vec![output(1)],
            )
            .unwrap();
        while let Some(wire) = original.poll_send(0).unwrap() {
            standby
                .receive(&wire, 0, &key, Activity::Advancing, |candidate, _, _| {
                    Ok(candidate.image.clone())
                })
                .unwrap();
        }
        let mut committed = None;
        while let Some(wire) = standby.poll_send(0).unwrap() {
            if let Some(PrimaryEvent::Committed { receipt, .. }) =
                original.receive(&wire, 0, &host).unwrap()
            {
                committed = Some(receipt);
            }
        }
        let receipt = committed.unwrap();
        let mut calls = 0;
        let result: Result<()> = original.adopt(|gate| {
            calls += 1;
            if panic_after_claim {
                gate.claim_adoption(&receipt)?;
                panic!("adoption fault after consuming publication slot");
            }
            Err(Error::Invalid("adoption fault before publication"))
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
        let failure = original.failure().unwrap().clone();
        original.pause(Error::Bounds);
        assert_eq!(original.failure(), Some(&failure));
        assert_eq!(original.status(1).unwrap(), WatchStatus::Paused);
        assert_eq!(original.claim_adoption(&receipt), Err(Error::Closed));
        assert_eq!(original.adopt(|_| Ok(())), Err(Error::Closed));
        assert_eq!(
            original.prepare(image, receipt.watermarks.clone(), vec![]),
            Err(Error::Closed)
        );
        assert_eq!(original.retry(), Err(Error::Closed));
        assert_eq!(original.probe(1), Err(Error::Closed));
        assert_eq!(original.set_activity(Activity::Idle), Err(Error::Closed));
        assert!(original.poll_send(1).unwrap().is_none());
        let (_, mut warm) = standby.begin_recovery(&key, 200, false).unwrap();
        let mut promoted = false;
        while let Some(wire) = warm.poll_send(200).unwrap() {
            if let Some(PrimaryEvent::Promoted(_)) = original.receive(&wire, 200, &host).unwrap() {
                promoted = true;
            }
        }
        assert!(promoted);
        assert!(original.primary().is_closed());
        assert_eq!(original.status(200).unwrap(), WatchStatus::Recovering);
        original.into_recovery_channel().unwrap();
    }
}

#[test]
fn primary_pause_before_replication_cannot_flush_a_queued_candidate_or_claim_a_fence() {
    let (_, host, key, mut original, standby, mut image) = replication_actors();
    image.logical_ms = 150;
    original
        .prepare(
            image,
            original.primary().receipt().watermarks.clone(),
            vec![],
        )
        .unwrap();
    original.pause(Error::Invalid("two fresh game attempts failed"));
    assert!(original.poll_send(0).unwrap().is_none());
    assert_eq!(standby.receipt().index, 0);
    assert!(
        !original.primary().is_closed(),
        "failure is not a signed promotion"
    );
    let (_, mut warm) = standby.begin_recovery(&key, 200, true).unwrap();
    while let Some(wire) = warm.poll_send(200).unwrap() {
        original.receive(&wire, 200, &host).unwrap();
    }
    assert!(original.primary().is_closed());
    assert_eq!(original.primary().receipt().index, 0);
    assert!(original.primary().pending().is_none());
}

#[test]
fn full_replication_queue_rejects_prepare_without_consuming_the_next_candidate() {
    let (_, host, key, mut original, mut standby, mut image) = replication_actors();
    image.logical_ms = 150;
    image.game = vec![1; 300_000];
    original
        .prepare(
            image.clone(),
            original.primary().receipt().watermarks.clone(),
            vec![],
        )
        .unwrap();
    let mut retries = 0;
    while original.retry().is_ok() {
        retries += 1;
    }
    assert!(retries > 0);
    let mut now = 0;
    while standby.receipt().index == 0 {
        while let Some(wire) = original.poll_send(now).unwrap() {
            standby
                .receive(&wire, now, &key, Activity::Advancing, |candidate, _, _| {
                    Ok(candidate.image.clone())
                })
                .unwrap();
            if standby.receipt().index == 1 {
                break;
            }
        }
        now += 1;
        assert!(now < 500);
    }
    while let Some(wire) = standby.poll_send(now).unwrap() {
        original.receive(&wire, now, &host).unwrap();
    }
    assert_eq!(original.primary().receipt().index, 1);
    assert!(original.primary().pending().is_none());
    image.logical_ms = 200;
    image.game = vec![2; 700_000];
    let marks = original.primary().receipt().watermarks.clone();
    assert_eq!(
        original.prepare(image.clone(), marks.clone(), vec![]),
        Err(Error::Bounds)
    );
    assert!(original.primary().pending().is_none());
    assert_eq!(original.primary().receipt().index, 1);
    // Drain the retained duplicates, then the same staged game can be queued.
    for at in now..now + 1000 {
        while original.poll_send(at).unwrap().is_some() {}
    }
    original.prepare(image, marks, vec![]).unwrap();
    assert_eq!(original.primary().pending().unwrap().index, 2);
}

fn seal_test_inputs(
    recovery: &mut Recovery,
    player: u64,
    tail: u64,
    standby: &Keys,
    signer: &Keys,
    now: u64,
) {
    if player == 3 || player == 5 {
        recovery.seal_inputs(player, tail).unwrap();
        return;
    }
    let root = recovery.root().clone();
    let tls = [player as u8; 32];
    let request = recovery
        .issue_input_round(player, tls, standby, now)
        .unwrap();
    let record = PlayerControl::sign(
        &root,
        &request.membership,
        1,
        // Synthetic replies follow their unique request, above ResumeProof(1).
        request.sequence,
        player,
        tls,
        PlayerAction::Applied {
            output: request
                .membership
                .receipt
                .watermarks
                .iter()
                .find(|m| m.player == player)
                .unwrap()
                .output_ack,
            tail,
            cut: Some(request.nonce),
        },
        signer,
    )
    .unwrap();
    recovery.accept_input_cut(&record, tls, now).unwrap();
}

fn converged_recovery() -> (Root, Keys, Keys, Keys, RecoveryBarrier, ProgressWatch) {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let initial =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let seq = Sequencer::arm_session(root.clone(), initial, &key).unwrap();
    let mut watch = ProgressWatch::new(
        root.clone(),
        seq.receipt().clone(),
        Activity::Advancing,
        [2; 32],
        0,
    )
    .unwrap();
    let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
    watch.promote(recovery.promotion(), 0).unwrap();
    for (id, keys) in [(1, &host), (2, &player)] {
        let tls = [id as u8; 32];
        let challenge = recovery
            .challenge(id, tls, id, keys.public_key().to_bytes(), &key, 0)
            .unwrap();
        let proof = ResumeProof::sign(&root, &challenge, tls, 0, 0, 1, keys).unwrap();
        recovery.accept(id, tls, &proof, 0).unwrap();
    }
    recovery.retain_local(3, 0, 0, 0).unwrap();
    assert!(recovery.seal(0).unwrap());
    recovery
        .revalidate_security(&key, 0, |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    recovery.begin_round().unwrap();
    for id in 1..=3 {
        seal_test_inputs(
            &mut recovery,
            id,
            0,
            &key,
            if id == 1 { &host } else { &player },
            0,
        );
    }
    recovery
        .commit_departures(&key, |_, _, _| {
            panic!("empty departures must not call game")
        })
        .unwrap();
    let barrier = RecoveryBarrier::new(recovery, &key, 10).unwrap();
    (root, host, key, player, barrier, watch)
}

#[test]
fn final_recovery_requires_every_retained_cut_before_signed_resume_unfreezes_clients() {
    let (root, host, key, player, mut barrier, mut watch) = converged_recovery();
    let promotion = barrier.promotion().clone();
    let delivery = DeliveryJournal::default();
    let intents = IntentJournal::default();
    barrier.retain_local(3, &delivery, &intents, 0, 20).unwrap();
    assert!(!barrier.is_ready());
    let mut player_records = None;
    for (id, keys) in [(1, &host), (2, &player)] {
        let tls = [id as u8; 32];
        let cut = barrier.issue(id, tls, &key, id * 20).unwrap();
        let wire = cut.encode(&root, &promotion).unwrap();
        assert_eq!(RecoveryCut::decode(&root, &promotion, &wire).unwrap(), cut);
        let ready = RecoveryReady::sign(
            &root,
            &promotion,
            &cut,
            tls,
            &delivery,
            &intents,
            125,
            cut.sequence,
            keys,
        )
        .unwrap();
        let wire = ready.encode(&root, &promotion, &cut).unwrap();
        assert_eq!(
            RecoveryReady::decode(&root, &promotion, &cut, &wire).unwrap(),
            ready
        );
        assert!(barrier.accept(&ready, [9; 32], id * 30).is_err());
        barrier.accept(&ready, tls, id * 30).unwrap();
        barrier.accept(&ready, tls, id * 30 + 1).unwrap();
        if id == 2 {
            player_records = Some((cut, ready));
        }
    }
    assert!(barrier.is_ready());
    assert_eq!(watch.status(70).unwrap(), WatchStatus::Recovering);
    let (seq, histories, resume) = barrier.finish(&key, 80).unwrap();
    assert_eq!(seq.receipt().logical_ms, 100);
    assert_eq!(histories.len(), 3);
    let wire = resume.encode(&root, &promotion).unwrap();
    assert_eq!(Resume::decode(&root, &promotion, &wire).unwrap(), resume);
    let mut trailing = wire;
    trailing.push(0);
    assert!(Resume::decode(&root, &promotion, &trailing).is_err());
    let (cut, ready) = player_records.unwrap();
    watch
        .resume(&resume, &cut, &ready, &delivery, &intents, 80)
        .unwrap();
    assert_eq!(watch.status(80).unwrap(), WatchStatus::Live);
    assert!(watch
        .resume(&resume, &cut, &ready, &delivery, &intents, 81)
        .is_err());
    assert!(watch.promote(&promotion, 82).is_err());
}

#[test]
fn recovery_ready_rejects_wrong_identity_clock_skew_journals_and_replaced_challenges() {
    let (root, host, key, player, mut barrier, _) = converged_recovery();
    let promotion = barrier.promotion().clone();
    let tls = [2; 32];
    let delivery = DeliveryJournal::default();
    let intents = IntentJournal::default();
    let cut = barrier.issue(2, tls, &key, 20).unwrap();
    assert!(RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        tls,
        &delivery,
        &intents,
        251,
        cut.sequence,
        &player
    )
    .is_err());
    assert!(RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        tls,
        &delivery,
        &intents,
        i64::MIN,
        cut.sequence,
        &player
    )
    .is_err());
    assert!(RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        tls,
        &delivery,
        &intents,
        0,
        cut.sequence,
        &host
    )
    .is_err());
    assert!(RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        [9; 32],
        &delivery,
        &intents,
        0,
        cut.sequence,
        &player
    )
    .is_err());
    let mut extra = IntentJournal::default();
    extra.append_batch(&[vec![1]]).unwrap();
    assert!(RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        tls,
        &delivery,
        &extra,
        0,
        cut.sequence,
        &player
    )
    .is_err());
    let mut extra = DeliveryJournal::default();
    extra.apply(1, &[1], |_| Ok(())).unwrap();
    assert!(RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        tls,
        &extra,
        &intents,
        0,
        cut.sequence,
        &player
    )
    .is_err());
    let ready = RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        tls,
        &delivery,
        &intents,
        0,
        cut.sequence,
        &player,
    )
    .unwrap();
    let replacement = barrier.issue(2, tls, &key, 30).unwrap();
    assert_ne!(cut.nonce, replacement.nonce);
    assert!(barrier.accept(&ready, tls, 31).is_err());
    let ready = RecoveryReady::sign(
        &root,
        &promotion,
        &replacement,
        tls,
        &delivery,
        &intents,
        0,
        replacement.sequence,
        &player,
    )
    .unwrap();
    barrier.accept(&ready, tls, 32).unwrap();
    assert!(!barrier.is_ready());
    assert!(barrier.issue(2, tls, &key, 33).is_err());
    assert!(barrier.retain_local(1, &delivery, &intents, 0, 34).is_err());
    assert!(barrier.finish(&key, 40).is_err());
}

#[test]
fn final_recovery_exchange_keeps_the_original_deadline_and_cannot_mask_missing_ready() {
    let (root, _, key, player, mut barrier, mut watch) = converged_recovery();
    let promotion = barrier.promotion().clone();
    let cut = barrier.issue(2, [2; 32], &key, 4900).unwrap();
    let delivery = DeliveryJournal::default();
    let intents = IntentJournal::default();
    let ready = RecoveryReady::sign(
        &root,
        &promotion,
        &cut,
        [2; 32],
        &delivery,
        &intents,
        0,
        cut.sequence,
        &player,
    )
    .unwrap();
    assert_eq!(watch.status(4999).unwrap(), WatchStatus::Recovering);
    assert_eq!(barrier.accept(&ready, [2; 32], 5000), Err(Error::Closed));
    assert_eq!(watch.status(5000).unwrap(), WatchStatus::Paused);
    assert!(barrier.issue(1, [1; 32], &key, 5001).is_err());
}

#[test]
fn local_journal_checkpoints_preserve_original_payloads_cursors_and_bounded_hash_history() {
    let mut intents = IntentJournal::default();
    intents
        .append_batch(&[vec![1], vec![2, 3], vec![4]])
        .unwrap();
    intents.acknowledge(1).unwrap();
    let bytes = intents.checkpoint().unwrap();
    let mut restored = IntentJournal::restore(&bytes).unwrap();
    assert_eq!(restored.checkpoint().unwrap(), bytes);
    assert_eq!(
        restored.pending().collect::<Vec<_>>(),
        vec![(2, &[2, 3][..]), (3, &[4][..])]
    );
    assert_eq!(restored.append_batch(&[vec![5]]).unwrap(), vec![4]);
    restored.acknowledge(4).unwrap();
    assert!(restored.pending().next().is_none());
    assert_eq!(
        IntentJournal::restore(&restored.checkpoint().unwrap())
            .unwrap()
            .tail(),
        4
    );
    let mut bad = bytes.clone();
    bad[25] = 255;
    assert!(IntentJournal::restore(&bad).is_err());
    let mut bad = bytes.clone();
    bad[33] = 9;
    assert!(IntentJournal::restore(&bad).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(IntentJournal::restore(&trailing).is_err());
    for len in [0, 6, bytes.len() - 1] {
        assert!(IntentJournal::restore(&bytes[..len]).is_err());
    }

    let mut delivery = DeliveryJournal::default();
    for seq in 1..=600 {
        delivery.apply(seq, &seq.to_be_bytes(), |_| Ok(())).unwrap();
    }
    let bytes = delivery.checkpoint().unwrap();
    let mut restored = DeliveryJournal::restore(&bytes).unwrap();
    assert_eq!(restored.applied(), 600);
    assert_eq!(restored.checkpoint().unwrap(), bytes);
    assert!(!restored
        .apply(600, &600u64.to_be_bytes(), |_| panic!("already applied"))
        .unwrap());
    assert_eq!(restored.apply(600, &[9], |_| Ok(())), Err(Error::Conflict));
    restored.apply(601, &[1], |_| Ok(())).unwrap();
    assert_eq!(restored.applied(), 601);
    let mut bad = bytes.clone();
    bad[16] = 0;
    assert!(DeliveryJournal::restore(&bad).is_err());
    let mut bad = bytes.clone();
    bad[25] = 9;
    assert!(DeliveryJournal::restore(&bad).is_err());
    let mut poisoned = DeliveryJournal::default();
    assert!(poisoned.apply(1, &[1], |_| Err(Error::Bounds)).is_err());
    assert_eq!(poisoned.checkpoint(), Err(Error::Closed));
}

#[test]
fn local_certified_delivery_checks_recipient_proof_and_reliable_stream_before_application() {
    let (mut seq, key) = armed();
    let mut lossy = output(1);
    lossy.delivery = Delivery::Lossy;
    let staged = seq
        .stage(
            seq.next(vec![1], 50, marks(0, 0), vec![output(1), lossy])
                .unwrap(),
        )
        .unwrap();
    seq.install(staged, &key).unwrap();
    let reliable = &seq.publication()[0];
    let lossy = &seq.publication()[1];
    let mut journal = DeliveryJournal::default();
    assert_eq!(
        journal.apply_certified(seq.context(), 2, reliable, |_| panic!("wrong recipient")),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        journal.apply_certified(seq.context(), 1, lossy, |_| panic!("lossy is not reliable")),
        Err(Error::Unauthorized)
    );
    let mut corrupt = reliable.clone();
    corrupt.output.bytes.push(0);
    assert!(journal
        .apply_certified(seq.context(), 1, &corrupt, |_| panic!("bad proof"))
        .is_err());
    let mut calls = 0;
    journal
        .apply_certified(seq.context(), 1, reliable, |_| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    let mut restored = DeliveryJournal::restore(&journal.checkpoint().unwrap()).unwrap();
    assert!(!restored
        .apply_certified(seq.context(), 1, reliable, |_| panic!(
            "duplicate after restore"
        ))
        .unwrap());
    assert_eq!(calls, 1);
}

fn resumed_successor() -> (Root, Keys, SuccessorActor) {
    let (root, host, key, player, mut barrier, _) = converged_recovery();
    let promotion = barrier.promotion().clone();
    let delivery = DeliveryJournal::default();
    let intents = IntentJournal::default();
    barrier.retain_local(3, &delivery, &intents, 0, 20).unwrap();
    for (id, keys) in [(1, &host), (2, &player)] {
        let tls = [id as u8; 32];
        let cut = barrier.issue(id, tls, &key, 20).unwrap();
        let ready = RecoveryReady::sign(
            &root,
            &promotion,
            &cut,
            tls,
            &delivery,
            &intents,
            0,
            cut.sequence,
            keys,
        )
        .unwrap();
        barrier.accept(&ready, tls, 20).unwrap();
    }
    let (successor, _, _) = barrier.finish(&key, 20).unwrap();
    (root, key, successor)
}

#[test]
fn final_ready_authorizes_one_warm_player_attachment_on_its_original_tls_and_roles() {
    for conflict_with_ready in [false, true] {
        let (root, host, key, player, mut barrier, _) = converged_recovery();
        let promotion = barrier.promotion().clone();
        let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
        descriptor.consent(&key).unwrap();
        let policy = EndpointPolicy {
            descriptor,
            role: LinkRole::Standby,
            promotion: None,
            membership: None,
        };
        let binding = ConnectionBinding {
            session: root.session,
            descriptor: root.digest().unwrap(),
            term: 0,
            client: LinkRole::ControlPlayer,
            server: LinkRole::Standby,
        };
        let mut client = Channel::new(
            &policy,
            binding.clone(),
            ChannelSide::Client,
            root.standby,
            [2; 32],
        )
        .unwrap();
        let mut server = Channel::new(
            &policy,
            binding.clone(),
            ChannelSide::Server,
            player.public_key().to_bytes(),
            [2; 32],
        )
        .unwrap();
        let probe = PulseProbe {
            term: 0,
            sequence: 1,
            nonce: [1; 32],
            tls: [2; 32],
        };
        assert_eq!(
            client
                .enqueue(PacketKind::Control, &probe.encode(&root).unwrap())
                .unwrap(),
            1
        );
        let old_frame = client.poll_send(0).unwrap().unwrap();
        assert!(server.receive(&old_frame, 0).unwrap().is_some());
        client.promote(&promotion).unwrap();
        server.promote(&promotion).unwrap();
        let mut cold = Channel::new(
            &policy,
            binding,
            ChannelSide::Server,
            player.public_key().to_bytes(),
            [9; 32],
        )
        .unwrap();
        cold.promote(&promotion).unwrap();
        let delivery = DeliveryJournal::default();
        let intents = IntentJournal::default();
        barrier.retain_local(3, &delivery, &intents, 0, 20).unwrap();
        let mut retained = None;
        let mut recovery_view = Vec::new();
        let mut original_ready_id = 0;
        let mut recovery_view_id = 0;
        for (id, keys) in [(1, &host), (2, &player)] {
            let tls = [id as u8; 32];
            let cut = barrier.issue(id, tls, &key, 20).unwrap();
            if id == 1 {
                original_ready_id = cut.sequence;
            }
            if id == 2 {
                recovery_view_id = cut.sequence - 1;
                let mut inbox = PlayerInbox::new(&server, cut.membership.clone()).unwrap();
                recovery_view = PlayerControl::sign(
                    &root,
                    &cut.membership,
                    1,
                    cut.sequence - 1,
                    2,
                    tls,
                    PlayerAction::Lossy {
                        number: 9,
                        bytes: vec![9],
                    },
                    &player,
                )
                .unwrap()
                .encode(&root)
                .unwrap();
                assert!(inbox.receive(&recovery_view).unwrap().is_some());
                retained = Some(inbox);
            }
            let ready = RecoveryReady::sign(
                &root,
                &promotion,
                &cut,
                tls,
                &delivery,
                &intents,
                0,
                cut.sequence,
                keys,
            )
            .unwrap();
            barrier.accept(&ready, tls, 20).unwrap();
        }
        let (mut successor, _, _) = barrier.finish(&key, 20).unwrap();
        let cert = successor.membership_certificate(&key).unwrap();
        assert!(successor
            .attach_warm_player(&cold, &mut retained, &key)
            .is_err());
        assert!(successor
            .attach_warm_player(&server, &mut retained, &Keys::generate())
            .is_err());
        assert!(retained.is_some());
        let mut foreign_inbox = Some(PlayerInbox::new(&cold, cert.clone()).unwrap());
        assert!(successor
            .attach_warm_player(&server, &mut foreign_inbox, &key)
            .is_err());
        let mut queue = successor
            .attach_warm_player(&server, &mut retained, &key)
            .unwrap();
        assert!(retained.is_none());
        assert!(!queue.receive(&recovery_view, successor.primary()).unwrap());
        let old_view = PlayerControl::sign(
            &root,
            &cert,
            1,
            4,
            2,
            [2; 32],
            PlayerAction::Lossy {
                number: 8,
                bytes: vec![8],
            },
            &player,
        )
        .unwrap();
        assert_eq!(
            client
                .enqueue(PacketKind::Control, &old_view.encode(&root).unwrap())
                .unwrap(),
            2
        );
        while let Some(wire) = client.poll_send(20).unwrap() {
            if let Some((_, _, bytes)) = server.receive(&wire, 20).unwrap() {
                assert!(!queue.receive(&bytes, successor.primary()).unwrap());
            }
        }
        assert!(queue.lossy().is_none());
        assert_eq!(queue.player(), 2);
        assert!(successor
            .attach_warm_player(&server, &mut retained, &key)
            .is_err());
        assert_eq!(server.binding().client, LinkRole::ControlPlayer);
        assert_eq!(server.binding().server, LinkRole::Standby);
        let input = PlayerControl::sign(
            &root,
            &cert,
            1,
            5,
            2,
            [2; 32],
            PlayerAction::Intent {
                number: 1,
                bytes: vec![4],
            },
            &player,
        )
        .unwrap();
        assert_eq!(
            client
                .enqueue(PacketKind::Control, &input.encode(&root).unwrap())
                .unwrap(),
            3,
            "warm framing counter must not reset"
        );
        while let Some(wire) = client.poll_send(20).unwrap() {
            if let Some((_, _, bytes)) = server.receive(&wire, 20).unwrap() {
                assert!(queue.receive(&bytes, successor.primary()).unwrap());
            }
        }
        assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(1, &[4][..])]);
        let mut image = SessionImage::decode(&root, successor.image()).unwrap();
        image.logical_ms += 16;
        image.inputs.get_mut(&2).unwrap().record(1, &[4]).unwrap();
        let mut marks = successor.receipt().watermarks.clone();
        marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
        successor
            .prepare(
                image,
                marks,
                vec![Output {
                    recipient: 2,
                    delivery: Delivery::Reliable,
                    sequence: 1,
                    bytes: vec![7],
                }],
            )
            .unwrap();
        let PrimaryEvent::Committed { outputs, .. } = successor
            .commit(&key, |candidate, _, _| Ok(candidate.image.clone()))
            .unwrap()
        else {
            panic!("one successor");
        };
        queue.refresh(successor.primary()).unwrap();
        assert_eq!(queue.pending().count(), 0);
        server
            .enqueue(
                PacketKind::Output,
                &outputs[0].encode(&root.context().unwrap()).unwrap(),
            )
            .unwrap();
        let mut applied = DeliveryJournal::default();
        while let Some(wire) = server.poll_send(20).unwrap() {
            if let Some((kind, _, bytes)) = client.receive(&wire, 20).unwrap() {
                assert_eq!(kind, PacketKind::Output);
                let output = CertifiedOutput::decode(&root.context().unwrap(), &bytes).unwrap();
                applied
                    .apply_certified(&root.context().unwrap(), 2, &output, |bytes| {
                        assert_eq!(bytes, &[7]);
                        Ok(())
                    })
                    .unwrap();
            }
        }
        assert_eq!(applied.applied(), 1);
        assert!(server.receive(&old_frame, 21).is_err());
        if !conflict_with_ready {
            let conflict = PlayerControl::sign(
                &root,
                &cert,
                1,
                recovery_view_id,
                2,
                [2; 32],
                PlayerAction::Lossy {
                    number: 10,
                    bytes: vec![10],
                },
                &player,
            )
            .unwrap();
            assert_eq!(
                queue.receive(&conflict.encode(&root).unwrap(), successor.primary()),
                Err(Error::Conflict)
            );
            assert!(successor
                .adopt::<()>(|_| panic!("faulted scope must not call game"))
                .is_err());
            continue;
        }
        // The original human keeps its own prepared link; it gains no authority.
        let mut original_binding = server.binding().clone();
        original_binding.client = LinkRole::Original;
        let mut original = Channel::new(
            &policy,
            original_binding,
            ChannelSide::Server,
            root.host,
            [1; 32],
        )
        .unwrap();
        original.promote(&promotion).unwrap();
        let cert = successor.membership_certificate(&key).unwrap();
        let mut retained = Some(PlayerInbox::new(&original, cert.clone()).unwrap());
        let mut original_queue = successor
            .attach_warm_player(&original, &mut retained, &key)
            .unwrap();
        assert_eq!(original_queue.player(), 1);
        // A new PlayerControl cannot reuse the final Ready's signed sequence ID.
        let reused_ready = PlayerControl::sign(
            &root,
            &cert,
            1,
            original_ready_id,
            1,
            [1; 32],
            PlayerAction::Intent {
                number: 1,
                bytes: vec![1],
            },
            &host,
        )
        .unwrap();
        assert_eq!(
            original_queue.receive(&reused_ready.encode(&root).unwrap(), successor.primary()),
            Err(Error::Conflict)
        );
        assert!(successor
            .adopt::<()>(|_| panic!("faulted scope must not call game"))
            .is_err());
    }
}

#[test]
fn warm_attachment_ready_sequence_collision_pauses_without_consuming_retained_inbox() {
    let (root, host, key, player, mut barrier, _) = converged_recovery();
    let promotion = barrier.promotion().clone();
    let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor,
        role: LinkRole::Standby,
        promotion: None,
        membership: None,
    };
    let mut channel = Channel::new(
        &policy,
        ConnectionBinding {
            session: root.session,
            descriptor: root.digest().unwrap(),
            term: 0,
            client: LinkRole::ControlPlayer,
            server: LinkRole::Standby,
        },
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [2; 32],
    )
    .unwrap();
    channel.promote(&promotion).unwrap();
    let delivery = DeliveryJournal::default();
    let intents = IntentJournal::default();
    barrier.retain_local(3, &delivery, &intents, 0, 20).unwrap();
    let mut retained = None;
    for (id, keys) in [(1, &host), (2, &player)] {
        let tls = [id as u8; 32];
        let cut = barrier.issue(id, tls, &key, 20).unwrap();
        if id == 2 {
            let mut inbox = PlayerInbox::new(&channel, cut.membership.clone()).unwrap();
            let reused = PlayerControl::sign(
                &root,
                &cut.membership,
                1,
                cut.sequence,
                2,
                tls,
                PlayerAction::Lossy {
                    number: 1,
                    bytes: vec![1],
                },
                &player,
            )
            .unwrap();
            inbox.receive(&reused.encode(&root).unwrap()).unwrap();
            retained = Some(inbox);
        }
        let ready = RecoveryReady::sign(
            &root,
            &promotion,
            &cut,
            tls,
            &delivery,
            &intents,
            0,
            cut.sequence,
            keys,
        )
        .unwrap();
        barrier.accept(&ready, tls, 20).unwrap();
    }
    let (mut successor, _, _) = barrier.finish(&key, 20).unwrap();
    assert!(matches!(
        successor.attach_warm_player(&channel, &mut retained, &key),
        Err(Error::Conflict)
    ));
    assert!(retained.is_some());
    assert_eq!(successor.failure(), Some(&Error::Conflict));
    assert!(matches!(
        successor.attach_warm_player(&channel, &mut retained, &key),
        Err(Error::Closed)
    ));
}

#[test]
fn successor_installs_validated_state_before_publication_and_preserves_streams() {
    let (root, key, mut successor) = resumed_successor();
    let initial_index = successor.receipt().index;
    assert!(successor.adopt(|_| Ok(())).is_err());
    for sequence in 1..=3 {
        let before = successor.image().to_vec();
        let mut image = SessionImage::decode(&root, &before).unwrap();
        image.logical_ms += 10;
        image.game = vec![sequence as u8];
        let mut marks = successor.receipt().watermarks.clone();
        marks.iter_mut().find(|m| m.player == 2).unwrap().output_ack = sequence - 1;
        let output = Output {
            recipient: 2,
            delivery: Delivery::Reliable,
            sequence,
            bytes: vec![sequence as u8],
        };
        successor
            .prepare(image, marks, vec![output.clone()])
            .unwrap();
        assert_eq!(successor.image(), before);
        assert_eq!(
            successor.primary().output_ceiling(2, Delivery::Reliable),
            sequence - 1
        );
        assert_eq!(successor.primary().pending().unwrap().term, 1);
        assert!(successor.adopt(|_| Ok(())).is_err());
        assert!(successor
            .commit(&Keys::generate(), |c, _, _| Ok(c.image.clone()))
            .is_err());
        assert_eq!(successor.image(), before);
        let mut attempts = 0;
        let PrimaryEvent::Committed { receipt, outputs } = successor
            .commit(&key, |c, image, previous| {
                attempts += 1;
                assert_eq!(previous.encode(&root).unwrap(), before);
                assert_eq!(image.encode(&root).unwrap(), c.image);
                if attempts == 1 {
                    return Err(Error::Invalid("transient restore"));
                }
                Ok(c.image.clone())
            })
            .unwrap()
        else {
            panic!("successor cannot promote again");
        };
        assert_eq!(attempts, 2);
        assert_eq!(receipt.term, 1);
        assert_eq!(receipt.index, initial_index + sequence);
        assert_eq!(outputs.len(), 1);
        outputs[0].verify(&root.context().unwrap()).unwrap();
        assert_eq!(outputs[0].output, output);
        assert_eq!(successor.outbox().count(), 1);
        assert_eq!(
            successor.primary().outbox().collect::<Vec<_>>(),
            successor.outbox().collect::<Vec<_>>()
        );
        assert_eq!(
            successor.primary().output_ceiling(2, Delivery::Reliable),
            sequence
        );
        successor
            .adopt(|gate| gate.claim_adoption(&receipt))
            .unwrap();
        assert!(successor
            .adopt(|gate| gate.claim_adoption(&receipt))
            .is_err());
        assert!(successor
            .commit(&key, |c, _, _| Ok(c.image.clone()))
            .is_err());
    }
}

#[test]
fn successor_persistent_restore_fault_cannot_install_publish_or_retry_later() {
    let (root, key, mut successor) = resumed_successor();
    let before = successor.image().to_vec();
    let receipt = successor.receipt().clone();
    let mut image = SessionImage::decode(&root, &before).unwrap();
    image.game = vec![99];
    let marks = receipt.watermarks.clone();
    successor
        .prepare(image.clone(), marks.clone(), vec![])
        .unwrap();
    let mut attempts = 0;
    assert!(successor
        .commit(&key, |_, _, _| {
            attempts += 1;
            Ok(vec![99])
        })
        .is_err());
    assert_eq!(attempts, 2);
    assert_eq!(successor.receipt(), &receipt);
    assert_eq!(successor.image(), before);
    assert!(successor.failure().is_some());
    assert!(successor
        .commit(&key, |c, _, _| Ok(c.image.clone()))
        .is_err());
    assert!(successor.prepare(image, marks, vec![]).is_err());
    assert!(successor.adopt(|_| Ok(())).is_err());
    assert_eq!(successor.outbox().count(), 0);
}

fn typed_local_recovery_keys(tail: u64) -> (Root, Keys, Recovery, Keys, Keys) {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let seq = Sequencer::arm_session(root.clone(), image, &key).unwrap();
    let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
    for (id, keys) in [(1, &host), (2, &player)] {
        let tls = [id as u8; 32];
        let challenge = recovery
            .challenge(id, tls, id, keys.public_key().to_bytes(), &key, 0)
            .unwrap();
        let proof = ResumeProof::sign(
            &root,
            &challenge,
            tls,
            0,
            if id == 2 { tail } else { 0 },
            1,
            keys,
        )
        .unwrap();
        recovery.accept(id, tls, &proof, 0).unwrap();
    }
    recovery.retain_local(3, 0, 0, 0).unwrap();
    recovery.seal(0).unwrap();
    recovery
        .revalidate_security(&key, 0, |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    (root, key, recovery, host, player)
}
fn typed_local_recovery(tail: u64) -> (Root, Keys, Recovery) {
    let (root, key, recovery, _, _) = typed_local_recovery_keys(tail);
    (root, key, recovery)
}

#[test]
fn local_bot_followups_do_not_restart_or_reorder_the_current_whole_tail_round() {
    let (root, key, mut recovery, host, player) = typed_local_recovery_keys(1);
    recovery.begin_round().unwrap();
    for (p, tail) in [(1, 0), (2, 1), (3, 0)] {
        seal_test_inputs(
            &mut recovery,
            p,
            tail,
            &key,
            if p == 1 { &host } else { &player },
            0,
        );
    }
    recovery.supply(2, 1, vec![2]).unwrap();
    let bytes = recovery.sequencer().image().to_vec();
    recovery
        .commit_local_clients(&key, |_| {
            Ok((
                bytes.clone(),
                vec![],
                vec![LocalRecoveryCut {
                    player: 3,
                    applied: 0,
                    tail: 1,
                }],
            ))
        })
        .unwrap();
    assert_eq!(recovery.phase(), RecoveryPhase::Draining);
    assert_eq!(recovery.next_input().unwrap().unwrap().0, 2);
    recovery
        .apply_next(&key, |_, _, _, histories| {
            let mut image = SessionImage::decode(&root, &bytes).unwrap();
            image.inputs = histories.clone();
            Ok((image.encode(&root).unwrap(), vec![]))
        })
        .unwrap();
    assert!(recovery.next_input().unwrap().is_none());
    recovery.begin_round().unwrap();
    for (p, tail) in [(1, 0), (2, 1), (3, 1)] {
        seal_test_inputs(
            &mut recovery,
            p,
            tail,
            &key,
            if p == 1 { &host } else { &player },
            0,
        );
    }
    recovery.supply(3, 1, vec![3]).unwrap();
    assert_eq!(recovery.next_input().unwrap().unwrap().0, 3);
}

#[test]
fn local_recovery_cannot_claim_a_remote_humans_journal_or_apply_after_budget_exhaustion() {
    let (_, key, mut recovery) = typed_local_recovery(0);
    let before = recovery.sequencer().receipt().clone();
    let bytes = recovery.sequencer().image().to_vec();
    assert_eq!(
        recovery.commit_local_clients(&key, |_| Ok((
            bytes.clone(),
            vec![],
            vec![LocalRecoveryCut {
                player: 2,
                applied: 0,
                tail: 0
            }]
        ))),
        Err(Error::Unauthorized)
    );
    assert_eq!(recovery.phase(), RecoveryPhase::Failed);
    assert_eq!(recovery.sequencer().receipt(), &before);
    let (_, key, mut recovery) = typed_local_recovery(0);
    let bytes = recovery.sequencer().image().to_vec();
    for batch in 0..16 {
        recovery
            .commit_local_clients(&key, |_| {
                Ok((
                    bytes.clone(),
                    // The mandatory security commit consumed one application.
                    (1..=if batch == 15 { 254 } else { 255 })
                        .map(|n| Output {
                            recipient: 3,
                            delivery: Delivery::Lossy,
                            sequence: batch * 255 + n,
                            bytes: vec![1],
                        })
                        .collect(),
                    vec![],
                ))
            })
            .unwrap();
    }
    let before = recovery.sequencer().receipt().clone();
    let mut calls = 0;
    assert_eq!(
        recovery.commit_local_clients(&key, |_| {
            calls += 1;
            Ok((bytes.clone(), vec![], vec![]))
        }),
        Err(Error::Bounds)
    );
    assert_eq!(calls, 0);
    assert_eq!(recovery.phase(), RecoveryPhase::Failed);
    assert_eq!(recovery.sequencer().receipt(), &before);
}

#[test]
fn reliable_sender_retirement_requires_its_whole_sealed_tail_and_cannot_evict_others() {
    for (tail, removed, allowed) in [(1, 2, true), (2, 2, false), (1, 1, false)] {
        let (root, key, mut recovery, host, player) = typed_local_recovery_keys(tail);
        recovery.begin_round().unwrap();
        for (p, t) in [(1, 0), (2, tail), (3, 0)] {
            seal_test_inputs(
                &mut recovery,
                p,
                t,
                &key,
                if p == 1 { &host } else { &player },
                0,
            );
        }
        recovery.supply(2, 1, vec![2]).unwrap();
        let previous = recovery.sequencer().image().to_vec();
        let before = recovery.sequencer().receipt().clone();
        let result = recovery.apply_next(&key, |_, _, _, histories| {
            let mut image = SessionImage::decode(&root, &previous).unwrap();
            image.members.retain(|m| m.player != removed);
            image.inputs = histories
                .iter()
                .filter(|(p, _)| **p != removed)
                .map(|(p, h)| (*p, h.clone()))
                .collect();
            image.membership_revision += 1;
            Ok((image.encode(&root).unwrap(), vec![]))
        });
        assert_eq!(result.is_ok(), allowed);
        if allowed {
            assert!(!recovery.histories().contains_key(&2));
            assert!(recovery
                .sequencer()
                .receipt()
                .watermarks
                .iter()
                .any(|m| m.player == 2 && m.retired && m.input == 1));
            assert!(recovery.next_input().unwrap().is_none());
        } else {
            assert_eq!(recovery.phase(), RecoveryPhase::Failed);
            assert_eq!(recovery.sequencer().receipt(), &before);
        }
    }
}

#[test]
fn human_input_envelopes_bind_original_bytes_to_authenticated_player_tls_and_term() {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let certificate = seq.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let tls = [7; 32];
    let mut client = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.host,
        tls,
    )
    .unwrap();
    let mut server = Channel::new(
        &policy,
        binding,
        ChannelSide::Server,
        player.public_key().to_bytes(),
        tls,
    )
    .unwrap();
    let mut inbox = PlayerInbox::new(&server, certificate.clone()).unwrap();
    assert_eq!(inbox.player(), 2);
    assert_eq!(server.remote_key(), player.public_key().to_bytes());
    let mut intents = IntentJournal::default();
    let original = vec![0x5a; 1024];
    let id = intents.append_batch(&[original.clone()]).unwrap()[0];
    let record = PlayerControl::sign(
        &root,
        &certificate,
        0,
        1,
        2,
        tls,
        PlayerAction::Intent {
            number: id,
            bytes: original.clone(),
        },
        &player,
    )
    .unwrap();
    let bytes = record.encode(&root).unwrap();
    assert_eq!(PlayerControl::decode(&root, &bytes).unwrap(), record);
    client.enqueue(PacketKind::Control, &bytes).unwrap();
    let mut frames = 0;
    let mut received = None;
    while let Some(wire) = client.poll_send(0).unwrap() {
        frames += 1;
        assert!(wire.len() <= 1024);
        if let Some((PacketKind::Control, _, bytes)) = server.receive(&wire, 0).unwrap() {
            received = inbox.receive(&bytes).unwrap();
        }
    }
    assert_eq!(frames, 2);
    assert_eq!(received, Some(record.clone()));
    assert_eq!(inbox.receive(&bytes).unwrap(), None);
    assert_eq!(intents.pending().next().unwrap(), (id, original.as_slice()));
    assert!(PlayerControl::sign(
        &root,
        &certificate,
        0,
        2,
        2,
        tls,
        PlayerAction::Intent {
            number: 2,
            bytes: vec![]
        },
        &host
    )
    .is_err());
    for (term, tls) in [(1, tls), (0, [8; 32])] {
        let foreign = PlayerControl::sign(
            &root,
            &certificate,
            term,
            2,
            2,
            tls,
            PlayerAction::Applied {
                output: 0,
                tail: 1,
                cut: None,
            },
            &player,
        )
        .unwrap();
        assert!(inbox.receive(&foreign.encode(&root).unwrap()).is_err());
    }
    let ack = PlayerControl::sign(
        &root,
        &certificate,
        0,
        2,
        2,
        tls,
        PlayerAction::Applied {
            output: 0,
            tail: 1,
            cut: Some([9; 32]),
        },
        &player,
    )
    .unwrap();
    assert_eq!(
        inbox.receive(&ack.encode(&root).unwrap()).unwrap(),
        Some(ack)
    );
    // The committed retirement closes queued input from this physical route.
    let mut post = image;
    post.members.retain(|m| m.player != 2);
    post.inputs.remove(&2);
    post.membership_revision += 1;
    let mut marks = seq.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().retired = true;
    let token = seq
        .stage(
            seq.next(post.encode(&root).unwrap(), 100, marks, vec![])
                .unwrap(),
        )
        .unwrap();
    seq.install(token, &key).unwrap();
    assert_eq!(
        inbox.update_membership(seq.membership_certificate(&key).unwrap()),
        Err(Error::Closed)
    );
    assert_eq!(inbox.receive(&bytes), Err(Error::Closed));
}

#[test]
fn player_queue_retains_originals_across_reconnect_and_commits_input_and_output_acks() {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let mut primary = Primary::armed(
        root.context().unwrap(),
        image.encode(&root).unwrap(),
        seq.receipt().clone(),
    )
    .unwrap();
    let channel = |certificate: &MembershipCertificate, tls| {
        let policy = EndpointPolicy {
            descriptor: descriptor.clone(),
            role: LinkRole::Original,
            promotion: None,
            membership: Some(certificate.clone()),
        };
        Channel::new(
            &policy,
            ConnectionBinding {
                session: root.session,
                descriptor: root.digest().unwrap(),
                term: 0,
                client: LinkRole::Player,
                server: LinkRole::Original,
            },
            ChannelSide::Server,
            player.public_key().to_bytes(),
            tls,
        )
        .unwrap()
    };
    let initial_cert = seq.membership_certificate(&key).unwrap();
    let initial_channel = channel(&initial_cert, [7; 32]);
    let mut queue = primary
        .attach_player(&initial_channel, initial_cert.clone())
        .unwrap();
    let signed = |certificate: &MembershipCertificate, tls, sequence, action| {
        PlayerControl::sign(&root, certificate, 0, sequence, 2, tls, action, &player)
            .unwrap()
            .encode(&root)
            .unwrap()
    };
    let intent = |number, bytes| PlayerAction::Intent { number, bytes };
    let first = signed(&initial_cert, [7; 32], 1, intent(1, vec![10]));
    assert!(queue.receive(&first, &primary).unwrap());
    assert!(!queue.receive(&first, &primary).unwrap());
    assert!(!queue
        .receive(
            &signed(&initial_cert, [7; 32], 2, intent(1, vec![10])),
            &primary
        )
        .unwrap());
    assert!(queue
        .receive(
            &signed(&initial_cert, [7; 32], 3, intent(3, vec![30])),
            &primary
        )
        .is_err());
    // Failed intake does not consume the framing cursor or the original ID.
    assert!(queue
        .receive(
            &signed(&initial_cert, [7; 32], 3, intent(2, vec![20])),
            &primary
        )
        .unwrap());
    assert_eq!(queue.pending().count(), 2);
    let mut post = image;
    post.inputs.get_mut(&2).unwrap().record(1, &[10]).unwrap();
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
    let candidate = primary
        .prepare(
            post.encode(&root).unwrap(),
            100,
            marks,
            vec![Output {
                recipient: 2,
                delivery: Delivery::Reliable,
                sequence: 1,
                bytes: vec![50],
            }],
        )
        .unwrap()
        .clone();
    let token = seq.stage(candidate).unwrap();
    let receipt = seq.install(token, &key).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(queue.pending().count(), 2);
    primary.acknowledge(receipt).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(2, &[20][..])]);
    let cert = seq.membership_certificate(&key).unwrap();
    let mut intents = IntentJournal::default();
    intents.append_batch(&[vec![10], vec![20]]).unwrap();
    intents.acknowledge(1).unwrap();
    let request = queue
        .begin_reconnect(&channel(&cert, [8; 32]), cert.clone(), &primary, 0, &host)
        .unwrap();
    let proof = PlayerControl::resume_connection(
        &root,
        &request,
        [8; 32],
        &DeliveryJournal::default(),
        &intents,
        4,
        &player,
    )
    .unwrap();
    queue
        .finish_reconnect(&proof.encode(&root).unwrap(), &primary, 1)
        .unwrap();
    assert!(queue
        .receive(&signed(&cert, [7; 32], 4, intent(3, vec![30])), &primary)
        .is_err());
    assert!(!queue
        .receive(&signed(&cert, [8; 32], 5, intent(2, vec![20])), &primary)
        .unwrap());
    assert!(queue
        .receive(&signed(&cert, [8; 32], 6, intent(3, vec![30])), &primary)
        .unwrap());
    let ack = |output| PlayerAction::Applied {
        output,
        tail: 3,
        cut: None,
    };
    assert!(queue
        .receive(&signed(&cert, [8; 32], 7, ack(2)), &primary)
        .is_err());
    assert!(queue
        .receive(&signed(&cert, [8; 32], 7, ack(1)), &primary)
        .unwrap());
    assert_eq!(queue.output_ack(), 1);
    assert_eq!(primary.outbox().count(), 1);
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().output_ack = queue.output_ack();
    let candidate = primary
        .prepare(post.encode(&root).unwrap(), 100, marks, vec![])
        .unwrap()
        .clone();
    let token = seq.stage(candidate).unwrap();
    let receipt = seq.install(token, &key).unwrap();
    assert_eq!(primary.outbox().count(), 1);
    primary.acknowledge(receipt).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(primary.outbox().count(), 0);
    assert_eq!(queue.pending().count(), 2);
    assert_eq!(primary.output_ceiling(2, Delivery::Reliable), 1);
    let view = signed(
        &cert,
        [8; 32],
        8,
        PlayerAction::Lossy {
            number: 1,
            bytes: vec![1],
        },
    );
    queue.receive(&view, &primary).unwrap();
    queue
        .receive(
            &signed(
                &cert,
                [8; 32],
                9,
                PlayerAction::Lossy {
                    number: 2,
                    bytes: vec![2],
                },
            ),
            &primary,
        )
        .unwrap();
    queue.discard_lossy(1);
    assert_eq!(queue.lossy(), Some((2, &[2][..])));
    queue.discard_lossy(2);
    assert_eq!(queue.lossy(), None);
    // Reusing a pending original ID with different game bytes poisons intake.
    assert_eq!(
        queue.receive(&signed(&cert, [8; 32], 10, intent(2, vec![99])), &primary),
        Err(Error::Conflict)
    );
    assert_eq!(
        queue.receive(&signed(&cert, [8; 32], 11, intent(4, vec![40])), &primary),
        Err(Error::Closed)
    );
}

fn normal_player_endpoint() -> (
    Root,
    Keys,
    Keys,
    Sequencer,
    Primary,
    PlayerEndpoint,
    Channel,
    PlayerQueue,
    SessionImage,
) {
    normal_player_endpoint_with_activation().0
}

fn normal_player_endpoint_with_activation() -> (
    (
        Root,
        Keys,
        Keys,
        Sequencer,
        Primary,
        PlayerEndpoint,
        Channel,
        PlayerQueue,
        SessionImage,
    ),
    Armed,
    Keys,
) {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let initial = state_hash(&image.encode(&root).unwrap()).unwrap();
    let capability = CapabilityAck::sign(&root, 2, initial, 1, &player).unwrap();
    let mut activation = Activation::new_session(descriptor.clone(), image.clone()).unwrap();
    activation
        .acknowledge(CapabilityAck::sign(&root, 1, initial, 1, &host).unwrap())
        .unwrap();
    activation.acknowledge(capability.clone()).unwrap();
    let (seq, armed) = activation.arm(&key, |bytes| Ok(bytes.to_vec())).unwrap();
    let mut primary = Primary::armed(
        root.context().unwrap(),
        image.encode(&root).unwrap(),
        seq.receipt().clone(),
    )
    .unwrap();
    let certificate = seq.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let client = Channel::new_bound(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        player.public_key().to_bytes(),
        root.host,
        [7; 32],
    )
    .unwrap();
    let server = Channel::new(
        &policy,
        binding,
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [7; 32],
    )
    .unwrap();
    let endpoint = PlayerEndpoint::new(
        descriptor,
        &armed,
        &capability,
        certificate.clone(),
        client,
        player.clone(),
    )
    .unwrap();
    let queue = primary.attach_player(&server, certificate).unwrap();
    (
        (
            root, host, key, seq, primary, endpoint, server, queue, image,
        ),
        armed,
        player,
    )
}

#[test]
fn normal_player_endpoint_requires_its_actual_local_handshake_identity() {
    let (mut descriptor, host, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = &descriptor.root;
    let image = SessionImage::initial(root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let initial = state_hash(&image.encode(root).unwrap()).unwrap();
    let capability = CapabilityAck::sign(root, 2, initial, 1, &player).unwrap();
    let mut activation = Activation::new_session(descriptor.clone(), image).unwrap();
    activation
        .acknowledge(CapabilityAck::sign(root, 1, initial, 1, &host).unwrap())
        .unwrap();
    activation.acknowledge(capability.clone()).unwrap();
    let (seq, armed) = activation.arm(&key, |bytes| Ok(bytes.to_vec())).unwrap();
    let membership = seq.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(membership.clone()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    for local in [None, Some(root.host), Some(player.public_key().to_bytes())] {
        let channel = match local {
            Some(local) => Channel::new_bound(
                &policy,
                binding.clone(),
                ChannelSide::Client,
                local,
                root.host,
                [7; 32],
            )
            .unwrap(),
            None => Channel::new(
                &policy,
                binding.clone(),
                ChannelSide::Client,
                root.host,
                [7; 32],
            )
            .unwrap(),
        };
        let result = PlayerEndpoint::new(
            descriptor.clone(),
            &armed,
            &capability,
            membership.clone(),
            channel,
            player.clone(),
        );
        assert_eq!(
            result.is_ok(),
            local == Some(player.public_key().to_bytes())
        );
    }
    assert!(Channel::new_bound(
        &policy,
        binding,
        ChannelSide::Server,
        root.standby,
        player.public_key().to_bytes(),
        [7; 32]
    )
    .is_err());
}

#[test]
fn normal_player_endpoint_reconnect_keeps_originals_applied_effects_and_sender_counters() {
    let (root, host, key, mut seq, mut primary, mut endpoint, mut server, mut queue, mut image) =
        normal_player_endpoint();
    endpoint
        .intents_mut()
        .unwrap()
        .append_batch(&[vec![10], vec![20]])
        .unwrap();
    assert_eq!(endpoint.queue_pending(MAX_BATCH).unwrap(), 2);
    endpoint.queue_view(vec![30]).unwrap();
    while let Some(wire) = endpoint.poll_send(0).unwrap() {
        if let Some((_, _, bytes)) = server.receive(&wire, 0).unwrap() {
            queue.receive(&bytes, &primary).unwrap();
        }
    }
    image.inputs.get_mut(&2).unwrap().record(1, &[10]).unwrap();
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
    let out = Output {
        recipient: 2,
        delivery: Delivery::Reliable,
        sequence: 1,
        bytes: vec![40],
    };
    let candidate = primary
        .prepare(image.encode(&root).unwrap(), 100, marks, vec![out])
        .unwrap()
        .clone();
    let token = seq.stage(candidate).unwrap();
    primary
        .acknowledge(seq.install(token, &key).unwrap())
        .unwrap();
    queue.refresh(&primary).unwrap();
    let effect = seq.publication()[0].clone();
    server
        .enqueue(
            PacketKind::Output,
            &effect.encode(&root.context().unwrap()).unwrap(),
        )
        .unwrap();
    while let Some(wire) = server.poll_send(0).unwrap() {
        endpoint
            .receive(&wire, 0, |_, bytes, intents| {
                assert_eq!(bytes, &[40]);
                intents.append_batch(&[vec![50]])?;
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(endpoint.journals().0.applied(), 1);
    assert_eq!(
        endpoint.journals().1.pending().collect::<Vec<_>>(),
        vec![(2, &[20][..]), (3, &[50][..])]
    );
    let policy = EndpointPolicy {
        descriptor: endpoint.descriptor().clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(seq.membership_certificate(&key).unwrap()),
    };
    let binding = server.binding().clone();
    let fresh_client = |tls, local| {
        Channel::new_bound(
            &policy,
            binding.clone(),
            ChannelSide::Client,
            local,
            root.host,
            tls,
        )
        .unwrap()
    };
    let mut fresh_server = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Server,
        root.members[1].key.unwrap(),
        [8; 32],
    )
    .unwrap();
    let request = queue
        .begin_reconnect(
            &fresh_server,
            policy.membership.clone().unwrap(),
            &primary,
            0,
            &host,
        )
        .unwrap();
    let old_journal = endpoint.journals().1.checkpoint().unwrap();
    for channel in [
        fresh_client([7; 32], root.members[1].key.unwrap()),
        fresh_client([8; 32], root.host),
        Channel::new(
            &policy,
            binding.clone(),
            ChannelSide::Client,
            root.host,
            [8; 32],
        )
        .unwrap(),
    ] {
        assert!(endpoint.reconnect(channel, &request).is_err());
        assert_eq!(endpoint.journals().1.checkpoint().unwrap(), old_journal);
        assert_eq!(endpoint.journals().0.applied(), 1);
        assert!(endpoint.failure().is_none());
    }
    let sequence = endpoint.sequence();
    let previous_sequence = sequence.allocate().unwrap();
    endpoint
        .reconnect(
            fresh_client([8; 32], root.members[1].key.unwrap()),
            &request,
        )
        .unwrap();
    assert_eq!(endpoint.queue_pending(MAX_BATCH).unwrap(), 2);
    assert_eq!(endpoint.queue_view(vec![60]).unwrap(), 2);
    let mut proof_seen = false;
    while let Some(wire) = endpoint.poll_send(1).unwrap() {
        if let Some((_, _, bytes)) = fresh_server.receive(&wire, 1).unwrap() {
            assert!(PlayerControl::decode(&root, &bytes).unwrap().sequence > previous_sequence);
            if !proof_seen {
                queue.finish_reconnect(&bytes, &primary, 1).unwrap();
                proof_seen = true;
            } else {
                queue.receive(&bytes, &primary).unwrap();
            }
        }
    }
    assert!(proof_seen);
    assert_eq!(
        queue.pending().collect::<Vec<_>>(),
        vec![(2, &[20][..]), (3, &[50][..])]
    );
    assert_eq!(queue.lossy(), Some((2, &[60][..])));
    // Replay the installed proof on the fresh TLS path. The retained delivery
    // journal prevents a second native mutation or generated followup.
    fresh_server
        .enqueue(
            PacketKind::Output,
            &effect.encode(&root.context().unwrap()).unwrap(),
        )
        .unwrap();
    while let Some(wire) = fresh_server.poll_send(1).unwrap() {
        endpoint
            .receive(&wire, 1, |_, _, _| panic!("reconnect replay applied twice"))
            .unwrap();
    }
    assert_eq!(endpoint.journals().1.checkpoint().unwrap(), old_journal);
    assert_eq!(endpoint.journals().0.applied(), 1);
    assert_eq!(primary.outbox().count(), 1);
}

#[test]
fn normal_player_endpoint_journals_originals_and_applies_only_certified_effects_once() {
    let (root, _, key, mut seq, mut primary, mut endpoint, mut server, mut queue, mut image) =
        normal_player_endpoint();
    endpoint
        .intents_mut()
        .unwrap()
        .append_batch(&[vec![10], vec![20]])
        .unwrap();
    assert_eq!(endpoint.queue_pending(1).unwrap(), 1);
    let shared = endpoint.sequence();
    let mut watch = ProgressWatch::new(
        root.clone(),
        primary.receipt().clone(),
        Activity::Idle,
        [8; 32],
        0,
    )
    .unwrap();
    assert_eq!(
        watch
            .probe_with_sequence(0, shared.allocate().unwrap())
            .unwrap()
            .sequence,
        3
    );
    assert_eq!(endpoint.queue_pending(1).unwrap(), 1);
    assert_eq!(endpoint.queue_pending(MAX_BATCH).unwrap(), 0);
    assert_eq!(endpoint.queue_view(vec![21]).unwrap(), 1);
    endpoint.queue_applied().unwrap();
    let mut sequences = Vec::new();
    while let Some(wire) = endpoint.poll_send(0).unwrap() {
        if let Some((kind, _, bytes)) = server.receive(&wire, 0).unwrap() {
            assert_eq!(kind, PacketKind::Control);
            sequences.push(PlayerControl::decode(&root, &bytes).unwrap().sequence);
            queue.receive(&bytes, &primary).unwrap();
        }
    }
    assert_eq!(sequences, vec![2, 4, 5, 6]);
    assert_eq!(
        queue.pending().collect::<Vec<_>>(),
        vec![(1, &[10][..]), (2, &[20][..])]
    );
    assert_eq!(queue.lossy(), Some((1, &[21][..])));
    for (number, bytes) in queue.pending() {
        image
            .inputs
            .get_mut(&2)
            .unwrap()
            .record(number, bytes)
            .unwrap();
    }
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 2;
    let outputs = vec![
        Output {
            recipient: 2,
            delivery: Delivery::Reliable,
            sequence: 1,
            bytes: vec![30],
        },
        Output {
            recipient: 2,
            delivery: Delivery::Lossy,
            sequence: 1,
            bytes: vec![40],
        },
    ];
    let token = seq
        .stage(
            primary
                .prepare(image.encode(&root).unwrap(), 100, marks, outputs)
                .unwrap()
                .clone(),
        )
        .unwrap();
    primary
        .acknowledge(seq.install(token, &key).unwrap())
        .unwrap();
    queue.refresh(&primary).unwrap();
    let records = seq.publication().to_vec();
    let mut applied = Vec::new();
    for round in 0..2 {
        for record in &records {
            server
                .enqueue(
                    PacketKind::Output,
                    &record.encode(&root.context().unwrap()).unwrap(),
                )
                .unwrap();
        }
        while let Some(wire) = server.poll_send(0).unwrap() {
            if let Some(PlayerEvent::Output {
                applied: changed, ..
            }) = endpoint
                .receive(&wire, 0, |delivery, bytes, intents| {
                    applied.push((delivery, bytes.to_vec()));
                    if delivery == Delivery::Reliable {
                        intents.append_batch(&[vec![50]])?;
                    }
                    Ok(())
                })
                .unwrap()
            {
                assert_eq!(changed, round == 0);
            }
        }
    }
    assert_eq!(
        applied,
        vec![(Delivery::Reliable, vec![30]), (Delivery::Lossy, vec![40])]
    );
    assert_eq!(endpoint.journals().0.applied(), 1);
    assert_eq!(endpoint.journals().1.acknowledged(), 2);
    assert_eq!(
        endpoint.journals().1.pending().collect::<Vec<_>>(),
        vec![(3, &[50][..])]
    );
    assert_eq!(primary.outbox().count(), 1);
    endpoint.queue_applied().unwrap();
    assert_eq!(endpoint.queue_pending(1).unwrap(), 1);
    while let Some(wire) = endpoint.poll_send(0).unwrap() {
        if let Some((_, _, bytes)) = server.receive(&wire, 0).unwrap() {
            queue.receive(&bytes, &primary).unwrap();
        }
    }
    assert_eq!(queue.output_ack(), 1);
    assert_eq!(primary.outbox().count(), 1);
    assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(3, &[50][..])]);
    image.inputs.get_mut(&2).unwrap().record(3, &[50]).unwrap();
    let mut marks = primary.receipt().watermarks.clone();
    let mark = marks.iter_mut().find(|m| m.player == 2).unwrap();
    mark.input = 3;
    mark.output_ack = 1;
    let token = seq
        .stage(
            primary
                .prepare(image.encode(&root).unwrap(), 100, marks, vec![])
                .unwrap()
                .clone(),
        )
        .unwrap();
    primary
        .acknowledge(seq.install(token, &key).unwrap())
        .unwrap();
    queue.refresh(&primary).unwrap();
    let certificate = seq.membership_certificate(&key).unwrap();
    server
        .enqueue(PacketKind::Control, &certificate.encode(&root).unwrap())
        .unwrap();
    let mut membership_seen = false;
    while let Some(wire) = server.poll_send(0).unwrap() {
        membership_seen |= matches!(
            endpoint
                .receive(&wire, 0, |_, _, _| panic!("membership is not game payload"))
                .unwrap(),
            Some(PlayerEvent::Membership(_))
        );
    }
    assert!(membership_seen);
    assert_eq!(endpoint.journals().1.pending().count(), 0);
    assert_eq!(endpoint.journals().1.acknowledged(), 3);
    assert_eq!(primary.outbox().count(), 0);
}

#[test]
fn normal_player_endpoint_application_faults_pause_without_retry_or_further_output() {
    for delivery in [Delivery::Reliable, Delivery::Lossy] {
        for failure in 0..3 {
            let (root, _, key, mut seq, mut primary, mut endpoint, mut server, _, image) =
                normal_player_endpoint();
            let token = seq
                .stage(
                    primary
                        .prepare(
                            image.encode(&root).unwrap(),
                            100,
                            primary.receipt().watermarks.clone(),
                            vec![Output {
                                recipient: 2,
                                delivery,
                                sequence: 1,
                                bytes: vec![30],
                            }],
                        )
                        .unwrap()
                        .clone(),
                )
                .unwrap();
            primary
                .acknowledge(seq.install(token, &key).unwrap())
                .unwrap();
            server
                .enqueue(
                    PacketKind::Output,
                    &seq.publication()[0]
                        .encode(&root.context().unwrap())
                        .unwrap(),
                )
                .unwrap();
            let wire = server.poll_send(0).unwrap().unwrap();
            let mut ingress = ReceiveQueue::default();
            ingress.enqueue(wire.clone()).unwrap();
            let mut calls = 0;
            let result = ingress.poll(|wire| {
                endpoint.receive(wire, 0, |_, _, intents| {
                    calls += 1;
                    intents.append_batch(&[vec![90]])?;
                    match failure {
                        0 => Err(Error::Bounds),
                        1 => Err(Error::RateLimited),
                        _ => panic!("native callback panic"),
                    }
                })
            });
            assert!(result.is_err());
            assert_ne!(result, Err(Error::RateLimited));
            assert_eq!(
                ingress.queued_bytes(),
                0,
                "consumed application failure cannot retry ingress"
            );
            assert_eq!(calls, 1);
            assert!(endpoint.failure().is_some());
            assert_eq!(endpoint.journals().0.applied(), 0);
            assert_eq!(
                endpoint.journals().1.tail(),
                0,
                "failed private journal cannot leak a followup"
            );
            assert_eq!(
                endpoint.receive(&wire, 0, |_, _, _| {
                    calls += 1;
                    Ok(())
                }),
                Err(Error::Closed)
            );
            assert_eq!(calls, 1);
            assert!(endpoint.queue_applied().is_err());
            assert!(endpoint.queue_pending(1).is_err());
            assert!(endpoint.queue_view(vec![0]).is_err());
            assert!(endpoint.intents_mut().is_err());
            assert!(endpoint.poll_send(1).is_err());
        }
    }
}

#[test]
fn normal_player_endpoint_committed_ack_frees_full_journal_before_reliable_followup() {
    for size in [0, 1024] {
        let (root, _, key, mut seq, mut primary, mut endpoint, mut server, _, mut image) =
            normal_player_endpoint();
        let count = if size == 0 {
            MAX_JOURNAL_RECORDS
        } else {
            MAX_JOURNAL_BYTES / size
        };
        let bytes = vec![10; size];
        endpoint
            .intents_mut()
            .unwrap()
            .append_batch(&vec![bytes.clone(); count])
            .unwrap();
        assert!(!endpoint.journals().1.can_reserve(1, 1024));
        for number in 1..=count as u64 {
            image
                .inputs
                .get_mut(&2)
                .unwrap()
                .record(number, &bytes)
                .unwrap();
        }
        let mut marks = primary.receipt().watermarks.clone();
        marks.iter_mut().find(|m| m.player == 2).unwrap().input = count as u64;
        let token = seq
            .stage(
                primary
                    .prepare(
                        image.encode(&root).unwrap(),
                        100,
                        marks,
                        vec![Output {
                            recipient: 2,
                            delivery: Delivery::Reliable,
                            sequence: 1,
                            bytes: vec![30],
                        }],
                    )
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        primary
            .acknowledge(seq.install(token, &key).unwrap())
            .unwrap();
        server
            .enqueue(
                PacketKind::Output,
                &seq.publication()[0]
                    .encode(&root.context().unwrap())
                    .unwrap(),
            )
            .unwrap();
        let mut applied = false;
        while let Some(wire) = server.poll_send(0).unwrap() {
            applied |= endpoint
                .receive(&wire, 0, |_, _, intents| {
                    assert_eq!(intents.acknowledged(), count as u64);
                    assert_eq!(intents.pending().count(), 0);
                    assert_eq!(
                        intents.append_batch(&[vec![50; 1024]]).unwrap(),
                        vec![count as u64 + 1]
                    );
                    Ok(())
                })
                .unwrap()
                .is_some();
        }
        assert!(applied);
        assert!(endpoint.failure().is_none());
        assert_eq!(endpoint.journals().0.applied(), 1);
        assert_eq!(endpoint.journals().1.acknowledged(), count as u64);
        assert_eq!(endpoint.journals().1.pending().count(), 1);
        assert_eq!(endpoint.journals().1.tail(), count as u64 + 1);
    }
}

#[test]
fn normal_player_endpoint_rejects_lost_originals_before_any_game_callback() {
    let (root, _, key, mut seq, mut primary, mut endpoint, mut server, _, mut image) =
        normal_player_endpoint();
    image.inputs.get_mut(&2).unwrap().record(1, &[10]).unwrap();
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
    let token = seq
        .stage(
            primary
                .prepare(
                    image.encode(&root).unwrap(),
                    100,
                    marks,
                    vec![Output {
                        recipient: 2,
                        delivery: Delivery::Reliable,
                        sequence: 1,
                        bytes: vec![30],
                    }],
                )
                .unwrap()
                .clone(),
        )
        .unwrap();
    primary
        .acknowledge(seq.install(token, &key).unwrap())
        .unwrap();
    server
        .enqueue(
            PacketKind::Output,
            &seq.publication()[0]
                .encode(&root.context().unwrap())
                .unwrap(),
        )
        .unwrap();
    while let Some(wire) = server.poll_send(0).unwrap() {
        assert!(endpoint
            .receive(&wire, 0, |_, _, _| panic!(
                "lost journal reached native game"
            ))
            .is_err());
    }
    assert!(endpoint.failure().is_some());
    assert_eq!(endpoint.journals().0.applied(), 0);
    assert_eq!(endpoint.journals().1.tail(), 0);
}

#[test]
fn initial_player_attachment_is_owned_once_and_invalid_attempts_do_not_consume_it() {
    let (mut descriptor, host, standby, player) = descriptor_fixture();
    descriptor.consent(&standby).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &standby).unwrap();
    let mut primary = Primary::armed(
        root.context().unwrap(),
        image.encode(&root).unwrap(),
        seq.receipt().clone(),
    )
    .unwrap();
    let certificate = seq.membership_certificate(&standby).unwrap();
    let channel = |certificate: &MembershipCertificate, key: &Keys, tls| {
        Channel::new(
            &EndpointPolicy {
                descriptor: descriptor.clone(),
                role: LinkRole::Original,
                promotion: None,
                membership: Some(certificate.clone()),
            },
            ConnectionBinding {
                session: root.session,
                descriptor: root.digest().unwrap(),
                term: 0,
                client: LinkRole::Player,
                server: LinkRole::Original,
            },
            ChannelSide::Server,
            key.public_key().to_bytes(),
            tls,
        )
        .unwrap()
    };
    let first = channel(&certificate, &player, [1; 32]);
    let mut corrupt = certificate.clone();
    corrupt.signature[0] ^= 1;
    assert!(primary.attach_player(&first, corrupt).is_err());
    let queue = primary.attach_player(&first, certificate.clone()).unwrap();
    assert!(primary.attach_player(&first, certificate.clone()).is_err());
    drop(queue);
    assert!(primary
        .attach_player(
            &channel(&certificate, &player, [2; 32]),
            certificate.clone()
        )
        .is_err());
    // An unclaimed initial player can attach after other ordinary commits;
    // it cannot reclaim the already consumed route, even with a fresh TLS link.
    let token = seq
        .stage(
            primary
                .prepare(
                    image.encode(&root).unwrap(),
                    100,
                    primary.receipt().watermarks.clone(),
                    vec![],
                )
                .unwrap()
                .clone(),
        )
        .unwrap();
    primary
        .acknowledge(seq.install(token, &standby).unwrap())
        .unwrap();
    let certificate = seq.membership_certificate(&standby).unwrap();
    assert!(primary
        .attach_player(&channel(&certificate, &host, [3; 32]), certificate.clone())
        .is_ok());
    assert!(primary
        .attach_player(&channel(&certificate, &player, [4; 32]), certificate)
        .is_err());
}

#[test]
fn reconnect_requires_fresh_retained_journals_and_preserves_control_history() {
    for case in [
        "valid", "nonce", "tls", "tail", "output", "sequence", "expiry", "replace", "frontier",
        "clock",
    ] {
        let (mut descriptor, host, standby, player) = descriptor_fixture();
        descriptor.consent(&standby).unwrap();
        let root = descriptor.root.clone();
        let mut image =
            SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
        let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &standby).unwrap();
        let mut primary = Primary::armed(
            root.context().unwrap(),
            image.encode(&root).unwrap(),
            seq.receipt().clone(),
        )
        .unwrap();
        let channel = |certificate: &MembershipCertificate, tls| {
            Channel::new(
                &EndpointPolicy {
                    descriptor: descriptor.clone(),
                    role: LinkRole::Original,
                    promotion: None,
                    membership: Some(certificate.clone()),
                },
                ConnectionBinding {
                    session: root.session,
                    descriptor: root.digest().unwrap(),
                    term: 0,
                    client: LinkRole::Player,
                    server: LinkRole::Original,
                },
                ChannelSide::Server,
                player.public_key().to_bytes(),
                tls,
            )
            .unwrap()
        };
        let certificate = seq.membership_certificate(&standby).unwrap();
        let mut queue = primary
            .attach_player(&channel(&certificate, [7; 32]), certificate.clone())
            .unwrap();
        let mut intents = IntentJournal::default();
        intents.append_batch(&[vec![10], vec![20]]).unwrap();
        for number in 1..=2 {
            let wire = PlayerControl::sign(
                &root,
                &certificate,
                0,
                number,
                2,
                [7; 32],
                PlayerAction::Intent {
                    number,
                    bytes: vec![number as u8 * 10],
                },
                &player,
            )
            .unwrap()
            .encode(&root)
            .unwrap();
            queue.receive(&wire, &primary).unwrap();
        }
        image.inputs.get_mut(&2).unwrap().record(1, &[10]).unwrap();
        let mut marks = primary.receipt().watermarks.clone();
        marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
        let token = seq
            .stage(
                primary
                    .prepare(
                        image.encode(&root).unwrap(),
                        100,
                        marks,
                        vec![Output {
                            recipient: 2,
                            delivery: Delivery::Reliable,
                            sequence: 1,
                            bytes: vec![50],
                        }],
                    )
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        primary
            .acknowledge(seq.install(token, &standby).unwrap())
            .unwrap();
        queue.refresh(&primary).unwrap();
        let certificate = seq.membership_certificate(&standby).unwrap();
        let mut delivery = DeliveryJournal::default();
        delivery
            .apply_certified(
                &root.context().unwrap(),
                2,
                primary.outbox().next().unwrap(),
                |_| Ok(()),
            )
            .unwrap();
        intents.acknowledge(1).unwrap();
        queue
            .receive(
                &PlayerControl::sign(
                    &root,
                    &certificate,
                    0,
                    3,
                    2,
                    [7; 32],
                    PlayerAction::Applied {
                        output: 1,
                        tail: 2,
                        cut: None,
                    },
                    &player,
                )
                .unwrap()
                .encode(&root)
                .unwrap(),
                &primary,
            )
            .unwrap();
        // A transport attachment or matching key alone cannot replace a client.
        assert!(queue
            .begin_reconnect(
                &channel(&certificate, [7; 32]),
                certificate.clone(),
                &primary,
                10,
                &host
            )
            .is_err());
        assert!(queue
            .begin_reconnect(
                &channel(&certificate, [8; 32]),
                certificate.clone(),
                &primary,
                10,
                &player
            )
            .is_err());
        assert!(primary
            .attach_player(&channel(&certificate, [8; 32]), certificate.clone())
            .is_err());
        let request = queue
            .begin_reconnect(
                &channel(&certificate, [8; 32]),
                certificate.clone(),
                &primary,
                10,
                &host,
            )
            .unwrap();
        let wire = request.encode(&root).unwrap();
        assert_eq!(ReconnectChallenge::decode(&root, &wire).unwrap(), request);
        for end in [0, 1, 64, wire.len() - 65, wire.len() - 1] {
            assert!(ReconnectChallenge::decode(&root, &wire[..end]).is_err());
        }
        let mut invalid = wire.clone();
        invalid.push(0);
        assert!(ReconnectChallenge::decode(&root, &invalid).is_err());
        let mut invalid = wire;
        let last = invalid.len() - 1;
        invalid[last] ^= 1;
        assert!(ReconnectChallenge::decode(&root, &invalid).is_err());
        assert!(PlayerControl::resume_connection(
            &root, &request, [9; 32], &delivery, &intents, 4, &player
        )
        .is_err());
        assert!(PlayerControl::resume_connection(
            &root,
            &request,
            [8; 32],
            &delivery,
            &IntentJournal::default(),
            4,
            &player
        )
        .is_err());
        assert!(PlayerControl::resume_connection(
            &root, &request, [8; 32], &delivery, &intents, 4, &host
        )
        .is_err());
        let mut proof = PlayerControl::resume_connection(
            &root, &request, [8; 32], &delivery, &intents, 4, &player,
        )
        .unwrap();
        let mut now = 11;
        match case {
            "nonce" => {
                proof.action = PlayerAction::Applied {
                    output: 1,
                    tail: 2,
                    cut: Some([42; 32]),
                }
            }
            "tail" => {
                proof.action = PlayerAction::Applied {
                    output: 1,
                    tail: 1,
                    cut: Some(request.nonce),
                }
            }
            "output" => {
                proof.action = PlayerAction::Applied {
                    output: 0,
                    tail: 2,
                    cut: Some(request.nonce),
                }
            }
            "tls" => proof.tls = [9; 32],
            "sequence" => proof.sequence = 1,
            "expiry" => now = 5010,
            "clock" => {
                queue
                    .begin_reconnect(
                        &channel(&certificate, [8; 32]),
                        certificate.clone(),
                        &primary,
                        12,
                        &host,
                    )
                    .unwrap();
                now = 11;
            }
            "replace" => {
                queue
                    .begin_reconnect(
                        &channel(&certificate, [8; 32]),
                        certificate.clone(),
                        &primary,
                        10,
                        &host,
                    )
                    .unwrap();
            }
            "frontier" => {
                for _ in 0..3 {
                    let token = seq
                        .stage(
                            primary
                                .prepare(
                                    image.encode(&root).unwrap(),
                                    100,
                                    primary.receipt().watermarks.clone(),
                                    vec![],
                                )
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                    primary
                        .acknowledge(seq.install(token, &standby).unwrap())
                        .unwrap();
                }
            }
            _ => {}
        }
        // Re-sign altered fields to test semantic validation after valid crypto.
        proof = PlayerControl::sign(
            &root,
            &certificate,
            0,
            proof.sequence,
            2,
            proof.tls,
            proof.action,
            &player,
        )
        .unwrap();
        let encoded = proof.encode(&root).unwrap();
        let result = queue.finish_reconnect(&encoded, &primary, now);
        if case == "valid" || case == "frontier" {
            result.unwrap();
            assert!(queue.finish_reconnect(&encoded, &primary, now).is_err());
            let action = PlayerAction::Intent {
                number: 2,
                bytes: vec![20],
            };
            let replay =
                PlayerControl::sign(&root, &certificate, 0, 5, 2, [8; 32], action, &player)
                    .unwrap()
                    .encode(&root)
                    .unwrap();
            assert!(!queue.receive(&replay, &primary).unwrap());
        } else {
            assert!(result.is_err(), "accepted {case}");
        }
        assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(2, &[20][..])]);
        assert_eq!(primary.outbox().count(), 1);
        assert_eq!(
            primary
                .receipt()
                .watermarks
                .iter()
                .find(|m| m.player == 2)
                .unwrap()
                .output_ack,
            0
        );
        assert_eq!(delivery.applied(), 1);
        assert_eq!(intents.pending().collect::<Vec<_>>(), vec![(2, &[20][..])]);
    }
}

#[test]
fn player_queue_caps_are_retryable_and_committed_original_conflicts_are_sticky() {
    for size in [0, 1024] {
        let (mut descriptor, _, key, player) = descriptor_fixture();
        descriptor.consent(&key).unwrap();
        let root = descriptor.root.clone();
        let image =
            SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
        let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
        let mut primary = Primary::armed(
            root.context().unwrap(),
            image.encode(&root).unwrap(),
            seq.receipt().clone(),
        )
        .unwrap();
        let certificate = seq.membership_certificate(&key).unwrap();
        let policy = EndpointPolicy {
            descriptor,
            role: LinkRole::Original,
            promotion: None,
            membership: Some(certificate.clone()),
        };
        let binding = ConnectionBinding {
            session: root.session,
            descriptor: root.digest().unwrap(),
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        };
        let channel = Channel::new(
            &policy,
            binding,
            ChannelSide::Server,
            player.public_key().to_bytes(),
            [1; 32],
        )
        .unwrap();
        let mut queue = primary
            .attach_player(&channel, certificate.clone())
            .unwrap();
        let capacity = if size == 0 {
            MAX_JOURNAL_RECORDS
        } else {
            MAX_JOURNAL_BYTES / size
        } as u64;
        let payload = vec![3; size];
        let wire = |number| {
            PlayerControl::sign(
                &root,
                &certificate,
                0,
                number,
                2,
                [1; 32],
                PlayerAction::Intent {
                    number,
                    bytes: payload.clone(),
                },
                &player,
            )
            .unwrap()
            .encode(&root)
            .unwrap()
        };
        for number in 1..=capacity {
            assert!(queue.receive(&wire(number), &primary).unwrap());
        }
        let overflow = wire(capacity + 1);
        assert_eq!(queue.receive(&overflow, &primary), Err(Error::Bounds));
        assert_eq!(queue.pending().count(), capacity as usize);
        let mut post = SessionImage::decode(&root, primary.committed_image()).unwrap();
        for (number, bytes) in queue.pending().take(capacity as usize / 2) {
            post.inputs
                .get_mut(&2)
                .unwrap()
                .record(number, bytes)
                .unwrap();
        }
        let mut marks = primary.receipt().watermarks.clone();
        marks.iter_mut().find(|m| m.player == 2).unwrap().input = capacity / 2;
        let candidate = primary
            .prepare(post.encode(&root).unwrap(), 100, marks, vec![])
            .unwrap()
            .clone();
        let token = seq.stage(candidate).unwrap();
        let receipt = seq.install(token, &key).unwrap();
        primary.acknowledge(receipt).unwrap();
        queue.refresh(&primary).unwrap();
        assert!(queue.receive(&overflow, &primary).unwrap());
        assert_eq!(queue.pending().count(), capacity as usize / 2 + 1);
        // Even a signed committed image must not contradict a retained original.
        let number = capacity / 2 + 1;
        post.inputs
            .get_mut(&2)
            .unwrap()
            .record(number, &[9])
            .unwrap();
        let mut marks = primary.receipt().watermarks.clone();
        marks.iter_mut().find(|m| m.player == 2).unwrap().input = number;
        let candidate = primary
            .prepare(post.encode(&root).unwrap(), 100, marks, vec![])
            .unwrap()
            .clone();
        let token = seq.stage(candidate).unwrap();
        let receipt = seq.install(token, &key).unwrap();
        primary.acknowledge(receipt).unwrap();
        assert_eq!(queue.refresh(&primary), Err(Error::Conflict));
        assert_eq!(queue.refresh(&primary), Err(Error::Closed));
        assert_eq!(queue.validate_for(&root, &primary), Err(Error::Closed));
    }
}

#[test]
fn one_slot_selection_is_fair_to_busy_and_quiet_humans_bots_and_views() {
    let (descriptor, host, key, player) = descriptor_fixture();
    let mut root = descriptor.root;
    root.members.push(Member {
        player: 4,
        seat: 3,
        key: None,
    });
    let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&key).unwrap();
    let image = SessionImage::initial(
        &root,
        &[(1, 10), (2, 11), (3, 12), (4, 13)],
        vec![0],
        1,
        100,
    )
    .unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let mut primary = Primary::armed(
        root.context().unwrap(),
        image.encode(&root).unwrap(),
        seq.receipt().clone(),
    )
    .unwrap();
    let cert = seq.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor,
        role: LinkRole::Original,
        promotion: None,
        membership: Some(cert.clone()),
    };
    let mut queues = Vec::new();
    for keys in [&host, &player] {
        let channel = Channel::new(
            &policy,
            ConnectionBinding {
                session: root.session,
                descriptor: root.digest().unwrap(),
                term: 0,
                client: LinkRole::Player,
                server: LinkRole::Original,
            },
            ChannelSide::Server,
            keys.public_key().to_bytes(),
            [1; 32],
        )
        .unwrap();
        queues.push(primary.attach_player(&channel, cert.clone()).unwrap());
    }
    let mut controls = [0u64; 2];
    let mut tail = [0u64; 2];
    let mut seen = std::collections::BTreeSet::new();
    for round in 0..12 {
        for (i, keys) in [&host, &player].into_iter().enumerate() {
            let target = if i == 0 {
                256
            } else if round == 0 {
                1
            } else {
                0
            };
            while queues[i].pending().count() < target {
                tail[i] += 1;
                controls[i] += 1;
                let wire = PlayerControl::sign(
                    &root,
                    &cert,
                    0,
                    controls[i],
                    i as u64 + 1,
                    [1; 32],
                    PlayerAction::Intent {
                        number: tail[i],
                        bytes: vec![i as u8],
                    },
                    keys,
                )
                .unwrap()
                .encode(&root)
                .unwrap();
                queues[i].receive(&wire, &primary).unwrap();
            }
            controls[i] += 1;
            let wire = PlayerControl::sign(
                &root,
                &cert,
                0,
                controls[i],
                i as u64 + 1,
                [1; 32],
                PlayerAction::Lossy {
                    number: round + 1,
                    bytes: vec![10 + i as u8],
                },
                keys,
            )
            .unwrap()
            .encode(&root)
            .unwrap();
            queues[i].receive(&wire, &primary).unwrap();
        }
        let mut post = SessionImage::decode(&root, primary.committed_image()).unwrap();
        let start = post.inputs[&3].handled();
        let locals = [
            LocalInputs {
                player: 3,
                originals: (start + 1..=start + 256).map(|n| (n, vec![3])).collect(),
            },
            LocalInputs {
                player: 4,
                originals: if post.inputs[&4].handled() == 0 {
                    vec![(1, vec![4])]
                } else {
                    vec![]
                },
            },
        ];
        let selected = select_player_and_local_inputs(
            &root,
            &primary,
            &[&queues[0], &queues[1]],
            &locals,
            1,
            1024,
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        let mut marks = primary.receipt().watermarks.clone();
        for input in selected {
            match input {
                SelectedPlayerInput::Reliable {
                    player,
                    number,
                    bytes,
                } => {
                    seen.insert((player, false));
                    post.inputs
                        .get_mut(&player)
                        .unwrap()
                        .record(number, &bytes)
                        .unwrap();
                    marks.iter_mut().find(|m| m.player == player).unwrap().input = number;
                }
                SelectedPlayerInput::Lossy { player, number, .. } => {
                    seen.insert((player, true));
                    queues[player as usize - 1].discard_lossy(number);
                }
            }
        }
        let candidate = primary
            .prepare(post.encode(&root).unwrap(), 100, marks, vec![])
            .unwrap()
            .clone();
        let token = seq.stage(candidate).unwrap();
        let receipt = seq.install(token, &key).unwrap();
        primary.acknowledge(receipt).unwrap();
        for queue in &mut queues {
            queue.refresh(&primary).unwrap();
        }
    }
    for expected in [
        (1, false),
        (2, false),
        (3, false),
        (4, false),
        (1, true),
        (2, true),
    ] {
        assert!(seen.contains(&expected), "starved {expected:?}");
    }
    assert!(select_player_inputs(&root, &primary, &[&queues[0]], 1, 0)
        .unwrap()
        .is_empty());
}

#[test]
fn human_control_replay_conflict_is_sticky_and_bad_lengths_or_wrap_never_decode() {
    let (mut descriptor, _, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let seq = Sequencer::arm_session(root.clone(), image, &key).unwrap();
    let certificate = seq.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor,
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let tls = [3; 32];
    let server = Channel::new(
        &policy,
        binding,
        ChannelSide::Server,
        player.public_key().to_bytes(),
        tls,
    )
    .unwrap();
    let mut inbox = PlayerInbox::new(&server, certificate.clone()).unwrap();
    let make = |sequence, bytes| {
        PlayerControl::sign(
            &root,
            &certificate,
            0,
            sequence,
            2,
            tls,
            PlayerAction::Intent { number: 1, bytes },
            &player,
        )
    };
    let first = make(1, vec![1]).unwrap().encode(&root).unwrap();
    inbox.receive(&first).unwrap();
    let conflict = make(1, vec![2]).unwrap().encode(&root).unwrap();
    assert_eq!(inbox.receive(&conflict), Err(Error::Conflict));
    assert_eq!(inbox.receive(&first), Err(Error::Closed));
    assert!(make(0, vec![]).is_err());
    assert!(make(2, vec![0; 1025]).is_err());
    let mut trailing = first.clone();
    trailing.push(0);
    assert!(PlayerControl::decode(&root, &trailing).is_err());
    let mut oversized = first;
    let length_at = 1 + 16 + 32 + 8 + 1 + 8 + 8 + 32 + 1 + 8;
    oversized[length_at..length_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(PlayerControl::decode(&root, &oversized).is_err());
    let mut inbox = PlayerInbox::new(&server, certificate.clone()).unwrap();
    let final_record = make(u64::MAX, vec![]).unwrap().encode(&root).unwrap();
    assert!(inbox.receive(&final_record).unwrap().is_some());
    assert!(make(0, vec![]).is_err());
}

#[test]
fn recovery_families_share_resume_ids_and_faults_stop_the_final_barrier() {
    let (root, key, mut recovery, host, _) = typed_local_recovery_keys(0);
    recovery.begin_round().unwrap();
    let request = recovery.issue_input_round(1, [1; 32], &key, 1).unwrap();
    let cut = PlayerControl::seal_round(
        &root,
        recovery.promotion(),
        &request,
        [1; 32],
        &DeliveryJournal::default(),
        &IntentJournal::default(),
        1,
        &host,
    )
    .unwrap();
    assert_eq!(
        recovery.accept_input_cut(&cut, [9; 32], 1),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        recovery.accept_input_cut(&cut, [1; 32], 1),
        Err(Error::Conflict)
    );
    assert_eq!(recovery.poll(2), Err(Error::Closed));
    assert_eq!(recovery.begin_round(), Err(Error::Closed));
    assert_eq!(recovery.replay(), Err(Error::Closed));
    assert_eq!(
        recovery.commit_local_clients(&key, |_| panic!("faulted recovery")),
        Err(Error::Closed)
    );

    let (root, host, key, _, mut barrier, _) = converged_recovery();
    let cut = barrier.issue(1, [1; 32], &key, 20).unwrap();
    let ready = RecoveryReady::sign(
        &root,
        barrier.promotion(),
        &cut,
        [1; 32],
        &DeliveryJournal::default(),
        &IntentJournal::default(),
        0,
        1,
        &host,
    )
    .unwrap();
    assert_eq!(
        barrier.accept(&ready, [9; 32], 20),
        Err(Error::Unauthorized)
    );
    assert_eq!(barrier.accept(&ready, [1; 32], 20), Err(Error::Conflict));
    assert_eq!(barrier.issue(2, [2; 32], &key, 21), Err(Error::Closed));
    assert!(matches!(barrier.finish(&key, 21), Err(Error::Closed)));
}

#[test]
fn each_remote_input_round_uses_a_fresh_tls_bound_cut_from_actual_retained_journals() {
    let (root, key, mut recovery, host, player) = typed_local_recovery_keys(1);
    let promotion = recovery.promotion().clone();
    let delivery = DeliveryJournal::default();
    let empty = IntentJournal::default();
    let mut intents = IntentJournal::default();
    intents.append_batch(&[vec![7]]).unwrap();
    recovery.begin_round().unwrap();
    assert_eq!(recovery.seal_inputs(2, 1), Err(Error::Unauthorized));
    recovery.seal_inputs(3, 0).unwrap();
    let host_request = recovery.issue_input_round(1, [1; 32], &key, 1).unwrap();
    let host_cut = PlayerControl::seal_round(
        &root,
        &promotion,
        &host_request,
        [1; 32],
        &delivery,
        &empty,
        2,
        &host,
    )
    .unwrap();
    recovery.accept_input_cut(&host_cut, [1; 32], 1).unwrap();
    let replaced = recovery.issue_input_round(2, [2; 32], &key, 1).unwrap();
    let request = recovery.issue_input_round(2, [2; 32], &key, 2).unwrap();
    assert_ne!(request.nonce, replaced.nonce);
    let wire = request.encode(&root, &promotion).unwrap();
    assert_eq!(
        InputRound::decode(&root, &promotion, &wire).unwrap(),
        request
    );
    let mut bad = wire.clone();
    bad.push(0);
    assert!(InputRound::decode(&root, &promotion, &bad).is_err());
    let old = PlayerControl::seal_round(
        &root, &promotion, &replaced, [2; 32], &delivery, &intents, 2, &player,
    )
    .unwrap();
    assert_eq!(
        recovery.accept_input_cut(&old, [2; 32], 2),
        Err(Error::Stale)
    );
    assert!(PlayerControl::seal_round(
        &root, &promotion, &request, [9; 32], &delivery, &intents, 2, &player
    )
    .is_err());
    assert!(PlayerControl::seal_round(
        &root, &promotion, &request, [2; 32], &delivery, &intents, 2, &host
    )
    .is_err());
    let mut lost_originals = IntentJournal::default();
    lost_originals.append_batch(&[vec![7]]).unwrap();
    lost_originals.acknowledge(1).unwrap();
    assert!(PlayerControl::seal_round(
        &root,
        &promotion,
        &request,
        [2; 32],
        &delivery,
        &lost_originals,
        2,
        &player
    )
    .is_err());
    let cut = PlayerControl::seal_round(
        &root, &promotion, &request, [2; 32], &delivery, &intents, 3, &player,
    )
    .unwrap();
    recovery.accept_input_cut(&cut, [2; 32], 2).unwrap();
    assert_eq!(recovery.phase(), RecoveryPhase::Draining);
    recovery.accept_input_cut(&cut, [2; 32], 3).unwrap();
    recovery.supply(2, 1, vec![7]).unwrap();
    let before = recovery.sequencer().image().to_vec();
    recovery
        .apply_next(&key, |_, _, _, histories| {
            let mut image = SessionImage::decode(&root, &before).unwrap();
            image.inputs = histories.clone();
            Ok((image.encode(&root).unwrap(), vec![]))
        })
        .unwrap();
    recovery.begin_round().unwrap();
    recovery.seal_inputs(3, 0).unwrap();
    let host_request = recovery.issue_input_round(1, [1; 32], &key, 4).unwrap();
    let host_cut = PlayerControl::seal_round(
        &root,
        &promotion,
        &host_request,
        [1; 32],
        &delivery,
        &empty,
        3,
        &host,
    )
    .unwrap();
    recovery.accept_input_cut(&host_cut, [1; 32], 4).unwrap();
    let next = recovery.issue_input_round(2, [2; 32], &key, 4).unwrap();
    assert_eq!(
        recovery.accept_input_cut(&cut, [2; 32], 4),
        Err(Error::Stale)
    );
    let lost = IntentJournal::default();
    assert!(PlayerControl::seal_round(
        &root, &promotion, &next, [2; 32], &delivery, &lost, 4, &player
    )
    .is_err());
    let final_cut = PlayerControl::seal_round(
        &root, &promotion, &next, [2; 32], &delivery, &intents, 4, &player,
    )
    .unwrap();
    recovery.accept_input_cut(&final_cut, [2; 32], 4).unwrap();
    assert_eq!(recovery.phase(), RecoveryPhase::Departures);
    recovery
        .commit_departures(&key, |_, _, _| panic!("no absent peer"))
        .unwrap();
    assert_eq!(recovery.phase(), RecoveryPhase::Ready);
}

#[test]
fn inbox_construction_cannot_restore_retired_or_readmitted_key_to_an_old_player_id() {
    let (mut descriptor, _, key, player) = descriptor_fixture();
    descriptor.consent(&key).unwrap();
    let root = descriptor.root.clone();
    let mut image =
        SessionImage::initial(&root, &[(1, 10), (2, 11), (3, 12)], vec![0], 1, 100).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let original = seq.membership_certificate(&key).unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let policy = |cert: MembershipCertificate| EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(cert),
    };
    let old_channel = Channel::new(
        &policy(original.clone()),
        binding.clone(),
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [1; 32],
    )
    .unwrap();
    image.members.retain(|m| m.player != 2);
    image.inputs.remove(&2);
    image.membership_revision += 1;
    let mut marks = seq.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().retired = true;
    let token = seq
        .stage(
            seq.next(image.encode(&root).unwrap(), 100, marks.clone(), vec![])
                .unwrap(),
        )
        .unwrap();
    seq.install(token, &key).unwrap();
    let retired = seq.membership_certificate(&key).unwrap();
    image.members.push(SessionMember {
        player: 4,
        seat: 1,
        key: Some(player.public_key().to_bytes()),
        logical_peer: 99,
    });
    image.inputs.insert(4, HandledInputs::default());
    image.membership_revision += 1;
    image.next_player = 5;
    marks.push(Watermark {
        player: 4,
        input: 0,
        output_ack: 0,
        retired: false,
    });
    let token = seq
        .stage(
            seq.next(image.encode(&root).unwrap(), 100, marks, vec![])
                .unwrap(),
        )
        .unwrap();
    seq.install(token, &key).unwrap();
    let current = seq.membership_certificate(&key).unwrap();
    let new_channel = Channel::new(
        &policy(current.clone()),
        binding,
        ChannelSide::Server,
        player.public_key().to_bytes(),
        [2; 32],
    )
    .unwrap();
    assert!(PlayerInbox::new(&new_channel, original).is_err());
    assert!(PlayerInbox::new(&new_channel, retired).is_err());
    assert!(PlayerInbox::new(&old_channel, current.clone()).is_err());
    assert_eq!(PlayerInbox::new(&new_channel, current).unwrap().player(), 4);
}

#[test]
fn prepared_player_control_receives_only_public_pulses_from_the_owned_replica_and_closes_on_retirement(
) {
    let (root, host, key, mut primary, mut standby, mut image, player) =
        replication_actors_with_player();
    let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&key).unwrap();
    let certificate = standby.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor,
        role: LinkRole::Standby,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let tls = [0x61; 32];
    let mut client = Channel::new(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.standby,
        tls,
    )
    .unwrap();
    let mut server = Channel::new(
        &policy,
        binding,
        ChannelSide::Server,
        player.public_key().to_bytes(),
        tls,
    )
    .unwrap();
    let mut watch = ProgressWatch::new(
        root.clone(),
        standby.receipt().clone(),
        Activity::Idle,
        tls,
        0,
    )
    .unwrap();
    let probe = watch.probe(0).unwrap();
    client
        .enqueue(PacketKind::Control, &probe.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = client.poll_send(0).unwrap() {
        standby
            .receive_control_probe(&mut server, &wire, 0, &key, Activity::Idle)
            .unwrap();
    }
    while let Some(wire) = server.poll_send(0).unwrap() {
        if let Some((kind, _, bytes)) = client.receive(&wire, 0).unwrap() {
            assert_eq!(kind, PacketKind::Control);
            let pulse = Pulse::decode(&root, &bytes).unwrap();
            assert_eq!(pulse.frontier, *standby.receipt());
            watch.pulse(&pulse, 0).unwrap();
        }
    }
    assert_eq!(watch.status(100).unwrap(), WatchStatus::Live);
    assert!(client.enqueue(PacketKind::Candidate, &[1]).is_err());
    let intent = PlayerControl::sign(
        &root,
        &certificate,
        0,
        1,
        2,
        tls,
        PlayerAction::Intent {
            number: 1,
            bytes: vec![1],
        },
        &player,
    )
    .unwrap();
    client
        .enqueue(PacketKind::Control, &intent.encode(&root).unwrap())
        .unwrap();
    let mut rejected = false;
    while let Some(wire) = client.poll_send(100).unwrap() {
        if standby
            .receive_control_probe(&mut server, &wire, 100, &key, Activity::Idle)
            .is_err()
        {
            rejected = true;
        }
    }
    assert!(rejected);
    assert_eq!(standby.receipt().index, 0);
    // Retire this human without changing the fixed original authority pair.
    image.members.retain(|m| m.player != 2);
    image.inputs.remove(&2);
    image.membership_revision += 1;
    let mut marks = primary.primary().receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().retired = true;
    primary.prepare(image, marks, vec![]).unwrap();
    while let Some(wire) = primary.poll_send(100).unwrap() {
        standby
            .receive(&wire, 100, &key, Activity::Idle, |candidate, _, _| {
                Ok(candidate.image.clone())
            })
            .unwrap();
    }
    let probe = watch.probe(100).unwrap();
    client
        .enqueue(PacketKind::Control, &probe.encode(&root).unwrap())
        .unwrap();
    let wire = client.poll_send(100).unwrap().unwrap();
    assert_eq!(
        standby.receive_control_probe(&mut server, &wire, 100, &key, Activity::Idle),
        Err(Error::Unauthorized)
    );
    assert_eq!(standby.receipt().index, 1);
}

#[test]
fn actual_quic_player_input_output_and_ack_use_handshake_channels_and_committed_journals() {
    use fray_net::{Bytes, ClientEvent, HostEvent, Identity, NetConfig, RoomInfo};
    use std::time::{Duration, Instant};
    fn until(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(Instant::now() < deadline, "QUIC framed test timeout");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let mut cfg = NetConfig::new(std::env::temp_dir(), "migration-player-wire-test").lan_only();
    cfg.lan_port = 0;
    cfg.host_has_player = false;
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let host = fray_net::host(
        &cfg,
        &original,
        RoomInfo {
            name: "Original test".into(),
            max_players: 8,
        },
    );
    until(|| matches!(host.poll(), Some(HostEvent::Ready { .. })));
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.app = cfg.app_tag.clone();
    root.host = original.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.code = room_code_hash(host.code()).unwrap();
    root.members = vec![Member {
        player: 1,
        seat: 0,
        key: Some(player.pubkey().to_bytes()),
    }];
    let mut descriptor = Descriptor::offer(root.clone(), original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let mut image = SessionImage::initial(&root, &[(1, 99)], vec![0], 1, 0).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), standby.keys()).unwrap();
    let mut primary = Primary::armed(
        root.context().unwrap(),
        image.encode(&root).unwrap(),
        seq.receipt().clone(),
    )
    .unwrap();
    let certificate = seq.membership_certificate(standby.keys()).unwrap();
    host.pin_session(descriptor.clone()).unwrap();
    host.update_session_membership(certificate.clone()).unwrap();
    let addr = std::net::SocketAddr::new(
        std::net::Ipv4Addr::LOCALHOST.into(),
        host.local_addr().unwrap().port(),
    );
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let mut client = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &host.lan_token(),
        binding.clone(),
        original.pubkey(),
    )
    .unwrap();
    let mut connected = false;
    let mut peer = None;
    until(|| {
        while let Some(event) = client.poll() {
            match event {
                ClientEvent::Connected { host_pubkey, .. } => {
                    assert_eq!(host_pubkey, original.pubkey());
                    connected = true;
                }
                ClientEvent::Progress { .. } => {}
                other => panic!("unexpected connection event {other:?}"),
            }
        }
        while let Some(event) = host.poll() {
            if let HostEvent::PeerJoined {
                peer: id, pubkey, ..
            } = event
            {
                assert_eq!(pubkey, player.pubkey());
                peer = Some(id);
            }
        }
        connected && peer.is_some()
    });
    let mut peer = peer.unwrap();
    let mut policy = EndpointPolicy {
        descriptor,
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let mut sending = client.migration_channel(&policy).unwrap();
    let mut receiving = host.migration_channel(peer).unwrap();
    assert!(client.migration_channel(&policy).is_err());
    assert!(host.migration_channel(peer).is_err());
    assert_eq!(sending.tls(), receiving.tls());
    assert_eq!(sending.local_key(), Some(player.pubkey().to_bytes()));
    assert_eq!(receiving.local_key(), Some(original.pubkey().to_bytes()));
    assert_eq!(receiving.remote_key(), player.pubkey().to_bytes());
    let mut queue = primary
        .attach_player(&receiving, certificate.clone())
        .unwrap();
    let mut intents = IntentJournal::default();
    let payload = vec![0xa5; 1024];
    assert_eq!(intents.append_batch(&[payload.clone()]).unwrap(), vec![1]);
    let record = PlayerControl::sign(
        &root,
        &certificate,
        0,
        1,
        1,
        sending.tls(),
        PlayerAction::Intent {
            number: 1,
            bytes: payload.clone(),
        },
        player.keys(),
    )
    .unwrap();
    sending
        .enqueue(PacketKind::Control, &record.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut input = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { peer: id, bytes } = event {
                assert_eq!(id, peer);
                if let Some((kind, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert_eq!(kind, PacketKind::Control);
                    input = queue.receive(&bytes, &primary).unwrap();
                }
            }
        }
        input
    });
    assert_eq!(
        queue.pending().collect::<Vec<_>>(),
        vec![(1, payload.as_slice())]
    );
    assert_eq!(intents.pending().count(), 1);
    assert_eq!(seq.receipt().index, 0);
    image
        .inputs
        .get_mut(&1)
        .unwrap()
        .record(1, &payload)
        .unwrap();
    image.game = vec![1];
    let marks = vec![Watermark {
        player: 1,
        input: 1,
        output_ack: 0,
        retired: false,
    }];
    let token = seq
        .stage(
            primary
                .prepare(
                    image.encode(&root).unwrap(),
                    0,
                    marks,
                    vec![Output {
                        recipient: 1,
                        delivery: Delivery::Reliable,
                        sequence: 1,
                        bytes: payload.clone(),
                    }],
                )
                .unwrap()
                .clone(),
        )
        .unwrap();
    assert!(seq.outbox().next().is_none());
    let receipt = seq.install(token, standby.keys()).unwrap();
    assert_eq!(queue.pending().count(), 1);
    assert_eq!(primary.outbox().count(), 0);
    primary.acknowledge(receipt).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(queue.pending().count(), 0);
    let committed = primary.outbox().next().unwrap().clone();
    assert_eq!(&committed, &seq.publication()[0]);
    let mut delivery = DeliveryJournal::default();
    let mut applications = 0;
    for _ in 0..2 {
        receiving
            .enqueue(
                PacketKind::Output,
                &committed.encode(&root.context().unwrap()).unwrap(),
            )
            .unwrap();
        while let Some(wire) = receiving.poll_send(0).unwrap() {
            host.send_reliable(peer, Bytes::from(wire));
        }
        let mut seen = false;
        until(|| {
            while let Some(event) = client.poll() {
                if let ClientEvent::Reliable(bytes) = event {
                    if let Some((kind, _, bytes)) = sending.receive(&bytes, 0).unwrap() {
                        assert_eq!(kind, PacketKind::Output);
                        let output =
                            CertifiedOutput::decode(&root.context().unwrap(), &bytes).unwrap();
                        delivery
                            .apply_certified(&root.context().unwrap(), 1, &output, |bytes| {
                                assert_eq!(bytes, payload);
                                applications += 1;
                                Ok(())
                            })
                            .unwrap();
                        seen = true;
                    }
                }
            }
            seen
        });
    }
    assert_eq!(applications, 1);
    assert_eq!(delivery.applied(), 1);
    intents
        .acknowledge(committed.receipt.watermarks[0].input)
        .unwrap();
    assert!(intents.pending().next().is_none());
    let current = seq.membership_certificate(standby.keys()).unwrap();
    host.update_session_membership(current.clone()).unwrap();
    queue.refresh(&primary).unwrap();
    let previous_tls = sending.tls();
    let previous_peer = peer;
    client.shutdown();
    until(
        || matches!(host.poll(), Some(HostEvent::PeerLeft { peer, .. }) if peer == previous_peer),
    );
    policy.membership = Some(current.clone());
    client = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &host.lan_token(),
        binding,
        original.pubkey(),
    )
    .unwrap();
    connected = false;
    let mut next_peer = None;
    until(|| {
        while let Some(event) = client.poll() {
            match event {
                ClientEvent::Connected { host_pubkey, .. } => {
                    assert_eq!(host_pubkey, original.pubkey());
                    connected = true;
                }
                ClientEvent::Progress { .. } => {}
                other => panic!("unexpected reconnect event {other:?}"),
            }
        }
        while let Some(event) = host.poll() {
            if let HostEvent::PeerJoined { peer, pubkey, .. } = event {
                assert_eq!(pubkey, player.pubkey());
                next_peer = Some(peer);
            }
        }
        connected && next_peer.is_some()
    });
    peer = next_peer.unwrap();
    assert_ne!(peer, previous_peer);
    sending = client.migration_channel(&policy).unwrap();
    receiving = host.migration_channel(peer).unwrap();
    assert_ne!(sending.tls(), previous_tls);
    assert_eq!(sending.tls(), receiving.tls());
    let request = queue
        .begin_reconnect(&receiving, current.clone(), &primary, 0, original.keys())
        .unwrap();
    receiving
        .enqueue(PacketKind::Control, &request.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = receiving.poll_send(0).unwrap() {
        host.send_reliable(peer, Bytes::from(wire));
    }
    let mut challenge_seen = false;
    until(|| {
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                if let Some((kind, _, bytes)) = sending.receive(&bytes, 0).unwrap() {
                    assert_eq!(kind, PacketKind::Control);
                    let request = ReconnectChallenge::decode(&root, &bytes).unwrap();
                    let proof = PlayerControl::resume_connection(
                        &root,
                        &request,
                        sending.tls(),
                        &delivery,
                        &intents,
                        2,
                        player.keys(),
                    )
                    .unwrap();
                    sending
                        .enqueue(PacketKind::Control, &proof.encode(&root).unwrap())
                        .unwrap();
                    challenge_seen = true;
                }
            }
        }
        challenge_seen
    });
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut resumed = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { bytes, .. } = event {
                if let Some((kind, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert_eq!(kind, PacketKind::Control);
                    queue.finish_reconnect(&bytes, &primary, 0).unwrap();
                    resumed = true;
                }
            }
        }
        resumed
    });
    // A delayed original is re-signed under the fresh TLS exporter, keeping its
    // old game ID and bytes. The already committed action cannot run again.
    let replay = PlayerControl::sign(
        &root,
        &current,
        0,
        3,
        1,
        sending.tls(),
        PlayerAction::Intent {
            number: 1,
            bytes: payload.clone(),
        },
        player.keys(),
    )
    .unwrap();
    sending
        .enqueue(PacketKind::Control, &replay.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut replayed = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { bytes, .. } = event {
                if let Some((_, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert!(!queue.receive(&bytes, &primary).unwrap());
                    replayed = true;
                }
            }
        }
        replayed
    });
    assert_eq!(queue.pending().count(), 0);
    // Replay the exact proof from the retained primary log on the new socket.
    receiving
        .enqueue(
            PacketKind::Output,
            &primary
                .outbox()
                .next()
                .unwrap()
                .encode(&root.context().unwrap())
                .unwrap(),
        )
        .unwrap();
    while let Some(wire) = receiving.poll_send(0).unwrap() {
        host.send_reliable(peer, Bytes::from(wire));
    }
    replayed = false;
    until(|| {
        while let Some(event) = client.poll() {
            if let ClientEvent::Reliable(bytes) = event {
                if let Some((_, _, bytes)) = sending.receive(&bytes, 0).unwrap() {
                    let output = CertifiedOutput::decode(&root.context().unwrap(), &bytes).unwrap();
                    assert_eq!(output, committed);
                    assert!(!delivery
                        .apply_certified(&root.context().unwrap(), 1, &output, |_| {
                            applications += 1;
                            Ok(())
                        })
                        .unwrap());
                    replayed = true;
                }
            }
        }
        replayed
    });
    assert_eq!(applications, 1);
    let ack = PlayerControl::sign(
        &root,
        &current,
        0,
        4,
        1,
        sending.tls(),
        PlayerAction::Applied {
            output: delivery.applied(),
            tail: intents.tail(),
            cut: None,
        },
        player.keys(),
    )
    .unwrap();
    sending
        .enqueue(PacketKind::Control, &ack.encode(&root).unwrap())
        .unwrap();
    while let Some(wire) = sending.poll_send(0).unwrap() {
        client.send_reliable(Bytes::from(wire));
    }
    let mut applied = false;
    until(|| {
        while let Some(event) = host.poll() {
            if let HostEvent::Reliable { bytes, .. } = event {
                if let Some((_, _, bytes)) = receiving.receive(&bytes, 0).unwrap() {
                    assert!(!queue.receive(&bytes, &primary).unwrap());
                    applied = true;
                }
            }
        }
        applied
    });
    assert_eq!(queue.output_ack(), 1);
    assert_eq!(primary.outbox().count(), 1);
    assert_eq!(
        seq.outbox().count(),
        1,
        "network receipt cannot prune committed outbox"
    );
    let mut marks = seq.receipt().watermarks.clone();
    marks[0].output_ack = queue.output_ack();
    let token = seq
        .stage(
            primary
                .prepare(image.encode(&root).unwrap(), 0, marks, vec![])
                .unwrap()
                .clone(),
        )
        .unwrap();
    let receipt = seq.install(token, standby.keys()).unwrap();
    assert_eq!(primary.outbox().count(), 1);
    primary.acknowledge(receipt).unwrap();
    queue.refresh(&primary).unwrap();
    assert_eq!(primary.outbox().count(), 0);
    assert_eq!(seq.outbox().count(), 0);
    client.shutdown();
    host.shutdown();
}

#[test]
fn actual_quic_retained_recovery_resumes_over_the_prepared_warm_connection() {
    use fray_net::{Bytes, ClientEvent, HostEvent, Identity, NetConfig, RoomInfo};
    use std::time::{Duration, Instant};

    fn peer(host: &fray_net::HostHandle, key: [u8; 32]) -> fray_net::PeerId {
        let started = Instant::now();
        loop {
            while let Some(event) = host.poll() {
                if let HostEvent::PeerJoined { peer, pubkey, .. } = event {
                    assert_eq!(pubkey.to_bytes(), key);
                    return peer;
                }
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // This drives actual TLS-bound handles, framing, ingress backpressure and
    // real monotonic clocks. Native game/process-kill acceptance is separate.
    struct Wire {
        listener: fray_net::HostHandle,
        link: fray_net::ClientHandle,
        peer: fray_net::PeerId,
        server_ingress: ReceiveQueue,
        client_ingress: ReceiveQueue,
        started: Instant,
        client_transfer: u64,
    }
    impl Wire {
        fn now(&self) -> u64 {
            self.started.elapsed().as_millis() as u64
        }
        fn exchange(
            &mut self,
            server: &mut Channel,
            client: &mut PlayerRecovery,
            controls: usize,
            resume: bool,
        ) -> Vec<Vec<u8>> {
            let mut records = Vec::new();
            let mut resumed = false;
            loop {
                let now = self.now();
                assert!(now < 5000, "actual QUIC recovery deadline");
                while let Some(wire) = server.poll_send(now).unwrap() {
                    self.listener.send_reliable(self.peer, Bytes::from(wire));
                }
                while let Some(event) = self.link.poll() {
                    match event {
                        ClientEvent::Reliable(bytes) => {
                            self.client_ingress.enqueue(bytes.to_vec()).unwrap()
                        }
                        ClientEvent::Progress { .. } => {}
                        other => panic!("unexpected warm client event {other:?}"),
                    }
                }
                while let Some(event) = self
                    .client_ingress
                    .poll(|wire| {
                        client.receive(wire, now, |_, _, _| {
                            panic!("no game outputs in this fixture")
                        })
                    })
                    .unwrap()
                {
                    match event {
                        Some(RecoveryPlayerEvent::ClockCut { logical_ms }) => {
                            assert_eq!(logical_ms, 100);
                            client
                                .confirm_clock(0, now, |logical, delta| {
                                    assert_eq!((logical, delta), (100, 0));
                                    Ok(())
                                })
                                .unwrap();
                        }
                        Some(RecoveryPlayerEvent::Resumed) => resumed = true,
                        None => {}
                        other => panic!("unexpected recovery event {other:?}"),
                    }
                }
                while let Some(wire) = client.poll_send(now).unwrap() {
                    let frame = Frame::decode(&wire).unwrap();
                    if frame.ordinal == 0 {
                        assert!(
                            frame.transfer > self.client_transfer,
                            "recovery framing reset"
                        );
                        self.client_transfer = frame.transfer;
                    }
                    self.link.send_reliable(Bytes::from(wire));
                }
                while let Some(event) = self.listener.poll() {
                    match event {
                        HostEvent::Reliable { peer, bytes } => {
                            assert_eq!(peer, self.peer);
                            self.server_ingress.enqueue(bytes.to_vec()).unwrap();
                        }
                        other => panic!("unexpected warm server event {other:?}"),
                    }
                }
                while let Some(record) = self
                    .server_ingress
                    .poll(|wire| server.receive(wire, now))
                    .unwrap()
                {
                    if let Some((kind, _, bytes)) = record {
                        assert_eq!(kind, PacketKind::Control);
                        records.push(bytes);
                    }
                }
                if records.len() >= controls && resumed == resume {
                    assert_eq!(records.len(), controls);
                    return records;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    let mut cfg =
        NetConfig::new(std::env::temp_dir(), "migration-retained-recovery-test").lan_only();
    cfg.lan_port = 0;
    cfg.host_has_player = false;
    let original = Identity::ephemeral();
    let standby = Identity::ephemeral();
    let player = Identity::ephemeral();
    let host = fray_net::host(
        &cfg,
        &original,
        RoomInfo {
            name: "Original".into(),
            max_players: 8,
        },
    );
    let addr = wait_host_ready(&host);
    let code = host.code().to_owned();
    let (fixture, _, _, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.session = fresh_session().unwrap();
    root.app = cfg.app_tag.clone();
    root.host = original.pubkey().to_bytes();
    root.standby = standby.pubkey().to_bytes();
    root.controller = root.host;
    root.code = room_code_hash(host.code()).unwrap();
    root.members = vec![Member {
        player: 1,
        seat: 0,
        key: Some(player.pubkey().to_bytes()),
    }];
    let mut descriptor = Descriptor::offer(root.clone(), original.keys()).unwrap();
    descriptor.consent(standby.keys()).unwrap();
    let image = SessionImage::initial(&root, &[(1, 99)], vec![0], 1, 100).unwrap();
    let capability = CapabilityAck::sign(
        &root,
        1,
        state_hash(&image.encode(&root).unwrap()).unwrap(),
        1,
        player.keys(),
    )
    .unwrap();
    let mut activation = Activation::new_session(descriptor.clone(), image).unwrap();
    activation.acknowledge(capability.clone()).unwrap();
    let (seq, armed) = activation
        .arm(standby.keys(), |bytes| Ok(bytes.to_vec()))
        .unwrap();
    let certificate = seq.membership_certificate(standby.keys()).unwrap();
    host.pin_session(descriptor.clone()).unwrap();
    host.update_session_membership(certificate.clone()).unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Player,
        server: LinkRole::Original,
    };
    let normal = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &host.lan_token(),
        binding,
        original.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&normal));
    let normal_peer = peer(&host, player.pubkey().to_bytes());
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let channel = normal.migration_channel(&policy).unwrap();
    assert_eq!(
        channel.tls(),
        host.migration_channel(normal_peer).unwrap().tls()
    );
    let mut endpoint = PlayerEndpoint::new(
        descriptor.clone(),
        &armed,
        &capability,
        certificate.clone(),
        channel,
        player.keys().clone(),
    )
    .unwrap();
    let originals = (0..70).map(|n| vec![n as u8; 1024]).collect::<Vec<_>>();
    endpoint
        .intents_mut()
        .unwrap()
        .append_batch(&originals)
        .unwrap();

    let listener = fray_net::host_standby(&cfg, &standby, host.code(), descriptor.clone()).unwrap();
    let addr = wait_host_ready(&listener);
    listener
        .update_session_membership(certificate.clone())
        .unwrap();
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let link = fray_net::join_session_addr(
        &cfg,
        &player,
        addr,
        &listener.lan_token(),
        binding,
        standby.pubkey(),
    )
    .unwrap();
    assert!(wait_connected(&link));
    let warm_peer = peer(&listener, player.pubkey().to_bytes());
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: Some(certificate),
    };
    let mut warm = link.migration_channel(&policy).unwrap();
    let mut server = listener.migration_channel(warm_peer).unwrap();
    let tls = server.tls();
    assert_eq!(warm.tls(), tls);
    // Consume a real warm frame before takeover; neither framing nor TLS may
    // restart when the retained endpoint later moves into recovery.
    let probe = PulseProbe {
        term: 0,
        sequence: endpoint.sequence().allocate().unwrap(),
        nonce: [9; 32],
        tls,
    };
    warm.enqueue(PacketKind::Control, &probe.encode(&root).unwrap())
        .unwrap();
    let mut warm_transfer = 0;
    while let Some(wire) = warm.poll_send(0).unwrap() {
        warm_transfer = Frame::decode(&wire).unwrap().transfer;
        link.send_reliable(Bytes::from(wire));
    }
    assert!(warm_transfer > 0);
    let wait = Instant::now();
    let mut seen = false;
    while !seen {
        while let Some(event) = listener.poll() {
            if let HostEvent::Reliable { peer, bytes } = event {
                assert_eq!(peer, warm_peer);
                seen |= server.receive(&bytes, 0).unwrap().is_some();
            }
        }
        assert!(wait.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    normal.shutdown();
    host.shutdown();
    let started = Instant::now();
    let mut recovery = Recovery::begin_session(descriptor, seq, standby.keys(), 0).unwrap();
    let promotion = recovery.promotion().clone();
    server.promote(&promotion).unwrap();
    let mut client = endpoint.into_recovery(warm, promotion.clone(), 0).unwrap();
    let mut wire = Wire {
        listener,
        link,
        peer: warm_peer,
        server_ingress: ReceiveQueue::default(),
        client_ingress: ReceiveQueue::default(),
        started,
        client_transfer: warm_transfer,
    };
    let challenge = recovery
        .challenge(
            1,
            tls,
            1,
            player.pubkey().to_bytes(),
            standby.keys(),
            wire.now(),
        )
        .unwrap();
    server
        .enqueue(PacketKind::Control, &challenge.encode(&root).unwrap())
        .unwrap();
    let replies = wire.exchange(&mut server, &mut client, 1, false);
    recovery
        .accept(
            1,
            tls,
            &ResumeProof::decode(&root, &replies[0]).unwrap(),
            wire.now(),
        )
        .unwrap();
    assert!(recovery.seal(wire.now()).unwrap());
    recovery
        .revalidate_security(standby.keys(), wire.now(), |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    assert!(recovery.replay().unwrap().is_empty());
    for round in 0..2 {
        recovery.begin_round().unwrap();
        let request = recovery
            .issue_input_round(1, tls, standby.keys(), wire.now())
            .unwrap();
        server
            .enqueue(
                PacketKind::Control,
                &request.encode(&root, &promotion).unwrap(),
            )
            .unwrap();
        let replies = wire.exchange(
            &mut server,
            &mut client,
            if round == 0 { originals.len() + 1 } else { 1 },
            false,
        );
        for reply in replies {
            recovery
                .accept_player_control(
                    &PlayerControl::decode(&root, &reply).unwrap(),
                    tls,
                    wire.now(),
                )
                .unwrap();
        }
        if round == 0 {
            for (index, original) in originals.iter().enumerate() {
                let (_, number, bytes) = recovery.next_input().unwrap().unwrap();
                assert_eq!(number, index as u64 + 1);
                assert_eq!(bytes, original);
                let before = recovery.sequencer().image().to_vec();
                recovery
                    .apply_next(standby.keys(), |_, _, _, histories| {
                        let mut image = SessionImage::decode(&root, &before)?;
                        image.inputs = histories.clone();
                        image.game.push(number as u8);
                        Ok((image.encode(&root)?, vec![]))
                    })
                    .unwrap();
            }
            assert!(recovery.next_input().unwrap().is_none());
        } else {
            recovery
                .commit_departures(standby.keys(), |_, _, _| panic!("empty departure callback"))
                .unwrap();
        }
    }
    let mut barrier = RecoveryBarrier::new(recovery, standby.keys(), wire.now()).unwrap();
    let cut = barrier.issue(1, tls, standby.keys(), wire.now()).unwrap();
    server
        .enqueue(PacketKind::Control, &cut.encode(&root, &promotion).unwrap())
        .unwrap();
    let replies = wire.exchange(&mut server, &mut client, 1, false);
    let ready = RecoveryReady::decode(&root, &promotion, &cut, &replies[0]).unwrap();
    barrier.accept(&ready, tls, wire.now()).unwrap();
    let mut inbox = Some(PlayerInbox::new(&server, cut.membership.clone()).unwrap());
    let (mut successor, _, resume) = barrier.finish(standby.keys(), wire.now()).unwrap();
    let final_image = SessionImage::decode(&root, successor.primary().committed_image()).unwrap();
    assert_eq!(final_image.logical_ms, 100);
    assert_eq!(final_image.inputs[&1].handled(), 70);
    assert_eq!(final_image.game, (0..=70).collect::<Vec<u8>>());
    server
        .enqueue(
            PacketKind::Control,
            &resume.encode(&root, &promotion).unwrap(),
        )
        .unwrap();
    assert!(wire.exchange(&mut server, &mut client, 0, true).is_empty());
    let mut endpoint = client.into_endpoint().unwrap();
    assert_eq!(
        (
            endpoint.journals().1.tail(),
            endpoint.journals().1.acknowledged()
        ),
        (70, 70)
    );
    let mut queue = successor
        .attach_warm_player(&server, &mut inbox, standby.keys())
        .unwrap();
    assert_eq!(
        endpoint
            .intents_mut()
            .unwrap()
            .append_batch(&[vec![33]])
            .unwrap(),
        vec![71]
    );
    endpoint.queue_pending(MAX_BATCH).unwrap();
    let before_resume_input = wire.client_transfer;
    let wait = Instant::now();
    while queue.pending().next().is_none() {
        let now = wire.now();
        while let Some(bytes) = endpoint.poll_send(now).unwrap() {
            let frame = Frame::decode(&bytes).unwrap();
            if frame.ordinal == 0 {
                assert!(
                    frame.transfer > wire.client_transfer,
                    "resumed framing reset"
                );
                wire.client_transfer = frame.transfer;
            }
            wire.link.send_reliable(Bytes::from(bytes));
        }
        while let Some(event) = wire.listener.poll() {
            if let HostEvent::Reliable { peer, bytes } = event {
                assert_eq!(peer, warm_peer);
                wire.server_ingress.enqueue(bytes.to_vec()).unwrap();
            }
        }
        while let Some(record) = wire
            .server_ingress
            .poll(|bytes| server.receive(bytes, now))
            .unwrap()
        {
            if let Some((_, _, bytes)) = record {
                queue.receive(&bytes, successor.primary()).unwrap();
            }
        }
        assert!(wait.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(71, &[33][..])]);
    assert!(wire.client_transfer > before_resume_input);
    assert_eq!(wire.listener.code(), code);
    assert_eq!(wire.listener.tls_binding(warm_peer).unwrap(), tls);
    wire.link.shutdown();
    wire.listener.shutdown();
}

fn security_boundary_fixture(local: bool) -> (Root, Keys, Recovery) {
    let (mut descriptor, host, key, _) = descriptor_fixture();
    let mut root = descriptor.root.clone();
    root.members = if local {
        vec![Member {
            player: 1,
            seat: 0,
            key: None,
        }]
    } else {
        vec![]
    };
    descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&key).unwrap();
    let routes = if local { vec![(1, 9)] } else { vec![] };
    let image = SessionImage::initial(&root, &routes, vec![42], 1, 100).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    if local {
        let candidate = seq
            .next(
                image.encode(&root).unwrap(),
                100,
                seq.receipt().watermarks.clone(),
                vec![Output {
                    recipient: 1,
                    delivery: Delivery::Reliable,
                    sequence: 1,
                    bytes: vec![7],
                }],
            )
            .unwrap();
        let token = seq.stage(candidate).unwrap();
        seq.install(token, &key).unwrap();
    }
    let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
    if local {
        recovery.retain_local(1, 0, 2, 0).unwrap();
    }
    assert!(recovery.seal(0).unwrap());
    (root, key, recovery)
}

#[test]
fn security_revalidation_is_a_required_once_only_frozen_commit_even_without_survivors() {
    for local in [false, true] {
        let (root, key, mut recovery) = security_boundary_fixture(local);
        assert_eq!(recovery.phase(), RecoveryPhase::Security);
        let before = recovery.sequencer().image().to_vec();
        let final_receipt = recovery.promotion().final_receipt.clone();
        let outbox = recovery.sequencer().outbox().cloned().collect::<Vec<_>>();
        assert!(recovery.replay().is_err());
        assert!(recovery.begin_round().is_err());
        assert!(recovery.commit_delivery_acks(&key).is_err());
        let mut calls = 0;
        let receipt = recovery
            .revalidate_security(&key, 0, |bytes, boundary| {
                calls += 1;
                assert_eq!(bytes, before);
                assert_eq!(boundary.fence, final_receipt.digest(&root.context()?)?);
                assert_eq!(
                    boundary.tails,
                    if local {
                        std::collections::BTreeMap::from([(1, 2)])
                    } else {
                        Default::default()
                    }
                );
                let mut image = SessionImage::decode(&root, bytes)?;
                image.game = vec![43];
                image.encode(&root)
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(receipt.index, final_receipt.index + 1);
        assert_eq!(
            receipt.parent,
            final_receipt.digest(&root.context().unwrap()).unwrap()
        );
        assert_eq!(receipt.logical_ms, 100);
        assert_eq!(receipt.watermarks, final_receipt.watermarks);
        assert_eq!(receipt.outputs_count, 0);
        assert_eq!(recovery.phase(), RecoveryPhase::Replay);
        assert_eq!(
            recovery.sequencer().outbox().cloned().collect::<Vec<_>>(),
            outbox
        );
        let installed = SessionImage::decode(&root, recovery.sequencer().image()).unwrap();
        assert_eq!(installed.game, vec![43]);
        assert!(installed.security_boundary.is_some());
        assert!(recovery
            .revalidate_security(&key, 0, |_, _| panic!("second reset"))
            .is_err());
        assert_eq!(recovery.sequencer().receipt(), &receipt);
        let mut removed = installed.clone();
        removed.security_boundary = None;
        let candidate = recovery
            .sequencer()
            .next(
                removed.encode(&root).unwrap(),
                100,
                receipt.watermarks.clone(),
                vec![],
            )
            .unwrap();
        assert!(recovery.sequencer().stage(candidate).is_err());
        let mut changed = installed.clone();
        changed
            .security_boundary
            .as_mut()
            .unwrap()
            .tails
            .insert(99, 3);
        let candidate = recovery
            .sequencer()
            .next(
                changed.encode(&root).unwrap(),
                100,
                receipt.watermarks.clone(),
                vec![],
            )
            .unwrap();
        assert!(recovery.sequencer().stage(candidate).is_err());
    }
}

#[test]
fn security_revalidation_retries_the_exact_base_and_latches_faults_or_envelope_mutations() {
    for mode in [
        "retry", "fault", "panic", "clock", "roster", "history", "marker", "overflow",
    ] {
        let (root, key, mut recovery) = security_boundary_fixture(false);
        let before = recovery.sequencer().image().to_vec();
        let frontier = recovery.sequencer().receipt().clone();
        let mut calls = 0;
        let mut fixed = None;
        let result = recovery.revalidate_security(&key, 0, |bytes, boundary| {
            calls += 1;
            assert_eq!(bytes, before);
            if let Some(old) = &fixed {
                assert_eq!(old, boundary);
            } else {
                fixed = Some(boundary.clone());
            }
            if mode == "fault" || mode == "retry" && calls == 1 {
                return Err(Error::Invalid("test security fault"));
            }
            if mode == "panic" {
                panic!("test security panic");
            }
            let mut image = SessionImage::decode(&root, bytes)?;
            match mode {
                "clock" => image.logical_ms += 1,
                "roster" => image.next_player += 1,
                "history" => image.config[0] ^= 1,
                "marker" => image.security_boundary = Some(boundary.clone()),
                "overflow" => image.game = vec![0; MAX_IMAGE],
                _ => image.game = vec![99],
            }
            image.encode(&root)
        });
        if mode == "retry" {
            result.unwrap();
            assert_eq!(calls, 2);
            assert_eq!(recovery.phase(), RecoveryPhase::Replay);
        } else {
            assert!(result.is_err(), "{mode}");
            assert!(calls <= 2);
            assert_eq!(recovery.phase(), RecoveryPhase::Failed);
            assert_eq!(recovery.sequencer().receipt(), &frontier);
            assert_eq!(recovery.sequencer().image(), before);
            assert!(recovery
                .revalidate_security(&key, 0, |_, _| panic!("retry after failure"))
                .is_err());
        }
    }
}

#[test]
fn security_revalidation_rejects_wrong_signer_and_original_deadline_before_callbacks() {
    let (_, key, mut recovery) = security_boundary_fixture(false);
    assert_eq!(
        recovery.revalidate_security(&Keys::generate(), 0, |_, _| panic!("wrong signer callback")),
        Err(Error::Unauthorized)
    );
    assert_eq!(recovery.phase(), RecoveryPhase::Security);
    assert!(recovery
        .revalidate_security(&key, 5000, |_, _| panic!("expired callback"))
        .is_err());
    assert_eq!(recovery.phase(), RecoveryPhase::Failed);
}

#[test]
fn security_revalidation_checks_aggregate_headroom_before_any_native_callback() {
    let (fixture, host, key, _) = descriptor_fixture();
    let mut root = fixture.root;
    root.members = vec![Member {
        player: 1,
        seat: 0,
        key: None,
    }];
    let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&key).unwrap();
    let mut image = SessionImage::initial(&root, &[(1, 9)], vec![], 1, 100).unwrap();
    let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &key).unwrap();
    let candidate = seq
        .next(
            image.encode(&root).unwrap(),
            100,
            seq.receipt().watermarks.clone(),
            vec![Output {
                recipient: 1,
                delivery: Delivery::Reliable,
                sequence: 1,
                bytes: vec![7; 900],
            }],
        )
        .unwrap();
    let token = seq.stage(candidate).unwrap();
    seq.install(token, &key).unwrap();
    let receipt_body = seq
        .receipt()
        .encode(&root.context().unwrap())
        .unwrap()
        .len()
        - 64;
    let headroom = 8;
    image.game =
        vec![
            0;
            MAX_IMAGE - 900 - receipt_body - 17 - image.encode(&root).unwrap().len() - headroom
        ];
    let candidate = seq
        .next(
            image.encode(&root).unwrap(),
            100,
            seq.receipt().watermarks.clone(),
            vec![],
        )
        .unwrap();
    let token = seq.stage(candidate).unwrap();
    seq.install(token, &key).unwrap();
    let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
    recovery.retain_local(1, 0, 0, 0).unwrap();
    recovery.seal(0).unwrap();
    let frontier = recovery.sequencer().receipt().clone();
    let before = recovery.sequencer().image().to_vec();
    let outbox = recovery.sequencer().outbox().cloned().collect::<Vec<_>>();
    assert_eq!(
        recovery.revalidate_security(&key, 0, |_, _| panic!(
            "aggregate overflow ran native reset"
        )),
        Err(Error::Bounds)
    );
    assert_eq!(recovery.phase(), RecoveryPhase::Failed);
    assert_eq!(recovery.sequencer().receipt(), &frontier);
    assert_eq!(recovery.sequencer().image(), before);
    assert_eq!(
        recovery.sequencer().outbox().cloned().collect::<Vec<_>>(),
        outbox
    );
}

#[test]
fn security_revalidation_callback_cannot_run_past_the_original_deadline() {
    let (_, key, mut recovery) = security_boundary_fixture(false);
    let frontier = recovery.sequencer().receipt().clone();
    let mut calls = 0;
    assert!(recovery
        .revalidate_security(&key, 4990, |bytes, _| {
            calls += 1;
            std::thread::sleep(std::time::Duration::from_millis(15));
            Ok(bytes.to_vec())
        })
        .is_err());
    assert_eq!(calls, 1);
    assert_eq!(recovery.phase(), RecoveryPhase::Failed);
    assert_eq!(recovery.sequencer().receipt(), &frontier);
}

#[test]
fn security_boundary_rejects_forged_first_commit_and_noncanonical_codec() {
    let (root, _, recovery) = security_boundary_fixture(true);
    let base = SessionImage::decode(&root, recovery.sequencer().image()).unwrap();
    let fence = recovery
        .promotion()
        .final_receipt
        .digest(&root.context().unwrap())
        .unwrap();
    for (digest, tails) in [
        (fence, std::collections::BTreeMap::from([(99, 0)])),
        ([4; 32], Default::default()),
        (fence, std::collections::BTreeMap::from([(1, 513)])),
    ] {
        let mut post = base.clone();
        post.security_boundary = Some(SecurityBoundary {
            fence: digest,
            tails,
        });
        let candidate = recovery
            .sequencer()
            .next(
                post.encode(&root).unwrap(),
                100,
                recovery.sequencer().receipt().watermarks.clone(),
                vec![],
            )
            .unwrap();
        assert!(recovery.sequencer().stage(candidate).is_err());
    }
    let mut post = base;
    post.security_boundary = Some(SecurityBoundary {
        fence,
        tails: std::collections::BTreeMap::from([(1, 0), (2, 0)]),
    });
    let encoded = post.encode(&root).unwrap();
    assert_eq!(SessionImage::decode(&root, &encoded).unwrap(), post);
    // FRYI, context, versions, match/C, config/content, revision/next-player.
    let option = 4 + 1 + 16 + 32 + 4 + 4 + 8 + 8 + 32 + 32 + 8 + 8;
    assert_eq!(encoded[option], 1);
    let count = option + 1 + 32;
    let first = count + 4;
    let mut oversized = encoded.clone();
    oversized[count..count + 4].copy_from_slice(&(MAX_PLAYERS as u32 + 1).to_be_bytes());
    assert!(SessionImage::decode(&root, &oversized).is_err());
    for second in [0u64, 1] {
        let mut changed = encoded.clone();
        changed[first + 16..first + 24].copy_from_slice(&second.to_be_bytes());
        assert!(SessionImage::decode(&root, &changed).is_err());
    }
    for end in [
        option,
        option + 1,
        count + 2,
        first + 7,
        first + 24,
        encoded.len() - 1,
    ] {
        assert!(SessionImage::decode(&root, &encoded[..end]).is_err());
    }
}

fn deliver_recovery_player(
    server: &mut Channel,
    client: &mut PlayerRecovery,
    kind: PacketKind,
    bytes: &[u8],
    now: u64,
    mut apply: impl FnMut(Delivery, &[u8], &mut IntentJournal) -> Result<()>,
) -> Vec<RecoveryPlayerEvent> {
    server.enqueue(kind, bytes).unwrap();
    let mut events = Vec::new();
    while let Some(wire) = server.poll_send(now).unwrap() {
        if let Some(event) = client.receive(&wire, now, &mut apply).unwrap() {
            events.push(event);
        }
    }
    events
}
fn recovery_player_controls(
    client: &mut PlayerRecovery,
    server: &mut Channel,
    now: u64,
) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    while let Some(wire) = client.poll_send(now).unwrap() {
        if let Some((kind, _, bytes)) = server.receive(&wire, now).unwrap() {
            assert_eq!(kind, PacketKind::Control);
            records.push(bytes);
        }
    }
    records
}

#[test]
fn retained_player_recovery_moves_real_journals_and_warm_framing_through_every_barrier() {
    let (root, _, key, mut seq, mut primary, mut endpoint, mut normal, _, image) =
        normal_player_endpoint();
    endpoint
        .intents_mut()
        .unwrap()
        .append_batch(&[vec![10], vec![20]])
        .unwrap();
    endpoint.queue_view(vec![1]).unwrap();
    let descriptor = endpoint.descriptor().clone();
    // One applied output and one lost output from the same committed prefix.
    let mut applications = 0;
    for number in 1..=2 {
        let candidate = primary
            .prepare(
                image.encode(&root).unwrap(),
                image.logical_ms,
                primary.receipt().watermarks.clone(),
                vec![Output {
                    recipient: 2,
                    delivery: Delivery::Reliable,
                    sequence: number,
                    bytes: vec![40 + number as u8],
                }],
            )
            .unwrap()
            .clone();
        let staged = seq.stage(candidate).unwrap();
        primary
            .acknowledge(seq.install(staged, &key).unwrap())
            .unwrap();
        if number == 1 {
            normal
                .enqueue(
                    PacketKind::Output,
                    &seq.publication()[0]
                        .encode(&root.context().unwrap())
                        .unwrap(),
                )
                .unwrap();
            while let Some(wire) = normal.poll_send(0).unwrap() {
                endpoint
                    .receive(&wire, 0, |_, _, intents| {
                        applications += 1;
                        intents.append_batch(&[vec![30]])?;
                        Ok(())
                    })
                    .unwrap();
            }
        }
    }
    let first = seq
        .outbox()
        .find(|o| o.output.sequence == 1)
        .unwrap()
        .clone();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: Some(seq.membership_certificate(&key).unwrap()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let tls = [8; 32];
    let player = root.member(2).unwrap().key.unwrap();
    let mut warm = Channel::new_bound(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        player,
        root.standby,
        tls,
    )
    .unwrap();
    let mut server = Channel::new_bound(
        &policy,
        binding,
        ChannelSide::Server,
        root.standby,
        player,
        tls,
    )
    .unwrap();
    let probe = PulseProbe {
        term: 0,
        sequence: endpoint.sequence().allocate().unwrap(),
        nonce: [3; 32],
        tls,
    };
    assert_eq!(
        warm.enqueue(PacketKind::Control, &probe.encode(&root).unwrap())
            .unwrap(),
        1
    );
    while let Some(wire) = warm.poll_send(0).unwrap() {
        assert!(server.receive(&wire, 0).unwrap().is_some());
    }
    let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
    let promotion = recovery.promotion().clone();
    server.promote(&promotion).unwrap();
    let mut client = endpoint.into_recovery(warm, promotion.clone(), 0).unwrap();
    let challenge = recovery.challenge(2, tls, 2, player, &key, 0).unwrap();
    deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &challenge.encode(&root).unwrap(),
        0,
        |_, _, _| panic!("challenge is not game input"),
    );
    let replies = recovery_player_controls(&mut client, &mut server, 0);
    assert_eq!(replies.len(), 1);
    let certificate = recovery.sequencer().membership_certificate(&key).unwrap();
    let proof = ResumeProof::decode_with_certificate(&root, &certificate, &replies[0]).unwrap();
    assert_eq!((proof.output_ack, proof.input_tail), (1, 3));
    recovery.accept(2, tls, &proof, 0).unwrap();
    // Identical challenge retries reuse exact signed bytes and sender ID.
    deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &challenge.encode(&root).unwrap(),
        0,
        |_, _, _| panic!("duplicate challenge callback"),
    );
    assert_eq!(
        recovery_player_controls(&mut client, &mut server, 0),
        replies
    );
    recovery.retain_local(3, 0, 0, 0).unwrap();
    recovery.seal(250).unwrap();
    recovery
        .revalidate_security(&key, 250, |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    let mut replay = vec![first];
    replay.extend(recovery.replay().unwrap());
    for output in replay {
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Output,
            &output.encode(&root.context().unwrap()).unwrap(),
            250,
            |delivery, bytes, intents| {
                assert_eq!(delivery, Delivery::Reliable);
                assert_eq!(bytes, &[42]);
                applications += 1;
                intents.append_batch(&[vec![40]])?;
                Ok(())
            },
        );
    }
    assert_eq!(applications, 2);
    for bytes in recovery_player_controls(&mut client, &mut server, 250) {
        let control = PlayerControl::decode(&root, &bytes).unwrap();
        control.verify(&root, &certificate, 2, tls, 1).unwrap();
        if let PlayerAction::Applied {
            output, cut: None, ..
        } = control.action
        {
            assert_eq!(output, 2);
            assert_eq!(recovery.accept_player_control(&control, tls, 250), Ok(true));
            assert_eq!(
                recovery.accept_player_control(&control, tls, 250),
                Ok(false)
            );
        } else {
            panic!("only applied ACKs precede the round");
        }
    }
    recovery.commit_delivery_acks(&key).unwrap();
    let mut control_ids = vec![proof.sequence];
    let mut original_payloads = Vec::new();
    let mut last_round = Vec::new();
    for round in 0..3 {
        recovery.begin_round().unwrap();
        recovery.seal_inputs(3, 0).unwrap();
        let request = recovery.issue_input_round(2, tls, &key, 250).unwrap();
        let wire = request.encode(&root, &promotion).unwrap();
        last_round = wire.clone();
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &wire,
            250,
            |_, _, _| panic!("input round is not native game work"),
        );
        let replies = recovery_player_controls(&mut client, &mut server, 250);
        for bytes in &replies {
            let control = PlayerControl::decode(&root, bytes).unwrap();
            control
                .verify(&root, &request.membership, 2, tls, 1)
                .unwrap();
            control_ids.push(control.sequence);
            match &control.action {
                PlayerAction::Applied { cut: Some(_), .. } => {
                    recovery.accept_player_control(&control, tls, 250).unwrap();
                }
                PlayerAction::Intent { number, bytes } => {
                    original_payloads.push((*number, bytes.clone()));
                    assert_eq!(recovery.accept_player_control(&control, tls, 250), Ok(true));
                    assert_eq!(
                        recovery.accept_player_control(&control, tls, 250),
                        Ok(false)
                    );
                }
                _ => panic!("unexpected recovery action"),
            }
        }
        if round == 0 {
            // Lost round replies retain both the signed envelopes and originals.
            deliver_recovery_player(
                &mut server,
                &mut client,
                PacketKind::Control,
                &wire,
                250,
                |_, _, _| panic!("duplicate round callback"),
            );
            assert_eq!(
                recovery_player_controls(&mut client, &mut server, 250),
                replies
            );
            while recovery.next_input().unwrap().is_some() {
                let before = recovery.sequencer().image().to_vec();
                recovery
                    .apply_next(&key, |_, _, _, histories| {
                        let mut next = SessionImage::decode(&root, &before).unwrap();
                        next.inputs = histories.clone();
                        Ok((next.encode(&root).unwrap(), vec![]))
                    })
                    .unwrap();
            }
        } else if round == 1 {
            let before = recovery.sequencer().image().to_vec();
            recovery
                .commit_departures(&key, |absent, _, histories| {
                    assert_eq!(absent, &[1]);
                    let mut next = SessionImage::decode(&root, &before).unwrap();
                    next.members.retain(|m| !absent.contains(&m.player));
                    next.inputs = histories.clone();
                    next.membership_revision += 1;
                    Ok((next.encode(&root).unwrap(), vec![]))
                })
                .unwrap();
        }
    }
    assert_eq!(
        original_payloads,
        vec![(1, vec![10]), (2, vec![20]), (3, vec![30]), (4, vec![40])]
    );
    assert!(control_ids.windows(2).all(|w| w[0] < w[1]));
    let mut barrier = RecoveryBarrier::new(recovery, &key, 250).unwrap();
    barrier
        .retain_local(
            3,
            &DeliveryJournal::default(),
            &IntentJournal::default(),
            0,
            250,
        )
        .unwrap();
    let cut = barrier.issue(2, tls, &key, 250).unwrap();
    let cut_wire = cut.encode(&root, &promotion).unwrap();
    assert_eq!(
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &cut_wire,
            250,
            |_, _, _| panic!("clock cut is not game input")
        ),
        vec![RecoveryPlayerEvent::ClockCut { logical_ms: 100 }]
    );
    for old in [&challenge.encode(&root).unwrap(), &last_round] {
        assert!(deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            old,
            250,
            |_, _, _| panic!("late request callback")
        )
        .is_empty());
    }
    assert!(recovery_player_controls(&mut client, &mut server, 250).is_empty());
    let mut rebases = 0;
    client
        .confirm_clock(125, 250, |logical, delta| {
            assert_eq!((logical, delta), (100, 125));
            rebases += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        client.confirm_clock(125, 250, |_, _| panic!("second native rebase")),
        Err(Error::Stale)
    );
    let ready_bytes = recovery_player_controls(&mut client, &mut server, 250);
    assert_eq!(ready_bytes.len(), 1);
    let ready = RecoveryReady::decode(&root, &promotion, &cut, &ready_bytes[0]).unwrap();
    let original_ready = ready;
    let cut = barrier.issue(2, tls, &key, 250).unwrap();
    assert_eq!(barrier.accept(&original_ready, tls, 250), Err(Error::Stale));
    let cut_wire = cut.encode(&root, &promotion).unwrap();
    assert!(deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &cut_wire,
        250,
        |_, _, _| panic!("replacement cut is not native work")
    )
    .is_empty());
    let ready_bytes = recovery_player_controls(&mut client, &mut server, 250);
    assert_eq!(ready_bytes.len(), 1);
    let ready = RecoveryReady::decode(&root, &promotion, &cut, &ready_bytes[0]).unwrap();
    assert_eq!(ready.clock_delta, original_ready.clock_delta);
    assert!(ready.sequence > original_ready.sequence);
    barrier.accept(&ready, tls, 250).unwrap();
    deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &cut_wire,
        250,
        |_, _, _| panic!("duplicate cut callback"),
    );
    assert_eq!(
        recovery_player_controls(&mut client, &mut server, 250),
        ready_bytes
    );
    for old in [&challenge.encode(&root).unwrap(), &last_round] {
        assert!(deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            old,
            250,
            |_, _, _| panic!("late request callback")
        )
        .is_empty());
    }
    assert!(recovery_player_controls(&mut client, &mut server, 250).is_empty());
    assert_eq!(rebases, 1);
    let mut inbox = Some(PlayerInbox::new(&server, cut.membership.clone()).unwrap());
    let (mut successor, _, resume) = barrier.finish(&key, 250).unwrap();
    deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &cut_wire,
        250,
        |_, _, _| panic!("queued ready retry callback"),
    );
    assert_eq!(
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &resume.encode(&root, &promotion).unwrap(),
            250,
            |_, _, _| panic!("resume is not a new game start")
        ),
        vec![RecoveryPlayerEvent::Resumed]
    );
    let mut endpoint = client.into_endpoint().unwrap();
    assert_eq!(
        (
            endpoint.journals().0.applied(),
            endpoint.journals().1.tail(),
            endpoint.journals().1.acknowledged()
        ),
        (2, 4, 4)
    );
    let mut queue = successor
        .attach_warm_player(&server, &mut inbox, &key)
        .unwrap();
    assert_eq!(endpoint.queue_view(vec![2]).unwrap(), 2);
    let mut final_transfer = 0;
    while let Some(wire) = endpoint.poll_send(250).unwrap() {
        final_transfer = Frame::decode(&wire).unwrap().transfer;
        if let Some((_, _, bytes)) = server.receive(&wire, 250).unwrap() {
            assert!(queue.receive(&bytes, successor.primary()).unwrap());
        }
    }
    assert!(final_transfer > 2, "warm physical framing must not restart");
    assert_eq!(queue.lossy(), Some((2, &[2][..])));
    endpoint
        .intents_mut()
        .unwrap()
        .append_batch(&[vec![50]])
        .unwrap();
    let policy = EndpointPolicy {
        descriptor: endpoint.descriptor().clone(),
        role: LinkRole::Successor,
        promotion: Some(promotion.clone()),
        membership: Some(successor.membership_certificate(&key).unwrap()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 1,
        client: LinkRole::Player,
        server: LinkRole::Successor,
    };
    let new_tls = [9; 32];
    let client_channel = Channel::new_bound(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        player,
        root.standby,
        new_tls,
    )
    .unwrap();
    let mut server_channel = Channel::new_bound(
        &policy,
        binding,
        ChannelSide::Server,
        root.standby,
        player,
        new_tls,
    )
    .unwrap();
    let request = queue
        .begin_reconnect(
            &server_channel,
            successor.membership_certificate(&key).unwrap(),
            successor.primary(),
            251,
            &key,
        )
        .unwrap();
    endpoint.reconnect(client_channel, &request).unwrap();
    while let Some(wire) = endpoint.poll_send(251).unwrap() {
        if let Some((_, _, bytes)) = server_channel.receive(&wire, 251).unwrap() {
            queue
                .finish_reconnect(&bytes, successor.primary(), 251)
                .unwrap();
        }
    }
    assert_eq!(endpoint.queue_pending(MAX_BATCH).unwrap(), 1);
    while let Some(wire) = endpoint.poll_send(251).unwrap() {
        if let Some((_, _, bytes)) = server_channel.receive(&wire, 251).unwrap() {
            assert!(queue.receive(&bytes, successor.primary()).unwrap());
        }
    }
    assert_eq!(queue.pending().collect::<Vec<_>>(), vec![(5, &[50][..])]);
    assert_eq!(endpoint.journals().0.applied(), 2);
}

#[test]
fn retained_original_player_consumes_the_authority_owned_already_fenced_channel() {
    let ((root, host, key, seq, primary, _, _, _, image), armed, _) =
        normal_player_endpoint_with_activation();
    let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
    descriptor.consent(&key).unwrap();
    let certificate = seq.membership_certificate(&key).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let host_player = Channel::new_bound(
        &policy,
        ConnectionBinding {
            session: root.session,
            descriptor: root.digest().unwrap(),
            term: 0,
            client: LinkRole::Player,
            server: LinkRole::Original,
        },
        ChannelSide::Client,
        root.host,
        root.host,
        [7; 32],
    )
    .unwrap();
    let capability = CapabilityAck::sign(
        &root,
        1,
        state_hash(&image.encode(&root).unwrap()).unwrap(),
        1,
        &host,
    )
    .unwrap();
    let mut endpoint = PlayerEndpoint::new_with_sender(
        descriptor.clone(),
        &armed,
        &capability,
        certificate.clone(),
        host_player,
        host.clone(),
        primary.sender_sequence(),
    )
    .unwrap();
    endpoint.queue_view(vec![1]).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: Some(certificate.clone()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::Original,
        server: LinkRole::Standby,
    };
    let tls = [6; 32];
    let original = Channel::new_bound(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        root.host,
        root.standby,
        tls,
    )
    .unwrap();
    let standby = Channel::new_bound(
        &policy,
        binding,
        ChannelSide::Server,
        root.standby,
        root.host,
        tls,
    )
    .unwrap();
    let mut original =
        PrimaryActor::new(descriptor.clone(), primary, original, Activity::Idle, 0).unwrap();
    let mut standby = StandbyActor::new(descriptor.clone(), seq, standby, 0).unwrap();
    original.probe(0).unwrap();
    while let Some(wire) = original.poll_send(0).unwrap() {
        standby
            .receive(&wire, 0, &key, Activity::Idle, |_, _, _| {
                panic!("probe native callback")
            })
            .unwrap();
    }
    while let Some(wire) = standby.poll_send(0).unwrap() {
        original.receive(&wire, 0, &host).unwrap();
    }
    let (mut recovery, mut server) = standby.begin_recovery(&key, 0, true).unwrap();
    let promotion = recovery.promotion().clone();
    let mut closed = false;
    while let Some(wire) = server.poll_send(0).unwrap() {
        closed |= matches!(
            original.receive(&wire, 0, &host).unwrap(),
            Some(PrimaryEvent::Promoted(_))
        );
    }
    assert!(closed);
    assert!(original.primary().is_closed());
    let already_fenced = original.into_recovery_channel().unwrap();
    let mut client = endpoint
        .into_recovery(already_fenced, promotion, 0)
        .unwrap();
    let challenge = recovery.challenge(1, tls, 1, root.host, &key, 0).unwrap();
    deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &challenge.encode(&root).unwrap(),
        0,
        |_, _, _| panic!("proof is not native work"),
    );
    let mut records = Vec::new();
    let mut transfer = 0;
    while let Some(wire) = client.poll_send(0).unwrap() {
        transfer = Frame::decode(&wire).unwrap().transfer;
        if let Some((_, _, bytes)) = server.receive(&wire, 0).unwrap() {
            records.push(bytes);
        }
    }
    assert_eq!(
        transfer, 2,
        "owned original framing carries its probe counter"
    );
    assert_eq!(records.len(), 1);
    let proof = ResumeProof::decode_with_certificate(&root, &certificate, &records[0]).unwrap();
    assert_eq!(proof.player, 1);
    recovery.accept(1, tls, &proof, 0).unwrap();
}

#[test]
fn retained_recovery_streams_512_originals_under_retries_and_interleaved_output_acks() {
    for mixed in [false, true] {
        let (root, _, key, seq, _, mut endpoint, _, _, _) = normal_player_endpoint();
        let entries = (1..=MAX_JOURNAL_RECORDS)
            .map(|id| {
                let size = if mixed {
                    if id <= 128 {
                        1024
                    } else {
                        340
                    }
                } else {
                    MAX_JOURNAL_BYTES / MAX_JOURNAL_RECORDS
                };
                let mut bytes = vec![0; size];
                bytes[..8].copy_from_slice(&(id as u64).to_be_bytes());
                bytes
            })
            .collect::<Vec<_>>();
        endpoint
            .intents_mut()
            .unwrap()
            .append_batch(&entries)
            .unwrap();
        let descriptor = endpoint.descriptor().clone();
        let player = root.member(2).unwrap().key.unwrap();
        let tls = [8; 32];
        let policy = EndpointPolicy {
            descriptor: descriptor.clone(),
            role: LinkRole::Standby,
            promotion: None,
            membership: Some(seq.membership_certificate(&key).unwrap()),
        };
        let binding = ConnectionBinding {
            session: root.session,
            descriptor: root.digest().unwrap(),
            term: 0,
            client: LinkRole::ControlPlayer,
            server: LinkRole::Standby,
        };
        let warm = Channel::new_bound(
            &policy,
            binding.clone(),
            ChannelSide::Client,
            player,
            root.standby,
            tls,
        )
        .unwrap();
        let mut server = Channel::new_bound(
            &policy,
            binding,
            ChannelSide::Server,
            root.standby,
            player,
            tls,
        )
        .unwrap();
        let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
        let promotion = recovery.promotion().clone();
        server.promote(&promotion).unwrap();
        let mut client = endpoint.into_recovery(warm, promotion.clone(), 0).unwrap();
        let challenge = recovery.challenge(2, tls, 2, player, &key, 0).unwrap();
        let challenge_wire = challenge.encode(&root).unwrap();
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &challenge_wire,
            0,
            |_, _, _| panic!("challenge callback"),
        );
        let proof = recovery_player_controls(&mut client, &mut server, 0);
        assert_eq!(proof.len(), 1);
        recovery
            .accept(2, tls, &ResumeProof::decode(&root, &proof[0]).unwrap(), 0)
            .unwrap();
        recovery.retain_local(3, 0, 0, 0).unwrap();
        recovery.seal(250).unwrap();
        recovery
            .revalidate_security(&key, 250, |bytes, _| Ok(bytes.to_vec()))
            .unwrap();
        recovery.begin_round().unwrap();
        recovery.seal_inputs(3, 0).unwrap();
        let request = recovery.issue_input_round(2, tls, &key, 250).unwrap();
        let wire = request.encode(&root, &promotion).unwrap();
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &wire,
            250,
            |_, _, _| panic!("round callback"),
        );
        let mut callbacks = 0;
        let mut applied = 0;
        let mut acknowledged = 0;
        let mut now = 250;
        let mut received = std::collections::BTreeSet::new();
        while now < 4500 {
            if (now - 250) % 50 == 0 {
                deliver_recovery_player(
                    &mut server,
                    &mut client,
                    PacketKind::Control,
                    &wire,
                    now,
                    |_, _, _| panic!("retry callback"),
                );
            }
            for bytes in recovery_player_controls(&mut client, &mut server, now) {
                let record = PlayerControl::decode(&root, &bytes).unwrap();
                recovery.accept_player_control(&record, tls, now).unwrap();
                if let PlayerAction::Intent { number, bytes } = record.action {
                    assert_eq!(bytes, entries[number as usize - 1]);
                    received.insert(number);
                } else if let PlayerAction::Applied {
                    output, cut: None, ..
                } = record.action
                {
                    acknowledged = acknowledged.max(output);
                }
            }
            if acknowledged == MAX_JOURNAL_RECORDS as u64 {
                break;
            }
            if let Ok(Some(_)) = recovery.next_input() {
                let before = recovery.sequencer().image().to_vec();
                recovery
                    .apply_next(&key, |_, _, _, histories| {
                        callbacks += 1;
                        let mut next = SessionImage::decode(&root, &before).unwrap();
                        next.inputs = histories.clone();
                        Ok((
                            next.encode(&root).unwrap(),
                            vec![Output {
                                recipient: 2,
                                delivery: Delivery::Reliable,
                                sequence: callbacks,
                                bytes: vec![1],
                            }],
                        ))
                    })
                    .unwrap();
                let output = recovery.sequencer().publication()[0].clone();
                deliver_recovery_player(
                    &mut server,
                    &mut client,
                    PacketKind::Output,
                    &output.encode(&root.context().unwrap()).unwrap(),
                    now,
                    |_, _, _| {
                        applied += 1;
                        Ok(())
                    },
                );
            }
            now += 1;
        }
        assert_eq!(received.len(), MAX_JOURNAL_RECORDS);
        assert_eq!(callbacks, MAX_JOURNAL_RECORDS as u64);
        assert_eq!(applied, callbacks);
        assert_eq!(acknowledged, callbacks);
        assert!(
            now < 4500,
            "periodic exact retries must not starve an unfinished suffix"
        );
        let completed = now;
        // Both cached standby requests have aged behind >512 distinct receipts.
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &challenge_wire,
            now,
            |_, _, _| panic!("aged proof callback"),
        );
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &wire,
            now,
            |_, _, _| panic!("aged round callback"),
        );
        for at in now..now + 400 {
            for bytes in recovery_player_controls(&mut client, &mut server, at) {
                let record = PlayerControl::decode(&root, &bytes).unwrap();
                assert!(!matches!(record.action, PlayerAction::Lossy { .. }));
                recovery.accept_player_control(&record, tls, at).unwrap();
            }
        }
        assert_eq!(callbacks, MAX_JOURNAL_RECORDS as u64);
        assert!(client.failure().is_none());
        eprintln!("RECOVERY_STREAM_PROFILE originals={} output_callbacks={} completed_virtual_ms={} periodic_retry_ms=50 unchanged_deadline_ms=5000 mixed_payloads={mixed}",received.len(),callbacks,completed);
    }
}

#[test]
fn normal_queue_ignores_authenticated_old_originals_beyond_its_control_window() {
    let ((root, _, key, mut seq, mut primary, _, _, mut queue, mut image), _, player) =
        normal_player_endpoint_with_activation();
    let certificate = seq.membership_certificate(&key).unwrap();
    let make = |sequence, action| {
        PlayerControl::sign(
            &root,
            &certificate,
            0,
            sequence,
            2,
            [7; 32],
            action,
            &player,
        )
        .unwrap()
        .encode(&root)
        .unwrap()
    };
    let old = make(
        2,
        PlayerAction::Intent {
            number: 1,
            bytes: vec![7],
        },
    );
    queue.receive(&old, &primary).unwrap();
    image.inputs.get_mut(&2).unwrap().record(1, &[7]).unwrap();
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
    let candidate = primary
        .prepare(image.encode(&root).unwrap(), 100, marks, vec![])
        .unwrap()
        .clone();
    let staged = seq.stage(candidate).unwrap();
    primary
        .acknowledge(seq.install(staged, &key).unwrap())
        .unwrap();
    queue.refresh(&primary).unwrap();
    for sequence in 3..=MAX_JOURNAL_RECORDS as u64 + 3 {
        queue
            .receive(
                &make(
                    sequence,
                    PlayerAction::Lossy {
                        number: sequence,
                        bytes: vec![1],
                    },
                ),
                &primary,
            )
            .unwrap();
    }
    assert_eq!(queue.receive(&old, &primary), Ok(false));
    assert!(queue.pending().next().is_none());
    let changed = make(
        1000,
        PlayerAction::Intent {
            number: 1,
            bytes: vec![8],
        },
    );
    assert_eq!(queue.receive(&changed, &primary), Err(Error::Conflict));
    assert_eq!(primary.sender_sequence().allocate(), Err(Error::Closed));
}

fn retained_player_waiting_for_clock() -> (
    Root,
    Keys,
    PlayerRecovery,
    Channel,
    RecoveryBarrier,
    RecoveryCut,
) {
    let (root, _, key, seq, _, endpoint, _, _, _) = normal_player_endpoint();
    let descriptor = endpoint.descriptor().clone();
    let player = root.member(2).unwrap().key.unwrap();
    let tls = [8; 32];
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Standby,
        promotion: None,
        membership: Some(seq.membership_certificate(&key).unwrap()),
    };
    let binding = ConnectionBinding {
        session: root.session,
        descriptor: root.digest().unwrap(),
        term: 0,
        client: LinkRole::ControlPlayer,
        server: LinkRole::Standby,
    };
    let warm = Channel::new_bound(
        &policy,
        binding.clone(),
        ChannelSide::Client,
        player,
        root.standby,
        tls,
    )
    .unwrap();
    let mut server = Channel::new_bound(
        &policy,
        binding,
        ChannelSide::Server,
        root.standby,
        player,
        tls,
    )
    .unwrap();
    let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
    let promotion = recovery.promotion().clone();
    server.promote(&promotion).unwrap();
    let mut client = endpoint.into_recovery(warm, promotion.clone(), 0).unwrap();
    let challenge = recovery.challenge(2, tls, 2, player, &key, 0).unwrap();
    deliver_recovery_player(
        &mut server,
        &mut client,
        PacketKind::Control,
        &challenge.encode(&root).unwrap(),
        0,
        |_, _, _| panic!("challenge callback"),
    );
    let replies = recovery_player_controls(&mut client, &mut server, 0);
    recovery
        .accept(2, tls, &ResumeProof::decode(&root, &replies[0]).unwrap(), 0)
        .unwrap();
    recovery.retain_local(3, 0, 0, 0).unwrap();
    recovery.seal(250).unwrap();
    recovery
        .revalidate_security(&key, 250, |bytes, _| Ok(bytes.to_vec()))
        .unwrap();
    for round in 0..2 {
        recovery.begin_round().unwrap();
        recovery.seal_inputs(3, 0).unwrap();
        let request = recovery.issue_input_round(2, tls, &key, 250).unwrap();
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &request.encode(&root, &promotion).unwrap(),
            250,
            |_, _, _| panic!("round callback"),
        );
        for bytes in recovery_player_controls(&mut client, &mut server, 250) {
            recovery
                .accept_player_control(&PlayerControl::decode(&root, &bytes).unwrap(), tls, 250)
                .unwrap();
        }
        if round == 0 {
            let before = recovery.sequencer().image().to_vec();
            recovery
                .commit_departures(&key, |absent, _, histories| {
                    let mut image = SessionImage::decode(&root, &before).unwrap();
                    image.members.retain(|m| !absent.contains(&m.player));
                    image.inputs = histories.clone();
                    image.membership_revision += 1;
                    Ok((image.encode(&root).unwrap(), vec![]))
                })
                .unwrap();
        }
    }
    let mut barrier = RecoveryBarrier::new(recovery, &key, 250).unwrap();
    barrier
        .retain_local(
            3,
            &DeliveryJournal::default(),
            &IntentJournal::default(),
            0,
            250,
        )
        .unwrap();
    let cut = barrier.issue(2, tls, &key, 250).unwrap();
    assert_eq!(
        deliver_recovery_player(
            &mut server,
            &mut client,
            PacketKind::Control,
            &cut.encode(&root, &promotion).unwrap(),
            250,
            |_, _, _| panic!("clock callback")
        ),
        vec![RecoveryPlayerEvent::ClockCut { logical_ms: 100 }]
    );
    (root, key, client, server, barrier, cut)
}

#[test]
fn retained_recovery_clock_faults_and_replacement_nonces_never_restart_the_deadline() {
    for fault in 0..4 {
        let (root, key, mut client, mut server, mut barrier, _) =
            retained_player_waiting_for_clock();
        let mut calls = 0;
        let result = match fault {
            0 => client.confirm_clock(251, 250, |_, _| {
                calls += 1;
                Ok(())
            }),
            1 => client.confirm_clock(0, 250, |_, _| {
                calls += 1;
                Err(Error::RateLimited)
            }),
            2 => client.confirm_clock(0, 250, |_, _| {
                calls += 1;
                panic!("clock rebase test panic")
            }),
            _ => {
                let cut = barrier.issue(2, [8; 32], &key, 4900).unwrap();
                deliver_recovery_player(
                    &mut server,
                    &mut client,
                    PacketKind::Control,
                    &cut.encode(&root, barrier.promotion()).unwrap(),
                    4900,
                    |_, _, _| panic!("replacement clock callback"),
                );
                client.confirm_clock(0, 5000, |_, _| {
                    calls += 1;
                    Ok(())
                })
            }
        };
        assert!(result.is_err());
        assert_eq!(calls, usize::from(fault == 1 || fault == 2));
        assert!(client.failure().is_some());
        assert_eq!(
            client.confirm_clock(0, 5000, |_, _| panic!("clock fault retry")),
            Err(Error::Closed)
        );
        assert_eq!(client.poll_send(5000), Err(Error::Closed));
        assert_eq!(client.journals().0.applied(), 0);
        assert_eq!(client.journals().1.tail(), 0);
    }
}

#[test]
fn normal_player_remembered_membership_retry_after_newer_certificate_is_a_noop() {
    let (root, _, key, mut seq, mut primary, mut endpoint, mut server, _, mut image) =
        normal_player_endpoint();
    let old = seq.membership_certificate(&key).unwrap();
    let old_bytes = old.encode(&root).unwrap();
    server.enqueue(PacketKind::Control, &old_bytes).unwrap();
    while let Some(wire) = server.poll_send(0).unwrap() {
        assert!(endpoint
            .receive(&wire, 0, |_, _, _| panic!(
                "membership cannot run game code"
            ))
            .unwrap()
            .is_none());
    }
    image.logical_ms += 16;
    image.game = vec![9];
    let candidate = primary
        .prepare(
            image.encode(&root).unwrap(),
            image.logical_ms,
            primary.receipt().watermarks.clone(),
            vec![],
        )
        .unwrap()
        .clone();
    let staged = seq.stage(candidate).unwrap();
    primary
        .acknowledge(seq.install(staged, &key).unwrap())
        .unwrap();
    let newer = seq.membership_certificate(&key).unwrap();
    server
        .enqueue(PacketKind::Control, &newer.encode(&root).unwrap())
        .unwrap();
    let mut installed = false;
    while let Some(wire) = server.poll_send(1).unwrap() {
        if let Some(PlayerEvent::Membership(certificate)) = endpoint
            .receive(&wire, 1, |_, _, _| {
                panic!("membership cannot run game code")
            })
            .unwrap()
        {
            assert_eq!(certificate, newer);
            installed = true;
        }
    }
    assert!(installed);
    let before = (
        endpoint.journals().0.checkpoint().unwrap(),
        endpoint.journals().1.checkpoint().unwrap(),
    );
    let sender_before = endpoint.sequence().allocate().unwrap();
    server.enqueue(PacketKind::Control, &old_bytes).unwrap();
    while let Some(wire) = server.poll_send(2).unwrap() {
        assert!(endpoint
            .receive(&wire, 2, |_, _, _| panic!("old retry cannot run game code"))
            .unwrap()
            .is_none());
    }
    assert!(endpoint.failure().is_none());
    assert_eq!(
        (
            endpoint.journals().0.checkpoint().unwrap(),
            endpoint.journals().1.checkpoint().unwrap()
        ),
        before
    );
    assert_eq!(endpoint.sequence().allocate().unwrap(), sender_before + 1);
    endpoint.queue_applied().unwrap();
}

#[test]
fn normal_player_applies_newer_membership_already_seen_by_shared_consumer() {
    let (
        (root, _, key, mut seq, mut primary, mut endpoint, mut server, _, mut image),
        armed,
        player,
    ) = normal_player_endpoint_with_activation();
    let descriptor = endpoint.descriptor().clone();
    let old = seq.membership_certificate(&key).unwrap();
    let initial = state_hash(&image.encode(&root).unwrap()).unwrap();
    let capability = CapabilityAck::sign(&root, 2, initial, 1, &player).unwrap();
    let policy = EndpointPolicy {
        descriptor: descriptor.clone(),
        role: LinkRole::Original,
        promotion: None,
        membership: Some(old.clone()),
    };
    let channel = Channel::new_bound(
        &policy,
        server.binding().clone(),
        ChannelSide::Client,
        player.public_key().to_bytes(),
        root.host,
        server.tls(),
    )
    .unwrap();
    // Two metadata consumers share canonical replay history but retain their
    // own applied frontiers and journals. The channel here is synthetic.
    let mut sibling = PlayerEndpoint::new_with_sender(
        descriptor,
        &armed,
        &capability,
        old,
        channel,
        player,
        endpoint.sequence(),
    )
    .unwrap();
    for client in [&mut endpoint, &mut sibling] {
        client
            .intents_mut()
            .unwrap()
            .append_batch(&[vec![7]])
            .unwrap();
    }
    image.logical_ms += 16;
    image.inputs.get_mut(&2).unwrap().record(1, &[7]).unwrap();
    let mut marks = primary.receipt().watermarks.clone();
    marks.iter_mut().find(|m| m.player == 2).unwrap().input = 1;
    let candidate = primary
        .prepare(
            image.encode(&root).unwrap(),
            image.logical_ms,
            marks,
            vec![],
        )
        .unwrap()
        .clone();
    let staged = seq.stage(candidate).unwrap();
    primary
        .acknowledge(seq.install(staged, &key).unwrap())
        .unwrap();
    let newer = seq.membership_certificate(&key).unwrap();
    server
        .enqueue(PacketKind::Control, &newer.encode(&root).unwrap())
        .unwrap();
    let mut local_applied = false;
    while let Some(wire) = server.poll_send(0).unwrap() {
        let _ = sibling
            .receive(&wire, 0, |_, _, _| {
                panic!("membership has no game callback")
            })
            .unwrap();
        if let Some(PlayerEvent::Membership(certificate)) = endpoint
            .receive(&wire, 0, |_, _, _| {
                panic!("membership has no game callback")
            })
            .unwrap()
        {
            assert_eq!(certificate, newer);
            local_applied = true;
        }
    }
    assert!(local_applied);
    assert_eq!(sibling.journals().1.acknowledged(), 1);
    assert_eq!(endpoint.journals().1.acknowledged(), 1);
    assert!(endpoint.failure().is_none());
}
