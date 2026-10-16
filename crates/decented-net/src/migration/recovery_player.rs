//! Retained client-side half of frozen recovery. Native game state remains in
//! the owning runner; only its existing endpoint and prepared channel can enter.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryPlayerEvent {
    Output(PlayerEvent),
    ClockCut { logical_ms: u64 },
    Resumed,
}

pub struct PlayerRecovery {
    endpoint: PlayerEndpoint,
    promotion: Promotion,
    started: u64,
    last_ms: u64,
    proof: Option<(ResumeChallenge, Vec<u8>)>,
    round: Option<(InputRound, Vec<Vec<u8>>)>,
    round_send: usize,
    first_pass_complete: bool,
    needs_applied: bool,
    cut: Option<RecoveryCut>,
    ready: Option<(RecoveryReady, Vec<u8>)>,
    resumed: bool,
}

impl PlayerEndpoint {
    /// Freeze ordinary client work and move the same journals, sender namespace
    /// and prepared TLS/framing into recovery. A failed transition cannot return
    /// to the unfenced endpoint. The native client must remain in its runner.
    pub fn into_recovery(
        mut self,
        mut warm: Channel,
        promotion: Promotion,
        now_ms: u64,
    ) -> Result<PlayerRecovery> {
        self.live()?;
        let root = &self.descriptor.root;
        promotion.verify(&root.context()?)?;
        if warm.descriptor != self.descriptor
            || warm.side != ChannelSide::Client
            || warm.term > 1
            || warm.binding.server != LinkRole::Standby
            || !matches!(
                warm.binding.client,
                LinkRole::ControlPlayer | LinkRole::Original
            )
            || warm.remote_key != root.standby
            || warm.local_key != Some(self.keys.public_key().to_bytes())
            || promotion.final_receipt.index < self.membership.receipt.index
            || promotion.final_receipt.logical_ms < self.membership.receipt.logical_ms
        {
            return Err(Error::Unauthorized);
        }
        if promotion.final_receipt.index == self.membership.receipt.index
            && promotion.final_receipt != self.membership.receipt
        {
            return Err(Error::Conflict);
        }
        self.retained_mark(&promotion.final_receipt)?;
        let incoming = self.sequence.replay.begin(
            root.standby,
            promotion.sequence,
            &promotion.encode(&root.context()?)?,
            false,
        )?;
        if warm.term == 0 {
            warm.promote(&promotion)?;
        } else if warm.promotion.as_ref() != Some(&promotion) {
            return Err(Error::Unauthorized);
        }
        incoming.commit()?;
        self.channel = warm;
        Ok(PlayerRecovery {
            endpoint: self,
            promotion,
            started: now_ms,
            last_ms: now_ms,
            proof: None,
            round: None,
            round_send: 0,
            first_pass_complete: false,
            needs_applied: false,
            cut: None,
            ready: None,
            resumed: false,
        })
    }
}

impl PlayerRecovery {
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        self.endpoint.live()?;
        if now_ms < self.last_ms {
            return Err(Error::Invalid("backwards player recovery clock"));
        }
        self.last_ms = now_ms;
        if !self.resumed && now_ms - self.started >= 5000 {
            self.endpoint.pause(Error::Closed);
            return Err(Error::Closed);
        }
        Ok(())
    }
    pub fn player(&self) -> u64 {
        self.endpoint.player
    }
    pub fn journals(&self) -> (&DeliveryJournal, &IntentJournal) {
        self.endpoint.journals()
    }
    pub fn failure(&self) -> Option<&Error> {
        self.endpoint.failure()
    }
    fn flush_applied(&mut self) -> Result<()> {
        if self.needs_applied && (self.round.is_none() || self.first_pass_complete) {
            match self.endpoint.queue_applied() {
                Ok(()) => self.needs_applied = false,
                Err(Error::Bounds) if self.endpoint.channel.sender.queued_bytes() != 0 => {}
                Err(error) => {
                    self.endpoint.pause(error.clone());
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    pub fn poll_send(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        self.advance(now_ms)?;
        self.flush_applied()?;
        if let Some((_, replies)) = &self.round {
            while let Some(bytes) = replies.get(self.round_send) {
                // A cached retransmission must not build a bulk FIFO in front
                // of a new applied ACK. First transmissions preserve ID order;
                // later passes admit one complete envelope only when drained.
                if self.first_pass_complete && self.endpoint.channel.sender.queued_bytes() != 0 {
                    break;
                }
                match self.endpoint.channel.enqueue(PacketKind::Control, bytes) {
                    Ok(_) => self.round_send += 1,
                    Err(Error::Bounds) if self.endpoint.channel.sender.queued_bytes() != 0 => break,
                    Err(error) => {
                        self.endpoint.pause(error.clone());
                        return Err(error);
                    }
                }
                if self.first_pass_complete {
                    break;
                }
            }
        }
        if self
            .round
            .as_ref()
            .is_some_and(|(_, replies)| self.round_send == replies.len())
        {
            self.first_pass_complete = true;
        }
        self.flush_applied()?;
        self.endpoint.channel.poll_send(now_ms)
    }
    // Stage all replies and frame allocations before replacing any journal or
    // invoking the clock callback. Refusal leaves the live channel unchanged.
    fn queued_controls(&self, records: &[Vec<u8>]) -> Result<(SendQueue, u64)> {
        let channel = &self.endpoint.channel;
        let mut queue = channel.sender.clone();
        let mut next = channel.next;
        let mut frames = Vec::new();
        if records.len() > MAX_JOURNAL_RECORDS + 1 {
            return Err(Error::Bounds);
        }
        for bytes in records {
            channel.check(ChannelSide::Server, PacketKind::Control, bytes.len())?;
            let following = next.checked_add(1).ok_or(Error::Bounds)?;
            frames.extend(Frame::split(
                channel.binding.session,
                channel.term,
                next,
                PacketKind::Control,
                bytes,
            )?);
            next = following;
        }
        queue.enqueue(frames)?;
        Ok((queue, next))
    }
    fn install_controls(&mut self, staged: (SendQueue, u64)) {
        (self.endpoint.channel.sender, self.endpoint.channel.next) = staged;
    }
    fn incoming(
        &self,
        sequence: u64,
        bytes: &[u8],
        cached: Option<(u64, Vec<u8>)>,
    ) -> Result<ReplayTicket> {
        let cached = cached.filter(|(old, _)| *old == sequence);
        if cached.as_ref().is_some_and(|(_, old)| old != bytes) {
            self.endpoint.sequence.replay.fail();
            return Err(Error::Conflict);
        }
        self.endpoint.sequence.replay.begin(
            self.endpoint.descriptor.root.standby,
            sequence,
            bytes,
            cached.is_some(),
        )
    }
    fn own_membership(&self, membership: &MembershipCertificate) -> Result<()> {
        let root = &self.endpoint.descriptor.root;
        membership.follows(root, &self.endpoint.membership)?;
        if !membership.members.iter().any(|m| {
            m.player == self.player() && m.key == Some(self.endpoint.keys.public_key().to_bytes())
        }) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    fn pruned_intents(&self, receipt: &Receipt) -> Result<IntentJournal> {
        let input = self.endpoint.retained_mark(receipt)?.input;
        if self.endpoint.intents.acknowledged() > input {
            return Err(Error::Invalid("recovery input frontier regressed"));
        }
        let mut intents = IntentJournal::restore(&self.endpoint.intents.checkpoint()?)?;
        if input > intents.acknowledged() {
            intents.acknowledge(input)?;
        }
        Ok(intents)
    }
    /// Only physical ingress RateLimited is retryable. Once a framed request
    /// reaches a native callback, any failure permanently suppresses this client.
    pub fn receive(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        mut apply: impl FnMut(Delivery, &[u8], &mut IntentJournal) -> Result<()>,
    ) -> Result<Option<RecoveryPlayerEvent>> {
        self.advance(now_ms)?;
        if self.resumed {
            return Err(Error::Closed);
        }
        let packet = match self.endpoint.channel.receive(wire, now_ms) {
            Ok(Some((kind, _, bytes))) => (kind, bytes),
            Ok(None) => return Ok(None),
            Err(Error::RateLimited) => return Err(Error::RateLimited),
            Err(error) => {
                self.endpoint.pause(error.clone());
                return Err(error);
            }
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.apply_packet(packet.0, &packet.1, &mut apply)
        }))
        .unwrap_or(Err(Error::Invalid("player recovery callback panic")))
        .map_err(|error| {
            if error == Error::RateLimited {
                Error::Invalid("player recovery application rate refusal")
            } else {
                error
            }
        });
        if let Err(error) = &result {
            self.endpoint.pause(error.clone());
        }
        result
    }
    fn apply_packet(
        &mut self,
        kind: PacketKind,
        bytes: &[u8],
        apply: &mut impl FnMut(Delivery, &[u8], &mut IntentJournal) -> Result<()>,
    ) -> Result<Option<RecoveryPlayerEvent>> {
        let root = self.endpoint.descriptor.root.clone();
        if kind == PacketKind::Output {
            if self.proof.is_none() {
                return Err(Error::Unauthorized);
            }
            let record = CertifiedOutput::decode(&root.context()?, bytes)?;
            if record.output.delivery != Delivery::Reliable
                || (record.receipt.term == 0
                    && record.receipt.index > self.promotion.final_receipt.index)
                || (record.receipt.term == 1
                    && (record.receipt.index <= self.promotion.final_receipt.index
                        || record.receipt.logical_ms != self.promotion.final_receipt.logical_ms))
                || (self.cut.is_some() && record.output.sequence > self.endpoint.delivery.applied())
            {
                return Err(Error::Unauthorized);
            }
            let event = self.endpoint.apply_packet(kind, bytes, apply)?;
            self.needs_applied = self.cut.is_none();
            return Ok(event.map(RecoveryPlayerEvent::Output));
        }
        if kind != PacketKind::Control {
            return Err(Error::Unauthorized);
        }
        match control_kind(&root, bytes)? {
            7 => {
                let challenge = ResumeChallenge::decode(&root, bytes)?;
                if challenge.player != self.player()
                    || challenge.tls != self.endpoint.channel.tls
                    || challenge.frontier != self.promotion.final_receipt
                {
                    return Err(Error::Unauthorized);
                }
                self.endpoint.sequence.replay.receipt(&challenge.frontier)?;
                let incoming = self.incoming(
                    challenge.sequence,
                    bytes,
                    self.proof
                        .as_ref()
                        .map(|(old, _)| Ok((old.sequence, old.encode(&root)?)))
                        .transpose()?,
                )?;
                if !incoming.is_new() {
                    if self.round.is_some() || self.cut.is_some() {
                        incoming.commit()?;
                        return Ok(None);
                    }
                    if let Some((old, reply)) = &self.proof {
                        if old == &challenge {
                            let queued = self.queued_controls(&[reply.clone()])?;
                            self.install_controls(queued);
                        }
                    }
                    incoming.commit()?;
                    return Ok(None);
                }
                if self.round.is_some() || self.cut.is_some() {
                    return Err(Error::Stale);
                }
                let intents = self.pruned_intents(&challenge.frontier)?;
                let proof = ResumeProof::sign_with_certificate(
                    &root,
                    &self.endpoint.membership,
                    &challenge,
                    self.endpoint.channel.tls,
                    self.endpoint.delivery.applied(),
                    intents.tail(),
                    self.endpoint.sequence.allocate()?,
                    &self.endpoint.keys,
                )?;
                let reply = proof.encode_with_certificate(&root, &self.endpoint.membership)?;
                let queued = self.queued_controls(&[reply.clone()])?;
                incoming.commit()?;
                self.install_controls(queued);
                self.endpoint.intents = intents;
                self.proof = Some((challenge, reply));
                Ok(None)
            }
            16 => {
                let request = InputRound::decode(&root, &self.promotion, bytes)?;
                if self.proof.is_none()
                    || request.player != self.player()
                    || request.tls != self.endpoint.channel.tls
                {
                    return Err(Error::Unauthorized);
                }
                let incoming = self.incoming(
                    request.sequence,
                    bytes,
                    self.round
                        .as_ref()
                        .map(|(old, _)| Ok((old.sequence, old.encode(&root, &self.promotion)?)))
                        .transpose()?,
                )?;
                if !incoming.is_new() {
                    if self.cut.is_some() {
                        incoming.commit()?;
                        return Ok(None);
                    }
                    if let Some((old, replies)) = &self.round {
                        if old == &request && self.round_send == replies.len() {
                            self.round_send = 0;
                        }
                    }
                    incoming.commit()?;
                    return Ok(None);
                }
                if self.cut.is_some() {
                    return Err(Error::Stale);
                }
                self.own_membership(&request.membership)?;
                self.endpoint
                    .sequence
                    .replay
                    .certificate(&root, &request.membership)?;
                let intents = self.pruned_intents(&request.membership.receipt)?;
                let cut = PlayerControl::seal_round(
                    &root,
                    &self.promotion,
                    &request,
                    request.tls,
                    &self.endpoint.delivery,
                    &intents,
                    self.endpoint.sequence.allocate()?,
                    &self.endpoint.keys,
                )?;
                let mut replies = vec![cut.encode(&root)?];
                for (number, payload) in intents.pending() {
                    replies.push(
                        PlayerControl::sign(
                            &root,
                            &request.membership,
                            1,
                            self.endpoint.sequence.allocate()?,
                            self.player(),
                            request.tls,
                            PlayerAction::Intent {
                                number,
                                bytes: payload.to_vec(),
                            },
                            &self.endpoint.keys,
                        )?
                        .encode(&root)?,
                    );
                }
                if replies.iter().try_fold(0usize, |sum, bytes| {
                    sum.checked_add(bytes.len()).ok_or(Error::Bounds)
                })? > MAX_IMAGE
                {
                    return Err(Error::Bounds);
                }
                let queued = self.queued_controls(&replies[..1])?;
                incoming.commit()?;
                self.install_controls(queued);
                self.round_send = 1;
                self.first_pass_complete = replies.len() == 1;
                self.needs_applied = false;
                self.endpoint.membership = request.membership.clone();
                self.endpoint.intents = intents;
                self.round = Some((request, replies));
                Ok(None)
            }
            12 => {
                let cut = RecoveryCut::decode(&root, &self.promotion, bytes)?;
                if self.proof.is_none()
                    || cut.player != self.player()
                    || cut.tls != self.endpoint.channel.tls
                {
                    return Err(Error::Unauthorized);
                }
                self.own_membership(&cut.membership)?;
                self.endpoint
                    .sequence
                    .replay
                    .certificate(&root, &cut.membership)?;
                let incoming = self.incoming(
                    cut.sequence,
                    bytes,
                    self.cut
                        .as_ref()
                        .map(|old| Ok((old.sequence, old.encode(&root, &self.promotion)?)))
                        .transpose()?,
                )?;
                if !incoming.is_new() {
                    if self.cut.as_ref() == Some(&cut) {
                        if let Some((_, reply)) = &self.ready {
                            let queued = self.queued_controls(&[reply.clone()])?;
                            self.install_controls(queued);
                        }
                    }
                    incoming.commit()?;
                    return Ok(None);
                }
                if let Some((old_ready, _)) = &self.ready {
                    let old_cut = self.cut.as_ref().ok_or(Error::Gap)?;
                    if cut.membership != old_cut.membership
                        || old_ready.applied != self.endpoint.delivery.applied()
                        || old_ready.tail != self.endpoint.intents.tail()
                    {
                        return Err(Error::Conflict);
                    }
                    let ready = RecoveryReady::sign(
                        &root,
                        &self.promotion,
                        &cut,
                        cut.tls,
                        &self.endpoint.delivery,
                        &self.endpoint.intents,
                        old_ready.clock_delta,
                        self.endpoint.sequence.allocate()?,
                        &self.endpoint.keys,
                    )?;
                    let reply = ready.encode(&root, &self.promotion, &cut)?;
                    let queued = self.queued_controls(&[reply.clone()])?;
                    incoming.commit()?;
                    self.install_controls(queued);
                    self.cut = Some(cut);
                    self.ready = Some((ready, reply));
                    return Ok(None);
                }
                let intents = self.pruned_intents(&cut.membership.receipt)?;
                let mark = cut.watermark()?;
                if self.endpoint.delivery.applied() != mark.output_ack
                    || intents.tail() != mark.input
                {
                    return Err(Error::Gap);
                }
                incoming.commit()?;
                self.endpoint.membership = cut.membership.clone();
                self.endpoint.intents = intents;
                self.cut = Some(cut);
                self.round_send = self.round.as_ref().map_or(0, |(_, replies)| replies.len());
                self.needs_applied = false;
                Ok(Some(RecoveryPlayerEvent::ClockCut {
                    logical_ms: self.promotion.final_receipt.logical_ms,
                }))
            }
            14 => {
                let resume = Resume::decode(&root, &self.promotion, bytes)?;
                let cut = self.cut.as_ref().ok_or(Error::Gap)?;
                let (ready, _) = self.ready.as_ref().ok_or(Error::Gap)?;
                ready.verify(&root, &self.promotion, cut)?;
                if resume.membership != cut.membership
                    || ready.applied != self.endpoint.delivery.applied()
                    || ready.tail != self.endpoint.intents.tail()
                    || !resume.cuts.iter().any(|c| {
                        c.player == self.player()
                            && c.input == ready.tail
                            && c.output == ready.applied
                            && c.clock_delta == ready.clock_delta
                            && c.challenge == ready.cut
                    })
                {
                    return Err(Error::Conflict);
                }
                self.endpoint
                    .sequence
                    .replay
                    .certificate(&root, &resume.membership)?;
                let incoming = self.endpoint.sequence.replay.begin(
                    root.standby,
                    resume.sequence,
                    bytes,
                    false,
                )?;
                let remaining = retired_controls(&self.endpoint.channel.sender)?;
                incoming.commit()?;
                self.endpoint.channel.sender = remaining;
                self.endpoint.membership = resume.membership;
                self.endpoint.sent_input = ready.tail;
                self.resumed = true;
                Ok(Some(RecoveryPlayerEvent::Resumed))
            }
            _ => Err(Error::Unauthorized),
        }
    }
    /// The runner supplies its bounded native clock adjustment. Queue capacity
    /// and actual retained journals are checked before this one-shot callback.
    pub fn confirm_clock(
        &mut self,
        clock_delta: i64,
        now_ms: u64,
        rebase: impl FnOnce(u64, i64) -> Result<()>,
    ) -> Result<()> {
        self.advance(now_ms)?;
        if self.resumed || self.ready.is_some() {
            return Err(Error::Stale);
        }
        let root = &self.endpoint.descriptor.root;
        let cut = self.cut.as_ref().ok_or(Error::Gap)?;
        if clock_delta.unsigned_abs() > 250 {
            self.endpoint.pause(Error::Bounds);
            return Err(Error::Bounds);
        }
        let ready = RecoveryReady::sign(
            root,
            &self.promotion,
            cut,
            self.endpoint.channel.tls,
            &self.endpoint.delivery,
            &self.endpoint.intents,
            clock_delta,
            self.endpoint.sequence.allocate()?,
            &self.endpoint.keys,
        )?;
        let bytes = ready.encode(root, &self.promotion, cut)?;
        let queued = self.queued_controls(&[bytes.clone()])?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rebase(self.promotion.final_receipt.logical_ms, clock_delta)
        }))
        .unwrap_or(Err(Error::Invalid("player recovery clock panic")))
        .and_then(|()| self.endpoint.live());
        if let Err(error) = result {
            self.endpoint.pause(error.clone());
            return Err(error);
        }
        self.install_controls(queued);
        self.ready = Some((ready, bytes));
        Ok(())
    }
    /// Resume returns the original endpoint with its same warm framing and
    /// retained journals. Neither a proof nor a public Resume can construct one.
    pub fn into_endpoint(self) -> Result<PlayerEndpoint> {
        self.endpoint.live()?;
        if !self.resumed {
            return Err(Error::Gap);
        }
        Ok(self.endpoint)
    }
}

fn retired_controls(sender: &SendQueue) -> Result<SendQueue> {
    let mut queue = sender.clone();
    let mut whole = BTreeSet::new();
    for (_, bytes) in queue.priority.iter().chain(&queue.ordinary) {
        let frame = Frame::decode(bytes)?;
        if frame.kind == PacketKind::Control && frame.ordinal == 0 {
            whole.insert((frame.term, frame.transfer));
        }
    }
    for pending in [&mut queue.priority, &mut queue.ordinary] {
        let mut retained = VecDeque::new();
        while let Some((term, bytes)) = pending.pop_front() {
            let frame = Frame::decode(&bytes)?;
            if frame.kind == PacketKind::Control && whole.contains(&(frame.term, frame.transfer)) {
                queue.bytes -= bytes.len();
            } else {
                retained.push_back((term, bytes));
            }
        }
        *pending = retained;
    }
    Ok(queue)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retiring_whole_controls_keeps_partial_envelopes_and_exact_pacing_state() {
        let mut queue = SendQueue::default();
        queue
            .enqueue(Frame::split([1; 16], 1, 7, PacketKind::Control, &vec![1; 1024]).unwrap())
            .unwrap();
        assert_eq!(
            Frame::decode(&queue.poll(123).unwrap().unwrap())
                .unwrap()
                .ordinal,
            0
        );
        queue
            .enqueue(Frame::split([1; 16], 1, 8, PacketKind::Control, &vec![2; 226]).unwrap())
            .unwrap();
        queue
            .enqueue(Frame::split([1; 16], 1, 9, PacketKind::Control, &vec![3; 1024]).unwrap())
            .unwrap();
        queue
            .enqueue(Frame::split([1; 16], 1, 10, PacketKind::Output, &[4]).unwrap())
            .unwrap();
        let pacing = (queue.tokens, queue.last_ms, queue.fraction);
        let mut retired = retired_controls(&queue).unwrap();
        assert_eq!((retired.tokens, retired.last_ms, retired.fraction), pacing);
        let rest = Frame::decode(&retired.poll(123).unwrap().unwrap()).unwrap();
        assert_eq!((rest.transfer, rest.ordinal), (7, 1));
        let output = Frame::decode(&retired.poll(123).unwrap().unwrap()).unwrap();
        assert_eq!(output.transfer, 10);
        assert!(retired.poll(123).unwrap().is_none());
        assert_eq!(retired.queued_bytes(), 0);
    }
}
