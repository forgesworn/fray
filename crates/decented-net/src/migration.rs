//! Bounded, poll-driven building blocks for the fixed-pair migration protocol.
//!
//! A standby installs an exact state image before signing a receipt. Closing
//! its original term and installing a candidate use the same mutable actor;
//! speculative state and a validation result are never publication authority.
//! Game admission and checkpoint completeness remain the game runner's duties.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use nostr::secp256k1::{schnorr::Signature, Message};
use nostr::{Keys, PublicKey};
use sha2::{Digest as _, Sha256};

pub type Hash = [u8; 32];
pub type SessionId = [u8; 16];
pub type RuntimeKey = [u8; 32];
pub type SignatureBytes = [u8; 64];
pub const VERSION: u8 = 1;
pub const MAX_IMAGE: usize = 1024 * 1024;
pub const MAX_PATCH: usize = 64 * 1024;
pub const CHUNK_PAYLOAD: usize = 768;
pub const MAX_BATCH: usize = 256;
pub const MAX_OUTBOX_RECORDS: usize = 1024;
pub const MAX_OUTBOX_BYTES: usize = 256 * 1024;
pub const MAX_PROOF_BYTES: usize = 512 * 1024;
pub const MAX_JOURNAL_RECORDS: usize = 512;
pub const MAX_JOURNAL_BYTES: usize = 256 * 1024;
pub const MAX_PLAYERS: usize = 8;
/// Signed lossy views one human queue retains between commits. A view's payload
/// is capped at the 1024-byte transport limit, so this many views fit the same
/// per-player memory cap as the original journal. Overflow drops the oldest view.
pub const MAX_LOSSY_VIEWS: usize = MAX_JOURNAL_BYTES / crate::MAX_RELIABLE_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Bounds,
    /// Frame was not consumed; defer it through a bounded ReceiveQueue.
    RateLimited,
    Unauthorized,
    Stale,
    Closed,
    Conflict,
    Gap,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

fn hash(label: &[u8], bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(label);
    h.update(bytes);
    h.finalize().into()
}
pub fn state_hash(bytes: &[u8]) -> Result<Hash> {
    if bytes.len() > MAX_IMAGE {
        return Err(Error::Bounds);
    }
    Ok(hash(b"fray/migration/state/v1\0", bytes))
}
fn sign(keys: &Keys, digest: Hash) -> SignatureBytes {
    keys.sign_schnorr(&Message::from_digest(digest)).serialize()
}
fn verify(key: RuntimeKey, digest: Hash, sig: SignatureBytes) -> Result<()> {
    let key = PublicKey::from_slice(&key).map_err(|_| Error::Unauthorized)?;
    let sig = Signature::from_slice(&sig).map_err(|_| Error::Unauthorized)?;
    nostr::SECP256K1
        .verify_schnorr(
            &sig,
            &Message::from_digest(digest),
            &key.xonly().map_err(|_| Error::Unauthorized)?,
        )
        .map_err(|_| Error::Unauthorized)
}
fn put_u32(out: &mut Vec<u8>, n: usize) -> Result<()> {
    out.extend(u32::try_from(n).map_err(|_| Error::Bounds)?.to_be_bytes());
    Ok(())
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Result<()> {
    if bytes.len() > cap {
        return Err(Error::Bounds);
    }
    put_u32(out, bytes.len())?;
    out.extend(bytes);
    Ok(())
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(Error::Invalid("truncated record"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Invalid("array"))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u32(&mut self) -> Result<usize> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| Error::Bounds)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn bytes(&mut self, cap: usize) -> Result<Vec<u8>> {
        let n = self.u32()?;
        if n > cap {
            return Err(Error::Bounds);
        }
        Ok(self.take(n)?.to_vec())
    }
    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Invalid("trailing bytes"))
        }
    }
}

/// Immutable authenticated session binding. It is not an admission credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub session: SessionId,
    pub descriptor: Hash,
    pub host: RuntimeKey,
    pub standby: RuntimeKey,
}
impl Context {
    pub fn validate(&self) -> Result<()> {
        if self.session == [0; 16] || self.descriptor == [0; 32] || self.host == self.standby {
            return Err(Error::Invalid("session binding"));
        }
        PublicKey::from_slice(&self.host).map_err(|_| Error::Unauthorized)?;
        PublicKey::from_slice(&self.standby).map_err(|_| Error::Unauthorized)?;
        Ok(())
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(VERSION);
        out.extend(self.session);
        out.extend(self.descriptor);
    }
    fn read_binding(&self, r: &mut Reader<'_>) -> Result<()> {
        if r.u8()? != VERSION
            || r.array::<16>()? != self.session
            || r.array::<32>()? != self.descriptor
        {
            return Err(Error::Invalid("session/version binding"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Reliable,
    Lossy,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub recipient: u64,
    pub delivery: Delivery,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}
impl Output {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.sequence == 0 {
            return Err(Error::Invalid("zero output sequence"));
        }
        out.extend(self.recipient.to_be_bytes());
        out.push(match self.delivery {
            Delivery::Reliable => 0,
            Delivery::Lossy => 1,
        });
        out.extend(self.sequence.to_be_bytes());
        put_bytes(out, &self.bytes, crate::MAX_RELIABLE_LEN)
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let recipient = r.u64()?;
        let delivery = match r.u8()? {
            0 => Delivery::Reliable,
            1 => Delivery::Lossy,
            _ => return Err(Error::Invalid("delivery")),
        };
        let sequence = r.u64()?;
        if sequence == 0 {
            return Err(Error::Invalid("zero output sequence"));
        }
        Ok(Self {
            recipient,
            delivery,
            sequence,
            bytes: r.bytes(crate::MAX_RELIABLE_LEN)?,
        })
    }
}
fn leaf(index: u64, ordinal: usize, output: &Output) -> Result<Hash> {
    let mut bytes = index.to_be_bytes().to_vec();
    put_u32(&mut bytes, ordinal)?;
    output.encode(&mut bytes)?;
    Ok(hash(b"fray/migration/output/v1\0", &bytes))
}
fn node(left: Hash, right: Hash) -> Hash {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    hash(b"fray/migration/node/v1\0", &bytes)
}
fn empty_leaf() -> Hash {
    hash(b"fray/migration/empty/v1\0", &[])
}
fn tree(index: u64, outputs: &[Output]) -> Result<Vec<Vec<Hash>>> {
    if outputs.len() > MAX_BATCH {
        return Err(Error::Bounds);
    }
    if outputs.is_empty() {
        return Ok(vec![vec![empty_leaf()]]);
    }
    let mut leaves = outputs
        .iter()
        .enumerate()
        .map(|(i, o)| leaf(index, i, o))
        .collect::<Result<Vec<_>>>()?;
    leaves.resize(outputs.len().next_power_of_two(), empty_leaf());
    let mut layers = vec![leaves];
    while layers.last().unwrap().len() > 1 {
        let next = layers
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|pair| node(pair[0], pair[1]))
            .collect();
        layers.push(next);
    }
    Ok(layers)
}

/// Cumulative handled input and application-ACKed output, sorted by stable ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Watermark {
    pub player: u64,
    pub input: u64,
    pub output_ack: u64,
    pub retired: bool,
}
fn encode_watermarks(out: &mut Vec<u8>, marks: &[Watermark]) -> Result<()> {
    if marks.len() > MAX_PLAYERS {
        return Err(Error::Bounds);
    }
    put_u32(out, marks.len())?;
    let mut previous = None;
    for m in marks {
        if previous.is_some_and(|p| p >= m.player) {
            return Err(Error::Invalid("watermark order"));
        }
        previous = Some(m.player);
        out.extend(m.player.to_be_bytes());
        out.extend(m.input.to_be_bytes());
        out.extend(m.output_ack.to_be_bytes());
        out.push(u8::from(m.retired));
    }
    Ok(())
}
fn read_watermarks(r: &mut Reader<'_>) -> Result<Vec<Watermark>> {
    let count = r.u32()?;
    if count > MAX_PLAYERS {
        return Err(Error::Bounds);
    }
    let mut marks = Vec::with_capacity(count);
    for _ in 0..count {
        marks.push(Watermark {
            player: r.u64()?,
            input: r.u64()?,
            output_ack: r.u64()?,
            retired: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Invalid("retired flag")),
            },
        });
    }
    let mut canonical = Vec::new();
    encode_watermarks(&mut canonical, &marks)?;
    Ok(marks)
}

/// A receipt authorizes the exact installed image and output batch, not a timer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub sequence: u64,
    pub term: u64,
    pub index: u64,
    pub parent: Hash,
    pub state: Hash,
    pub logical_ms: u64,
    pub outputs_root: Hash,
    pub outputs_count: u32,
    pub watermarks: Vec<Watermark>,
    pub signature: SignatureBytes,
}
impl Receipt {
    fn body(&self, context: &Context) -> Result<Vec<u8>> {
        if self.sequence == 0 || self.term > 1 || self.outputs_count as usize > MAX_BATCH {
            return Err(Error::Invalid("receipt bounds"));
        }
        let mut out = control_prefix(context, self.term, 4, self.sequence);
        out.extend(self.index.to_be_bytes());
        out.extend(self.parent);
        out.extend(self.state);
        out.extend(self.logical_ms.to_be_bytes());
        out.extend(self.outputs_root);
        out.extend(self.outputs_count.to_be_bytes());
        encode_watermarks(&mut out, &self.watermarks)?;
        Ok(out)
    }
    fn signing_hash(&self, context: &Context) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(context)?))
    }
    pub fn digest(&self, context: &Context) -> Result<Hash> {
        Ok(hash(b"fray/migration/commit/v1\0", &self.body(context)?))
    }
    pub fn verify(&self, context: &Context) -> Result<()> {
        context.validate()?;
        if self.outputs_count == 0 && self.outputs_root != empty_leaf() {
            return Err(Error::Invalid("empty output root"));
        }
        verify(context.standby, self.signing_hash(context)?, self.signature)
    }
    pub fn encode(&self, context: &Context) -> Result<Vec<u8>> {
        let mut bytes = self.body(context)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::MAX_RELIABLE_LEN {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        context.read_binding(&mut r)?;
        let term = r.u64()?;
        if r.u8()? != 4 {
            return Err(Error::Invalid("receipt kind"));
        }
        let result = Self {
            sequence: r.u64()?,
            term,
            index: r.u64()?,
            parent: r.array()?,
            state: r.array()?,
            logical_ms: r.u64()?,
            outputs_root: r.array()?,
            outputs_count: u32::try_from(r.u32()?).map_err(|_| Error::Bounds)?,
            watermarks: read_watermarks(&mut r)?,
            signature: r.array()?,
        };
        r.finish()?;
        result.verify(context)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedOutput {
    pub receipt: Receipt,
    pub ordinal: u32,
    pub output: Output,
    pub siblings: Vec<Hash>,
}
impl CertifiedOutput {
    /// Verify the authenticated target before dispatching to a game session.
    pub fn verify_for(&self, context: &Context, recipient: u64, delivery: Delivery) -> Result<()> {
        self.verify(context)?;
        if self.output.recipient != recipient || self.output.delivery != delivery {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub fn verify(&self, context: &Context) -> Result<()> {
        self.receipt.verify(context)?;
        let count = self.receipt.outputs_count as usize;
        let ordinal = self.ordinal as usize;
        if count == 0
            || ordinal >= count
            || self.siblings.len() != count.next_power_of_two().trailing_zeros() as usize
        {
            return Err(Error::Invalid("proof dimensions"));
        }
        let mut digest = leaf(self.receipt.index, ordinal, &self.output)?;
        let mut at = ordinal;
        for sibling in &self.siblings {
            digest = if at & 1 == 0 {
                node(digest, *sibling)
            } else {
                node(*sibling, digest)
            };
            at >>= 1;
        }
        if digest != self.receipt.outputs_root {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub fn encode(&self, context: &Context) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_bytes(
            &mut out,
            &self.receipt.encode(context)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        out.extend(self.ordinal.to_be_bytes());
        self.output.encode(&mut out)?;
        put_u32(&mut out, self.siblings.len())?;
        for sibling in &self.siblings {
            out.extend(sibling);
        }
        Ok(out)
    }
    pub fn decode(context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        let receipt = Receipt::decode(context, &r.bytes(crate::MAX_RELIABLE_LEN)?)?;
        let ordinal = u32::try_from(r.u32()?).map_err(|_| Error::Bounds)?;
        let output = Output::decode(&mut r)?;
        let n = r.u32()?;
        if n > 8 {
            return Err(Error::Bounds);
        }
        let siblings = (0..n).map(|_| r.array()).collect::<Result<Vec<_>>>()?;
        r.finish()?;
        let result = Self {
            receipt,
            ordinal,
            output,
            siblings,
        };
        result.verify(context)?;
        Ok(result)
    }
}

/// One fully validated speculative image. Its private stage token binds the
/// current open term/base, so validation finishing after close cannot commit.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub sequence: u64,
    pub term: u64,
    pub index: u64,
    pub parent: Hash,
    pub logical_ms: u64,
    pub image: Vec<u8>,
    pub watermarks: Vec<Watermark>,
    pub outputs: Vec<Output>,
}
impl Candidate {
    pub fn encode(&self, context: &Context) -> Result<Vec<u8>> {
        if self.sequence == 0 || self.image.len() > MAX_IMAGE || self.outputs.len() > MAX_BATCH {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(context, self.term, 3, self.sequence);
        bytes.extend(self.index.to_be_bytes());
        bytes.extend(self.parent);
        bytes.extend(self.logical_ms.to_be_bytes());
        put_bytes(&mut bytes, &self.image, MAX_IMAGE)?;
        encode_watermarks(&mut bytes, &self.watermarks)?;
        put_u32(&mut bytes, self.outputs.len())?;
        for output in &self.outputs {
            output.encode(&mut bytes)?;
        }
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }
    pub fn decode(context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        context.read_binding(&mut r)?;
        let term = r.u64()?;
        if r.u8()? != 3 {
            return Err(Error::Invalid("candidate kind"));
        }
        let sequence = r.u64()?;
        if term > 1 || sequence == 0 {
            return Err(Error::Invalid("candidate term"));
        }
        let index = r.u64()?;
        let parent = r.array()?;
        let logical_ms = r.u64()?;
        let image = r.bytes(MAX_IMAGE)?;
        let watermarks = read_watermarks(&mut r)?;
        let count = r.u32()?;
        if count > MAX_BATCH {
            return Err(Error::Bounds);
        }
        let outputs = (0..count)
            .map(|_| Output::decode(&mut r))
            .collect::<Result<Vec<_>>>()?;
        r.finish()?;
        Ok(Self {
            sequence,
            term,
            index,
            parent,
            logical_ms,
            image,
            watermarks,
            outputs,
        })
    }
    fn digest(&self, context: &Context) -> Result<Hash> {
        Ok(hash(
            b"fray/migration/candidate/v1\0",
            &self.encode(context)?,
        ))
    }
}

#[derive(Debug)]
pub struct Staged {
    session_bound: bool,
    context: Context,
    candidate: Candidate,
    state: Hash,
    tree: Vec<Vec<Hash>>,
    replay: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Promotion {
    pub sequence: u64,
    pub final_receipt: Receipt,
    pub signature: SignatureBytes,
}
impl Promotion {
    fn body(&self, context: &Context) -> Result<Vec<u8>> {
        if self.sequence <= self.final_receipt.sequence {
            return Err(Error::Invalid("promotion sequence"));
        }
        let mut body = control_prefix(context, 1, 6, self.sequence);
        put_bytes(
            &mut body,
            &self.final_receipt.encode(context)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        Ok(body)
    }
    fn digest(&self, context: &Context) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(context)?))
    }
    pub fn verify(&self, context: &Context) -> Result<()> {
        self.final_receipt.verify(context)?;
        if self.final_receipt.term != 0 {
            return Err(Error::Invalid("promotion term"));
        }
        verify(context.standby, self.digest(context)?, self.signature)
    }
    pub fn encode(&self, context: &Context) -> Result<Vec<u8>> {
        self.verify(context)?;
        let mut bytes = self.body(context)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        context.read_binding(&mut r)?;
        if r.u64()? != 1 || r.u8()? != 6 {
            return Err(Error::Invalid("promotion kind/term"));
        }
        let sequence = r.u64()?;
        let promotion = Self {
            sequence,
            final_receipt: Receipt::decode(context, &r.bytes(crate::MAX_RELIABLE_LEN)?)?,
            signature: r.array()?,
        };
        r.finish()?;
        promotion.verify(context)?;
        Ok(promotion)
    }
}

/// Sole commit sequencer. The application must freeze/validate its arming
/// barrier before construction; this actor does not replace game admission.
pub struct Sequencer {
    context: Context,
    sender: SenderSequence,
    model_original_sender: SenderSequence,
    membership: Option<MembershipCertificate>,
    session_root: Option<Root>,
    receipt: Receipt,
    image: Vec<u8>,
    promotion: Option<Promotion>,
    outbox: BTreeMap<(u64, u64), CertifiedOutput>,
    allocated: BTreeMap<(u64, u8), u64>,
    retired: BTreeSet<u64>,
    last_candidate: Option<Hash>,
    publication: Vec<CertifiedOutput>,
}
fn check_install_budget(
    context: &Context,
    image_len: usize,
    receipt: &Receipt,
    outbox: &BTreeMap<(u64, u64), CertifiedOutput>,
    allocated: &BTreeMap<(u64, u8), u64>,
    retired: &BTreeSet<u64>,
) -> Result<()> {
    let payload_bytes = outbox.values().try_fold(0usize, |n, o| {
        n.checked_add(o.output.bytes.len()).ok_or(Error::Bounds)
    })?;
    let proof_bytes = outbox.values().try_fold(0usize, |n, o| {
        n.checked_add(o.encode(context)?.len()).ok_or(Error::Bounds)
    })?;
    let metadata_bytes = retired
        .len()
        .checked_mul(8)
        .and_then(|n| {
            allocated
                .len()
                .checked_mul(17)
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| n.checked_add(receipt.body(context).ok()?.len()))
        .ok_or(Error::Bounds)?;
    let image_bytes = image_len
        .checked_add(payload_bytes)
        .and_then(|n| n.checked_add(metadata_bytes))
        .ok_or(Error::Bounds)?;
    if outbox.len() > MAX_OUTBOX_RECORDS
        || payload_bytes > MAX_OUTBOX_BYTES
        || proof_bytes > MAX_PROOF_BYTES
        || image_bytes > MAX_IMAGE
    {
        return Err(Error::Bounds);
    }
    Ok(())
}

impl Sequencer {
    pub fn arm(
        context: Context,
        initial: Vec<u8>,
        logical_ms: u64,
        marks: Vec<Watermark>,
        signer: &Keys,
    ) -> Result<Self> {
        let sender = SenderSequence::starting(context.clone(), context.standby, 1)?;
        Self::arm_with_sender(context, initial, logical_ms, marks, signer, sender)
    }
    fn arm_with_sender(
        context: Context,
        initial: Vec<u8>,
        logical_ms: u64,
        marks: Vec<Watermark>,
        signer: &Keys,
        sender: SenderSequence,
    ) -> Result<Self> {
        context.validate()?;
        sender.matches(&context, context.standby)?;
        if signer.public_key().to_bytes() != context.standby {
            return Err(Error::Unauthorized);
        }
        if marks
            .iter()
            .any(|m| m.input != 0 || m.output_ack != 0 || m.retired)
        {
            return Err(Error::Invalid("initial watermark"));
        }
        let mut receipt = Receipt {
            sequence: sender.reserve(2)?,
            term: 0,
            index: 0,
            parent: [0; 32],
            state: state_hash(&initial)?,
            logical_ms,
            outputs_root: empty_leaf(),
            outputs_count: 0,
            watermarks: marks,
            signature: [0; 64],
        };
        if initial
            .len()
            .checked_add(receipt.body(&context)?.len())
            .ok_or(Error::Bounds)?
            > MAX_IMAGE
        {
            return Err(Error::Bounds);
        }
        receipt.signature = sign(signer, receipt.signing_hash(&context)?);
        Ok(Self {
            model_original_sender: SenderSequence::starting(context.clone(), context.host, 1)?,
            sender,
            membership: None,
            context,
            session_root: None,
            receipt,
            image: initial,
            promotion: None,
            outbox: BTreeMap::new(),
            allocated: BTreeMap::new(),
            retired: BTreeSet::new(),
            last_candidate: None,
            publication: Vec::new(),
        })
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn sender_sequence(&self) -> SenderSequence {
        self.sender.clone()
    }
    /// Bind every future candidate to Fray's complete session envelope. The
    /// game adapter still validates the embedded runner by fresh restore.
    pub fn arm_session(root: Root, initial: SessionImage, signer: &Keys) -> Result<Self> {
        let sender = SenderSequence::starting(root.context()?, root.standby, 1)?;
        Self::arm_session_with_sender(root, initial, signer, sender)
    }
    fn arm_session_with_sender(
        root: Root,
        initial: SessionImage,
        signer: &Keys,
        sender: SenderSequence,
    ) -> Result<Self> {
        initial.validate_initial(&root)?;
        let bytes = initial.encode(&root)?;
        let marks = initial
            .members
            .iter()
            .map(|m| Watermark {
                player: m.player,
                input: 0,
                output_ack: 0,
                retired: false,
            })
            .collect();
        let mut sequencer = Self::arm_with_sender(
            root.context()?,
            bytes,
            initial.logical_ms,
            marks,
            signer,
            sender,
        )?;
        sequencer.membership = Some(MembershipCertificate::issue(
            &root,
            sequencer.receipt.clone(),
            &initial,
            signer,
        )?);
        sequencer
            .sender
            .replay
            .advance_membership(&root, sequencer.membership.as_ref().unwrap())?;
        sequencer.session_root = Some(root);
        Ok(sequencer)
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// Complete last installed batch, including lossy views. These proof-carrying
    /// effects may be published; staging candidates provides no such capability.
    pub fn publication(&self) -> &[CertifiedOutput] {
        &self.publication
    }
    pub fn outbox(&self) -> impl Iterator<Item = &CertifiedOutput> {
        self.outbox.values()
    }
    pub fn next(
        &self,
        image: Vec<u8>,
        logical_ms: u64,
        watermarks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<Candidate> {
        Ok(Candidate {
            sequence: if self.promotion.is_some() {
                self.sender.allocate()?
            } else {
                self.model_original_sender.allocate()?
            },
            term: if self.promotion.is_some() { 1 } else { 0 },
            index: self.receipt.index.checked_add(1).ok_or(Error::Bounds)?,
            parent: self.receipt.digest(&self.context)?,
            logical_ms,
            image,
            watermarks,
            outputs,
        })
    }
    /// Pure bounded staging; caller additionally restores/re-checkpoints the
    /// complete game+runner image before installation. It cannot publish outputs.
    pub fn stage(&self, candidate: Candidate) -> Result<Staged> {
        if candidate.outputs.len() > MAX_BATCH {
            return Err(Error::Bounds);
        }
        let candidate_digest = candidate.digest(&self.context)?;
        if candidate.index == self.receipt.index {
            if self.last_candidate == Some(candidate_digest) {
                return Ok(Staged {
                    session_bound: self.session_root.is_some(),
                    context: self.context.clone(),
                    candidate,
                    state: self.receipt.state,
                    tree: Vec::new(),
                    replay: true,
                });
            }
            return Err(Error::Conflict);
        }
        self.check_base(&candidate)?;
        if let Some(root) = &self.session_root {
            let previous = SessionImage::decode(root, &self.image)?;
            let next = SessionImage::decode(root, &candidate.image)?;
            next.validate_successor(root, &previous, &candidate.watermarks, candidate.logical_ms)?;
            match (
                &self.promotion,
                &previous.security_boundary,
                &next.security_boundary,
            ) {
                (None, None, None) => {}
                (Some(promotion), None, Some(boundary)) => {
                    if boundary.fence != promotion.final_receipt.digest(&self.context)?
                        || self.receipt != promotion.final_receipt
                        || candidate.logical_ms != self.receipt.logical_ms
                        || candidate.watermarks != self.receipt.watermarks
                        || !candidate.outputs.is_empty()
                    {
                        return Err(Error::Conflict);
                    }
                    let mut envelope = next.clone();
                    envelope.security_boundary = None;
                    envelope.game = previous.game.clone();
                    if envelope != previous
                        || boundary.tails.iter().any(|(player, tail)| {
                            previous.inputs.get(player).is_none_or(|history| {
                                *tail < history.handled()
                                    || *tail - history.handled() > MAX_JOURNAL_RECORDS as u64
                            })
                        })
                    {
                        return Err(Error::Conflict);
                    }
                }
                (Some(_), Some(old), Some(new)) if old == new => {}
                _ => return Err(Error::Invalid("security revalidation boundary")),
            }
        }
        if candidate.logical_ms < self.receipt.logical_ms {
            return Err(Error::Invalid("backwards logical time"));
        }
        let mut marks_bytes = Vec::new();
        encode_watermarks(&mut marks_bytes, &candidate.watermarks)?;
        for previous in &self.receipt.watermarks {
            let mark = candidate
                .watermarks
                .iter()
                .find(|m| m.player == previous.player);
            if previous.retired {
                if mark.is_some_and(|m| m != previous) {
                    return Err(Error::Invalid("retired watermark changed"));
                }
                continue;
            }
            let mark = mark.ok_or(Error::Invalid("forgotten active player watermark"))?;
            if mark.input < previous.input || mark.output_ack < previous.output_ack {
                return Err(Error::Invalid("watermark regression"));
            }
        }
        for mark in &candidate.watermarks {
            if self.retired.contains(&mark.player)
                && !self.receipt.watermarks.iter().any(|old| old == mark)
            {
                return Err(Error::Invalid("retired player ID reused"));
            }
        }
        let mut allocated = self.allocated.clone();
        for output in &candidate.outputs {
            let mark = candidate
                .watermarks
                .iter()
                .find(|m| m.player == output.recipient && !m.retired)
                .ok_or(Error::Invalid("output recipient"))?;
            let kind = match output.delivery {
                Delivery::Reliable => 0,
                Delivery::Lossy => 1,
            };
            let seq = allocated.entry((mark.player, kind)).or_default();
            if output.sequence != seq.checked_add(1).ok_or(Error::Bounds)? {
                return Err(Error::Invalid("output sequence allocation"));
            }
            *seq = output.sequence;
        }
        // ACKs can cover only previously allocated, already published records.
        for mark in &candidate.watermarks {
            if !self.retired.contains(&mark.player)
                && mark.output_ack > *self.allocated.get(&(mark.player, 0)).unwrap_or(&0)
            {
                return Err(Error::Invalid("future output ACK"));
            }
        }
        let state = state_hash(&candidate.image)?;
        let tree = tree(candidate.index, &candidate.outputs)?;
        Ok(Staged {
            session_bound: self.session_root.is_some(),
            context: self.context.clone(),
            candidate,
            state,
            tree,
            replay: false,
        })
    }
    fn check_base(&self, candidate: &Candidate) -> Result<()> {
        let term = u64::from(self.promotion.is_some());
        if candidate.term != term {
            return Err(Error::Closed);
        }
        if candidate.index != self.receipt.index.checked_add(1).ok_or(Error::Bounds)?
            || candidate.parent != self.receipt.digest(&self.context)?
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Atomically install and authorize outputs after all checks. Nothing in the
    /// actor changes on error. Reusing a stale staged token is always rejected.
    pub fn install(&mut self, staged: Staged, signer: &Keys) -> Result<Receipt> {
        if staged.context != self.context
            || staged.session_bound != self.session_root.is_some()
            || signer.public_key().to_bytes() != self.context.standby
        {
            return Err(Error::Unauthorized);
        }
        let candidate_digest = staged.candidate.digest(&self.context)?;
        if staged.candidate.index == self.receipt.index
            && self.last_candidate == Some(candidate_digest)
        {
            return Ok(self.receipt.clone());
        }
        if staged.replay {
            return Err(Error::Stale);
        }
        self.check_base(&staged.candidate)?;
        let c = staged.candidate;
        let mut receipt = Receipt {
            sequence: self.sender.reserve(2)?,
            term: c.term,
            index: c.index,
            parent: c.parent,
            state: staged.state,
            logical_ms: c.logical_ms,
            outputs_root: staged.tree.last().unwrap()[0],
            outputs_count: c.outputs.len() as u32,
            watermarks: c.watermarks,
            signature: [0; 64],
        };
        receipt.signature = sign(signer, receipt.signing_hash(&self.context)?);
        let mut outbox = self.outbox.clone();
        outbox.retain(|(player, sequence), _| {
            receipt
                .watermarks
                .iter()
                .find(|m| m.player == *player)
                .is_some_and(|m| !m.retired && m.output_ack < *sequence)
        });
        let mut allocated = self.allocated.clone();
        let mut retired = self.retired.clone();
        for mark in &receipt.watermarks {
            if mark.retired {
                retired.insert(mark.player);
            }
        }
        allocated.retain(|(player, _), _| !retired.contains(player));
        let mut publication = Vec::with_capacity(c.outputs.len());
        for (ordinal, output) in c.outputs.into_iter().enumerate() {
            let kind = match output.delivery {
                Delivery::Reliable => 0,
                Delivery::Lossy => 1,
            };
            allocated.insert((output.recipient, kind), output.sequence);
            let mut at = ordinal;
            let siblings = staged
                .tree
                .iter()
                .take(staged.tree.len() - 1)
                .map(|layer| {
                    let h = layer[at ^ 1];
                    at >>= 1;
                    h
                })
                .collect();
            let certified = CertifiedOutput {
                receipt: receipt.clone(),
                ordinal: ordinal as u32,
                output,
                siblings,
            };
            if certified.output.delivery == Delivery::Reliable {
                outbox.insert(
                    (certified.output.recipient, certified.output.sequence),
                    certified.clone(),
                );
            }
            publication.push(certified);
        }
        check_install_budget(
            &self.context,
            c.image.len(),
            &receipt,
            &outbox,
            &allocated,
            &retired,
        )?;
        let membership = if let Some(root) = &self.session_root {
            let image = SessionImage::decode(root, &c.image)?;
            Some(MembershipCertificate::issue(
                root,
                receipt.clone(),
                &image,
                signer,
            )?)
        } else {
            None
        };
        if let (Some(root), Some(certificate)) = (&self.session_root, &membership) {
            self.sender.replay.advance_membership(root, certificate)?;
        }
        self.membership = membership;
        self.retired = retired;
        self.last_candidate = Some(candidate_digest);
        self.publication = publication;
        self.image = c.image;
        self.outbox = outbox;
        self.allocated = allocated;
        self.receipt = receipt.clone();
        Ok(receipt)
    }
    pub fn stream_ceiling(&self, player: u64, delivery: Delivery) -> u64 {
        *self
            .allocated
            .get(&(player, u8::from(delivery == Delivery::Lossy)))
            .unwrap_or(&0)
    }
    pub fn output_ceiling(&self, player: u64) -> u64 {
        *self.allocated.get(&(player, 0)).unwrap_or(&0)
    }
    /// Close once, without a lease. Late original-host candidates cannot commit.
    pub fn promote(&mut self, signer: &Keys) -> Result<Promotion> {
        if signer.public_key().to_bytes() != self.context.standby {
            return Err(Error::Unauthorized);
        }
        if let Some(p) = &self.promotion {
            return Ok(p.clone());
        }
        let mut p = Promotion {
            sequence: self.sender.allocate()?,
            final_receipt: self.receipt.clone(),
            signature: [0; 64],
        };
        p.signature = sign(signer, p.digest(&self.context)?);
        self.promotion = Some(p.clone());
        Ok(p)
    }
}

/// Exact byte replacement, never native game re-simulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub base: Hash,
    pub target: Hash,
    pub prefix: u32,
    pub remove: u32,
    pub insert: Vec<u8>,
    pub target_len: u32,
}
impl Patch {
    pub fn between(base: &[u8], target: &[u8]) -> Result<Self> {
        let base_hash = state_hash(base)?;
        let target_hash = state_hash(target)?;
        let prefix = base.iter().zip(target).take_while(|(a, b)| a == b).count();
        let suffix = base[prefix..]
            .iter()
            .rev()
            .zip(target[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let replacement = &target[prefix..target.len() - suffix];
        if replacement.len() > MAX_PATCH {
            return Err(Error::Bounds);
        }
        let insert = replacement.to_vec();
        Ok(Self {
            base: base_hash,
            target: target_hash,
            prefix: prefix as u32,
            remove: (base.len() - prefix - suffix) as u32,
            insert,
            target_len: target.len() as u32,
        })
    }
    pub fn apply(&self, base: &[u8]) -> Result<Vec<u8>> {
        if self.insert.len() > MAX_PATCH
            || self.target_len as usize > MAX_IMAGE
            || self.base != state_hash(base)?
        {
            return Err(Error::Invalid("patch base/bounds"));
        }
        let prefix = self.prefix as usize;
        let end = prefix
            .checked_add(self.remove as usize)
            .ok_or(Error::Bounds)?;
        if end > base.len() {
            return Err(Error::Bounds);
        }
        let len = prefix
            .checked_add(self.insert.len())
            .and_then(|n| n.checked_add(base.len() - end))
            .ok_or(Error::Bounds)?;
        if len != self.target_len as usize {
            return Err(Error::Invalid("patch length"));
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend(&base[..prefix]);
        bytes.extend(&self.insert);
        bytes.extend(&base[end..]);
        if state_hash(&bytes)? != self.target {
            return Err(Error::Invalid("patch target"));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BytePatchOp {
    Copy { offset: u32, length: u32 },
    Insert(Vec<u8>),
}
/// Bounded exact byte patch for complete canonical images with several changed
/// regions or shifted vectors. Copy operations refer only to the immutable
/// base image; no native input, simulation or prior patch is replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytePatch {
    pub base: Hash,
    pub target: Hash,
    pub target_len: u32,
    operations: Vec<BytePatchOp>,
}
impl BytePatch {
    const HEADER: usize = 5 + 32 + 32 + 4 + 4;
    const MAX_OPERATIONS: usize = 4096;
    const BLOCK: usize = 32;
    fn fingerprint(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0u64, |hash, byte| {
            hash.wrapping_mul(257).wrapping_add(u64::from(*byte))
        })
    }
    fn append(
        operations: &mut Vec<BytePatchOp>,
        size: &mut usize,
        operation: BytePatchOp,
    ) -> Result<()> {
        let added = match &operation {
            BytePatchOp::Copy { .. } => 9,
            BytePatchOp::Insert(bytes) => 5usize.checked_add(bytes.len()).ok_or(Error::Bounds)?,
        };
        let next = size.checked_add(added).ok_or(Error::Bounds)?;
        if operations.len() >= Self::MAX_OPERATIONS || next > MAX_PATCH {
            return Err(Error::Bounds);
        }
        *size = next;
        operations.push(operation);
        Ok(())
    }
    pub fn between(base: &[u8], target: &[u8]) -> Result<Self> {
        let base_hash = state_hash(base)?;
        let target_hash = state_hash(target)?;
        // Stable anchor offsets and first-match selection make the patch
        // independent of allocation order. Fingerprints are only a lookup
        // accelerator: exact bytes and the final cryptographic hash decide.
        let mut anchors = BTreeMap::new();
        if base.len() >= Self::BLOCK {
            for offset in (0..=base.len() - Self::BLOCK).step_by(Self::BLOCK) {
                anchors
                    .entry(Self::fingerprint(&base[offset..offset + Self::BLOCK]))
                    .or_insert(offset);
            }
        }
        let power = (1..Self::BLOCK).fold(1u64, |value, _| value.wrapping_mul(257));
        let mut cursor = 0usize;
        let mut literal = 0usize;
        let mut rolling = None;
        let mut operations = Vec::new();
        let mut size = Self::HEADER;
        while cursor < target.len() {
            let available = target.len() - cursor;
            let mut matched = None;
            if available >= Self::BLOCK {
                let fingerprint = *rolling.get_or_insert_with(|| {
                    Self::fingerprint(&target[cursor..cursor + Self::BLOCK])
                });
                if let Some(&offset) = anchors.get(&fingerprint) {
                    if base[offset..offset + Self::BLOCK] == target[cursor..cursor + Self::BLOCK] {
                        let mut length = Self::BLOCK;
                        while offset + length < base.len()
                            && cursor + length < target.len()
                            && base[offset + length] == target[cursor + length]
                        {
                            length += 1;
                        }
                        matched = Some((offset, length));
                    }
                }
            }
            if let Some((offset, length)) = matched {
                if literal < cursor {
                    Self::append(
                        &mut operations,
                        &mut size,
                        BytePatchOp::Insert(target[literal..cursor].to_vec()),
                    )?;
                }
                Self::append(
                    &mut operations,
                    &mut size,
                    BytePatchOp::Copy {
                        offset: offset as u32,
                        length: length as u32,
                    },
                )?;
                cursor += length;
                literal = cursor;
                rolling = None;
            } else {
                if cursor - literal >= MAX_PATCH - size.saturating_add(5).min(MAX_PATCH) {
                    return Err(Error::Bounds);
                }
                rolling = if available > Self::BLOCK {
                    rolling.map(|value| {
                        value
                            .wrapping_sub(u64::from(target[cursor]).wrapping_mul(power))
                            .wrapping_mul(257)
                            .wrapping_add(u64::from(target[cursor + Self::BLOCK]))
                    })
                } else {
                    None
                };
                cursor += 1;
            }
        }
        if literal < target.len() {
            Self::append(
                &mut operations,
                &mut size,
                BytePatchOp::Insert(target[literal..].to_vec()),
            )?;
        }
        let patch = Self {
            base: base_hash,
            target: target_hash,
            target_len: target.len() as u32,
            operations,
        };
        patch.encoded_len()?;
        Ok(patch)
    }
    pub fn encoded_len(&self) -> Result<usize> {
        if self.target_len as usize > MAX_IMAGE || self.operations.len() > Self::MAX_OPERATIONS {
            return Err(Error::Bounds);
        }
        let mut size = Self::HEADER;
        let mut produced = 0usize;
        for operation in &self.operations {
            let (length, added) = match operation {
                BytePatchOp::Copy { offset, length } => {
                    let length = *length as usize;
                    if length == 0
                        || (*offset as usize)
                            .checked_add(length)
                            .is_none_or(|end| end > MAX_IMAGE)
                    {
                        return Err(Error::Bounds);
                    }
                    (length, 9)
                }
                BytePatchOp::Insert(bytes) => {
                    if bytes.is_empty() {
                        return Err(Error::Invalid("empty patch literal"));
                    }
                    (
                        bytes.len(),
                        5usize.checked_add(bytes.len()).ok_or(Error::Bounds)?,
                    )
                }
            };
            size = size.checked_add(added).ok_or(Error::Bounds)?;
            produced = produced.checked_add(length).ok_or(Error::Bounds)?;
            if size > MAX_PATCH || produced > self.target_len as usize {
                return Err(Error::Bounds);
            }
        }
        if produced != self.target_len as usize {
            return Err(Error::Invalid("byte patch target length"));
        }
        Ok(size)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        bytes.extend(b"FRYP\x01");
        bytes.extend(self.base);
        bytes.extend(self.target);
        bytes.extend(self.target_len.to_be_bytes());
        put_u32(&mut bytes, self.operations.len())?;
        for operation in &self.operations {
            match operation {
                BytePatchOp::Copy { offset, length } => {
                    bytes.push(0);
                    bytes.extend(offset.to_be_bytes());
                    bytes.extend(length.to_be_bytes());
                }
                BytePatchOp::Insert(insert) => {
                    bytes.push(1);
                    put_bytes(&mut bytes, insert, MAX_PATCH)?;
                }
            }
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PATCH {
            return Err(Error::Bounds);
        }
        let mut reader = Reader(bytes);
        if reader.take(5)? != b"FRYP\x01" {
            return Err(Error::Invalid("byte patch version"));
        }
        let base = reader.array()?;
        let target = reader.array()?;
        let target_len = u32::try_from(reader.u32()?).map_err(|_| Error::Bounds)?;
        let count = reader.u32()?;
        if target_len as usize > MAX_IMAGE || count > Self::MAX_OPERATIONS {
            return Err(Error::Bounds);
        }
        let mut operations = Vec::with_capacity(count);
        for _ in 0..count {
            operations.push(match reader.u8()? {
                0 => BytePatchOp::Copy {
                    offset: u32::try_from(reader.u32()?).map_err(|_| Error::Bounds)?,
                    length: u32::try_from(reader.u32()?).map_err(|_| Error::Bounds)?,
                },
                1 => BytePatchOp::Insert(reader.bytes(MAX_PATCH)?),
                _ => return Err(Error::Invalid("byte patch operation")),
            });
        }
        reader.finish()?;
        let patch = Self {
            base,
            target,
            target_len,
            operations,
        };
        patch.encoded_len()?;
        Ok(patch)
    }
    pub fn apply(&self, base: &[u8]) -> Result<Vec<u8>> {
        self.encoded_len()?;
        if state_hash(base)? != self.base {
            return Err(Error::Invalid("byte patch base"));
        }
        let mut target = Vec::with_capacity(self.target_len as usize);
        for operation in &self.operations {
            match operation {
                BytePatchOp::Copy { offset, length } => {
                    let start = *offset as usize;
                    let end = start.checked_add(*length as usize).ok_or(Error::Bounds)?;
                    target.extend(base.get(start..end).ok_or(Error::Bounds)?);
                }
                BytePatchOp::Insert(bytes) => target.extend(bytes),
            }
        }
        if state_hash(&target)? != self.target {
            return Err(Error::Invalid("byte patch target"));
        }
        Ok(target)
    }
}

/// The same native candidate carried as an exact patch against the last
/// committed image. The expanded Candidate, not this wire representation, is
/// validated and committed by the sole sequencer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateDelta {
    pub sequence: u64,
    pub term: u64,
    pub index: u64,
    pub parent: Hash,
    pub logical_ms: u64,
    pub patch: BytePatch,
    pub watermarks: Vec<Watermark>,
    pub outputs: Vec<Output>,
}
impl CandidateDelta {
    pub fn between(base: &[u8], candidate: &Candidate) -> Result<Self> {
        Ok(Self {
            sequence: candidate.sequence,
            term: candidate.term,
            index: candidate.index,
            parent: candidate.parent,
            logical_ms: candidate.logical_ms,
            patch: BytePatch::between(base, &candidate.image)?,
            watermarks: candidate.watermarks.clone(),
            outputs: candidate.outputs.clone(),
        })
    }
    pub fn expand(&self, base: &[u8]) -> Result<Candidate> {
        Ok(Candidate {
            sequence: self.sequence,
            term: self.term,
            index: self.index,
            parent: self.parent,
            logical_ms: self.logical_ms,
            image: self.patch.apply(base)?,
            watermarks: self.watermarks.clone(),
            outputs: self.outputs.clone(),
        })
    }
    pub fn encode(&self, context: &Context) -> Result<Vec<u8>> {
        if self.sequence == 0 || self.term > 1 || self.index == 0 || self.outputs.len() > MAX_BATCH
        {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(context, self.term, 18, self.sequence);
        bytes.extend(self.index.to_be_bytes());
        bytes.extend(self.parent);
        bytes.extend(self.logical_ms.to_be_bytes());
        put_bytes(&mut bytes, &self.patch.encode()?, MAX_PATCH)?;
        encode_watermarks(&mut bytes, &self.watermarks)?;
        put_u32(&mut bytes, self.outputs.len())?;
        for output in &self.outputs {
            output.encode(&mut bytes)?;
        }
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }
    pub fn decode(context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        let mut reader = Reader(bytes);
        context.read_binding(&mut reader)?;
        let term = reader.u64()?;
        if reader.u8()? != 18 {
            return Err(Error::Invalid("delta candidate kind"));
        }
        let sequence = reader.u64()?;
        let index = reader.u64()?;
        if sequence == 0 || term > 1 || index == 0 {
            return Err(Error::Bounds);
        }
        let parent = reader.array()?;
        let logical_ms = reader.u64()?;
        let patch = BytePatch::decode(&reader.bytes(MAX_PATCH)?)?;
        let watermarks = read_watermarks(&mut reader)?;
        let count = reader.u32()?;
        if count > MAX_BATCH {
            return Err(Error::Bounds);
        }
        let outputs = (0..count)
            .map(|_| Output::decode(&mut reader))
            .collect::<Result<Vec<_>>>()?;
        reader.finish()?;
        Ok(Self {
            sequence,
            term,
            index,
            parent,
            logical_ms,
            patch,
            watermarks,
            outputs,
        })
    }
}

/// A receiver keeps a complete committed image while assembling one replacement.
/// The manifest is checked before reserving any attacker-specified memory.
pub struct Transfer {
    pub session: SessionId,
    pub term: u64,
    pub index: u64,
    expected_hash: Hash,
    length: usize,
    buffer: Vec<u8>,
    received: Vec<bool>,
}
impl Transfer {
    pub fn begin(
        session: SessionId,
        term: u64,
        index: u64,
        length: usize,
        count: usize,
        expected_hash: Hash,
    ) -> Result<Self> {
        if length > MAX_IMAGE
            || count != length.div_ceil(CHUNK_PAYLOAD)
            || session == [0; 16]
            || term > 1
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            session,
            term,
            index,
            expected_hash,
            length,
            buffer: vec![0; length],
            received: vec![false; count],
        })
    }
    pub fn chunk(
        &mut self,
        session: SessionId,
        term: u64,
        index: u64,
        ordinal: usize,
        bytes: &[u8],
    ) -> Result<()> {
        if session != self.session || term != self.term || index != self.index {
            return Err(Error::Invalid("mixed transfer"));
        }
        if ordinal >= self.received.len() {
            return Err(Error::Bounds);
        }
        let expected = (self.length - ordinal * CHUNK_PAYLOAD).min(CHUNK_PAYLOAD);
        if bytes.len() != expected {
            return Err(Error::Invalid("chunk length"));
        }
        let start = ordinal * CHUNK_PAYLOAD;
        if self.received[ordinal] {
            return if &self.buffer[start..start + expected] == bytes {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.buffer[start..start + expected].copy_from_slice(bytes);
        self.received[ordinal] = true;
        Ok(())
    }
    pub fn finish(self) -> Result<Vec<u8>> {
        if self.received.iter().any(|received| !received) {
            return Err(Error::Gap);
        }
        if state_hash(&self.buffer)? != self.expected_hash {
            return Err(Error::Invalid("transfer digest"));
        }
        Ok(self.buffer)
    }
}

/// Reliable intent storage. Reserve a complete producer batch before simulation
/// mutates; commit/drain watermarks, not transport ACKs, release its capacity.
pub struct IntentJournal {
    next: u64,
    acknowledged: u64,
    bytes: usize,
    entries: VecDeque<(u64, Vec<u8>)>,
}
impl Default for IntentJournal {
    fn default() -> Self {
        Self {
            next: 1,
            acknowledged: 0,
            bytes: 0,
            entries: VecDeque::new(),
        }
    }
}
impl IntentJournal {
    /// Bounded canonical runner state; inclusion in a committed game image
    /// binds original local/bot payloads without serializing a transport.
    pub fn checkpoint(&self) -> Result<Vec<u8>> {
        if self.next == 0
            || self.acknowledged >= self.next
            || self.entries.len() > MAX_JOURNAL_RECORDS
            || self.bytes > MAX_JOURNAL_BYTES
        {
            return Err(Error::Bounds);
        }
        let mut bytes = b"FRYJI\x01".to_vec();
        bytes.extend(self.next.to_be_bytes());
        bytes.extend(self.acknowledged.to_be_bytes());
        put_u32(&mut bytes, self.entries.len())?;
        let mut next = self.acknowledged.checked_add(1).ok_or(Error::Bounds)?;
        let mut size = 0usize;
        for (sequence, payload) in &self.entries {
            if *sequence != next {
                return Err(Error::Gap);
            }
            next = next.checked_add(1).ok_or(Error::Bounds)?;
            bytes.extend(sequence.to_be_bytes());
            put_bytes(&mut bytes, payload, crate::MAX_RELIABLE_LEN)?;
            size = size.checked_add(payload.len()).ok_or(Error::Bounds)?;
        }
        if next != self.next || size != self.bytes {
            return Err(Error::Conflict);
        }
        Ok(bytes)
    }
    pub fn restore(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_JOURNAL_BYTES + MAX_JOURNAL_RECORDS * 12 + 26 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        if r.take(6)? != b"FRYJI\x01" {
            return Err(Error::Invalid("intent journal version"));
        }
        let next = r.u64()?;
        let acknowledged = r.u64()?;
        let count = r.u32()?;
        if count > MAX_JOURNAL_RECORDS {
            return Err(Error::Bounds);
        }
        let mut entries = VecDeque::new();
        let mut size = 0usize;
        for _ in 0..count {
            let sequence = r.u64()?;
            let payload = r.bytes(crate::MAX_RELIABLE_LEN)?;
            size = size.checked_add(payload.len()).ok_or(Error::Bounds)?;
            if size > MAX_JOURNAL_BYTES {
                return Err(Error::Bounds);
            }
            entries.push_back((sequence, payload));
        }
        r.finish()?;
        let journal = Self {
            next,
            acknowledged,
            bytes: size,
            entries,
        };
        if journal.checkpoint()? != bytes {
            return Err(Error::Conflict);
        }
        Ok(journal)
    }
    pub fn can_reserve(&self, records: usize, bytes: usize) -> bool {
        u64::try_from(records)
            .ok()
            .and_then(|n| self.next.checked_add(n))
            .is_some()
            && self
                .entries
                .len()
                .checked_add(records)
                .is_some_and(|n| n <= MAX_JOURNAL_RECORDS)
            && self
                .bytes
                .checked_add(bytes)
                .is_some_and(|n| n <= MAX_JOURNAL_BYTES)
    }
    /// Atomically journal the whole batch, returning its original sequence range.
    pub fn append_batch(&mut self, entries: &[Vec<u8>]) -> Result<Vec<u64>> {
        let bytes = entries.iter().try_fold(0usize, |n, b| {
            if b.len() > crate::MAX_RELIABLE_LEN {
                return Err(Error::Bounds);
            }
            n.checked_add(b.len()).ok_or(Error::Bounds)
        })?;
        if !self.can_reserve(entries.len(), bytes)
            || self.next.checked_add(entries.len() as u64).is_none()
        {
            return Err(Error::Bounds);
        }
        let mut ids = Vec::with_capacity(entries.len());
        for bytes in entries {
            ids.push(self.next);
            self.entries.push_back((self.next, bytes.clone()));
            self.bytes += bytes.len();
            self.next += 1;
        }
        Ok(ids)
    }
    pub fn acknowledge(&mut self, handled: u64) -> Result<()> {
        if handled < self.acknowledged || handled >= self.next {
            return Err(Error::Invalid("intent ACK"));
        }
        self.acknowledged = handled;
        while self.entries.front().is_some_and(|(n, _)| *n <= handled) {
            self.bytes -= self.entries.pop_front().unwrap().1.len();
        }
        Ok(())
    }
    pub fn pending(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.entries.iter().map(|(n, b)| (*n, b.as_slice()))
    }
    pub fn tail(&self) -> u64 {
        self.next - 1
    }
    pub fn acknowledged(&self) -> u64 {
        self.acknowledged
    }
}

/// Application delivery cursor retained when replacing the transport. State
/// advances only after the application's whole effect callback succeeds.
#[derive(Default)]
pub struct DeliveryJournal {
    applied: u64,
    poisoned: bool,
    recent: VecDeque<(u64, Hash)>,
}
impl DeliveryJournal {
    pub fn checkpoint(&self) -> Result<Vec<u8>> {
        if self.poisoned {
            return Err(Error::Closed);
        }
        let count = usize::try_from(self.applied.min(MAX_JOURNAL_RECORDS as u64))
            .map_err(|_| Error::Bounds)?;
        if self.recent.len() != count {
            return Err(Error::Gap);
        }
        let mut bytes = b"FRYJD\x01".to_vec();
        bytes.extend(self.applied.to_be_bytes());
        put_u32(&mut bytes, count)?;
        let start = self
            .applied
            .checked_sub(count as u64)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Bounds)?;
        for (i, (sequence, digest)) in self.recent.iter().enumerate() {
            if *sequence != start + i as u64 {
                return Err(Error::Gap);
            }
            bytes.extend(sequence.to_be_bytes());
            bytes.extend(digest);
        }
        Ok(bytes)
    }
    pub fn restore(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 18 + MAX_JOURNAL_RECORDS * 40 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        if r.take(6)? != b"FRYJD\x01" {
            return Err(Error::Invalid("delivery journal version"));
        }
        let applied = r.u64()?;
        let count = r.u32()?;
        if count > MAX_JOURNAL_RECORDS {
            return Err(Error::Bounds);
        }
        let mut recent = VecDeque::new();
        for _ in 0..count {
            recent.push_back((r.u64()?, r.array()?));
        }
        r.finish()?;
        let journal = Self {
            applied,
            poisoned: false,
            recent,
        };
        if journal.checkpoint()? != bytes {
            return Err(Error::Conflict);
        }
        Ok(journal)
    }
    pub fn apply_certified(
        &mut self,
        context: &Context,
        player: u64,
        record: &CertifiedOutput,
        effect: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<bool> {
        record.verify(context)?;
        if record.output.recipient != player || record.output.delivery != Delivery::Reliable {
            return Err(Error::Unauthorized);
        }
        self.apply(record.output.sequence, &record.output.bytes, effect)
    }
    pub fn applied(&self) -> u64 {
        self.applied
    }
    pub fn apply(
        &mut self,
        sequence: u64,
        bytes: &[u8],
        effect: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(Error::Closed);
        }
        if sequence == 0 || bytes.len() > crate::MAX_RELIABLE_LEN {
            return Err(Error::Bounds);
        }
        let digest = hash(b"fray/migration/delivery/v1\0", bytes);
        if sequence <= self.applied {
            if self
                .recent
                .iter()
                .any(|(n, h)| *n == sequence && *h != digest)
            {
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
        if sequence != self.applied.checked_add(1).ok_or(Error::Bounds)? {
            return Err(Error::Gap);
        }
        // The callback may mutate before returning an error or unwinding. That
        // cannot be rolled back by this generic journal: never retry it.
        self.poisoned = true;
        effect(bytes)?;
        self.applied = sequence;
        self.recent.push_back((sequence, digest));
        if self.recent.len() > MAX_JOURNAL_RECORDS {
            self.recent.pop_front();
        }
        self.poisoned = false;
        Ok(true)
    }
}

/// Session packet classes, separate from the games' own protocol versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    Candidate = 0,
    Receipt = 1,
    Output = 2,
    Control = 3,
    InitialImage = 4,
    Delta = 5,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateManifest {
    pub descriptor: Hash,
    pub schema: u32,
    pub index: u64,
    pub base: Hash,
    pub target: Hash,
}
/// One bounded frame; its transfer ID is the transport-envelope sender sequence.
/// Fray's authenticated connection supplies origin/role; hashes alone do not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub candidate: Option<CandidateManifest>,
    pub session: SessionId,
    pub term: u64,
    pub transfer: u64,
    pub kind: PacketKind,
    pub length: u32,
    pub count: u32,
    pub ordinal: u32,
    pub digest: Hash,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn split(
        session: SessionId,
        term: u64,
        transfer: u64,
        kind: PacketKind,
        bytes: &[u8],
    ) -> Result<Vec<Self>> {
        if bytes.is_empty()
            || bytes.len() > MAX_IMAGE
            || session == [0; 16]
            || term > 1
            || transfer == 0
        {
            return Err(Error::Bounds);
        }
        let digest = state_hash(bytes)?;
        let count = bytes.len().div_ceil(CHUNK_PAYLOAD) as u32;
        Ok(bytes
            .chunks(CHUNK_PAYLOAD)
            .enumerate()
            .map(|(i, payload)| Self {
                candidate: None,
                session,
                term,
                transfer,
                kind,
                length: bytes.len() as u32,
                count,
                ordinal: i as u32,
                digest,
                payload: payload.to_vec(),
            })
            .collect())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = b"FRYM".to_vec();
        out.push(VERSION);
        out.extend(self.session);
        out.extend(self.term.to_be_bytes());
        out.extend(self.transfer.to_be_bytes());
        out.push(self.kind as u8);
        out.extend(self.length.to_be_bytes());
        out.extend(self.count.to_be_bytes());
        out.extend(self.ordinal.to_be_bytes());
        out.extend(self.digest);
        match &self.candidate {
            None => out.push(0),
            Some(m) => {
                out.push(1);
                out.extend(m.descriptor);
                out.extend(m.schema.to_be_bytes());
                out.extend(m.index.to_be_bytes());
                out.extend(m.base);
                out.extend(m.target);
            }
        }
        put_bytes(&mut out, &self.payload, CHUNK_PAYLOAD)?;
        if out.len() > crate::MAX_RELIABLE_LEN {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::MAX_RELIABLE_LEN {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        if r.take(4)? != b"FRYM" || r.u8()? != VERSION {
            return Err(Error::Invalid("frame version/magic"));
        }
        let session = r.array()?;
        let term = r.u64()?;
        let transfer = r.u64()?;
        let kind = match r.u8()? {
            0 => PacketKind::Candidate,
            1 => PacketKind::Receipt,
            2 => PacketKind::Output,
            3 => PacketKind::Control,
            4 => PacketKind::InitialImage,
            5 => PacketKind::Delta,
            _ => return Err(Error::Invalid("packet kind")),
        };
        let length = u32::try_from(r.u32()?).map_err(|_| Error::Bounds)?;
        let count = u32::try_from(r.u32()?).map_err(|_| Error::Bounds)?;
        let ordinal = u32::try_from(r.u32()?).map_err(|_| Error::Bounds)?;
        let digest = r.array()?;
        let candidate = match r.u8()? {
            0 => None,
            1 => Some(CandidateManifest {
                descriptor: r.array()?,
                schema: u32::from_be_bytes(r.array()?),
                index: r.u64()?,
                base: r.array()?,
                target: r.array()?,
            }),
            _ => return Err(Error::Invalid("candidate manifest option")),
        };
        let payload = r.bytes(CHUNK_PAYLOAD)?;
        r.finish()?;
        let frame = Self {
            candidate,
            session,
            term,
            transfer,
            kind,
            length,
            count,
            ordinal,
            digest,
            payload,
        };
        frame.validate()?;
        Ok(frame)
    }
    fn validate(&self) -> Result<()> {
        if let Some(m) = &self.candidate {
            if !matches!(self.kind, PacketKind::Candidate | PacketKind::Delta)
                || m.descriptor == [0; 32]
                || m.schema == 0
                || m.index == 0
                || m.base == [0; 32]
            {
                return Err(Error::Invalid("candidate manifest fields"));
            }
        }
        let length = self.length as usize;
        let count = self.count as usize;
        let ordinal = self.ordinal as usize;
        if self.session == [0; 16]
            || self.term > 1
            || self.transfer == 0
            || length == 0
            || length > MAX_IMAGE
            || count != length.div_ceil(CHUNK_PAYLOAD)
            || ordinal >= count
        {
            return Err(Error::Bounds);
        }
        let expected = (length - ordinal * CHUNK_PAYLOAD).min(CHUNK_PAYLOAD);
        if self.payload.len() != expected {
            return Err(Error::Invalid("frame length"));
        }
        Ok(())
    }
}
struct PendingTransfer {
    candidate: Option<CandidateManifest>,
    kind: PacketKind,
    transfer: Transfer,
    started_ms: u64,
    count: u32,
    digest: Hash,
}
/// Bounded reassembly on one authenticated peer link. Poll timeouts even during
/// idle periods; a completed transfer is checked before its message is exposed.
pub struct PacketReceiver {
    session: SessionId,
    term: u64,
    pending: BTreeMap<u64, PendingTransfer>,
    queued_bytes: usize,
    completed: VecDeque<(u64, PacketKind, Hash, u32, u32, Option<CandidateManifest>)>,
    highest: u64,
    late_chunks: u64,
}
impl PacketReceiver {
    pub fn new(session: SessionId, term: u64) -> Result<Self> {
        if session == [0; 16] || term > 1 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            session,
            term,
            pending: BTreeMap::new(),
            queued_bytes: 0,
            completed: VecDeque::new(),
            highest: 0,
            late_chunks: 0,
        })
    }
    pub fn advance_term(&mut self, term: u64) -> Result<()> {
        if term != self.term + 1 || term > 1 {
            return Err(Error::Closed);
        }
        self.term = term;
        self.pending.clear();
        self.queued_bytes = 0;
        self.completed.clear();
        self.highest = 0;
        Ok(())
    }
    /// Drop every part-received transfer at least 500 ms old (or started in
    /// the future), and return their ids. Live partials are kept.
    fn drop_expired(&mut self, now_ms: u64) -> Vec<u64> {
        let mut dropped = Vec::new();
        let mut freed = 0;
        self.pending.retain(|id, p| {
            let expired = now_ms
                .checked_sub(p.started_ms)
                .is_none_or(|age| age >= 500);
            if expired {
                dropped.push(*id);
                freed += p.transfer.length;
            }
            !expired
        });
        self.queued_bytes -= freed;
        dropped
    }
    /// Drop expired partial transfers; `Stale` reports that any were dropped.
    pub fn expire(&mut self, now_ms: u64) -> Result<()> {
        if self.drop_expired(now_ms).is_empty() {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    /// Chunks ignored because their transfer was dropped as expired by the
    /// same call that received them (see [`Self::receive`]).
    pub fn late_chunks(&self) -> u64 {
        self.late_chunks
    }
    /// Expired partial transfers are dropped first. A chunk of a transfer
    /// just dropped is late but harmless: it is ignored (`Ok(None)`), counted
    /// in [`Self::late_chunks`] and never assembled. Any other valid frame is
    /// processed normally.
    pub fn receive(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<Option<(PacketKind, u64, Vec<u8>)>> {
        let expired = self.drop_expired(now_ms);
        let frame = Frame::decode(bytes)?;
        if frame.session != self.session || frame.term != self.term {
            return Err(Error::Invalid("frame session/term"));
        }
        if expired.contains(&frame.transfer) {
            self.late_chunks = self.late_chunks.saturating_add(1);
            return Ok(None);
        }
        if let Some((_, kind, digest, length, count, candidate)) =
            self.completed.iter().find(|(id, ..)| *id == frame.transfer)
        {
            return if (*kind, *digest, *length, *count)
                == (frame.kind, frame.digest, frame.length, frame.count)
                && *candidate == frame.candidate
            {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        if frame.transfer <= self.highest.saturating_sub(MAX_JOURNAL_RECORDS as u64) {
            return Ok(None);
        }
        if !self.pending.contains_key(&frame.transfer) {
            if self.pending.len() >= 8
                || self
                    .queued_bytes
                    .checked_add(frame.length as usize)
                    .ok_or(Error::Bounds)?
                    > 2 * MAX_IMAGE
            {
                return Err(Error::Bounds);
            }
            let transfer = Transfer::begin(
                frame.session,
                frame.term,
                frame.transfer,
                frame.length as usize,
                frame.count as usize,
                frame.digest,
            )?;
            self.queued_bytes += frame.length as usize;
            self.pending.insert(
                frame.transfer,
                PendingTransfer {
                    candidate: frame.candidate.clone(),
                    kind: frame.kind,
                    transfer,
                    started_ms: now_ms,
                    count: frame.count,
                    digest: frame.digest,
                },
            );
        }
        let pending = self.pending.get_mut(&frame.transfer).unwrap();
        if pending.kind != frame.kind
            || pending.candidate != frame.candidate
            || pending.count != frame.count
            || pending.digest != frame.digest
            || pending.transfer.length != frame.length as usize
        {
            return Err(Error::Conflict);
        }
        pending.transfer.chunk(
            frame.session,
            frame.term,
            frame.transfer,
            frame.ordinal as usize,
            &frame.payload,
        )?;
        if pending.transfer.received.iter().all(|done| *done) {
            let complete = self.pending.remove(&frame.transfer).unwrap();
            self.queued_bytes -= complete.transfer.length;
            let length = complete.transfer.length as u32;
            let payload = complete.transfer.finish()?;
            self.highest = self.highest.max(frame.transfer);
            self.completed.push_back((
                frame.transfer,
                complete.kind,
                complete.digest,
                length,
                complete.count,
                complete.candidate,
            ));
            if self.completed.len() > MAX_JOURNAL_RECORDS {
                self.completed.pop_front();
            }
            return Ok(Some((complete.kind, frame.transfer, payload)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod reservation_exhaustion_tests {
    use super::*;
    #[test]
    fn reservation_refuses_sequence_overflow_before_simulation_can_mutate() {
        let mut journal = IntentJournal::default();
        journal.next = u64::MAX;
        assert!(!journal.can_reserve(1, 1));
        assert_eq!(journal.append_batch(&[vec![1]]), Err(Error::Bounds));
        assert_eq!(journal.next, u64::MAX);
        assert!(journal.entries.is_empty());
    }
}

/// Original host's publication gate. A single speculative candidate can be
/// retried, but cannot produce application effects without its exact receipt.
pub struct Primary {
    sender: SenderSequence,
    initial_player_routes: BTreeSet<u64>,
    publication_term: u64,
    recovery_elapsed_ms: u64,
    outbox: BTreeMap<(u64, u64), CertifiedOutput>,
    allocated: BTreeMap<(u64, u8), u64>,
    adopted: u64,
    context: Context,
    receipt: Receipt,
    committed: Vec<u8>,
    pending: Option<Candidate>,
    closed: bool,
    membership: Option<MembershipCertificate>,
}
impl Primary {
    /// Claim the one initial route for an armed human. Only this owned initial
    /// authority grants that capability; replacing a claimed route requires
    /// its retained PlayerQueue and the fresh reconnect journal challenge.
    pub fn attach_player(
        &mut self,
        channel: &Channel,
        membership: MembershipCertificate,
    ) -> Result<PlayerQueue> {
        let player = channel.authenticated_player.ok_or(Error::Unauthorized)?;
        if self.publication_term != 0
            || self.initial_player_routes.contains(&player)
            || !channel
                .descriptor
                .root
                .members
                .iter()
                .any(|member| member.player == player && member.key.is_some())
        {
            return Err(Error::Unauthorized);
        }
        let queue = PlayerQueue::from_channel(channel, membership, self)?;
        self.initial_player_routes.insert(player);
        Ok(queue)
    }
    /// Retain proof-carrying original outputs until their application ACK is
    /// committed. A replacement player transport replays this same bounded log.
    pub fn outbox(&self) -> impl Iterator<Item = &CertifiedOutput> {
        self.outbox.values()
    }
    /// Security age since the last committed game-clock advance, including
    /// failure detection and the final barrier. On the first successor
    /// batch the game must adopt this security-clock offset before processing
    /// any input, while advancing simulation only by the normal logical dt.
    pub fn recovery_elapsed_ms(&self) -> u64 {
        self.recovery_elapsed_ms
    }
    pub fn sender_sequence(&self) -> SenderSequence {
        self.sender.clone()
    }
    pub fn output_ceiling(&self, player: u64, delivery: Delivery) -> u64 {
        *self
            .allocated
            .get(&(player, u8::from(delivery == Delivery::Lossy)))
            .unwrap_or(&0)
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// One game/UI adoption for the exact current receipt. The runner restores
    /// and validates its staged game before consuming this publication slot.
    pub fn claim_adoption(&mut self, receipt: &Receipt) -> Result<()> {
        if self.closed {
            return Err(Error::Closed);
        }
        if receipt != &self.receipt || receipt.index <= self.adopted {
            return Err(Error::Stale);
        }
        self.adopted = receipt.index;
        Ok(())
    }
    pub fn armed(context: Context, image: Vec<u8>, receipt: Receipt) -> Result<Self> {
        receipt.verify(&context)?;
        if receipt.index != 0
            || receipt.term != 0
            || receipt.parent != [0; 32]
            || receipt.outputs_count != 0
            || receipt.state != state_hash(&image)?
        {
            return Err(Error::Invalid("initial primary checkpoint"));
        }
        Ok(Self {
            sender: SenderSequence::starting(context.clone(), context.host, 1)?,
            initial_player_routes: BTreeSet::new(),
            publication_term: 0,
            recovery_elapsed_ms: 0,
            outbox: BTreeMap::new(),
            allocated: BTreeMap::new(),
            adopted: 0,
            context,
            receipt,
            committed: image,
            pending: None,
            closed: false,
            membership: None,
        })
    }
    pub fn committed_image(&self) -> &[u8] {
        &self.committed
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// The newest standby-signed membership certificate received over the
    /// pair link, verified against an installed receipt and its image. It may
    /// trail [`Self::receipt`] until the certificate following that receipt
    /// arrives; callers needing the current frontier compare the receipts.
    pub fn membership_certificate(&self) -> Option<&MembershipCertificate> {
        self.membership.as_ref()
    }
    pub fn pending(&self) -> Option<&Candidate> {
        self.pending.as_ref()
    }
    /// Caller has already staged all game effects, including its local loopback
    /// and UI sinks, and stops advancing that authority while this is pending.
    pub fn prepare(
        &mut self,
        image: Vec<u8>,
        logical_ms: u64,
        watermarks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<&Candidate> {
        let candidate = self.proposal(image, logical_ms, watermarks, outputs)?;
        self.pending = Some(candidate);
        Ok(self.pending.as_ref().unwrap())
    }
    fn proposal(
        &self,
        image: Vec<u8>,
        logical_ms: u64,
        watermarks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<Candidate> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        if logical_ms < self.receipt.logical_ms {
            return Err(Error::Invalid("primary time regression"));
        }
        let candidate = Candidate {
            sequence: self.sender.allocate()?,
            term: self.publication_term,
            index: self.receipt.index.checked_add(1).ok_or(Error::Bounds)?,
            parent: self.receipt.digest(&self.context)?,
            logical_ms,
            image,
            watermarks,
            outputs,
        };
        candidate.encode(&self.context)?;
        Ok(candidate)
    }
    /// Return only committed, proof-carrying effects. Receipt replay is a no-op;
    /// an unrelated valid receipt cannot unlock this primary's pending state.
    pub fn acknowledge(&mut self, receipt: Receipt) -> Result<Vec<CertifiedOutput>> {
        if self.closed {
            return Err(Error::Closed);
        }
        receipt.verify(&self.context)?;
        if receipt == self.receipt {
            return Ok(Vec::new());
        }
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        let layers = tree(pending.index, &pending.outputs)?;
        if receipt.term != pending.term
            || receipt.index != pending.index
            || receipt.parent != pending.parent
            || receipt.logical_ms != pending.logical_ms
            || receipt.state != state_hash(&pending.image)?
            || receipt.watermarks != pending.watermarks
            || receipt.outputs_count as usize != pending.outputs.len()
            || receipt.outputs_root != layers.last().unwrap()[0]
        {
            return Err(Error::Conflict);
        }
        let mut publication = Vec::with_capacity(pending.outputs.len());
        for (ordinal, output) in pending.outputs.iter().enumerate() {
            let mut at = ordinal;
            let siblings = layers
                .iter()
                .take(layers.len() - 1)
                .map(|layer| {
                    let h = layer[at ^ 1];
                    at >>= 1;
                    h
                })
                .collect();
            publication.push(CertifiedOutput {
                receipt: receipt.clone(),
                ordinal: ordinal as u32,
                output: output.clone(),
                siblings,
            });
        }
        let mut outbox = self.outbox.clone();
        outbox.retain(|(player, number), _| {
            receipt
                .watermarks
                .iter()
                .any(|m| m.player == *player && !m.retired && m.output_ack < *number)
        });
        for record in &publication {
            if record.output.delivery == Delivery::Reliable {
                outbox.insert(
                    (record.output.recipient, record.output.sequence),
                    record.clone(),
                );
            }
        }
        let payload = outbox.values().try_fold(0usize, |n, r| {
            n.checked_add(r.output.bytes.len()).ok_or(Error::Bounds)
        })?;
        let proofs = outbox.values().try_fold(0usize, |n, r| {
            n.checked_add(r.encode(&self.context)?.len())
                .ok_or(Error::Bounds)
        })?;
        if outbox.len() > MAX_OUTBOX_RECORDS
            || payload > MAX_OUTBOX_BYTES
            || proofs > MAX_PROOF_BYTES
            || pending
                .image
                .len()
                .checked_add(payload)
                .and_then(|n| n.checked_add(receipt.body(&self.context).ok()?.len()))
                .is_none_or(|n| n > MAX_IMAGE)
        {
            return Err(Error::Bounds);
        }
        self.outbox = outbox;
        let pending = self.pending.take().unwrap();
        for output in &pending.outputs {
            self.allocated.insert(
                (
                    output.recipient,
                    u8::from(output.delivery == Delivery::Lossy),
                ),
                output.sequence,
            );
        }
        self.allocated.retain(|(player, _), _| {
            receipt
                .watermarks
                .iter()
                .any(|m| m.player == *player && !m.retired)
        });
        self.committed = pending.image;
        self.receipt = receipt;
        Ok(publication)
    }
    pub fn close(&mut self, promotion: &Promotion) -> Result<()> {
        if self.publication_term != 0 {
            return Err(Error::Closed);
        }
        promotion.verify(&self.context)?;
        // Only this sequencer's signed closure can stop the primary. It may
        // include its in-flight candidate whose commit ACK was lost.
        let final_index = promotion.final_receipt.index;
        if final_index < self.receipt.index {
            return Err(Error::Stale);
        }
        let allowed = self
            .receipt
            .index
            .checked_add(u64::from(self.pending.is_some()))
            .ok_or(Error::Bounds)?;
        if final_index > allowed {
            return Err(Error::Invalid("unknown promotion frontier"));
        }
        if final_index == self.receipt.index && promotion.final_receipt != self.receipt {
            return Err(Error::Conflict);
        }
        if final_index > self.receipt.index {
            // Validate the exact pending commit before abandoning authority.
            self.acknowledge(promotion.final_receipt.clone())?;
        }
        self.closed = true;
        self.pending = None;
        Ok(())
    }
}

/// Bounded session-frame queue. One shared token bucket includes priority
/// control/receipt traffic; priority never bypasses the pair's bandwidth cap.
#[derive(Clone)]
pub struct SendQueue {
    ordinary: VecDeque<(u64, Vec<u8>)>,
    priority: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    tokens: usize,
    last_ms: Option<u64>,
    fraction: u64,
}
impl Default for SendQueue {
    fn default() -> Self {
        Self {
            ordinary: VecDeque::new(),
            priority: VecDeque::new(),
            bytes: 0,
            tokens: 64 * 1024,
            last_ms: None,
            fraction: 0,
        }
    }
}
impl SendQueue {
    /// Atomically accept a complete framed message, or leave the queue intact.
    pub fn enqueue(&mut self, frames: Vec<Frame>) -> Result<()> {
        let mut encoded = Vec::with_capacity(frames.len().min(MAX_IMAGE.div_ceil(CHUNK_PAYLOAD)));
        let mut added = 0usize;
        let mut priority_added = 0usize;
        for frame in frames {
            let wire = frame.encode()?;
            added = added.checked_add(wire.len()).ok_or(Error::Bounds)?;
            let priority = matches!(frame.kind, PacketKind::Control | PacketKind::Receipt);
            if priority {
                priority_added = priority_added
                    .checked_add(wire.len())
                    .ok_or(Error::Bounds)?;
            }
            if self.bytes.checked_add(added).ok_or(Error::Bounds)? > 2 * MAX_IMAGE
                || priority_added > 64 * 1024
            {
                return Err(Error::Bounds);
            }
            encoded.push((frame.term, wire, priority));
        }
        let existing_priority = self.priority.iter().try_fold(0usize, |n, (_, w)| {
            n.checked_add(w.len()).ok_or(Error::Bounds)
        })?;
        if existing_priority
            .checked_add(priority_added)
            .ok_or(Error::Bounds)?
            > 64 * 1024
        {
            return Err(Error::Bounds);
        }
        for (term, wire, priority) in encoded {
            if priority {
                self.priority.push_back((term, wire));
            } else {
                self.ordinary.push_back((term, wire));
            }
        }
        self.bytes += added;
        Ok(())
    }
    pub fn queued_bytes(&self) -> usize {
        self.bytes
    }
    /// Discard old-term transfer work only after an authenticated promotion.
    pub fn retain_term(&mut self, term: u64) {
        self.ordinary.retain(|(t, _)| *t == term);
        self.priority.retain(|(t, _)| *t == term);
        self.bytes = self
            .ordinary
            .iter()
            .chain(&self.priority)
            .map(|(_, b)| b.len())
            .sum();
    }
    /// Session-frame byte pacing (QUIC/UDP overhead is measured separately).
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        if let Some(last) = self.last_ms {
            let elapsed = now_ms
                .checked_sub(last)
                .ok_or(Error::Invalid("backwards send clock"))?;
            let credit = u128::from(elapsed) * (4 * 1024 * 1024) + u128::from(self.fraction);
            let whole = (credit / 1000).min(64 * 1024) as usize;
            self.tokens = self.tokens.saturating_add(whole).min(64 * 1024);
            self.fraction = (credit % 1000) as u64;
        }
        self.last_ms = Some(now_ms);
        let queue = if self.priority.is_empty() {
            &mut self.ordinary
        } else {
            &mut self.priority
        };
        if queue
            .front()
            .is_some_and(|(_, wire)| wire.len() <= self.tokens)
        {
            let (_, wire) = queue.pop_front().unwrap();
            self.tokens -= wire.len();
            self.bytes -= wire.len();
            return Ok(Some(wire));
        }
        Ok(None)
    }
}

/// Audit every serialized numeric leaf before accepting an authority image.
/// Game-specific sentinels must have an explicit codec (for example an absent
/// deadline), so malformed NaNs/infinities cannot hide inside nested state.
pub fn validate_finite<T: serde::Serialize + ?Sized>(value: &T) -> Result<()> {
    value.serialize(number_check::Check)
}
mod number_check {
    use super::*;
    use serde::ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant, Serializer,
    };
    #[derive(Clone, Copy)]
    pub(super) struct Check;
    impl serde::ser::Error for Error {
        fn custom<T: fmt::Display>(_: T) -> Self {
            Error::Invalid("invalid serialized number")
        }
    }
    macro_rules! scalar {
        ($($name:ident: $ty:ty),* $(,)?) => {$(fn $name(self, _: $ty) -> Result<()> { Ok(()) })*};
    }
    impl Serializer for Check {
        type Ok = ();
        type Error = Error;
        type SerializeSeq = Self;
        type SerializeTuple = Self;
        type SerializeTupleStruct = Self;
        type SerializeTupleVariant = Self;
        type SerializeMap = Self;
        type SerializeStruct = Self;
        type SerializeStructVariant = Self;
        scalar!(serialize_bool: bool, serialize_i8: i8, serialize_i16: i16,
            serialize_i32: i32, serialize_i64: i64, serialize_i128: i128,
            serialize_u8: u8, serialize_u16: u16, serialize_u32: u32,
            serialize_u64: u64, serialize_u128: u128, serialize_char: char,
            serialize_str: &str, serialize_bytes: &[u8]);
        fn serialize_f32(self, v: f32) -> Result<()> {
            if v.is_finite() {
                Ok(())
            } else {
                Err(Error::Invalid("nonfinite checkpoint number"))
            }
        }
        fn serialize_f64(self, v: f64) -> Result<()> {
            if v.is_finite() {
                Ok(())
            } else {
                Err(Error::Invalid("nonfinite checkpoint number"))
            }
        }
        fn serialize_none(self) -> Result<()> {
            Ok(())
        }
        fn serialize_some<T: serde::Serialize + ?Sized>(self, v: &T) -> Result<()> {
            v.serialize(self)
        }
        fn serialize_unit(self) -> Result<()> {
            Ok(())
        }
        fn serialize_unit_struct(self, _: &'static str) -> Result<()> {
            Ok(())
        }
        fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<()> {
            Ok(())
        }
        fn serialize_newtype_struct<T: serde::Serialize + ?Sized>(
            self,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(self)
        }
        fn serialize_newtype_variant<T: serde::Serialize + ?Sized>(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(self)
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self> {
            Ok(self)
        }
        fn serialize_tuple(self, _: usize) -> Result<Self> {
            Ok(self)
        }
        fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self> {
            Ok(self)
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self> {
            Ok(self)
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self> {
            Ok(self)
        }
        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self> {
            Ok(self)
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self> {
            Ok(self)
        }
    }
    macro_rules! sequence {
        ($trait:ident, $method:ident) => {
            impl $trait for Check {
                type Ok = ();
                type Error = Error;
                fn $method<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<()> {
                    v.serialize(*self)
                }
                fn end(self) -> Result<()> {
                    Ok(())
                }
            }
        };
    }
    sequence!(SerializeSeq, serialize_element);
    sequence!(SerializeTuple, serialize_element);
    sequence!(SerializeTupleStruct, serialize_field);
    sequence!(SerializeTupleVariant, serialize_field);
    impl SerializeMap for Check {
        type Ok = ();
        type Error = Error;
        fn serialize_key<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<()> {
            v.serialize(*self)
        }
        fn serialize_value<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<()> {
            v.serialize(*self)
        }
        fn end(self) -> Result<()> {
            Ok(())
        }
    }
    impl SerializeStruct for Check {
        type Ok = ();
        type Error = Error;
        fn serialize_field<T: serde::Serialize + ?Sized>(
            &mut self,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(*self)
        }
        fn end(self) -> Result<()> {
            Ok(())
        }
    }
    impl SerializeStructVariant for Check {
        type Ok = ();
        type Error = Error;
        fn serialize_field<T: serde::Serialize + ?Sized>(
            &mut self,
            _: &'static str,
            v: &T,
        ) -> Result<()> {
            v.serialize(*self)
        }
        fn end(self) -> Result<()> {
            Ok(())
        }
    }
}

/// Decode a fixed-cap collection without trusting its advertised allocation
/// size. Used by game checkpoint envelopes as well as session metadata.
pub fn bounded_vec<'de, D, T, const N: usize>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} values")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > N) {
                return Err(serde::de::Error::custom("collection bound"));
            }
            let mut values = Vec::new();
            while let Some(value) = seq.next_element()? {
                if values.len() == N {
                    return Err(serde::de::Error::custom("collection bound"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Visitor::<T, N>(std::marker::PhantomData))
}

/// A game's peer IDs identify logical links, not QUIC allocator slots. Keeping
/// that distinction outside the authority preserves the committed state and
/// per-seat security history while transport connections are replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerBindings {
    logical: BTreeMap<u64, (u32, bool)>,
    physical: BTreeMap<u32, u64>,
}
impl PeerBindings {
    /// `local` includes retained host-owned bot/loopback links. They never bind
    /// to remote connections or acquire a new player seat on promotion.
    pub fn new(routes: impl IntoIterator<Item = (u64, u32, bool)>) -> Result<Self> {
        let mut logical = BTreeMap::new();
        let mut peers = BTreeSet::new();
        for (player, peer, local) in routes {
            if logical.len() == MAX_PLAYERS
                || !peers.insert(peer)
                || logical.insert(player, (peer, local)).is_some()
            {
                return Err(Error::Conflict);
            }
        }
        Ok(Self {
            logical,
            physical: BTreeMap::new(),
        })
    }
    /// Atomically bind exactly the sealed authenticated survivors. Missing
    /// players keep their logical links until committed departure, with no
    /// physical destination. Reused physical IDs cannot inherit their state.
    pub fn bind_survivors(&mut self, bindings: &[(u64, u32)]) -> Result<()> {
        let mut next = BTreeMap::new();
        let mut players = BTreeSet::new();
        if bindings.len() > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        for &(player, physical) in bindings {
            match self.logical.get(&player) {
                Some((_, false)) => {}
                _ => return Err(Error::Unauthorized),
            }
            if !players.insert(player) || next.insert(physical, player).is_some() {
                return Err(Error::Conflict);
            }
        }
        self.physical = next;
        Ok(())
    }
    pub fn incoming(&self, physical: u32) -> Option<(u64, u32)> {
        let player = *self.physical.get(&physical)?;
        Some((player, self.logical.get(&player)?.0))
    }
    pub fn outgoing(&self, logical: u32) -> Option<u32> {
        let (&player, _) = self
            .logical
            .iter()
            .find(|(_, route)| route.0 == logical && !route.1)?;
        self.physical
            .iter()
            .find_map(|(peer, p)| (*p == player).then_some(*peer))
    }
    pub fn logical(&self, player: u64) -> Option<u32> {
        self.logical.get(&player).map(|r| r.0)
    }
}

/// Fixed v0.1 resource profile, included in both parties' signed descriptor.
/// Changes require another supported profile rather than silently larger caps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub frame: u32,
    pub chunk: u32,
    pub image: u32,
    pub custom: u32,
    pub patch: u32,
    pub transfer_queue: u32,
    pub rate: u32,
    pub burst: u32,
    pub intent_bytes: u32,
    pub intent_records: u32,
    pub outbox_bytes: u32,
    pub outbox_records: u32,
    pub proof_bytes: u32,
    pub batch: u32,
    pub recovery_applications: u32,
    pub players: u32,
    pub control_links: u32,
    pub pending_handshakes: u32,
    pub handshake_ms: u32,
    pub transfer_ms: u32,
    pub batch_ms: u32,
    pub full_image_ms: u32,
    pub correction_ms: u32,
    pub survivor_ms: u32,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            frame: 1024,
            chunk: 768,
            image: MAX_IMAGE as u32,
            custom: MAX_IMAGE as u32,
            patch: MAX_PATCH as u32,
            transfer_queue: 2 * MAX_IMAGE as u32,
            rate: 4 * 1024 * 1024,
            burst: 64 * 1024,
            intent_bytes: MAX_JOURNAL_BYTES as u32,
            intent_records: MAX_JOURNAL_RECORDS as u32,
            outbox_bytes: MAX_OUTBOX_BYTES as u32,
            outbox_records: MAX_OUTBOX_RECORDS as u32,
            proof_bytes: MAX_PROOF_BYTES as u32,
            batch: MAX_BATCH as u32,
            recovery_applications: 4096,
            players: 8,
            control_links: 9,
            pending_handshakes: 2,
            handshake_ms: 5000,
            transfer_ms: 500,
            batch_ms: 50,
            full_image_ms: 250,
            correction_ms: 250,
            survivor_ms: 250,
        }
    }
}
impl ResourceLimits {
    fn values(&self) -> [u32; 24] {
        [
            self.frame,
            self.chunk,
            self.image,
            self.custom,
            self.patch,
            self.transfer_queue,
            self.rate,
            self.burst,
            self.intent_bytes,
            self.intent_records,
            self.outbox_bytes,
            self.outbox_records,
            self.proof_bytes,
            self.batch,
            self.recovery_applications,
            self.players,
            self.control_links,
            self.pending_handshakes,
            self.handshake_ms,
            self.transfer_ms,
            self.batch_ms,
            self.full_image_ms,
            self.correction_ms,
            self.survivor_ms,
        ]
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        // This implementation supports exactly the reviewed initial profile.
        // Read and compare before creating any allocation influenced by limits.
        let supported = Self::default();
        for n in supported.values() {
            if u32::from_be_bytes(r.array()?) != n {
                return Err(Error::Invalid("unsupported resource profile"));
            }
        }
        Ok(supported)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub player: u64,
    pub seat: u8,
    /// None is a host-owned bot, with no consent/capability vote.
    pub key: Option<RuntimeKey>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub session: SessionId,
    pub app: String,
    pub transport_version: u32,
    pub game_version: u32,
    pub checkpoint_version: u32,
    pub host: RuntimeKey,
    pub standby: RuntimeKey,
    pub controller: RuntimeKey,
    pub code: Hash,
    pub created_day: u64,
    pub roster_revision: u64,
    pub members: Vec<Member>,
    pub config: Hash,
    pub content: Hash,
    pub limits: ResourceLimits,
}
pub fn fresh_session() -> Result<SessionId> {
    let mut session = [0; 16];
    getrandom::fill(&mut session).map_err(|_| Error::Invalid("session RNG"))?;
    Ok(session)
}
pub fn room_code_hash(code: &str) -> Result<Hash> {
    let code = crate::room::normalize_code(code).ok_or(Error::Invalid("room code"))?;
    Ok(hash(b"fray/migration/code/v1\0", code.as_bytes()))
}
impl Root {
    pub fn validate(&self) -> Result<()> {
        if self.session == [0; 16]
            || self.app.is_empty()
            || self.app.len() > 64
            || !self
                .app
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || self.transport_version != 7
            || self.game_version == 0
            || self.checkpoint_version == 0
            || self.roster_revision == 0
            || self.limits != ResourceLimits::default()
            || self.members.len() > MAX_PLAYERS
            || self.host == self.standby
        {
            return Err(Error::Invalid("migration root profile"));
        }
        for key in [self.host, self.standby, self.controller] {
            PublicKey::from_slice(&key).map_err(|_| Error::Unauthorized)?;
        }
        let mut seats = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut last = None;
        for member in &self.members {
            if member.seat as usize >= MAX_PLAYERS
                || !seats.insert(member.seat)
                || last.is_some_and(|id| id >= member.player)
            {
                return Err(Error::Invalid("root roster order/seat"));
            }
            last = Some(member.player);
            if let Some(key) = member.key {
                PublicKey::from_slice(&key).map_err(|_| Error::Unauthorized)?;
                if !keys.insert(key) {
                    return Err(Error::Invalid("duplicate player key"));
                }
            }
        }
        Ok(())
    }
    fn body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = vec![VERSION];
        bytes.extend(self.session);
        put_bytes(&mut bytes, self.app.as_bytes(), 64)?;
        for n in [
            self.transport_version,
            self.game_version,
            self.checkpoint_version,
        ] {
            bytes.extend(n.to_be_bytes());
        }
        bytes.extend(self.host);
        bytes.extend(self.standby);
        bytes.extend(self.controller);
        bytes.extend(self.code);
        bytes.extend(self.created_day.to_be_bytes());
        bytes.extend(self.roster_revision.to_be_bytes());
        put_u32(&mut bytes, self.members.len())?;
        for member in &self.members {
            bytes.extend(member.player.to_be_bytes());
            bytes.push(member.seat);
            match member.key {
                None => bytes.push(0),
                Some(key) => {
                    bytes.push(1);
                    bytes.extend(key);
                }
            }
        }
        bytes.extend(self.config);
        bytes.extend(self.content);
        for n in self.limits.values() {
            bytes.extend(n.to_be_bytes());
        }
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<Hash> {
        Ok(hash(b"fray/migration/descriptor/v1\0", &self.body()?))
    }
    pub fn context(&self) -> Result<Context> {
        Ok(Context {
            session: self.session,
            descriptor: self.digest()?,
            host: self.host,
            standby: self.standby,
        })
    }
    pub fn member(&self, player: u64) -> Result<&Member> {
        self.members
            .iter()
            .find(|m| m.player == player)
            .ok_or(Error::Unauthorized)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        if r.u8()? != VERSION {
            return Err(Error::Invalid("root version"));
        }
        let session = r.array()?;
        let app = String::from_utf8(r.bytes(64)?).map_err(|_| Error::Invalid("app UTF8"))?;
        let transport_version = u32::from_be_bytes(r.array()?);
        let game_version = u32::from_be_bytes(r.array()?);
        let checkpoint_version = u32::from_be_bytes(r.array()?);
        let host = r.array()?;
        let standby = r.array()?;
        let controller = r.array()?;
        let code = r.array()?;
        let created_day = r.u64()?;
        let roster_revision = r.u64()?;
        let count = r.u32()?;
        if count > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let player = r.u64()?;
            let seat = r.u8()?;
            let key = match r.u8()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(Error::Invalid("root key option")),
            };
            members.push(Member { player, seat, key });
        }
        let config = r.array()?;
        let content = r.array()?;
        let limits = ResourceLimits::read(r)?;
        let root = Self {
            session,
            app,
            transport_version,
            game_version,
            checkpoint_version,
            host,
            standby,
            controller,
            code,
            created_day,
            roster_revision,
            members,
            config,
            content,
            limits,
        };
        root.validate()?;
        Ok(root)
    }
}
/// The standby signature is explicit consent to this exact fixed pair,
/// controller, roster, content and limit profile. Admission remains mandatory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub root: Root,
    pub host_signature: SignatureBytes,
    pub standby_signature: SignatureBytes,
}
impl Descriptor {
    pub fn offer(root: Root, host: &Keys) -> Result<Self> {
        if root.host != host.public_key().to_bytes() {
            return Err(Error::Unauthorized);
        }
        let digest = root.digest()?;
        Ok(Self {
            root,
            host_signature: sign(host, digest),
            standby_signature: [0; 64],
        })
    }
    pub fn consent(&mut self, standby: &Keys) -> Result<()> {
        let digest = self.root.digest()?;
        verify(self.root.host, digest, self.host_signature)?;
        if self.root.standby != standby.public_key().to_bytes() {
            return Err(Error::Unauthorized);
        }
        self.standby_signature = sign(standby, digest);
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        let digest = self.root.digest()?;
        verify(self.root.host, digest, self.host_signature)?;
        verify(self.root.standby, digest, self.standby_signature)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.root.body()?;
        bytes.extend(self.host_signature);
        bytes.extend(self.standby_signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        let root = Root::read(&mut r)?;
        let descriptor = Self {
            root,
            host_signature: r.array()?,
            standby_signature: r.array()?,
        };
        r.finish()?;
        // A bootstrap offer intentionally lacks standby consent; callers must
        // verify() before disclosing authority state or constructing Activation.
        verify(
            descriptor.root.host,
            descriptor.root.digest()?,
            descriptor.host_signature,
        )?;
        Ok(descriptor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityAck {
    pub player: u64,
    pub sequence: u64,
    pub initial: Hash,
    pub signature: SignatureBytes,
}
fn control_prefix(context: &Context, term: u64, kind: u8, sequence: u64) -> Vec<u8> {
    let mut bytes = vec![VERSION];
    bytes.extend(context.session);
    bytes.extend(context.descriptor);
    bytes.extend(term.to_be_bytes());
    bytes.push(kind);
    bytes.extend(sequence.to_be_bytes());
    bytes
}
impl CapabilityAck {
    fn digest(&self, root: &Root) -> Result<Hash> {
        if self.sequence == 0 {
            return Err(Error::Invalid("capability sequence"));
        }
        let mut bytes = control_prefix(&root.context()?, 0, 1, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.initial);
        Ok(hash(b"fray/migration/control/v1\0", &bytes))
    }
    pub fn sign(
        root: &Root,
        player: u64,
        initial: Hash,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        if root.member(player)?.key != Some(keys.public_key().to_bytes()) {
            return Err(Error::Unauthorized);
        }
        let mut ack = Self {
            player,
            sequence,
            initial,
            signature: [0; 64],
        };
        ack.signature = sign(keys, ack.digest(root)?);
        Ok(ack)
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        verify(
            root.member(self.player)?.key.ok_or(Error::Unauthorized)?,
            self.digest(root)?,
            self.signature,
        )
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.verify(root)?;
        let mut bytes = control_prefix(&root.context()?, 0, 1, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.initial);
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let prefix = control_prefix(&root.context()?, 0, 1, 0);
        if r.take(prefix.len() - 8)? != &prefix[..prefix.len() - 8] {
            return Err(Error::Invalid("capability context"));
        }
        let sequence = r.u64()?;
        let ack = Self {
            sequence,
            player: r.u64()?,
            initial: r.array()?,
            signature: r.array()?,
        };
        r.finish()?;
        ack.verify(root)?;
        Ok(ack)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Armed {
    pub sequence: u64,
    pub receipt: Receipt,
    pub signature: SignatureBytes,
}
impl Armed {
    fn digest(&self, context: &Context) -> Result<Hash> {
        let mut bytes = control_prefix(context, 0, 2, self.sequence);
        bytes.extend(self.receipt.digest(context)?);
        Ok(hash(b"fray/migration/control/v1\0", &bytes))
    }
    pub fn verify(&self, context: &Context) -> Result<()> {
        self.receipt.verify(context)?;
        if self.sequence <= self.receipt.sequence.checked_add(1).ok_or(Error::Bounds)?
            || self.receipt.term != 0
            || self.receipt.index != 0
            || self.receipt.parent != [0; 32]
            || self.receipt.outputs_count != 0
            || self.receipt.outputs_root != tree(0, &[])?.last().unwrap()[0]
            || self
                .receipt
                .watermarks
                .iter()
                .any(|m| m.retired || m.input != 0 || m.output_ack != 0)
        {
            return Err(Error::Invalid("armed initial receipt"));
        }
        verify(context.standby, self.digest(context)?, self.signature)
    }
    /// A player pins only its previously acknowledged checkpoint hash and the
    /// public roster/clock; it does not receive hidden authority state.
    pub fn verify_initial(&self, root: &Root, initial: Hash, logical_ms: u64) -> Result<()> {
        self.verify(&root.context()?)?;
        if self.receipt.state != initial
            || self.receipt.logical_ms != logical_ms
            || self
                .receipt
                .watermarks
                .iter()
                .map(|m| m.player)
                .collect::<Vec<_>>()
                != root.members.iter().map(|m| m.player).collect::<Vec<_>>()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn encode(&self, context: &Context) -> Result<Vec<u8>> {
        self.verify(context)?;
        let mut bytes = control_prefix(context, 0, 2, self.sequence);
        put_bytes(
            &mut bytes,
            &self.receipt.encode(context)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut reader = Reader(bytes);
        let sequence = read_control_prefix(&mut reader, context, 0, 2)?;
        let armed = Self {
            sequence,
            receipt: Receipt::decode(context, &reader.bytes(crate::MAX_RELIABLE_LEN)?)?,
            signature: reader.array()?,
        };
        reader.finish()?;
        armed.verify(context)?;
        Ok(armed)
    }
}
/// Fail-closed lobby activation. The runner freezes ordinary output before
/// construction and never returns to ordinary mode after this actor exists.
/// A consumed activation cannot be retried as another session with the same ID.
pub struct Activation {
    replay: ReplaySession,
    session_bound: bool,
    descriptor: Descriptor,
    image: Vec<u8>,
    logical_ms: u64,
    acknowledgements: BTreeMap<u64, CapabilityAck>,
}
impl Activation {
    pub fn new(descriptor: Descriptor, image: Vec<u8>, logical_ms: u64) -> Result<Self> {
        descriptor.verify()?;
        state_hash(&image)?;
        Ok(Self {
            replay: ReplaySession::new(descriptor.root.context()?),
            session_bound: false,
            descriptor,
            image,
            logical_ms,
            acknowledgements: BTreeMap::new(),
        })
    }
    pub fn new_session(descriptor: Descriptor, image: SessionImage) -> Result<Self> {
        image.validate_initial(&descriptor.root)?;
        let mut activation = Self::new(
            descriptor.clone(),
            image.encode(&descriptor.root)?,
            image.logical_ms,
        )?;
        activation.session_bound = true;
        Ok(activation)
    }
    pub fn acknowledge(&mut self, ack: CapabilityAck) -> Result<()> {
        ack.verify(&self.descriptor.root)?;
        if ack.initial != state_hash(&self.image)? {
            return Err(Error::Conflict);
        }
        let ticket = self.replay.begin(
            self.descriptor
                .root
                .member(ack.player)?
                .key
                .ok_or(Error::Unauthorized)?,
            ack.sequence,
            &ack.encode(&self.descriptor.root)?,
            false,
        )?;
        match self.acknowledgements.get(&ack.player) {
            Some(old) if old == &ack => return Ok(()),
            Some(_) => return Err(Error::Conflict),
            None => {}
        }
        self.acknowledgements.insert(ack.player, ack);
        ticket.commit()?;
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.descriptor
            .root
            .members
            .iter()
            .filter(|m| m.key.is_some())
            .all(|m| self.acknowledgements.contains_key(&m.player))
    }
    /// Restore through the game's real fresh-instance adapter, then compare
    /// exact canonical bytes before commit0 is installed or readiness is signed.
    pub fn arm(
        self,
        standby: &Keys,
        restore: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<(Sequencer, Armed)> {
        self.replay.live()?;
        if !self.ready() {
            return Err(Error::Gap);
        }
        if restore(&self.image)? != self.image {
            return Err(Error::Invalid("initial restore equivalence"));
        }
        let context = self.descriptor.root.context()?;
        let marks = self
            .descriptor
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
        let mut sender = if let Some(ack) = self.acknowledgements.values().find(|ack| {
            self.descriptor
                .root
                .member(ack.player)
                .is_ok_and(|m| m.key == Some(context.standby))
        }) {
            SenderSequence::from_capability(&self.descriptor.root, ack, standby)?
        } else {
            SenderSequence::starting(context.clone(), context.standby, 1)?
        };
        sender.replay = self.replay;
        let sequencer = if self.session_bound {
            let image = SessionImage::decode(&self.descriptor.root, &self.image)?;
            Sequencer::arm_session_with_sender(
                self.descriptor.root.clone(),
                image,
                standby,
                sender,
            )?
        } else {
            Sequencer::arm_with_sender(
                context.clone(),
                self.image,
                self.logical_ms,
                marks,
                standby,
                sender,
            )?
        };
        let mut armed = Armed {
            sequence: sequencer.sender.allocate()?,
            receipt: sequencer.receipt().clone(),
            signature: [0; 64],
        };
        armed.signature = sign(standby, armed.digest(&context)?);
        Ok((sequencer, armed))
    }
}

/// One frozen lobby checkpoint travels only on the designated pair's already
/// authenticated, consenting link. No image is sent to roster control players.
/// The source retains its exact canonical bytes until the standby signs Armed.
pub struct ActivationSource {
    replay: ReplaySession,
    descriptor: Descriptor,
    image: Vec<u8>,
    channel: Channel,
    acknowledgements: BTreeMap<u64, CapabilityAck>,
    armed: Option<Armed>,
    membership: Option<MembershipCertificate>,
    clock: ActivationClock,
}
struct ActivationClock {
    started: u64,
    last: u64,
    failed: bool,
}
impl ActivationClock {
    fn new(now_ms: u64) -> Self {
        Self {
            started: now_ms,
            last: now_ms,
            failed: false,
        }
    }
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        if self.failed {
            return Err(Error::Closed);
        }
        if now_ms < self.last || now_ms - self.started >= 5000 {
            self.failed = true;
            return Err(Error::Closed);
        }
        self.last = now_ms;
        Ok(())
    }
}
fn activation_channel(descriptor: &Descriptor, channel: &Channel, side: ChannelSide) -> Result<()> {
    descriptor.verify()?;
    if &channel.descriptor != descriptor
        || channel.side != side
        || channel.term != 0
        || channel.binding.client != LinkRole::Original
        || channel.binding.server != LinkRole::Standby
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
impl ActivationSource {
    /// The authenticated public certificate, after it has been received.
    /// Consuming finish still checks the original deadline and live replay state.
    pub fn armed(&self) -> Option<&Armed> {
        self.armed.as_ref()
    }
    /// The standby-signed index-0 membership certificate, once received after
    /// `Armed`. `finish` moves it into the returned [`Primary`]; if it arrives
    /// after the handoff, [`PrimaryActor`] accepts it instead.
    pub fn membership_certificate(&self) -> Option<&MembershipCertificate> {
        self.membership.as_ref()
    }
    pub fn new(
        descriptor: Descriptor,
        image: SessionImage,
        mut channel: Channel,
        now_ms: u64,
    ) -> Result<Self> {
        activation_channel(&descriptor, &channel, ChannelSide::Client)?;
        image.validate_initial(&descriptor.root)?;
        let image = image.encode(&descriptor.root)?;
        channel.enqueue(PacketKind::InitialImage, &image)?;
        Ok(Self {
            replay: ReplaySession::new(descriptor.root.context()?),
            descriptor,
            image,
            channel,
            acknowledgements: BTreeMap::new(),
            armed: None,
            membership: None,
            clock: ActivationClock::new(now_ms),
        })
    }
    pub fn initial_hash(&self) -> Result<Hash> {
        state_hash(&self.image)
    }
    /// Relay an actual human's signed capability ACK, including the local
    /// creator. Bots cannot vote and no ACK is synthesized for another key.
    pub fn acknowledge(&mut self, ack: CapabilityAck, now_ms: u64) -> Result<()> {
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        ack.verify(&self.descriptor.root)?;
        if ack.initial != self.initial_hash()? {
            return Err(Error::Conflict);
        }
        let ticket = self.replay.begin(
            self.descriptor
                .root
                .member(ack.player)?
                .key
                .ok_or(Error::Unauthorized)?,
            ack.sequence,
            &ack.encode(&self.descriptor.root)?,
            false,
        )?;
        if let Some(previous) = self.acknowledgements.get(&ack.player) {
            if previous.initial == ack.initial && previous.sequence == ack.sequence {
                return Ok(());
            }
            return Err(Error::Conflict);
        }
        self.channel
            .enqueue(PacketKind::Control, &ack.encode(&self.descriptor.root)?)?;
        self.acknowledgements.insert(ack.player, ack);
        ticket.commit()?;
        Ok(())
    }
    pub fn receive(&mut self, wire: &[u8], now_ms: u64) -> Result<bool> {
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        let Some((kind, _, bytes)) = self.channel.receive(wire, now_ms)? else {
            return Ok(false);
        };
        if kind != PacketKind::Control {
            return Err(Error::Unauthorized);
        }
        match control_kind(&self.descriptor.root, &bytes)? {
            2 => {}
            9 => {
                let installed = self.armed.as_ref().ok_or(Error::Gap)?.receipt.clone();
                let accepted = accept_pair_certificate(
                    &self.replay,
                    &self.descriptor.root,
                    &installed,
                    &self.image,
                    self.membership.as_ref(),
                    &bytes,
                );
                if accepted == Err((Error::Conflict, true)) {
                    // A signature-verified standby certificate contradicting
                    // the armed receipt, the frozen image or the ledger.
                    self.clock.failed = true;
                }
                if let Some(certificate) = accepted.map_err(|(error, _)| error)? {
                    self.membership = Some(certificate);
                }
                return Ok(false);
            }
            _ => return Err(Error::Unauthorized),
        }
        let armed = Armed::decode(&self.descriptor.root.context()?, &bytes)?;
        let image = SessionImage::decode(&self.descriptor.root, &self.image)?;
        armed.verify_initial(
            &self.descriptor.root,
            self.initial_hash()?,
            image.logical_ms,
        )?;
        if !self
            .descriptor
            .root
            .members
            .iter()
            .filter(|m| m.key.is_some())
            .all(|m| self.acknowledgements.contains_key(&m.player))
        {
            return Err(Error::Gap);
        }
        self.replay.receipt(&armed.receipt)?;
        let ticket =
            self.replay
                .begin(self.descriptor.root.standby, armed.sequence, &bytes, false)?;
        if let Some(previous) = &self.armed {
            if previous.receipt.digest(&self.descriptor.root.context()?)?
                != armed.receipt.digest(&self.descriptor.root.context()?)?
            {
                self.clock.failed = true;
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
        self.armed = Some(armed);
        ticket.commit()?;
        Ok(true)
    }
    pub fn poll_send(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        self.channel.expire(now_ms)?;
        self.channel.poll_send(now_ms)
    }
    /// Consume the activation once; reuse its physical Channel and framing
    /// counters for ordinary replication rather than constructing another link.
    pub fn finish(mut self, now_ms: u64) -> Result<(Primary, Channel)> {
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        self.channel.expire(now_ms)?;
        let receipt = self.armed.take().ok_or(Error::Gap)?.receipt;
        let mut primary = Primary::armed(self.descriptor.root.context()?, self.image, receipt)?;
        primary.membership = self.membership.take();
        if let Some(ack) = self.acknowledgements.values().find(|ack| {
            self.descriptor
                .root
                .member(ack.player)
                .is_ok_and(|m| m.key == Some(self.descriptor.root.host))
        }) {
            primary.sender.advance_past(ack.sequence)?;
        }
        primary.sender.replay = self.replay;
        Ok((primary, self.channel))
    }
}
/// Standby half of lobby activation. The sink owns the only transfer buffer;
/// it cannot expose a Sequencer before all signed human ACKs and native fresh
/// restore equivalence pass. A failed/expired arming never returns to ordinary.
pub struct ActivationSink {
    replay: ReplaySession,
    descriptor: Descriptor,
    channel: Channel,
    image: Option<Vec<u8>>,
    acknowledgements: BTreeMap<u64, CapabilityAck>,
    clock: ActivationClock,
}
impl ActivationSink {
    /// Advance the original arming/reassembly deadlines even on a quiet link.
    pub fn poll(&mut self, now_ms: u64) -> Result<()> {
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        self.channel.expire(now_ms)
    }

    pub fn new(descriptor: Descriptor, channel: Channel, now_ms: u64) -> Result<Self> {
        activation_channel(&descriptor, &channel, ChannelSide::Server)?;
        Ok(Self {
            replay: ReplaySession::new(descriptor.root.context()?),
            descriptor,
            channel,
            image: None,
            acknowledgements: BTreeMap::new(),
            clock: ActivationClock::new(now_ms),
        })
    }
    pub fn receive(&mut self, wire: &[u8], now_ms: u64) -> Result<bool> {
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        let Some((kind, _, bytes)) = self.channel.receive(wire, now_ms)? else {
            return Ok(false);
        };
        match kind {
            PacketKind::InitialImage => {
                let image = SessionImage::decode(&self.descriptor.root, &bytes)?;
                image.validate_initial(&self.descriptor.root)?;
                if let Some(previous) = &self.image {
                    if previous != &bytes {
                        self.clock.failed = true;
                        return Err(Error::Conflict);
                    }
                    return Ok(false);
                }
                if self
                    .acknowledgements
                    .values()
                    .any(|ack| Some(ack.initial) != state_hash(&bytes).ok())
                {
                    self.clock.failed = true;
                    return Err(Error::Conflict);
                }
                self.image = Some(bytes);
            }
            PacketKind::Control => {
                let ack = CapabilityAck::decode(&self.descriptor.root, &bytes)?;
                if self
                    .image
                    .as_ref()
                    .is_some_and(|image| Some(ack.initial) != state_hash(image).ok())
                {
                    self.clock.failed = true;
                    return Err(Error::Conflict);
                }
                let ticket = self.replay.begin(
                    self.descriptor
                        .root
                        .member(ack.player)?
                        .key
                        .ok_or(Error::Unauthorized)?,
                    ack.sequence,
                    &bytes,
                    false,
                )?;
                if let Some(previous) = self.acknowledgements.get(&ack.player) {
                    if previous.initial == ack.initial && previous.sequence == ack.sequence {
                        return Ok(false);
                    }
                    self.clock.failed = true;
                    return Err(Error::Conflict);
                }
                self.acknowledgements.insert(ack.player, ack);
                ticket.commit()?;
            }
            _ => return Err(Error::Unauthorized),
        }
        Ok(self.ready())
    }
    pub fn ready(&self) -> bool {
        !self.clock.failed
            && self.replay.live().is_ok()
            && self.image.is_some()
            && self
                .descriptor
                .root
                .members
                .iter()
                .filter(|m| m.key.is_some())
                .all(|m| self.acknowledgements.contains_key(&m.player))
    }
    pub fn arm(
        mut self,
        keys: &Keys,
        now_ms: u64,
        mut restore: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<(Sequencer, Armed, Channel)> {
        let started = std::time::Instant::now();
        self.replay.live()?;
        self.clock.advance(now_ms)?;
        let remaining = std::time::Duration::from_millis(5000 - (now_ms - self.clock.started));
        if !self.ready() {
            return Err(Error::Gap);
        }
        let image = SessionImage::decode(
            &self.descriptor.root,
            self.image.as_ref().ok_or(Error::Gap)?,
        )?;
        let mut activation = Activation::new_session(self.descriptor.clone(), image)?;
        activation.replay = self.replay;
        for (_, ack) in self.acknowledgements {
            activation.acknowledge(ack)?;
        }
        let restore_replay = activation.replay.clone();
        let (sequencer, armed) = activation.arm(keys, |bytes| {
            for _ in 0..2 {
                restore_replay.live()?;
                if started.elapsed() >= remaining {
                    return Err(Error::Closed);
                }
                if let Ok(Ok(restored)) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| restore(bytes)))
                {
                    if started.elapsed() >= remaining {
                        return Err(Error::Closed);
                    }
                    if restored == bytes {
                        return Ok(restored);
                    }
                }
            }
            Err(Error::Invalid("initial restore equivalence"))
        })?;
        if started.elapsed() >= remaining {
            return Err(Error::Closed);
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).map_err(|_| Error::Bounds)?;
        self.channel
            .expire(now_ms.checked_add(elapsed_ms).ok_or(Error::Bounds)?)?;
        self.channel.enqueue(
            PacketKind::Control,
            &armed.encode(&self.descriptor.root.context()?)?,
        )?;
        // Only the standby can sign membership; the original needs index 0.
        self.channel.enqueue(
            PacketKind::Control,
            &sequencer
                .membership_certificate(keys)?
                .encode(&self.descriptor.root)?,
        )?;
        Ok((sequencer, armed, self.channel))
    }
}

/// Roles are transcript-bound before either endpoint releases application data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum LinkRole {
    Player = 1,
    Original = 2,
    Standby = 3,
    ControlPlayer = 4,
    Successor = 5,
    ResumePlayer = 6,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConnectionBinding {
    pub session: SessionId,
    pub descriptor: Hash,
    pub term: u64,
    pub client: LinkRole,
    pub server: LinkRole,
}
impl ConnectionBinding {
    pub fn validate(&self) -> Result<()> {
        if self.session == [0; 16] || self.descriptor == [0; 32] {
            return Err(Error::Invalid("empty session binding"));
        }
        let valid = matches!(
            (self.term, self.client, self.server),
            (0, LinkRole::Original, LinkRole::Standby)
                | (0, LinkRole::ControlPlayer, LinkRole::Standby)
                | (0, LinkRole::Player, LinkRole::Original)
                | (1, LinkRole::ResumePlayer, LinkRole::Successor)
                | (1, LinkRole::Player, LinkRole::Successor)
        );
        if !valid {
            return Err(Error::Invalid("session link roles/term"));
        }
        Ok(())
    }
    pub(crate) fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = vec![VERSION];
        bytes.extend(self.session);
        bytes.extend(self.descriptor);
        bytes.extend(self.term.to_be_bytes());
        bytes.push(self.client as u8);
        bytes.push(self.server as u8);
        Ok(bytes)
    }
}

/// Transport admission for the fixed pair. Persona/attestation verification is
/// still performed by the owning game before arming and before seat recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointPolicy {
    pub descriptor: Descriptor,
    pub role: LinkRole,
    pub promotion: Option<Promotion>,
    pub membership: Option<MembershipCertificate>,
}
impl EndpointPolicy {
    pub fn player_for_key(&self, key: RuntimeKey) -> Option<u64> {
        match &self.membership {
            Some(c) => c
                .members
                .iter()
                .find(|m| m.key == Some(key))
                .map(|m| m.player),
            None => self
                .descriptor
                .root
                .members
                .iter()
                .find(|m| m.key == Some(key))
                .map(|m| m.player),
        }
    }
    pub fn validate(&self, key: RuntimeKey, code: &str, app: &str) -> Result<()> {
        self.descriptor.verify()?;
        let root = &self.descriptor.root;
        if let Some(certificate) = &self.membership {
            certificate.verify(root)?;
            if certificate.receipt.term > u64::from(self.role == LinkRole::Successor) {
                return Err(Error::Unauthorized);
            }
            if let Some(p) = &self.promotion {
                if certificate.receipt.index < p.final_receipt.index {
                    return Err(Error::Stale);
                }
            }
        }
        if root.code != room_code_hash(code)? || root.app != app {
            return Err(Error::Invalid("endpoint room/app binding"));
        }
        match (self.role, &self.promotion) {
            (LinkRole::Original, None) if key == root.host => Ok(()),
            (LinkRole::Standby, None) if key == root.standby => Ok(()),
            (LinkRole::Successor, Some(p)) if key == root.standby => p.verify(&root.context()?),
            _ => Err(Error::Unauthorized),
        }
    }
    pub fn check_request(&self, binding: &ConnectionBinding) -> Result<()> {
        binding.validate()?;
        let root = &self.descriptor.root;
        if binding.session != root.session
            || binding.descriptor != root.digest()?
            || binding.server != self.role
            || binding.term != u64::from(self.role == LinkRole::Successor)
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub fn authorize(&self, binding: &ConnectionBinding, key: RuntimeKey) -> Result<()> {
        self.check_request(binding)?;
        let player = self.player_for_key(key).is_some();
        let allowed = match (binding.client, self.role) {
            (LinkRole::Original, LinkRole::Standby) => key == self.descriptor.root.host,
            (LinkRole::ControlPlayer, LinkRole::Standby) => {
                player && key != self.descriptor.root.host
            }
            (LinkRole::Player, LinkRole::Original)
            | (LinkRole::ResumePlayer, LinkRole::Successor)
            | (LinkRole::Player, LinkRole::Successor) => player,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
    pub fn passive(&self) -> bool {
        self.role == LinkRole::Standby
    }
}

fn read_control_prefix(r: &mut Reader<'_>, context: &Context, term: u64, kind: u8) -> Result<u64> {
    let expected = control_prefix(context, term, kind, 0);
    if r.take(expected.len() - 8)? != &expected[..expected.len() - 8] {
        return Err(Error::Invalid("control context/term/kind"));
    }
    let sequence = r.u64()?;
    if sequence == 0 {
        return Err(Error::Invalid("control sequence"));
    }
    Ok(sequence)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeChallenge {
    pub player: u64,
    pub sequence: u64,
    pub nonce: [u8; 32],
    pub tls: [u8; 32],
    pub frontier: Receipt,
    pub signature: SignatureBytes,
}
impl ResumeChallenge {
    fn body(&self, context: &Context) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Invalid("challenge sequence"));
        }
        let mut bytes = control_prefix(context, 1, 7, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.nonce);
        bytes.extend(self.tls);
        put_bytes(
            &mut bytes,
            &self.frontier.encode(context)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        Ok(bytes)
    }
    fn digest(&self, context: &Context) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(context)?))
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        let context = root.context()?;
        self.frontier.verify(&context)?;
        if !self
            .frontier
            .watermarks
            .iter()
            .any(|m| m.player == self.player && !m.retired)
        {
            return Err(Error::Unauthorized);
        }
        verify(root.standby, self.digest(&context)?, self.signature)
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.verify(root)?;
        let mut bytes = self.body(&root.context()?)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let context = root.context()?;
        let mut r = Reader(bytes);
        let sequence = read_control_prefix(&mut r, &context, 1, 7)?;
        let player = r.u64()?;
        let nonce = r.array()?;
        let tls = r.array()?;
        let frontier = Receipt::decode(&context, &r.bytes(crate::MAX_RELIABLE_LEN)?)?;
        let challenge = Self {
            player,
            sequence,
            nonce,
            tls,
            frontier,
            signature: r.array()?,
        };
        r.finish()?;
        challenge.verify(root)?;
        Ok(challenge)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeProof {
    pub player: u64,
    pub sequence: u64,
    pub challenge: Hash,
    pub output_ack: u64,
    pub input_tail: u64,
    pub signature: SignatureBytes,
}
impl ResumeProof {
    fn body(&self, context: &Context) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Invalid("resume proof sequence"));
        }
        let mut bytes = control_prefix(context, 1, 8, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.challenge);
        bytes.extend(self.output_ack.to_be_bytes());
        bytes.extend(self.input_tail.to_be_bytes());
        Ok(bytes)
    }
    fn digest(&self, context: &Context) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(context)?))
    }
    pub fn sign(
        root: &Root,
        challenge: &ResumeChallenge,
        tls: [u8; 32],
        output_ack: u64,
        input_tail: u64,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        Self::sign_bound(
            root, None, challenge, tls, output_ack, input_tail, sequence, keys,
        )
    }
    pub fn sign_with_certificate(
        root: &Root,
        membership: &MembershipCertificate,
        challenge: &ResumeChallenge,
        tls: [u8; 32],
        output_ack: u64,
        input_tail: u64,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        Self::sign_bound(
            root,
            Some(membership),
            challenge,
            tls,
            output_ack,
            input_tail,
            sequence,
            keys,
        )
    }
    fn sign_bound(
        root: &Root,
        membership: Option<&MembershipCertificate>,
        challenge: &ResumeChallenge,
        tls: [u8; 32],
        output_ack: u64,
        input_tail: u64,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        challenge.verify(root)?;
        if let Some(m) = membership {
            if m.receipt.index > challenge.frontier.index
                || m.receipt.term > challenge.frontier.term
                || m.receipt.logical_ms > challenge.frontier.logical_ms
            {
                return Err(Error::Stale);
            }
            if m.receipt.index == challenge.frontier.index
                && m.receipt.digest(&root.context()?)?
                    != challenge.frontier.digest(&root.context()?)?
            {
                return Err(Error::Conflict);
            }
        }
        if challenge.tls != tls
            || resume_member(root, membership, challenge.player)?.key
                != Some(keys.public_key().to_bytes())
        {
            return Err(Error::Unauthorized);
        }
        let context = root.context()?;
        let mut proof = Self {
            player: challenge.player,
            sequence,
            challenge: challenge.digest(&context)?,
            output_ack,
            input_tail,
            signature: [0; 64],
        };
        proof.signature = sign(keys, proof.digest(&context)?);
        Ok(proof)
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        self.verify_bound(root, None)
    }
    pub fn verify_with_certificate(
        &self,
        root: &Root,
        membership: &MembershipCertificate,
    ) -> Result<()> {
        self.verify_bound(root, Some(membership))
    }
    fn verify_bound(&self, root: &Root, membership: Option<&MembershipCertificate>) -> Result<()> {
        verify(
            resume_member(root, membership, self.player)?
                .key
                .ok_or(Error::Unauthorized)?,
            self.digest(&root.context()?)?,
            self.signature,
        )
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.encode_bound(root, None)
    }
    pub fn encode_with_certificate(
        &self,
        root: &Root,
        membership: &MembershipCertificate,
    ) -> Result<Vec<u8>> {
        self.encode_bound(root, Some(membership))
    }
    fn encode_bound(
        &self,
        root: &Root,
        membership: Option<&MembershipCertificate>,
    ) -> Result<Vec<u8>> {
        self.verify_bound(root, membership)?;
        let mut bytes = self.body(&root.context()?)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        Self::decode_bound(root, None, bytes)
    }
    pub fn decode_with_certificate(
        root: &Root,
        membership: &MembershipCertificate,
        bytes: &[u8],
    ) -> Result<Self> {
        Self::decode_bound(root, Some(membership), bytes)
    }
    fn decode_bound(
        root: &Root,
        membership: Option<&MembershipCertificate>,
        bytes: &[u8],
    ) -> Result<Self> {
        if bytes.len() > 256 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        let sequence = read_control_prefix(&mut r, &root.context()?, 1, 8)?;
        let proof = Self {
            player: r.u64()?,
            sequence,
            challenge: r.array()?,
            output_ack: r.u64()?,
            input_tail: r.u64()?,
            signature: r.array()?,
        };
        r.finish()?;
        proof.verify_bound(root, membership)?;
        Ok(proof)
    }
}
/// Single-use challenges on prepared, already authenticated control links.
/// The owning game must still run its normal persona/admission verifier before
/// issue(). No join event or seat allocation is authorized by a valid proof.
pub struct ResumeGate {
    membership: Option<MembershipCertificate>,
    descriptor: Descriptor,
    promotion: Promotion,
    last_ms: u64,
    pending: BTreeMap<u64, (ResumeChallenge, u64)>,
    accepted: BTreeMap<u64, (u64, u64)>,
}
fn resume_member(
    root: &Root,
    membership: Option<&MembershipCertificate>,
    player: u64,
) -> Result<Member> {
    if let Some(certificate) = membership {
        certificate.verify(root)?;
        let member = certificate
            .members
            .iter()
            .find(|m| m.player == player)
            .ok_or(Error::Unauthorized)?;
        Ok(Member {
            player: member.player,
            seat: member.seat,
            key: member.key,
        })
    } else {
        Ok(root.member(player)?.clone())
    }
}
impl ResumeGate {
    pub fn new(descriptor: Descriptor, promotion: Promotion) -> Result<Self> {
        descriptor.verify()?;
        promotion.verify(&descriptor.root.context()?)?;
        Ok(Self {
            membership: None,
            descriptor,
            promotion,
            last_ms: 0,
            pending: BTreeMap::new(),
            accepted: BTreeMap::new(),
        })
    }
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        if now_ms < self.last_ms {
            return Err(Error::Invalid("backwards resume clock"));
        }
        self.last_ms = now_ms;
        self.pending.retain(|_, (_, expires)| *expires > now_ms);
        Ok(())
    }
    pub fn with_certificate(
        descriptor: Descriptor,
        promotion: Promotion,
        membership: MembershipCertificate,
    ) -> Result<Self> {
        membership.verify(&descriptor.root)?;
        if membership.receipt != promotion.final_receipt {
            return Err(Error::Stale);
        }
        let mut gate = Self::new(descriptor, promotion)?;
        gate.membership = Some(membership);
        Ok(gate)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        connection: u64,
        tls: [u8; 32],
        player: u64,
        authenticated_key: RuntimeKey,
        current: &Sequencer,
        now_ms: u64,
        keys: &Keys,
    ) -> Result<ResumeChallenge> {
        let root = &self.descriptor.root;
        let context = root.context()?;
        if keys.public_key().to_bytes() != root.standby
            || resume_member(root, self.membership.as_ref(), player)?.key != Some(authenticated_key)
        {
            return Err(Error::Unauthorized);
        }
        if current.context() != &context || current.promotion.as_ref() != Some(&self.promotion) {
            return Err(Error::Unauthorized);
        }
        let frontier = current.receipt().clone();
        frontier.verify(&context)?;
        if frontier.index < self.promotion.final_receipt.index
            || frontier.index == self.promotion.final_receipt.index
                && frontier != self.promotion.final_receipt
        {
            return Err(Error::Stale);
        }
        let sequence = current.sender.allocate()?;
        let expires = now_ms.checked_add(5000).ok_or(Error::Bounds)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Invalid("resume RNG"))?;
        let mut challenge = ResumeChallenge {
            player,
            sequence,
            nonce,
            tls,
            frontier,
            signature: [0; 64],
        };
        challenge.signature = sign(keys, challenge.digest(&context)?);
        challenge.verify(root)?;
        self.advance(now_ms)?;
        // Reissuing to the same player invalidates its previous connection's
        // nonce. At most eight surviving player challenges occupy memory.
        if self.pending.len() >= MAX_PLAYERS
            && !self.pending.contains_key(&connection)
            && !self.pending.values().any(|(c, _)| c.player == player)
        {
            return Err(Error::Bounds);
        }
        self.pending.retain(|_, (c, _)| c.player != player);
        self.pending
            .insert(connection, (challenge.clone(), expires));
        Ok(challenge)
    }
    /// Compare the current sequencer atomically with challenge issuance. Any
    /// intervening commit invalidates the challenge; issue a fresh one. Accepted
    /// client cuts survive nonce/connection replacement and cannot regress.
    pub fn consume(
        &mut self,
        connection: u64,
        tls: [u8; 32],
        proof: &ResumeProof,
        current: &Sequencer,
        now_ms: u64,
    ) -> Result<()> {
        current.sender.replay.live()?;
        self.advance(now_ms)?;
        let (challenge, _) = self.pending.get(&connection).ok_or(Error::Stale)?;
        if current.context() != &self.descriptor.root.context()?
            || current.promotion.as_ref() != Some(&self.promotion)
        {
            return Err(Error::Unauthorized);
        }
        if current.receipt() != &challenge.frontier {
            return Err(Error::Stale);
        }
        proof.verify_bound(&self.descriptor.root, self.membership.as_ref())?;
        if proof.player != challenge.player
            || tls != challenge.tls
            || proof.challenge != challenge.digest(&self.descriptor.root.context()?)?
        {
            return Err(Error::Unauthorized);
        }
        let root = &self.descriptor.root;
        let issuer = resume_member(root, self.membership.as_ref(), proof.player)?
            .key
            .ok_or(Error::Unauthorized)?;
        let incoming = current.sender.replay.begin(
            issuer,
            proof.sequence,
            &proof.encode_bound(root, self.membership.as_ref())?,
            false,
        )?;
        let mark = challenge
            .frontier
            .watermarks
            .iter()
            .find(|m| m.player == proof.player && !m.retired)
            .ok_or(Error::Unauthorized)?;
        if proof.output_ack < mark.output_ack
            || proof.output_ack > current.output_ceiling(proof.player)
            || proof.input_tail < mark.input
        {
            return Err(Error::Invalid("lost/inconsistent retained journal"));
        }
        if proof.input_tail - mark.input > MAX_JOURNAL_RECORDS as u64 {
            return Err(Error::Bounds);
        }
        if self
            .accepted
            .get(&proof.player)
            .is_some_and(|(ack, tail)| proof.output_ack < *ack || proof.input_tail < *tail)
        {
            return Err(Error::Invalid("retained recovery cut regressed"));
        }
        incoming.commit()?;
        self.accepted
            .insert(proof.player, (proof.output_ack, proof.input_tail));
        self.pending.remove(&connection);
        Ok(())
    }
}

/// Host-side intent history is captured in the game's complete runner image.
/// It is distinct from the surviving client's original-payload send journal.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HandledInputs {
    handled: u64,
    #[serde(deserialize_with = "bounded_deque::<_,_,512>")]
    recent: VecDeque<(u64, Hash)>,
}
fn bounded_deque<'de, D, T, const N: usize>(d: D) -> std::result::Result<VecDeque<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    bounded_vec::<'de, D, T, N>(d).map(VecDeque::from)
}
impl HandledInputs {
    pub fn handled(&self) -> u64 {
        self.handled
    }
    pub fn validate(&self) -> Result<()> {
        if self.recent.len() != self.handled.min(MAX_JOURNAL_RECORDS as u64) as usize {
            return Err(Error::Invalid("input history length"));
        }
        let first = self.handled.saturating_sub(self.recent.len() as u64) + 1;
        if self
            .recent
            .iter()
            .enumerate()
            .any(|(i, (n, _))| *n != first + i as u64)
        {
            return Err(Error::Invalid("input history order"));
        }
        Ok(())
    }
    pub fn check(&self, sequence: u64, bytes: &[u8]) -> Result<bool> {
        if sequence == 0 || bytes.len() > crate::MAX_RELIABLE_LEN {
            return Err(Error::Bounds);
        }
        let digest = hash(b"fray/migration/intent/v1\0", bytes);
        if sequence <= self.handled {
            if self
                .recent
                .iter()
                .any(|(n, h)| *n == sequence && *h != digest)
            {
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
        if sequence != self.handled.checked_add(1).ok_or(Error::Bounds)? {
            return Err(Error::Gap);
        }
        Ok(true)
    }
    pub fn record(&mut self, sequence: u64, bytes: &[u8]) -> Result<bool> {
        if !self.check(sequence, bytes)? {
            return Ok(false);
        }
        self.handled = sequence;
        self.recent
            .push_back((sequence, hash(b"fray/migration/intent/v1\0", bytes)));
        if self.recent.len() > MAX_JOURNAL_RECORDS {
            self.recent.pop_front();
        }
        Ok(true)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPhase {
    Collecting,
    Security,
    Replay,
    AwaitCuts,
    Draining,
    Departures,
    Ready,
    Failed,
}
#[derive(Clone, Debug)]
struct Survivor {
    remote_tls: Option<[u8; 32]>,
    applied: u64,
    tail: u64,
    sealed: Option<u64>,
    pending: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
}
/// Actual retained journals of a restored bot or the standby's own client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRecoveryCut {
    pub player: u64,
    pub applied: u64,
    pub tail: u64,
}
/// Owns the same sequencer which closes term0. No timer or network callback can
/// replace it. Game time stays at C through cohort sealing, committed replay,
/// stable-player journal drains and only then missing-player departure.
pub struct Recovery {
    descriptor: Descriptor,
    sequencer: Sequencer,
    gate: ResumeGate,
    promotion: Promotion,
    histories: BTreeMap<u64, HandledInputs>,
    survivors: BTreeMap<u64, Survivor>,
    input_rounds: BTreeMap<u64, (InputRound, Option<PlayerControl>)>,
    phase: RecoveryPhase,
    started: u64,
    security_anchor: u64,
    last_ms: u64,
    /// Holds the survivor collection window open across one local stall.
    grace: StallGrace,
    applications: usize,
    departed: bool,
}
impl Recovery {
    pub fn begin_session(
        descriptor: Descriptor,
        sequencer: Sequencer,
        keys: &Keys,
        now_ms: u64,
    ) -> Result<Self> {
        if sequencer.session_root.is_none() {
            return Err(Error::Invalid("recovery requires session envelope"));
        }
        let histories = SessionImage::decode(&descriptor.root, sequencer.image())?.inputs;
        Self::begin(descriptor, sequencer, histories, keys, now_ms)
    }
    pub fn begin(
        descriptor: Descriptor,
        mut sequencer: Sequencer,
        histories: BTreeMap<u64, HandledInputs>,
        keys: &Keys,
        now_ms: u64,
    ) -> Result<Self> {
        descriptor.verify()?;
        if sequencer.promotion.is_some() {
            return Err(Error::Closed);
        }
        if sequencer.context() != &descriptor.root.context()? {
            return Err(Error::Unauthorized);
        }
        let active: BTreeSet<_> = sequencer
            .receipt()
            .watermarks
            .iter()
            .filter(|m| !m.retired)
            .map(|m| m.player)
            .collect();
        if histories.keys().copied().collect::<BTreeSet<_>>() != active {
            return Err(Error::Invalid("restored input history membership"));
        }
        for (&player, history) in &histories {
            history.validate()?;
            if sequencer
                .receipt()
                .watermarks
                .iter()
                .find(|m| m.player == player)
                .map(|m| m.input)
                != Some(history.handled())
            {
                return Err(Error::Invalid("restored input watermark"));
            }
        }
        if sequencer.session_root.is_some()
            && SessionImage::decode(&descriptor.root, sequencer.image())?.inputs != histories
        {
            return Err(Error::Conflict);
        }
        let promotion = sequencer.promote(keys)?;
        let gate = if sequencer.session_root.is_some() {
            ResumeGate::with_certificate(
                descriptor.clone(),
                promotion.clone(),
                sequencer.membership_certificate(keys)?,
            )?
        } else {
            ResumeGate::new(descriptor.clone(), promotion.clone())?
        };
        Ok(Self {
            descriptor,
            sequencer,
            gate,
            promotion,
            histories,
            survivors: BTreeMap::new(),
            input_rounds: BTreeMap::new(),
            phase: RecoveryPhase::Collecting,
            started: now_ms,
            security_anchor: now_ms,
            last_ms: now_ms,
            grace: StallGrace::new(),
            applications: 0,
            departed: false,
        })
    }
    pub fn phase(&self) -> RecoveryPhase {
        self.phase
    }
    pub fn promotion(&self) -> &Promotion {
        &self.promotion
    }
    pub fn sequencer(&self) -> &Sequencer {
        &self.sequencer
    }
    pub fn root(&self) -> &Root {
        &self.descriptor.root
    }
    pub fn elapsed_ms(&self) -> u64 {
        self.last_ms - self.started
    }
    /// Authentication ages through the pre-promotion stall as well as causal
    /// recovery. The owned standby anchors this to its last game-clock commit;
    /// ACK-only commits and liveness traffic cannot postpone that anchor.
    pub fn security_elapsed_ms(&self) -> u64 {
        self.last_ms - self.security_anchor
    }
    /// Input callbacks use these ACK cuts when validating their complete
    /// session image. They cannot acknowledge newly emitted output.
    pub fn reconciled_watermarks(&self) -> Vec<Watermark> {
        let mut marks = self.sequencer.receipt().watermarks.clone();
        for mark in &mut marks {
            if let Some(survivor) = self.survivors.get(&mark.player) {
                mark.output_ack = survivor.applied;
            }
        }
        marks
    }
    pub fn histories(&self) -> &BTreeMap<u64, HandledInputs> {
        &self.histories
    }
    pub fn logical_ms(&self) -> u64 {
        self.promotion.final_receipt.logical_ms
    }
    pub fn poll(&mut self, now_ms: u64) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if self.phase == RecoveryPhase::Failed {
            return Err(Error::Closed);
        }
        if now_ms < self.last_ms {
            return Err(Error::Invalid("backwards recovery wall clock"));
        }
        // A local stall is not peer silence: proofs that arrived during it
        // are read after it. Only a stall that began while the window was
        // open and a challenge was unanswered can have hidden one. The
        // window then stays open until 200 ms after the stall, once.
        if self.phase == RecoveryPhase::Collecting && self.collecting(self.last_ms) {
            let probe = (!self.gate.pending.is_empty()).then_some(self.last_ms);
            self.grace.sample(self.last_ms, now_ms, probe, self.last_ms);
        }
        self.last_ms = now_ms;
        if self.phase != RecoveryPhase::Ready && now_ms.saturating_sub(self.started) >= 5000 {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Invalid("recovery deadline"));
        }
        Ok(())
    }
    /// The 250 ms survivor collection window from promotion, extended
    /// across at most one local stall.
    fn collecting(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started) < 250 || self.grace.holds(now_ms)
    }
    fn require(&self, phase: RecoveryPhase) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if self.phase == phase {
            Ok(())
        } else {
            Err(Error::Invalid("recovery phase"))
        }
    }
    pub fn challenge(
        &mut self,
        connection: u64,
        tls: [u8; 32],
        player: u64,
        key: RuntimeKey,
        keys: &Keys,
        now_ms: u64,
    ) -> Result<ResumeChallenge> {
        self.poll(now_ms)?;
        self.require(RecoveryPhase::Collecting)?;
        if !self.collecting(now_ms) {
            return Err(Error::Closed);
        }
        self.gate
            .issue(connection, tls, player, key, &self.sequencer, now_ms, keys)
    }
    pub fn accept(
        &mut self,
        connection: u64,
        tls: [u8; 32],
        proof: &ResumeProof,
        now_ms: u64,
    ) -> Result<()> {
        self.poll(now_ms)?;
        self.require(RecoveryPhase::Collecting)?;
        if !self.collecting(now_ms) {
            return Err(Error::Closed);
        }
        self.gate
            .consume(connection, tls, proof, &self.sequencer, now_ms)?;
        self.retain(proof.player, proof.output_ack, proof.input_tail)?;
        self.survivors.get_mut(&proof.player).unwrap().remote_tls = Some(tls);
        Ok(())
    }
    /// Only restored bots or this standby's retained player can be local.
    /// They are not reached over a control path, so no peer can be late and
    /// the collection window does not apply: retain them any time before
    /// `seal`.
    pub fn retain_local(
        &mut self,
        player: u64,
        applied: u64,
        tail: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.poll(now_ms)?;
        self.require(RecoveryPhase::Collecting)?;
        let key = resume_member(&self.descriptor.root, self.gate.membership.as_ref(), player)?.key;
        if key.is_some_and(|key| key != self.descriptor.root.standby) {
            return Err(Error::Unauthorized);
        }
        self.retain(player, applied, tail)
    }
    fn retain(&mut self, player: u64, applied: u64, tail: u64) -> Result<()> {
        let history = self.histories.get(&player).ok_or(Error::Unauthorized)?;
        let mark = self
            .sequencer
            .receipt()
            .watermarks
            .iter()
            .find(|m| m.player == player && !m.retired)
            .ok_or(Error::Unauthorized)?;
        if applied < mark.output_ack
            || applied > self.sequencer.output_ceiling(player)
            || tail < history.handled()
            || tail - history.handled() > MAX_JOURNAL_RECORDS as u64
        {
            return Err(Error::Invalid("survivor retained cuts"));
        }
        if let Some(old) = self.survivors.get(&player) {
            if applied < old.applied || tail < old.tail {
                return Err(Error::Conflict);
            }
        }
        self.survivors.insert(
            player,
            Survivor {
                remote_tls: None,
                applied,
                tail,
                sealed: None,
                pending: BTreeMap::new(),
                bytes: 0,
            },
        );
        Ok(())
    }
    pub fn seal(&mut self, now_ms: u64) -> Result<bool> {
        self.poll(now_ms)?;
        self.require(RecoveryPhase::Collecting)?;
        if self.survivors.len() != self.histories.len() && self.collecting(now_ms) {
            return Ok(false);
        }
        for &player in self.histories.keys() {
            let member =
                resume_member(&self.descriptor.root, self.gate.membership.as_ref(), player)?;
            if (member.key.is_none() || member.key == Some(self.descriptor.root.standby))
                && !self.survivors.contains_key(&player)
            {
                self.phase = RecoveryPhase::Failed;
                return Err(Error::Invalid("restored local client state missing"));
            }
        }
        self.phase = if self.sequencer.session_root.is_some() {
            RecoveryPhase::Security
        } else {
            RecoveryPhase::Replay
        };
        Ok(true)
    }
    /// Commit the native game's conservative security reset once, after the
    /// exact checkpoint and survivor cuts have been retained. This cannot
    /// publish game effects, change the envelope or move the frozen clock.
    pub fn revalidate_security(
        &mut self,
        keys: &Keys,
        now_ms: u64,
        mut game: impl FnMut(&[u8], &SecurityBoundary) -> Result<Vec<u8>>,
    ) -> Result<Receipt> {
        let started = std::time::Instant::now();
        self.poll(now_ms)?;
        self.require(RecoveryPhase::Security)?;
        if keys.public_key().to_bytes() != self.descriptor.root.standby {
            return Err(Error::Unauthorized);
        }
        let root = self.descriptor.root.clone();
        let original = self.sequencer.image().to_vec();
        let previous = SessionImage::decode(&root, &original)?;
        let boundary = SecurityBoundary {
            fence: self.promotion.final_receipt.digest(&root.context()?)?,
            tails: self
                .survivors
                .iter()
                .map(|(player, s)| (*player, s.tail))
                .collect(),
        };
        if previous.security_boundary.is_some()
            || self.sequencer.receipt() != &self.promotion.final_receipt
        {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Conflict);
        }
        if self.applications >= 4096 {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        let mut sized = previous.clone();
        sized.security_boundary = Some(boundary.clone());
        if let Err(error) = sized.encode(&root).and_then(|bytes| {
            check_install_budget(
                self.sequencer.context(),
                bytes.len(),
                self.sequencer.receipt(),
                &self.sequencer.outbox,
                &self.sequencer.allocated,
                &self.sequencer.retired,
            )
        }) {
            self.phase = RecoveryPhase::Failed;
            return Err(error);
        }
        let mut result = Err(Error::Invalid("security revalidation fault"));
        for _ in 0..2 {
            if now_ms.saturating_sub(self.started) as u128 + started.elapsed().as_millis() >= 5000 {
                self.phase = RecoveryPhase::Failed;
                return Err(Error::Invalid("recovery deadline"));
            }
            if let Err(error) = self.sequencer.sender.replay.live() {
                self.phase = RecoveryPhase::Failed;
                return Err(error);
            }
            result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                game(&original, &boundary)
            }))
            .unwrap_or(Err(Error::Invalid("security revalidation panic")));
            if result.is_ok() {
                break;
            }
        }
        let commit = (|| {
            self.sequencer.sender.replay.live()?;
            if now_ms.saturating_sub(self.started) as u128 + started.elapsed().as_millis() >= 5000 {
                return Err(Error::Invalid("recovery deadline"));
            }
            let bytes = result?;
            let mut post = SessionImage::decode(&root, &bytes)?;
            let mut envelope = post.clone();
            envelope.game = previous.game.clone();
            if envelope != previous {
                return Err(Error::Conflict);
            }
            post.security_boundary = Some(boundary);
            let candidate = self.sequencer.next(
                post.encode(&root)?,
                self.logical_ms(),
                self.sequencer.receipt().watermarks.clone(),
                vec![],
            )?;
            let staged = self.sequencer.stage(candidate)?;
            self.sequencer.install(staged, keys)
        })();
        match commit {
            Ok(receipt) => {
                self.applications += 1;
                self.phase = RecoveryPhase::Replay;
                Ok(receipt)
            }
            Err(error) => {
                self.phase = RecoveryPhase::Failed;
                Err(error)
            }
        }
    }
    /// Replays contain the original commit/proof and original per-player ID.
    /// Retransmitting this list does not consume another application budget.
    pub fn replay(&self) -> Result<Vec<CertifiedOutput>> {
        self.sequencer.sender.replay.live()?;
        if !matches!(self.phase, RecoveryPhase::Replay | RecoveryPhase::Draining) {
            return Err(Error::Invalid("replay before cohort seal"));
        }
        Ok(self
            .sequencer
            .outbox()
            .filter(|record| {
                self.survivors
                    .get(&record.output.recipient)
                    .is_some_and(|s| record.output.sequence > s.applied)
            })
            .cloned()
            .collect())
    }
    pub fn acknowledge_outputs(&mut self, player: u64, applied: u64) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if !matches!(self.phase, RecoveryPhase::Replay | RecoveryPhase::Draining) {
            return Err(Error::Invalid("recovery output acknowledgement phase"));
        }
        let ceiling = self.sequencer.output_ceiling(player);
        let survivor = self.survivors.get_mut(&player).ok_or(Error::Unauthorized)?;
        if applied < survivor.applied || applied > ceiling {
            return Err(Error::Invalid("recovery output acknowledgement"));
        }
        let count = usize::try_from(applied - survivor.applied).map_err(|_| Error::Bounds)?;
        let applications = self.applications.checked_add(count).ok_or(Error::Bounds)?;
        if applications > 4096 {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        survivor.applied = applied;
        self.applications = applications;
        Ok(())
    }
    fn delivered(&self) -> bool {
        self.survivors
            .iter()
            .all(|(&p, s)| s.applied == self.sequencer.output_ceiling(p))
    }
    pub fn commit_delivery_acks(&mut self, keys: &Keys) -> Result<Option<Receipt>> {
        self.sequencer.sender.replay.live()?;
        if !matches!(self.phase, RecoveryPhase::Replay | RecoveryPhase::Draining) {
            return Err(Error::Invalid("recovery output commit phase"));
        }
        let mut marks = self.sequencer.receipt().watermarks.clone();
        let mut changed = false;
        for mark in &mut marks {
            if let Some(s) = self.survivors.get(&mark.player) {
                if mark.output_ack != s.applied {
                    mark.output_ack = s.applied;
                    changed = true;
                }
            }
        }
        if !changed {
            return Ok(None);
        }
        let candidate = self.sequencer.next(
            self.sequencer.image().to_vec(),
            self.logical_ms(),
            marks,
            vec![],
        )?;
        let staged = self.sequencer.stage(candidate)?;
        Ok(Some(self.sequencer.install(staged, keys)?))
    }
    pub fn begin_round(&mut self) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if !matches!(self.phase, RecoveryPhase::Replay | RecoveryPhase::Draining)
            || !self.delivered()
        {
            return Err(Error::Gap);
        }
        if self.phase == RecoveryPhase::Draining
            && self
                .survivors
                .iter()
                .any(|(&p, s)| s.sealed != Some(self.histories[&p].handled()))
        {
            return Err(Error::Gap);
        }
        if self.survivors.iter().any(|(&p, s)| {
            self.sequencer
                .receipt()
                .watermarks
                .iter()
                .find(|m| m.player == p)
                .map(|m| m.output_ack)
                != Some(s.applied)
        }) {
            return Err(Error::Gap);
        }
        self.input_rounds.clear();
        for s in self.survivors.values_mut() {
            s.sealed = None;
        }
        self.phase = if self.survivors.is_empty() {
            if self.departed {
                RecoveryPhase::Ready
            } else {
                RecoveryPhase::Departures
            }
        } else {
            RecoveryPhase::AwaitCuts
        };
        Ok(())
    }
    /// A remote survivor seals each new whole-tail round against a fresh nonce
    /// on its authenticated connection. Local bot journals use seal_inputs.
    pub fn issue_input_round(
        &mut self,
        player: u64,
        tls: [u8; 32],
        keys: &Keys,
        now_ms: u64,
    ) -> Result<InputRound> {
        self.poll(now_ms)?;
        let sequence = self.sequencer.sender.allocate()?;
        self.require(RecoveryPhase::AwaitCuts)?;
        if self
            .survivors
            .get(&player)
            .is_none_or(|s| s.sealed.is_some())
        {
            return Err(Error::Unauthorized);
        }
        let membership = self.sequencer.membership_certificate(keys)?;
        let request = InputRound::issue(
            &self.descriptor.root,
            &self.promotion,
            membership,
            player,
            tls,
            sequence,
            keys,
        )?;
        self.input_rounds.insert(player, (request.clone(), None));
        Ok(request)
    }
    pub fn accept_input_cut(
        &mut self,
        record: &PlayerControl,
        tls: [u8; 32],
        now_ms: u64,
    ) -> Result<()> {
        self.poll(now_ms)?;
        let (request, accepted) = self
            .input_rounds
            .get(&record.player)
            .cloned()
            .ok_or(Error::Stale)?;
        record.verify(
            &self.descriptor.root,
            &request.membership,
            record.player,
            tls,
            1,
        )?;
        if tls != request.tls {
            return Err(Error::Unauthorized);
        }
        let issuer = request
            .membership
            .members
            .iter()
            .find(|member| member.player == record.player)
            .and_then(|member| member.key)
            .ok_or(Error::Unauthorized)?;
        let cached = accepted
            .as_ref()
            .filter(|old| old.sequence == record.sequence);
        if cached.is_some_and(|old| old != record) {
            self.sequencer.sender.replay.fail();
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Conflict);
        }
        let incoming = self.sequencer.sender.replay.begin(
            issuer,
            record.sequence,
            &record.encode(&self.descriptor.root)?,
            cached.is_some(),
        )?;
        let PlayerAction::Applied {
            output,
            tail,
            cut: Some(nonce),
        } = record.action
        else {
            return Err(Error::Unauthorized);
        };
        if nonce != request.nonce {
            return Err(Error::Stale);
        }
        if let Some(old) = accepted {
            if old.action != record.action {
                self.sequencer.sender.replay.fail();
                self.phase = RecoveryPhase::Failed;
                return Err(Error::Conflict);
            }
            incoming.commit()?;
            return Ok(());
        }
        self.require(RecoveryPhase::AwaitCuts)?;
        if request
            .membership
            .receipt
            .digest(&self.descriptor.root.context()?)?
            != self
                .sequencer
                .receipt()
                .digest(&self.descriptor.root.context()?)?
            || self
                .survivors
                .get(&record.player)
                .is_none_or(|s| s.applied != output)
            || self.sequencer.output_ceiling(record.player) != output
        {
            return Err(Error::Stale);
        }
        self.seal_inputs_inner(record.player, tail)?;
        incoming.commit()?;
        self.input_rounds.get_mut(&record.player).unwrap().1 = Some(record.clone());
        Ok(())
    }
    /// Authenticated remote controls use the TLS identity retained by the
    /// accepted ResumeProof and the current committed roster. The transport
    /// supplies tls; it must never be copied from the untrusted record.
    pub fn accept_player_control(
        &mut self,
        record: &PlayerControl,
        tls: [u8; 32],
        now_ms: u64,
    ) -> Result<bool> {
        self.poll(now_ms)?;
        let root = &self.descriptor.root;
        let membership = self
            .sequencer
            .membership
            .as_ref()
            .ok_or(Error::Invalid("recovery control requires typed session"))?;
        record.verify(root, membership, record.player, tls, 1)?;
        let survivor = self
            .survivors
            .get(&record.player)
            .ok_or(Error::Unauthorized)?;
        if survivor.remote_tls != Some(tls) {
            return Err(Error::Unauthorized);
        }
        if matches!(record.action, PlayerAction::Applied { cut: Some(_), .. }) {
            self.accept_input_cut(record, tls, now_ms)?;
            return Ok(true);
        }
        let issuer = membership
            .members
            .iter()
            .find(|m| m.player == record.player)
            .and_then(|m| m.key)
            .ok_or(Error::Unauthorized)?;
        // Original payload history remains authoritative when an exact wire
        // retry has aged out of the common control window. It can only confirm
        // work already retained/handled, never admit a previously unseen input.
        let archived = if let PlayerAction::Intent { number, bytes } = &record.action {
            let known = if *number <= self.histories[&record.player].handled() {
                self.histories[&record.player]
                    .check(*number, bytes)
                    .map(|_| true)
            } else if let Some(old) = survivor.pending.get(number) {
                if old == bytes {
                    Ok(true)
                } else {
                    Err(Error::Conflict)
                }
            } else {
                Ok(false)
            };
            match known {
                Ok(known) => known,
                Err(error) => {
                    self.sequencer.sender.replay.fail();
                    self.phase = RecoveryPhase::Failed;
                    return Err(error);
                }
            }
        } else {
            false
        };
        let incoming = self.sequencer.sender.replay.begin(
            issuer,
            record.sequence,
            &record.encode(root)?,
            archived,
        )?;
        if !incoming.is_new() {
            incoming.commit()?;
            return Ok(false);
        }
        match &record.action {
            PlayerAction::Intent { number, bytes } => {
                if self
                    .input_rounds
                    .get(&record.player)
                    .is_none_or(|(_, accepted)| accepted.is_none())
                {
                    return Err(Error::Gap);
                }
                self.supply(record.player, *number, bytes.clone())?;
            }
            PlayerAction::Applied {
                output,
                tail,
                cut: None,
            } => {
                let handled = self
                    .histories
                    .get(&record.player)
                    .ok_or(Error::Unauthorized)?
                    .handled();
                if *tail < handled || *tail - handled > MAX_JOURNAL_RECORDS as u64 {
                    return Err(Error::Bounds);
                }
                self.acknowledge_outputs(record.player, *output)?;
            }
            _ => return Err(Error::Unauthorized),
        }
        incoming.commit()?;
        Ok(true)
    }
    /// Only a restored bot or this standby's retained local client may supply
    /// a cut directly. Remote humans must use the signed fresh-round exchange.
    pub fn seal_inputs(&mut self, player: u64, tail: u64) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        let key = resume_member(&self.descriptor.root, self.gate.membership.as_ref(), player)?.key;
        if key.is_some_and(|key| key != self.descriptor.root.standby) {
            return Err(Error::Unauthorized);
        }
        self.seal_inputs_inner(player, tail)
    }
    fn seal_inputs_inner(&mut self, player: u64, tail: u64) -> Result<()> {
        self.require(RecoveryPhase::AwaitCuts)?;
        let survivor = self.survivors.get_mut(&player).ok_or(Error::Unauthorized)?;
        let handled = self.histories[&player].handled();
        if tail < survivor.tail || tail < handled || tail - handled > MAX_JOURNAL_RECORDS as u64 {
            return Err(Error::Invalid("recovery input tail"));
        }
        if survivor.sealed.is_some_and(|previous| previous != tail) {
            return Err(Error::Conflict);
        }
        survivor.tail = tail;
        survivor.sealed = Some(tail);
        if self.survivors.values().all(|s| s.sealed.is_some()) {
            self.phase = if self
                .survivors
                .iter()
                .all(|(&p, s)| s.sealed == Some(self.histories[&p].handled()))
            {
                if self.departed {
                    RecoveryPhase::Ready
                } else {
                    RecoveryPhase::Departures
                }
            } else {
                RecoveryPhase::Draining
            };
        }
        Ok(())
    }
    pub fn supply(&mut self, player: u64, sequence: u64, bytes: Vec<u8>) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if !matches!(
            self.phase,
            RecoveryPhase::AwaitCuts | RecoveryPhase::Draining
        ) {
            return Err(Error::Invalid("recovery input supply phase"));
        }
        if !self.survivors.contains_key(&player) {
            return Err(Error::Unauthorized);
        }
        let history = self.histories.get(&player).ok_or(Error::Unauthorized)?;
        if sequence <= history.handled() {
            if let Err(error) = history.check(sequence, &bytes) {
                if error == Error::Conflict {
                    self.sequencer.sender.replay.fail();
                    self.phase = RecoveryPhase::Failed;
                }
                return Err(error);
            }
            return Ok(());
        }
        let s = self.survivors.get_mut(&player).ok_or(Error::Unauthorized)?;
        if sequence > s.tail || bytes.len() > crate::MAX_RELIABLE_LEN {
            return Err(Error::Bounds);
        }
        if let Some(old) = s.pending.get(&sequence) {
            return if old == &bytes {
                Ok(())
            } else {
                self.sequencer.sender.replay.fail();
                self.phase = RecoveryPhase::Failed;
                Err(Error::Conflict)
            };
        }
        let size = s.bytes.checked_add(bytes.len()).ok_or(Error::Bounds)?;
        if s.pending.len() >= MAX_JOURNAL_RECORDS || size > MAX_JOURNAL_BYTES {
            return Err(Error::Bounds);
        }
        s.bytes = size;
        s.pending.insert(sequence, bytes);
        Ok(())
    }
    pub fn next_input(&self) -> Result<Option<(u64, u64, &[u8])>> {
        self.require(RecoveryPhase::Draining)?;
        if !self.delivered() {
            return Err(Error::Gap);
        }
        for (&player, s) in &self.survivors {
            let history = &self.histories[&player];
            if history.handled() < s.sealed.ok_or(Error::Gap)? {
                let sequence = history.handled().checked_add(1).ok_or(Error::Bounds)?;
                return Ok(Some((
                    player,
                    sequence,
                    s.pending.get(&sequence).ok_or(Error::Gap)?.as_slice(),
                )));
            }
        }
        Ok(None)
    }
    /// Each invocation receives the same original bytes and C. The adapter
    /// stages on a fresh restored game, so a failed attempt exposes no effect.
    /// Retry an authority fault once; a repeat fault stays permanently paused.
    pub fn apply_next(
        &mut self,
        keys: &Keys,
        mut game: impl FnMut(
            u64,
            u64,
            &[u8],
            &BTreeMap<u64, HandledInputs>,
        ) -> Result<(Vec<u8>, Vec<Output>)>,
    ) -> Result<Receipt> {
        let (player, sequence, bytes) = self
            .next_input()?
            .map(|(p, n, b)| (p, n, b.to_vec()))
            .ok_or(Error::Gap)?;
        if self.applications >= 4096 {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        let mut histories = self.histories.clone();
        histories
            .get_mut(&player)
            .unwrap()
            .record(sequence, &bytes)?;
        let mut result = Err(Error::Invalid("authority recovery fault"));
        for _ in 0..2 {
            self.sequencer.sender.replay.live()?;
            result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                game(player, self.logical_ms(), &bytes, &histories)
            }))
            .unwrap_or(Err(Error::Invalid("authority recovery panic")));
            if result.is_ok() {
                break;
            }
        }
        let (image, outputs) = match result {
            Ok(value) => value,
            Err(error) => {
                self.phase = RecoveryPhase::Failed;
                return Err(error);
            }
        };
        if self
            .applications
            .checked_add(1 + outputs.len())
            .is_none_or(|n| n > 4096)
        {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        let lossy = outputs
            .iter()
            .filter(|o| o.delivery == Delivery::Lossy)
            .count();
        let mut marks = self.reconciled_watermarks();
        marks.iter_mut().find(|m| m.player == player).unwrap().input = sequence;
        let mut retired = BTreeSet::new();
        if self.sequencer.session_root.is_some() {
            let post = match SessionImage::decode(&self.descriptor.root, &image) {
                Ok(post) => post,
                Err(error) => {
                    self.phase = RecoveryPhase::Failed;
                    return Err(error);
                }
            };
            for mark in &mut marks {
                if !mark.retired && !post.members.iter().any(|m| m.player == mark.player) {
                    mark.retired = true;
                    retired.insert(mark.player);
                }
            }
            // A retained input may leave its own seat. It cannot turn a
            // reliable cause into arbitrary cohort eviction or new admission.
            if retired.iter().any(|p| *p != player)
                || (!retired.is_empty() && self.survivors[&player].sealed != Some(sequence))
            {
                self.phase = RecoveryPhase::Failed;
                return Err(Error::Unauthorized);
            }
            histories.retain(|p, _| !retired.contains(p));
            if post.inputs != histories {
                self.phase = RecoveryPhase::Failed;
                return Err(Error::Conflict);
            }
        }
        let commit = (|| {
            let candidate = self
                .sequencer
                .next(image, self.logical_ms(), marks, outputs)?;
            let staged = self.sequencer.stage(candidate)?;
            self.sequencer.install(staged, keys)
        })();
        let receipt = match commit {
            Ok(receipt) => receipt,
            Err(error) => {
                self.phase = RecoveryPhase::Failed;
                return Err(error);
            }
        };
        self.histories = histories;
        if retired.contains(&player) {
            self.survivors.remove(&player);
        } else {
            let s = self.survivors.get_mut(&player).unwrap();
            s.bytes -= s.pending.remove(&sequence).unwrap().len();
        }
        self.applications += 1 + lossy;
        Ok(receipt)
    }
    /// Commit private local-client restoration/delivery and authority rebinding
    /// at C. This is not a tick or a new admission. Bot followups keep their
    /// original journals and become inputs only in the next sealed round.
    pub fn commit_local_clients(
        &mut self,
        keys: &Keys,
        mut game: impl FnMut(
            &BTreeMap<u64, HandledInputs>,
        ) -> Result<(Vec<u8>, Vec<Output>, Vec<LocalRecoveryCut>)>,
    ) -> Result<Receipt> {
        self.sequencer.sender.replay.live()?;
        if !matches!(
            self.phase,
            RecoveryPhase::Replay | RecoveryPhase::Draining | RecoveryPhase::Ready
        ) || self.sequencer.session_root.is_none()
        {
            return Err(Error::Invalid("local recovery phase/session"));
        }
        if self.applications >= 4096 {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        let previous = SessionImage::decode(&self.descriptor.root, self.sequencer.image())?;
        let mut result = Err(Error::Invalid("local recovery fault"));
        for _ in 0..2 {
            self.sequencer.sender.replay.live()?;
            result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| game(&self.histories)))
                    .unwrap_or(Err(Error::Invalid("local recovery panic")));
            if result.is_ok() {
                break;
            }
        }
        let commit = (|| {
            let (bytes, outputs, cuts) = result?;
            let post = SessionImage::decode(&self.descriptor.root, &bytes)?;
            if post.members != previous.members || post.inputs != self.histories {
                return Err(Error::Conflict);
            }
            let mut survivors = self.survivors.clone();
            let mut marks = self.reconciled_watermarks();
            let mut seen = BTreeSet::new();
            let mut applications = self.applications.checked_add(1).ok_or(Error::Bounds)?;
            let mut new_work = !outputs.is_empty();
            for cut in cuts {
                let member = previous
                    .members
                    .iter()
                    .find(|m| m.player == cut.player)
                    .ok_or(Error::Unauthorized)?;
                if !seen.insert(cut.player)
                    || member
                        .key
                        .is_some_and(|key| key != self.descriptor.root.standby)
                {
                    return Err(Error::Unauthorized);
                }
                let survivor = survivors.get_mut(&cut.player).ok_or(Error::Unauthorized)?;
                let handled = self.histories[&cut.player].handled();
                if cut.applied < survivor.applied
                    || cut.applied > self.sequencer.output_ceiling(cut.player)
                    || cut.tail < survivor.tail
                    || cut.tail < handled
                    || cut.tail - handled > MAX_JOURNAL_RECORDS as u64
                {
                    return Err(Error::Gap);
                }
                applications = applications
                    .checked_add(
                        usize::try_from(cut.applied - survivor.applied)
                            .map_err(|_| Error::Bounds)?,
                    )
                    .ok_or(Error::Bounds)?;
                new_work |= cut.tail != handled;
                survivor.applied = cut.applied;
                survivor.tail = cut.tail;
                marks
                    .iter_mut()
                    .find(|m| m.player == cut.player && !m.retired)
                    .ok_or(Error::Gap)?
                    .output_ack = cut.applied;
            }
            if applications
                .checked_add(outputs.len())
                .is_none_or(|n| n > 4096)
            {
                return Err(Error::Bounds);
            }
            let lossy = outputs
                .iter()
                .filter(|o| o.delivery == Delivery::Lossy)
                .count();
            let candidate = self
                .sequencer
                .next(bytes, self.logical_ms(), marks, outputs)?;
            let staged = self.sequencer.stage(candidate)?;
            let receipt = self.sequencer.install(staged, keys)?;
            Ok((receipt, survivors, applications + lossy, new_work))
        })();
        match commit {
            Ok((receipt, survivors, applications, new_work)) => {
                self.survivors = survivors;
                self.applications = applications;
                if self.phase == RecoveryPhase::Ready && new_work {
                    self.phase = RecoveryPhase::Replay;
                }
                Ok(receipt)
            }
            Err(error) => {
                self.phase = RecoveryPhase::Failed;
                Err(error)
            }
        }
    }
    /// Internal causal-drain handoff. Only RecoveryBarrier may consume it;
    /// causal convergence alone does not license successor ticks.
    fn finish(self) -> Result<(Sequencer, BTreeMap<u64, HandledInputs>)> {
        self.require(RecoveryPhase::Ready)?;
        if self.sequencer.session_root.is_some()
            && SessionImage::decode(&self.descriptor.root, self.sequencer.image())?
                .security_boundary
                .as_ref()
                .is_none_or(|boundary| {
                    self.promotion
                        .final_receipt
                        .digest(self.sequencer.context())
                        .ok()
                        != Some(boundary.fence)
                })
        {
            return Err(Error::Invalid("missing security revalidation"));
        }
        if !self.delivered() {
            return Err(Error::Gap);
        }
        for (&player, s) in &self.survivors {
            let mark = self
                .sequencer
                .receipt()
                .watermarks
                .iter()
                .find(|m| m.player == player && !m.retired)
                .ok_or(Error::Gap)?;
            if mark.input != s.tail || mark.output_ack != s.applied {
                return Err(Error::Gap);
            }
        }
        Ok((self.sequencer, self.histories))
    }
    pub fn absent(&self) -> Result<Vec<u64>> {
        self.require(RecoveryPhase::Departures)?;
        Ok(self
            .histories
            .keys()
            .filter(|p| !self.survivors.contains_key(p))
            .copied()
            .collect())
    }
    pub fn commit_departures(
        &mut self,
        keys: &Keys,
        mut game: impl FnMut(
            &[u64],
            u64,
            &BTreeMap<u64, HandledInputs>,
        ) -> Result<(Vec<u8>, Vec<Output>)>,
    ) -> Result<Receipt> {
        let absent = self.absent()?;
        // An empty departure barrier has no game applications. Commit the
        // reconciled frontier in term 1 even at the exact application limit.
        if absent.is_empty() {
            let candidate = self.sequencer.next(
                self.sequencer.image().to_vec(),
                self.logical_ms(),
                self.sequencer.receipt().watermarks.clone(),
                vec![],
            )?;
            let staged = self.sequencer.stage(candidate)?;
            let receipt = self.sequencer.install(staged, keys)?;
            self.departed = true;
            self.phase = RecoveryPhase::Ready;
            return Ok(receipt);
        }
        if self.applications >= 4096
            || self
                .applications
                .checked_add(absent.len())
                .is_none_or(|n| n > 4096)
        {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        let histories = self
            .histories
            .iter()
            .filter(|(p, _)| self.survivors.contains_key(p))
            .map(|(p, h)| (*p, h.clone()))
            .collect();
        let mut result = Err(Error::Invalid("authority departure fault"));
        for _ in 0..2 {
            self.sequencer.sender.replay.live()?;
            result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                game(&absent, self.logical_ms(), &histories)
            }))
            .unwrap_or(Err(Error::Invalid("authority departure panic")));
            if result.is_ok() {
                break;
            }
        }
        let (image, outputs) = match result {
            Ok(value) => value,
            Err(error) => {
                self.phase = RecoveryPhase::Failed;
                return Err(error);
            }
        };
        if self
            .applications
            .checked_add(absent.len() + outputs.len())
            .is_none_or(|n| n > 4096)
        {
            self.phase = RecoveryPhase::Failed;
            return Err(Error::Bounds);
        }
        let lossy = outputs
            .iter()
            .filter(|o| o.delivery == Delivery::Lossy)
            .count();
        let mut marks = self.sequencer.receipt().watermarks.clone();
        for mark in &mut marks {
            if absent.contains(&mark.player) {
                mark.retired = true;
            }
            if let Some(s) = self.survivors.get(&mark.player) {
                mark.output_ack = s.applied;
            }
        }
        let commit = (|| {
            let candidate = self
                .sequencer
                .next(image, self.logical_ms(), marks, outputs)?;
            let staged = self.sequencer.stage(candidate)?;
            self.sequencer.install(staged, keys)
        })();
        let receipt = match commit {
            Ok(receipt) => receipt,
            Err(error) => {
                self.phase = RecoveryPhase::Failed;
                return Err(error);
            }
        };
        self.histories = histories;
        self.applications += absent.len() + lossy;
        self.departed = true;
        self.phase = RecoveryPhase::Replay;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMember {
    pub player: u64,
    pub seat: u8,
    pub key: Option<RuntimeKey>,
    pub logical_peer: u32,
}
/// Fray-owned metadata around the game's complete runner bytes. Input histories
/// and logical routes therefore share the exact state hash and commit frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityBoundary {
    /// Domain/root/term-bound digest of the exact term-0 close frontier.
    pub fence: Hash,
    /// Actual retained pre-reset tails, fixed before any replay/followups.
    pub tails: BTreeMap<u64, u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionImage {
    pub checkpoint_version: u32,
    pub game_version: u32,
    pub match_id: u64,
    pub logical_ms: u64,
    pub config: Hash,
    pub content: Hash,
    pub membership_revision: u64,
    pub next_player: u64,
    pub security_boundary: Option<SecurityBoundary>,
    pub members: Vec<SessionMember>,
    pub inputs: BTreeMap<u64, HandledInputs>,
    pub game: Vec<u8>,
}
impl SessionImage {
    pub fn initial(
        root: &Root,
        routes: &[(u64, u32)],
        game: Vec<u8>,
        match_id: u64,
        logical_ms: u64,
    ) -> Result<Self> {
        root.validate()?;
        if routes.len() != root.members.len() {
            return Err(Error::Invalid("initial logical routes"));
        }
        let routes: BTreeMap<_, _> = routes.iter().copied().collect();
        if routes.len() != root.members.len() {
            return Err(Error::Conflict);
        }
        let members = root
            .members
            .iter()
            .map(|m| {
                Ok(SessionMember {
                    player: m.player,
                    seat: m.seat,
                    key: m.key,
                    logical_peer: *routes.get(&m.player).ok_or(Error::Gap)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_player = root
            .members
            .last()
            .map_or(Some(1), |m| m.player.checked_add(1))
            .ok_or(Error::Bounds)?;
        let image = Self {
            checkpoint_version: root.checkpoint_version,
            game_version: root.game_version,
            match_id,
            logical_ms,
            config: root.config,
            content: root.content,
            membership_revision: root.roster_revision,
            next_player,
            security_boundary: None,
            members,
            inputs: root
                .members
                .iter()
                .map(|m| (m.player, HandledInputs::default()))
                .collect(),
            game,
        };
        image.encode(root)?;
        Ok(image)
    }
    pub fn validate(&self, root: &Root) -> Result<()> {
        if self.checkpoint_version != root.checkpoint_version
            || self.game_version != root.game_version
            || self.membership_revision < root.roster_revision
            || self.members.len() > MAX_PLAYERS
            || self.next_player == 0
            || self.game.len() > MAX_IMAGE
        {
            return Err(Error::Invalid("session image versions/bounds"));
        }
        if self
            .security_boundary
            .as_ref()
            .is_some_and(|b| b.fence == [0; 32] || b.tails.len() > MAX_PLAYERS)
        {
            return Err(Error::Invalid("security boundary bounds"));
        }
        let mut last = None;
        let mut peers = BTreeSet::new();
        let mut seats = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut players = BTreeSet::new();
        for m in &self.members {
            if last.is_some_and(|p| p >= m.player)
                || m.player >= self.next_player
                || m.seat as usize >= MAX_PLAYERS
                || !seats.insert(m.seat)
                || !peers.insert(m.logical_peer)
            {
                return Err(Error::Invalid("session roster order/routes"));
            }
            if let Some(key) = m.key {
                PublicKey::from_slice(&key).map_err(|_| Error::Unauthorized)?;
                if !keys.insert(key) {
                    return Err(Error::Conflict);
                }
            }
            players.insert(m.player);
            last = Some(m.player);
        }
        if self.inputs.keys().copied().collect::<BTreeSet<_>>() != players {
            return Err(Error::Invalid("session input roster"));
        }
        if self.membership_revision == root.roster_revision
            && !root_roster_matches(root, &self.members)
        {
            return Err(Error::Invalid("initial roster revision changed"));
        }
        for h in self.inputs.values() {
            h.validate()?;
        }
        Ok(())
    }
    pub fn validate_initial(&self, root: &Root) -> Result<()> {
        self.validate(root)?;
        if self.security_boundary.is_some()
            || self.members.len() != root.members.len()
            || self
                .members
                .iter()
                .zip(&root.members)
                .any(|(a, b)| a.player != b.player || a.seat != b.seat || a.key != b.key)
            || self.config != root.config
            || self.content != root.content
            || self.membership_revision != root.roster_revision
            || self.next_player
                != root
                    .members
                    .last()
                    .map_or(Some(1), |m| m.player.checked_add(1))
                    .ok_or(Error::Bounds)?
            || self.inputs.values().any(|h| h.handled() != 0)
        {
            return Err(Error::Invalid("initial session root binding"));
        }
        Ok(())
    }
    pub fn validate_successor(
        &self,
        root: &Root,
        previous: &Self,
        marks: &[Watermark],
        logical_ms: u64,
    ) -> Result<()> {
        self.validate(root)?;
        previous.validate(root)?;
        if self.logical_ms != logical_ms {
            return Err(Error::Invalid("image/receipt logical time binding"));
        }
        if previous.security_boundary.is_some()
            && self.security_boundary != previous.security_boundary
        {
            return Err(Error::Invalid("security boundary changed"));
        }
        let mut canonical_marks = Vec::new();
        encode_watermarks(&mut canonical_marks, marks)?;
        if self.next_player < previous.next_player
            || self.match_id < previous.match_id
            || self.logical_ms < previous.logical_ms
        {
            return Err(Error::Invalid("session counters regressed"));
        }
        let changed = self.members != previous.members;
        let revision = previous
            .membership_revision
            .checked_add(u64::from(changed))
            .ok_or(Error::Bounds)?;
        if self.membership_revision != revision {
            return Err(Error::Invalid("membership revision"));
        }
        for member in &self.members {
            if let Some(old) = previous
                .members
                .iter()
                .find(|old| old.player == member.player)
            {
                if old != member {
                    return Err(Error::Invalid("stable player changed identity/seat/route"));
                }
                let old = &previous.inputs[&member.player];
                let next = &self.inputs[&member.player];
                if next.handled() < old.handled()
                    || next.handled() - old.handled() > MAX_JOURNAL_RECORDS as u64
                {
                    return Err(Error::Invalid("input history advance"));
                }
                if let Some((first, _)) = next.recent.front() {
                    for (n, h) in &old.recent {
                        if n >= first && next.recent.get((n - first) as usize) != Some(&(*n, *h)) {
                            return Err(Error::Conflict);
                        }
                    }
                }
            } else {
                if member.player < previous.next_player {
                    return Err(Error::Invalid("retired player ID reused"));
                }
                if self.inputs[&member.player].handled() != 0
                    || marks
                        .iter()
                        .find(|m| m.player == member.player)
                        .is_none_or(|m| m.retired || m.input != 0 || m.output_ack != 0)
                {
                    return Err(Error::Invalid(
                        "new player requires an empty committed frontier",
                    ));
                }
            }
        }
        for old in &previous.members {
            if !self.members.iter().any(|m| m.player == old.player)
                && !marks.iter().any(|m| m.player == old.player && m.retired)
            {
                return Err(Error::Invalid("membership removed without retirement"));
            }
        }
        let active: BTreeMap<_, _> = marks
            .iter()
            .filter(|m| !m.retired)
            .map(|m| (m.player, m.input))
            .collect();
        if active.len() != self.inputs.len()
            || self
                .inputs
                .iter()
                .any(|(p, h)| active.get(p) != Some(&h.handled()))
        {
            return Err(Error::Invalid("image/receipt input binding"));
        }
        Ok(())
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.validate(root)?;
        let mut bytes = b"FRYI".to_vec();
        root.context()?.encode(&mut bytes);
        bytes.extend(self.checkpoint_version.to_be_bytes());
        bytes.extend(self.game_version.to_be_bytes());
        bytes.extend(self.match_id.to_be_bytes());
        bytes.extend(self.logical_ms.to_be_bytes());
        bytes.extend(self.config);
        bytes.extend(self.content);
        bytes.extend(self.membership_revision.to_be_bytes());
        bytes.extend(self.next_player.to_be_bytes());
        match &self.security_boundary {
            None => bytes.push(0),
            Some(boundary) => {
                bytes.push(1);
                bytes.extend(boundary.fence);
                put_u32(&mut bytes, boundary.tails.len())?;
                for (player, tail) in &boundary.tails {
                    bytes.extend(player.to_be_bytes());
                    bytes.extend(tail.to_be_bytes());
                }
            }
        }
        put_u32(&mut bytes, self.members.len())?;
        for m in &self.members {
            bytes.extend(m.player.to_be_bytes());
            bytes.push(m.seat);
            match m.key {
                None => bytes.push(0),
                Some(key) => {
                    bytes.push(1);
                    bytes.extend(key);
                }
            }
            bytes.extend(m.logical_peer.to_be_bytes());
            let history = &self.inputs[&m.player];
            bytes.extend(history.handled.to_be_bytes());
            put_u32(&mut bytes, history.recent.len())?;
            for (n, h) in &history.recent {
                bytes.extend(n.to_be_bytes());
                bytes.extend(h);
            }
        }
        if bytes
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(self.game.len()))
            .is_none_or(|n| n > MAX_IMAGE)
        {
            return Err(Error::Bounds);
        }
        put_bytes(&mut bytes, &self.game, MAX_IMAGE)?;
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        if r.take(4)? != b"FRYI" {
            return Err(Error::Invalid("session image magic"));
        }
        root.context()?.read_binding(&mut r)?;
        let checkpoint_version = u32::from_be_bytes(r.array()?);
        let game_version = u32::from_be_bytes(r.array()?);
        let match_id = r.u64()?;
        let logical_ms = r.u64()?;
        let config = r.array()?;
        let content = r.array()?;
        let membership_revision = r.u64()?;
        let next_player = r.u64()?;
        let security_boundary = match r.u8()? {
            0 => None,
            1 => {
                let fence = r.array()?;
                let count = r.u32()?;
                if count > MAX_PLAYERS {
                    return Err(Error::Bounds);
                }
                let mut tails = BTreeMap::new();
                let mut last = None;
                for _ in 0..count {
                    let player = r.u64()?;
                    let tail = r.u64()?;
                    if last.is_some_and(|old| old >= player) {
                        return Err(Error::Invalid("security tail order"));
                    }
                    tails.insert(player, tail);
                    last = Some(player);
                }
                Some(SecurityBoundary { fence, tails })
            }
            _ => return Err(Error::Invalid("security boundary option")),
        };
        let count = r.u32()?;
        if count > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        let mut members = Vec::with_capacity(count);
        let mut inputs = BTreeMap::new();
        for _ in 0..count {
            let player = r.u64()?;
            let seat = r.u8()?;
            let key = match r.u8()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(Error::Invalid("session member key option")),
            };
            let logical_peer = u32::from_be_bytes(r.array()?);
            let handled = r.u64()?;
            let count = r.u32()?;
            if count > MAX_JOURNAL_RECORDS {
                return Err(Error::Bounds);
            }
            let mut recent = VecDeque::with_capacity(count);
            for _ in 0..count {
                recent.push_back((r.u64()?, r.array()?));
            }
            if inputs
                .insert(player, HandledInputs { handled, recent })
                .is_some()
            {
                return Err(Error::Conflict);
            }
            members.push(SessionMember {
                player,
                seat,
                key,
                logical_peer,
            });
        }
        let game = r.bytes(MAX_IMAGE)?;
        r.finish()?;
        let image = Self {
            checkpoint_version,
            game_version,
            match_id,
            logical_ms,
            config,
            content,
            membership_revision,
            next_player,
            security_boundary,
            members,
            inputs,
            game,
        };
        image.validate(root)?;
        Ok(image)
    }
}

/// Public membership is signed only from the sequencer's installed image.
/// The receipt hash binds this table without disclosing hidden runner state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipCertificate {
    pub sequence: u64,
    pub receipt: Receipt,
    pub revision: u64,
    pub next_player: u64,
    pub members: Vec<SessionMember>,
    pub signature: SignatureBytes,
}
impl MembershipCertificate {
    fn issue(root: &Root, receipt: Receipt, image: &SessionImage, signer: &Keys) -> Result<Self> {
        if signer.public_key().to_bytes() != root.standby {
            return Err(Error::Unauthorized);
        }
        let mut certificate = Self {
            sequence: receipt.sequence.checked_add(1).ok_or(Error::Bounds)?,
            receipt,
            revision: image.membership_revision,
            next_player: image.next_player,
            members: image.members.clone(),
            signature: [0; 64],
        };
        certificate.signature = sign(signer, certificate.digest(root)?);
        certificate.verify(root)?;
        Ok(certificate)
    }
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence != self.receipt.sequence.checked_add(1).ok_or(Error::Bounds)? {
            return Err(Error::Invalid("membership sequence"));
        }
        let mut bytes = control_prefix(&root.context()?, self.receipt.term, 9, self.sequence);
        put_bytes(
            &mut bytes,
            &self.receipt.encode(&root.context()?)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        bytes.extend(self.revision.to_be_bytes());
        bytes.extend(self.next_player.to_be_bytes());
        if self.members.len() > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        put_u32(&mut bytes, self.members.len())?;
        for m in &self.members {
            bytes.extend(m.player.to_be_bytes());
            bytes.push(m.seat);
            match m.key {
                None => bytes.push(0),
                Some(key) => {
                    bytes.push(1);
                    bytes.extend(key);
                }
            }
            bytes.extend(m.logical_peer.to_be_bytes());
        }
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        root.validate()?;
        self.receipt.verify(&root.context()?)?;
        if self.revision < root.roster_revision
            || self.next_player == 0
            || self.members.len() > MAX_PLAYERS
        {
            return Err(Error::Bounds);
        }
        let mut seats = BTreeSet::new();
        let mut peers = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut last = None;
        for m in &self.members {
            if last.is_some_and(|p| p >= m.player)
                || m.player >= self.next_player
                || m.seat as usize >= MAX_PLAYERS
                || !seats.insert(m.seat)
                || !peers.insert(m.logical_peer)
            {
                return Err(Error::Invalid("membership table"));
            }
            if let Some(key) = m.key {
                PublicKey::from_slice(&key).map_err(|_| Error::Unauthorized)?;
                if !keys.insert(key) {
                    return Err(Error::Conflict);
                }
            }
            last = Some(m.player);
        }
        let active: Vec<_> = self
            .receipt
            .watermarks
            .iter()
            .filter(|m| !m.retired)
            .map(|m| m.player)
            .collect();
        if self.revision == root.roster_revision && !root_roster_matches(root, &self.members) {
            return Err(Error::Invalid("initial roster revision changed"));
        }
        if active != self.members.iter().map(|m| m.player).collect::<Vec<_>>() {
            return Err(Error::Invalid("membership receipt binding"));
        }
        verify(root.standby, self.digest(root)?, self.signature)
    }
    /// Check replacement against an already authenticated local certificate.
    /// Revision jumps are allowed when a peer missed intermediate commits;
    /// lifetime IDs below the previous allocation frontier cannot reappear.
    pub fn follows(&self, root: &Root, previous: &Self) -> Result<()> {
        self.verify(root)?;
        previous.verify(root)?;
        if self.body(root)? == previous.body(root)? {
            return Ok(());
        }
        if self.receipt.index <= previous.receipt.index
            || self.receipt.term < previous.receipt.term
            || self.receipt.logical_ms < previous.receipt.logical_ms
            || self.revision < previous.revision
            || self.next_player < previous.next_player
        {
            return Err(Error::Stale);
        }
        if self.members != previous.members && self.revision == previous.revision {
            return Err(Error::Conflict);
        }
        for m in &self.members {
            if let Some(old) = previous.members.iter().find(|old| old.player == m.player) {
                if m != old {
                    return Err(Error::Conflict);
                }
            } else if m.player < previous.next_player {
                return Err(Error::Invalid("retired player ID reused"));
            }
        }
        Ok(())
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.verify(root)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        let term = r.u64()?;
        if r.u8()? != 9 {
            return Err(Error::Invalid("membership control kind"));
        }
        let sequence = r.u64()?;
        let receipt = Receipt::decode(&root.context()?, &r.bytes(crate::MAX_RELIABLE_LEN)?)?;
        if term != receipt.term
            || sequence != receipt.sequence.checked_add(1).ok_or(Error::Bounds)?
        {
            return Err(Error::Invalid("membership control frontier"));
        }
        let revision = r.u64()?;
        let next_player = r.u64()?;
        let count = r.u32()?;
        if count > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let player = r.u64()?;
            let seat = r.u8()?;
            let key = match r.u8()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(Error::Invalid("membership key option")),
            };
            members.push(SessionMember {
                player,
                seat,
                key,
                logical_peer: u32::from_be_bytes(r.array()?),
            });
        }
        let certificate = Self {
            sequence,
            receipt,
            revision,
            next_player,
            members,
            signature: r.array()?,
        };
        r.finish()?;
        certificate.verify(root)?;
        Ok(certificate)
    }
}
fn root_roster_matches(root: &Root, members: &[SessionMember]) -> bool {
    members.len() == root.members.len()
        && members
            .iter()
            .zip(&root.members)
            .all(|(a, b)| a.player == b.player && a.seat == b.seat && a.key == b.key)
}
impl Sequencer {
    pub fn membership_certificate(&self, signer: &Keys) -> Result<MembershipCertificate> {
        let root = self
            .session_root
            .as_ref()
            .ok_or(Error::Invalid("sequencer has no session envelope"))?;
        if signer.public_key().to_bytes() != root.standby {
            return Err(Error::Unauthorized);
        }
        self.membership
            .clone()
            .ok_or(Error::Invalid("missing installed membership"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelSide {
    Client,
    Server,
}
/// One already authenticated v7 connection. Role/size/rate checks happen
/// before the reassembler allocates a transfer buffer. Control records still
/// need their own signature, sequence and game admission checks after receive.
pub struct Channel {
    descriptor: Descriptor,
    binding: ConnectionBinding,
    side: ChannelSide,
    tls: [u8; 32],
    remote_key: RuntimeKey,
    local_key: Option<RuntimeKey>,
    authenticated_player: Option<u64>,
    authenticated_membership: Option<MembershipCertificate>,
    promotion: Option<Promotion>,
    term: u64,
    next: u64,
    receiver: PacketReceiver,
    sender: SendQueue,
    ingress: IngressRate,
}
impl Channel {
    /// Supply the role/root, key and exporter reported by the authenticated
    /// transport, never values parsed from a migration payload.
    pub fn new(
        policy: &EndpointPolicy,
        binding: ConnectionBinding,
        side: ChannelSide,
        remote: RuntimeKey,
        tls: [u8; 32],
    ) -> Result<Self> {
        policy.descriptor.verify()?;
        policy.check_request(&binding)?;
        match (policy.role, &policy.promotion) {
            (LinkRole::Original | LinkRole::Standby, None) => {}
            (LinkRole::Successor, Some(p)) => p.verify(&policy.descriptor.root.context()?)?,
            _ => return Err(Error::Unauthorized),
        }
        match side {
            ChannelSide::Server => policy.authorize(&binding, remote)?,
            ChannelSide::Client => {
                let expected = if binding.server == LinkRole::Original {
                    policy.descriptor.root.host
                } else {
                    policy.descriptor.root.standby
                };
                if remote != expected {
                    return Err(Error::Unauthorized);
                }
            }
        }
        if let Some(membership) = &policy.membership {
            membership.verify(&policy.descriptor.root)?;
            if membership.receipt.term > binding.term
                || policy
                    .promotion
                    .as_ref()
                    .is_some_and(|p| membership.receipt.index < p.final_receipt.index)
            {
                return Err(Error::Stale);
            }
        }
        if binding.term == 1 {
            policy
                .promotion
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .verify(&policy.descriptor.root.context()?)?;
        }
        let term = binding.term;
        Ok(Self {
            descriptor: policy.descriptor.clone(),
            receiver: PacketReceiver::new(binding.session, term)?,
            binding,
            side,
            tls,
            remote_key: remote,
            local_key: None,
            authenticated_player: policy.player_for_key(remote),
            authenticated_membership: policy.membership.clone(),
            promotion: if term == 1 {
                policy.promotion.clone()
            } else {
                None
            },
            term,
            next: 1,
            sender: SendQueue::default(),
            ingress: IngressRate::default(),
        })
    }
    /// Construct from verified local and remote handshake identities. The
    /// built-in transport handles supply these from their Identify/Welcome
    /// state; custom transports must supply equally verified metadata.
    pub fn new_bound(
        policy: &EndpointPolicy,
        binding: ConnectionBinding,
        side: ChannelSide,
        local: RuntimeKey,
        remote: RuntimeKey,
        tls: [u8; 32],
    ) -> Result<Self> {
        PublicKey::from_slice(&local).map_err(|_| Error::Unauthorized)?;
        match side {
            ChannelSide::Client => policy.authorize(&binding, local)?,
            ChannelSide::Server => {
                let expected = if binding.server == LinkRole::Original {
                    policy.descriptor.root.host
                } else {
                    policy.descriptor.root.standby
                };
                if local != expected {
                    return Err(Error::Unauthorized);
                }
            }
        }
        let mut channel = Self::new(policy, binding, side, remote, tls)?;
        channel.local_key = Some(local);
        Ok(channel)
    }
    pub fn local_key(&self) -> Option<RuntimeKey> {
        self.local_key
    }
    pub fn remote_key(&self) -> RuntimeKey {
        self.remote_key
    }
    pub fn tls(&self) -> [u8; 32] {
        self.tls
    }
    pub fn binding(&self) -> &ConnectionBinding {
        &self.binding
    }
    fn allowed(&self, side: ChannelSide, kind: PacketKind) -> bool {
        let from_client = side == ChannelSide::Server;
        if from_client {
            match kind {
                PacketKind::Candidate | PacketKind::Delta | PacketKind::InitialImage => {
                    self.term == 0
                        && self.binding.client == LinkRole::Original
                        && self.binding.server == LinkRole::Standby
                }
                PacketKind::Control => true,
                _ => false,
            }
        } else {
            match kind {
                PacketKind::Receipt => {
                    self.term == 0
                        && self.binding.client == LinkRole::Original
                        && self.binding.server == LinkRole::Standby
                }
                PacketKind::Output => {
                    matches!(
                        self.binding.server,
                        LinkRole::Original | LinkRole::Successor
                    ) || (self.term == 1 && self.binding.server == LinkRole::Standby)
                }
                PacketKind::Control => true,
                _ => false,
            }
        }
    }
    fn check(&self, side: ChannelSide, kind: PacketKind, length: usize) -> Result<()> {
        if !self.allowed(side, kind) {
            return Err(Error::Unauthorized);
        }
        let cap = match kind {
            PacketKind::Candidate | PacketKind::Delta | PacketKind::InitialImage => MAX_IMAGE,
            PacketKind::Receipt => crate::MAX_RELIABLE_LEN,
            PacketKind::Output | PacketKind::Control => 4096,
        };
        if length == 0 || length > cap {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn receive(
        &mut self,
        wire: &[u8],
        now_ms: u64,
    ) -> Result<Option<(PacketKind, u64, Vec<u8>)>> {
        self.ingress.debit(wire.len(), now_ms)?;
        let frame = Frame::decode(wire)?;
        if frame.session != self.binding.session || frame.term != self.term {
            return Err(Error::Unauthorized);
        }
        self.check(self.side, frame.kind, frame.length as usize)?;
        if matches!(frame.kind, PacketKind::Candidate | PacketKind::Delta) {
            let m = frame
                .candidate
                .as_ref()
                .ok_or(Error::Invalid("missing candidate manifest"))?;
            if m.descriptor != self.binding.descriptor
                || m.schema != self.descriptor.root.checkpoint_version
            {
                return Err(Error::Unauthorized);
            }
        }
        let complete = self.receiver.receive(wire, now_ms)?;
        if let Some((PacketKind::Candidate, _, bytes)) = &complete {
            let candidate = Candidate::decode(&self.descriptor.root.context()?, bytes)?;
            let m = frame
                .candidate
                .as_ref()
                .ok_or(Error::Invalid("missing candidate manifest"))?;
            if candidate.term != self.term
                || candidate.index != m.index
                || candidate.parent != m.base
                || state_hash(&candidate.image)? != m.target
            {
                return Err(Error::Conflict);
            }
        }
        if let Some((PacketKind::Delta, _, bytes)) = &complete {
            let delta = CandidateDelta::decode(&self.descriptor.root.context()?, bytes)?;
            let manifest = frame
                .candidate
                .as_ref()
                .ok_or(Error::Invalid("missing candidate manifest"))?;
            if delta.term != self.term
                || delta.index != manifest.index
                || delta.parent != manifest.base
                || delta.patch.target != manifest.target
            {
                return Err(Error::Conflict);
            }
        }
        Ok(complete)
    }
    pub fn enqueue(&mut self, kind: PacketKind, bytes: &[u8]) -> Result<u64> {
        let receiving_side = match self.side {
            ChannelSide::Client => ChannelSide::Server,
            ChannelSide::Server => ChannelSide::Client,
        };
        self.check(receiving_side, kind, bytes.len())?;
        let next = self.next.checked_add(1).ok_or(Error::Bounds)?;
        let mut frames = Frame::split(self.binding.session, self.term, self.next, kind, bytes)?;
        if kind == PacketKind::Candidate {
            let candidate = Candidate::decode(&self.descriptor.root.context()?, bytes)?;
            if candidate.term != self.term {
                return Err(Error::Closed);
            }
            let manifest = CandidateManifest {
                descriptor: self.binding.descriptor,
                schema: self.descriptor.root.checkpoint_version,
                index: candidate.index,
                base: candidate.parent,
                target: state_hash(&candidate.image)?,
            };
            for frame in &mut frames {
                frame.candidate = Some(manifest.clone());
            }
        }
        if kind == PacketKind::Delta {
            let delta = CandidateDelta::decode(&self.descriptor.root.context()?, bytes)?;
            if delta.term != self.term {
                return Err(Error::Closed);
            }
            let manifest = CandidateManifest {
                descriptor: self.binding.descriptor,
                schema: self.descriptor.root.checkpoint_version,
                index: delta.index,
                base: delta.parent,
                target: delta.patch.target,
            };
            for frame in &mut frames {
                frame.candidate = Some(manifest.clone());
            }
        }
        self.sender.enqueue(frames)?;
        let id = self.next;
        self.next = next;
        Ok(id)
    }
    /// Queue several manifest-free messages (Receipt or Control) as one
    /// all-or-nothing unit; returns the last message's transfer ID.
    fn enqueue_replies(&mut self, messages: &[(PacketKind, &[u8])]) -> Result<u64> {
        let receiving_side = match self.side {
            ChannelSide::Client => ChannelSide::Server,
            ChannelSide::Server => ChannelSide::Client,
        };
        let mut frames = vec![];
        let mut id = self.next;
        let mut last = 0;
        for (kind, bytes) in messages {
            if !matches!(kind, PacketKind::Receipt | PacketKind::Control) {
                return Err(Error::Unauthorized);
            }
            self.check(receiving_side, *kind, bytes.len())?;
            frames.extend(Frame::split(
                self.binding.session,
                self.term,
                id,
                *kind,
                bytes,
            )?);
            last = id;
            id = id.checked_add(1).ok_or(Error::Bounds)?;
        }
        self.sender.enqueue(frames)?;
        self.next = id;
        Ok(last)
    }
    pub fn poll_send(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        self.sender.poll(now_ms)
    }
    /// Framed bytes still awaiting release on this same connection.
    pub fn queued_bytes(&self) -> usize {
        self.sender.queued_bytes()
    }
    pub fn expire(&mut self, now_ms: u64) -> Result<()> {
        self.receiver.expire(now_ms)
    }
    /// Late chunks of expired transfers this channel ignored
    /// ([`PacketReceiver::late_chunks`]).
    pub fn late_chunks(&self) -> u64 {
        self.receiver.late_chunks()
    }
    /// A warm control link keeps its TLS identity/exporter. Only the signed
    /// fixed-pair promotion changes its packet term and publication direction.
    pub fn promote(&mut self, promotion: &Promotion) -> Result<()> {
        promotion.verify(&self.descriptor.root.context()?)?;
        if self.term != 0 {
            return Err(Error::Closed);
        }
        self.receiver.advance_term(1)?;
        self.sender.retain_term(1);
        self.promotion = Some(promotion.clone());
        self.term = 1;
        Ok(())
    }
    /// Fence locally first, then deliver the signed transition in the old
    /// framing term so a warm peer can authenticate it before changing terms.
    /// This is the only old-term record allowed into a promoted send queue.
    pub fn promote_and_announce(&mut self, promotion: &Promotion) -> Result<()> {
        if self.side != ChannelSide::Server || self.binding.server != LinkRole::Standby {
            return Err(Error::Unauthorized);
        }
        let bytes = promotion.encode(&self.descriptor.root.context()?)?;
        let next = self.next.checked_add(1).ok_or(Error::Bounds)?;
        let frames = Frame::split(
            self.binding.session,
            0,
            self.next,
            PacketKind::Control,
            &bytes,
        )?;
        self.promote(promotion)?;
        self.sender.enqueue(frames)?;
        self.next = next;
        Ok(())
    }
}
/// Bounded physical ingress waiting for the same 4 MiB/s, 64 KiB burst debit
/// used by Channel. QUIC may deliver several paced sends together in one app
/// poll. Defer such frames without changing their order, replay IDs or clocks;
/// this does not extend the existing 500 ms transfer deadline.
#[derive(Default)]
pub struct ReceiveQueue {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl ReceiveQueue {
    pub fn enqueue(&mut self, wire: Vec<u8>) -> Result<()> {
        if wire.is_empty()
            || wire.len() > crate::MAX_RELIABLE_LEN
            || self.frames.len() >= 4096
            || self
                .bytes
                .checked_add(wire.len())
                .is_none_or(|n| n > 2 * MAX_IMAGE)
        {
            return Err(Error::Bounds);
        }
        self.bytes += wire.len();
        self.frames.push_back(wire);
        Ok(())
    }
    pub fn queued_bytes(&self) -> usize {
        self.bytes
    }
    /// Some means one complete physical frame was consumed (its actor result
    /// may itself be None for a partial transfer). None means empty/rate-limited:
    /// stop this poll and retry at a later real monotonic time.
    pub fn poll<T>(&mut self, receive: impl FnOnce(&[u8]) -> Result<T>) -> Result<Option<T>> {
        let Some(wire) = self.frames.front() else {
            return Ok(None);
        };
        match receive(wire) {
            Err(Error::RateLimited) => Ok(None),
            result => {
                self.bytes -= self.frames.pop_front().unwrap().len();
                result.map(Some)
            }
        }
    }
}

struct IngressRate {
    tokens: usize,
    last: Option<u64>,
    fraction: u64,
}
impl Default for IngressRate {
    fn default() -> Self {
        Self {
            tokens: 64 * 1024,
            last: None,
            fraction: 0,
        }
    }
}
impl IngressRate {
    fn debit(&mut self, bytes: usize, now: u64) -> Result<()> {
        if let Some(last) = self.last {
            if now < last {
                return Err(Error::Invalid("backwards ingress clock"));
            }
            let scaled = u128::from(now - last) * 4 * 1024 * 1024 + u128::from(self.fraction);
            self.tokens = self
                .tokens
                .saturating_add(usize::try_from(scaled / 1000).unwrap_or(usize::MAX))
                .min(64 * 1024);
            self.fraction = (scaled % 1000) as u64;
        }
        self.last = Some(now);
        if bytes > self.tokens {
            return Err(Error::RateLimited);
        }
        self.tokens -= bytes;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Activity {
    Idle = 0,
    Advancing = 1,
    Recovering = 2,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PulseProbe {
    pub term: u64,
    pub sequence: u64,
    pub nonce: [u8; 32],
    pub tls: [u8; 32],
}
impl PulseProbe {
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        if self.term > 1 || self.sequence == 0 {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(&root.context()?, self.term, 10, self.sequence);
        bytes.extend(self.nonce);
        bytes.extend(self.tls);
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/probe/v1\0", &self.encode(root)?))
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 256 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        let term = r.u64()?;
        if r.u8()? != 10 {
            return Err(Error::Invalid("probe kind"));
        }
        let probe = Self {
            term,
            sequence: r.u64()?,
            nonce: r.array()?,
            tls: r.array()?,
        };
        r.finish()?;
        probe.encode(root)?;
        Ok(probe)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pulse {
    pub term: u64,
    pub sequence: u64,
    pub challenge: Hash,
    pub frontier: Receipt,
    pub activity: Activity,
    pub signature: SignatureBytes,
}
impl Pulse {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.term > 1
            || self.sequence == 0
            || self.frontier.term > self.term
            || (self.term == 0 && self.activity == Activity::Recovering)
        {
            return Err(Error::Invalid("pulse term/mode"));
        }
        let mut bytes = control_prefix(&root.context()?, self.term, 5, self.sequence);
        bytes.extend(self.challenge);
        bytes.push(self.activity as u8);
        put_bytes(
            &mut bytes,
            &self.frontier.encode(&root.context()?)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    /// The game runner derives activity from the installed checkpoint. It
    /// never accepts a primary/client declaration as proof of idle game time.
    pub fn respond(
        root: &Root,
        current: &Sequencer,
        probe: &PulseProbe,
        tls: [u8; 32],
        activity: Activity,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        let term = u64::from(current.promotion.is_some());
        if current.context() != &root.context()?
            || keys.public_key().to_bytes() != root.standby
            || probe.term != term
            || probe.tls != tls
        {
            return Err(Error::Unauthorized);
        }
        let mut pulse = Self {
            term,
            sequence,
            challenge: probe.digest(root)?,
            frontier: current.receipt().clone(),
            activity,
            signature: [0; 64],
        };
        pulse.signature = sign(keys, pulse.digest(root)?);
        pulse.verify(root)?;
        Ok(pulse)
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        self.frontier.verify(&root.context()?)?;
        verify(root.standby, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.verify(root)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        let term = r.u64()?;
        if r.u8()? != 5 {
            return Err(Error::Invalid("pulse kind"));
        }
        let sequence = r.u64()?;
        let challenge = r.array()?;
        let activity = match r.u8()? {
            0 => Activity::Idle,
            1 => Activity::Advancing,
            2 => Activity::Recovering,
            _ => return Err(Error::Invalid("pulse mode")),
        };
        let frontier = Receipt::decode(&root.context()?, &r.bytes(crate::MAX_RELIABLE_LEN)?)?;
        let pulse = Self {
            term,
            sequence,
            challenge,
            frontier,
            activity,
            signature: r.array()?,
        };
        r.finish()?;
        pulse.verify(root)?;
        Ok(pulse)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchStatus {
    Live,
    Paused,
    Recovering,
}

/// A host proves that it is still participating on its authenticated control
/// connection. This never grants publication or renews an authority lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimaryAlive {
    pub sequence: u64,
    pub challenge: Hash,
    pub frontier: Receipt,
    pub signature: SignatureBytes,
}
impl PrimaryAlive {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence == 0 || self.frontier.term != 0 {
            return Err(Error::Invalid("primary alive term/sequence"));
        }
        let mut bytes = control_prefix(&root.context()?, 0, 11, self.sequence);
        bytes.extend(self.challenge);
        put_bytes(
            &mut bytes,
            &self.frontier.encode(&root.context()?)?,
            crate::MAX_RELIABLE_LEN,
        )?;
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    pub fn respond(
        root: &Root,
        primary: &Primary,
        probe: &PulseProbe,
        tls: [u8; 32],
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        if primary.context != root.context()?
            || primary.closed
            || keys.public_key().to_bytes() != root.host
            || probe.term != 0
            || probe.tls != tls
        {
            return Err(Error::Unauthorized);
        }
        let mut response = Self {
            sequence,
            challenge: probe.digest(root)?,
            frontier: primary.receipt().clone(),
            signature: [0; 64],
        };
        response.signature = sign(keys, response.digest(root)?);
        response.verify(root)?;
        Ok(response)
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        self.frontier.verify(&root.context()?)?;
        verify(root.host, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.verify(root)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        if r.u64()? != 0 || r.u8()? != 11 {
            return Err(Error::Invalid("primary alive kind/term"));
        }
        let response = Self {
            sequence: r.u64()?,
            challenge: r.array()?,
            frontier: Receipt::decode(&root.context()?, &r.bytes(crate::MAX_RELIABLE_LEN)?)?,
            signature: r.array()?,
        };
        r.finish()?;
        response.verify(root)?;
        Ok(response)
    }
}

/// A gap between two consecutive samples of a failure watch longer than this
/// is the watcher's own stall, not silence from the peer.
pub const STALL_GAP_MS: u64 = 100;

/// "A local stall is not peer silence" (`docs/migration-v1.md`, "Local stalls
/// and the failure watches"). Answers to probes sent before a watcher stall are
/// read after it, too late for their 200 ms window. After a sampling gap over
/// [`STALL_GAP_MS`] that began within 200 ms of the watcher's last probe, the
/// watch reports no silence until a probe sent at the end of the gap has had
/// its full 200 ms answer window. One deferral per fresh progress or answer,
/// so a watcher that keeps stalling is still detected.
#[derive(Clone, Copy, Debug)]
struct StallGrace {
    until: Option<u64>,
    armed: bool,
}
impl StallGrace {
    fn new() -> Self {
        Self {
            until: None,
            armed: true,
        }
    }
    /// One watch sample at `now_ms`; `last_ms` is the previous sample and
    /// `fresh_ms` the last fresh evidence. Only a watcher that probed within
    /// the answer window before the gap can have lost an answer to its stall,
    /// and only a watch still live when the gap began is deferred: silence
    /// already due stays due until fresh evidence arrives.
    fn sample(&mut self, last_ms: u64, now_ms: u64, last_probe: Option<u64>, fresh_ms: u64) {
        let probing = last_probe.is_some_and(|probe| last_ms - probe < 200);
        let live = last_ms - fresh_ms < 200;
        if self.armed && probing && live && now_ms - last_ms > STALL_GAP_MS {
            self.until = Some(now_ms.saturating_add(200));
            self.armed = false;
        }
    }
    /// Fresh progress or a valid probe answer restores the allowance.
    fn fresh(&mut self) {
        self.until = None;
        self.armed = true;
    }
    fn holds(&self, now_ms: u64) -> bool {
        self.until.is_some_and(|until| now_ms < until)
    }
}

/// How many probes a watch remembers after they leave the 200 ms answer
/// window unanswered. An answer to one of them is late, not forged.
const RETIRED_PROBES: usize = 64;

/// Move probes that left the 200 ms answer window from `pending` to
/// `retired`, keeping at most [`RETIRED_PROBES`] digests.
fn retire_probes(
    root: &Root,
    pending: &mut VecDeque<(u64, PulseProbe)>,
    retired: &mut VecDeque<Hash>,
    now_ms: u64,
) -> Result<()> {
    while let Some((sent, probe)) = pending.front() {
        if now_ms - *sent < 200 {
            break;
        }
        let digest = probe.digest(root)?;
        pending.pop_front();
        if retired.len() == RETIRED_PROBES {
            retired.pop_front();
        }
        retired.push_back(digest);
    }
    Ok(())
}

/// After no in-window probe matched: true, and forget the probe, when
/// `challenge` answers a probe this watch sent whose window has passed
/// (still pending or retired). A probe already answered, or never sent by
/// this watch on this connection, matches nothing.
fn take_late_probe(
    root: &Root,
    pending: &mut VecDeque<(u64, PulseProbe)>,
    retired: &mut VecDeque<Hash>,
    challenge: &Hash,
) -> Result<bool> {
    for (index, (_, probe)) in pending.iter().enumerate() {
        if *challenge == probe.digest(root)? {
            pending.remove(index);
            return Ok(true);
        }
    }
    if let Some(index) = retired.iter().position(|digest| digest == challenge) {
        retired.remove(index);
        return Ok(true);
    }
    Ok(false)
}

/// Standby-side suspicion uses fresh challenges or newly installed proposals.
/// The caller closes the very same sequencer on expiry; a response cannot
/// reopen it and a duplicate proposal cannot keep it alive indefinitely.
pub struct PrimaryWatch {
    root: Root,
    tls: [u8; 32],
    next: u64,
    index: u64,
    last_ms: u64,
    fresh_ms: u64,
    last_probe: Option<u64>,
    pending: VecDeque<(u64, PulseProbe)>,
    retired: VecDeque<Hash>,
    last_response: u64,
    late_answers: u64,
    grace: StallGrace,
}
impl PrimaryWatch {
    pub fn new(root: Root, current: &Sequencer, tls: [u8; 32], now_ms: u64) -> Result<Self> {
        if current.context() != &root.context()? || current.promotion.is_some() {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            root,
            tls,
            next: 1,
            index: current.receipt().index,
            last_ms: now_ms,
            fresh_ms: now_ms,
            last_probe: None,
            pending: VecDeque::new(),
            retired: VecDeque::new(),
            last_response: 0,
            late_answers: 0,
            grace: StallGrace::new(),
        })
    }
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        if now_ms < self.last_ms {
            return Err(Error::Invalid("backwards primary watch clock"));
        }
        self.grace
            .sample(self.last_ms, now_ms, self.last_probe, self.fresh_ms);
        self.last_ms = now_ms;
        Ok(())
    }
    fn current(&self, current: &Sequencer) -> Result<()> {
        if current.context() != &self.root.context()? || current.promotion.is_some() {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// True while a probe at `now_ms` would be paced out. Callers check this
    /// before allocating a sender sequence so a too-early probe burns no number.
    /// It advances the clock first, exactly as `probe_with_sequence` does, so a
    /// backwards clock still errors before the subtraction.
    fn probe_paced_out(&mut self, now_ms: u64) -> Result<bool> {
        self.advance(now_ms)?;
        Ok(self.last_probe.is_some_and(|last| now_ms - last < 50))
    }
    pub fn probe(&mut self, now_ms: u64) -> Result<PulseProbe> {
        self.probe_with_sequence(now_ms, self.next)
    }
    pub fn probe_with_sequence(&mut self, now_ms: u64, sequence: u64) -> Result<PulseProbe> {
        self.advance(now_ms)?;
        if sequence < self.next {
            return Err(Error::Stale);
        }
        if self.probe_paced_out(now_ms)? {
            return Err(Error::Stale);
        }
        let next = sequence.checked_add(1).ok_or(Error::Bounds)?;
        retire_probes(&self.root, &mut self.pending, &mut self.retired, now_ms)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Invalid("primary probe RNG"))?;
        let probe = PulseProbe {
            term: 0,
            sequence,
            nonce,
            tls: self.tls,
        };
        self.next = next;
        self.last_probe = Some(now_ms);
        self.pending.push_back((now_ms, probe.clone()));
        Ok(probe)
    }
    pub fn response(
        &mut self,
        current: &Sequencer,
        response: &PrimaryAlive,
        now_ms: u64,
    ) -> Result<()> {
        self.advance(now_ms)?;
        self.current(current)?;
        response.verify(&self.root)?;
        if response.sequence <= self.last_response
            || response.frontier.index > current.receipt().index
        {
            return Err(Error::Stale);
        }
        if response.frontier.index == current.receipt().index
            && response.frontier.digest(current.context())?
                != current.receipt().digest(current.context())?
        {
            return Err(Error::Conflict);
        }
        let mut matched = None;
        for (index, (sent, probe)) in self.pending.iter().enumerate() {
            if now_ms - *sent < 200 && response.challenge == probe.digest(&self.root)? {
                matched = Some(index);
                break;
            }
        }
        let Some(matched) = matched else {
            // A valid answer to one of this watch's probes, read after its
            // window: harmless. It is ignored and counted, never fresh; its
            // sequence is consumed so a replay of it still fails above.
            if take_late_probe(
                &self.root,
                &mut self.pending,
                &mut self.retired,
                &response.challenge,
            )? {
                self.last_response = response.sequence;
                self.late_answers = self.late_answers.saturating_add(1);
                return Ok(());
            }
            return Err(Error::Stale);
        };
        self.pending.remove(matched);
        self.last_response = response.sequence;
        self.fresh_ms = now_ms;
        self.grace.fresh();
        Ok(())
    }
    /// Invoke only after installation, never after decoding/validating a proposal.
    pub fn installed(&mut self, current: &Sequencer, now_ms: u64) -> Result<()> {
        self.advance(now_ms)?;
        self.current(current)?;
        if current.receipt().index < self.index {
            return Err(Error::Stale);
        }
        if current.receipt().index > self.index {
            self.index = current.receipt().index;
            self.fresh_ms = now_ms;
            self.grace.fresh();
        }
        Ok(())
    }
    pub fn expired(&mut self, current: &Sequencer, now_ms: u64) -> Result<bool> {
        self.advance(now_ms)?;
        self.current(current)?;
        Ok(now_ms - self.fresh_ms >= 200 && !self.grace.holds(now_ms))
    }
    /// Valid `PrimaryAlive` answers ignored because they arrived after their
    /// probe's 200 ms window ([`Self::response`] returned `Ok` without
    /// recording freshness).
    pub fn late_answers(&self) -> u64 {
        self.late_answers
    }
}
/// Client-side freshness; a valid pulse during play cannot conceal a stopped
/// game clock. Promotion always freezes until the separate recovery barrier.
pub struct ProgressWatch {
    root: Root,
    frontier: Receipt,
    activity: Activity,
    tls: [u8; 32],
    term: u64,
    next: u64,
    last_ms: u64,
    progress_ms: u64,
    last_probe: Option<u64>,
    pending: VecDeque<(u64, PulseProbe)>,
    retired: VecDeque<Hash>,
    last_pulse: u64,
    late_answers: u64,
    recovery: Option<u64>,
    promotion: Option<Promotion>,
    grace: StallGrace,
    // An idle Pulse refreshed the window since the last Idle -> Advancing
    // refresh; each idle answer funds at most one.
    idle_refresh: bool,
}
impl ProgressWatch {
    pub fn new(
        root: Root,
        frontier: Receipt,
        activity: Activity,
        tls: [u8; 32],
        now_ms: u64,
    ) -> Result<Self> {
        frontier.verify(&root.context()?)?;
        if frontier.term != 0 || activity == Activity::Recovering {
            return Err(Error::Invalid("initial watch term/mode"));
        }
        Ok(Self {
            root,
            frontier,
            activity,
            tls,
            term: 0,
            next: 1,
            last_ms: now_ms,
            progress_ms: now_ms,
            last_probe: None,
            pending: VecDeque::new(),
            retired: VecDeque::new(),
            last_pulse: 0,
            late_answers: 0,
            recovery: None,
            promotion: None,
            grace: StallGrace::new(),
            idle_refresh: false,
        })
    }
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        if now_ms < self.last_ms {
            return Err(Error::Invalid("backwards liveness clock"));
        }
        self.grace
            .sample(self.last_ms, now_ms, self.last_probe, self.progress_ms);
        self.last_ms = now_ms;
        Ok(())
    }
    pub fn status(&mut self, now_ms: u64) -> Result<WatchStatus> {
        self.advance(now_ms)?;
        Ok(if let Some(start) = self.recovery {
            if now_ms - start >= 5000 {
                WatchStatus::Paused
            } else {
                WatchStatus::Recovering
            }
        } else if now_ms - self.progress_ms >= 200 && !self.grace.holds(now_ms) {
            WatchStatus::Paused
        } else {
            WatchStatus::Live
        })
    }
    pub fn set_activity(&mut self, activity: Activity) -> Result<()> {
        if activity == Activity::Recovering {
            return Err(Error::Invalid("recovery requires signed promotion"));
        }
        // Play resuming after an idle phase starts a fresh no-progress window
        // at the watch's latest sample, so the first batch is not convicted
        // at once. This is local, not peer evidence: no stall deferral is
        // restored. One refresh per idle answer, and only while still live,
        // so toggling activity can neither sustain nor withdraw silence.
        if self.activity == Activity::Idle
            && activity == Activity::Advancing
            && self.idle_refresh
            && self.last_ms - self.progress_ms < 200
        {
            self.progress_ms = self.last_ms;
            self.idle_refresh = false;
        }
        self.activity = activity;
        Ok(())
    }
    /// True while a probe at `now_ms` would be paced out. Callers check this
    /// before allocating a sender sequence so a too-early probe burns no number.
    /// It advances the clock first, exactly as `probe_with_sequence` does, so a
    /// backwards clock still errors before the subtraction.
    fn probe_paced_out(&mut self, now_ms: u64) -> Result<bool> {
        self.advance(now_ms)?;
        Ok(self.last_probe.is_some_and(|last| now_ms - last < 50))
    }
    pub fn probe(&mut self, now_ms: u64) -> Result<PulseProbe> {
        self.probe_with_sequence(now_ms, self.next)
    }
    /// Use the player's shared control sender namespace across normal and
    /// prepared standby paths, retaining this watch's nonce/replay window.
    pub fn probe_with_sequence(&mut self, now_ms: u64, sequence: u64) -> Result<PulseProbe> {
        self.advance(now_ms)?;
        if sequence < self.next || sequence == 0 {
            return Err(Error::Stale);
        }
        if self.probe_paced_out(now_ms)? {
            return Err(Error::Stale);
        }
        let next = sequence.checked_add(1).ok_or(Error::Bounds)?;
        retire_probes(&self.root, &mut self.pending, &mut self.retired, now_ms)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Invalid("probe RNG"))?;
        let probe = PulseProbe {
            term: self.term,
            sequence,
            nonce,
            tls: self.tls,
        };
        self.next = next;
        self.last_probe = Some(now_ms);
        self.pending.push_back((now_ms, probe.clone()));
        Ok(probe)
    }
    /// Every refusal [`Self::accept_frontier`] makes, without adopting it.
    fn check_frontier(&self, frontier: &Receipt) -> Result<()> {
        frontier.verify(&self.root.context()?)?;
        if frontier.term > self.term
            || frontier.term < self.frontier.term
            || frontier.index < self.frontier.index
            || frontier.logical_ms < self.frontier.logical_ms
        {
            return Err(Error::Stale);
        }
        if frontier.index == self.frontier.index {
            if frontier.digest(&self.root.context()?)?
                != self.frontier.digest(&self.root.context()?)?
            {
                return Err(Error::Conflict);
            }
            return Ok(());
        }
        if self.frontier.index.checked_add(1) == Some(frontier.index)
            && frontier.parent != self.frontier.digest(&self.root.context()?)?
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn accept_frontier(&mut self, frontier: &Receipt) -> Result<bool> {
        self.check_frontier(frontier)?;
        if frontier.index == self.frontier.index {
            return Ok(false);
        }
        let progress = frontier.logical_ms > self.frontier.logical_ms;
        self.frontier = frontier.clone();
        Ok(progress)
    }
    pub fn committed(&mut self, frontier: &Receipt, now_ms: u64) -> Result<()> {
        self.advance(now_ms)?;
        let progress = self.accept_frontier(frontier)?;
        if progress {
            self.progress_ms = now_ms;
            self.grace.fresh();
        }
        Ok(())
    }
    pub fn pulse(&mut self, pulse: &Pulse, now_ms: u64) -> Result<()> {
        self.advance(now_ms)?;
        pulse.verify(&self.root)?;
        if pulse.term != self.term || pulse.sequence <= self.last_pulse {
            return Err(Error::Stale);
        }
        let mut matched = None;
        for (index, (sent, probe)) in self.pending.iter().enumerate() {
            if now_ms - *sent < 200 && pulse.challenge == probe.digest(&self.root)? {
                matched = Some(index);
                break;
            }
        }
        let Some(matched) = matched else {
            // A valid answer to one of this watch's probes, read after its
            // window: harmless. Its frontier is checked but not adopted, it is
            // never fresh, and its sequence is consumed so a replay of it
            // still fails above.
            if take_late_probe(
                &self.root,
                &mut self.pending,
                &mut self.retired,
                &pulse.challenge,
            )? {
                self.check_frontier(&pulse.frontier)?;
                self.last_pulse = pulse.sequence;
                self.late_answers = self.late_answers.saturating_add(1);
                return Ok(());
            }
            return Err(Error::Stale);
        };
        let progress = self.accept_frontier(&pulse.frontier)?;
        let idle = self.activity == Activity::Idle && pulse.activity == Activity::Idle;
        if progress || idle {
            self.progress_ms = now_ms;
            self.grace.fresh();
        }
        if idle {
            self.idle_refresh = true;
        }
        self.pending.remove(matched);
        self.last_pulse = pulse.sequence;
        Ok(())
    }
    /// Valid Pulses ignored because they arrived after their probe's 200 ms
    /// window ([`Self::pulse`] returned `Ok` without recording freshness).
    pub fn late_answers(&self) -> u64 {
        self.late_answers
    }
    pub fn promote(&mut self, promotion: &Promotion, now_ms: u64) -> Result<()> {
        self.advance(now_ms)?;
        promotion.verify(&self.root.context()?)?;
        if self.term != 0 {
            return Err(Error::Closed);
        }
        self.accept_frontier(&promotion.final_receipt)?;
        self.term = 1;
        self.pending.clear();
        self.retired.clear();
        self.recovery = Some(now_ms);
        self.promotion = Some(promotion.clone());
        Ok(())
    }
    /// The retained game has already validated its clock correction and signed
    /// Ready. Verify that no journal changed while waiting for every survivor.
    pub fn resume(
        &mut self,
        resume: &Resume,
        cut: &RecoveryCut,
        ready: &RecoveryReady,
        delivery: &DeliveryJournal,
        intents: &IntentJournal,
        now_ms: u64,
    ) -> Result<()> {
        self.advance(now_ms)?;
        let started = self.recovery.ok_or(Error::Closed)?;
        if now_ms - started >= 5000 || delivery.poisoned {
            return Err(Error::Closed);
        }
        let promotion = self.promotion.as_ref().ok_or(Error::Closed)?;
        if cut.tls != self.tls {
            return Err(Error::Unauthorized);
        }
        ready.verify(&self.root, promotion, cut)?;
        resume.verify(&self.root, promotion)?;
        if resume.membership != cut.membership
            || ready.applied != delivery.applied()
            || ready.tail != intents.tail()
        {
            return Err(Error::Conflict);
        }
        let mine = resume
            .cuts
            .iter()
            .find(|c| c.player == ready.player)
            .ok_or(Error::Unauthorized)?;
        if mine.input != ready.tail
            || mine.output != ready.applied
            || mine.clock_delta != ready.clock_delta
            || mine.challenge != ready.cut
        {
            return Err(Error::Conflict);
        }
        self.accept_frontier(&resume.membership.receipt)?;
        self.recovery = None;
        self.progress_ms = now_ms;
        self.grace.fresh();
        Ok(())
    }
}

fn control_kind(root: &Root, bytes: &[u8]) -> Result<u8> {
    if bytes.len() > 4096 {
        return Err(Error::Bounds);
    }
    let mut r = Reader(bytes);
    root.context()?.read_binding(&mut r)?;
    if r.u64()? > 1 {
        return Err(Error::Invalid("control term"));
    }
    r.u8()
}

/// Verify a standby-signed membership certificate received on the pair link
/// (control kind 9) against the original's installed receipt and image.
/// Returns `None` for an exact retry of `current`. Decode authenticates the
/// standby's signature, root binding, term/sequence frontier and the 2048-byte
/// bound. A refusal carries `true` only once that authentication passed.
fn accept_pair_certificate(
    replay: &ReplaySession,
    root: &Root,
    installed: &Receipt,
    image: &[u8],
    current: Option<&MembershipCertificate>,
    bytes: &[u8],
) -> std::result::Result<Option<MembershipCertificate>, (Error, bool)> {
    let certificate = MembershipCertificate::decode(root, bytes).map_err(|error| (error, false))?;
    accept_signed_certificate(replay, root, installed, image, current, bytes, certificate)
        .map_err(|error| (error, true))
}
fn accept_signed_certificate(
    replay: &ReplaySession,
    root: &Root,
    installed: &Receipt,
    image: &[u8],
    current: Option<&MembershipCertificate>,
    bytes: &[u8],
    certificate: MembershipCertificate,
) -> Result<Option<MembershipCertificate>> {
    let context = root.context()?;
    // Reserve, but do not yet record, the embedded receipt and the certificate.
    // Different bytes at a remembered standby sequence still fault the shared
    // session here. A record that a sibling consumer of the same ledger (a
    // local seat) already holds is not new, and is not recorded twice.
    let receipt = replay.begin(
        root.standby,
        certificate.receipt.sequence,
        &certificate.receipt.encode(&context)?,
        true,
    )?;
    let incoming = replay.begin(root.standby, certificate.sequence, bytes, false)?;
    let exact_retry = current == Some(&certificate);
    if !exact_retry {
        if certificate.receipt != *installed {
            return Err(match certificate.receipt.index.cmp(&installed.index) {
                std::cmp::Ordering::Less => Error::Stale,
                std::cmp::Ordering::Equal => Error::Conflict,
                std::cmp::Ordering::Greater => Error::Gap,
            });
        }
        let image = SessionImage::decode(root, image)?;
        if certificate.members != image.members
            || certificate.revision != image.membership_revision
            || certificate.next_player != image.next_player
        {
            return Err(Error::Conflict);
        }
        if let Some(previous) = current {
            certificate.follows(root, previous)?;
        }
    }
    receipt.commit()?;
    incoming.commit()?;
    Ok((!exact_retry).then_some(certificate))
}

/// Attribution of a failed [`StandbyActor::receive_classified`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StandbyFault {
    /// The original's frame failed a named protocol check. Nothing was
    /// restored, installed or acknowledged, and the actor is still usable.
    Frame(Error),
    /// A standby-side fault. The caller must treat it as permanent.
    Local(Error),
}
impl StandbyFault {
    pub fn error(&self) -> &Error {
        match self {
            Self::Frame(error) | Self::Local(error) => error,
        }
    }
    pub fn into_error(self) -> Error {
        match self {
            Self::Frame(error) | Self::Local(error) => error,
        }
    }
}
/// Marks an error as raised by a protocol check of a peer's frame.
fn by_frame<T>(frame: &mut bool, result: Result<T>) -> Result<T> {
    if result.is_err() {
        *frame = true;
    }
    result
}
/// The fixed-pair replica on the standby's authenticated original-host link.
/// Installation, receipts and failure detection share one owned sequencer.
/// Game restore callbacks validate outputs and return a canonical fresh full session image for comparison;
/// they must not publish effects or mutate the active game instance.
pub struct StandbyActor {
    descriptor: Descriptor,
    sequencer: Sequencer,
    members: Vec<SessionMember>,
    channel: Channel,
    watch: PrimaryWatch,
    checkpoint_received_ms: u64,
    // Only an identical delta actually installed here may reuse the target
    // image after an ACK is lost. A claimed target hash alone is insufficient.
    last_delta: Option<(u64, Hash)>,
    // The receipt whose reply (receipt then certificate) is still queued, and
    // the reply's last transfer ID. Identical retries coalesce onto it.
    queued_reply: Option<(Receipt, u64)>,
    failed: Option<Error>,
}
impl StandbyActor {
    pub fn new(
        descriptor: Descriptor,
        sequencer: Sequencer,
        channel: Channel,
        now_ms: u64,
    ) -> Result<Self> {
        descriptor.verify()?;
        if sequencer.session_root.as_ref() != Some(&descriptor.root)
            || channel.descriptor != descriptor
            || channel.side != ChannelSide::Server
            || channel.binding.client != LinkRole::Original
            || channel.binding.server != LinkRole::Standby
            || channel.term != 0
        {
            return Err(Error::Unauthorized);
        }
        let members = SessionImage::decode(&descriptor.root, sequencer.image())?.members;
        let watch = PrimaryWatch::new(descriptor.root.clone(), &sequencer, channel.tls(), now_ms)?;
        Ok(Self {
            descriptor,
            sequencer,
            members,
            channel,
            watch,
            checkpoint_received_ms: now_ms,
            last_delta: None,
            queued_reply: None,
            failed: None,
        })
    }
    /// Serve a player's prepared standby control path from the SAME installed
    /// sequencer. Before promotion this path receives public liveness receipts
    /// only; it cannot send inputs or request the complete hidden game image.
    pub fn receive_control_probe(
        &mut self,
        channel: &mut Channel,
        wire: &[u8],
        now_ms: u64,
        keys: &Keys,
        activity: Activity,
    ) -> Result<bool> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if keys.public_key().to_bytes() != self.descriptor.root.standby
            || channel.descriptor.root != self.descriptor.root
            || channel.side != ChannelSide::Server
            || channel.term != 0
            || channel.binding.client != LinkRole::ControlPlayer
            || channel.binding.server != LinkRole::Standby
            || !self.members.iter().any(|m| {
                Some(m.player) == channel.authenticated_player && m.key == Some(channel.remote_key)
            })
        {
            return Err(Error::Unauthorized);
        }
        self.watch.advance(now_ms)?;
        let Some((kind, _, bytes)) = channel.receive(wire, now_ms)? else {
            return Ok(false);
        };
        if kind != PacketKind::Control || control_kind(&self.descriptor.root, &bytes)? != 10 {
            return Err(Error::Unauthorized);
        }
        let probe = PulseProbe::decode(&self.descriptor.root, &bytes)?;
        if probe.tls != channel.tls() {
            return Err(Error::Unauthorized);
        }
        let incoming = self.sequencer.sender.replay.begin(
            channel.remote_key,
            probe.sequence,
            &bytes,
            false,
        )?;
        if !incoming.is_new() {
            return Ok(false);
        }
        let sequence = self.sequence()?;
        let response = Pulse::respond(
            &self.descriptor.root,
            &self.sequencer,
            &probe,
            channel.tls(),
            activity,
            sequence,
            keys,
        )?;
        channel.enqueue(
            PacketKind::Control,
            &response.encode(&self.descriptor.root)?,
        )?;
        incoming.commit()?;
        Ok(true)
    }
    pub fn receipt(&self) -> &Receipt {
        self.sequencer.receipt()
    }
    /// Valid `PrimaryAlive` answers ignored as late ([`PrimaryWatch::late_answers`]).
    pub fn late_answers(&self) -> u64 {
        self.watch.late_answers()
    }
    /// Late chunks of expired transfers ignored on the pair link
    /// ([`Channel::late_chunks`]).
    pub fn late_chunks(&self) -> u64 {
        self.channel.late_chunks()
    }
    pub fn failure(&self) -> Option<&Error> {
        self.failed.as_ref()
    }
    pub fn image(&self) -> &[u8] {
        self.sequencer.image()
    }
    pub fn membership_certificate(&self, keys: &Keys) -> Result<MembershipCertificate> {
        self.sequencer.membership_certificate(keys)
    }
    fn sequence(&mut self) -> Result<u64> {
        self.sequencer.sender.allocate()
    }
    /// Every receipt sent to the original is followed by the certificate for
    /// that exact receipt, queued together. The certificate's sequence is the
    /// receipt's reserved successor, so a retry resends byte-identical bytes
    /// and allocates nothing. While the same reply is still queued, a retry
    /// queues nothing more. A full queue is the original's traffic, so that
    /// refusal is a frame fault; the install stands and a retry resends it.
    fn reply(&mut self, receipt: &Receipt, keys: &Keys, frame: &mut bool) -> Result<()> {
        if self
            .queued_reply
            .as_ref()
            .is_some_and(|(queued, _)| queued == receipt)
        {
            return Ok(());
        }
        let certificate = self.sequencer.membership_certificate(keys)?;
        if &certificate.receipt != receipt {
            return Err(Error::Invalid("membership certificate frontier"));
        }
        let receipt_bytes = receipt.encode(&self.descriptor.root.context()?)?;
        let certificate_bytes = certificate.encode(&self.descriptor.root)?;
        let last = by_frame(
            frame,
            self.channel.enqueue_replies(&[
                (PacketKind::Receipt, &receipt_bytes),
                (PacketKind::Control, &certificate_bytes),
            ]),
        )?;
        self.queued_reply = Some((receipt.clone(), last));
        Ok(())
    }
    pub fn probe(&mut self, now_ms: u64) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if self.watch.probe_paced_out(now_ms)? {
            return Err(Error::Stale);
        }
        let probe = self
            .watch
            .probe_with_sequence(now_ms, self.sequencer.sender.allocate()?)?;
        self.channel
            .enqueue(PacketKind::Control, &probe.encode(&self.descriptor.root)?)?;
        Ok(())
    }
    pub fn expired(&mut self, now_ms: u64) -> Result<bool> {
        self.watch.expired(&self.sequencer, now_ms)
    }
    /// No receipt is queued until complete session validation and game restore
    /// equivalence succeed and the entire image/outbox is atomically installed.
    pub fn receive(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        keys: &Keys,
        activity: Activity,
        restore: impl FnMut(&Candidate, &SessionImage, &SessionImage) -> Result<Vec<u8>>,
    ) -> Result<Option<Receipt>> {
        self.receive_classified(wire, now_ms, keys, activity, restore)
            .map_err(StandbyFault::into_error)
    }
    /// [`Self::receive`], with the failure attributed. Only a named protocol
    /// check of the original's frame yields [`StandbyFault::Frame`]: physical
    /// framing and binding, decoding, replay order, frontier, delta and
    /// candidate validation, and liveness-response checks. Every other error
    /// is [`StandbyFault::Local`], including a failed actor or replay session
    /// (even when an original's conflicting record poisoned it), the watch
    /// clock, keys, restore equivalence, installation and all post-install
    /// receipt, replay-commit and watch bookkeeping. `RateLimited` is a
    /// `Frame` fault and leaves the frame queued, exactly as before. A reply
    /// (receipt and certificate, or the Pulse answering a probe) that the send
    /// queue cannot hold is also a `Frame` fault: the original's traffic filled
    /// it. An install that already happened stands, and the original's retry
    /// resends its reply; an unanswered probe is not recorded, so its retry is
    /// answered.
    pub fn receive_classified(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        keys: &Keys,
        activity: Activity,
        restore: impl FnMut(&Candidate, &SessionImage, &SessionImage) -> Result<Vec<u8>>,
    ) -> std::result::Result<Option<Receipt>, StandbyFault> {
        let mut frame = false;
        match self.receive_inner(wire, now_ms, keys, activity, restore, &mut frame) {
            Ok(receipt) => Ok(receipt),
            Err(error)
                if frame
                    && self.failed.is_none()
                    && self.sequencer.sender.replay.live().is_ok() =>
            {
                Err(StandbyFault::Frame(error))
            }
            Err(error) => Err(StandbyFault::Local(error)),
        }
    }
    fn receive_inner(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        keys: &Keys,
        activity: Activity,
        mut restore: impl FnMut(&Candidate, &SessionImage, &SessionImage) -> Result<Vec<u8>>,
        frame: &mut bool,
    ) -> Result<Option<Receipt>> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        self.watch.advance(now_ms)?;
        if keys.public_key().to_bytes() != self.descriptor.root.standby {
            return Err(Error::Unauthorized);
        }
        let Some((kind, _, bytes)) = by_frame(frame, self.channel.receive(wire, now_ms))? else {
            return Ok(None);
        };
        let root = &self.descriptor.root;
        let context = root.context()?;
        match kind {
            PacketKind::Candidate | PacketKind::Delta => {
                let delta_digest = (kind == PacketKind::Delta)
                    .then(|| hash(b"fray/migration/delta-wire/v1\0", &bytes));
                let incoming;
                let candidate = if let Some(digest) = delta_digest {
                    let delta = by_frame(frame, CandidateDelta::decode(&context, &bytes))?;
                    incoming = by_frame(
                        frame,
                        self.sequencer.sender.replay.begin(
                            root.host,
                            delta.sequence,
                            &bytes,
                            false,
                        ),
                    )?;
                    if delta.index == self.sequencer.receipt.index {
                        if self.last_delta != Some((delta.index, digest)) {
                            return by_frame(frame, Err(Error::Conflict));
                        }
                        // Identical bytes were fully validated and installed.
                        // Do not reconstruct or run native restore again, and
                        // do not let retries refresh any liveness/security age.
                        let receipt = self.sequencer.receipt.clone();
                        self.reply(&receipt, keys, frame)?;
                        incoming.commit()?;
                        return Ok(Some(receipt));
                    } else {
                        // Reject invalid frontiers before allowing a compact
                        // wire message to expand into a complete native image.
                        if delta.term != self.sequencer.receipt.term {
                            return by_frame(frame, Err(Error::Closed));
                        }
                        let next = self
                            .sequencer
                            .receipt
                            .index
                            .checked_add(1)
                            .ok_or(Error::Bounds)?;
                        if delta.index != next
                            || delta.parent != self.sequencer.receipt.digest(&context)?
                        {
                            return by_frame(frame, Err(Error::Stale));
                        }
                        if delta.patch.base != self.sequencer.receipt.state {
                            return by_frame(frame, Err(Error::Conflict));
                        }
                        by_frame(frame, delta.expand(self.sequencer.image()))?
                    }
                } else {
                    let candidate = by_frame(frame, Candidate::decode(&context, &bytes))?;
                    incoming = by_frame(
                        frame,
                        self.sequencer.sender.replay.begin(
                            root.host,
                            candidate.sequence,
                            &bytes,
                            false,
                        ),
                    )?;
                    candidate
                };
                let staged = by_frame(frame, self.sequencer.stage(candidate))?;
                let image = by_frame(frame, SessionImage::decode(root, &staged.candidate.image))?;
                let previous = SessionImage::decode(root, self.sequencer.image())?;
                let restore_once = |restore: &mut dyn FnMut(
                    &Candidate,
                    &SessionImage,
                    &SessionImage,
                ) -> Result<Vec<u8>>| {
                    self.sequencer.sender.replay.live()?;
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        restore(&staged.candidate, &image, &previous)
                    })) {
                        Ok(Ok(bytes)) if bytes == staged.candidate.image => Ok(()),
                        _ => Err(Error::Invalid("standby restore equivalence")),
                    }
                };
                if restore_once(&mut restore).is_err() {
                    if let Err(error) = restore_once(&mut restore) {
                        self.failed = Some(error.clone());
                        return Err(error);
                    }
                }
                let previous_clock = self.sequencer.receipt.logical_ms;
                let previous_index = self.sequencer.receipt.index;
                let receipt = self.sequencer.install(staged, keys)?;
                incoming.commit()?;
                if receipt.index > previous_index {
                    self.last_delta = delta_digest.map(|digest| (receipt.index, digest));
                }
                if receipt.logical_ms > previous_clock {
                    self.checkpoint_received_ms = now_ms;
                }
                self.members = image.members;
                self.watch.installed(&self.sequencer, now_ms)?;
                self.reply(&receipt, keys, frame)?;
                Ok(Some(receipt))
            }
            PacketKind::Control => {
                match by_frame(frame, control_kind(root, &bytes))? {
                    1 => {
                        let ack = by_frame(frame, CapabilityAck::decode(root, &bytes))?;
                        let issuer = by_frame(
                            frame,
                            root.member(ack.player)
                                .and_then(|member| member.key.ok_or(Error::Unauthorized)),
                        )?;
                        by_frame(
                            frame,
                            self.sequencer.sender.replay.archived_duplicate(
                                issuer,
                                ack.sequence,
                                &bytes,
                            ),
                        )?;
                    }
                    10 => {
                        let probe = by_frame(frame, PulseProbe::decode(root, &bytes))?;
                        if probe.tls != self.channel.tls() {
                            return by_frame(frame, Err(Error::Unauthorized));
                        }
                        let incoming = by_frame(
                            frame,
                            self.sequencer.sender.replay.begin(
                                root.host,
                                probe.sequence,
                                &bytes,
                                false,
                            ),
                        )?;
                        if !incoming.is_new() {
                            return Ok(None);
                        }
                        // A reply the queue refuses still burns this sender
                        // sequence. The gap is harmless: the original's replay
                        // set and its monotonic probe-response check both
                        // tolerate gaps.
                        let sequence = self.sequence()?;
                        let pulse = Pulse::respond(
                            &self.descriptor.root,
                            &self.sequencer,
                            &probe,
                            self.channel.tls(),
                            activity,
                            sequence,
                            keys,
                        )?;
                        let pulse = pulse.encode(&self.descriptor.root)?;
                        // A full queue is the original's traffic: a frame
                        // fault. The probe stays unrecorded, so a retry of it
                        // is answered.
                        by_frame(frame, self.channel.enqueue(PacketKind::Control, &pulse))?;
                        incoming.commit()?;
                    }
                    11 => {
                        let response = by_frame(frame, PrimaryAlive::decode(root, &bytes))?;
                        by_frame(
                            frame,
                            self.sequencer.sender.replay.receipt(&response.frontier),
                        )?;
                        let incoming = by_frame(
                            frame,
                            self.sequencer.sender.replay.begin(
                                root.host,
                                response.sequence,
                                &bytes,
                                false,
                            ),
                        )?;
                        // The watch's own clock and term are standby state.
                        self.watch.advance(now_ms)?;
                        self.watch.current(&self.sequencer)?;
                        by_frame(
                            frame,
                            self.watch.response(&self.sequencer, &response, now_ms),
                        )?;
                        incoming.commit()?;
                    }
                    _ => return by_frame(frame, Err(Error::Unauthorized)),
                }
                Ok(None)
            }
            _ => by_frame(frame, Err(Error::Unauthorized)),
        }
    }
    pub fn poll_send(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        self.sequencer.sender.replay.live()?;
        let wire = self.channel.poll_send(now_ms)?;
        if let (Some(wire), Some((_, last))) = (&wire, &self.queued_reply) {
            let frame = Frame::decode(wire)?;
            if frame.transfer == *last && frame.ordinal + 1 == frame.count {
                self.queued_reply = None;
            }
        }
        Ok(wire)
    }
    /// Consuming the actor prevents reopening its old sequencer. The returned
    /// warm channel carries promotion while the owned Recovery reconciles at C.
    pub fn begin_recovery(
        mut self,
        keys: &Keys,
        now_ms: u64,
        transport_closed: bool,
    ) -> Result<(Recovery, Channel)> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if !transport_closed && !self.expired(now_ms)? {
            return Err(Error::Stale);
        }
        self.watch.advance(now_ms)?;
        let mut recovery = Recovery::begin_session(self.descriptor, self.sequencer, keys, now_ms)?;
        recovery.security_anchor = self.checkpoint_received_ms;
        self.channel.promote_and_announce(recovery.promotion())?;
        Ok((recovery, self.channel))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrimaryEvent {
    Committed {
        receipt: Receipt,
        outputs: Vec<CertifiedOutput>,
    },
    Promoted(Promotion),
}
/// One result of [`PrimaryActor::receive_update`]. `Membership` reports a newly
/// accepted standby-signed certificate. It arrives on the frame after the
/// `Committed` event for the same receipt, and equals the certificate
/// [`PrimaryActor::membership_certificate`] now exposes. [`PrimaryEvent`]
/// itself is unchanged, so existing exhaustive matches keep compiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrimaryUpdate {
    Event(PrimaryEvent),
    Membership(MembershipCertificate),
}
/// Original-host replication/publication gate. The game stages its authority,
/// local transports and UI before prepare; only Committed permits adoption.
pub struct PrimaryActor {
    descriptor: Descriptor,
    primary: Primary,
    channel: Channel,
    watch: ProgressWatch,
    last_full_clock: u64,
    pending_is_delta: bool,
    failed: Option<Error>,
}
impl PrimaryActor {
    pub fn root(&self) -> &Root {
        &self.descriptor.root
    }
    pub fn new(
        descriptor: Descriptor,
        primary: Primary,
        channel: Channel,
        activity: Activity,
        now_ms: u64,
    ) -> Result<Self> {
        descriptor.verify()?;
        if primary.context != descriptor.root.context()?
            || channel.descriptor != descriptor
            || channel.side != ChannelSide::Client
            || channel.binding.client != LinkRole::Original
            || channel.binding.server != LinkRole::Standby
            || channel.term != 0
        {
            return Err(Error::Unauthorized);
        }
        let image = SessionImage::decode(&descriptor.root, primary.committed_image())?;
        image.validate_initial(&descriptor.root)?;
        if image.logical_ms != primary.receipt().logical_ms {
            return Err(Error::Conflict);
        }
        let watch = ProgressWatch::new(
            descriptor.root.clone(),
            primary.receipt().clone(),
            activity,
            channel.tls(),
            now_ms,
        )?;
        let last_full_clock = primary.receipt().logical_ms;
        Ok(Self {
            descriptor,
            primary,
            channel,
            watch,
            last_full_clock,
            pending_is_delta: false,
            failed: None,
        })
    }
    /// An original authority which received the signed close may retain its
    /// human client over this prepared warm link. Consuming the actor removes
    /// its publication capability; it cannot reopen as another authority.
    pub fn into_recovery_channel(self) -> Result<Channel> {
        if !self.primary.closed {
            return Err(Error::Invalid("original authority is not fenced"));
        }
        Ok(self.channel)
    }
    pub fn attach_player(
        &mut self,
        channel: &Channel,
        membership: MembershipCertificate,
    ) -> Result<PlayerQueue> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        self.primary.attach_player(channel, membership)
    }
    pub fn primary(&self) -> &Primary {
        &self.primary
    }
    /// The newest verified standby-signed membership certificate; see
    /// [`Primary::membership_certificate`].
    pub fn membership_certificate(&self) -> Option<&MembershipCertificate> {
        self.primary.membership_certificate()
    }
    /// Valid Pulses ignored as late ([`ProgressWatch::late_answers`]).
    pub fn late_answers(&self) -> u64 {
        self.watch.late_answers()
    }
    /// Late chunks of expired transfers ignored on the pair link
    /// ([`Channel::late_chunks`]).
    pub fn late_chunks(&self) -> u64 {
        self.channel.late_chunks()
    }
    pub fn failure(&self) -> Option<&Error> {
        self.failed.as_ref()
    }
    /// The game runner calls this after its bounded fresh-restore retry fails.
    /// Keep the owned pending frontier for a later signed fence, but stop all
    /// publication and traffic which could claim the original is healthy.
    pub fn pause(&mut self, error: Error) {
        if self.failed.is_none() {
            self.failed = Some(error);
        }
    }
    pub fn claim_adoption(&mut self, receipt: &Receipt) -> Result<()> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        self.primary.claim_adoption(receipt)
    }
    /// Runs the game's validated adoption seam against this owned publication
    /// gate. The game consumes claim_adoption before releasing local effects.
    pub fn adopt<T>(&mut self, game: impl FnOnce(&mut Primary) -> Result<T>) -> Result<T> {
        self.primary.sender.replay.live()?;
        if self.primary.closed || self.failed.is_some() {
            return Err(Error::Closed);
        }
        if self.primary.pending.is_some() || self.primary.receipt.index <= self.primary.adopted {
            return Err(Error::Stale);
        }
        // Adoption can consume its one-use slot or mutate local effects before
        // an error/unwind. It cannot be retried safely against the live runner.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| game(&mut self.primary)))
                .unwrap_or(Err(Error::Invalid("primary adoption panic")));
        if let Err(error) = &result {
            self.pause(error.clone());
        }
        result
    }
    pub fn status(&mut self, now_ms: u64) -> Result<WatchStatus> {
        self.watch.advance(now_ms)?;
        if self.primary.sender.replay.live().is_err()
            || self.failed.is_some() && !self.primary.closed
        {
            return Ok(WatchStatus::Paused);
        }
        self.watch.status(now_ms)
    }
    pub fn set_activity(&mut self, activity: Activity) -> Result<()> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        self.watch.set_activity(activity)
    }
    pub fn prepare(
        &mut self,
        image: SessionImage,
        watermarks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<()> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        let root = &self.descriptor.root;
        let previous = SessionImage::decode(root, self.primary.committed_image())?;
        image.validate_successor(root, &previous, &watermarks, image.logical_ms)?;
        let bytes = image.encode(root)?;
        let candidate = self
            .primary
            .proposal(bytes, image.logical_ms, watermarks, outputs)?;
        let context = root.context()?;
        let full = candidate.encode(&context)?;
        // Periodic full checkpoints follow advancing GAME time, as specified
        // by the protocol. Every intervening delta is still materialized and
        // validated before receipt; recovery never walks a delta chain.
        let delta = if candidate.image.len() >= 4096
            && candidate.logical_ms.saturating_sub(self.last_full_clock) < 250
        {
            match CandidateDelta::between(self.primary.committed_image(), &candidate) {
                Ok(delta) => Some(delta.encode(&context)?),
                Err(Error::Bounds) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let use_delta = delta.as_ref().is_some_and(|bytes| bytes.len() < full.len());
        self.channel.enqueue(
            if use_delta {
                PacketKind::Delta
            } else {
                PacketKind::Candidate
            },
            if use_delta {
                delta.as_ref().unwrap()
            } else {
                &full
            },
        )?;
        self.pending_is_delta = use_delta;
        self.primary.pending = Some(candidate);
        Ok(())
    }
    pub fn retry(&mut self) -> Result<()> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        let candidate = self.primary.pending().ok_or(Error::Stale)?;
        let context = self.descriptor.root.context()?;
        let (kind, bytes) = if self.pending_is_delta {
            (
                PacketKind::Delta,
                CandidateDelta::between(self.primary.committed_image(), candidate)?
                    .encode(&context)?,
            )
        } else {
            (PacketKind::Candidate, candidate.encode(&context)?)
        };
        self.channel.enqueue(kind, &bytes)?;
        Ok(())
    }
    pub fn probe(&mut self, now_ms: u64) -> Result<()> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if self.watch.probe_paced_out(now_ms)? {
            return Err(Error::Stale);
        }
        let probe = self
            .watch
            .probe_with_sequence(now_ms, self.primary.sender.allocate()?)?;
        self.channel
            .enqueue(PacketKind::Control, &probe.encode(&self.descriptor.root)?)?;
        Ok(())
    }
    /// [`Self::receive_update`] without membership notices: an accepted
    /// certificate is still verified and exposed, but reported as `None`.
    pub fn receive(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        keys: &Keys,
    ) -> Result<Option<PrimaryEvent>> {
        Ok(match self.receive_update(wire, now_ms, keys)? {
            Some(PrimaryUpdate::Event(event)) => Some(event),
            Some(PrimaryUpdate::Membership(_)) | None => None,
        })
    }
    /// Receive one pair-link frame, reporting an accepted membership
    /// certificate as [`PrimaryUpdate::Membership`].
    pub fn receive_update(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        keys: &Keys,
    ) -> Result<Option<PrimaryUpdate>> {
        self.primary.sender.replay.live()?;
        self.watch.advance(now_ms)?;
        if keys.public_key().to_bytes() != self.descriptor.root.host {
            return Err(Error::Unauthorized);
        }
        let Some((kind, _, bytes)) = self.channel.receive(wire, now_ms)? else {
            return Ok(None);
        };
        let root = &self.descriptor.root;
        // A failed authority may still learn the sequencer's signed close so
        // its retained human client can recover. No receipt or liveness reply
        // may reopen publication or make a failed original look healthy.
        if self.failed.is_some()
            && (kind != PacketKind::Control || control_kind(root, &bytes)? != 6)
        {
            return Err(Error::Closed);
        }
        match kind {
            PacketKind::Receipt => {
                let receipt = Receipt::decode(&root.context()?, &bytes)?;
                let incoming = self.primary.sender.replay.begin(
                    root.standby,
                    receipt.sequence,
                    &bytes,
                    false,
                )?;
                let duplicate = receipt == *self.primary.receipt();
                let outputs = self.primary.acknowledge(receipt.clone())?;
                if !duplicate && !self.pending_is_delta {
                    self.last_full_clock = receipt.logical_ms;
                }
                self.watch.committed(&receipt, now_ms)?;
                incoming.commit()?;
                Ok(
                    (!duplicate).then_some(PrimaryUpdate::Event(PrimaryEvent::Committed {
                        receipt,
                        outputs,
                    })),
                )
            }
            PacketKind::Control => {
                match control_kind(root, &bytes)? {
                    2 => {
                        let armed = Armed::decode(&root.context()?, &bytes)?;
                        self.primary.sender.replay.archived_duplicate(
                            root.standby,
                            armed.sequence,
                            &bytes,
                        )?;
                        self.primary.sender.replay.receipt(&armed.receipt)?;
                    }
                    5 => {
                        let pulse = Pulse::decode(root, &bytes)?;
                        self.primary.sender.replay.receipt(&pulse.frontier)?;
                        let incoming = self.primary.sender.replay.begin(
                            root.standby,
                            pulse.sequence,
                            &bytes,
                            false,
                        )?;
                        self.watch.pulse(&pulse, now_ms)?;
                        incoming.commit()?;
                    }
                    9 => {
                        if let Some(certificate) = accept_pair_certificate(
                            &self.primary.sender.replay,
                            root,
                            &self.primary.receipt,
                            &self.primary.committed,
                            self.primary.membership.as_ref(),
                            &bytes,
                        )
                        .map_err(|(error, _)| error)?
                        {
                            self.primary.membership = Some(certificate.clone());
                            return Ok(Some(PrimaryUpdate::Membership(certificate)));
                        }
                    }
                    6 => {
                        let promotion = Promotion::decode(&root.context()?, &bytes)?;
                        self.primary
                            .sender
                            .replay
                            .receipt(&promotion.final_receipt)?;
                        let incoming = self.primary.sender.replay.begin(
                            root.standby,
                            promotion.sequence,
                            &bytes,
                            false,
                        )?;
                        self.primary.close(&promotion)?;
                        self.watch.promote(&promotion, now_ms)?;
                        self.channel.promote(&promotion)?;
                        incoming.commit()?;
                        return Ok(Some(PrimaryUpdate::Event(PrimaryEvent::Promoted(
                            promotion,
                        ))));
                    }
                    10 => {
                        let probe = PulseProbe::decode(root, &bytes)?;
                        if probe.tls != self.channel.tls() {
                            return Err(Error::Unauthorized);
                        }
                        let incoming = self.primary.sender.replay.begin(
                            root.standby,
                            probe.sequence,
                            &bytes,
                            false,
                        )?;
                        if !incoming.is_new() {
                            return Ok(None);
                        }
                        let sequence = self.primary.sender.allocate()?;
                        let response = PrimaryAlive::respond(
                            root,
                            &self.primary,
                            &probe,
                            self.channel.tls(),
                            sequence,
                            keys,
                        )?;
                        self.channel
                            .enqueue(PacketKind::Control, &response.encode(root)?)?;
                        incoming.commit()?;
                    }
                    _ => return Err(Error::Unauthorized),
                }
                Ok(None)
            }
            _ => Err(Error::Unauthorized),
        }
    }
    pub fn poll_send(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        self.primary.sender.replay.live()?;
        if self.failed.is_some() || self.primary.sender.replay.live().is_err() {
            return Ok(None);
        }
        self.channel.poll_send(now_ms)
    }
}

/// Final per-connection recovery cut. Only the sealed survivor may acknowledge
/// this nonce, on this TLS connection, after applying outputs and rebasing its
/// retained client. No game checkpoint or hidden state is included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCut {
    pub sequence: u64,
    pub player: u64,
    pub nonce: [u8; 32],
    pub tls: [u8; 32],
    pub membership: MembershipCertificate,
    pub signature: SignatureBytes,
}
impl RecoveryCut {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(&root.context()?, 1, 12, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.nonce);
        bytes.extend(self.tls);
        put_bytes(&mut bytes, &self.membership.encode(root)?, 2048)?;
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    pub fn verify(&self, root: &Root, promotion: &Promotion) -> Result<()> {
        promotion.verify(&root.context()?)?;
        self.membership.verify(root)?;
        let receipt = &self.membership.receipt;
        if receipt.term != 1
            || receipt.index <= promotion.final_receipt.index
            || receipt.logical_ms != promotion.final_receipt.logical_ms
            || !self
                .membership
                .members
                .iter()
                .any(|m| m.player == self.player)
        {
            return Err(Error::Conflict);
        }
        verify(root.standby, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root, promotion: &Promotion) -> Result<Vec<u8>> {
        self.verify(root, promotion)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, promotion: &Promotion, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        if r.u64()? != 1 || r.u8()? != 12 {
            return Err(Error::Invalid("recovery cut kind/term"));
        }
        let cut = Self {
            sequence: r.u64()?,
            player: r.u64()?,
            nonce: r.array()?,
            tls: r.array()?,
            membership: MembershipCertificate::decode(root, &r.bytes(2048)?)?,
            signature: r.array()?,
        };
        r.finish()?;
        cut.verify(root, promotion)?;
        Ok(cut)
    }
    fn watermark(&self) -> Result<&Watermark> {
        self.membership
            .receipt
            .watermarks
            .iter()
            .find(|m| m.player == self.player && !m.retired)
            .ok_or(Error::Gap)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReady {
    pub sequence: u64,
    pub player: u64,
    pub cut: Hash,
    pub applied: u64,
    pub tail: u64,
    pub clock_delta: i64,
    pub tls: [u8; 32],
    pub signature: SignatureBytes,
}
impl RecoveryReady {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence == 0 || self.clock_delta.unsigned_abs() > 250 {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(&root.context()?, 1, 13, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.cut);
        bytes.extend(self.applied.to_be_bytes());
        bytes.extend(self.tail.to_be_bytes());
        bytes.extend(self.clock_delta.to_be_bytes());
        bytes.extend(self.tls);
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    /// The game validates and performs its bounded clock rebase before calling
    /// this. Exact retained journals, never reconstructed fields, prove the cut.
    pub fn sign(
        root: &Root,
        promotion: &Promotion,
        cut: &RecoveryCut,
        tls: [u8; 32],
        delivery: &DeliveryJournal,
        intents: &IntentJournal,
        clock_delta: i64,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        cut.verify(root, promotion)?;
        if delivery.poisoned || cut.tls != tls {
            return Err(Error::Unauthorized);
        }
        let mut ready = Self {
            sequence,
            player: cut.player,
            cut: cut.digest(root)?,
            applied: delivery.applied(),
            tail: intents.tail(),
            clock_delta,
            tls,
            signature: [0; 64],
        };
        ready.signature = sign(keys, ready.digest(root)?);
        ready.verify(root, promotion, cut)?;
        Ok(ready)
    }
    pub fn verify(&self, root: &Root, promotion: &Promotion, cut: &RecoveryCut) -> Result<()> {
        cut.verify(root, promotion)?;
        let mark = cut.watermark()?;
        if self.player != cut.player
            || self.cut != cut.digest(root)?
            || self.tls != cut.tls
            || self.applied != mark.output_ack
            || self.tail != mark.input
        {
            return Err(Error::Conflict);
        }
        let key = cut
            .membership
            .members
            .iter()
            .find(|m| m.player == self.player)
            .and_then(|m| m.key)
            .ok_or(Error::Unauthorized)?;
        verify(key, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root, promotion: &Promotion, cut: &RecoveryCut) -> Result<Vec<u8>> {
        self.verify(root, promotion, cut)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(
        root: &Root,
        promotion: &Promotion,
        cut: &RecoveryCut,
        bytes: &[u8],
    ) -> Result<Self> {
        if bytes.len() > 512 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        if r.u64()? != 1 || r.u8()? != 13 {
            return Err(Error::Invalid("recovery ready kind/term"));
        }
        let ready = Self {
            sequence: r.u64()?,
            player: r.u64()?,
            cut: r.array()?,
            applied: r.u64()?,
            tail: r.u64()?,
            clock_delta: i64::from_be_bytes(r.array()?),
            tls: r.array()?,
            signature: r.array()?,
        };
        r.finish()?;
        ready.verify(root, promotion, cut)?;
        Ok(ready)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeCut {
    pub player: u64,
    pub input: u64,
    pub output: u64,
    pub clock_delta: i64,
    pub challenge: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resume {
    pub sequence: u64,
    pub membership: MembershipCertificate,
    pub cuts: Vec<ResumeCut>,
    pub signature: SignatureBytes,
}
impl Resume {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence == 0 || self.cuts.len() > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(&root.context()?, 1, 14, self.sequence);
        put_bytes(&mut bytes, &self.membership.encode(root)?, 2048)?;
        put_u32(&mut bytes, self.cuts.len())?;
        let mut previous = None;
        for cut in &self.cuts {
            if cut.clock_delta.unsigned_abs() > 250 || previous.is_some_and(|p| p >= cut.player) {
                return Err(Error::Invalid("resume cuts"));
            }
            bytes.extend(cut.player.to_be_bytes());
            bytes.extend(cut.input.to_be_bytes());
            bytes.extend(cut.output.to_be_bytes());
            bytes.extend(cut.clock_delta.to_be_bytes());
            bytes.extend(cut.challenge);
            previous = Some(cut.player);
        }
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    pub fn verify(&self, root: &Root, promotion: &Promotion) -> Result<()> {
        promotion.verify(&root.context()?)?;
        self.membership.verify(root)?;
        let receipt = &self.membership.receipt;
        if receipt.term != 1
            || receipt.index <= promotion.final_receipt.index
            || receipt.logical_ms != promotion.final_receipt.logical_ms
            || self.cuts.len() != self.membership.members.len()
        {
            return Err(Error::Conflict);
        }
        for (cut, member) in self.cuts.iter().zip(&self.membership.members) {
            let mark = receipt
                .watermarks
                .iter()
                .find(|m| m.player == cut.player && !m.retired)
                .ok_or(Error::Gap)?;
            if member.player != cut.player
                || mark.input != cut.input
                || mark.output_ack != cut.output
            {
                return Err(Error::Conflict);
            }
        }
        verify(root.standby, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root, promotion: &Promotion) -> Result<Vec<u8>> {
        self.verify(root, promotion)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, promotion: &Promotion, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        if r.u64()? != 1 || r.u8()? != 14 {
            return Err(Error::Invalid("resume kind/term"));
        }
        let sequence = r.u64()?;
        let membership = MembershipCertificate::decode(root, &r.bytes(2048)?)?;
        let count = r.u32()?;
        if count > MAX_PLAYERS {
            return Err(Error::Bounds);
        }
        let mut cuts = Vec::with_capacity(count);
        for _ in 0..count {
            cuts.push(ResumeCut {
                player: r.u64()?,
                input: r.u64()?,
                output: r.u64()?,
                clock_delta: i64::from_be_bytes(r.array()?),
                challenge: r.array()?,
            });
        }
        let resume = Self {
            sequence,
            membership,
            cuts,
            signature: r.array()?,
        };
        r.finish()?;
        resume.verify(root, promotion)?;
        Ok(resume)
    }
}
struct WarmPlayerReady {
    tls: [u8; 32],
    sequence: u64,
    digest: Hash,
}
/// A second barrier after causal recovery has converged. No successor tick is
/// licensed until every sealed survivor proves its final journals and rebase.
/// The original five-second deadline includes this final network exchange.
pub struct RecoveryBarrier {
    root: Root,
    promotion: Promotion,
    sequencer: Sequencer,
    histories: BTreeMap<u64, HandledInputs>,
    membership: MembershipCertificate,
    started: u64,
    security_anchor: u64,
    last_ms: u64,
    pending: BTreeMap<u64, RecoveryCut>,
    ready: BTreeMap<u64, ResumeCut>,
    ready_tls: BTreeMap<u64, WarmPlayerReady>,
}
impl RecoveryBarrier {
    pub fn is_ready(&self) -> bool {
        self.ready.len() == self.membership.members.len()
    }
    pub fn promotion(&self) -> &Promotion {
        &self.promotion
    }
    pub fn new(mut recovery: Recovery, keys: &Keys, now_ms: u64) -> Result<Self> {
        recovery.poll(now_ms)?;
        if now_ms - recovery.started >= 5000 {
            return Err(Error::Closed);
        }
        let root = recovery.descriptor.root.clone();
        let promotion = recovery.promotion.clone();
        let started = recovery.started;
        let security_anchor = recovery.security_anchor;
        let (sequencer, histories) = recovery.finish()?;
        let membership = sequencer.membership_certificate(keys)?;
        Ok(Self {
            root,
            promotion,
            sequencer,
            histories,
            membership,
            started,
            security_anchor,
            last_ms: now_ms,
            pending: BTreeMap::new(),
            ready: BTreeMap::new(),
            ready_tls: BTreeMap::new(),
        })
    }
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if now_ms < self.last_ms {
            return Err(Error::Invalid("backwards final recovery clock"));
        }
        self.last_ms = now_ms;
        if now_ms - self.started >= 5000 {
            return Err(Error::Closed);
        }
        Ok(())
    }
    pub fn issue(
        &mut self,
        player: u64,
        tls: [u8; 32],
        keys: &Keys,
        now_ms: u64,
    ) -> Result<RecoveryCut> {
        self.advance(now_ms)?;
        if keys.public_key().to_bytes() != self.root.standby || self.ready.contains_key(&player) {
            return Err(Error::Unauthorized);
        }
        let member = self
            .membership
            .members
            .iter()
            .find(|m| m.player == player)
            .ok_or(Error::Unauthorized)?;
        if member.key.is_none() || member.key == Some(self.root.standby) {
            return Err(Error::Unauthorized);
        }
        let sequence = self.sequencer.sender.allocate()?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Invalid("recovery cut RNG"))?;
        let mut cut = RecoveryCut {
            sequence,
            player,
            nonce,
            tls,
            membership: self.membership.clone(),
            signature: [0; 64],
        };
        cut.signature = sign(keys, cut.digest(&self.root)?);
        cut.verify(&self.root, &self.promotion)?;
        self.pending.insert(player, cut.clone());
        Ok(cut)
    }
    pub fn accept(&mut self, ready: &RecoveryReady, tls: [u8; 32], now_ms: u64) -> Result<()> {
        self.advance(now_ms)?;
        let cut = self.pending.get(&ready.player).ok_or(Error::Stale)?;
        if tls != cut.tls {
            return Err(Error::Unauthorized);
        }
        let issuer = self
            .membership
            .members
            .iter()
            .find(|member| member.player == ready.player)
            .and_then(|member| member.key)
            .ok_or(Error::Unauthorized)?;
        verify(issuer, ready.digest(&self.root)?, ready.signature)?;
        let mut encoded = ready.body(&self.root)?;
        encoded.extend(ready.signature);
        let incoming =
            self.sequencer
                .sender
                .replay
                .begin(issuer, ready.sequence, &encoded, false)?;
        if ready.cut != cut.digest(&self.root)? {
            return Err(Error::Stale);
        }
        ready.verify(&self.root, &self.promotion, cut)?;
        let confirmed = ResumeCut {
            player: ready.player,
            input: ready.tail,
            output: ready.applied,
            clock_delta: ready.clock_delta,
            challenge: ready.cut,
        };
        if self
            .ready
            .get(&ready.player)
            .is_some_and(|old| old != &confirmed)
        {
            return Err(Error::Conflict);
        }
        let digest = hash(b"fray/migration/received-control/v1\0", &encoded);
        incoming.commit()?;
        self.ready.insert(ready.player, confirmed);
        self.ready_tls.insert(
            ready.player,
            WarmPlayerReady {
                tls,
                sequence: ready.sequence,
                digest,
            },
        );
        Ok(())
    }
    pub fn retain_local(
        &mut self,
        player: u64,
        delivery: &DeliveryJournal,
        intents: &IntentJournal,
        clock_delta: i64,
        now_ms: u64,
    ) -> Result<()> {
        self.advance(now_ms)?;
        let member = self
            .membership
            .members
            .iter()
            .find(|m| m.player == player)
            .ok_or(Error::Unauthorized)?;
        if member.key.is_some_and(|key| key != self.root.standby)
            || delivery.poisoned
            || clock_delta.unsigned_abs() > 250
        {
            return Err(Error::Unauthorized);
        }
        let mark = self
            .membership
            .receipt
            .watermarks
            .iter()
            .find(|m| m.player == player && !m.retired)
            .ok_or(Error::Gap)?;
        if mark.input != intents.tail() || mark.output_ack != delivery.applied() {
            return Err(Error::Gap);
        }
        let confirmed = ResumeCut {
            player,
            input: mark.input,
            output: mark.output_ack,
            clock_delta,
            challenge: [0; 32],
        };
        if self.ready.get(&player).is_some_and(|old| old != &confirmed) {
            return Err(Error::Conflict);
        }
        self.ready.insert(player, confirmed);
        Ok(())
    }
    pub fn finish(
        mut self,
        keys: &Keys,
        now_ms: u64,
    ) -> Result<(SuccessorActor, BTreeMap<u64, HandledInputs>, Resume)> {
        self.advance(now_ms)?;
        if keys.public_key().to_bytes() != self.root.standby
            || self.ready.len() != self.membership.members.len()
        {
            return Err(Error::Gap);
        }
        let mut resume = Resume {
            sequence: self.sequencer.sender.allocate()?,
            membership: self.membership,
            cuts: self.ready.into_values().collect(),
            signature: [0; 64],
        };
        resume.signature = sign(keys, resume.digest(&self.root)?);
        resume.verify(&self.root, &self.promotion)?;
        let successor = SuccessorActor::resumed(
            self.root,
            self.sequencer,
            &resume,
            now_ms - self.security_anchor,
            self.ready_tls,
        )?;
        Ok((successor, self.histories, resume))
    }
}

mod publication_sealed {
    pub trait Sealed {}
}
/// The game transaction seam shared by the replicated original authority and
/// the single unprotected successor. Implementations own their publication gate;
/// callers cannot acknowledge speculative work or extract a mutable sequencer.
pub trait PublicationActor: publication_sealed::Sealed {
    fn root(&self) -> &Root;
    fn primary(&self) -> &Primary;
    fn prepare(
        &mut self,
        image: SessionImage,
        marks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<()>;
    fn adopt<T>(&mut self, game: impl FnOnce(&mut Primary) -> Result<T>) -> Result<T>;
}
impl publication_sealed::Sealed for PrimaryActor {}
impl PublicationActor for PrimaryActor {
    fn root(&self) -> &Root {
        self.root()
    }
    fn primary(&self) -> &Primary {
        self.primary()
    }
    fn prepare(
        &mut self,
        image: SessionImage,
        marks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<()> {
        self.prepare(image, marks, outputs)
    }
    fn adopt<T>(&mut self, game: impl FnOnce(&mut Primary) -> Result<T>) -> Result<T> {
        self.adopt(game)
    }
}

/// One unprotected authority after the final recovery barrier. It retains the
/// exact sequencer, outbox and stream counters which fenced term zero. There is
/// no constructor from a checkpoint or signed Resume supplied by a remote peer,
/// and no route back to standby/recovery or a second automatic takeover.
pub struct SuccessorActor {
    root: Root,
    sequencer: Sequencer,
    primary: Primary,
    failed: Option<Error>,
    warm_players: BTreeMap<u64, WarmPlayerReady>,
}
impl SuccessorActor {
    fn resumed(
        root: Root,
        sequencer: Sequencer,
        resume: &Resume,
        elapsed_ms: u64,
        warm_players: BTreeMap<u64, WarmPlayerReady>,
    ) -> Result<Self> {
        if sequencer.session_root.as_ref() != Some(&root)
            || sequencer.promotion.is_none()
            || sequencer.receipt.term != 1
            || resume.membership.receipt != sequencer.receipt
        {
            return Err(Error::Conflict);
        }
        resume.verify(&root, sequencer.promotion.as_ref().unwrap())?;
        if warm_players.keys().any(|player| {
            !resume
                .cuts
                .iter()
                .any(|cut| cut.player == *player && cut.challenge != [0; 32])
        }) {
            return Err(Error::Unauthorized);
        }
        let primary = Primary {
            sender: sequencer.sender.clone(),
            initial_player_routes: BTreeSet::new(),
            publication_term: 1,
            recovery_elapsed_ms: elapsed_ms,
            outbox: sequencer.outbox.clone(),
            allocated: sequencer.allocated.clone(),
            adopted: sequencer.receipt.index,
            context: root.context()?,
            receipt: sequencer.receipt.clone(),
            committed: sequencer.image.clone(),
            pending: None,
            closed: false,
            membership: sequencer.membership.clone(),
        };
        Ok(Self {
            root,
            sequencer,
            primary,
            failed: None,
            warm_players,
        })
    }
    pub fn root(&self) -> &Root {
        &self.root
    }
    pub fn primary(&self) -> &Primary {
        &self.primary
    }
    /// Continue a prepared recovery link only after this owned barrier accepted
    /// that player's final Ready on the exact same authenticated TLS exporter.
    /// Consume one attachment without resetting the Channel's framing counters
    /// or changing its transcript-bound roles. Move the existing recovery inbox
    /// with its signed-control history; it is consumed only on success.
    /// Public Resume bytes alone grant
    /// no such capability, and a fresh TLS connection must resume separately.
    pub fn attach_warm_player(
        &mut self,
        channel: &Channel,
        retained: &mut Option<PlayerInbox>,
        keys: &Keys,
    ) -> Result<PlayerQueue> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if channel.descriptor.root != self.root
            || channel.side != ChannelSide::Server
            || channel.term != 1
            || channel.binding.server != LinkRole::Standby
            || !matches!(
                channel.binding.client,
                LinkRole::Original | LinkRole::ControlPlayer
            )
        {
            return Err(Error::Unauthorized);
        }
        let player = channel.authenticated_player.ok_or(Error::Unauthorized)?;
        let ready = self.warm_players.get(&player).ok_or(Error::Unauthorized)?;
        if ready.tls != channel.tls {
            return Err(Error::Unauthorized);
        }
        let previous = retained.as_ref().ok_or(Error::Closed)?;
        if previous.closed
            || previous.root != self.root
            || previous.player != player
            || previous.key != channel.remote_key
            || previous.tls != channel.tls
            || previous.term != channel.term
        {
            return Err(Error::Unauthorized);
        }
        let mut inbox = previous.clone();
        inbox.update_membership(self.membership_certificate(keys)?)?;
        if let Err(error) = inbox.remember_control(ready.sequence, ready.digest) {
            self.sequencer.sender.replay.fail();
            self.failed = Some(error.clone());
            return Err(error);
        }
        let queue = PlayerQueue::from_inbox(inbox, &self.primary)?;
        retained.take();
        self.warm_players.remove(&player);
        Ok(queue)
    }
    pub fn receipt(&self) -> &Receipt {
        self.sequencer.receipt()
    }
    pub fn image(&self) -> &[u8] {
        self.sequencer.image()
    }
    pub fn failure(&self) -> Option<&Error> {
        self.failed.as_ref()
    }
    pub fn outbox(&self) -> impl Iterator<Item = &CertifiedOutput> {
        self.sequencer.outbox()
    }
    pub fn membership_certificate(&self, keys: &Keys) -> Result<MembershipCertificate> {
        self.sequencer.membership_certificate(keys)
    }
    pub fn prepare(
        &mut self,
        image: SessionImage,
        marks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<()> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        let previous = SessionImage::decode(&self.root, self.primary.committed_image())?;
        image.validate_successor(&self.root, &previous, &marks, image.logical_ms)?;
        let candidate =
            self.primary
                .proposal(image.encode(&self.root)?, image.logical_ms, marks, outputs)?;
        self.sequencer.stage(candidate.clone())?;
        self.primary.pending = Some(candidate);
        Ok(())
    }
    /// Fresh restore/re-checkpoint validation runs before the atomic local
    /// install, just as on the standby. A repeated fault permanently pauses
    /// this authority. Only a successful install licenses proof-carrying output.
    pub fn commit(
        &mut self,
        keys: &Keys,
        mut restore: impl FnMut(&Candidate, &SessionImage, &SessionImage) -> Result<Vec<u8>>,
    ) -> Result<PrimaryEvent> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if keys.public_key().to_bytes() != self.root.standby {
            return Err(Error::Unauthorized);
        }
        let candidate = self.primary.pending().ok_or(Error::Stale)?.clone();
        let staged = self.sequencer.stage(candidate.clone())?;
        let image = SessionImage::decode(&self.root, &candidate.image)?;
        let previous = SessionImage::decode(&self.root, self.sequencer.image())?;
        let mut valid = false;
        for _ in 0..2 {
            self.sequencer.sender.replay.live()?;
            let restored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                restore(&candidate, &image, &previous)
            }));
            if matches!(restored, Ok(Ok(bytes)) if bytes == candidate.image) {
                valid = true;
                break;
            }
        }
        if !valid {
            let error = Error::Invalid("successor restore equivalence");
            self.failed = Some(error.clone());
            return Err(error);
        }
        let receipt = match self.sequencer.install(staged, keys) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.failed = Some(error.clone());
                return Err(error);
            }
        };
        let outputs = match self.primary.acknowledge(receipt.clone()) {
            Ok(outputs) => outputs,
            Err(error) => {
                self.failed = Some(error.clone());
                return Err(error);
            }
        };
        Ok(PrimaryEvent::Committed { receipt, outputs })
    }
    pub fn adopt<T>(&mut self, game: impl FnOnce(&mut Primary) -> Result<T>) -> Result<T> {
        self.sequencer.sender.replay.live()?;
        if self.failed.is_some() {
            return Err(Error::Closed);
        }
        if self.primary.pending.is_some() || self.primary.receipt.index <= self.primary.adopted {
            return Err(Error::Stale);
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| game(&mut self.primary)))
                .unwrap_or(Err(Error::Invalid("successor adoption panic")));
        if let Err(error) = &result {
            self.failed = Some(error.clone());
        }
        result
    }
}
impl publication_sealed::Sealed for SuccessorActor {}
impl PublicationActor for SuccessorActor {
    fn root(&self) -> &Root {
        self.root()
    }
    fn primary(&self) -> &Primary {
        self.primary()
    }
    fn prepare(
        &mut self,
        image: SessionImage,
        marks: Vec<Watermark>,
        outputs: Vec<Output>,
    ) -> Result<()> {
        self.prepare(image, marks, outputs)
    }
    fn adopt<T>(&mut self, game: impl FnOnce(&mut Primary) -> Result<T>) -> Result<T> {
        self.adopt(game)
    }
}

/// Original game bytes are journaled under Intent.number before this signed,
/// connection-bound envelope is formed. Reconnect re-signs the same original
/// number/bytes on the new TLS connection; it never allocates another intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlayerAction {
    Intent {
        number: u64,
        bytes: Vec<u8>,
    },
    Lossy {
        number: u64,
        bytes: Vec<u8>,
    },
    /// cut echoes a fresh recovery input-round request. None is an ordinary
    /// delivery update, which cannot seal or advance a recovery input round.
    Applied {
        output: u64,
        tail: u64,
        cut: Option<Hash>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerControl {
    pub term: u64,
    pub sequence: u64,
    pub player: u64,
    pub tls: [u8; 32],
    pub action: PlayerAction,
    pub signature: SignatureBytes,
}
impl PlayerControl {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.term > 1 || self.sequence == 0 {
            return Err(Error::Invalid("player control term/sequence"));
        }
        let mut bytes = control_prefix(&root.context()?, self.term, 15, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.tls);
        match &self.action {
            PlayerAction::Intent {
                number,
                bytes: payload,
            }
            | PlayerAction::Lossy {
                number,
                bytes: payload,
            } => {
                if *number == 0 {
                    return Err(Error::Invalid("player input number"));
                }
                bytes.push(u8::from(matches!(self.action, PlayerAction::Lossy { .. })));
                bytes.extend(number.to_be_bytes());
                put_bytes(&mut bytes, payload, crate::MAX_RELIABLE_LEN)?;
            }
            PlayerAction::Applied { output, tail, cut } => {
                bytes.push(2);
                bytes.extend(output.to_be_bytes());
                bytes.extend(tail.to_be_bytes());
                bytes.push(u8::from(cut.is_some()));
                if let Some(cut) = cut {
                    bytes.extend(cut);
                }
            }
        }
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    pub fn sign(
        root: &Root,
        membership: &MembershipCertificate,
        term: u64,
        sequence: u64,
        player: u64,
        tls: [u8; 32],
        action: PlayerAction,
        keys: &Keys,
    ) -> Result<Self> {
        membership.verify(root)?;
        if membership.receipt.term > term
            || resume_member(root, Some(membership), player)?.key
                != Some(keys.public_key().to_bytes())
        {
            return Err(Error::Unauthorized);
        }
        let mut record = Self {
            term,
            sequence,
            player,
            tls,
            action,
            signature: [0; 64],
        };
        record.signature = sign(keys, record.digest(root)?);
        Ok(record)
    }
    pub fn verify(
        &self,
        root: &Root,
        membership: &MembershipCertificate,
        player: u64,
        tls: [u8; 32],
        term: u64,
    ) -> Result<()> {
        membership.verify(root)?;
        self.verify_member_signature(root, membership, player, tls, term)
    }
    /// Binding, membership and signature checks against a certificate the
    /// caller has ALREADY fully verified (`MembershipCertificate::verify`).
    /// Never call it with an unverified certificate: it does not re-check the
    /// certificate's own standby signature or its receipt binding.
    fn verify_member_signature(
        &self,
        root: &Root,
        membership: &MembershipCertificate,
        player: u64,
        tls: [u8; 32],
        term: u64,
    ) -> Result<()> {
        if self.term != term
            || self.tls != tls
            || self.player != player
            || membership.receipt.term > term
        {
            return Err(Error::Unauthorized);
        }
        let key = membership
            .members
            .iter()
            .find(|m| m.player == player)
            .ok_or(Error::Unauthorized)?
            .key
            .ok_or(Error::Unauthorized)?;
        verify(key, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        root.context()?.read_binding(&mut r)?;
        let term = r.u64()?;
        if r.u8()? != 15 {
            return Err(Error::Invalid("player control kind"));
        }
        let sequence = r.u64()?;
        let player = r.u64()?;
        let tls = r.array()?;
        let action = match r.u8()? {
            kind @ (0 | 1) => {
                let number = r.u64()?;
                let bytes = r.bytes(crate::MAX_RELIABLE_LEN)?;
                if kind == 0 {
                    PlayerAction::Intent { number, bytes }
                } else {
                    PlayerAction::Lossy { number, bytes }
                }
            }
            2 => {
                let output = r.u64()?;
                let tail = r.u64()?;
                let cut = match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(Error::Invalid("input cut option")),
                };
                PlayerAction::Applied { output, tail, cut }
            }
            _ => return Err(Error::Invalid("player action kind")),
        };
        let record = Self {
            term,
            sequence,
            player,
            tls,
            action,
            signature: r.array()?,
        };
        r.finish()?;
        record.body(root)?;
        Ok(record)
    }
}

/// A player control whose signature was verified once by a `PlayerInbox`,
/// bound to that route (player, TLS exporter, term) and to the digest of the
/// trusted membership certificate it was checked against. Only `authenticate`
/// constructs it; `admit` refuses it on any other route or certificate.
struct VerifiedControl {
    record: PlayerControl,
    digest: Hash,
    membership: Hash,
    player: u64,
    tls: [u8; 32],
    term: u64,
}

/// Authenticated per-connection control replay guard. It emits ordered runner
/// events, never mutates the authority or committed ACK/input watermarks. The
/// owning runner admits only actions valid in its current normal/recovery phase.
#[derive(Clone)]
pub struct PlayerInbox {
    root: Root,
    membership: MembershipCertificate,
    /// Digest of the certificate in `membership` as of its last full
    /// `MembershipCertificate::verify`. Per-control checks trust the
    /// certificate only while its digest still equals this value.
    trusted: Hash,
    player: u64,
    key: RuntimeKey,
    tls: [u8; 32],
    term: u64,
    last: u64,
    recent: VecDeque<(u64, Hash)>,
    lossy_number: u64,
    closed: bool,
}
impl PlayerInbox {
    /// Channel metadata comes from the v7 handshake, not a payload's player ID.
    pub fn new(channel: &Channel, membership: MembershipCertificate) -> Result<Self> {
        let root = channel.descriptor.root.clone();
        membership.verify(&root)?;
        if channel.side != ChannelSide::Server || membership.receipt.term > channel.term {
            return Err(Error::Unauthorized);
        }
        let allowed = matches!(
            (channel.term, channel.binding.client, channel.binding.server),
            (0, LinkRole::Player, LinkRole::Original)
                | (
                    1,
                    LinkRole::Player | LinkRole::ResumePlayer,
                    LinkRole::Successor
                )
                | (
                    1,
                    LinkRole::ControlPlayer | LinkRole::Original,
                    LinkRole::Standby
                )
        );
        if !allowed {
            return Err(Error::Unauthorized);
        }
        if let Some(authenticated) = &channel.authenticated_membership {
            membership.follows(&root, authenticated)?;
        }
        let player = channel.authenticated_player.ok_or(Error::Unauthorized)?;
        if !membership
            .members
            .iter()
            .any(|m| m.player == player && m.key == Some(channel.remote_key))
        {
            return Err(Error::Unauthorized);
        }
        let trusted = membership.digest(&root)?;
        Ok(Self {
            root,
            membership,
            trusted,
            player,
            key: channel.remote_key,
            tls: channel.tls,
            term: channel.term,
            last: 0,
            recent: VecDeque::new(),
            lossy_number: 0,
            closed: false,
        })
    }
    pub fn player(&self) -> u64 {
        self.player
    }
    /// A committed retirement closes this logical route before another input
    /// can be returned, including already queued bytes on the old connection.
    pub fn update_membership(&mut self, next: MembershipCertificate) -> Result<()> {
        if self.closed {
            return Err(Error::Closed);
        }
        // follows() fully verifies both certificates, so `next` is trusted.
        next.follows(&self.root, &self.membership)?;
        if next.receipt.term > self.term {
            return Err(Error::Unauthorized);
        }
        if !next
            .members
            .iter()
            .any(|m| m.player == self.player && m.key == Some(self.key))
        {
            self.closed = true;
            return Err(Error::Closed);
        }
        self.trusted = next.digest(&self.root)?;
        self.membership = next;
        Ok(())
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Option<PlayerControl>> {
        if self.closed {
            return Err(Error::Closed);
        }
        let verified = self.authenticate(bytes)?;
        self.admit(verified)
    }
    /// Trust the installed certificate by identity. A certificate fully
    /// verified at `new`/`update_membership` is not re-verified per control;
    /// any other certificate is verified fully once before being trusted.
    fn trust_membership(&mut self) -> Result<Hash> {
        let digest = self.membership.digest(&self.root)?;
        if digest != self.trusted {
            self.membership.verify(&self.root)?;
            if !self
                .membership
                .members
                .iter()
                .any(|m| m.player == self.player && m.key == Some(self.key))
            {
                return Err(Error::Unauthorized);
            }
            self.trusted = digest;
        }
        Ok(digest)
    }
    /// Decode and authenticate one control exactly once: the trusted
    /// certificate, this route's player/TLS/term binding, signer membership
    /// and the signature. Replay state is not touched; see `admit`.
    fn authenticate(&mut self, bytes: &[u8]) -> Result<VerifiedControl> {
        let record = PlayerControl::decode(&self.root, bytes)?;
        let membership = self.trust_membership()?;
        record.verify_member_signature(
            &self.root,
            &self.membership,
            self.player,
            self.tls,
            self.term,
        )?;
        Ok(VerifiedControl {
            digest: hash(b"fray/migration/received-control/v1\0", bytes),
            record,
            membership,
            player: self.player,
            tls: self.tls,
            term: self.term,
        })
    }
    /// Sequence/replay admission of a control authenticated for this exact
    /// route and trusted certificate.
    fn admit(&mut self, verified: VerifiedControl) -> Result<Option<PlayerControl>> {
        if self.closed {
            return Err(Error::Closed);
        }
        if verified.membership != self.trusted
            || verified.player != self.player
            || verified.tls != self.tls
            || verified.term != self.term
        {
            return Err(Error::Unauthorized);
        }
        let VerifiedControl { record, digest, .. } = verified;
        if !self.remember_control(record.sequence, digest)? {
            return Ok(None);
        }
        if let PlayerAction::Lossy { number, .. } = record.action {
            self.lossy_number = self.lossy_number.max(number);
        }
        Ok(Some(record))
    }
    fn remember_control(&mut self, sequence: u64, digest: Hash) -> Result<bool> {
        if self.closed {
            return Err(Error::Closed);
        }
        if let Some((_, old)) = self.recent.iter().find(|(n, _)| *n == sequence) {
            if *old != digest {
                self.closed = true;
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
        // Allocation is global across links. An unseen lower ID may arrive
        // after a higher one and still carry a required original intent.
        if self.recent.len() >= MAX_JOURNAL_RECORDS
            && self
                .recent
                .front()
                .is_some_and(|(first, _)| sequence < *first)
        {
            return Err(Error::Stale);
        }
        self.last = self.last.max(sequence);
        self.recent.push_back((sequence, digest));
        self.recent
            .make_contiguous()
            .sort_unstable_by_key(|(n, _)| *n);
        if self.recent.len() > MAX_JOURNAL_RECORDS {
            self.recent.pop_front();
        }
        Ok(true)
    }
}

/// Fresh normal-play reconnect cut, signed by the original authority in term0
/// or the successor in term1. Only public committed membership is disclosed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectChallenge {
    pub sequence: u64,
    pub player: u64,
    pub nonce: Hash,
    pub tls: [u8; 32],
    pub membership: MembershipCertificate,
    pub signature: SignatureBytes,
}
impl ReconnectChallenge {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Bounds);
        }
        let mut bytes = control_prefix(
            &root.context()?,
            self.membership.receipt.term,
            17,
            self.sequence,
        );
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.nonce);
        bytes.extend(self.tls);
        put_bytes(&mut bytes, &self.membership.encode(root)?, 2048)?;
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    pub fn verify(&self, root: &Root) -> Result<()> {
        self.membership.verify(root)?;
        if !self
            .membership
            .members
            .iter()
            .any(|m| m.player == self.player && m.key.is_some())
        {
            return Err(Error::Unauthorized);
        }
        let signer = if self.membership.receipt.term == 0 {
            root.host
        } else {
            root.standby
        };
        verify(signer, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root) -> Result<Vec<u8>> {
        self.verify(root)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut reader = Reader(bytes);
        root.context()?.read_binding(&mut reader)?;
        let term = reader.u64()?;
        if term > 1 || reader.u8()? != 17 {
            return Err(Error::Invalid("reconnect challenge kind/term"));
        }
        let request = Self {
            sequence: reader.u64()?,
            player: reader.u64()?,
            nonce: reader.array()?,
            tls: reader.array()?,
            membership: MembershipCertificate::decode(root, &reader.bytes(2048)?)?,
            signature: reader.array()?,
        };
        reader.finish()?;
        if request.membership.receipt.term != term {
            return Err(Error::Conflict);
        }
        request.verify(root)?;
        Ok(request)
    }
}
impl PlayerControl {
    /// Prove the actual journals retained by the complete live client. Signing
    /// this cut never prunes either journal or substitutes a fresh game client.
    pub fn resume_connection(
        root: &Root,
        request: &ReconnectChallenge,
        tls: [u8; 32],
        delivery: &DeliveryJournal,
        intents: &IntentJournal,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        request.verify(root)?;
        let mark = request
            .membership
            .receipt
            .watermarks
            .iter()
            .find(|m| m.player == request.player && !m.retired)
            .ok_or(Error::Unauthorized)?;
        if request.tls != tls
            || delivery.poisoned
            || delivery.applied() < mark.output_ack
            || intents.acknowledged() > mark.input
            || intents.tail() < mark.input
            || intents.tail() - mark.input > MAX_JOURNAL_RECORDS as u64
        {
            return Err(Error::Invalid("lost reconnect journal"));
        }
        Self::sign(
            root,
            &request.membership,
            request.membership.receipt.term,
            sequence,
            request.player,
            tls,
            PlayerAction::Applied {
                output: delivery.applied(),
                tail: intents.tail(),
                cut: Some(request.nonce),
            },
            keys,
        )
    }
}
struct PendingReconnect {
    inbox: PlayerInbox,
    request: ReconnectChallenge,
    expires: u64,
}
#[derive(Default)]
struct PeerReplay {
    committed: BTreeMap<u64, Hash>,
    pending: BTreeMap<u64, Hash>,
}
#[derive(Default)]
struct ReplayState {
    failed: bool,
    peers: BTreeMap<RuntimeKey, PeerReplay>,
    allowed: Option<BTreeSet<RuntimeKey>>,
    retired: BTreeMap<RuntimeKey, u64>,
    membership: Option<(u64, Hash)>,
}
/// One receiving process's conflict history for a pinned root. Clones share
/// all issuers and links. Arrival order is independent of allocation order.
#[derive(Clone)]
pub struct ReplaySession {
    context: Context,
    state: std::sync::Arc<std::sync::Mutex<ReplayState>>,
}
impl ReplaySession {
    /// An obsolete activation record may already be buffered when roles move
    /// into normal actors. Only a remembered exact record or authenticated old
    /// record below the bounded archive floor is a no-op. Never admit a new
    /// activation ID, extend liveness or rerun native work at this boundary.
    fn archived_duplicate(&self, issuer: RuntimeKey, sequence: u64, bytes: &[u8]) -> Result<()> {
        let ticket = self.begin(issuer, sequence, bytes, true)?;
        if ticket.is_new() {
            return Err(Error::Unauthorized);
        }
        ticket.commit()
    }
    fn new(context: Context) -> Self {
        Self {
            context,
            state: Default::default(),
        }
    }
    fn live(&self) -> Result<()> {
        if self.state.lock().map_err(|_| Error::Closed)?.failed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn fail(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.failed = true;
        }
    }
    /// Only call after authenticating the complete record and its issuer.
    /// Archived proofs may outlive the bounded live-control window. Their own
    /// signature and the containing record still need normal validation.
    fn begin(
        &self,
        issuer: RuntimeKey,
        sequence: u64,
        bytes: &[u8],
        archived: bool,
    ) -> Result<ReplayTicket> {
        if sequence == 0 || bytes.len() > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        let digest = hash(b"fray/migration/received-control/v1\0", bytes);
        let mut state = self.state.lock().map_err(|_| Error::Closed)?;
        if state.failed {
            return Err(Error::Closed);
        }
        if !archived {
            if state
                .allowed
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&issuer))
            {
                return Err(Error::Unauthorized);
            }
            let remembered = state.peers.get(&issuer).is_some_and(|peer| {
                peer.committed.contains_key(&sequence) || peer.pending.contains_key(&sequence)
            });
            if !remembered
                && state
                    .retired
                    .get(&issuer)
                    .is_some_and(|floor| sequence <= *floor)
            {
                return Err(Error::Stale);
            }
        }
        // Retired issuers with outstanding tickets are temporarily retained.
        // Empty rolled-back slots never count against the active roster.
        if state.peers.len() >= 2 * (MAX_PLAYERS + 2) && !state.peers.contains_key(&issuer) {
            return Err(Error::Bounds);
        }
        let peer = state.peers.entry(issuer).or_default();
        if let Some(old) = peer
            .committed
            .get(&sequence)
            .or_else(|| peer.pending.get(&sequence))
        {
            if *old != digest {
                state.failed = true;
                return Err(Error::Conflict);
            }
            if peer.pending.contains_key(&sequence) && !archived {
                return Err(Error::Stale);
            }
            return Ok(ReplayTicket {
                session: self.clone(),
                issuer,
                sequence,
                digest,
                reserved: false,
            });
        }
        if peer.committed.len() >= MAX_JOURNAL_RECORDS
            && peer
                .committed
                .first_key_value()
                .is_some_and(|(first, _)| sequence < *first)
        {
            if !archived {
                return Err(Error::Stale);
            }
            return Ok(ReplayTicket {
                session: self.clone(),
                issuer,
                sequence,
                digest,
                reserved: false,
            });
        }
        // Pending records have their own small bound so a failed transaction
        // never has to evict a committed conflict record and restore it later.
        if peer.pending.len() >= 8 {
            return Err(Error::Bounds);
        }
        peer.pending.insert(sequence, digest);
        Ok(ReplayTicket {
            session: self.clone(),
            issuer,
            sequence,
            digest,
            reserved: true,
        })
    }
    fn receipt(&self, receipt: &Receipt) -> Result<()> {
        receipt.verify(&self.context)?;
        self.begin(
            self.context.standby,
            receipt.sequence,
            &receipt.encode(&self.context)?,
            true,
        )?
        .commit()
    }
    fn certificate(&self, root: &Root, certificate: &MembershipCertificate) -> Result<()> {
        if self.context != root.context()? {
            return Err(Error::Unauthorized);
        }
        certificate.verify(root)?;
        self.receipt(&certificate.receipt)?;
        self.begin(
            root.standby,
            certificate.sequence,
            &certificate.encode(root)?,
            true,
        )?
        .commit()?;
        self.advance_membership(root, certificate)
    }
    fn advance_membership(&self, root: &Root, certificate: &MembershipCertificate) -> Result<()> {
        if self.context != root.context()? {
            return Err(Error::Unauthorized);
        }
        certificate.verify(root)?;
        let frontier = (
            certificate.receipt.index,
            certificate.receipt.digest(&self.context)?,
        );
        let mut state = self.state.lock().map_err(|_| Error::Closed)?;
        if state.failed {
            return Err(Error::Closed);
        }
        if let Some(current) = state.membership {
            if frontier.0 < current.0 {
                return Ok(());
            }
            if frontier.0 == current.0 {
                if frontier.1 == current.1 {
                    return Ok(());
                }
                state.failed = true;
                return Err(Error::Conflict);
            }
        }
        let mut allowed: BTreeSet<_> = certificate
            .members
            .iter()
            .filter_map(|member| member.key)
            .collect();
        allowed.extend([root.host, root.standby]);
        let mut retired = state.retired.clone();
        for (key, peer) in &state.peers {
            if !allowed.contains(key) {
                let maximum = peer
                    .committed
                    .keys()
                    .chain(peer.pending.keys())
                    .copied()
                    .max()
                    .unwrap_or(0);
                if maximum != 0 {
                    retired
                        .entry(*key)
                        .and_modify(|floor| *floor = (*floor).max(maximum))
                        .or_insert(maximum);
                }
            }
        }
        // A bounded tombstone preserves the key/root namespace on readmission.
        // Check the byte budget before changing roster or conflict history.
        if retired
            .len()
            .checked_mul(32 + 8)
            .is_none_or(|bytes| bytes > MAX_IMAGE)
        {
            return Err(Error::Bounds);
        }
        state.retired = retired;
        state.allowed = Some(allowed.clone());
        state
            .peers
            .retain(|key, peer| allowed.contains(key) || !peer.pending.is_empty());
        state.membership = Some(frontier);
        Ok(())
    }
}
struct ReplayTicket {
    session: ReplaySession,
    issuer: RuntimeKey,
    sequence: u64,
    digest: Hash,
    reserved: bool,
}
impl ReplayTicket {
    fn is_new(&self) -> bool {
        self.reserved
    }
    fn commit(mut self) -> Result<()> {
        if !self.reserved {
            return self.session.live();
        }
        let mut state = self.session.state.lock().map_err(|_| Error::Closed)?;
        if state.failed {
            return Err(Error::Closed);
        }
        let peer = state.peers.get_mut(&self.issuer).ok_or(Error::Stale)?;
        if peer.pending.remove(&self.sequence) != Some(self.digest) {
            return Err(Error::Conflict);
        }
        peer.committed.insert(self.sequence, self.digest);
        if peer.committed.len() > MAX_JOURNAL_RECORDS {
            peer.committed.pop_first();
        }
        if state
            .allowed
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&self.issuer))
            && state
                .peers
                .get(&self.issuer)
                .is_some_and(|peer| peer.pending.is_empty())
        {
            state.peers.remove(&self.issuer);
        }
        self.reserved = false;
        Ok(())
    }
}
impl Drop for ReplayTicket {
    fn drop(&mut self) {
        if self.reserved {
            if let Ok(mut state) = self.session.state.lock() {
                if let Some(peer) = state.peers.get_mut(&self.issuer) {
                    if peer.pending.get(&self.sequence) == Some(&self.digest) {
                        peer.pending.remove(&self.sequence);
                    }
                    let empty = peer.pending.is_empty() && peer.committed.is_empty();
                    let retired = state
                        .allowed
                        .as_ref()
                        .is_some_and(|allowed| !allowed.contains(&self.issuer));
                    if empty
                        || retired
                            && state
                                .peers
                                .get(&self.issuer)
                                .is_some_and(|peer| peer.pending.is_empty())
                    {
                        state.peers.remove(&self.issuer);
                    }
                }
            }
        }
    }
}
/// One runtime's client control counter, shared by its normal and prepared warm
/// paths. Cloning shares the allocation; it never restarts a sender namespace.
#[derive(Clone)]
pub struct SenderSequence {
    context: Context,
    key: RuntimeKey,
    next: std::sync::Arc<std::sync::atomic::AtomicU64>,
    replay: ReplaySession,
}
/// Compatibility name for the same shared per-runtime allocator.
pub type PlayerSequence = SenderSequence;
impl SenderSequence {
    /// Inspect the shared fault latch without allocating an ID or changing
    /// replay history. Native consumers check this before fresh callbacks.
    pub fn check_live(&self) -> Result<()> {
        self.replay.live()
    }
    fn starting(context: Context, key: RuntimeKey, next: u64) -> Result<Self> {
        context.validate()?;
        if next == 0 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            replay: ReplaySession::new(context.clone()),
            context,
            key,
            next: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(next)),
        })
    }
    fn matches(&self, context: &Context, key: RuntimeKey) -> Result<()> {
        if self.context != *context || self.key != key {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    fn reserve(&self, count: u64) -> Result<u64> {
        self.replay.live()?;
        if count == 0 {
            return Err(Error::Bounds);
        }
        use std::sync::atomic::Ordering;
        self.next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(count)
            })
            .map_err(|_| Error::Bounds)
    }
    fn advance_past(&self, used: u64) -> Result<()> {
        use std::sync::atomic::Ordering;
        let floor = used.checked_add(1).ok_or(Error::Bounds)?;
        self.next.fetch_max(floor, Ordering::AcqRel);
        Ok(())
    }
    pub fn from_capability(root: &Root, ack: &CapabilityAck, keys: &Keys) -> Result<Self> {
        ack.verify(root)?;
        if root.member(ack.player)?.key != Some(keys.public_key().to_bytes()) {
            return Err(Error::Unauthorized);
        }
        let next = ack.sequence.checked_add(1).ok_or(Error::Bounds)?;
        Ok(Self {
            replay: ReplaySession::new(root.context()?),
            context: root.context()?,
            key: keys.public_key().to_bytes(),
            next: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(next)),
        })
    }
    pub fn allocate(&self) -> Result<u64> {
        self.replay.live()?;
        self.reserve(1)
    }
    pub fn replay_session(&self) -> ReplaySession {
        self.replay.clone()
    }
}

#[cfg(test)]
mod sender_scope_tests {
    use super::*;
    #[test]
    fn public_live_check_shares_fault_without_allocating_sender_ids() {
        let (context, key) = fixture();
        let sender = SenderSequence::starting(context, key.public_key().to_bytes(), 1).unwrap();
        assert_eq!(sender.check_live(), Ok(()));
        assert_eq!(sender.allocate(), Ok(1));
        assert_eq!(sender.check_live(), Ok(()));
        assert_eq!(sender.allocate(), Ok(2));
        let sibling = sender.clone();
        sibling.replay.fail();
        assert_eq!(sender.check_live(), Err(Error::Closed));
        assert_eq!(sender.allocate(), Err(Error::Closed));
        assert_eq!(sender.next.load(std::sync::atomic::Ordering::Acquire), 3);
    }
    fn fixture() -> (Context, Keys) {
        let original = Keys::generate();
        let standby = Keys::generate();
        (
            Context {
                session: [21; 16],
                descriptor: [31; 32],
                host: original.public_key().to_bytes(),
                standby: standby.public_key().to_bytes(),
            },
            standby,
        )
    }
    fn room() -> (Root, SessionImage, Sequencer, Keys) {
        let (context, standby) = fixture();
        let player = Keys::generate();
        let root = Root {
            session: context.session,
            app: "sender-scope-test".into(),
            transport_version: 7,
            game_version: 13,
            checkpoint_version: 1,
            host: context.host,
            standby: context.standby,
            controller: context.host,
            code: room_code_hash("ABCDEF").unwrap(),
            created_day: 20741,
            roster_revision: 1,
            members: vec![
                Member {
                    player: 1,
                    seat: 0,
                    key: Some(context.host),
                },
                Member {
                    player: 2,
                    seat: 1,
                    key: Some(player.public_key().to_bytes()),
                },
            ],
            config: [11; 32],
            content: [12; 32],
            limits: ResourceLimits::default(),
        };
        let image = SessionImage::initial(&root, &[(1, 10), (2, 11)], vec![0], 1, 0).unwrap();
        let sequencer = Sequencer::arm_session(root.clone(), image.clone(), &standby).unwrap();
        (root, image, sequencer, standby)
    }
    fn replacement(
        root: &Root,
        previous: &SessionImage,
        key: RuntimeKey,
    ) -> (SessionImage, Vec<Watermark>) {
        let mut next = previous.clone();
        let old = next.members.remove(1);
        next.inputs.remove(&old.player);
        let player = next.next_player;
        next.next_player += 1;
        next.members.push(SessionMember {
            player,
            seat: 1,
            key: Some(key),
            logical_peer: 10 + player as u32,
        });
        next.inputs.insert(player, HandledInputs::default());
        next.membership_revision += 1;
        next.logical_ms += 16;
        let marks = vec![
            Watermark {
                player: 1,
                input: 0,
                output_ack: 0,
                retired: false,
            },
            Watermark {
                player: old.player,
                input: 0,
                output_ack: 0,
                retired: true,
            },
            Watermark {
                player,
                input: 0,
                output_ack: 0,
                retired: false,
            },
        ];
        next.validate(root).unwrap();
        (next, marks)
    }
    #[test]
    fn membership_churn_prunes_retired_peers_preserves_pending_tickets_and_key_floors() {
        let (root, mut image, mut sequencer, key) = room();
        let scope = sequencer.sender.replay.clone();
        let initial = sequencer.membership_certificate(&key).unwrap();
        let original_player = image.members[1].key.unwrap();
        for round in 0..16 {
            let old = image.members[1].key.unwrap();
            scope
                .begin(old, 5, b"accepted", false)
                .unwrap()
                .commit()
                .unwrap();
            let held = scope.begin(old, 6, b"in-flight", false).unwrap();
            let fresh = Keys::generate().public_key().to_bytes();
            let (next, marks) = replacement(&root, &image, fresh);
            let candidate = sequencer
                .next(next.encode(&root).unwrap(), next.logical_ms, marks, vec![])
                .unwrap();
            let staged = sequencer.stage(candidate).unwrap();
            sequencer.install(staged, &key).unwrap();
            assert!(scope.state.lock().unwrap().peers.contains_key(&old));
            if round % 2 == 0 {
                held.commit().unwrap();
            } else {
                drop(held);
            }
            assert!(!scope.state.lock().unwrap().peers.contains_key(&old));
            image = next;
        }
        // An archived certificate must never restore an old membership frontier.
        let current = scope.state.lock().unwrap().membership;
        scope.certificate(&root, &initial).unwrap();
        assert_eq!(scope.state.lock().unwrap().membership, current);
        assert!(scope
            .state
            .lock()
            .unwrap()
            .allowed
            .as_ref()
            .unwrap()
            .contains(&image.members[1].key.unwrap()));
        let (next, marks) = replacement(&root, &image, original_player);
        let candidate = sequencer
            .next(next.encode(&root).unwrap(), next.logical_ms, marks, vec![])
            .unwrap();
        let staged = sequencer.stage(candidate).unwrap();
        sequencer.install(staged, &key).unwrap();
        assert!(matches!(
            scope.begin(original_player, 6, b"new identity", false),
            Err(Error::Stale)
        ));
        scope
            .begin(original_player, 7, b"continuing namespace", false)
            .unwrap()
            .commit()
            .unwrap();
        assert!(scope.state.lock().unwrap().peers.len() <= MAX_PLAYERS + 2);
    }
    #[test]
    fn readmission_cannot_hide_a_remembered_conflict_under_the_retired_floor() {
        let (root, image, mut sequencer, key) = room();
        let scope = sequencer.sender.replay.clone();
        let original = image.members[1].key.unwrap();
        let held = scope.begin(original, 6, b"in-flight", false).unwrap();
        let fresh = Keys::generate().public_key().to_bytes();
        let (away, marks) = replacement(&root, &image, fresh);
        let candidate = sequencer
            .next(away.encode(&root).unwrap(), away.logical_ms, marks, vec![])
            .unwrap();
        let staged = sequencer.stage(candidate).unwrap();
        sequencer.install(staged, &key).unwrap();
        let (back, marks) = replacement(&root, &away, original);
        let candidate = sequencer
            .next(back.encode(&root).unwrap(), back.logical_ms, marks, vec![])
            .unwrap();
        let staged = sequencer.stage(candidate).unwrap();
        sequencer.install(staged, &key).unwrap();
        assert!(matches!(
            scope.begin(original, 5, b"unknown old ID", false),
            Err(Error::Stale)
        ));
        assert!(matches!(
            scope.begin(original, 6, b"in-flight", false),
            Err(Error::Stale)
        ));
        assert!(matches!(
            scope.begin(original, 6, b"changed", false),
            Err(Error::Conflict)
        ));
        assert_eq!(held.commit(), Err(Error::Closed));
        assert_eq!(scope.live(), Err(Error::Closed));
    }
    #[test]
    fn empty_replay_rollbacks_do_not_consume_lifetime_issuer_slots() {
        let (context, _) = fixture();
        let scope = ReplaySession::new(context);
        for _ in 0..32 {
            let key = Keys::generate().public_key().to_bytes();
            drop(scope.begin(key, 1, b"capacity refusal", false).unwrap());
            assert!(scope.state.lock().unwrap().peers.is_empty());
        }
    }
    #[test]
    fn tombstone_budget_failure_precedes_authority_membership_and_image_mutation() {
        let (root, image, mut sequencer, key) = room();
        let scope = sequencer.sender.replay.clone();
        scope
            .begin(image.members[1].key.unwrap(), 5, b"accepted", false)
            .unwrap()
            .commit()
            .unwrap();
        {
            let mut state = scope.state.lock().unwrap();
            for n in 0..MAX_IMAGE / 40 {
                let mut key = [0; 32];
                key[..8].copy_from_slice(&(n as u64).to_be_bytes());
                state.retired.insert(key, 1);
            }
        }
        let before = sequencer.receipt().clone();
        let before_frontier = scope.state.lock().unwrap().membership;
        let (next, marks) = replacement(&root, &image, Keys::generate().public_key().to_bytes());
        let candidate = sequencer
            .next(next.encode(&root).unwrap(), next.logical_ms, marks, vec![])
            .unwrap();
        let staged = sequencer.stage(candidate).unwrap();
        assert_eq!(sequencer.install(staged, &key), Err(Error::Bounds));
        assert_eq!(sequencer.receipt(), &before);
        assert_eq!(sequencer.image(), image.encode(&root).unwrap());
        assert_eq!(scope.state.lock().unwrap().membership, before_frontier);
    }
    #[test]
    fn shared_replay_accepts_reversed_links_and_faults_cross_family_ids() {
        let (context, _) = fixture();
        let normal = ReplaySession::new(context.clone());
        let warm = normal.clone();
        warm.begin(context.host, 11, b"probe-kind10", false)
            .unwrap()
            .commit()
            .unwrap();
        normal
            .begin(context.host, 7, b"intent-kind15", false)
            .unwrap()
            .commit()
            .unwrap();
        // Separate runtime keys may use the same number.
        normal
            .begin(context.standby, 7, b"receipt-kind4", false)
            .unwrap()
            .commit()
            .unwrap();
        normal
            .begin(context.host, 7, b"intent-kind15", false)
            .unwrap()
            .commit()
            .unwrap();
        assert!(matches!(
            warm.begin(context.host, 7, b"ready-kind13", false),
            Err(Error::Conflict)
        ));
        assert_eq!(normal.live(), Err(Error::Closed));
        assert!(matches!(
            normal.begin(context.standby, 12, b"new", false),
            Err(Error::Closed)
        ));
    }
    #[test]
    fn replay_tickets_rollback_capacity_errors_and_do_not_evict_pending_work() {
        let (context, _) = fixture();
        let session = ReplaySession::new(context.clone());
        {
            let _refused = session
                .begin(context.host, 1, b"retained-original", false)
                .unwrap();
            // A second live handler cannot run the same in-flight action.
            assert!(matches!(
                session.begin(context.host, 1, b"retained-original", false),
                Err(Error::Stale)
            ));
        }
        session
            .begin(context.host, 1, b"retained-original", false)
            .unwrap()
            .commit()
            .unwrap();
        let mut held = Vec::new();
        for sequence in 2..=9 {
            held.push(
                session
                    .begin(context.host, sequence, b"pending", false)
                    .unwrap(),
            );
        }
        assert!(matches!(
            session.begin(context.host, 10, b"later", false),
            Err(Error::Bounds)
        ));
        held.pop();
        session
            .begin(context.host, 10, b"later", false)
            .unwrap()
            .commit()
            .unwrap();
        drop(held);
        // A discarded ticket did not consume the ID.
        session
            .begin(context.host, 2, b"pending", false)
            .unwrap()
            .commit()
            .unwrap();
        assert!(matches!(
            session.begin(context.host, 1, b"changed", false),
            Err(Error::Conflict)
        ));
    }
    #[test]
    fn archived_proofs_survive_the_bounded_live_window_without_unbounded_history() {
        let (context, _) = fixture();
        let session = ReplaySession::new(context.clone());
        for sequence in 1..=MAX_JOURNAL_RECORDS as u64 + 10 {
            session
                .begin(context.standby, sequence, &sequence.to_be_bytes(), false)
                .unwrap()
                .commit()
                .unwrap();
        }
        assert!(matches!(
            session.begin(context.standby, 1, b"old", false),
            Err(Error::Stale)
        ));
        session
            .begin(context.standby, 1, &1u64.to_be_bytes(), true)
            .unwrap()
            .commit()
            .unwrap();
        let state = session.state.lock().unwrap();
        assert_eq!(
            state.peers[&context.standby].committed.len(),
            MAX_JOURNAL_RECORDS
        );
        assert!(state.peers[&context.standby].pending.is_empty());
    }
    #[test]
    fn exhausted_authority_counter_cannot_install_or_close_a_frontier() {
        let (context, standby) = fixture();
        let sender =
            SenderSequence::starting(context.clone(), context.standby, u64::MAX - 2).unwrap();
        let mut sequencer =
            Sequencer::arm_with_sender(context, vec![0], 0, vec![], &standby, sender.clone())
                .unwrap();
        let before = sequencer.receipt().clone();
        let candidate = sequencer.next(vec![1], 16, vec![], vec![]).unwrap();
        let staged = sequencer.stage(candidate).unwrap();
        assert_eq!(sequencer.install(staged, &standby), Err(Error::Bounds));
        assert_eq!(sequencer.promote(&standby), Err(Error::Bounds));
        assert_eq!(sequencer.receipt(), &before);
        assert_eq!(sequencer.image(), &[0]);
        assert!(sequencer.promotion.is_none());
        assert_eq!(sender.allocate(), Err(Error::Bounds));
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlayerEvent {
    Output {
        receipt: Receipt,
        delivery: Delivery,
        sequence: u64,
        applied: bool,
    },
    Membership(MembershipCertificate),
}
/// Normal client framing over the actual initial player connection. The game
/// retains its complete ClientSession separately and uses intents_mut only for
/// its atomic native transaction seam. A physical reconnect must retain this
/// object and its journals; reconnect verifies a fresh bound challenge before
/// swapping the physical channel. There is no journal reset path.
pub struct PlayerEndpoint {
    descriptor: Descriptor,
    player: u64,
    keys: Keys,
    membership: MembershipCertificate,
    channel: Channel,
    sequence: PlayerSequence,
    intents: IntentJournal,
    delivery: DeliveryJournal,
    sent_input: u64,
    sent_view: u64,
    received_view: u64,
    failed: Option<Error>,
}
impl PlayerEndpoint {
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn new(
        descriptor: Descriptor,
        armed: &Armed,
        capability: &CapabilityAck,
        membership: MembershipCertificate,
        channel: Channel,
        keys: Keys,
    ) -> Result<Self> {
        let key = keys.public_key().to_bytes();
        if key == descriptor.root.host || key == descriptor.root.standby {
            return Err(Error::Invalid("authority player must share its sender"));
        }
        let sequence = PlayerSequence::from_capability(&descriptor.root, capability, &keys)?;
        Self::new_with_sender(
            descriptor, armed, capability, membership, channel, keys, sequence,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_sender(
        descriptor: Descriptor,
        armed: &Armed,
        capability: &CapabilityAck,
        membership: MembershipCertificate,
        channel: Channel,
        keys: Keys,
        sequence: SenderSequence,
    ) -> Result<Self> {
        descriptor.verify()?;
        let root = &descriptor.root;
        capability.verify(root)?;
        sequence.matches(&root.context()?, keys.public_key().to_bytes())?;
        sequence.advance_past(capability.sequence)?;
        armed.verify_initial(root, capability.initial, armed.receipt.logical_ms)?;
        membership.verify(root)?;
        if membership.receipt.digest(&root.context()?)? != armed.receipt.digest(&root.context()?)?
            || channel.descriptor != descriptor
            || channel.side != ChannelSide::Client
            || channel.term != 0
            || channel.binding.client != LinkRole::Player
            || channel.binding.server != LinkRole::Original
            || channel.remote_key != root.host
            || channel.local_key != Some(keys.public_key().to_bytes())
            || membership.members.len() != root.members.len()
            || membership.members.iter().any(|member| {
                !root.members.iter().any(|initial| {
                    initial.player == member.player
                        && initial.seat == member.seat
                        && initial.key == member.key
                })
            })
        {
            return Err(Error::Unauthorized);
        }
        if let Some(authenticated) = &channel.authenticated_membership {
            membership.follows(root, authenticated)?;
        }
        if !membership.members.iter().any(|member| {
            member.player == capability.player && member.key == Some(keys.public_key().to_bytes())
        }) {
            return Err(Error::Unauthorized);
        }
        sequence.replay.receipt(&armed.receipt)?;
        sequence
            .replay
            .begin(
                root.standby,
                armed.sequence,
                &armed.encode(&root.context()?)?,
                true,
            )?
            .commit()?;
        sequence.replay.certificate(root, &membership)?;
        Ok(Self {
            descriptor,
            player: capability.player,
            keys,
            membership,
            channel,
            sequence,
            intents: IntentJournal::default(),
            delivery: DeliveryJournal::default(),
            sent_input: 0,
            sent_view: 0,
            received_view: 0,
            failed: None,
        })
    }
    fn live(&self) -> Result<()> {
        self.sequence.replay.live()?;
        if self.failed.is_some() {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    pub fn failure(&self) -> Option<&Error> {
        self.failed.as_ref()
    }
    pub fn player(&self) -> u64 {
        self.player
    }
    pub fn sequence(&self) -> PlayerSequence {
        self.sequence.clone()
    }
    pub fn journals(&self) -> (&DeliveryJournal, &IntentJournal) {
        (&self.delivery, &self.intents)
    }
    /// Append before applying a dependent local game effect, through the game's
    /// complete private transaction. Transport ACKs never prune this journal.
    pub fn intents_mut(&mut self) -> Result<&mut IntentJournal> {
        self.live()?;
        Ok(&mut self.intents)
    }
    pub fn pause(&mut self, error: Error) {
        if error == Error::Conflict {
            self.sequence.replay.fail();
        }
        if self.failed.is_none() {
            self.failed = Some(error);
        }
    }
    fn enqueue(&mut self, action: PlayerAction) -> Result<()> {
        self.live()?;
        if self.sequence.context != self.descriptor.root.context()?
            || self.sequence.key != self.keys.public_key().to_bytes()
        {
            return Err(Error::Unauthorized);
        }
        let record = PlayerControl::sign(
            &self.descriptor.root,
            &self.membership,
            self.channel.term,
            self.sequence.allocate()?,
            self.player,
            self.channel.tls,
            action,
            &self.keys,
        )?;
        self.channel
            .enqueue(PacketKind::Control, &record.encode(&self.descriptor.root)?)?;
        Ok(())
    }
    /// Queue a bounded prefix of already journaled originals. Unsent entries
    /// remain in the same journal; only a verified committed watermark frees it.
    pub fn queue_pending(&mut self, limit: usize) -> Result<usize> {
        self.live()?;
        if limit > MAX_BATCH {
            return Err(Error::Bounds);
        }
        let pending = self
            .intents
            .pending()
            .filter(|(number, _)| *number > self.sent_input)
            .take(limit)
            .map(|(number, bytes)| (number, bytes.to_vec()))
            .collect::<Vec<_>>();
        let mut queued = 0;
        for (number, bytes) in pending {
            self.enqueue(PlayerAction::Intent { number, bytes })?;
            self.sent_input = number;
            queued += 1;
        }
        Ok(queued)
    }
    pub fn queue_applied(&mut self) -> Result<()> {
        self.enqueue(PlayerAction::Applied {
            output: self.delivery.applied(),
            tail: self.intents.tail(),
            cut: None,
        })
    }
    /// Replace only the physical normal-play connection, proving the complete
    /// journals already retained here. This cannot clear an application fault,
    /// change player/term, or manufacture a fresh game client.
    pub fn reconnect(&mut self, mut channel: Channel, request: &ReconnectChallenge) -> Result<()> {
        self.live()?;
        let root = &self.descriptor.root;
        request.verify(root)?;
        request.membership.follows(root, &self.membership)?;
        if channel.descriptor != self.descriptor
            || channel.side != ChannelSide::Client
            || channel.binding.client != LinkRole::Player
            || channel.binding.server
                != if self.channel.term == 0 {
                    LinkRole::Original
                } else {
                    LinkRole::Successor
                }
            || channel.term != self.channel.term
            || request.membership.receipt.term != channel.term
            || request.player != self.player
            || request.tls != channel.tls
            || channel.tls == self.channel.tls
            || channel.local_key != Some(self.keys.public_key().to_bytes())
            || channel.remote_key != self.channel.remote_key
        {
            return Err(Error::Unauthorized);
        }
        if let Some(authenticated) = &channel.authenticated_membership {
            request.membership.follows(root, authenticated)?;
        }
        self.sequence
            .replay
            .certificate(root, &request.membership)?;
        let incoming = self.sequence.replay.begin(
            channel.remote_key,
            request.sequence,
            &request.encode(root)?,
            false,
        )?;
        let proof = PlayerControl::resume_connection(
            root,
            request,
            channel.tls,
            &self.delivery,
            &self.intents,
            self.sequence.allocate()?,
            &self.keys,
        )?;
        let input = request
            .membership
            .receipt
            .watermarks
            .iter()
            .find(|mark| mark.player == self.player && !mark.retired)
            .ok_or(Error::Unauthorized)?
            .input;
        let mut intents = IntentJournal::restore(&self.intents.checkpoint()?)?;
        if input > intents.acknowledged() {
            intents.acknowledge(input)?;
        }
        channel.enqueue(PacketKind::Control, &proof.encode(root)?)?;
        // Enqueue succeeds before any owned state is replaced. Sender sequence
        // gaps are harmless; original intent IDs and all delivery cursors remain.
        incoming.commit()?;
        self.channel = channel;
        self.membership = request.membership.clone();
        self.intents = intents;
        self.sent_input = input;
        Ok(())
    }
    pub fn queue_view(&mut self, bytes: Vec<u8>) -> Result<u64> {
        self.live()?;
        let number = self.sent_view.checked_add(1).ok_or(Error::Bounds)?;
        self.enqueue(PlayerAction::Lossy { number, bytes })?;
        self.sent_view = number;
        Ok(number)
    }
    pub fn poll_send(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        self.live()?;
        self.channel.poll_send(now_ms)
    }
    fn retained_mark<'a>(&self, receipt: &'a Receipt) -> Result<&'a Watermark> {
        self.sequence.replay.receipt(receipt)?;
        let mark = receipt
            .watermarks
            .iter()
            .find(|mark| mark.player == self.player && !mark.retired)
            .ok_or(Error::Closed)?;
        if receipt.term > self.channel.term
            || mark.input > self.intents.tail()
            || mark.output_ack > self.delivery.applied()
        {
            return Err(Error::Invalid("lost client journals"));
        }
        Ok(mark)
    }
    /// Apply only certified game bytes. The callback must use the game's
    /// complete transaction seam and journal any generated reliable followups.
    /// A callback error/panic latches the endpoint, suppressing later traffic.
    pub fn receive(
        &mut self,
        wire: &[u8],
        now_ms: u64,
        mut apply: impl FnMut(Delivery, &[u8], &mut IntentJournal) -> Result<()>,
    ) -> Result<Option<PlayerEvent>> {
        self.live()?;
        // Only ingress refusal leaves a physical frame unconsumed. Application
        // callbacks can return the same Error variant after mutation, so keep
        // their failures outside this retryable branch.
        let received = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.channel.receive(wire, now_ms)
        }))
        .unwrap_or(Err(Error::Invalid("player framing panic")));
        let (kind, bytes) = match received {
            Ok(Some((kind, _, bytes))) => (kind, bytes),
            Ok(None) => return Ok(None),
            Err(Error::RateLimited) => return Err(Error::RateLimited),
            Err(error) => {
                self.pause(error.clone());
                return Err(error);
            }
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.apply_packet(kind, &bytes, &mut apply)
        }))
        .unwrap_or(Err(Error::Invalid("player application panic")))
        .map_err(|error| {
            if error == Error::RateLimited {
                Error::Invalid("player application rate refusal")
            } else {
                error
            }
        });
        if let Err(error) = &result {
            self.pause(error.clone());
        }
        result
    }
    fn apply_packet(
        &mut self,
        kind: PacketKind,
        bytes: &[u8],
        apply: &mut impl FnMut(Delivery, &[u8], &mut IntentJournal) -> Result<()>,
    ) -> Result<Option<PlayerEvent>> {
        match kind {
            PacketKind::Output => {
                let record = CertifiedOutput::decode(&self.descriptor.root.context()?, &bytes)?;
                if record.output.recipient != self.player {
                    return Err(Error::Unauthorized);
                }
                let input = self.retained_mark(&record.receipt)?.input;
                // This committed prefix may free a full journal for reliable
                // followups. Stage pruning before the native transaction, and
                // install that journal only after successful local adoption.
                let mut intents = IntentJournal::restore(&self.intents.checkpoint()?)?;
                if input > intents.acknowledged() {
                    intents.acknowledge(input)?;
                }
                let output = &record.output;
                let applied = match output.delivery {
                    Delivery::Reliable => self.delivery.apply_certified(
                        &self.descriptor.root.context()?,
                        self.player,
                        &record,
                        |bytes| apply(Delivery::Reliable, bytes, &mut intents),
                    )?,
                    Delivery::Lossy if output.sequence > self.received_view => {
                        apply(Delivery::Lossy, &output.bytes, &mut intents)?;
                        self.received_view = output.sequence;
                        true
                    }
                    Delivery::Lossy => false,
                };
                self.intents = intents;
                Ok(Some(PlayerEvent::Output {
                    receipt: record.receipt.clone(),
                    delivery: output.delivery,
                    sequence: output.sequence,
                    applied,
                }))
            }
            PacketKind::Control => {
                let membership = MembershipCertificate::decode(&self.descriptor.root, &bytes)?;
                // Decode authenticates the complete signed certificate. Check
                // remembered canonical contradictions before stale-frontier
                // filtering; a failed later check rolls back this ticket.
                let incoming = self.sequence.replay.begin(
                    self.descriptor.root.standby,
                    membership.sequence,
                    bytes,
                    false,
                )?;
                if !incoming.is_new()
                    && (membership.receipt.index < self.membership.receipt.index
                        || membership.body(&self.descriptor.root)?
                            == self.membership.body(&self.descriptor.root)?)
                {
                    incoming.commit()?;
                    return Ok(None);
                }
                membership.follows(&self.descriptor.root, &self.membership)?;
                if !membership.members.iter().any(|member| {
                    member.player == self.player
                        && member.key == Some(self.keys.public_key().to_bytes())
                }) {
                    return Err(Error::Closed);
                }
                let input = self.retained_mark(&membership.receipt)?.input;
                if input > self.intents.acknowledged() {
                    self.intents.acknowledge(input)?;
                }
                incoming.commit()?;
                self.sequence
                    .replay
                    .advance_membership(&self.descriptor.root, &membership)?;
                self.membership = membership.clone();
                Ok(Some(PlayerEvent::Membership(membership)))
            }
            _ => Err(Error::Unauthorized),
        }
    }
}

/// Normal-play inputs retained across a replacement player connection. Reading
/// a batch never drains it: only an installed authority receipt frees reliable
/// entries. Recovery uses its own signed input-round protocol instead.
pub struct PlayerQueue {
    inbox: PlayerInbox,
    base: Receipt,
    accepted: HandledInputs,
    pending: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    applied: u64,
    lossy_number: u64,
    lossy: VecDeque<(u64, Vec<u8>)>,
    closed: bool,
    reconnect: Option<PendingReconnect>,
    reconnect_ms: Option<u64>,
    /// True once `accepted`/`pending`/`applied` were rebuilt from the image
    /// committed under `base`. A receipt binds its image (`receipt.state ==
    /// state_hash(image)`), so an equal receipt means an identical image.
    refreshed: bool,
}
impl PlayerQueue {
    fn from_channel(
        channel: &Channel,
        membership: MembershipCertificate,
        primary: &Primary,
    ) -> Result<Self> {
        if !matches!(
            channel.binding.server,
            LinkRole::Original | LinkRole::Successor
        ) {
            return Err(Error::Unauthorized);
        }
        let inbox = PlayerInbox::new(channel, membership)?;
        Self::from_inbox(inbox, primary)
    }
    fn from_inbox(inbox: PlayerInbox, primary: &Primary) -> Result<Self> {
        let lossy_number = inbox.lossy_number;
        let mut queue = Self {
            base: inbox.membership.receipt.clone(),
            inbox,
            accepted: HandledInputs::default(),
            pending: VecDeque::new(),
            bytes: 0,
            applied: 0,
            lossy_number,
            lossy: VecDeque::new(),
            closed: false,
            reconnect: None,
            reconnect_ms: None,
            refreshed: false,
        };
        queue.refresh(primary)?;
        Ok(queue)
    }
    pub fn player(&self) -> u64 {
        self.inbox.player
    }
    pub fn receipt(&self) -> &Receipt {
        &self.base
    }
    /// A game batch may consume only a live queue anchored to its exact
    /// committed authority base. Refresh after every accepted receipt.
    pub fn validate_for(&self, root: &Root, primary: &Primary) -> Result<()> {
        primary.sender.replay.live()?;
        if self.closed || self.inbox.closed || primary.closed {
            return Err(Error::Closed);
        }
        if &self.inbox.root != root
            || primary.context != root.context()?
            || self.inbox.term != primary.receipt.term
        {
            return Err(Error::Unauthorized);
        }
        if self.base != primary.receipt {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn pending(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.pending.iter().map(|(n, bytes)| (*n, bytes.as_slice()))
    }
    pub fn output_ack(&self) -> u64 {
        self.applied
    }
    /// The newest retained lossy view, if any.
    pub fn lossy(&self) -> Option<(u64, &[u8])> {
        self.lossy.back().map(|(n, bytes)| (*n, bytes.as_slice()))
    }
    /// Every retained lossy view in number order. Each is one verified signed
    /// view, delivered on its own, as the plain host processes every datagram.
    pub fn lossy_views(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.lossy.iter().map(|(n, bytes)| (*n, bytes.as_slice()))
    }
    /// Called after adoption of the batch which used this view. Selection takes
    /// a number-ordered prefix, so this view and any older one are consumed; a
    /// newer view received while that batch was in flight remains queued.
    pub fn discard_lossy(&mut self, number: u64) {
        while self.lossy.front().is_some_and(|(n, _)| *n <= number) {
            self.lossy.pop_front();
        }
    }
    /// Adopt committed input hashes and prune only that committed prefix. The
    /// queued delivery ACK is still speculative until a later receipt includes
    /// it; this method never changes the Primary or its retained output proofs.
    pub fn refresh(&mut self, primary: &Primary) -> Result<()> {
        primary.sender.replay.live()?;
        if self.closed || primary.closed {
            return Err(Error::Closed);
        }
        let context = self.inbox.root.context()?;
        if context != primary.context || primary.receipt.term != self.inbox.term {
            return Err(Error::Unauthorized);
        }
        if primary.receipt.index < self.base.index
            || primary.receipt.logical_ms < self.base.logical_ms
        {
            return Err(Error::Stale);
        }
        if self.refreshed && primary.receipt == self.base {
            // Same signed receipt, so the same committed image: decoding it and
            // re-recording `pending` would reproduce the current state exactly.
            // Only the Primary-side output ceiling is re-checked.
            if self.applied > primary.output_ceiling(self.inbox.player, Delivery::Reliable) {
                return Err(Error::Conflict);
            }
            return Ok(());
        }
        if primary.receipt.index == self.base.index
            && primary.receipt.digest(&context)? != self.base.digest(&context)?
        {
            return Err(Error::Conflict);
        }
        let image = SessionImage::decode(&self.inbox.root, primary.committed_image())?;
        if !image
            .members
            .iter()
            .any(|m| m.player == self.inbox.player && m.key == Some(self.inbox.key))
        {
            self.closed = true;
            return Err(Error::Closed);
        }
        let mark = primary
            .receipt
            .watermarks
            .iter()
            .find(|m| m.player == self.inbox.player && !m.retired)
            .ok_or(Error::Unauthorized)?;
        let mut accepted = image
            .inputs
            .get(&self.inbox.player)
            .ok_or(Error::Gap)?
            .clone();
        if accepted.handled() != mark.input {
            return Err(Error::Conflict);
        }
        let mut pending = VecDeque::new();
        let mut bytes = 0usize;
        for (number, payload) in &self.pending {
            if accepted.record(*number, payload).map_err(|error| {
                if error == Error::Conflict {
                    self.closed = true;
                    primary.sender.replay.fail();
                }
                error
            })? {
                bytes = bytes.checked_add(payload.len()).ok_or(Error::Bounds)?;
                pending.push_back((*number, payload.clone()));
            }
        }
        let applied = self.applied.max(mark.output_ack);
        if applied > primary.output_ceiling(self.inbox.player, Delivery::Reliable) {
            return Err(Error::Conflict);
        }
        self.accepted = accepted;
        self.pending = pending;
        self.bytes = bytes;
        self.applied = applied;
        self.base = primary.receipt.clone();
        self.refreshed = true;
        Ok(())
    }
    fn reconnect_clock(&mut self, now_ms: u64) -> Result<()> {
        if self.reconnect_ms.is_some_and(|last| now_ms < last) {
            return Err(Error::Invalid("backwards reconnect clock"));
        }
        self.reconnect_ms = Some(now_ms);
        Ok(())
    }
    /// Retain original IDs, bytes, delivery cursor and latest view while the
    /// physical TLS connection and its framing replay counters are replaced.
    pub fn begin_reconnect(
        &mut self,
        channel: &Channel,
        membership: MembershipCertificate,
        primary: &Primary,
        now_ms: u64,
        keys: &Keys,
    ) -> Result<ReconnectChallenge> {
        self.reconnect_clock(now_ms)?;
        let next = Self::from_channel(channel, membership, primary)?;
        if next.inbox.root != self.inbox.root
            || next.inbox.player != self.inbox.player
            || next.inbox.key != self.inbox.key
            || next.inbox.term != self.inbox.term
            || next.inbox.tls == self.inbox.tls
        {
            return Err(Error::Unauthorized);
        }
        next.inbox
            .membership
            .follows(&self.inbox.root, &self.inbox.membership)?;
        self.refresh(primary)?;
        let context = self.inbox.root.context()?;
        if next.inbox.membership.receipt.digest(&context)? != self.base.digest(&context)? {
            return Err(Error::Stale);
        }
        let image = SessionImage::decode(&self.inbox.root, primary.committed_image())?;
        if next.inbox.membership.members != image.members
            || next.inbox.membership.revision != image.membership_revision
            || next.inbox.membership.next_player != image.next_player
        {
            return Err(Error::Conflict);
        }
        let signer = if self.base.term == 0 {
            self.inbox.root.host
        } else {
            self.inbox.root.standby
        };
        if keys.public_key().to_bytes() != signer {
            return Err(Error::Unauthorized);
        }
        let expires = now_ms.checked_add(5000).ok_or(Error::Bounds)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Invalid("reconnect RNG"))?;
        let sequence = primary.sender.allocate()?;
        let mut request = ReconnectChallenge {
            sequence,
            player: self.player(),
            nonce,
            tls: channel.tls,
            membership: next.inbox.membership.clone(),
            signature: [0; 64],
        };
        request.signature = sign(keys, request.digest(&self.inbox.root)?);
        request.verify(&self.inbox.root)?;
        self.reconnect = Some(PendingReconnect {
            inbox: next.inbox,
            request: request.clone(),
            expires,
        });
        Ok(request)
    }
    /// Switch only after a fresh TLS/nonce/frontier-bound proof of retained
    /// journals. Ordinary commits may advance the owned issued frontier while
    /// the proof travels; validate its cuts against the current continuation. Keep original pending bytes, view floors and control counters;
    /// a transport handshake alone never grants this continuation.
    pub fn finish_reconnect(&mut self, bytes: &[u8], primary: &Primary, now_ms: u64) -> Result<()> {
        self.reconnect_clock(now_ms)?;
        self.refresh(primary)?;
        let pending = self.reconnect.as_ref().ok_or(Error::Stale)?;
        if now_ms >= pending.expires || now_ms < pending.expires - 5000 {
            return Err(Error::Stale);
        }
        let issued = &pending.request.membership.receipt;
        if issued.term != self.base.term
            || issued.index > self.base.index
            || issued.logical_ms > self.base.logical_ms
        {
            return Err(Error::Stale);
        }
        if issued.index == self.base.index
            && issued.digest(&self.inbox.root.context()?)?
                != self.base.digest(&self.inbox.root.context()?)?
        {
            return Err(Error::Conflict);
        }
        let mut inbox = pending.inbox.clone();
        inbox.last = self.inbox.last;
        inbox.recent = self.inbox.recent.clone();
        inbox.lossy_number = self.inbox.lossy_number;
        let record = inbox
            .receive(bytes)
            .map_err(|error| {
                if error == Error::Conflict {
                    self.closed = true;
                    primary.sender.replay.fail();
                }
                error
            })?
            .ok_or(Error::Stale)?;
        let incoming =
            primary
                .sender
                .replay
                .begin(self.inbox.key, record.sequence, bytes, false)?;
        let PlayerAction::Applied { output, tail, cut } = record.action else {
            return Err(Error::Unauthorized);
        };
        let mark = self
            .base
            .watermarks
            .iter()
            .find(|m| m.player == self.player() && !m.retired)
            .ok_or(Error::Unauthorized)?;
        if cut != Some(pending.request.nonce)
            || output < self.applied
            || output > primary.output_ceiling(self.player(), Delivery::Reliable)
            || tail < self.accepted.handled()
            || tail < mark.input
            || tail - mark.input > MAX_JOURNAL_RECORDS as u64
        {
            return Err(Error::Invalid("reconnect retained cut"));
        }
        incoming.commit()?;
        self.inbox = inbox;
        self.applied = output;
        self.reconnect = None;
        Ok(())
    }
    /// Verify a framed human action before queuing it. Capacity errors leave
    /// the action and replay cursor unconsumed; the runner pauses intake and
    /// retains the client's original journal for retry or fresh reconnect.
    pub fn receive(&mut self, bytes: &[u8], primary: &Primary) -> Result<bool> {
        self.refresh(primary)?;
        // The one signature verification on this path; the result is carried
        // into the cloned inbox's replay admission below.
        let verified = self.inbox.authenticate(bytes)?;
        let mut inbox = self.inbox.clone();
        let parsed = &verified.record;
        let sequence = parsed.sequence;
        let known_original = if let PlayerAction::Intent { number, bytes } = &parsed.action {
            if *number <= self.accepted.handled() {
                self.accepted.check(*number, bytes).map_err(|error| {
                    if error == Error::Conflict {
                        self.closed = true;
                        primary.sender.replay.fail();
                    }
                    error
                })?;
                true
            } else {
                false
            }
        } else {
            false
        };
        let received = inbox.admit(verified);
        if known_original && matches!(received, Err(Error::Stale)) {
            primary
                .sender
                .replay
                .begin(self.inbox.key, sequence, bytes, true)?
                .commit()?;
            return Ok(false);
        }
        let record = received.map_err(|error| {
            if error == Error::Conflict {
                self.closed = true;
                primary.sender.replay.fail();
            }
            error
        })?;
        let incoming = primary.sender.replay.begin(
            self.inbox.key,
            sequence,
            bytes,
            record.is_none() || known_original,
        )?;
        let Some(record) = record else {
            incoming.commit()?;
            return Ok(false);
        };
        let changed = match record.action {
            PlayerAction::Intent { number, bytes } => {
                let fresh = self.accepted.check(number, &bytes).map_err(|error| {
                    if error == Error::Conflict {
                        self.closed = true;
                        primary.sender.replay.fail();
                    }
                    error
                })?;
                if fresh {
                    let size = self.bytes.checked_add(bytes.len()).ok_or(Error::Bounds)?;
                    if size > MAX_JOURNAL_BYTES || self.pending.len() >= MAX_JOURNAL_RECORDS {
                        return Err(Error::Bounds);
                    }
                    self.accepted.record(number, &bytes)?;
                    self.pending.push_back((number, bytes));
                    self.bytes = size;
                }
                fresh
            }
            PlayerAction::Lossy { number, bytes } => {
                if number > self.lossy_number {
                    // Lossy semantics: a full view list drops its oldest view,
                    // never pauses intake and never touches reliable originals.
                    if self.lossy.len() >= MAX_LOSSY_VIEWS {
                        self.lossy.pop_front();
                    }
                    self.lossy_number = number;
                    self.lossy.push_back((number, bytes));
                    true
                } else {
                    false
                }
            }
            PlayerAction::Applied { output, tail, cut } => {
                let handled = self
                    .base
                    .watermarks
                    .iter()
                    .find(|m| m.player == self.inbox.player)
                    .ok_or(Error::Gap)?
                    .input;
                if cut.is_some()
                    || tail < handled
                    || tail
                        .checked_sub(handled)
                        .is_none_or(|n| n > MAX_JOURNAL_RECORDS as u64)
                    || output > primary.output_ceiling(self.inbox.player, Delivery::Reliable)
                {
                    return Err(Error::Invalid("normal player delivery ACK"));
                }
                let changed = output > self.applied;
                self.applied = self.applied.max(output);
                changed
            }
        };
        incoming.commit()?;
        self.inbox = inbox;
        Ok(changed)
    }
}

/// One verified original or signed lossy view selected for a private game batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedPlayerInput {
    Reliable {
        player: u64,
        number: u64,
        bytes: Vec<u8>,
    },
    Lossy {
        player: u64,
        number: u64,
        bytes: Vec<u8>,
    },
}
/// Bot originals read from the exact committed complete game runner. These
/// records are scheduling input, not remote authentication or publication.
pub struct LocalInputs {
    pub player: u64,
    pub originals: Vec<(u64, Vec<u8>)>,
}
/// Deterministic fair selection, bounded by both bytes and records. Rotate the
/// first player using the committed index, then select one action per player
/// per pass. On alternating full rotations views get a turn ahead of originals,
/// so neither stream can starve even when only one action fits a batch. Each
/// player's originals and lossy views leave in number order.
pub fn select_player_inputs(
    root: &Root,
    primary: &Primary,
    queues: &[&PlayerQueue],
    max_records: usize,
    max_bytes: usize,
) -> Result<Vec<SelectedPlayerInput>> {
    select_player_and_local_inputs(root, primary, queues, &[], max_records, max_bytes)
}
pub fn select_player_and_local_inputs(
    root: &Root,
    primary: &Primary,
    queues: &[&PlayerQueue],
    locals: &[LocalInputs],
    max_records: usize,
    max_bytes: usize,
) -> Result<Vec<SelectedPlayerInput>> {
    if primary.closed {
        return Err(Error::Closed);
    }
    if primary.context != root.context()? {
        return Err(Error::Unauthorized);
    }
    if queues.len() + locals.len() > MAX_PLAYERS
        || max_records > MAX_BATCH
        || max_bytes > MAX_JOURNAL_BYTES
    {
        return Err(Error::Bounds);
    }
    let mut ordered = BTreeMap::new();
    for queue in queues {
        queue.validate_for(root, primary)?;
        if ordered
            .insert(
                queue.player(),
                (
                    queue
                        .pending()
                        .map(|(n, b)| (n, b.to_vec()))
                        .collect::<Vec<_>>(),
                    queue
                        .lossy_views()
                        .map(|(n, b)| (n, b.to_vec()))
                        .collect::<Vec<_>>(),
                ),
            )
            .is_some()
        {
            return Err(Error::Conflict);
        }
    }
    if !locals.is_empty() {
        let image = SessionImage::decode(root, primary.committed_image())?;
        for local in locals {
            if !image
                .members
                .iter()
                .any(|m| m.player == local.player && m.key.is_none())
            {
                return Err(Error::Unauthorized);
            }
            let mut history = image.inputs.get(&local.player).ok_or(Error::Gap)?.clone();
            if local.originals.len() > MAX_JOURNAL_RECORDS {
                return Err(Error::Bounds);
            }
            let mut bytes = 0usize;
            let mut pending = Vec::new();
            for (number, payload) in &local.originals {
                bytes = bytes.checked_add(payload.len()).ok_or(Error::Bounds)?;
                if bytes > MAX_JOURNAL_BYTES {
                    return Err(Error::Bounds);
                }
                if history.record(*number, payload)? {
                    pending.push((*number, payload.clone()));
                }
            }
            if ordered
                .insert(local.player, (pending, Vec::new()))
                .is_some()
            {
                return Err(Error::Conflict);
            }
        }
    }
    if ordered.is_empty() {
        return Ok(Vec::new());
    }
    let ordered = ordered.into_iter().collect::<Vec<_>>();
    let count = ordered.len();
    let start = (primary.receipt.index % count as u64) as usize;
    let prefer_view = (primary.receipt.index / count as u64) % 2 == 1;
    let mut cursors = vec![0; count];
    let mut view_cursors = vec![0; count];
    let mut remaining = max_bytes;
    let mut selected = Vec::new();
    while selected.len() < max_records {
        let before = selected.len();
        for step in 0..count {
            if selected.len() == max_records {
                break;
            }
            let i = (start + step) % count;
            let (player, (pending, views)) = &ordered[i];
            let player = *player;
            let original = pending.get(cursors[i]).map(|(n, b)| (*n, b.as_slice()));
            let view = views.get(view_cursors[i]).map(|(n, b)| (*n, b.as_slice()));
            let use_view = match (original, view) {
                (Some((_, bytes)), Some((_, view))) => {
                    if prefer_view && view.len() <= remaining {
                        true
                    } else if bytes.len() <= remaining {
                        false
                    } else if view.len() <= remaining {
                        true
                    } else {
                        continue;
                    }
                }
                (Some((_, bytes)), None) if bytes.len() <= remaining => false,
                (None, Some((_, bytes))) if bytes.len() <= remaining => true,
                _ => continue,
            };
            if use_view {
                let (number, bytes) = view.unwrap();
                remaining -= bytes.len();
                view_cursors[i] += 1;
                selected.push(SelectedPlayerInput::Lossy {
                    player,
                    number,
                    bytes: bytes.to_vec(),
                });
            } else {
                let (number, bytes) = original.unwrap();
                remaining -= bytes.len();
                cursors[i] += 1;
                selected.push(SelectedPlayerInput::Reliable {
                    player,
                    number,
                    bytes: bytes.to_vec(),
                });
            }
        }
        if selected.len() == before {
            break;
        }
    }
    Ok(selected)
}

/// Fresh, signed request to seal one survivor's next reliable input tail. The
/// request carries only the public committed roster/frontier, never game state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputRound {
    pub sequence: u64,
    pub player: u64,
    pub nonce: Hash,
    pub tls: [u8; 32],
    pub membership: MembershipCertificate,
    pub signature: SignatureBytes,
}
impl InputRound {
    fn body(&self, root: &Root) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Invalid("input round sequence"));
        }
        let mut bytes = control_prefix(&root.context()?, 1, 16, self.sequence);
        bytes.extend(self.player.to_be_bytes());
        bytes.extend(self.nonce);
        bytes.extend(self.tls);
        put_bytes(&mut bytes, &self.membership.encode(root)?, 2048)?;
        Ok(bytes)
    }
    fn digest(&self, root: &Root) -> Result<Hash> {
        Ok(hash(b"fray/migration/control/v1\0", &self.body(root)?))
    }
    fn issue(
        root: &Root,
        promotion: &Promotion,
        membership: MembershipCertificate,
        player: u64,
        tls: [u8; 32],
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        if keys.public_key().to_bytes() != root.standby {
            return Err(Error::Unauthorized);
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Invalid("input round RNG"))?;
        let mut request = Self {
            sequence,
            player,
            nonce,
            tls,
            membership,
            signature: [0; 64],
        };
        request.signature = sign(keys, request.digest(root)?);
        request.verify(root, promotion)?;
        Ok(request)
    }
    pub fn verify(&self, root: &Root, promotion: &Promotion) -> Result<()> {
        let context = root.context()?;
        promotion.verify(&context)?;
        self.membership.verify(root)?;
        let receipt = &self.membership.receipt;
        if receipt.logical_ms != promotion.final_receipt.logical_ms
            || receipt.index < promotion.final_receipt.index
            || (receipt.term == 0
                && receipt.digest(&context)? != promotion.final_receipt.digest(&context)?)
            || (receipt.term == 1 && receipt.index <= promotion.final_receipt.index)
            || !self
                .membership
                .members
                .iter()
                .any(|m| m.player == self.player && m.key.is_some())
        {
            return Err(Error::Conflict);
        }
        verify(root.standby, self.digest(root)?, self.signature)
    }
    pub fn encode(&self, root: &Root, promotion: &Promotion) -> Result<Vec<u8>> {
        self.verify(root, promotion)?;
        let mut bytes = self.body(root)?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(root: &Root, promotion: &Promotion, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(bytes);
        let sequence = read_control_prefix(&mut r, &root.context()?, 1, 16)?;
        let request = Self {
            sequence,
            player: r.u64()?,
            nonce: r.array()?,
            tls: r.array()?,
            membership: MembershipCertificate::decode(root, &r.bytes(2048)?)?,
            signature: r.array()?,
        };
        r.finish()?;
        request.verify(root, promotion)?;
        Ok(request)
    }
}
impl PlayerControl {
    /// Seal the actual retained journals after this round's output replay. A
    /// state-lost client cannot synthesize the already-handled input prefix.
    pub fn seal_round(
        root: &Root,
        promotion: &Promotion,
        request: &InputRound,
        tls: [u8; 32],
        delivery: &DeliveryJournal,
        intents: &IntentJournal,
        sequence: u64,
        keys: &Keys,
    ) -> Result<Self> {
        request.verify(root, promotion)?;
        let mark = request
            .membership
            .receipt
            .watermarks
            .iter()
            .find(|m| m.player == request.player && !m.retired)
            .ok_or(Error::Unauthorized)?;
        if request.tls != tls
            || delivery.poisoned
            || delivery.applied() != mark.output_ack
            || intents.acknowledged() > mark.input
            || intents.tail() < mark.input
            || intents.tail() - mark.input > MAX_JOURNAL_RECORDS as u64
        {
            return Err(Error::Gap);
        }
        Self::sign(
            root,
            &request.membership,
            1,
            sequence,
            request.player,
            tls,
            PlayerAction::Applied {
                output: delivery.applied(),
                tail: intents.tail(),
                cut: Some(request.nonce),
            },
            keys,
        )
    }
}

#[cfg(test)]
mod raw_recovery_engine_tests {
    use super::*;
    #[test]
    fn security_callback_shared_fault_suppresses_its_second_attempt_and_install() {
        let (fixture, host, key, _) = descriptor_fixture();
        let mut root = fixture.root;
        root.members.clear();
        let mut descriptor = Descriptor::offer(root.clone(), &host).unwrap();
        descriptor.consent(&key).unwrap();
        let image = SessionImage::initial(&root, &[], vec![0], 1, 100).unwrap();
        let seq = Sequencer::arm_session(root, image, &key).unwrap();
        let mut recovery = Recovery::begin_session(descriptor, seq, &key, 0).unwrap();
        recovery.seal(0).unwrap();
        let replay = recovery.sequencer.sender.replay.clone();
        let frontier = recovery.sequencer.receipt.clone();
        let mut calls = 0;
        assert_eq!(
            recovery.revalidate_security(&key, 0, |_, _| {
                calls += 1;
                replay.fail();
                Err(Error::Invalid("native fault"))
            }),
            Err(Error::Closed)
        );
        assert_eq!(calls, 1);
        assert_eq!(recovery.phase, RecoveryPhase::Failed);
        assert_eq!(recovery.sequencer.receipt, frontier);
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
    fn recovery_fixture(tail: u64, initial_outputs: bool) -> (Recovery, Descriptor, Keys, Keys) {
        let (mut recovery, descriptor, standby, player) = collecting_fixture(initial_outputs);
        let challenge = recovery
            .challenge(20, [2; 32], 2, player.public_key().to_bytes(), &standby, 0)
            .unwrap();
        let proof =
            ResumeProof::sign(&descriptor.root, &challenge, [2; 32], 0, tail, 1, &player).unwrap();
        recovery.accept(20, [2; 32], &proof, 0).unwrap();
        recovery.retain_local(3, 0, 0, 0).unwrap();
        (recovery, descriptor, standby, player)
    }
    /// A recovery promoted at 0 that has collected nobody yet.
    fn collecting_fixture(initial_outputs: bool) -> (Recovery, Descriptor, Keys, Keys) {
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
            100,
            marks,
            &standby,
        )
        .unwrap();
        if initial_outputs {
            let outputs = [1, 2]
                .map(|recipient| Output {
                    recipient,
                    delivery: Delivery::Reliable,
                    sequence: 1,
                    bytes: vec![recipient as u8],
                })
                .to_vec();
            let candidate = sequencer
                .next(
                    vec![0],
                    100,
                    sequencer.receipt().watermarks.clone(),
                    outputs,
                )
                .unwrap();
            let staged = sequencer.stage(candidate).unwrap();
            sequencer.install(staged, &standby).unwrap();
        }
        let histories = descriptor
            .root
            .members
            .iter()
            .map(|m| (m.player, HandledInputs::default()))
            .collect();
        let recovery =
            Recovery::begin(descriptor.clone(), sequencer, histories, &standby, 0).unwrap();
        (recovery, descriptor, standby, player)
    }
    #[test]
    fn contradictory_pending_or_handled_recovery_originals_fault_before_more_game_work() {
        for handled in [false, true] {
            let (mut recovery, _, key, _) = recovery_fixture(1, false);
            recovery.seal(250).unwrap();
            recovery.begin_round().unwrap();
            recovery.seal_inputs_inner(2, 1).unwrap();
            recovery.seal_inputs_inner(3, 0).unwrap();
            recovery.supply(2, 1, vec![7]).unwrap();
            if handled {
                recovery
                    .apply_next(&key, |_, _, _, _| Ok((vec![1], vec![])))
                    .unwrap();
            }
            let receipt = recovery.sequencer.receipt().clone();
            let histories = recovery.histories.clone();
            recovery.supply(2, 1, vec![7]).unwrap();
            assert_eq!(recovery.supply(2, 1, vec![8]), Err(Error::Conflict));
            assert_eq!(recovery.phase(), RecoveryPhase::Failed);
            assert_eq!(recovery.sequencer.sender.allocate(), Err(Error::Closed));
            assert_eq!(recovery.supply(2, 1, vec![7]), Err(Error::Closed));
            assert_eq!(
                recovery.apply_next(&key, |_, _, _, _| panic!("contradictory original")),
                Err(Error::Closed)
            );
            assert_eq!(
                recovery.commit_departures(&key, |_, _, _| panic!("contradictory original")),
                Err(Error::Closed)
            );
            assert_eq!(recovery.histories, histories);
            assert_eq!(recovery.sequencer.receipt(), &receipt);
        }
    }
    #[test]
    fn recovery_shared_fault_blocks_all_remaining_work_and_a_second_callback_attempt() {
        for callback_kind in [0, 1, 2] {
            let (mut recovery, descriptor, key, _) = recovery_fixture(1, false);
            if callback_kind == 2 {
                // Exercise the complete native-image local-client path as well.
                let image = SessionImage::initial(
                    &descriptor.root,
                    &[(1, 10), (2, 11), (3, 12)],
                    vec![0],
                    1,
                    100,
                )
                .unwrap();
                let sequencer =
                    Sequencer::arm_session(descriptor.root.clone(), image, &key).unwrap();
                recovery = Recovery::begin_session(descriptor.clone(), sequencer, &key, 0).unwrap();
                recovery.retain_local(3, 0, 0, 0).unwrap();
            }
            recovery.seal(250).unwrap();
            if recovery.phase() == RecoveryPhase::Security {
                recovery
                    .revalidate_security(&key, 250, |bytes, _| Ok(bytes.to_vec()))
                    .unwrap();
            }
            if callback_kind != 2 {
                recovery.begin_round().unwrap();
            }
            if callback_kind == 0 {
                recovery.seal_inputs_inner(2, 1).unwrap();
                recovery.seal_inputs_inner(3, 0).unwrap();
                recovery.supply(2, 1, vec![7]).unwrap();
            } else if callback_kind == 1 {
                recovery.survivors.get_mut(&2).unwrap().tail = 0;
                recovery.seal_inputs_inner(2, 0).unwrap();
                recovery.seal_inputs_inner(3, 0).unwrap();
            }
            let scope = recovery.sequencer.sender.replay.clone();
            let phase = recovery.phase();
            let receipt = recovery.sequencer.receipt().clone();
            let histories = recovery.histories.clone();
            let applications = recovery.applications;
            let cuts = recovery
                .survivors
                .iter()
                .map(|(p, s)| (*p, s.applied, s.tail, s.sealed))
                .collect::<Vec<_>>();
            let mut calls = 0;
            let mut fault = || {
                calls += 1;
                scope.fail();
                Err(Error::Invalid("callback raised shared conflict"))
            };
            let result = match callback_kind {
                0 => recovery.apply_next(&key, |_, _, _, _| fault()),
                1 => recovery.commit_departures(&key, |_, _, _| fault()),
                _ => recovery.commit_local_clients(&key, |_| {
                    fault()?;
                    unreachable!()
                }),
            };
            assert_eq!(result, Err(Error::Closed));
            assert_eq!(calls, 1);
            assert_eq!(recovery.poll(251), Err(Error::Closed));
            assert_eq!(recovery.replay(), Err(Error::Closed));
            assert_eq!(recovery.acknowledge_outputs(3, 0), Err(Error::Closed));
            assert_eq!(recovery.commit_delivery_acks(&key), Err(Error::Closed));
            assert_eq!(recovery.begin_round(), Err(Error::Closed));
            assert_eq!(recovery.seal_inputs(3, 0), Err(Error::Closed));
            assert_eq!(recovery.supply(3, 1, vec![1]), Err(Error::Closed));
            assert_eq!(
                recovery.apply_next(&key, |_, _, _, _| panic!("faulted game")),
                Err(Error::Closed)
            );
            assert_eq!(
                recovery.commit_departures(&key, |_, _, _| panic!("faulted departures")),
                Err(Error::Closed)
            );
            assert_eq!(
                recovery.commit_local_clients(&key, |_| panic!("faulted local clients")),
                Err(Error::Closed)
            );
            assert_eq!(recovery.phase(), phase);
            assert_eq!(recovery.sequencer.receipt(), &receipt);
            assert_eq!(recovery.histories, histories);
            assert_eq!(recovery.applications, applications);
            assert_eq!(
                recovery
                    .survivors
                    .iter()
                    .map(|(p, s)| (*p, s.applied, s.tail, s.sealed))
                    .collect::<Vec<_>>(),
                cuts
            );
        }
    }
    /// Challenge player 2 at `at` and sign its proof, as the survivor would.
    fn challenge_survivor(
        recovery: &mut Recovery,
        descriptor: &Descriptor,
        standby: &Keys,
        player: &Keys,
        at: u64,
    ) -> ResumeProof {
        let challenge = recovery
            .challenge(20, [2; 32], 2, player.public_key().to_bytes(), standby, at)
            .unwrap();
        ResumeProof::sign(&descriptor.root, &challenge, [2; 32], 0, 0, 1, player).unwrap()
    }
    #[test]
    fn a_survivor_proof_read_after_a_local_stall_is_retained() {
        // The proof arrives at about 60 ms, but the standby stalls from 10 ms
        // to 300 ms and only reads it then. A local stall is not peer silence.
        let (mut recovery, descriptor, standby, player) = collecting_fixture(false);
        let proof = challenge_survivor(&mut recovery, &descriptor, &standby, &player, 10);
        assert_eq!(recovery.accept(20, [2; 32], &proof, 300), Ok(()));
        assert!(recovery.survivors.contains_key(&2));
        recovery.retain_local(3, 0, 0, 300).unwrap();
        // The dead host never answers, so the extended window runs out.
        assert!(!recovery.seal(300).unwrap());
        assert!(recovery.seal(500).unwrap());
        assert_eq!(
            recovery.survivors.keys().copied().collect::<Vec<_>>(),
            vec![2, 3]
        );
    }
    #[test]
    fn local_members_are_retained_when_the_first_drive_is_late() {
        // The standby samples every frame, but its first drive after
        // promotion reaches the local bot only at 300 ms.
        let (mut recovery, _descriptor, _standby, _player) = collecting_fixture(false);
        for now in (50..=300).step_by(50) {
            recovery.poll(now).unwrap();
        }
        assert_eq!(recovery.retain_local(3, 0, 0, 300), Ok(()));
        assert_eq!(recovery.seal(300), Ok(true));
        assert_ne!(recovery.phase(), RecoveryPhase::Failed);
        assert_eq!(
            recovery.survivors.keys().copied().collect::<Vec<_>>(),
            vec![3]
        );
    }
    #[test]
    fn a_survivor_proof_that_arrives_after_the_window_is_refused() {
        // No local stall: the standby samples every 50 ms and the proof is
        // simply late.
        let (mut recovery, descriptor, standby, player) = collecting_fixture(false);
        let proof = challenge_survivor(&mut recovery, &descriptor, &standby, &player, 0);
        for now in (50..=200).step_by(50) {
            recovery.poll(now).unwrap();
        }
        assert_eq!(
            recovery.accept(20, [2; 32], &proof, 250),
            Err(Error::Closed)
        );
        assert!(!recovery.survivors.contains_key(&2));
    }
    #[test]
    fn the_collection_window_extends_for_one_local_stall_only() {
        // A first stall from 10 to 300 holds the window open until 500. A
        // second stall, from 400 to 520, is not deferred again.
        let (mut recovery, descriptor, standby, player) = collecting_fixture(false);
        let proof = challenge_survivor(&mut recovery, &descriptor, &standby, &player, 10);
        recovery.poll(300).unwrap();
        recovery.poll(400).unwrap();
        assert_eq!(
            recovery.accept(20, [2; 32], &proof, 520),
            Err(Error::Closed)
        );
    }
    #[test]
    fn recovery_seals_survivors_replays_then_drains_stable_ids_before_missing_host_departure() {
        let (mut recovery, _descriptor, key, _player) = recovery_fixture(2, true);
        assert!(recovery.replay().is_err());
        assert!(recovery.absent().is_err());
        assert!(!recovery.seal(249).unwrap());
        assert!(recovery.seal(250).unwrap());
        assert!(recovery.retain_local(3, 0, 0, 250).is_err());
        let replay = recovery.replay().unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].output.recipient, 2);
        assert_eq!(replay[0].output.sequence, 1);
        recovery.acknowledge_outputs(2, 1).unwrap();
        assert!(
            recovery.begin_round().is_err(),
            "output ACK must commit before barrier"
        );
        recovery.commit_delivery_acks(&key).unwrap();
        recovery.begin_round().unwrap();
        recovery.seal_inputs_inner(2, 3).unwrap();
        recovery.seal_inputs_inner(3, 1).unwrap();
        recovery.supply(2, 2, vec![2]).unwrap();
        recovery.supply(3, 1, vec![9]).unwrap();
        assert_eq!(recovery.next_input(), Err(Error::Gap));
        recovery.supply(2, 1, vec![1]).unwrap();
        let mut seen = Vec::new();
        for n in 1..=3 {
            if n == 3 {
                recovery.supply(2, 3, vec![3]).unwrap();
            }
            recovery
                .apply_next(&key, |player, clock, bytes, histories| {
                    assert_eq!(clock, 100);
                    assert_eq!(player, 2);
                    assert_eq!(histories[&player].handled(), n);
                    seen.push((player, n));
                    let outputs = if n == 3 {
                        vec![Output {
                            recipient: 3,
                            delivery: Delivery::Reliable,
                            sequence: 1,
                            bytes: vec![7],
                        }]
                    } else {
                        vec![]
                    };
                    Ok((bytes.to_vec(), outputs))
                })
                .unwrap();
            if n == 1 {
                recovery.supply(2, 1, vec![1]).unwrap();
                // Contradictory originals are terminal; their separate test
                // must not continue along this successful recovery path.
            }
        }
        assert!(
            recovery.next_input().is_err(),
            "bot cannot run ahead of committed output delivery"
        );
        recovery.acknowledge_outputs(3, 1).unwrap();
        recovery
            .apply_next(&key, |player, clock, bytes, histories| {
                assert_eq!(player, 3);
                assert_eq!(clock, 100);
                assert_eq!(histories[&3].handled(), 1);
                seen.push((3, 1));
                Ok((bytes.to_vec(), vec![]))
            })
            .unwrap();
        assert!(recovery.next_input().unwrap().is_none());
        recovery.begin_round().unwrap();
        recovery.seal_inputs_inner(2, 3).unwrap();
        recovery.seal_inputs_inner(3, 1).unwrap();
        assert_eq!(recovery.phase(), RecoveryPhase::Departures);
        assert_eq!(recovery.absent().unwrap(), vec![1]);
        recovery
            .commit_departures(&key, |absent, clock, histories| {
                assert_eq!(absent, &[1]);
                assert_eq!(clock, 100);
                assert!(!histories.contains_key(&1));
                Ok((
                    vec![4],
                    vec![Output {
                        recipient: 2,
                        delivery: Delivery::Reliable,
                        sequence: 2,
                        bytes: vec![8],
                    }],
                ))
            })
            .unwrap();
        assert!(recovery
            .sequencer()
            .outbox()
            .all(|o| o.output.recipient != 1));
        recovery.acknowledge_outputs(2, 2).unwrap();
        recovery.commit_delivery_acks(&key).unwrap();
        recovery.begin_round().unwrap();
        // Departure's committed effects may create another surviving-client intent.
        recovery.seal_inputs_inner(2, 4).unwrap();
        recovery.seal_inputs_inner(3, 1).unwrap();
        recovery.supply(2, 4, vec![4]).unwrap();
        recovery
            .apply_next(&key, |p, c, b, h| {
                assert_eq!(c, 100);
                assert_eq!(h[&p].handled(), 4);
                seen.push((p, 4));
                Ok((b.to_vec(), vec![]))
            })
            .unwrap();
        recovery.begin_round().unwrap();
        recovery.seal_inputs_inner(2, 4).unwrap();
        recovery.seal_inputs_inner(3, 1).unwrap();
        assert_eq!(recovery.phase(), RecoveryPhase::Ready);
        assert_eq!(recovery.sequencer().receipt().logical_ms, 100);
        assert_eq!(seen, vec![(2, 1), (2, 2), (2, 3), (3, 1), (2, 4)]);
        assert!(recovery.sequencer().outbox().next().is_none());
    }
    #[test]
    fn recovery_retries_the_exact_authority_batch_once_and_never_skips_a_persistent_fault() {
        for succeeds in [true, false] {
            let (mut recovery, _, key, _) = recovery_fixture(1, false);
            recovery.seal(250).unwrap();
            recovery.begin_round().unwrap();
            recovery.seal_inputs_inner(2, 1).unwrap();
            recovery.seal_inputs_inner(3, 0).unwrap();
            recovery.supply(2, 1, vec![42]).unwrap();
            let original = recovery.sequencer().receipt().clone();
            let mut attempts = 0;
            let result = recovery.apply_next(&key, |player, clock, bytes, histories| {
                attempts += 1;
                assert_eq!(player, 2);
                assert_eq!(clock, 100);
                assert_eq!(bytes, &[42]);
                assert_eq!(histories[&2].handled(), 1);
                if succeeds && attempts == 2 {
                    Ok((vec![42], vec![]))
                } else {
                    Err(Error::Invalid("test authority fault"))
                }
            });
            assert_eq!(attempts, 2);
            if succeeds {
                result.unwrap();
                assert_eq!(recovery.histories()[&2].handled(), 1);
            } else {
                assert!(result.is_err());
                assert_eq!(recovery.phase(), RecoveryPhase::Failed);
                assert_eq!(recovery.sequencer().receipt(), &original);
                assert_eq!(recovery.histories()[&2].handled(), 0);
                assert!(recovery.poll(251).is_err());
            }
        }
    }
    #[test]
    fn missing_recovery_journal_gap_stays_paused_and_wall_timeout_cannot_advance_game_time() {
        let (mut recovery, _, key, _) = recovery_fixture(2, false);
        recovery.seal(250).unwrap();
        recovery.begin_round().unwrap();
        recovery.seal_inputs_inner(2, 2).unwrap();
        recovery.seal_inputs_inner(3, 0).unwrap();
        recovery.supply(2, 2, vec![2]).unwrap();
        assert_eq!(recovery.next_input(), Err(Error::Gap));
        assert!(recovery.absent().is_err());
        let before = recovery.sequencer().receipt().clone();
        let mut invoked = false;
        assert!(recovery
            .apply_next(&key, |_, _, _, _| {
                invoked = true;
                Ok((vec![2], vec![]))
            })
            .is_err());
        assert!(!invoked);
        assert!(recovery.poll(5000).is_err());
        assert_eq!(recovery.phase(), RecoveryPhase::Failed);
        assert_eq!(recovery.sequencer().receipt(), &before);
    }
    #[test]
    fn recovery_application_bound_is_checked_before_another_effect_batch() {
        let (mut recovery, _, key, _) = recovery_fixture(17, false);
        recovery.seal(250).unwrap();
        recovery.begin_round().unwrap();
        recovery.seal_inputs_inner(2, 17).unwrap();
        recovery.seal_inputs_inner(3, 0).unwrap();
        for n in 1..=17 {
            recovery.supply(2, n, vec![n as u8]).unwrap();
        }
        for batch in 0..16 {
            recovery
                .apply_next(&key, |_, _, bytes, _| {
                    let outputs = (1..=255)
                        .map(|i| Output {
                            recipient: 2,
                            delivery: Delivery::Lossy,
                            sequence: batch * 255 + i,
                            bytes: vec![1],
                        })
                        .collect();
                    Ok((bytes.to_vec(), outputs))
                })
                .unwrap();
        }
        let before = recovery.sequencer().receipt().clone();
        let mut invoked = false;
        assert_eq!(
            recovery.apply_next(&key, |_, _, _, _| {
                invoked = true;
                Ok((vec![], vec![]))
            }),
            Err(Error::Bounds)
        );
        assert!(!invoked);
        assert_eq!(recovery.phase(), RecoveryPhase::Failed);
        assert_eq!(recovery.sequencer().receipt(), &before);
    }

    #[test]
    fn exact_recovery_limit_allows_empty_departures_but_blocks_real_departure_callbacks() {
        for all_survive in [true, false] {
            let (mut descriptor, host, key, player) = descriptor_fixture();
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
            let mut recovery =
                Recovery::begin(descriptor.clone(), sequencer, histories, &key, 0).unwrap();
            for (id, identity, tail) in [(1, &host, 0), (2, &player, 16)] {
                if id == 1 && !all_survive {
                    continue;
                }
                let tls = [id as u8; 32];
                let challenge = recovery
                    .challenge(id, tls, id, identity.public_key().to_bytes(), &key, 0)
                    .unwrap();
                let proof =
                    ResumeProof::sign(&descriptor.root, &challenge, tls, 0, tail, 1, identity)
                        .unwrap();
                recovery.accept(id, tls, &proof, 0).unwrap();
            }
            recovery.retain_local(3, 0, 0, 0).unwrap();
            recovery.seal(250).unwrap();
            recovery.begin_round().unwrap();
            if all_survive {
                recovery.seal_inputs_inner(1, 0).unwrap();
            }
            recovery.seal_inputs_inner(2, 16).unwrap();
            recovery.seal_inputs_inner(3, 0).unwrap();
            for n in 1..=16 {
                recovery.supply(2, n, vec![n as u8]).unwrap();
                recovery
                    .apply_next(&key, |_, _, _, _| {
                        Ok((
                            vec![n as u8],
                            (1..=255)
                                .map(|i| Output {
                                    recipient: 2,
                                    delivery: Delivery::Lossy,
                                    sequence: (n - 1) * 255 + i,
                                    bytes: vec![1],
                                })
                                .collect(),
                        ))
                    })
                    .unwrap();
            }
            recovery.begin_round().unwrap();
            if all_survive {
                recovery.seal_inputs_inner(1, 0).unwrap();
            }
            recovery.seal_inputs_inner(2, 16).unwrap();
            recovery.seal_inputs_inner(3, 0).unwrap();
            let before = recovery.sequencer().receipt().clone();
            let mut called = false;
            let result = recovery.commit_departures(&key, |_, _, _| {
                called = true;
                Ok((vec![], vec![]))
            });
            assert!(!called);
            if all_survive {
                let receipt = result.unwrap();
                assert_eq!(receipt.term, 1);
                assert_eq!(receipt.index, before.index + 1);
                assert_eq!(recovery.phase(), RecoveryPhase::Ready);
                assert_eq!(recovery.sequencer().receipt(), &receipt);
                assert_eq!(recovery.histories().len(), descriptor.root.members.len());
            } else {
                assert_eq!(result, Err(Error::Bounds));
                assert_eq!(recovery.phase(), RecoveryPhase::Failed);
                assert_eq!(recovery.sequencer().receipt(), &before);
            }
        }
    }

    #[test]
    fn zero_survivors_retire_every_player_and_drop_their_committed_outboxes() {
        let (descriptor, host, key, _) = descriptor_fixture();
        let mut root = descriptor.root;
        root.members.retain(|m| m.key.is_some());
        let mut descriptor = Descriptor::offer(root, &host).unwrap();
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
        let mut sequencer = Sequencer::arm(
            descriptor.root.context().unwrap(),
            vec![0],
            100,
            marks,
            &key,
        )
        .unwrap();
        let outputs = descriptor
            .root
            .members
            .iter()
            .map(|m| Output {
                recipient: m.player,
                delivery: Delivery::Reliable,
                sequence: 1,
                bytes: vec![1],
            })
            .collect();
        let candidate = sequencer
            .next(
                vec![1],
                100,
                sequencer.receipt().watermarks.clone(),
                outputs,
            )
            .unwrap();
        let staged = sequencer.stage(candidate).unwrap();
        sequencer.install(staged, &key).unwrap();
        let histories = descriptor
            .root
            .members
            .iter()
            .map(|m| (m.player, HandledInputs::default()))
            .collect();
        let mut recovery = Recovery::begin(descriptor, sequencer, histories, &key, 0).unwrap();
        assert!(!recovery.seal(249).unwrap());
        recovery.seal(250).unwrap();
        assert!(recovery.replay().unwrap().is_empty());
        recovery.begin_round().unwrap();
        recovery
            .commit_departures(&key, |absent, c, h| {
                assert_eq!(absent, &[1, 2]);
                assert_eq!(c, 100);
                assert!(h.is_empty());
                Ok((vec![2], vec![]))
            })
            .unwrap();
        recovery.begin_round().unwrap();
        assert_eq!(recovery.phase(), RecoveryPhase::Ready);
        assert!(recovery.histories().is_empty());
        assert!(recovery.sequencer().outbox().next().is_none());
        assert!(recovery
            .sequencer()
            .receipt()
            .watermarks
            .iter()
            .all(|m| m.retired));
    }
}

mod recovery_player;
pub use recovery_player::{PlayerRecovery, RecoveryPlayerEvent};

#[cfg(test)]
mod control_trust_tests {
    use super::*;

    /// An inbox for player 2 on term 0, plus its keys and a second valid
    /// certificate for the same membership at a later receipt.
    fn fixture() -> (Root, PlayerInbox, Keys, MembershipCertificate) {
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
            ],
            config: [11; 32],
            content: [12; 32],
            limits: ResourceLimits::default(),
        };
        let image = SessionImage::initial(&root, &[(1, 10), (2, 11)], vec![0], 1, 100).unwrap();
        let mut seq = Sequencer::arm_session(root.clone(), image.clone(), &standby).unwrap();
        let first = seq.membership_certificate(&standby).unwrap();
        let candidate = seq
            .next(
                image.encode(&root).unwrap(),
                100,
                seq.receipt().watermarks.clone(),
                vec![],
            )
            .unwrap();
        let token = seq.stage(candidate).unwrap();
        seq.install(token, &standby).unwrap();
        let second = seq.membership_certificate(&standby).unwrap();
        let inbox = PlayerInbox {
            trusted: first.digest(&root).unwrap(),
            root: root.clone(),
            membership: first,
            player: 2,
            key: player.public_key().to_bytes(),
            tls: [7; 32],
            term: 0,
            last: 0,
            recent: VecDeque::new(),
            lossy_number: 0,
            closed: false,
        };
        (root, inbox, player, second)
    }

    fn control(root: &Root, sequence: u64, keys: &Keys) -> Vec<u8> {
        let mut record = PlayerControl {
            term: 0,
            sequence,
            player: 2,
            tls: [7; 32],
            action: PlayerAction::Lossy {
                number: sequence,
                bytes: vec![1],
            },
            signature: [0; 64],
        };
        record.signature = sign(keys, record.digest(root).unwrap());
        record.encode(root).unwrap()
    }

    /// A certificate that did not pass full verification is never trusted
    /// by digest: swapping one in re-verifies it before any control.
    #[test]
    fn untrusted_certificate_digest_forces_full_verification() {
        let (root, mut inbox, player, second) = fixture();
        let outsider = Keys::generate();
        let trusted = inbox.trusted;
        assert!(inbox
            .receive(&control(&root, 1, &player))
            .unwrap()
            .is_some());
        assert_eq!(
            inbox.receive(&control(&root, 2, &outsider)),
            Err(Error::Unauthorized)
        );

        // Forged table handing seat 2 to the outsider, old standby signature.
        let genuine = inbox.membership.clone();
        let mut forged = genuine.clone();
        forged.revision += 1;
        forged.members[1].key = Some(outsider.public_key().to_bytes());
        inbox.membership = forged;
        assert_eq!(
            inbox.receive(&control(&root, 2, &outsider)),
            Err(Error::Unauthorized)
        );
        assert_eq!(inbox.trusted, trusted, "a forged digest is never cached");

        // A genuine but different certificate is verified once, then trusted.
        inbox.membership = second.clone();
        assert!(inbox
            .receive(&control(&root, 3, &player))
            .unwrap()
            .is_some());
        assert_eq!(inbox.trusted, second.digest(&root).unwrap());
    }

    /// A verified control is admitted only by the route and certificate it
    /// was authenticated against.
    #[test]
    fn verified_control_is_bound_to_its_route_and_certificate() {
        let (root, mut inbox, player, second) = fixture();
        let verified = inbox.authenticate(&control(&root, 1, &player)).unwrap();
        let mut other = inbox.clone();
        other.tls = [8; 32];
        assert_eq!(other.admit(verified), Err(Error::Unauthorized));
        let verified = inbox.authenticate(&control(&root, 1, &player)).unwrap();
        let mut moved = inbox.clone();
        moved.trusted = second.digest(&root).unwrap();
        assert_eq!(moved.admit(verified), Err(Error::Unauthorized));
        let verified = inbox.authenticate(&control(&root, 1, &player)).unwrap();
        assert!(inbox.admit(verified).unwrap().is_some());
    }
}
