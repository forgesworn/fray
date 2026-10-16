# Migration v1 implementation draft

The `migration` module implements a fixed original host and one explicitly
selected, consenting standby. The standby commits complete authority state and
reliable outputs before the original can publish them. Promotion closes the old
term once; the successor continues that same committed history. There is one
automatic takeover. Loss of the standby, retained state or a resource bound
pauses the armed session.

This is an implementation draft. The game adapters and focused transport tests
exist. Complete app activation, admission/discovery, actual game process-kill
acceptance, updated-phone acceptance and final implementation review remain
outstanding. These APIs do not yet establish a complete migration result.

## Consent and lobby activation

`Descriptor::offer` signs the immutable root with the original runtime identity.
The selected device must explicitly accept complete hidden gameplay state before
calling `Descriptor::consent`. Decode checks the original offer signature;
`Descriptor::verify` also requires the selected standby's consent. Never send an
authority checkpoint while that full verification fails. Roster clients receive
public membership and receipts, not complete game or bot state.

The owning game first enters a frozen, fail-closed lobby barrier. It drains or
captures ordinary ordered effects and freezes roster/configuration changes.
`ActivationSource` sends its exact initial `SessionImage` over the already
verified Original-to-Standby channel. Each human signs a `CapabilityAck` for the
same root and initial state hash. Bots do not vote. The source forwards these
signatures; it cannot sign on another player's behalf.

`ActivationSink` waits for the complete image and every human acknowledgement.
Its consuming `arm` operation runs fresh native restore validation, allowing one
retry, installs commit0 and queues the standby's signed `Armed`. The source checks
the exact initial hash, logical clock and complete acknowledgement set before
returning a `Primary`. Both halves move their existing `Channel` into the
replication actors. Do not rebuild framing or reset transfer counters at that
handoff. Arming has a monotone five-second deadline and no ordinary-mode fallback.

The game must keep all ordinary game, UI and loopback effects frozen until that
barrier completes. The Fray activation actors cannot freeze an external game
object themselves.

## Normal inputs and publication

`PrimaryActor` and `StandbyActor` own the replication/publication boundary. Stage
on a private complete native copy, including local/bot clients, RNG and pending
logical traffic. A restore callback must use a fresh instance and publish no
effects. Only the exact accepted receipt permits adoption and publication.
Persistent restore failure or an adoption error/panic pauses the actor.

`PlayerEndpoint` owns the normal client's retained input/delivery journals and
shared sender allocator, bound to the actual local Identify key and remote
authority. Certified outputs go through the native client's complete private
transaction. Verified committed input ACKs free journal capacity before generated
followups; adoption occurs only after successful application. Application errors
and panics latch the endpoint, including a callback returning `RateLimited`.
Only an unconsumed physical ingress frame may be retried for rate pressure.

`Primary::attach_player` and `PrimaryActor::attach_player` grant each initial
human one normal route. The claim belongs to the initial authority and survives
queue drop. There is no public `PlayerQueue` constructor which can recreate an
active route. New membership admission requires its own committed extension;
initial attachment is not an admission API.

A `PlayerQueue` verifies the actual authenticated channel identity and signed
`PlayerControl` records. It retains contiguous original input IDs and exact bytes
until an installed receipt commits that prefix. Capacity refusal consumes neither
the original ID nor the signed control cursor. A known ID with different bytes
faults the queue. Delivery ACKs remain speculative until a later commit includes
them; only that commit can prune reliable output proofs.

Lossy views are kept as a bounded, number-ordered list per player, not just the
newest. Each signed view is delivered as its own `Lossy` input, in the order the
plain host would process the datagrams, so a burst within one batch loses no
press. Views at or below the newest received number are still dropped as stale or
duplicate. The list holds `MAX_LOSSY_VIEWS` (256 = `MAX_JOURNAL_BYTES` / the
1024-byte payload cap, so the same per-player memory as the original journal).
Overflow drops the oldest view; it never pauses intake or touches a reliable
original. Adopting a batch discards its selected view and any older one.

The games' queued-batch adapters select bounded fair prefixes across humans,
bots and lossy views. Reading a batch does not drain journals. They stage native
operations privately and reduce the selected prefix if native reply expansion
would exceed a complete candidate's bounds. Local UI mutations must use the same
journal and publication boundary as remote commands.

## Replacement connections and recovery

After cohort sealing, typed recovery enters the mandatory `Security` phase.
`Recovery::revalidate_security` validates the game's exact installed native
checkpoint, then installs one explicit security-only transition before replay or
journal drain. The callback runs on fresh private native state, has one retry and
may emit no output. C, membership, configuration, histories, watermarks and the
retained outbox remain unchanged. The transaction consumes one application in
the existing recovery budget and retains the original deadline.

`SessionImage::security_boundary` records the canonical final term-0 receipt
digest and each survivor's original retained input tail. It is absent in initial
and term-0 images, added only in the first term-1 commit and immutable thereafter.
Its canonical option follows `next_player`: byte 0, or byte 1, 32-byte fence hash,
bounded u32 count and sorted u64 player/tail pairs. The context binds the root.
Preflight checks aggregate image/outbox/metadata capacity before native code.
Later drain rounds cannot move the old-security-intent cutoff.

The native adapter expires uncertain maximum lifetimes and restarts only
minimum-delay windows conservatively. Actual UTC checks remain external. Twang
keeps real human nonce/signing/freeze clocks, invalidates live old-host proofs on
an authenticated root-bound handoff, and retains frozen seat-key pins separately
from expired bot display claims. Retained pre-boundary security intents become
stale without new trust or artificial strikes. This may leave identity badges
unverified until Results; seated gameplay continues. Normal armed batches also
require explicit real security time independently of their logical clock.

A matching runtime key and transport handshake do not prove retained client
state. Normal TLS replacement uses `PlayerQueue::begin_reconnect`, then the
retained `PlayerEndpoint::reconnect`, followed by the queue's `finish_reconnect`.
The endpoint signs its actual retained input/delivery cuts, queues the proof
before swapping channels and resends remaining originals with unchanged IDs.
The signed cut binds the fresh
TLS exporter, random nonce, stable player and issued committed frontier. Ordinary
commits may advance while the reply travels; the queue checks the owned continuing
history and current retained input/output cuts. Expired or replaced challenges,
missing journals and reused conflicting control IDs cannot reopen the route.

Keep the complete native client object across this change. Preserve its journals,
control sender sequence, latest-view floor and controller state. Fresh physical
framing belongs to the new TLS connection; original game input IDs do not restart.

After promotion, `Recovery` reconciles surviving journals at frozen logical time.
Absent-player departures happen after retained survivor tails. `RecoveryBarrier`
requires final TLS-bound cuts and bounded clock adjustments before returning the
owned `SuccessorActor`. Its one-use warm attachment moves the retained channel
and inbox, preserving framing/control replay history. A public `Resume` object
alone does not grant an attachment or recreate an authority.

`PlayerEndpoint::into_recovery` consumes its existing journals and a bound warm
channel. The original authority may pass its already fenced owned channel; the
exact promotion certificate is retained and checked without promoting twice.
`PlayerRecovery` answers challenges and fresh input rounds from those actual
journals, caches exact signed replies and streams the bounded original tail under
the same pacing limit. `Recovery::accept_player_control` authenticates the
accepted player's TLS, committed roster, sender ID and original payload history.

After the final clock cut, `confirm_clock` preflights its reply before invoking
the game's one-shot native rebase. A replacement nonce for the same final frontier
reuses the validated clock adjustment and unchanged journals. Larger-than-250 ms
corrections, callback faults and the original five-second deadline pause the
client. Only verified `Resume` permits `into_endpoint`; framing, sender IDs,
input/output/view cursors and the native client retained by the runner continue.
Queued obsolete recovery controls are retired without resetting pacing or
truncating a partly sent envelope. The returned warm endpoint can subsequently
prove retained state on a fresh Player-to-Successor TLS connection.

Simulation time and authentication freshness are separate. The standby retains
security age from the last received checkpoint which advanced the game clock;
ACK-only commits and pulses do not refresh that anchor. The game runner must also
supply its actual activation clock mapping and normal commit-wait security age.
It must keep pumping network/security work while simulation is frozen.

## Framing and ingress

Every physical session frame is at most 1024 bytes, with at most 768 payload
bytes. Packet classes are Candidate, Receipt, Output, Control, InitialImage and
Delta.
InitialImage is accepted only in term0 on the consented Original-to-Standby link;
it is ordinary paced transfer traffic, not priority control traffic. Control
roster links cannot request or receive it.

The `BytePatch`/`CandidateDelta` path uses bounded immutable-base
copy runs and literal insert runs. Its complete encoding is at most 64 KiB with
4,096 operations; the materialized target remains at most 1 MiB. Root/schema/
term/frontier/base checks precede reconstruction; exact target hashing and fresh
native validation precede installation. Identical installed delta retries return
the existing receipt without native replay or liveness refresh. Full candidates
replace deltas at the 250 ms advancing logical-time boundary. The owner approved this replacement for the single-span draft before the
unreleased migration session v1 is finalized. Complete implementation acceptance
and public conformance vectors remain outstanding.

The pair uses a 4 MiB/s rate with a 64 KiB burst. QUIC can deliver several paced
sends together in one app poll. `Error::RateLimited` means the physical frame was
not consumed. Use `ReceiveQueue` to defer it in order and retry at a later real
monotonic time. The queue holds at most 2 MiB and 4096 frames, each at most 1024
bytes. It retains the head only for `RateLimited`; any other returned result
consumes that physical frame and propagates errors. Sustained pressure reaches a
bound and pauses rather than discarding reliable traffic.

Deferred ingress does not renew a started transfer's 500 ms deadline. As with
`Channel` itself, that transfer deadline starts when its first chunk is accepted.
Activation and recovery retain their separate five-second deadlines. Do not pass
a cached receive timestamp when retrying queued frames.

Move the retained receive queue together with its channel when activation
hands off to normal actors. Bytes already accepted from the transport remain
ordered even when the per-poll work limit or ingress rate defers their parsing.
The normal actors authenticate archived capability/Armed retries against the
shared replay ledger. Exact remembered retries are no-ops; new activation IDs
are refused and remembered contradictions fault the shared session. These
retries do not restore native state or refresh authority liveness.

Poll `ActivationSink::poll` during quiet setup frames, so missing traffic does
not suspend reassembly or the original arming deadline. Native initial restore
wall time counts against that same five-second deadline; it also cannot extend
an already-started partial transfer. The source checks reassembly expiry before
its normal-channel handoff. The game still enforces its actual credential
expiry around every image/readiness release and after native restore.

The final wire inventory and conformance vectors require completed runtime
integration and review. Transport v7 is independent of package version; the game
integrations also require their explicit protocol-version changes.
