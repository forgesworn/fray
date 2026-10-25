# decented-net — security notes

What the room-code rendezvous protects, what it does not, and why.

## Threat model

- **Relay observers.** Anyone who runs or watches a Nostr relay sees every
  kind-20910 offer and kind-20911 answer:
  - the `#t` room tag and the `#p` tag;
  - the signer pubkeys;
  - timestamps and ciphertext sizes;
  - the IP of every websocket client.
- **People on the same network** (shared Wi-Fi, a LAN party) can hear the LAN
  beacon and can try to sit on-path.
- **Anyone who knows the code.** Knowing the code admits you to the room, by
  design. It is a party game, and the host can kick.
- **A hostile host.** Whoever answered is not necessarily who the joiner
  meant (see below). Its messages are untrusted input to the joiner. That is
  `twang-session`'s job; this crate only proves who the host is.

Out of scope: a compromised phone, and a referee for game state (each phone is
trusted for its own field).

## Room codes (protocol v5)

- **Code space.** 6 letters from a 24-letter alphabet (`ABCDEFGHJKLMNPQRSTUVWXYZ`,
  no I, no O, no digits): 24^6 ≈ 1.9 × 10^8 codes (~27.5 bits). Codes come from
  the OS RNG, rejection-sampled (bytes 240..=255 are discarded, so every
  letter is equally likely). Typing is case-insensitive; spaces and hyphens are
  ignored.
- **Derivation.** `master = Argon2id(code, salt = "<app_tag>-room-v3:<utc_day>")`,
  with 19 MiB of memory, t=2, p=1. Three domain-separated SHA-256 sub-keys come
  from it:
  - the relay **tag**;
  - the **room key** that offers are encrypted to;
  - the **admission token**.

  See `src/room.rs`. The test vectors are cross-checked against the reference
  C implementation.
- **Midnight.** The host listens on today's and yesterday's tag, and
  re-derives at UTC midnight. A joiner offers on today's tag first, and adds
  yesterday's from the second offer round.

**What that buys.** In v1 the tag was a plain SHA-256 of the code. One cheap
pass over the code space mapped every tag ever published back to its code,
forever. Now:

- One derivation costs about 54 ms on one laptop core, so a full sweep is
  about 1.9 × 10^8 × 54 ms ≈ 120 core-days (it was about 550 with the old
  31-character alphabet: the shorter alphabet is easier to read out and type,
  and costs a sweeper about 4.6 times less).
- A sweep is good for one UTC day only (two days of tags), and must be redone
  every day.
- Argon2id is memory-hard, so GPUs and ASICs gain far less than they do
  against SHA-256.

**What it does not buy.** It is a cost floor, not a secret:

- A well-funded observer (hundreds of cores, or a GPU farm) can sweep a day's
  codes within that day. One sweep covers **every** room published that day.
- **Record now, sweep later.** A recovered code opens that day's offers, which
  reveal the joiner's candidate addresses (LAN, IPv6, STUN-reflexive, UPnP). It does
  not open answers: those are encrypted to the joiner's throwaway key.
- **Clock skew.** A joiner whose clock is more than a day off sees "no answer".
  Offers and answers more than ±120 s off the receiver's clock are dropped.

## The QUIC handshake (protocol v4)

Four frames on the connection's one stream, in this order:

1. **Hello** (joiner → host): version, join session, path and admission
   proofs. Nothing in it identifies the joiner.
2. **Welcome** (host → joiner): sent only if the hello proved admission.
   Signed by the host identity over this TLS session (checks 1 and 2 below).
3. **Identify** (joiner → host): the joiner's identity key, its signature
   (over the TLS exporter, the join session and the host key it verified) and
   any persona attestation. Sent only once the welcome verified and, for a
   code join, matched the answer and no second answerer turned up (checks 1-3).
4. **Accepted** (host → joiner): the joiner is seated. The kick deny-list and
   the seat count are checked here, once the host knows who it is.

So the host reveals nothing to a dial without the code (or LAN token), and
the joiner reveals nothing identifying to a host it has not verified
(review-net-1 N5). Before v4 the joiner's key and attestation went in the
first frame, to whoever answered the dial.

## Admission: the hello must prove the code, an invite or the LAN token

A QUIC dial is admitted only if its hello proves an **admission token**:

- **Code joins:** the code's admission sub-key, for today or yesterday.
- **Invite joins:** the invite's admission sub-key (see "Invites" below), for
  today or yesterday.
- **LAN joins:** a random 32-byte token in the LAN beacon. Being on the same
  network counts as being in the room. The token rotates whenever the room
  opens or closes, so a token heard in an earlier lobby stops working.

The token never crosses the wire. The hello carries
`sha256("decented-net-admit-v2" || token || tls_exporter)`, which is bound to
that TLS session. A fake host learns nothing it can replay.

- **No proof, no entry.** Without a valid proof the host closes the connection
  with `NOT_ADMITTED`, before sending its welcome. Knowing the IP and port is not enough, whether you are a
  kicked player, a past joiner, or a scanner hitting the UPnP-mapped port.
- **Kicks stick (best effort).** A key the host kicked is refused for the rest
  of the room's life. The refusal comes after the welcome (the host can't know
  the key earlier), so a kicked player with the code sees the host's welcome
  again, which it had already seen. A new install key gets past this, but it
  still needs the code or the LAN token. Only the host's own kicks ban
  (including twang-session's kick of a peer that sends 20 undecodable
  messages; the net layer's `FLOOD` close does not ban): a joiner refused because the room was full, the match had
  started or its version differed, or one that sat on the confirm screen too
  long (`CONFIRM_TIMEOUT`), is only disconnected and may come back.
- **A disconnect may carry a reason.** `disconnect_with_reason` sends a short
  text in the close frame; the client shows it to the player as
  `DisconnectReason::KickedWith`. The text comes from the host, so the client
  treats it as untrusted: it must be valid UTF-8, has control, bidi and
  invisible characters removed, and is cut to 200 bytes. An older client reads
  the same close as plain `Kicked`. Close text on every other path (the error
  strings for a close with an unrecognised code or a transport-level close, on
  clients and hosts alike) goes through the same cleaner before a game sees it.

## Invites (code-room hosts)

A host can admit people by **invite** as well as by its room code. An invite is
a 32-byte secret from the OS RNG that the host hands out in a link, with its
own public key. `HostHandle::add_invite` / `remove_invite` manage them (at most
256 live at once); `join_invite` is the joiner's side.

- **Derivation.** `master = sha256("<app_tag>-invite-v1:" || utc_day || ":" ||
  secret)`, then the same three sub-keys as a code (relay tag, room keypair,
  admission token). No KDF: the secret already has 256 bits, so there is
  nothing to sweep. A code's master is an Argon2id output and an invite's a
  labelled sha256, so the two can never yield each other's tag, key or token.
  The invite's id (`InviteId`, 16 bytes) is `sha256("decented-net/invite-v1/id\0"
  || secret)` truncated: it names the invite to the app and reveals nothing of it.
- **No address in the link.** The link holds the secret and the host's key.
  The joiner finds the host through the same encrypted offer/answer exchange as
  a code join, on relay tags that change every UTC day (today and yesterday are
  both listened on, as for codes). A relay observer cannot map a tag to an
  invite, because it would have to guess 256 bits. What it can and cannot
  link, and what the relay serving the host can, is under "Privacy" below.
- **Revoking.** `remove_invite` strips the invite's tokens at once, so a hello
  proving them gets `NOT_ADMITTED` before any welcome, a handshake already
  under way is refused again when the peer would be seated, and the host stops
  answering offers on its tags. A revoked invite learns nothing: no answer, no
  welcome. Connections it already admitted stay: Fray does not drop them, the
  game decides (`kick`).
- **The host is pinned.** A joiner by invite joins only a host whose key is the
  one in the link. An answer (a refusal included) that names another key is
  ignored, as if it had not arrived: the joiner keeps waiting for the real
  host's answer until the normal timeout (`NoAnswer`), and never punches or
  dials towards the other. The welcome must be signed by the pinned key too
  (`HostUnverified`). Someone who obtains the secret cannot pass as the host
  or be admitted anywhere the invite is not, but can disrupt that invite's
  joins: a forged answer that names the pinned host (which anyone can read
  from the link) and points elsewhere fails the join closed
  (`HostUnverified`, `HostConflict` or a refusal). The fix for a leaked
  secret is to revoke it.
- **What a leaked link gives.** Whoever holds a live invite can ask the host to
  answer and can prove admission (the same as a code, only stronger because it
  cannot be guessed), so treat it as a bearer ticket: a host that wants it to
  work once should revoke it after use. The host reports which invite admitted
  each peer (`Admission::Invite(id)`) so the app can do that.
- **Limits.** All live invites share the host's one standing relay
  subscription, which then names two tags per invite (up to 514 values at
  the cap); a relay that caps the values of a tag filter would drop some. Invites
  need relays, like the code; a virtual-link host refuses them.

## Privacy: identity keys never reach relays

Each install's identity key is long-lived. If it signed relay events, a relay
operator could log which installs play together, when, and from which IP. So:

- Each **join attempt** signs its offer with a fresh **throwaway key**, and
  receives its answer (`#p`) on that key.
- Each **join session** (one offer, however often it is re-sent) gets its
  answer signed by a throwaway key made for that session alone: never the
  host's identity, and never a key shared with another joiner, invite, the
  code or day. The host names that key in the welcome (inside QUIC), which is
  how the joiner knows the answer and the host are the same party.
- The identity keys appear **only inside encrypted payloads**: the joiner's
  identify frame and the host's welcome inside QUIC (both signed over the TLS
  exporter), and the host's key inside the answer's NIP-44 ciphertext, which
  only the joiner's throwaway key can open (check 2 below).
- **The joiner names itself only to a verified host.** Whoever terminates the
  joiner's dial (an on-path box, a squatter on the host's LAN address, a LAN
  beacon spoofer) gets the hello: a session id, a path and admission proofs
  bound to that TLS session. It does not get the joiner's identity key or its
  attestation unless its welcome verifies:
  - **Code joins:** the welcome must be signed by the identity the encrypted
    answer named, and name the answer's relay key (check 2). Only the host
    that answered (or someone with its identity secret) gets the joiner's key.
  - **LAN joins:** there is no answer to bind to, and the beacon is plaintext.
    The joiner can only check that the welcome is signed over *this* TLS
    session (not forwarded from another). A party with **any** key that
    terminates the dial (a beacon spoofer heard first, or a box answering for
    the beacon's address) passes that check and learns the joiner's identity.
    On the LAN the confirm screen ("Join <name>?") is the backstop, as it is
    for admission (see Residual risk).

A relay observer can still see the room tag, that some keys exchanged an offer
and an answer, and the websocket IPs. It cannot link those keys to an install,
or one session to the next.

What an observer can and cannot link across rooms (the code and each invite):

- **Cannot link by author.** Every answer has its own signing key, so two
  answers, whether to the same room, to two invites, to the code or on two
  days, carry no common key that says one host sent them. A room's tag is
  derived from a 256-bit secret (an invite) or an Argon2id output (the code)
  and changes every UTC day, so a tag does not name its room to someone
  without the secret, and today's tag does not lead to yesterday's.
- **Can still see, per tag:** each offer on that tag and when, and each answer
  p-tagged to that offer's throwaway key, so the number and timing of joins
  per tag (per invite, so per link you handed out) are visible, as are
  that a host is online and answering at all.
- **The relay that serves the host's connection links all of its tags.** A
  host holds one standing subscription per relay, one REQ over one websocket
  naming every tag it listens on (two per room, today's and yesterday's: up to
  514 with the code and 256 invites). That relay's operator therefore sees,
  from one connection and IP, that all those tags belong to one host,
  and links the answers that follow them to it by arrival, even though the
  answers carry unrelated keys. Fray cannot avoid this without a separate
  connection per invite. A host that must not show this to a relay should not
  list that relay.
- **A holder of a live invite** learns nothing about other rooms from it: it
  can derive that invite's own tags and nothing else's, and the answers it
  receives are signed by keys that are not reused for anyone else. That holds for this crate's own events; once
decented-signet publishes an attestation for the runtime key, that key itself
is public and persona-linked (see "The runtime key is linked to the persona").

## Who is the host? (the forged-answer race)

Someone who recovered a code while the room is open could answer a joiner's
offer first, with their own addresses. The joiner checks:

1. **Signed welcome.** The host's first QUIC message is signed by its identity
   key over all of these:
   - the TLS exporter;
   - the join session id;
   - the peer id;
   - the display name;
   - the host's **relay key** (the throwaway key that signed the answer to
     this join session);
   - any persona attestation.

   No man in the middle can relay or replay it: each leg of a MITM has a
   different exporter.
2. **The answer names the host; the host must sign the welcome.** For a code
   join, the answer carries the host's identity key *inside* its NIP-44
   ciphertext (encrypted to the joiner's throwaway key, so relays never see
   it). The welcome must be signed by exactly that identity, and must name the
   relay key that signed the answer. Otherwise the joiner refuses
   (`HostUnverified`), as it does when an accepted answer names no valid key.

   Why the identity and not just the relay key: the relay key is public (it
   signs the answer on the relay), so anyone could *name* it in a welcome
   signed by their own identity. Before protocol v3 that was the only check,
   and an on-path box without the code (say, a device on the joiner's Wi-Fi
   answering ARP for the host's LAN candidate) could pose as the host
   (review-net-1 N1). Now it would also need the host identity's secret key.

   What this prevents: anyone **without the code**, whether on-path or racing
   on the relay, can't make the joiner accept them as the host. They can't
   read the answer, so they can't learn or change the identity it names, and
   they can't sign as that identity.

   **Each candidate is checked on its own** (review-net-1 N4). The joiner
   dials every candidate in the answer (LAN, IPv6, UPnP, STUN-reflexive),
   staggered, and each dial must produce a welcome that passes checks 1 and 2.
   A candidate whose welcome fails, or that refuses (an unrelated host at the
   same private address says `NOT_ADMITTED`), is dropped and the others keep
   racing. The join fails only if no candidate yields a verified host within
   the 8 s connect budget, with `HostUnverified` if any candidate sent an
   unverifiable welcome. The losing connections are closed before the
   identify frame goes out, so a host reached on two paths sees one join, and
   a squatter can no longer block a join the real host could have served.

   What it does not prevent:
   - Someone **with the code** can answer as themselves, naming their own
     identity. Check 3 catches them if the real host also answers; if the real
     host never sees the offer, the joiner meets the impostor. The confirm
     screen ("Join <name>?", with the key's npub prefix) is the backstop.
   - An on-path box still learns the joiner's admission proof for that one
     connection (but not who the joiner is: see Privacy). It is bound to that
     TLS session (useless to replay); it only allows an offline test of
     guessed codes, at the Argon2id cost of sweeping the public room tag (see
     Admission above).
3. **Any second answerer fails closed.** The joiner keeps listening through
   connect and handshake, and for at least 600 ms after the first answer. If a
   valid answer to its session arrives from any other key, it refuses
   (`HostConflict`). This check is **time-boxed**: a second answer that
   arrives more than ~600 ms after the first (a slow phone host far from the
   relays, behind an impostor that answered first) is not seen, and the
   confirm screen is then the only defence.
4. **Junk can't hide the real answer.** The relay receive queue is bounded
   (256 events). Before an event takes a slot, the relay worker:
   - drops duplicates (the same event arriving from several relays);
   - caps each author at 16 events per 10 s;
   - verifies the signature;
   - runs a **pre-queue check**: for a joiner, the answer must decrypt and
     match its session; for a host, the offer must open with a current room
     key.

   So undecryptable junk never takes a slot. An attacker who can make valid
   answers (it has the code) is a second answerer, caught by check 3. If the
   queue ever overflows anyway, the joiner fails closed.

Before the lobby, the app gets the host's name and identity key from the
verified welcome (`ClientEvent::Connected`). It can then ask "Join <name>'s
game?" and let the user back out.

## Virtual links (Bluetooth)

`host_virtual` / `join_virtual` run the same QUIC transport over any
point-to-point packet link (`src/virt.rs`); the app uses Bluetooth LE L2CAP.
Everything from the hello on is the LAN path unchanged: admission proof,
signed welcome, identify, attestation, the confirm step and kicks.

- **Admission: in radio range = may knock.** It mirrors the LAN beacon
  ("same network = in the room"). The host does not advertise the token. It
  sends the room's current LAN token as the **first packet on each link**
  (the pre-frame: tag `0x01` + 32 bytes). The joiner then proves that token
  in its hello, exactly as a LAN joiner proves the beacon's. The token rotates
  when the room opens or closes, so a pre-frame from an earlier lobby stops
  working. Anyone in radio range who opens a link gets the token, as anyone on
  the Wi-Fi hears the beacon. So the host must explicitly accept
  each Bluetooth joiner (the app's Accept prompt): strangers are in range on
  a plane. The door is **off by default**: the host turns Bluetooth on in the
  lobby (the choice is remembered per device) and can turn it off at any
  time, which stops advertising and drops everyone still waiting; players
  already seated through it keep playing.
- **What a knock returns, and the persona.** A valid hello gets the welcome
  (while the room is open and has a seat): the host's identity key and a
  room name. The app gives the Bluetooth door a **neutral room name**, "Bluetooth
  game · room 1A2B" (the id the advert already shows), never the host's own
  display name; that reaches a joiner only after Accept, in the lobby. The
  welcome still proves the host's identity key, which is linked to the
  persona if the host has chosen "Let contacts invite me" (that key is then
  published and names the persona): a stranger in range who already knows
  that link can tell whose game it is. A per-room ephemeral transport key
  would close that; it is a design question, accepted for now. On virtual
  links the welcome **withholds the host's persona attestation** (`NetConfig::withhold_host_attestation`, default on for
  `host_virtual`, off for LAN and code joins), so a stranger in range does not
  learn who the host is. The persona reaches a joiner only once the host has
  accepted it (the session layer's `Persona` message and presence, after
  seating). The joiner's own attestation still goes to the host in its
  identify: the joiner chose this host by connecting, as on LAN.
- **Framing is strict.** After the pre-frame, every packet is tag `0x02` + one
  QUIC datagram. A joiner whose first packet is not a well-formed pre-frame
  fails with `NotAdmitted`. A host drops any link that sends anything before
  QUIC. Either side drops a link on any later non-QUIC packet (a second
  pre-frame, an unknown tag, an empty or oversized packet).
- **Encryption.** BLE L2CAP "insecure" channels are not encrypted or
  authenticated at the link layer, so the pre-frame token is visible to a
  radio sniffer in range. That gives a sniffer what any device in range gets
  anyway: the right to knock. Everything after the pre-frame is QUIC (TLS
  1.3), encrypted and bound to the session. The admission proof is bound to
  the TLS exporter and cannot be replayed, and identities are proven in the
  signed welcome and identify.
- **Knockers can occupy pending slots (accepted, low).** A Bluetooth peer
  that has connected is a seated peer at this layer, and the session layer
  holds it as pending until the host accepts: up to 30 s to say Hello, then up
  to 60 s for the host's Accept, so about 90 s per knock. Seven knockers that
  say Hello and are never answered fill the Bluetooth door's seven peer slots
  for that long, friends in range get "full" meanwhile, and the host's lobby
  shows their prompts. A timed-out knocker is not banned and can knock again
  at once. The LAN/WAN door is a separate host and is unaffected, and so are
  seated players. The remedy is the host's: turn Bluetooth off, which drops
  every waiting knocker and stops advertising. A decline bans that runtime
  key at the door it came through only (a new Bluetooth door starts with an
  empty ban list).
- **No migration.** The host turns QUIC connection migration off: a link is
  one fixed peer, and connection ids travel in clear over BLE, so a packet
  diverted onto another link is discarded rather than taken as a move.
- **Link lifetime.** A link that has not started QUIC within 10 s of its
  pre-frame is dropped. A link whose connection is over (left, kicked,
  refused, failed) is dropped a second later, once the close has gone out.
  A link closed in either direction is dropped (a closed receive side at
  once, a closed send side within half a second). Dropping a link closes its
  channels, so the bridge can close the L2CAP socket.
- **Bounds.** A host holds at most 32 links at once. When full, a new link
  displaces the oldest one that never started QUIC (a flood of silent links
  cannot lock joiners out); if every link has started QUIC, the newcomer is
  dropped. QUIC runs at a pinned 1200-byte MTU with path MTU discovery off, so
  a link packet is never over 1201 bytes (the limit is 1452). A full link
  drops packets as UDP would, and QUIC recovers. A link that closes is
  forgotten: its address becomes unreachable and the idle timeout ends the
  connection.

## IPv6 addresses (dual-stack, W3)

The QUIC sockets are dual-stack (`[::]` with `IPV6_V6ONLY` off; plain
`0.0.0.0` if that bind fails), so both sides also offer global IPv6 addresses.
Mobile carriers put IPv4 behind carrier NAT but give each phone a global IPv6
address, so this is often the only path that works phone to phone.

- **Who sees them.** Exactly who sees the public IPv4 today: the addresses
  travel only inside the NIP-44 offer (readable by anyone holding the code, or
  who sweeps it) and the answer (readable only by that joiner). Relays never see
  them. Every handshake, admission and verification rule is unchanged; the
  address is a place to dial, never a credential.
- **What a v6 address says.** Unlike a carrier-NAT IPv4 shared by thousands, a
  global IPv6 address is this device's own. Its top 64 bits name the home or
  the cell network; the bottom 64 bits can name the device:
  - a **MAC-derived (EUI-64)** address names the network card on every network
    it joins. These are **never offered**;
  - a **stable** address (RFC 7217) is fixed for as long as the device stays on
    that network, so it links one session to the next;
  - a **temporary** address (RFC 8981, privacy extensions) rotates about daily.
- **The choice.** The first IPv6 candidate is the address the kernel sources
  traffic from (the routing trick in `local_outbound_v6`), so the OS's own
  privacy policy decides between stable and temporary. That is deliberate: our
  punches and dials leave from that address, and a stateful IPv6 firewall
  (every carrier, most home routers) opens its pinhole for that address only.
  Offering a different (stable) address would hand the peer an address with no
  hole in front of it. Android, and Linux with `use_tempaddr = 2`, source from
  the **temporary** address, the more private choice. **No other interface
  address is offered** (review-ipv6-1 I2): a stable sibling in the same /64, a
  deprecated temporary, another network's address (cellular while playing over
  Wi-Fi) or the real ISP address under a VPN would buy no connectivity and leak
  a linkable or off-route address.
- **Re-read per answer.** The host re-reads the source address for every answer
  it sends (one `connect()` syscall, no packet), so a temporary address that
  rotated during a long room is not advertised stale (I3).
- **One filter for every source.** Link-local, unique-local, Teredo, 6to4,
  documentation and MAC-derived addresses are never offered, whether learned
  from the routing table or reflected back by STUN (I1).
- **STUN over IPv6.** The STUN servers are also asked over IPv6 where they have
  an AAAA record. Without NAT66 the answer is the same address and adds nothing;
  with NAT66 or a tunnel it is the address the outside sees.
- **The LAN beacon is unchanged** (IPv4 broadcast). A LAN join reaches the
  dual-stack socket as a v4-mapped address.

## Bounded resources

- **Message sizes.** App messages are capped at 1 KiB (`MAX_RELIABLE_LEN`)
  unless the app sets `NetConfig::max_reliable_len` (1 KiB to 1 MiB, the same
  on both ends: there is no negotiation); a bigger frame ends the connection.
  The handshake keeps its own caps whatever the app sets (2 KiB for the hello,
  8 KiB for the rest), so a stranger cannot send a large frame before
  admission. Datagrams are capped at 1 KiB. Host migration needs the default
  size and refuses a raised one.
- **Queues.** The host's app may have at most 256 reliable messages (and
  256 KiB) from one peer waiting in `poll`; the client allows 1024 (and 1 MiB).
  One more of either disconnects that peer (`FLOOD`). `NetConfig::host_inbound`
  and `client_inbound` change the bounds. A link with more than 1 MiB queued to
  send (`NetConfig::outbound_queue_bytes`) is closed as too slow. Datagrams over
  the per-peer cap are dropped. One flooding peer cannot starve or bloat the
  others.
- **Punches.** The host sends hole-punch packets only to:
  - `lan` candidates inside one of its own IPv4 subnets;
  - otherwise, globally routable IPv4 addresses, or global unicast IPv6
    (2000::/3 minus Teredo, 6to4, documentation and the other special blocks).
    A v4-mapped spelling (`::ffff:10.0.0.5`) is judged as the IPv4 it is.

  It never punches ports below 1024, and at most 4 IPv4 plus 2 IPv6 targets
  per offer. It
  answers at most 16 new join sessions per 10 s, and an offer's session id
  must be 32 hex characters. So the host can't be turned into a packet sprayer
  inside its own network or at third parties.
- **The joiner's punches and dials** (review-ipv6-1 I4). The answer's
  addresses were chosen by whoever answered the code first, so the joiner
  drops, before punching or dialling: ports below 1024; multicast, broadcast,
  unspecified, link-local, documentation and reserved addresses in either
  family; and private, carrier-NAT, unique-local and loopback addresses unless
  they came as `lan` candidates (same house or same machine). At most 8 remain.
- **Relay websockets.** Messages are capped at 64 KiB, and every send times
  out after 3 s, so one stalled relay can't wedge the others. The UPnP mapping
  is renewed while the host runs.
- **Panics.** The host task, each peer task, the client task and the relay
  worker each run under a catch-unwind backstop. If anything ever panics, the
  peers are closed and told, rather than left connected to a dead room. Remote
  input is validated so this should never trigger.

## Residual risk

- **A fast sweeper whose answer is the only one seen.** The sweeper signs both
  its answer and its welcome itself, so checks 1 and 2 pass. Check 3 catches
  it whenever the real host's answer reaches the joiner in time. That fails
  only if every relay the joiner uses drops or delays the real answer (relay
  operators' cooperation, or a host that went offline).
  - The last line of defence is the confirm screen: a key prefix shown next to
    the self-chosen name.
  - A 40-bit prefix (8 bech32 characters) can be ground by a determined
    attacker who knows the host's key.
  - The host's key no longer appears on relays, but it does appear inside
    every QUIC session it hosts.
- **Denial of service by anyone with the code.** They can:
  - make joins fail, with a second answer, a fake "room full" answer, or more
    valid answers than the queue holds;
  - take seats until the host kicks them;
  - use up the host's new-session budget.
- **LAN access is room access.** The beacon is plaintext: anyone on the local
  network sees the code, the room name and the LAN token, and can join.
  - The first address heard for a code keeps it until it goes quiet. A spoofer
    can't take over a live room's entry, but can if it is heard first.
  - Even then, the welcome still proves the host's key.
  - Such a spoofer (or a box answering for the beacon's address) also learns
    the joiner's identity key and attestation: a LAN join has nothing to check
    the welcome's key against (see Privacy).
- **Joiner identity is a self-made key.** The host learns a proven key per
  joiner, but nothing ties it to a person. A persona attestation (below) will
  change that.
- **IPv6 candidates are not used.** The socket is IPv4-only in v1.

## Persona attestation (carried, verified by the app)

`Identity::with_attestation` attaches an opaque attestation for the install's
runtime key (for example a signed My Signet persona event, kind 30420).

- It rides in the joiner's identify frame and the host's welcome, covered by
  the connection-bound signature, capped at 2 KiB. The joiner's goes only to
  a verified host (see Privacy).
- It is handed to the app as is: the joiner's on `HostEvent::PeerJoined`, the
  host's on `ClientEvent::Connected`, each next to the key that proved this
  connection. This crate does **not** verify it. The app must check that it
  is a valid persona attestation **of that proven key** before showing or
  trusting a persona (Twang Thang does, with `decented_signet::verify_attestation`).
- The signature only shows the key holder chose to send it. An attestation
  names its runtime key, so one copied from another install fails the app's
  check against the proven key.
- **Beyond the host link.** Other players' personas reach a joiner through the
  host (twang-session relays each seated player's key and attestation). The
  joiner verifies each attestation against the key the host names for that
  seat, so the host cannot invent or alter a persona. It *can* name a key and
  a genuine attestation for someone who is not in the room: attestations are
  public once "Let contacts invite me" publishes them, and nothing proves the
  seat's holder has that key. The host's own seat is pinned to the key that
  signed the welcome only when the host names its seat (`host_slot`, which
  it writes itself); the confirm screen is the real check on who the host
  is. Closing this needs each player to sign something bound to the lobby
  with its runtime key; not done in v1.

## The runtime key is linked to the persona (accepted for v1)

The install's identity key here (`Identity::keys()`, the "runtime key") is the
same key decented-signet attests. Once the app wires signet in:

- **What is linked.** When "Let contacts invite me" is on, signet publishes a
  kind-30420 attestation on Nostr relays: signed by the persona, `p`-tagging
  the runtime key. Signet also subscribes to gift-wraps addressed (`#p`) to
  the runtime key. So the runtime key becomes a public key tied to the
  persona, and anyone who sees that key in a QUIC session can name the
  persona behind it.
- **Why that is acceptable for v1.** The runtime key appears nowhere else in
  public: every relay-facing rendezvous event is signed by a throwaway key
  (see Privacy), and the host's key travels only inside the encrypted answer.
  On the wire it appears only inside QUIC, and since v4 the joiner sends it
  only to a host it has verified (a code join's answered host, or on the LAN,
  whoever holds the beacon's address: see Privacy). Being findable by
  contacts is the point of the setting. It is on by default ("Let contacts
  invite me") and can be turned off at any time, which withdraws the
  attestation.
- **Rotation.** Signing out must rotate the runtime key (a new install
  identity), which ends the link for future sessions; a stale attestation
  then names a key that no longer plays. This is the app's and signet's
  contract to keep, not something this crate enforces.

If a later version needs the network key unlinkable from the persona, signet
must attest a separate key and this crate keeps its own.

## Version separation

`NET_PROTOCOL_VERSION = 5` flows into the QUIC ALPN (`<app_tag>/dnet5`), the
hello and welcome, the offer and answer `v`, and the LAN beacon filter. v1
builds use different tags and a different ALPN, so they never half-match a
later build. v2, v3 and v4 share the room derivation (the `room-v2` labels),
so a mix finds each other on the relay and is refused as "version"; v3 added
the host identity to the answer (check 2); v4 split the handshake so the
joiner's identity follows the verified welcome. v5 changed the room
derivation itself (6-letter codes from a 24-letter alphabet, salt `room-v3`):
a v5 build and an older one derive different tags and never find each other
on the relays, and the new ALPN and beacon filter keep them apart on the LAN.
