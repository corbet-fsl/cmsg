# Operational tuning

cmsg accepts prospective settings through typed calls. An embedding can reload
its own settings and pass a captured version to the next operation; cmsg has no
process-wide configuration loader or live mutation of existing signed policy.
Timestamps below are absolute UTC seconds, integers in `1..=2^53-1`.

## Existing controls

| Setting and source API | Valid range | When a change takes effect |
| --- | --- | --- |
| `FirstContactPolicy.response_deadline`, `.max_intro_bytes`; `Inbox::begin_first_contact`, browser `beginFirstContact` | Future deadline; introduction size `1..=65536` bytes. Text also has the 16384-byte text limit. | A new introduction or explicit owner-authorized fresh contact. Re-registering an existing nonce cannot change its policy. |
| `ReservationPolicy.opened_at`, `.abandon_after`, `.state_policy_digest`; `require_active_reservations` / `requireActiveReservations` | Nonzero pinned stable state-policy digest; `opened_at <= now`; duration greater than zero; original sum greater than now and at most `2^53-1`. | A new accounted introduction. Existing gate policy and explicit `expiresAt` are immutable; changing operator defaults cannot restart its deadline. An incoming gate copies the authenticated outgoing expiry, not a reloaded waiting default. cfrm owns admission counts, capacity/refill amounts and accounting policy selection. |
| `Inbox::begin_live_session(..., until, ...)`, browser `beginLiveSession`, `LiveInboxStream.open({until,...})` | `until > now`, at most `2^53-1`. Actual transmission also requires current device authority and an unexpired contact/reservation. | A fresh signed handshake for one device pair. Both signed leases constrain it. A replacement handshake retires that pair's previous session; it does not rewrite its deadline or replay queued data. |
| `block_member_until`, `close_contact_until`; browser `blockMemberUntil`, `closeContactUntil` | `None` / `undefined` for indefinite owner-controlled block; otherwise a future timestamp. | A new explicit signed owner action. Reloading a deployment default cannot alter existing block history. Expiry permits only a fresh authenticated introduction. |
| `Member::sign_presence`; browser `signPresence` / `signDisconnect` | Expiry greater than now, no later than either admission or root-device authorization expiry; sequence `1..=2^53-1`. The board can impose a narrower lease policy. | The next signed per-device presence update. Persist and increase sequence across restart. Presence is not proof of every device's exact connectivity. |
| `FrameCodec::new(max_frame_bytes)`, `BrowserFrameCodec` | `1..=1048576` bytes. | A new codec. Existing partial-frame state is not reconfigured. |
| Native `FramedStream::new(stream, max_frame_bytes, frame_timeout)` | Frame limit above; timeout greater than zero and at most 60 seconds. | A new owned stream. Timeout/partial I/O failure closes that stream. |
| `createTorJsOnionNode({bootstrapDeadlineMs,operationDeadlineMs,gateway,storage})` | Integer bootstrap deadline `1..=300000` ms; operation deadline `1..=60000` ms; nonempty gateway string/list. | A new browser Tor node. Existing streams capture that node's operation budget. Gateway routing is trusted deployment configuration, never supplied by a peer. |
| Browser Tor node `.listen({port,maximumStreams,deadlineMs})` | Port `1..=65535`; service streams `1..=32`; startup deadline `1..=60000` ms. | The node's single service launch. Changing an active service requires an explicit new lifecycle, not mutation of its existing sessions. |
| Native `OnionTransport::new(proxy)` | Nonzero loopback SOCKS address; application owns and verifies the Tor listener. | A new transport. Its current connect timeout is fixed at 45 seconds. |

Credential expiry is also explicit in root-device authorization and accounting
delegation APIs. Renewal requires valid signatures and the same required root,
member and device binding; it is not an operational bypass for eligibility.

## Fixed bounds and missing controls

`MAX_TEXT_BYTES` is 16384, `MAX_DATA_BYTES` is 65536 and `MAX_WIRE_BYTES` is
1048576. Sealed state is bounded by a private 64 MiB store ceiling; plaintext
reserves 128 bytes of that limit. These are validation limits, not runtime knobs.
The browser Tor factory caps its total owned streams at 64 and uses a 1 MiB
framing limit. Native SOCKS connect timeout has no setter. Changing these bounds
requires a reviewed code change and relevant interoperability/resource tests.

There is no general history-retention, pending-control-queue size, Wasm memory,
worker count, retry/backoff or automatic telemetry configuration API. An
embedding may impose stricter admission and resource limits, but must preserve
received evidence, nonce/closure history and storage version checks. Deleting
anti-replay state to satisfy a storage target is not supported cleanup. The
current live adapter does not retry canceled application deliveries offline.

## Metrics for choosing future settings

Measure locally first: bootstrap and handshake duration histograms, stream
operation timeouts, active stream counts, checkpoint size/write latency, CAS
conflict counts, canceled-unconfirmed counts and aggregate ACK delay. Keep
transport acceptance distinct from authenticated delivery and accounting
settlement. A lost ACK is not a failed-delivery observation.

If exported, use coarse aggregate windows and counts with an explicit retention
policy. Exclude member/device IDs, onion addresses, message/intro IDs, peer
proofs, request digests, payload sizes per contact and individual timestamps.
Do not join client metrics into a contact graph. Public errors already expose
coarse categories; raw Tor or cryptographic debug records are unsuitable metrics.
There is no built-in production collector or automatic tuning controller.

Record the configuration version alongside local aggregate measurements.
Choose changes from measured latency, memory and failure distributions; apply
them to new calls, sessions and introductions. Keep original contact, block and
accounting deadlines intact. Existing runtime and browser evidence does not
validate an arbitrary new deployment configuration.
