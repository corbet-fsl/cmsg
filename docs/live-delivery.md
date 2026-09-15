# Live delivery

BrowserInbox uses live delivery. Native callers select `Inbox::new_live`.
The generic Member remains a separate MLS primitive. A live Inbox's ordinary
send/receive APIs cannot bypass its contact and session rules.

Each device pair exchanges signed, root-authorized fresh Hello challenges and
Ready confirmations. Application envelopes bind the resulting session, group,
exact introduction nonce, author device, unique message ID and payload. A new
session, restored checkpoint, expired lease or observed transport loss cannot
accept application frames from the retired session. `LiveInboxStream` connects
these rules to an owned framed stream and closes its own session on I/O failure.
The host selects session leases; local clocks and failure detection are trusted
host inputs. A disconnected device does not imply all of its member's devices
are offline. Abrupt loss creates no member block or automatic Close.

The receiver persists accepted plaintext history and its signed ACK before
exposing plaintext. Outgoing pending records retain digests, not queued payload.
An outgoing Answer becomes an accepted decision only before the response deadline, after the original sender's
ACK reaches the recipient. A canceled queued Answer leaves Close available.
`CanceledUnconfirmed` means delivery is unknown: an authentic later ACK may
record acceptance, but never reopen a closed contact. Neither transport writes
nor cancellation create accounting refunds. Under the selected cfrm rule,
confirmed Answer permits early release; Close or silence returns the sender's
capacity only at the original fixed deadline. Refunds do not restore admission
turns or change cmsg's unresolved/contact-block history. Settlement remains the
accounting policy's responsibility.

Browser persistence receives `(checkpoint, outboundFrames, metadata)`, commits
atomically, and resolves `true`. Metadata identifies application message/session
IDs and canceled application IDs. Purge canceled app outbox entries; check
`canTransmitLiveWire` before any write. On restore all live application send
permissions are canceled even if the external outbox survived. Control recovery
uses retained signed evidence and `retransmitLiveAck`; it does not consume a new
introduction. Silence at the live response deadline cancels delivery eligibility and keeps the obligation; it signs no Close and creates no member block. Explicit Close remains available afterward. Signed sibling sync retains authenticated accepted history and
monotonic cancellation without transferring live socket permissions.

A full rollback of every replica and externally saved ciphertext cannot be
prevented by local encrypted journals alone. Honest endpoint enforcement does
not establish that a modified client discarded its own copies. Session
challenge proofs establish a bounded device session, not globally exact
presence or atomic delivery. No operator receives the history or session log.

At `80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`, Crow10/76 passed
161 native tests and Wasm checking, including nine live-delivery tests.
Crow10/77 passed 21 actual Chromium contract groups, including live delivery,
the supplied IndexedDB adapter across two connections, competing Wasm instances,
and separately labeled scripted stream cancellation. This is no new live Tor
or process-wide network-confinement claim.
