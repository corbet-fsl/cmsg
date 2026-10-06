# Native Tor owner

With `native-tor`, trusted construction may call `Door::bind_native_tor` with an
original Keys `NativeTorInitializer`. The Door checks its community and member
origin, consumes the capability directly into original Arti, starts the original
Tor Node, and waits for the original onion listener through Ferry and Mesh.
No raw key, endpoint override or network configuration is an API action.

Before constructing the native runtime, the Door preserves an embedding
application's installed rustls provider or installs the maintained ring provider
once, as the original transport examples do. This satisfies Arti's explicit
[provider initialization requirement](https://tpo.pages.torproject.net/core/doc/rust/src/tor_rtcompat/impls/rustls.rs.html).
It avoids depending on which other HTTP client happens to run first. An absent
Tokio runtime still returns Unavailable. Process-isolated regression cases cover
empty and preinstalled providers and repeated construction; execution is pending.

The retained Mesh owns a stop guard. Failed or cancelled initialization, normal
disconnect, owner drop and drained shutdown all stop the original Node. Original
Keys custody invalidation also stops that same Node. Background receive pumps
cannot keep the network alive after the owner releases it.

This is the message-transport constructor needed by the native test bed. It does
not provide Records, authenticated discovery, Inbox receive dispatch, or completed
custody. It does not set `runtime.status` to ready. `mesh.status` reports only the
existing original Mesh measurements; merely building a transport is insufficient
for the two-member voucher/profile/forum/Wave/chat journey.

Required pending execution: compile the exact Keys/Arti/Mesh closure; run through
the existing private Tor fixture; verify two real onion listeners and messages;
cancel bootstrap and publication; disconnect and drop while pumps hold handles;
lock/rotate Keys and confirm no old service remains; then exercise actual Inbox
and Records with this same Door through cmeet. No local build/test was performed.

## Board attendance and committed discovery wiring

The same dispatcher now has three concrete Board operations:

- `board.attend`, body `{}`: load the original current committed Profile, obtain
  the original Link challenge, sign that exact challenge with the retained owner,
  and enter through the same Link. Reload and compare the committed publication
  after signing and after Enter. Return only the original Board status after its
  actual connection is Present.
- `board.search`, body `{ "cursor": null, "page_size": 10 }`: prepare the
  original Forum Search request with Link's session and fresh nonce, use the
  existing Vault Prepared-request signer, then call `receive_search`. Its opaque
  pending response is consumed only by `finish_search_committed` after fresh
  local authority. This is Forum's original Search → Lookup route.
- `board.discovery`, body `{}`: re-read the held discovery page through
  `read_discovery_committed` with fresh local authority on every invocation.

None accepts a publication, member identity, revision floor, device signature,
policy snapshot, possession object or authority verdict. Raw network search
entries are never public results; Search produces its original Discovery DTOs.

Trusted native construction must use `Door::configure_board_with_owner` instead
of `configure_board`, or `Door::bind_board_with_owner` for an already constructed
original Board. Pass a `board::CommittedOwner` and an explicit `board::ReadPolicy`
(admission action and maximum signed-snapshot age). An existing Board is not
silently replaced. Hosts using the public configuration constructor must defer
its optional Forum construction and install this bound Board once custody's
shared owner capability is available. Ordinary public configuration still binds
only the original Board and these operations refuse with `unavailable`.

`Door::bind_vault_with_board_owner` now retains the actual Vault once and returns
its narrow `VaultBoardOwner`. Use that owner when binding Board. Inbox reads,
Board reads and attendance signatures share this custody; locking takes the Vault
out of the shared slot and closes its session before waiting. It borrows the
actual Store through the synchronous committed-read callback after original Keys
freshness checks. No accepted lineage or Store snapshot is cached by this adapter.

`Door::member_authority_with_intent` constructs the original intent channel with
that same member authority. Exact device signing requires both the forced lineage
and fresh HTTPS checks, then consumes the exact admitted command at the completed
check time. Admission expires across waits and the original guard remains alive
through the Board network operation. Broader signer loans, pairing and rotation
remain refused by this authority.

The `cshm::ContactCheck` callback detects prohibited contact details in profile
text; it is not the ctcs relationship journal. Until a real detector is installed,
the shared owner returns `Unavailable`: a field requiring that check refuses.
Other fields retain the original Schema validation. No accepting detector is used.

Failure, cancellation or panic clears local attendance/discovery. Interrupted
attendance remains fenced for reconciliation; `disconnect` does not erase that
uncertainty. Failed `receive_search` conservatively retains its signed request and
returns `reconcile`; a completed typed PendingSearch followed by local disclosure
refusal clears that request without replaying it.

These paths are source implementation, not an executed two-member journey.
The already-enrolled restore composer below supplies the native Records and root
recovery assembly; real embedding and CI qualification remain pending.

## Retained native Records construction

`scenario::network::Network::start(client, owner, configuration, watcher)` consumes
the matching transport pair on its existing LocalSet and a genuine original
`TorWatcher`. Supply explicit Tor directories/configuration, work/storage limits,
startup deadline and original signed bootstrap advertisements. The independent
credential pump authorizes the original initializer and actual listener's ad.
Original TorDiscovery verifies advertisements; ENV0 uses strict VLD0, actual wall
time and the transport session's existing freshness window. `TorRecords::run_shared`
drives one authenticated receiver for original Records and AppCall/AppMessage
operations concurrently with original maintenance; retained message drivers are
bounded. `applications()` exposes original `TorApplications` from the exact same
discovery owner. Its Mesh listener consumes the application queue without publishing
a second onion service. Supply explicit `application_queue` (1–1024 events) and
`application_payload` (1–32768 bytes); both are checked before startup.
Startup cancellation/error, close/drop and service exit close application delivery
and replies and stop the node, drivers and transport owner; `shutdown` also joins tasks.
Forward verified lineage through `observe_lineage`; lock/revoke must call `close`.
Retain this graph while using its original `records()`, `applications()` and `discovery()` owners.
The parent must supply `TorWatcher::{public_key, question}` from real record
authority and construct its member-record capability over those owners. This
adds no unsigned Backend, read authority, public installation action or readiness
claim. No network execution, build or tests have run for this composition.

`scenario::mesh::Owner::bind(door, origin, network)` binds that graph's original
application queue to Mesh/BoundMesh on the graph's existing active Tokio LocalSet.
It retains one Send receive task through `Arc`/`Mutex` tracking; a separate local
cleanup owner closes and joins the actual Network/TransportOwner and pump on
failure, cancellation, owner drop or facade teardown. Pump exit notifies cleanup;
a one-second check of the original network lifetime also catches service loss
while Mesh's bounded consumer queue is backpressured. Binding errors await drain.
Use `records()` and forward verified observations with `observe_lineage`; if
needed, take the original member builder from Network before moving it here.
`Network::prepare` and `mesh::Owner::prepare_bind` expose retained close/drain
handles before their futures are awaited, including cancelled initialization.
`Embedded::start_composed` retains a `VaultComposer` and awaits its cleanup before
Vault/Store teardown, then drains the LocalSet before exit. Inbox receive dispatch
remains unwired; no second onion listener, runtime, authority or readiness is added.
Execution is pending.

## Already-enrolled native restore

Construct `scenario::restore::Composer<W, B>` with `restore::Configuration`:
the actual `network::Configuration`, original `TorWatcher`, envelope `TimeWindow`
and a real `cwst::backend::Backend` such as the native file backend. Return it as
the retained `Box<dyn VaultComposer>` alongside Door from the
`Embedded::start_composed` initializer. Restoration runs on that owner's existing
LocalSet. This constructor accepts no credentials, authority verdict or callback.

Only a successful `login.start` or `login.poll` reporting
`authenticated_pending_custody` can consume the one recovery attempt. It obtains
the original `prepare_login_recovery` result and native transport, retains the
Network cleanup handle before startup, and reads the passkey checkpoint through
that exact Network. Original current policy and recovery owners perform the forced
lineage and fresh HTTPS checks before `RecoveryOwners::open` lends the Store.
An empty local backend restores the existing remote compound checkpoint; absent
recovery data refuses and never falls back to account or Vault creation.

The recovered Vault and intent bind to Door before the same Network binds Mesh.
The Mesh cleanup handle is retained before awaiting binding. Every eligible
login result then invokes `complete_login_recovery` afresh; transport construction
alone never reports login completion or runtime readiness. A cancellation guard
covers restoration and this final check, including later polls. Original refusals,
negative lifecycle observations, failure and Drop close custody synchronously.
Both independent cleanup completions remain awaitable through the common composer
drain before the parent tears down Store, even after startup or binding cancellation.

This is source implementation only. Independent review, native compilation and
executed qualification remain pending. Real enrollment, fixture composition,
Inbox receive dispatch and the complete member journey remain separate work;
this composer does not supply first creation.

## Public native host configuration

With `native-tor`, `Embedded::configured_restore(NativeDeployment, lifetime, clock)`
mounts the real restore composer through `Embedded::start_composed`. The deployment
wrapper has `runtime` (the existing `DeviceConfiguration`) and optional
`native_tor` (`native::deployment::TorDeployment`). The original origin, role and
action catalogue bind Pairing. Tor restoration rejects nonmember roles.

The CLI configuration file accepts this wrapper or the existing bare
`DeviceConfiguration`. A bare device file, or a wrapper with absent/null
`native_tor`, explicitly selects the partial host: it does not install restore.
Both forms and every nested deployment object reject unknown fields. Malformed
Tor settings cannot silently fall back to a partial host.

`native_tor` requires these public inputs:

- Absolute `state_directory`, `cache_directory` and `store_directory` paths.
  Arti receives the first two through its original `Directories`; they must differ.
  CWST receives an existing private Store directory through `FileBackend`, with
  no directory creation or deletion by this constructor. A symlink in place of
  that directory is refused; Unix group/other permissions must be absent. The
  embedding remains responsible for directory ownership and platform ACLs.
- `transport`, `messages`, `discovery`, `records`, optional `storage`, and `window`
  use the same public budget DTOs as browser deployment. Optional storage includes
  explicit original inbound watch limits; it does not grant client watch signing.
- `bootstrap` contains original signed PeerInfo byte arrays, verified and bounded
  by `maximum_bootstrap_bytes` and the discovery peer limit.
- Explicit `driver_tasks`, `record_concurrency`, `application_queue`,
  `application_payload` and `startup_millis` budgets. No budget defaults are added.

Arti uses its original default public network configuration. The scope is
SHA-256 over `cmsg.tor.scope.v1\0` followed by the immutable runtime community's
UTF-8 bytes, exactly as in browser deployment. A public configuration cannot
override that scope or install a connection callback. Trusted Chutney fixtures
can still construct `scenario::network::Configuration` separately.

Construction validates public shape and retains a dormant composer; the original
login starts actual custody and Tor. Original network, Records and Store
validators remain in force. Since no client watch signer exists,
`RefuseWatches` returns `WatchRefused` for both watch operations; recovery uses
forced polling reads. No node signer substitutes for record authority.
The configured host adds neither first creation nor readiness claims. This
wrapper and CLI selection await executed qualification.

With the native `test-authenticator` feature, trusted test composition may call
`Door::bind_test_authenticator(origin, owner)` after configuring that member's
Foyer and login. Supply an original `cpky::software::SoftwareAuthenticator`
genuinely enrolled with the real service. Live or uncertain login prevents
rebinding. Login uses the same pending ceremony's original HTTP callback helper
with `synced_test_device()`, then the unchanged wait/Foyer verification/custody
path. An explicit helper failure drops the ceremony before clearing uncertainty;
cancellation keeps the existing Foyer fence raised. With no bound test owner,
the original browser launcher runs. There is no public provider configuration.
The test-only Cmeet child constructor and real enrollment/retained provider setup
remain to be wired; enabling a feature cannot supply either or complete custody.
