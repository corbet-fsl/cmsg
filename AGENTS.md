# cmsg agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cmsg` — native suite, green
  (lib 288, cmsg 12, door 17, facades 4, foyer 3 passed), exit 0; long, background it
- `~/agents/scratch/cbuild <lane> fmt -p cmsg -- --check` — must be clean
- Full gate (clippy matrix, wasm vectors, 100% reachable line+branch coverage,
  generated-client parity) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Cross-facade effect in one combined encrypted checkpoint before anything escapes
  -> `tests/support/inbox_waves_owner.rs`, `tests/support/facades.rs`, `tests/foyer_browser.rs`
- No member keys, PRF material, plaintext, or identifiers in API/errors/logs
  -> `tests/support/foyer.rs::forwarding_catalog_preserves_owner_metadata_and_withholds_session_secrets`
- Capability + exact origin + role/community scope + expiry/revocation on every dispatch
  -> `tests/door.rs::capabilities_are_bound_to_origin_scope_role_and_actions`
- One registry, typed parity across HTTP/OpenAPI/MCP/CLI/TS; ambiguous/oversize
  refused; all HTTP `no-store`
  -> `tests/door.rs::projections_share_typed_action_bodies_and_refusal_semantics`
- Real owners only; unbound refuses; Inbox revalidates under Vault guard
  -> `tests/facades.rs::encrypted_storage_without_unlocked_current_keys_does_not_bind_vault_or_inbox`
- Preload starts unavailable; only a completed network bind releases it
  -> `tests/door.rs::only_a_completed_network_bind_releases_preload`
- Native client forwards original bytes; lost accepted reply reconciles, never blind-retries
  -> `tests/door.rs::lost_response_reattaches_to_the_kept_outcome`
- Wallet enrollment lifecycle runs on an explicit 8 MiB thread (2 MiB test threads overflow)
  -> `tests/wallet_enrollment.rs::same_certified_wallet_restores_its_holder_issues_and_joins_a_community`

Pointers: `src/door/mod.rs` (dispatcher), `src/door/registry.rs`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
No registry publication; backend changes need independent review.
