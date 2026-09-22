# Profile and discovery signing

`Member::sign_profile_statement` and the browser methods
`BrowserMember.signProfileStatement` / `BrowserInbox.signProfileStatement`
connect cfrm's profile clients to the existing root-authorized cmsg device key.
The key remains inside cmsg and its encrypted snapshots. Moving a member into
an Inbox preserves the same signing interface.

```js
const identity = {
  authority: { admission, authorization },
  sign: bytes => inbox.signProfileStatement(bytes),
};
// Supply identity to cfrm's profile publisher, reader-side discovery client,
// holder-key services and profile-ticket signing helper.
```

The embedding retains the admission and root-signed device authorization used
to enroll this device. cfrm independently verifies that the returned signature
matches that authority. After credential renewal, update the embedding's public
authority as well as cmsg's credential.

This API accepts only the exact canonical JSON-array schemas for:

- `cfrm.cached-profile.v1`
- `cfrm.discovery-request.v1`
- `cfrm.key-access.issue.v1`
- `cfrm.profile-holder-key.v1`
- `cfrm.profile-holder.v1`
- `cfrm.profile-holder-seed.v1`
- `cfrm.profile-key-challenge.v1`
- `cfrm.profile-key-grant.v1`

The validator checks the existing wire-size bound, tuple arity, canonical
encodings, certified local community/member/device fields, matching policy
digest where present, and current issuer and root-device authority using the
member's Clock. Browser bindings use the existing browser wall-clock contract;
transcript timestamps are never treated as the current time. Expiry cannot
exceed either credential, and issuance cannot predate either credential.
Holder seeds must contain this device's valid signed owner delegation. A key
grant carries a challenge digest instead of owner fields; cfrm verifies the
signature against the authenticated holder and binds that exact challenge.

cfrm retains operation schemas, discriminator registries, access decisions,
quotas and publication policy. The embedding supplies locally prepared cfrm
statements, never arbitrary remote signing requests. Signing does not establish
that a requested operation was permitted or successfully applied. Unsupported
domains, including MLS signing requests and profile associated-data domains,
fail closed. A new wire schema requires an explicit adapter update.

The native adversarial tests cover authority expiry, identity substitution,
domain confusion, malformed encodings and nested delegation signatures. The
browser contract tests the generated Wasm API with WebCrypto verification.
The portable browser suite requires the profile source revision recorded in
`.ci/archives.toml`. Crow supplies `CFRM_PROFILES_SOURCE_ARCHIVE` and
`CFRM_PROFILES_SOURCE_SHA256`; GitHub Actions archives the same exact public
revision. The shared script verifies these required inputs and exports
`CFRM_SOURCE_ARCHIVE`, `CFRM_SOURCE_COMMIT` and `CFRM_SOURCE_SHA256` to
`.ci/browser-check.mjs`. The runner verifies the checksum and embedded Git commit,
serves only the needed profile source modules, and records that revision in its
evidence. The composition exercises all eight cfrm-generated domains, encrypted
publication and owner/holder key release. Eligibility and ticket gates are
explicitly synthetic, and in-memory transport does not constitute Tor evidence.
