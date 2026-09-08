# Certified Semaphore enrollment signing

[Crow pipeline 32](https://crow.corbet.ch/repos/10/pipeline/32), at `b4b0c7c53a9679fb104ec32523ceb8adf81535a8`, passed **all 83 native tests**, formatting and profile interoperability, with no failed or ignored tests. This includes seven enrollment-signing cases. Their preceding genuine red was [pipeline 30](https://crow.corbet.ch/repos/10/pipeline/30), at `fcc146755bbd574a4470861acdd96fc7c9633fc3`: the existing 76 cases passed and all seven new cases failed against the rejecting signer. Each new case required a valid signature before checking rejection behavior.

The public adapter is:

```rust
member.sign_semaphore_enrollment(&challenge, &expected_wallet_commitment)?;
```

`SemaphoreEnrollmentChallenge` contains exactly the camelCase fields `communityId`, `memberId`, `chatPublicKey`, `commitment`, `challengeId`, `issuedAt` and `expiresAt`. Unknown fields are rejected during deserialization. The existing certified Ed25519 key signs UTF-8 JSON bytes matching cfrm's `enrollmentBytes`:

```text
["cfrm.semaphore.enroll.v1", communityId, memberId, chatPublicKey,
 commitment, challengeId, issuedAt, expiresAt]
```

The return value is a canonical unpadded base64url signature. The adapter verifies the stored cvld grant against the member's current trusted `Clock`, matches its community/member/chat key, and requires a fresh challenge wholly inside the grant's validity period with a maximum duration of 300 seconds. Times must be positive JavaScript-safe integers. The nonce must encode exactly 32 bytes; the commitment must be a nonzero canonical decimal string below cfrm's existing Baby Jubjub field modulus.

The expected commitment is a **separate trusted client input**, obtained from the persistent wallet identity. The client must not silently copy the server's proposed commitment into that argument. Equality prevents an unexpected proposal from being signed; a string API cannot prove where its caller obtained the value. A fresh certified chat key for the same member can authorize the same wallet commitment.

This adapter adds no generic signing function, private-key export, dependencies or curve arithmetic. cfrm retains Semaphore identity derivation, the second proof of key possession, point/subgroup validation, immutable enrollment and replay handling. The Rust tests use canonical field fixtures and verify real Ed25519 signatures over the specified bytes; they do not claim that those fixtures prove Semaphore-key possession or that a complete native enrollment transaction has run. The existing profile interoperability check does not establish enrollment interoperability.

The separate [public-Tor MLS round trip](../experiments/embedded-onion/README.md) is transport evidence. It did not exercise this enrollment adapter or the complete counter protocol.
