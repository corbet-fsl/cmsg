//! Device-signed original account request and the exact ApplyExtended outbox.
//!
//! The request is signed once, through the ordinary member Keys authority, before
//! the pending companion is sealed in state A. State A stores these exact bytes;
//! a reopen re-sends them and never re-signs, reproves or changes the request id.
use super::*;
use cblc::{
    accounting::{
        self as acct, AccountAcceptance, AccountProofScope, AccountRequest, AccountStatement,
    },
    contracts::{AccountServiceRequest, AccountServiceResponse},
    extensions::{
        self, Effect, EpochAncestryCertificate, ExtendedUpdate, ExtensionPolicy, Inbox,
        StateCertificate,
    },
};

/// Public proven genesis data from the lower proof owner: the statement that the
/// proof computed, its exact circuit/key scope and the locally verified proof.
/// It contains no witness or private opening and grants no authority.
pub struct ProvenGenesis {
    /// Exact public statement of the proven genesis.
    pub statement: AccountStatement,
    /// Original circuit and verification-key digests of the proof.
    pub scope: AccountProofScope,
    /// Locally verified proof bytes.
    pub proof: Vec<u8>,
}

#[cfg(any(all(feature = "native-prover", not(target_arch = "wasm32")), feature = "browser-prover"))]
impl ProvenGenesis {
    /// Convert the lower owner's borrowed public proof material into the original
    /// Balance statement. The economic policy is the verified current policy and
    /// is never taken from the proof owner; `statement_bytes` then checks that its
    /// digest, horizon and shape match what the proof committed to.
    pub fn from_material(
        material: &cwlt::account_owner::GenesisRequestMaterial<'_>,
        policy: &acct::AccountPolicy,
    ) -> Result<Self> {
        let public = &material.statement;
        let statement = AccountStatement {
            protocol_version: public.protocol_version,
            community: public.community,
            owner: public.owner,
            policy_digest: public.policy_digest,
            enrollment_root: public.enrollment_root,
            now: public.now,
            valid_until: public.valid_until,
            genesis: public.genesis,
            previous_version: public.previous_version,
            next_version: public.next_version,
            previous_state: public.previous_state,
            next_state: public.next_state,
            settlement_marker: public.settlement_marker,
            policy: policy.clone(),
        };
        acct::statement_bytes(&statement).map_err(|_| ErrorCode::Unauthorized)?;
        Ok(Self {
            statement,
            scope: material.scope.clone(),
            proof: material.proof.to_vec(),
        })
    }
}

/// Public proven update data from the wallet owner: the statement the proof
/// computed, its circuit/key scope, the verified proof and the extended effect it
/// was proven for (inbox frontier and effect). No witness, no opening, no authority:
/// the signer re-checks everything against the verified current material.
pub struct ProvenUpdate {
    /// Exact public statement of the proven (non-genesis) update.
    pub statement: AccountStatement,
    /// Circuit and verification-key digests of the extension relation used.
    pub scope: AccountProofScope,
    /// Locally verified proof bytes.
    pub proof: Vec<u8>,
    /// Inbox frontier before and after, and the effect the proof binds.
    pub update: ExtendedUpdate,
}

/// The exact signed ApplyExtended wire, ready for state A. Its bytes are the
/// outbox; everything else is derived data for response checks.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedApplyExtended {
    outbox: Vec<u8>,
    request: AccountRequest,
    /// Plain digest of the signed request, signature included.
    request_digest: [u8; 32],
    /// The acceptance's request binding: effect, pinned extension policy and scope.
    extended_request_digest: [u8; 32],
    /// The exact signed update (effect and inbox frontier) the acceptance is checked for.
    update: ExtendedUpdate,
}

/// Operator response whose signature and bindings were verified; the extended
/// acceptance digest is the value written into state B. Not yet custody.
pub struct AcceptedResponse {
    acceptance: AccountAcceptance,
    certificate: StateCertificate,
    ancestry: Option<Box<EpochAncestryCertificate>>,
    digest: [u8; 32],
}

/// Copy of the verified admission fields needed across the signing awaits.
struct Snapshot {
    grant: admission::AdmissionGrant,
    origin: String,
    expires: u64,
    now: u64,
    /// The signed policy's own request window; this module owns no second value.
    max_authorization: u64,
    extension_policy: ExtensionPolicy,
}

/// Genesis update, ruled by the manager: empty inboxes and the plain Update effect.
/// The ledger verifies every ApplyExtended proof as an extension update bundle.
/// A genesis is one step from the empty inbox to the statement's next state, the
/// proof in lower hex (the same wire as a community activation).
pub(super) fn genesis_bundle(next_state: &[u8; 32], proof: &[u8]) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "proofs": [{
            "state": next_state,
            "inbox": Inbox::default().root,
            "proof": data_encoding::HEXLOWER.encode(proof),
        }],
    }))
    .map_err(|_| ErrorCode::Unavailable)
}

fn genesis_update() -> ExtendedUpdate {
    ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    }
}

impl SignedApplyExtended {
    /// The exact outbox bytes that state A stores and a reopen re-sends.
    pub fn outbox(&self) -> &[u8] {
        &self.outbox
    }

    /// Original request identifier (non-zero).
    pub fn request_id(&self) -> [u8; 32] {
        self.request.request_id
    }

    /// The end of the signed request's window: from then on the operator can
    /// only refuse it, so it is never sent again.
    pub fn expires_at(&self) -> u64 {
        self.request.expires_at
    }

    /// Plain digest of the signed request, signature included.
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// The request binding that the operator's acceptance signs (and the server's
    /// exact-retry identity). The lower owner's acceptance transcript needs this
    /// value; it differs from the plain request digest.
    pub fn extended_request_digest(&self) -> [u8; 32] {
        self.extended_request_digest
    }

    /// Accept only the extended request digest as the acceptance binding of the
    /// pending companion. The plain request digest is never a binding: the
    /// operator's acceptance signs the extended one.
    pub fn check_binding_digest(&self, digest: [u8; 32]) -> Result<()> {
        if digest != self.extended_request_digest {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }

    /// Acceptance binding for the lower owner: request id, EXTENDED request
    /// digest and the pinned operator key from the verified material.
    #[cfg(any(all(feature = "native-prover", not(target_arch = "wasm32")), feature = "browser-prover"))]
    pub fn acceptance_binding(
        &self,
        operator_key: [u8; 32],
    ) -> ckmg::wallet_engine::account::AcceptanceBinding {
        ckmg::wallet_engine::account::AcceptanceBinding {
            request_id: self.request.request_id,
            request_digest: self.extended_request_digest,
            operator_key,
        }
    }

    /// Rebuild the derived data from stored outbox bytes after a restart, under the
    /// current pinned extension policy. Digests are recomputed; nothing is re-signed
    /// or regenerated.
    pub fn from_outbox(outbox: Vec<u8>, policy: &ExtensionPolicy) -> Result<Self> {
        let signed = Self::from_update_outbox(outbox, policy)?;
        if signed.update != genesis_update() || !signed.request.statement.genesis {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(signed)
    }

    /// Like `from_outbox` for a later (non-genesis) update: the stored bytes of a
    /// signed ApplyExtended wire, re-checked under the current pinned policy. The
    /// caller persists `outbox()` as its pending companion and re-sends it after a
    /// restart; nothing is re-signed, reproved or rebuilt.
    pub fn from_update_outbox(outbox: Vec<u8>, policy: &ExtensionPolicy) -> Result<Self> {
        if outbox.is_empty() || outbox.len() > pending::MAX_OUTBOX {
            return Err(ErrorCode::Unauthorized);
        }
        let wire: AccountServiceRequest =
            serde_json::from_slice(&outbox).map_err(|_| ErrorCode::Unauthorized)?;
        let AccountServiceRequest::ApplyExtended {
            request, update, ..
        } = wire
        else {
            return Err(ErrorCode::Unauthorized);
        };
        Ok(Self {
            request_digest: acct::account_request_digest(&request)
                .map_err(|_| ErrorCode::Unauthorized)?,
            extended_request_digest: extensions::extended_request_digest(&request, &update, policy)
                .map_err(|_| ErrorCode::Unauthorized)?,
            request: *request,
            update,
            outbox,
        })
    }

    /// The signed statement (public values only).
    pub fn statement(&self) -> &AccountStatement {
        &self.request.statement
    }

    /// The signed update (effect and inbox frontier).
    pub fn update(&self) -> &ExtendedUpdate {
        &self.update
    }
}

impl AcceptedResponse {
    /// The operator's signed acceptance, ready for the lower owner's own check.
    pub fn acceptance(&self) -> &AccountAcceptance {
        &self.acceptance
    }

    /// Original private state certificate returned only on this response.
    pub fn certificate(&self) -> &StateCertificate {
        &self.certificate
    }

    /// Original ancestry certificate, when issued in this acceptance's CAS.
    pub fn ancestry(&self) -> Option<&EpochAncestryCertificate> {
        self.ancestry.as_deref()
    }

    /// DISTINCT digest of the signed acceptance for the pending state B.
    pub fn extended_acceptance_digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[cfg(any(all(feature = "native-prover", not(target_arch = "wasm32")), feature = "browser-prover"))]
mod lower {
    //! The holder engine verifies certificate and ancestry itself, from raw
    //! signatures. These conversions only reshape the already decoded response
    //! and the current verified material; nothing here grants trust.
    use super::*;
    use ckmg::wallet_engine::account as engine;

    fn signature(bytes: &[u8]) -> Result<[u8; 64]> {
        bytes.try_into().map_err(|_| ErrorCode::Unauthorized)
    }

    impl AcceptedResponse {
        /// Lower-owner form: the operator signature, the issuer's state
        /// certificate signature and the private ancestry packet, unchanged.
        pub fn to_engine(&self) -> Result<engine::AcceptedResponse> {
            if self.certificate.accepted_at != self.acceptance.accepted_at {
                return Err(ErrorCode::Unauthorized);
            }
            let ancestry = match self.ancestry.as_deref() {
                None => None,
                Some(ancestry) => Some(engine::AncestryResponse {
                    epoch: ancestry.epoch,
                    root: ancestry.root,
                    frozen_leaf: ancestry.frozen_leaf,
                    signature: signature(&ancestry.signature)?,
                    record: serde_json::to_vec(&ancestry.record)
                        .map_err(|_| ErrorCode::Unauthorized)?,
                }),
            };
            Ok(engine::AcceptedResponse {
                issuer: engine::IssuerAcceptance {
                    accepted_at: self.acceptance.accepted_at,
                    signature: signature(
                        &B64.decode(self.acceptance.signature.as_bytes())
                            .map_err(|_| ErrorCode::Unauthorized)?,
                    )?,
                },
                certificate: signature(&self.certificate.signature)?,
                ancestry,
            })
        }
    }

    /// The CURRENT verified issuer material a response is checked against. A
    /// published frontier makes ancestry mandatory; its absence forbids it.
    pub fn response_trust(
        material: &cblc::publication::PublicVerifierMaterial,
    ) -> Result<engine::ResponseTrust> {
        Ok(engine::ResponseTrust {
            certificate_keys: material.certificate_keys.clone(),
            community_identity: material.community_identity,
            frontier: material
                .record_epoch
                .as_ref()
                .map(|epoch| engine::Frontier {
                    epoch: epoch.epoch,
                    root: epoch.root,
                }),
        })
    }
}
#[cfg(any(all(feature = "native-prover", not(target_arch = "wasm32")), feature = "browser-prover"))]
pub use lower::response_trust;

/// Digest of the signed acceptance, the same convention the Balance status
/// response uses for an embedded acceptance (message bytes then signature).
fn acceptance_digest(acceptance: &AccountAcceptance) -> Result<[u8; 32]> {
    let mut bytes =
        acct::account_acceptance_bytes(acceptance).map_err(|_| ErrorCode::Unauthorized)?;
    bytes.extend_from_slice(
        &B64.decode(acceptance.signature.as_bytes())
            .map_err(|_| ErrorCode::Unauthorized)?,
    );
    Ok(Sha256::digest(bytes).into())
}

/// Verify the operator's acceptance with the original extended verifier: exact
/// statement, request id, proof scope, extended request binding and the operator
/// signature under the pinned key. Returns the distinct acceptance digest.
fn verify_acceptance(
    acceptance: &AccountAcceptance,
    expected: &SignedApplyExtended,
    policy: &ExtensionPolicy,
    operator_key: &[u8; 32],
) -> Result<[u8; 32]> {
    extensions::verify_extended_acceptance(
        acceptance,
        &expected.request,
        &expected.update,
        policy,
        operator_key,
    )
    .map_err(|_| ErrorCode::Unauthorized)?;
    if acceptance.request_digest != expected.extended_request_digest {
        return Err(ErrorCode::Unauthorized);
    }
    acceptance_digest(acceptance)
}

/// The end of a genesis request's proof window: its proof time plus the shared
/// code constant the operator's acceptance applies, cut by the statement's own
/// horizon (the end of the rate window that contains the proof time), which no
/// request may outlive. Passing either is an overrun, never a verdict.
pub(super) fn genesis_window_end(statement: &AccountStatement) -> u64 {
    statement
        .now
        .saturating_add(cblc::accounting::GENESIS_PROOF_WINDOW_SECONDS)
        .min(statement.valid_until)
}

impl AcceptedResponse {
    /// The lost response of an accepted request, rebuilt from the issuer evidence
    /// of an authenticated status: the acceptance is verified exactly as an actual
    /// response is (`send_signed`); the certificate and ancestry are checked by
    /// the holder engine when state B is written.
    pub(super) fn from_status(
        acceptance: AccountAcceptance,
        evidence: extensions::ExtendedEvidence,
        expected: &SignedApplyExtended,
        policy: &ExtensionPolicy,
        operator_key: &[u8; 32],
    ) -> Result<Self> {
        let digest = verify_acceptance(&acceptance, expected, policy, operator_key)?;
        Ok(Self {
            acceptance,
            certificate: evidence.certificate,
            ancestry: evidence.ancestry,
            digest,
        })
    }
}

impl<'p> CurrentEnrollment<'p> {
    /// Sign the original account request exactly once and assemble the exact
    /// ApplyExtended outbox. The device signature runs through the account's
    /// ordinary member Keys authority with its own one-use intent; this owner and
    /// the local owner are rechecked after every await. Nothing durable is
    /// written here: a crash before state A is sealed restarts from the beginning.
    pub async fn sign_genesis_request<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        genesis: &ProvenGenesis,
        intent: &mut ckmg::IntentAdmission,
    ) -> Result<SignedApplyExtended>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let statement = &genesis.statement;
        acct::statement_bytes(statement).map_err(|_| ErrorCode::Unauthorized)?;
        if !statement.genesis || genesis.proof.is_empty() {
            return Err(ErrorCode::Unauthorized);
        }
        let authorization = self.authorization().clone();
        // The operator accepts a genesis only within the checkpoint slot of its
        // proof; a request never outlives that slot, so an elapsed state A becomes
        // discardable at the slot end instead of a full window later.
        let slot_end = self.slot_end();
        let current = self.with_verified(|publication, tree, index, current| {
            let row = tree.entries().get(index).ok_or(ErrorCode::Unauthorized)?;
            let owner: [u8; 32] = B64
                .decode(row.member_id.as_bytes())
                .map_err(|_| ErrorCode::Unauthorized)?
                .try_into()
                .map_err(|_| ErrorCode::Unauthorized)?;
            // The statement must be exactly this member's genesis under the
            // verified current roster and economic policy.
            if statement.owner != owner
                || statement.enrollment_root != publication.root
                || statement.policy != current.material.policy.account
                || current.now < statement.now
            {
                return Err(ErrorCode::Unauthorized);
            }
            // Never sign a request whose proof window (or horizon) has already elapsed.
            if current.now >= genesis_window_end(statement) {
                return Err(ErrorCode::ProofWindowElapsed);
            }
            Ok(Snapshot {
                grant: current.grant.clone(),
                origin: current.origin.clone(),
                expires: current.expires.min(slot_end),
                now: current.now,
                max_authorization: cblc::accounting::GENESIS_PROOF_WINDOW_SECONDS,
                extension_policy: current.material.extension_policy.clone(),
            })
        })??;
        let signed = self
            .admission_mut()
            .sign_core(
                account,
                authorization,
                current,
                statement,
                &genesis.scope,
                &genesis_bundle(&statement.next_state, &genesis.proof)?,
                genesis_update(),
                intent,
            )
            .await;
        match signed {
            // The window ran out during the signing awaits: an overrun, not a verdict.
            Err(ErrorCode::Unauthorized)
                if self.admission_mut().current()?.now >= genesis_window_end(statement) =>
            {
                Err(ErrorCode::ProofWindowElapsed)
            }
            signed => signed,
        }
    }

    /// Send the exact stored outbox once through the held HTTPS owner and verify
    /// the actual response (see `AccountAdmission::send_signed`).
    pub async fn send_genesis_request(
        &mut self,
        signed: &SignedApplyExtended,
    ) -> Result<AcceptedResponse> {
        self.admission_mut().send_signed(signed).await
    }
}

impl AccountAdmission<'_> {
    /// Sign one account request exactly once and assemble the exact ApplyExtended
    /// outbox. The device signature runs through the account's ordinary member
    /// Keys authority with its own one-use intent; this owner and the local owner
    /// are rechecked after every await. Nothing durable is written here.
    #[allow(clippy::too_many_arguments)]
    async fn sign_core<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        authorization: admission::DeviceAuthorization,
        current: Snapshot,
        statement: &AccountStatement,
        scope: &AccountProofScope,
        proof: &[u8],
        update: ExtendedUpdate,
        intent: &mut ckmg::IntentAdmission,
    ) -> Result<SignedApplyExtended>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let mut request_id = [0u8; 32];
        getrandom::fill(&mut request_id).map_err(|_| ErrorCode::Unavailable)?;
        if request_id == [0; 32] {
            return Err(ErrorCode::Unavailable);
        }
        // Minimum of every deadline; the signing intent expires with the request.
        let expires_at = statement
            .valid_until
            .min(statement.now.saturating_add(current.max_authorization))
            .min(current.expires)
            .min(authorization.expires_at);
        if expires_at <= current.now || expires_at <= statement.now {
            return Err(ErrorCode::Unauthorized);
        }
        let mut request = AccountRequest {
            statement: statement.clone(),
            request_id,
            proof_scope: scope.clone(),
            chat_public_key: current.grant.chat_public_key.clone(),
            issued_at: statement.now,
            expires_at,
            proof: proof.to_vec(),
            signature: String::new(),
        };
        let transcript =
            acct::account_request_bytes(&request).map_err(|_| ErrorCode::Unauthorized)?;
        account.check(&current.origin).await?;
        let lineage = account
            .vault()
            .await?
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = account
            .vault()
            .await?
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if lineage.binding.community() != self.cohort.scope
            || lineage.binding.member() != self.cohort.member
            || device.value() != &self.cohort.device
            || B64.encode(device.value()) != current.grant.chat_public_key
            || B64.encode(lineage.root.value()) != authorization.root_public_key
        {
            return Err(ErrorCode::Unauthorized);
        }
        // Held until the signature exists; dropping it cancels unused intent.
        let _admitted = intent
            .admit(
                ckmg::AdmittedCommand {
                    binding: lineage.binding,
                    origin: current.origin.clone(),
                    action: ckmg::Action::SignDeviceEd25519,
                    device,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: None,
                    statement: None,
                    transcript: Some(transcript.clone()),
                    expires: expires_at,
                },
                current.now,
            )
            .map_err(|_| ErrorCode::Unauthorized)?;
        let signature = account
            .vault()
            .await?
            .keys()
            .sign_device_ed25519_current(&transcript, expires_at)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        request.signature = B64.encode(&signature);
        // Both owners must still be current after the signing awaits.
        account.check(&current.origin).await?;
        let after = self.current()?;
        if after.grant != current.grant
            || after.origin != current.origin
            || after.now >= expires_at
            || after.expires < expires_at
        {
            return Err(ErrorCode::Unauthorized);
        }
        let request_digest =
            acct::account_request_digest(&request).map_err(|_| ErrorCode::Unauthorized)?;
        let extended_request_digest =
            extensions::extended_request_digest(&request, &update, &current.extension_policy)
                .map_err(|_| ErrorCode::Unauthorized)?;
        let wire = AccountServiceRequest::ApplyExtended {
            grant: current.grant,
            authorization,
            request: Box::new(request.clone()),
            update: update.clone(),
        };
        let outbox = serde_json::to_vec(&wire).map_err(|_| ErrorCode::Unauthorized)?;
        if outbox.len() > pending::MAX_OUTBOX {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(SignedApplyExtended {
            outbox,
            request,
            request_digest,
            extended_request_digest,
            update,
        })
    }
}

impl AccountAdmission<'_> {
    /// Sign a later account update (reservation, answer settlement, punishment,
    /// voucher spend, obligation consumption) exactly once. The admission is
    /// freshly issued for this community; the device authorization is signed by
    /// the root under its own one-use intent, the request by the device under
    /// another (`intents`). The statement must be this member's non-genesis step
    /// under the verified current economic policy; the server verifies the proof,
    /// the predecessor version, spent nullifiers, inbox consumption and the
    /// rulebook parameters again. Nothing durable is written here: the caller
    /// stores `outbox()` before sending and re-sends those exact bytes on retry.
    pub async fn sign_update_request<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        proven: &ProvenUpdate,
        intents: &mut AccountingIntents,
    ) -> Result<SignedApplyExtended>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let statement = &proven.statement;
        acct::statement_bytes(statement).map_err(|_| ErrorCode::Unauthorized)?;
        if statement.genesis || proven.proof.is_empty() {
            return Err(ErrorCode::Unauthorized);
        }
        let (authorization, _root_guard, current, _) =
            self.authorize_device(account, intents).await?;
        let owner: [u8; 32] = B64
            .decode(current.grant.member_id.as_bytes())
            .map_err(|_| ErrorCode::Unauthorized)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?;
        if statement.owner != owner
            || statement.policy != current.material.policy.account
            || current.now < statement.now
            || current.now >= statement.valid_until
        {
            return Err(ErrorCode::Unauthorized);
        }
        let snapshot = Snapshot {
            grant: current.grant.clone(),
            origin: current.origin.clone(),
            expires: current.expires,
            now: current.now,
            max_authorization: current.material.policy.max_authorization_seconds,
            extension_policy: current.material.extension_policy.clone(),
        };
        self.sign_core(
            account,
            authorization,
            snapshot,
            statement,
            &proven.scope,
            &proven.proof,
            proven.update.clone(),
            &mut intents.device,
        )
        .await
    }
}

/// The request identifier inside stored outbox bytes, without any policy: enough
/// to match a settlement to the stored update.
pub fn outbox_request_id(outbox: &[u8]) -> Result<[u8; 32]> {
    if outbox.is_empty() || outbox.len() > pending::MAX_OUTBOX {
        return Err(ErrorCode::Unauthorized);
    }
    match serde_json::from_slice(outbox).map_err(|_| ErrorCode::Unauthorized)? {
        AccountServiceRequest::ApplyExtended { request, .. } => Ok(request.request_id),
        _ => Err(ErrorCode::Unauthorized),
    }
}

impl AccountAdmission<'_> {
    /// Rebuild a stored later-update outbox under the CURRENT verified extension
    /// policy of this admission (never one the caller supplies). The bytes are
    /// kept exactly; nothing is re-signed.
    pub fn restore_signed(&mut self, outbox: Vec<u8>) -> Result<SignedApplyExtended> {
        let current = self.current()?;
        SignedApplyExtended::from_update_outbox(outbox, &current.material.extension_policy)
    }

    /// Send the exact stored outbox through the held HTTPS owner and verify the
    /// actual response: the operator signature under the pinned key, and the
    /// request identity, digest, statement and scope. Any failure after sending
    /// is uncertain (Reconcile); retry re-sends the same bytes, never a rebuilt
    /// request. A verified response is still not custody.
    pub async fn send_signed(&mut self, signed: &SignedApplyExtended) -> Result<AcceptedResponse> {
        let before = self.current()?;
        let wire: serde_json::Value =
            serde_json::from_slice(&signed.outbox).map_err(|_| ErrorCode::Unauthorized)?;
        let response = self
            .lease
            .apply_account(wire, now)
            .await
            .map_err(|error| match error {
                // Refused before commitment (409, reason expired): certain, and the
                // only answer that lets the device prepare a fresh request.
                cfyr::Error::Expired => ErrorCode::ProofWindowElapsed,
                _ => ErrorCode::Reconcile,
            })?;
        let response: AccountServiceResponse =
            serde_json::from_value(response).map_err(|_| ErrorCode::Reconcile)?;
        let AccountServiceResponse::ApplyExtended {
            acceptance,
            certificate,
            ancestry,
        } = response
        else {
            return Err(ErrorCode::Reconcile);
        };
        let after = self.current().map_err(|_| ErrorCode::Reconcile)?;
        if after.material != before.material
            || after.material_digest != before.material_digest
            || after.grant != before.grant
        {
            return Err(ErrorCode::Reconcile);
        }
        let digest = verify_acceptance(
            &acceptance,
            signed,
            &after.material.extension_policy,
            &after.material.account_response_key,
        )
        .map_err(|_| ErrorCode::Reconcile)?;
        Ok(AcceptedResponse {
            acceptance,
            certificate,
            ancestry,
            digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(super) fn policy() -> ExtensionPolicy {
        ExtensionPolicy {
            revision: 1,
            public_record_quorum: 2,
            change_token_cost: 1,
            deposit_delay_seconds: 100,
            minimum_deposit_batch: 2,
            standing_policy_digest: [7; 32],
        }
    }

    fn statement() -> AccountStatement {
        let community: [u8; 32] = Sha256::digest(b"community").into();
        let policy = acct::AccountPolicy {
            initial_credit: 20,
            maximum_available: 100,
            outgoing_reservation: 5,
            incoming_reservation: 5,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 10_000,
            newcomer_period: 100,
            rate_window: 100,
            newcomer_admissions: 2,
            maximum_admissions: 10,
            refill_period: 100,
            refill_units: 2,
            abandon_after: 200,
        };
        let (mut root, mut next) = ([0; 32], [0; 32]);
        root[31] = 7;
        next[31] = 9;
        AccountStatement {
            protocol_version: 2,
            community,
            owner: [2; 32],
            policy_digest: policy.digest(&community).unwrap(),
            enrollment_root: root,
            now: 101,
            valid_until: 200,
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: next,
            settlement_marker: [0; 32],
            policy,
        }
    }

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    fn signed() -> SignedApplyExtended {
        let request = AccountRequest {
            statement: statement(),
            request_id: [0xA1; 32],
            proof_scope: AccountProofScope {
                circuit_digest: [0xC3; 32],
                verifying_key_digest: [0xD4; 32],
            },
            chat_public_key: B64.encode(&[7; 32]),
            issued_at: 101,
            expires_at: 150,
            proof: vec![1, 2, 3],
            signature: B64.encode(&[8; 64]),
        };
        SignedApplyExtended {
            request_digest: acct::account_request_digest(&request).unwrap(),
            extended_request_digest: extensions::extended_request_digest(
                &request,
                &genesis_update(),
                &policy(),
            )
            .unwrap(),
            request,
            update: genesis_update(),
            outbox: vec![1],
        }
    }

    /// A later (non-genesis) step: version 4 -> 5, consuming one queued obligation.
    pub(super) fn later_wire(n: u8) -> (Vec<u8>, ExtendedUpdate) {
        let mut statement = statement();
        statement.genesis = false;
        statement.previous_version = 4 + u64::from(n);
        statement.next_version = 5 + u64::from(n);
        statement.previous_state = [3; 32];
        let mut previous = Inbox::default();
        previous.root[0] = 1;
        let mut next = Inbox::default();
        next.root[0] = 2;
        let update = ExtendedUpdate {
            previous_inbox: previous,
            inbox: next,
            effect: Effect::Update,
        };
        let request = AccountRequest {
            statement,
            request_id: [0xA2 + n; 32],
            proof_scope: AccountProofScope {
                circuit_digest: [0xC3; 32],
                verifying_key_digest: [0xD4; 32],
            },
            chat_public_key: B64.encode(&[7; 32]),
            issued_at: 101,
            expires_at: 150,
            proof: vec![1, 2, 3],
            signature: B64.encode(&[8; 64]),
        };
        let grant = admission::AdmissionGrant {
            version: 1,
            issuer_key_id: "k".into(),
            community_id: "c".into(),
            member_id: B64.encode(&[2; 32]),
            pseudonym: "00".into(),
            chat_public_key: B64.encode(&[7; 32]),
            policy_digest: "p".into(),
            policy_epoch: 1,
            passport_policy_digest: "d".into(),
            issued_at: 1,
            expires_at: 1000,
            signature: "s".into(),
        };
        let authorization = admission::DeviceAuthorization {
            version: 1,
            community_id: "c".into(),
            member_id: B64.encode(&[2; 32]),
            root_public_key: B64.encode(&[1; 32]),
            device_public_key: B64.encode(&[7; 32]),
            issued_at: 1,
            expires_at: 1000,
            signature: "s".into(),
        };
        let wire = AccountServiceRequest::ApplyExtended {
            grant,
            authorization,
            request: Box::new(request),
            update: update.clone(),
        };
        (serde_json::to_vec(&wire).unwrap(), update)
    }

    pub(super) fn accept(request: &SignedApplyExtended, accepted_at: u64) -> AccountAcceptance {
        let mut acceptance = AccountAcceptance {
            statement: request.request.statement.clone(),
            request_id: request.request.request_id,
            request_digest: request.extended_request_digest,
            proof_scope: request.request.proof_scope.clone(),
            accepted_at,
            signature: String::new(),
        };
        let bytes = acct::account_acceptance_bytes(&acceptance).unwrap();
        acceptance.signature = B64.encode(&operator().sign(&bytes).to_bytes());
        acceptance
    }

    fn key() -> [u8; 32] {
        operator().verifying_key().to_bytes()
    }

    #[test]
    fn a_genesis_window_ends_at_the_code_window_or_the_statement_horizon_whichever_is_first() {
        let window = cblc::accounting::GENESIS_PROOF_WINDOW_SECONDS;
        let mut early = statement();
        early.valid_until = early.now + window + 50;
        assert_eq!(genesis_window_end(&early), early.now + window);
        // A proof time near the end of its rate window: the horizon cuts the window.
        let late = statement();
        assert!(late.valid_until < late.now + window);
        assert_eq!(genesis_window_end(&late), late.valid_until);
    }

    #[test]
    fn a_genesis_proof_travels_as_the_ledgers_single_step_update_bundle() {
        let state = [7u8; 32];
        let raw = [1u8, 2, 3, 250];
        let bundle: serde_json::Value =
            serde_json::from_slice(&genesis_bundle(&state, &raw).unwrap()).unwrap();
        let object = bundle.as_object().unwrap();
        assert_eq!(object.len(), 2);
        assert_eq!(bundle["version"], 1);
        let steps = bundle["proofs"].as_array().unwrap();
        assert_eq!(steps.len(), 1);
        let step = steps[0].as_object().unwrap();
        assert_eq!(step.len(), 3);
        assert_eq!(
            serde_json::from_value::<[u8; 32]>(step["state"].clone()).unwrap(),
            state
        );
        assert_eq!(
            serde_json::from_value::<[u8; 32]>(step["inbox"].clone()).unwrap(),
            Inbox::default().root
        );
        let proof = data_encoding::HEXLOWER
            .decode(step["proof"].as_str().unwrap().as_bytes())
            .unwrap();
        assert_eq!(proof, raw);
        // The raw proof bytes alone are not a bundle the ledger can read.
        assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());
    }

    #[test]
    fn the_acceptance_binds_the_extended_digest_not_the_plain_request_digest() {
        let request = signed();
        assert_ne!(request.request_digest, request.extended_request_digest);
        let accepted = accept(&request, 150);
        let digest = verify_acceptance(&accepted, &request, &policy(), &key()).unwrap();
        // State B's digest is distinct from both request digests.
        assert_ne!(digest, request.request_digest);
        assert_ne!(digest, request.extended_request_digest);
        assert_eq!(digest, acceptance_digest(&accepted).unwrap());
        // An acceptance of the plain digest is the wrong binding for ApplyExtended.
        let mut plain = accepted.clone();
        plain.request_digest = request.request_digest;
        let bytes = acct::account_acceptance_bytes(&plain).unwrap();
        plain.signature = B64.encode(&operator().sign(&bytes).to_bytes());
        assert!(verify_acceptance(&plain, &request, &policy(), &key()).is_err());
    }

    #[test]
    fn every_request_binding_policy_time_and_key_are_required() {
        let request = signed();
        let accepted = accept(&request, 150);
        let mut other = key();
        other[0] ^= 1;
        assert!(verify_acceptance(&accepted, &request, &policy(), &other).is_err());
        let mut changed_policy = policy();
        changed_policy.revision = 2;
        assert!(verify_acceptance(&accepted, &request, &changed_policy, &key()).is_err());
        let mut late = accepted.clone();
        late.accepted_at = 151;
        assert!(verify_acceptance(&late, &request, &policy(), &key()).is_err());
        for mutate in [
            (|a: &mut AccountAcceptance| a.request_id[0] ^= 1) as fn(&mut AccountAcceptance),
            |a| a.request_digest[0] ^= 1,
            |a| a.statement.next_state[0] ^= 1,
            |a| a.proof_scope.verifying_key_digest[0] ^= 1,
        ] {
            let mut changed = accepted.clone();
            mutate(&mut changed);
            assert!(verify_acceptance(&changed, &request, &policy(), &key()).is_err());
        }
    }

    #[test]
    fn a_binding_built_from_the_plain_request_digest_is_refused() {
        let request = signed();
        assert!(request
            .check_binding_digest(request.request_digest)
            .is_err());
        assert!(request.check_binding_digest([0; 32]).is_err());
        request
            .check_binding_digest(request.extended_request_digest())
            .unwrap();
    }

    #[test]
    fn outbox_must_be_a_genesis_apply_extended_wire() {
        for bytes in [
            Vec::new(),
            b"not json".to_vec(),
            br#"{"action":"obligations"}"#.to_vec(),
            vec![b' '; pending::MAX_OUTBOX + 1],
        ] {
            assert!(SignedApplyExtended::from_outbox(bytes, &policy()).is_err());
        }
    }

    #[test]
    fn a_later_update_outbox_is_refused_as_genesis_and_keeps_its_exact_update() {
        let (bytes, update) = later_wire(0);
        assert!(SignedApplyExtended::from_outbox(bytes.clone(), &policy()).is_err());
        let signed = SignedApplyExtended::from_update_outbox(bytes.clone(), &policy()).unwrap();
        assert_eq!(signed.update(), &update);
        assert!(!signed.statement().genesis);
        assert_eq!(signed.outbox(), bytes.as_slice());
        for bytes in [
            Vec::new(),
            b"not json".to_vec(),
            vec![b' '; pending::MAX_OUTBOX + 1],
        ] {
            assert!(SignedApplyExtended::from_update_outbox(bytes, &policy()).is_err());
        }
    }

    #[test]
    fn the_acceptance_is_checked_against_the_stored_update_not_the_genesis_one() {
        let mut request = signed();
        let (_, update) = later_wire(0);
        request.update = update;
        // The binding was computed for the genesis update, so it no longer matches.
        let accepted = accept(&request, 150);
        assert!(verify_acceptance(&accepted, &request, &policy(), &key()).is_err());
    }

    /// Stay in the flow: each update takes one root and one device admission, both
    /// local Door admissions released with their guards. Twenty updates in a row
    /// need no reserve, no replenishing and no user ceremony.
    #[test]
    fn twenty_updates_in_a_row_never_need_a_ceremony() {
        let binding = ckmg::Binding::new("garden", "member").unwrap();
        let device = ckmg::PublicKey::new(ckmg::VLD0, [1; 32]);
        let root = ckmg::PublicKey::new(ckmg::VLD0, [2; 32]);
        let (mut root_admission, mut root_verifier) = ckmg::intent_channel();
        let (mut device_admission, mut device_verifier) = ckmg::intent_channel();
        for round in 0..20u64 {
            let now = 1000 + round;
            for (admission, verifier, action) in [
                (
                    &mut root_admission,
                    &mut root_verifier,
                    ckmg::Action::AuthorizeAccountDevice,
                ),
                (
                    &mut device_admission,
                    &mut device_verifier,
                    ckmg::Action::SignDeviceEd25519,
                ),
            ] {
                let guard = admission
                    .admit(
                        ckmg::AdmittedCommand {
                            binding: binding.clone(),
                            origin: "https://garden.example.com".into(),
                            action,
                            device,
                            root: Some(root),
                            epoch: 3,
                            target: None,
                            statement: None,
                            transcript: Some(vec![round as u8]),
                            expires: 5000,
                        },
                        now,
                    )
                    .unwrap();
                let request = ckmg::Authorization {
                    binding: &binding,
                    root: Some(root),
                    device,
                    epoch: 3,
                    action,
                    target: None,
                    statement: None,
                    signing: Some(ckmg::DeviceSigning {
                        transcript: &[round as u8],
                        expires: 5000,
                    }),
                    now,
                    evidence: &[],
                };
                verifier
                    .consume(&request, "https://garden.example.com")
                    .unwrap();
                drop(guard);
            }
        }
    }
}

/// Values for the actor tests: a later-update request, its proven form and an
/// operator acceptance that verifies under the test key.
#[cfg(test)]
pub(in crate::door) mod fixtures {
    use super::*;

    pub fn signed(n: u8) -> SignedApplyExtended {
        let (bytes, _) = tests::later_wire(n);
        SignedApplyExtended::from_update_outbox(bytes, &tests::policy()).unwrap()
    }

    pub fn restore(outbox: Vec<u8>) -> SignedApplyExtended {
        SignedApplyExtended::from_update_outbox(outbox, &tests::policy()).unwrap()
    }

    pub fn proven(n: u8) -> ProvenUpdate {
        let signed = signed(n);
        ProvenUpdate {
            statement: signed.statement().clone(),
            scope: signed.request.proof_scope.clone(),
            proof: vec![1, 2, 3],
            update: signed.update().clone(),
        }
    }

    pub fn accepted(signed: &SignedApplyExtended, at: u64) -> AcceptedResponse {
        let acceptance = tests::accept(signed, at);
        AcceptedResponse {
            digest: acceptance_digest(&acceptance).unwrap(),
            certificate: StateCertificate {
                accepted_at: at,
                signature: vec![0; 64],
            },
            acceptance,
            ancestry: None,
        }
    }
}
