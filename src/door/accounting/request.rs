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

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
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
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
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
        if update != genesis_update() || !request.statement.genesis {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(Self {
            request_digest: acct::account_request_digest(&request)
                .map_err(|_| ErrorCode::Unauthorized)?,
            extended_request_digest: extensions::extended_request_digest(&request, &update, policy)
                .map_err(|_| ErrorCode::Unauthorized)?,
            request: *request,
            outbox,
        })
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
        &genesis_update(),
        policy,
        operator_key,
    )
    .map_err(|_| ErrorCode::Unauthorized)?;
    if acceptance.request_digest != expected.extended_request_digest {
        return Err(ErrorCode::Unauthorized);
    }
    acceptance_digest(acceptance)
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
                || current.now >= statement.valid_until
            {
                return Err(ErrorCode::Unauthorized);
            }
            Ok(Snapshot {
                grant: current.grant.clone(),
                origin: current.origin.clone(),
                expires: current.expires,
                now: current.now,
                max_authorization: current.material.policy.max_authorization_seconds,
                extension_policy: current.material.extension_policy.clone(),
            })
        })??;
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
            proof_scope: genesis.scope.clone(),
            chat_public_key: current.grant.chat_public_key.clone(),
            issued_at: statement.now,
            expires_at,
            proof: genesis.proof.clone(),
            signature: String::new(),
        };
        let transcript =
            acct::account_request_bytes(&request).map_err(|_| ErrorCode::Unauthorized)?;
        account.check(&current.origin).await?;
        let lineage = account
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = account
            .vault
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if lineage.binding.community() != self.admission_mut().cohort.scope
            || lineage.binding.member() != self.admission_mut().cohort.member
            || device.value() != &self.admission_mut().cohort.device
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
            .vault
            .keys()
            .sign_device_ed25519_current(&transcript, expires_at)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        request.signature = B64.encode(&signature);
        // Both owners must still be current after the signing awaits.
        account.check(&current.origin).await?;
        let after = self.admission_mut().current()?;
        if after.grant != current.grant
            || after.origin != current.origin
            || after.now >= expires_at
            || after.expires < expires_at
        {
            return Err(ErrorCode::Unauthorized);
        }
        let request_digest =
            acct::account_request_digest(&request).map_err(|_| ErrorCode::Unauthorized)?;
        let update = genesis_update();
        let extended_request_digest =
            extensions::extended_request_digest(&request, &update, &current.extension_policy)
                .map_err(|_| ErrorCode::Unauthorized)?;
        let wire = AccountServiceRequest::ApplyExtended {
            grant: current.grant,
            authorization,
            request: Box::new(request.clone()),
            update,
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
        })
    }

    /// Send the exact stored outbox once through the held HTTPS owner and verify
    /// the actual response: the operator signature under the pinned key, and the
    /// request identity, digest, statement and scope. Any failure after sending
    /// is uncertain (Reconcile); retry re-sends the same bytes, never a rebuilt
    /// request. A verified response is still not custody.
    pub async fn send_genesis_request(
        &mut self,
        signed: &SignedApplyExtended,
    ) -> Result<AcceptedResponse> {
        let before = self.admission_mut().current()?;
        let wire: serde_json::Value =
            serde_json::from_slice(&signed.outbox).map_err(|_| ErrorCode::Unauthorized)?;
        let response = self
            .admission_mut()
            .lease
            .apply_account(wire, now)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
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
        let after = self
            .admission_mut()
            .current()
            .map_err(|_| ErrorCode::Reconcile)?;
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

    fn policy() -> ExtensionPolicy {
        ExtensionPolicy {
            revision: 1,
            public_record_quorum: 2,
            change_token_cost: 1,
            deposit_delay_seconds: 100,
            minimum_deposit_batch: 2,
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
            outbox: vec![1],
        }
    }

    fn accept(request: &SignedApplyExtended, accepted_at: u64) -> AccountAcceptance {
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
}
