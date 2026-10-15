//! Private account preparation from the actual current enrollment owner.
use super::*;
use ckmg::wallet_engine::account::{
    AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext, VoucherBond,
};

/// Same original private candidate and current enrollment. No private opening,
/// proof, request, initialized wallet or caller-selected context is exposed.
pub struct PreparedAccount<'p> {
    enrollment: CurrentEnrollment<'p>,
    candidate: cwlt::account_owner::AccountGenesis,
    context: GenesisContext,
    material: cblc::publication::PublicVerifierMaterial,
    material_digest: [u8; 32],
    origin: String,
    failed: bool,
}

fn hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    HEX.decode(value.as_bytes())
        .map_err(|_| ErrorCode::Unauthorized)?
        .try_into()
        .map_err(|_| ErrorCode::Unauthorized)
}

/// The wallet engine's view of the community's signed account policy.
pub(super) fn engine_account_policy(policy: &cblc::accounting::AccountPolicy) -> AccountPolicy {
    AccountPolicy {
        initial_credit: policy.initial_credit,
        maximum_available: policy.maximum_available,
        outgoing_reservation: policy.outgoing_reservation,
        incoming_reservation: policy.incoming_reservation,
        policy_revision: policy.policy_revision,
        policy_valid_from: policy.policy_valid_from,
        policy_valid_until: policy.policy_valid_until,
        newcomer_period: policy.newcomer_period,
        rate_window: policy.rate_window,
        newcomer_admissions: policy.newcomer_admissions,
        maximum_admissions: policy.maximum_admissions,
        refill_period: policy.refill_period,
        refill_units: policy.refill_units,
        abandon_after: policy.abandon_after,
    }
}

/// The wallet engine's view of the community's signed extension policy.
pub(super) fn engine_extension_policy(
    extension: &cblc::extensions::ExtensionPolicy,
) -> ExtensionPolicy {
    ExtensionPolicy {
        revision: extension.revision,
        quorum: extension.public_record_quorum,
        change_cost: extension.change_token_cost,
        delay: extension.deposit_delay_seconds,
        batch: extension.minimum_deposit_batch,
        standing: extension.standing_policy_digest,
    }
}

fn context(
    publication: &enrollment::EnrollmentPublication,
    tree: &enrollment::EnrollmentTree,
    index: usize,
    current: &CurrentAdmission,
    prepared_at: Option<u64>,
    bond: Option<VoucherBond>,
) -> Result<GenesisContext> {
    let row = tree.entries().get(index).ok_or(ErrorCode::Unauthorized)?;
    if row.member_id != current.grant.member_id {
        return Err(ErrorCode::Unauthorized);
    }
    let member = B64
        .decode(row.member_id.as_bytes())
        .map_err(|_| ErrorCode::Unauthorized)?
        .try_into()
        .map_err(|_| ErrorCode::Unauthorized)?;
    let policy = &current.material.policy.account;
    let extension = &current.material.extension_policy;
    Ok(GenesisContext {
        community_id: current.trust.community_id.clone(),
        owner: member,
        policy: engine_account_policy(policy),
        extension: engine_extension_policy(extension),
        // The parameters of the community's verified rulebook. The engine refuses the
        // genesis unless their digest equals `extension.standing`, so a community that
        // tuned them differently is refused, never silently accepted.
        standing: current.standing,
        // Read once from the vouchee's custody at preparation; refreshes compare
        // against the same value. A founder has none.
        bond,
        enrollment: Enrollment {
            member,
            key: hex(&row.account_key)?,
            secret_hash: hex(&row.secret_hash)?,
            starts_at: row.issued_at,
            expires_at: row.expires_at,
            delegation_digest: hex(&row.delegation_digest)?,
            leaf: *tree.leaves().get(index).ok_or(ErrorCode::Unauthorized)?,
            index: index.try_into().map_err(|_| ErrorCode::Unauthorized)?,
            path: *tree.paths().get(index).ok_or(ErrorCode::Unauthorized)?,
        },
        enrollment_root: publication.root,
        // Rechecking preserves the original proof time; it never changes the
        // opening's rate window or extends its original validity horizon.
        checked_at: prepared_at.unwrap_or(current.now),
    })
}

impl<'p> CurrentEnrollment<'p> {
    /// Join the actual complete current common tree and signed economic policy
    /// with the existing receipt-installed private account key. Both remote and
    /// local owners revalidate after awaits; ordinary Use cannot create a key.
    pub async fn prepare_account<B, C, E, A, R>(
        mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
    ) -> Result<PreparedAccount<'p>>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        self.refresh().await?;
        // The sponsor's member id and the shared bond secret, when this account
        // was admitted by a voucher; they live in the Vault beside the link bonds.
        let bond = account
            .voucher_custody()
            .await
            .ok()
            .flatten()
            .and_then(|raw| {
                super::super::vouching::Book::decode(Some(raw.as_slice()))
                    .ok()?
                    .vouchee_bond()
            })
            .map(|(sponsor, secret)| VoucherBond { sponsor, secret });
        let (context, material, material_digest, origin, checked) =
            self.with_verified(|publication, tree, index, current| {
                Ok::<_, ErrorCode>((
                    context(publication, tree, index, current, None, bond.clone())?,
                    current.material.clone(),
                    current.material_digest,
                    current.origin.clone(),
                    current.now,
                ))
            })??;
        account.check(&origin).await?;
        let candidate = account.vault().await?
            .prepare_community_genesis(context.clone(), checked)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let mut prepared = PreparedAccount {
            enrollment: self,
            candidate,
            context,
            material,
            material_digest,
            origin,
            failed: false,
        };
        prepared.refresh(account).await?;
        Ok(prepared)
    }
}

impl PreparedAccount<'_> {
    /// Reobserve the original HTTPS enrollment and local durable key without
    /// replacing the private candidate, common root, artifact group or policy.
    /// Cancellation or any refusal permanently consumes this preparation.
    pub async fn refresh<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
    ) -> Result<()>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        if self.failed {
            return Err(ErrorCode::Unauthorized);
        }
        self.failed = true;
        let mut attempt = Attempt {
            candidate: &self.candidate,
            completed: false,
        };
        self.enrollment.refresh().await?;
        let checked = self
            .enrollment
            .with_verified(|publication, tree, index, current| {
                let observed = context(
                    publication,
                    tree,
                    index,
                    current,
                    Some(self.context.checked_at),
                    self.context.bond.clone(),
                )?;
                if observed != self.context
                    || current.material != self.material
                    || current.material_digest != self.material_digest
                    || current.origin != self.origin
                {
                    return Err(ErrorCode::Unauthorized);
                }
                Ok::<_, ErrorCode>(current.now)
            })??;
        account.check(&self.origin).await?;
        account.vault().await?
            .check_community_genesis(&self.candidate, &self.context, checked)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        self.enrollment.refresh().await?;
        account.check(&self.origin).await?;
        // The final current owner cut follows all external work. A later proof
        // path must recheck again and durably retain its exact private candidate
        // and outbox before exposing any signed account request.
        let (final_now, completed_at) =
            self.enrollment
                .with_verified_completed(|publication, tree, index, current| {
                    let observed = context(
                        publication,
                        tree,
                        index,
                        current,
                        Some(self.context.checked_at),
                        self.context.bond.clone(),
                    )?;
                    if observed != self.context
                        || current.material != self.material
                        || current.material_digest != self.material_digest
                        || current.origin != self.origin
                        || current.now < checked
                    {
                        return Err(ErrorCode::Unauthorized);
                    }
                    Ok::<_, ErrorCode>(current.now)
                })?;
        let final_now = final_now?;
        let horizon = self
            .material
            .policy
            .account
            .proof_valid_until(self.context.checked_at)
            .map_err(|_| ErrorCode::Unauthorized)?;
        if final_now < checked
            || completed_at < final_now
            || completed_at >= horizon
            || completed_at >= self.context.enrollment.expires_at
        {
            return Err(ErrorCode::Unauthorized);
        }
        attempt.completed = true;
        self.failed = false;
        Ok(())
    }
}

struct Attempt<'a> {
    candidate: &'a cwlt::account_owner::AccountGenesis,
    completed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.candidate.invalidate();
        }
    }
}

/// Operation identifiers for Store commits; random, non-zero, never reused.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub(super) fn operation() -> Result<[u8; 32]> {
    let mut id = [0u8; 32];
    getrandom::fill(&mut id).map_err(|_| ErrorCode::Unavailable)?;
    if id == [0; 32] {
        return Err(ErrorCode::Unavailable);
    }
    Ok(id)
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use proven::{ProvenAccount, StagedRequest};

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
mod proven {
    //! The proven candidate, the signed request and the durable pending state A/B.
    use super::*;
    use ckmg::wallet_engine::{account as engine, native_prover::NativeProver};
    use cwlt::account_owner::AccountGenesisProof;

    /// The original private candidate after the bounded native proof, still bound
    /// to the same current enrollment owner. Neither a request nor custody yet.
    pub struct ProvenAccount<'p> {
        enrollment: CurrentEnrollment<'p>,
        proof: AccountGenesisProof,
        context: GenesisContext,
        material: cblc::publication::PublicVerifierMaterial,
        material_digest: [u8; 32],
        origin: String,
    }

    /// The exact signed request that state A committed. Sending it again is safe.
    pub struct StagedRequest {
        pub(super) signed: SignedApplyExtended,
    }

    impl<'p> PreparedAccount<'p> {
        /// Prove the candidate with the bounded original native prover under the
        /// account's Keys authority. Consumes the preparation: a refusal or a
        /// cancellation ends it for good. Both owners are rechecked afterwards.
        pub async fn prove<B, C, E, A, R>(
            mut self,
            account: &mut CommunityAccount<B, C, E, A, R>,
            prover: &NativeProver,
        ) -> Result<ProvenAccount<'p>>
        where
            B: cwst::backend::Backend,
            C: Clock,
            E: Entropy,
            A: Authority,
            R: Records,
        {
            self.refresh(account).await?;
            let Self {
                enrollment,
                candidate,
                context,
                material,
                material_digest,
                origin,
                ..
            } = self;
            let proof = account.vault().await?
                .prove_community_genesis(candidate, &context, prover, || Ok(now()))
                .await
                .map_err(|_| ErrorCode::Unauthorized)?;
            let mut proven = ProvenAccount {
                enrollment,
                proof,
                context,
                material,
                material_digest,
                origin,
            };
            proven.refresh(account).await?;
            Ok(proven)
        }
    }

    impl ProvenAccount<'_> {
        /// Reobserve the same HTTPS enrollment, publication, policy and origin and
        /// the local Keys; any difference from what the proof was made under refuses.
        pub async fn refresh<B, C, E, A, R>(
            &mut self,
            account: &mut CommunityAccount<B, C, E, A, R>,
        ) -> Result<u64>
        where
            B: cwst::backend::Backend,
            C: Clock,
            E: Entropy,
            A: Authority,
            R: Records,
        {
            self.enrollment.refresh().await?;
            let checked =
                self.enrollment
                    .with_verified(|publication, tree, index, current| {
                        let observed = context(
                            publication,
                            tree,
                            index,
                            current,
                            Some(self.context.checked_at),
                        self.context.bond.clone(),
                        )?;
                        if observed != self.context
                            || current.material != self.material
                            || current.material_digest != self.material_digest
                            || current.origin != self.origin
                        {
                            return Err(ErrorCode::Unauthorized);
                        }
                        Ok::<_, ErrorCode>(current.now)
                    })??;
            account.check(&self.origin).await?;
            Ok(checked)
        }

        /// Sign the account request once, bind it to this exact account and commit
        /// state A with the outbox in ONE Store commit. After this returns, a crash
        /// is recovered by `account_reopen`, never by signing or proving again.
        pub async fn stage<B, C, E, A, R>(
            &mut self,
            account: &mut CommunityAccount<B, C, E, A, R>,
            intent: &mut ckmg::IntentAdmission,
        ) -> Result<StagedRequest>
        where
            B: cwst::backend::Backend,
            C: Clock,
            E: Entropy,
            A: Authority,
            R: Records,
        {
            let checked = self.refresh(account).await?;
            let policy = self.material.policy.account.clone();
            let genesis = {
                let material = account.vault().await?
                    .community_genesis_material(&self.proof, &self.context, checked)
                    .await
                    .map_err(|_| ErrorCode::Unauthorized)?;
                ProvenGenesis::from_material(&material, &policy)?
            };
            let signed = self
                .enrollment
                .sign_genesis_request(account, &genesis, intent)
                .await?;
            let pending = account
                .pending_binding(self.material_digest, signed.outbox())
                .await?;
            let binding = engine::PendingGenesisBinding {
                acceptance: signed.acceptance_binding(self.material.account_response_key),
                extended_acceptance_digest: None,
                response: None,
                upper: pending.encode()?,
            };
            account.vault().await?
                .stage_pending_genesis(
                    &self.proof,
                    &binding,
                    signed.outbox().to_vec(),
                    operation()?,
                    now(),
                )
                .await
                .map_err(|_| ErrorCode::Reconcile)?;
            Ok(StagedRequest { signed })
        }

        /// Send the staged outbox, verify the actual response and advance the
        /// durable companion to state B. Any failure is uncertain (Reconcile);
        /// state A stays and `account_reopen` re-sends the identical bytes.
        pub async fn send<B, C, E, A, R>(
            &mut self,
            account: &mut CommunityAccount<B, C, E, A, R>,
            staged: &StagedRequest,
        ) -> Result<u64>
        where
            B: cwst::backend::Backend,
            C: Clock,
            E: Entropy,
            A: Authority,
            R: Records,
        {
            let response = self.enrollment.send_genesis_request(&staged.signed).await?;
            let trust = self
                .enrollment
                .with_verified(|_, _, _, current| response_trust(&current.material))
                .map_err(|_| ErrorCode::Reconcile)?
                .map_err(|_| ErrorCode::Reconcile)?;
            account.vault().await?
                .advance_pending_genesis(&response.to_engine()?, &trust, operation()?, now())
                .await
                .map_err(|_| ErrorCode::Reconcile)?;
            Ok(response.acceptance().accepted_at)
        }
    }
}
