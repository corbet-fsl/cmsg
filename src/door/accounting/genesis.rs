//! Private account preparation from the actual current enrollment owner.
use super::*;
use ckmg::wallet_engine::account::{AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext};

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

fn context(
    publication: &enrollment::EnrollmentPublication,
    tree: &enrollment::EnrollmentTree,
    index: usize,
    current: &CurrentAdmission,
    prepared_at: Option<u64>,
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
        policy: AccountPolicy {
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
        },
        extension: ExtensionPolicy {
            revision: extension.revision,
            quorum: extension.public_record_quorum,
            change_cost: extension.change_token_cost,
            delay: extension.deposit_delay_seconds,
            batch: extension.minimum_deposit_batch,
        },
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
        let (context, material, material_digest, origin, checked) =
            self.with_verified(|publication, tree, index, current| {
                Ok::<_, ErrorCode>((
                    context(publication, tree, index, current, None)?,
                    current.material.clone(),
                    current.material_digest,
                    current.origin.clone(),
                    current.now,
                ))
            })??;
        account.check(&origin).await?;
        let candidate = account
            .vault
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
        account
            .vault
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
