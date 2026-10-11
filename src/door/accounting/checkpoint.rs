//! Current original common enrollment verification; never historical admission.
use super::*;

/// Exact registry response retained with the original current admission owner.
/// Neither this receipt nor an HTTP success proves an installed account state.
pub struct SubmittedEnrollment<'p> {
    pub(super) prepared: PreparedEnrollment<'p>,
    pub(super) entry: enrollment::EnrollmentEntry,
}

/// A frozen slot can legitimately precede this member's enrollment. Waiting does
/// not extend the retained lease or grant; an expired owner must be reacquired.
pub enum CheckpointAcquisition<'p> {
    /// The authenticated complete current roster does not yet contain this owner.
    Pending {
        /// Same original owner, available only while its actual lease is live.
        enrollment: SubmittedEnrollment<'p>,
        /// Original signed slot end; a hint, never future eligibility authority.
        eligible_at: u64,
    },
    /// Every original delegation and the complete current common tree verified.
    Ready(CurrentEnrollment<'p>),
}

/// Current common publication plus its actual retained admission owner. This is
/// public enrollment context only: no private opening, proof or account acceptance.
/// There is deliberately no constructor from a parsed root or historical result.
pub struct CurrentEnrollment<'p> {
    enrolled: SubmittedEnrollment<'p>,
    publication: enrollment::EnrollmentPublication,
    failed: bool,
}

fn verify(
    publication: &enrollment::EnrollmentPublication,
    current: &CurrentAdmission,
    cohort: &Cohort,
    own: &enrollment::EnrollmentEntry,
) -> Result<(enrollment::EnrollmentTree, Option<usize>)> {
    let period = current.material.policy.checkpoint_period_seconds;
    let start = publication
        .slot
        .checked_mul(period)
        .ok_or(ErrorCode::Unauthorized)?;
    let end = publication
        .slot
        .checked_add(1)
        .and_then(|v| v.checked_mul(period))
        .ok_or(ErrorCode::Unauthorized)?;
    if publication.community_id != current.trust.community_id
        || publication.policy_digest != current.trust.policy_digest
        || period == 0
        || publication.not_before != start
        || publication.expires_at != end
        || current.now < start
        || current.now >= end
    {
        return Err(ErrorCode::Unauthorized);
    }
    publication
        .verify_signature(&current.material.account_response_key)
        .map_err(|_| ErrorCode::Unauthorized)?;
    let mut verified = Vec::with_capacity(publication.delegations.len());
    for row in &publication.delegations {
        if row.delegation.expires_at < end {
            return Err(ErrorCode::Unauthorized);
        }
        let value = enrollment::verify_delegation(
            &row.delegation,
            enrollment::ExpectedAdmission {
                trust: &current.trust,
                policy_epoch: cohort.epoch,
                passport_policy_digest: &cohort.digest,
            },
            current.now,
        )
        .map_err(|_| ErrorCode::Unauthorized)?;
        if enrollment::EnrollmentEntry::from_verified(&value) != row.entry {
            return Err(ErrorCode::Unauthorized);
        }
        verified.push(value);
    }
    let tree = enrollment::EnrollmentTree::from_verified(&verified)
        .map_err(|_| ErrorCode::Unauthorized)?;
    // The signed transcript sorts rows. Require their received order to be the
    // same canonical order before assigning a holder its original leaf position.
    if tree.root() != publication.root
        || tree
            .entries()
            .iter()
            .zip(&publication.delegations)
            .any(|(entry, row)| entry != &row.entry)
    {
        return Err(ErrorCode::Unauthorized);
    }
    let index = tree
        .entries()
        .iter()
        .position(|entry| entry.member_id == own.member_id);
    if let Some(index) = index {
        let entry = &tree.entries()[index];
        // A frozen slot may contain an earlier still-current renewal of the SAME
        // immutable account. Its actual leaf/digest remains the published one.
        if entry.account_key != own.account_key || entry.secret_hash != own.secret_hash {
            return Err(ErrorCode::Unauthorized);
        }
    }
    Ok((tree, index))
}

// All rows cover the entire publication slot. Reborrow the actual clock and
// owner AFTER potentially expensive whole-tree verification before any result.
fn final_cut(
    admission: &mut AccountAdmission<'_>,
    checked: &CurrentAdmission,
    publication: &enrollment::EnrollmentPublication,
) -> Result<u64> {
    let completed = admission.current()?;
    if completed.now < checked.now
        || completed.now >= publication.expires_at
        || completed.material != checked.material
        || completed.material_digest != checked.material_digest
        || completed.grant != checked.grant
    {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(completed.now)
}

impl<'p> SubmittedEnrollment<'p> {
    /// Fetch and verify the complete current publication, through the fixed
    /// original registry action. This never requests a caller-selected old slot.
    pub async fn current_checkpoint(mut self) -> Result<CheckpointAcquisition<'p>> {
        if self.prepared.expected_entry()? != self.entry {
            return Err(ErrorCode::Unauthorized);
        }
        let response = self
            .prepared
            .admission
            .lease
            .current_enrollment_checkpoint(now)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        let publication: Option<enrollment::EnrollmentPublication> =
            serde_json::from_value(response).map_err(|_| ErrorCode::Reconcile)?;
        let publication = publication.ok_or(ErrorCode::Unavailable)?;
        let current = self.prepared.admission.current()?;
        if self.prepared.expected_entry()? != self.entry {
            return Err(ErrorCode::Unauthorized);
        }
        let (_, selected) = verify(
            &publication,
            &current,
            &self.prepared.admission.cohort,
            &self.entry,
        )?;
        final_cut(&mut self.prepared.admission, &current, &publication)?;
        if selected.is_none() {
            return Ok(CheckpointAcquisition::Pending {
                eligible_at: publication.expires_at,
                enrollment: self,
            });
        }
        let mut result = CurrentEnrollment {
            enrolled: self,
            publication,
            failed: false,
        };
        result.with_current(|_, _, _, _| ())?;
        Ok(CheckpointAcquisition::Ready(result))
    }
}

impl<'p> CurrentEnrollment<'p> {
    /// The device authorization signed with the delegation, unchanged.
    pub(super) fn authorization(&self) -> &admission::DeviceAuthorization {
        &self.enrolled.prepared.delegation.authorization
    }

    /// The retained admission owner; every use re-authenticates around awaits.
    pub(super) fn admission_mut(&mut self) -> &mut AccountAdmission<'p> {
        &mut self.enrolled.prepared.admission
    }
}

impl CurrentEnrollment<'_> {
    /// Reobserve the real same-session HTTPS owner after external work, retaining
    /// this exact original publication. New slots/roots require a new preparation,
    /// never replacement of the context already used by a private proof.
    /// Cancellation or any uncertain/refused result permanently fences this owner.
    pub async fn refresh(&mut self) -> Result<()> {
        if self.failed {
            return Err(ErrorCode::Unauthorized);
        }
        self.failed = true;
        let response = self
            .enrolled
            .prepared
            .admission
            .lease
            .current_enrollment_checkpoint(now)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        let publication: Option<enrollment::EnrollmentPublication> =
            serde_json::from_value(response).map_err(|_| ErrorCode::Reconcile)?;
        let publication = publication.ok_or(ErrorCode::Unauthorized)?;
        if publication.signature != self.publication.signature
            || publication
                .signing_bytes()
                .map_err(|_| ErrorCode::Unauthorized)?
                != self
                    .publication
                    .signing_bytes()
                    .map_err(|_| ErrorCode::Unauthorized)?
        {
            return Err(ErrorCode::Unauthorized);
        }
        let current = self.enrolled.prepared.admission.current()?;
        let (_, index) = verify(
            &publication,
            &current,
            &self.enrolled.prepared.admission.cohort,
            &self.enrolled.entry,
        )?;
        index.ok_or(ErrorCode::Unauthorized)?;
        final_cut(
            &mut self.enrolled.prepared.admission,
            &current,
            &publication,
        )?;
        self.failed = false;
        Ok(())
    }

    /// Borrow only authenticated public context at a fresh original owner cut.
    /// The private holder must still match its own durable coordinate/opening,
    /// prove the original relation, receive acceptance and commit a real receipt.
    pub fn with_current<T>(
        &mut self,
        inspect: impl FnOnce(
            &enrollment::EnrollmentPublication,
            &enrollment::EnrollmentTree,
            usize,
            u64,
        ) -> T,
    ) -> Result<T> {
        self.with_verified(|publication, tree, index, current| {
            inspect(publication, tree, index, current.now)
        })
    }

    pub(super) fn with_verified<T>(
        &mut self,
        inspect: impl FnOnce(
            &enrollment::EnrollmentPublication,
            &enrollment::EnrollmentTree,
            usize,
            &CurrentAdmission,
        ) -> T,
    ) -> Result<T> {
        self.with_verified_completed(inspect)
            .map(|(output, _)| output)
    }

    pub(super) fn with_verified_completed<T>(
        &mut self,
        inspect: impl FnOnce(
            &enrollment::EnrollmentPublication,
            &enrollment::EnrollmentTree,
            usize,
            &CurrentAdmission,
        ) -> T,
    ) -> Result<(T, u64)> {
        if self.failed {
            return Err(ErrorCode::Unauthorized);
        }
        self.failed = true;
        let current = self.enrolled.prepared.admission.current()?;
        let (tree, index) = verify(
            &self.publication,
            &current,
            &self.enrolled.prepared.admission.cohort,
            &self.enrolled.entry,
        )?;
        let index = index.ok_or(ErrorCode::Unauthorized)?;
        final_cut(
            &mut self.enrolled.prepared.admission,
            &current,
            &self.publication,
        )?;
        let output = inspect(&self.publication, &tree, index, &current);
        let completed = self.enrolled.prepared.admission.current()?;
        if completed.material != current.material || completed.grant != current.grant {
            return Err(ErrorCode::Unauthorized);
        }
        verify(
            &self.publication,
            &completed,
            &self.enrolled.prepared.admission.cohort,
            &self.enrolled.entry,
        )?;
        let completed_at = final_cut(
            &mut self.enrolled.prepared.admission,
            &completed,
            &self.publication,
        )?;
        self.failed = false;
        Ok((output, completed_at))
    }
}
