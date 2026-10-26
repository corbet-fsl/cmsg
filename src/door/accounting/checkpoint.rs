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
    /// End of the genesis proof window that began in this publication's slot, or 0
    /// before a genesis was prepared. Only a genesis may outlive its slot.
    grace: u64,
    failed: bool,
}

fn verify(
    publication: &enrollment::EnrollmentPublication,
    current: &CurrentAdmission,
    cohort: &Cohort,
    own: &enrollment::EnrollmentEntry,
    grace: u64,
) -> Result<(enrollment::EnrollmentTree, Option<usize>)> {
    let tree = verify_tree(publication, current, cohort, grace)?;
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

/// The complete current publication verified at `current`: slot, community, policy,
/// signature, every delegation and the canonical tree. No member position.
/// `grace` is the end of a genesis proof window that began in this slot (0 for
/// every other use): the publication stays usable until the later of the slot end
/// and that window end, because a genesis gets its full window from its start.
fn verify_tree(
    publication: &enrollment::EnrollmentPublication,
    current: &CurrentAdmission,
    cohort: &Cohort,
    grace: u64,
) -> Result<enrollment::EnrollmentTree> {
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
        || current.now >= end.max(grace)
    {
        return Err(ErrorCode::Unauthorized);
    }
    publication
        .verify_signature(&current.material.account_response_key)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        if enrollment::EnrollmentEntry::from_verified(&value) != row.entry {
            return Err(ErrorCode::Unauthorized);
        }
        verified.push(value);
    }
    let tree = enrollment::EnrollmentTree::from_verified(&verified).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
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
    Ok(tree)
}

// All rows cover the entire publication slot. Reborrow the actual clock and
// owner AFTER potentially expensive whole-tree verification before any result.
fn final_cut(
    admission: &mut AccountAdmission<'_>,
    checked: &CurrentAdmission,
    publication: &enrollment::EnrollmentPublication,
    grace: u64,
) -> Result<u64> {
    let completed = admission.current()?;
    if completed.now < checked.now
        || completed.now >= publication.expires_at.max(grace)
        || completed.material != checked.material
        || completed.material_digest != checked.material_digest
        || completed.grant != checked.grant
    {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(completed.now)
}

impl<'p> SubmittedEnrollment<'p> {
    /// The retained admission owner of this registered delegation.
    pub fn admission_mut(&mut self) -> &mut AccountAdmission<'p> {
        &mut self.prepared.admission
    }

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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
        let publication: Option<enrollment::EnrollmentPublication> =
            serde_json::from_value(response).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
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
            0,
        )?;
        final_cut(&mut self.prepared.admission, &current, &publication, 0)?;
        // A genesis gets its full proof window from its start, also across the end of
        // this slot, so a late start is no reason to wait for the next slot.
        if selected.is_none() {
            return Ok(CheckpointAcquisition::Pending {
                eligible_at: publication.expires_at,
                enrollment: self,
            });
        }
        let mut result = CurrentEnrollment {
            enrolled: self,
            publication,
            grace: 0,
            failed: false,
        };
        result.with_current(|_, _, _, _| ())?;
        Ok(CheckpointAcquisition::Ready(result))
    }
}

impl<'p> CurrentEnrollment<'p> {
    /// Let this enrollment outlive its checkpoint slot until `until`, the end of the genesis
    /// proof window that began in it. Never shortens a window already granted.
    pub(super) fn extend_to(&mut self, until: u64) {
        self.grace = self.grace.max(until);
    }

    /// The device authorization signed with the delegation, unchanged.
    pub(super) fn authorization(&self) -> &admission::DeviceAuthorization {
        &self.enrolled.prepared.delegation.authorization
    }

    /// The retained admission owner; every use re-authenticates around awaits.
    pub fn admission_mut(&mut self) -> &mut AccountAdmission<'p> {
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
        let publication: Option<enrollment::EnrollmentPublication> =
            serde_json::from_value(response).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
        let publication = publication.ok_or(ErrorCode::Unauthorized)?;
        let current = self.enrolled.prepared.admission.current()?;
        let same = publication.signature == self.publication.signature
            && publication.signing_bytes().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unauthorized",
                    ErrorCode::Unauthorized,
                    &__cause,
                )
            })? == self.publication.signing_bytes().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unauthorized",
                    ErrorCode::Unauthorized,
                    &__cause,
                )
            })?;
        if same {
            let (_, index) = verify(
                &publication,
                &current,
                &self.enrolled.prepared.admission.cohort,
                &self.enrolled.entry,
                self.grace,
            )?;
            index.ok_or(ErrorCode::Unauthorized)?;
            final_cut(
                &mut self.enrolled.prepared.admission,
                &current,
                &publication,
                self.grace,
            )?;
        } else {
            // The operator moved on to a later slot while a genesis proved inside its
            // window. The proof stays bound to the retained original publication (the
            // operator keeps every slot's checkpoint), so the newer one is only checked
            // as an authentic later publication of the same community; it replaces
            // nothing. Outside such a window a different publication still refuses.
            if self.grace == 0
                || publication.slot <= self.publication.slot
                || publication.community_id != current.trust.community_id
                || publication.policy_digest != current.trust.policy_digest
                || current.now >= self.grace
            {
                return Err(ErrorCode::Unauthorized);
            }
            publication
                .verify_signature(&current.material.account_response_key)
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })?;
        }
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
            self.grace,
        )?;
        let index = index.ok_or(ErrorCode::Unauthorized)?;
        final_cut(
            &mut self.enrolled.prepared.admission,
            &current,
            &self.publication,
            self.grace,
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
            self.grace,
        )?;
        let completed_at = final_cut(
            &mut self.enrolled.prepared.admission,
            &completed,
            &self.publication,
            self.grace,
        )?;
        self.failed = false;
        Ok((output, completed_at))
    }
}

/// The verified current common roster as the wave wallet reads it: every row of the
/// current publication with its leaf and path, under the published root. Public
/// data only; valid until the publication's slot ends.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub struct VerifiedRoster {
    pub checkpoint: std::sync::Arc<ckmg::wallet_engine::account::Checkpoint>,
    /// Exclusive end of the publication slot.
    pub expires_at: u64,
}

/// Every row of a verified tree, in published order, as wallet roster rows.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
fn roster_rows(
    tree: &enrollment::EnrollmentTree,
) -> Result<Vec<ckmg::wallet_engine::account::Enrollment>> {
    (0..tree.entries().len())
        .map(|index| super::genesis::roster_row(tree, index))
        .collect()
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
impl AccountAdmission<'_> {
    /// The complete current common roster for an ACTIVE member, through the fixed
    /// original registry action of this admission: the same signature, slot, policy
    /// and per-delegation checks as an enrollment's own checkpoint, and this member's
    /// own row must be in it (an account outside the current roster has no wave).
    pub async fn current_roster(&mut self) -> Result<VerifiedRoster> {
        let response = self
            .lease
            .current_enrollment_checkpoint(now)
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
        let publication: Option<enrollment::EnrollmentPublication> =
            serde_json::from_value(response).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
        let publication = publication.ok_or(ErrorCode::Unavailable)?;
        let current = self.current()?;
        let tree = verify_tree(&publication, &current, &self.cohort, 0)?;
        if !tree
            .entries()
            .iter()
            .any(|entry| entry.member_id == current.grant.member_id)
        {
            return Err(ErrorCode::Unavailable);
        }
        let rows = roster_rows(&tree)?;
        final_cut(self, &current, &publication, 0)?;
        let checkpoint =
            ckmg::wallet_engine::account::Checkpoint::from_rows(publication.root, rows).map_err(
                |__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                },
            )?;
        Ok(VerifiedRoster {
            checkpoint: std::sync::Arc::new(checkpoint),
            expires_at: publication.expires_at,
        })
    }
}
