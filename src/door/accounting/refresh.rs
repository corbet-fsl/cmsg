//! The daily re-issue of the account delegation (decision (b), part 3).
//!
//! A delegation is valid as long as its admission grant (<= 1 day), not the
//! session lease, so the device re-signs it when the grant renews: at most once
//! per policy-signed grant day, never outside a current admission (a lease that
//! ended or a revoked device signs nothing), and after a crash it resends the
//! identical bytes, which the registry accepts again without a second record.
//!
//! The device keeps the last delegation it signed in its own Vault record
//! (`delegation_outbox`): one state byte, the digest of the member's lineage it was
//! signed under, and the exact delegation bytes. The record is written BEFORE the
//! delegation is sent (persist-before-send) and replaced only by compare-and-swap.
//!
//! A lineage change (a device added, removed or revoked) also re-signs at once, not
//! at the next grant day: the registry holds one row per member, the last device's,
//! so after that device is revoked a surviving one must take the row back, or the
//! member has no roster row until the next day (review M3; the design keeps a member
//! in the roster while any of their devices is current).
use super::*;

const SENT: u8 = 1;
const REGISTERED: u8 = 2;

/// The policy-signed day and epoch of an admission grant. Device clocks never
/// decide the day: `issued_at` is `day(now)` on the policy's side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::door) struct GrantDay {
    pub issued_at: u64,
    pub policy_epoch: u64,
}

impl GrantDay {
    fn of(grant: &admission::AdmissionGrant) -> Self {
        Self {
            issued_at: grant.issued_at,
            policy_epoch: grant.policy_epoch,
        }
    }

    /// Whether a delegation made under `self` is replaced under `fresh`: a later
    /// grant day, or another policy epoch.
    fn renewed_by(self, fresh: GrantDay) -> bool {
        fresh.issued_at > self.issued_at || fresh.policy_epoch != self.policy_epoch
    }
}

/// The digest of the member's lineage (`ckmg::Lineage::digest`: revision, root and devices).
pub(in crate::door) type LineageDigest = [u8; 32];

/// One stored delegation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::door) struct Stored {
    registered: bool,
    lineage: LineageDigest,
    delegation: Vec<u8>,
    day: GrantDay,
}

impl Stored {
    /// Read a record; an unreadable one is `None` (the device then signs anew).
    pub(in crate::door) fn parse(record: &[u8]) -> Option<Self> {
        let (&state, rest) = record.split_first()?;
        let registered = match state {
            SENT => false,
            REGISTERED => true,
            _ => return None,
        };
        let (lineage, delegation) = rest.split_first_chunk::<32>()?;
        let parsed: enrollment::AccountingDelegation = serde_json::from_slice(delegation).ok()?;
        Some(Self {
            registered,
            lineage: *lineage,
            delegation: delegation.to_vec(),
            day: GrantDay::of(&parsed.admission),
        })
    }
}

/// The record that says `delegation`, signed under `lineage`, is about to be (or was) sent.
pub(in crate::door) fn sent(lineage: &LineageDigest, delegation: &[u8]) -> Vec<u8> {
    [&[SENT][..], lineage, delegation].concat()
}

/// The record that says the registry accepted `delegation`, signed under `lineage`.
pub(in crate::door) fn registered(lineage: &LineageDigest, delegation: &[u8]) -> Vec<u8> {
    [&[REGISTERED][..], lineage, delegation].concat()
}

/// What one login does with the delegation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::door) enum Step {
    /// The registered delegation belongs to the current grant day.
    Nothing,
    /// A signed delegation whose answer was lost: send the identical bytes again.
    Resend(Vec<u8>),
    /// Sign a new delegation under the fresh admission.
    Sign,
}

/// The decision, from the stored record, the fresh admission's grant day and the
/// member's current lineage. `resendable` says whether stored bytes still verify
/// under the fresh admission and cover now.
pub(in crate::door) fn decide(
    stored: Option<&Stored>,
    fresh: GrantDay,
    lineage: &LineageDigest,
    resendable: impl FnOnce(&[u8]) -> bool,
) -> Step {
    match stored {
        None => Step::Sign,
        Some(stored) if stored.day.renewed_by(fresh) => Step::Sign,
        // Another device was added, removed or revoked since: take the member's row back.
        Some(stored) if stored.lineage != *lineage => Step::Sign,
        Some(stored) if stored.registered => Step::Nothing,
        Some(stored) if resendable(&stored.delegation) => Step::Resend(stored.delegation.clone()),
        Some(_) => Step::Sign,
    }
}

/// The resend rule of a stored `Sent` delegation (review M2, as the design states it): only
/// when the fresh admission's grant is exactly the one the delegation carries, and now is
/// before its end. A grant re-signed for the same day and epoch is not the stored one: the
/// device then signs anew instead of resending bytes made under another grant.
fn resend_allowed(
    fresh: &admission::AdmissionGrant,
    now: u64,
    delegation: &enrollment::AccountingDelegation,
) -> bool {
    *fresh == delegation.admission && now < delegation.expires_at
}

/// The outcome of one login's refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::door) enum Refreshed {
    Current,
    Resent,
    Issued,
}

/// The device side of one refresh, under one fresh admission.
pub(in crate::door) trait Delegations {
    /// The stored record (exact bytes), `None` when none is stored.
    async fn record(&mut self) -> Result<Option<Vec<u8>>>;
    /// Replace the record by compare-and-swap against `expected`.
    async fn replace(&mut self, expected: Option<&[u8]>, record: &[u8]) -> Result<()>;
    /// The fresh admission's grant day.
    fn grant(&mut self) -> Result<GrantDay>;
    /// The digest of the member's current lineage.
    async fn lineage(&mut self) -> Result<LineageDigest>;
    /// Whether these stored delegation bytes verify under the fresh admission and cover now.
    fn resendable(&mut self, delegation: &[u8]) -> bool;
    /// Sign a new delegation under the fresh admission (sends nothing).
    async fn sign(&mut self) -> Result<Vec<u8>>;
    /// Send these exact delegation bytes to the registry and check its answer.
    async fn send(&mut self, delegation: &[u8]) -> Result<()>;
}

/// Re-issue the delegation when the grant renewed, else resend a delegation
/// whose answer was lost, else nothing. A failure leaves the record as it is for
/// the next login.
pub(in crate::door) async fn refresh<D: Delegations>(device: &mut D) -> Result<Refreshed> {
    let raw = device.record().await?;
    let stored = raw.as_deref().and_then(Stored::parse);
    let fresh = device.grant()?;
    let lineage = device.lineage().await?;
    match decide(stored.as_ref(), fresh, &lineage, |bytes| {
        device.resendable(bytes)
    }) {
        Step::Nothing => Ok(Refreshed::Current),
        Step::Resend(delegation) => {
            device.send(&delegation).await?;
            device
                .replace(raw.as_deref(), &registered(&lineage, &delegation))
                .await?;
            Ok(Refreshed::Resent)
        }
        Step::Sign => {
            let delegation = device.sign().await?;
            let pending = sent(&lineage, &delegation);
            device.replace(raw.as_deref(), &pending).await?;
            device.send(&delegation).await?;
            device
                .replace(Some(&pending), &registered(&lineage, &delegation))
                .await?;
            Ok(Refreshed::Issued)
        }
    }
}

impl AccountAdmission<'_> {
    /// The grant day of this admission, after fresh verification.
    pub(in crate::door) fn grant_day(&mut self) -> Result<GrantDay> {
        Ok(GrantDay::of(&self.current()?.grant))
    }

    /// The registry entry `delegation` verifies to under this admission's
    /// current policy (the check every enrollment send makes).
    pub(super) fn verified_entry(
        &mut self,
        delegation: &enrollment::AccountingDelegation,
    ) -> Result<enrollment::EnrollmentEntry> {
        let current = self.current()?;
        let verified = enrollment::verify_delegation(
            delegation,
            enrollment::ExpectedAdmission {
                trust: &current.trust,
                policy_epoch: self.cohort.epoch,
                passport_policy_digest: &self.cohort.digest,
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
        Ok(enrollment::EnrollmentEntry::from_verified(&verified))
    }

    /// Whether stored delegation bytes verify under this admission, were made under exactly
    /// its fresh grant, and cover now (the design's resend rule).
    pub(in crate::door) fn resendable(&mut self, delegation: &[u8]) -> bool {
        serde_json::from_slice::<enrollment::AccountingDelegation>(delegation)
            .ok()
            .is_some_and(|delegation| {
                self.verified_entry(&delegation).is_ok()
                    && self.current().is_ok_and(|current| {
                        resend_allowed(&current.grant, current.now, &delegation)
                    })
            })
    }

    /// Send stored delegation bytes again over this admission's lease. The
    /// registry accepts byte-identical bytes without a second record; the answer
    /// must be exactly the entry these bytes verify to.
    pub(in crate::door) async fn resubmit(&mut self, delegation: &[u8]) -> Result<()> {
        let delegation: enrollment::AccountingDelegation = serde_json::from_slice(delegation)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::InvalidRequest",
                    ErrorCode::InvalidRequest,
                    &__cause,
                )
            })?;
        let expected = self.verified_entry(&delegation)?;
        let wire = serde_json::to_value(&delegation).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let response = Box::pin(submit_with_resend(&mut self.lease, wire)).await?;
        let response: enrollment::EnrollmentEntry =
            serde_json::from_value(response).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?;
        if response != expected {
            return Err(ErrorCode::Reconcile);
        }
        Ok(())
    }
}

impl PreparedEnrollment<'_> {
    /// The exact signed delegation bytes this enrollment sends.
    pub(in crate::door) fn delegation_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.delegation).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })
    }
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
