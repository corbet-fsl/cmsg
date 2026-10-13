//! Existing-device approval of one pairing request. Two explicit member steps with a
//! passkey ceremony between them (the ceremony runs on the member's own authenticator, in
//! the vault frame or the embedded authenticator, never here):
//!
//! 1. `pair_approve_begin`: the request is verified, then one step-up for exactly
//!    `device_authorize{request.device}` is begun on a held member lease.
//! 2. `pair_approve_finish`: the assertion is spent on that same lease (single use, fresh,
//!    for exactly that key), the server binds the key, the lease is released, and only then
//!    Keys adds the device under a distinct single-use `Pair` admission.
//!
//! Abort, expiry or any failure drops the pending approval; nothing is retried or reused.
//! While an approval is pending, the held lease blocks the member's other server calls, so
//! it expires after `APPROVAL_SECONDS`.
use super::*;
use crate::door::facades::PairApproved;
use cfyr::membership::{MembershipLease, StepUpAction, StepUpProof};
use serde_json::Value;

/// Longest a begun approval waits for the member's assertion.
pub const APPROVAL_SECONDS: u64 = 120;

/// One begun approval: the held lease and the exact request it was begun for.
pub(super) struct PendingApproval {
    lease: MembershipLease<foyer::Transport>,
    request: ckmg::PairingRequest,
    ceremony: String,
    expires: u64,
}

fn now() -> Result<u64> {
    ckmg::Clock::now(&mut custody::SystemClock).map_err(|_| ErrorCode::Clock)
}

impl Door {
    /// Step 1. Returns the server's step-up challenge (ceremony and WebAuthn options).
    pub async fn pair_approve_begin(
        &mut self,
        origin: &str,
        request: ckmg::PairingRequest,
    ) -> Result<Value> {
        // A new begin replaces and drops any earlier pending approval first.
        self.pairings.remove(origin);
        let at = now()?;
        request.verify(at).map_err(|_| ErrorCode::Unauthorized)?;
        if !self.vaults.contains_key(origin) {
            return Err(ErrorCode::Unavailable);
        }
        let mut membership = self.live_membership(origin)?;
        let mut lease = membership
            .observe_lease(|| now().unwrap_or(u64::MAX))
            .await
            .map_err(foyer::map_error)?;
        let answer = lease
            .step_up_begin(
                StepUpAction::DeviceAuthorize {
                    key: *request.device.value(),
                },
                || now().unwrap_or(u64::MAX),
            )
            .await
            .map_err(foyer::map_error)?;
        let ceremony = answer
            .get("ceremony")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::Reconcile)?
            .to_owned();
        self.pairings.insert(
            origin.into(),
            PendingApproval {
                lease,
                request,
                ceremony,
                expires: at.saturating_add(APPROVAL_SECONDS),
            },
        );
        Ok(answer)
    }

    /// Step 2. The member's assertion (the WebAuthn credential JSON) for the begun
    /// ceremony. Returns the committed approval; the caller sends the grant to the new
    /// device and has the member's passkey sign the receipt before publication.
    pub async fn pair_approve_finish(
        &mut self,
        origin: &str,
        credential: Value,
    ) -> Result<PairApproved> {
        let pending = self.pairings.remove(origin).ok_or(ErrorCode::Unavailable)?;
        let PendingApproval {
            mut lease,
            request,
            ceremony,
            expires,
        } = pending;
        if now()? >= expires {
            return Err(ErrorCode::Unavailable);
        }
        let proof = StepUpProof::new(ceremony, credential).map_err(foyer::map_error)?;
        lease
            .device_authorize(*request.device.value(), proof, || {
                now().unwrap_or(u64::MAX)
            })
            .await
            .map_err(foyer::map_error)?;
        // Keys' own authority check takes the same membership: release the lease first.
        drop(lease);
        let vault = self.vaults.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
        vault.pair_device(&request, origin).await
    }

    /// Drop a pending approval without using it.
    pub fn pair_approve_abort(&mut self, origin: &str) {
        self.pairings.remove(origin);
    }
}
