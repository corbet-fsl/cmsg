//! Existing-device approval of one pairing request. The server binds the new device's key to
//! the NEW device's own passkey (one key per credential, so the existing device's passkey
//! cannot bind a second key), so the existing device's approval is only the Keys step: after
//! the member's explicit approval, Keys adds exactly the proven device under a distinct
//! single-use `Pair` admission. The member's user-verified assertion over the resulting
//! receipt, which the next step publishes, is the approval's passkey evidence.
use super::*;
use crate::door::facades::PairApproved;

fn now() -> Result<u64> {
    ckmg::Clock::now(&mut custody::SystemClock).map_err(|_| ErrorCode::Clock)
}

impl Door {
    /// Verify the request, then add exactly its device to the member's lineage. The
    /// caller sends the grant to the new device and has the member's passkey sign the
    /// receipt before publication.
    pub async fn pair_approve(
        &mut self,
        origin: &str,
        request: &ckmg::PairingRequest,
    ) -> Result<PairApproved> {
        request
            .verify(now()?)
            .map_err(|_| ErrorCode::Unauthorized)?;
        let vault = self.vaults.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
        vault.pair_device(request, origin).await
    }
}
