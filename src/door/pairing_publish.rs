//! Lineage revision above 1: the public evidence of a pairing is the ONE wallet stamp of the
//! pairing digest (the stamp the community accepted at `device_add`) AND the host device key's
//! signature over the same digest (`ckmg::PairingApproval`). The host's key must be in the
//! CURRENT lineage `devices`. This replaces the member passkey assertion over the receipt, so
//! approving a device costs the host exactly the one wallet confirmation. Nothing here
//! publishes or acknowledges: the caller retains the prepared evidence
//! (`Vault::retain_lineage_evidence`), publishes it to the member's own lineage record slot,
//! and only then acknowledges the receipt and approves the new key.
use super::device_pair::{PairingActions, PresentedStamp};
use super::*;
use cfyr::policy::CurrentPolicy;
use cwlt::passport::StampPresentation;
use foyer::Transport;

fn refused() -> ErrorCode {
    ErrorCode::Unauthorized
}

/// Build the public revision evidence for an approval receipt.
///
/// `devices` is this host's CURRENT lineage of the member (the anchor shown to the guest);
/// `host_signature` is the host device key's signature over exactly
/// `ckmg::PairingApproval::new(community, digest).message()`.
pub fn prepare_revision_evidence(
    policy: &mut CurrentPolicy<Transport>,
    stamps: &cvlt::StampTrust,
    devices: &ckmg::Lineage,
    receipt: &ckmg::Receipt,
    actions: &PairingActions,
    stamp: &PresentedStamp,
    host_signature: [u8; 64],
    clock: &mut impl ckmg::Clock,
) -> Result<cvlt::PreparedLineageEvidence> {
    if !matches!(receipt.change, ckmg::Change::DeviceAuthorized(_)) {
        return Err(refused());
    }
    let presentation = StampPresentation::from_bytes(&stamp.presentation).map_err(|_| refused())?;
    let now = clock.now().map_err(|_| ErrorCode::Clock)?;
    policy
        .with_current(now, |current| {
            cvlt::LineageEvidence::prepare_revision(
                current,
                stamps,
                devices,
                receipt,
                &presentation,
                actions.salt(),
                *actions.session(),
                host_signature,
                stamp.at,
                actions.member(),
                now,
            )
            .map_err(|_| refused())
        })
        .map_err(|_| refused())?
}
