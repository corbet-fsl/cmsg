//! Fixed whole-object transport into the original common-root record recipient.
use super::{custody::SystemClock, foyer::Transport, ErrorCode, Result};
use cblc::publication::PublicVerifierMaterial;
use cfyr::membership::{CommonRecordLease, Observation};
use ckmg::{Authority, Clock, Entropy};
use cvlt::{AccountSlot, Records, Vault};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use sha2::{Digest, Sha256};

/// Trusted embedding configuration, absent from all device request JSON. The
/// actual signed Rulebook supplies its value through the original CRBK owner.
/// A missing/null setting refuses; this type chooses no period or default.
pub struct RecordConfiguration {
    period_key: String,
}
impl RecordConfiguration {
    /// Retain the original host's explicitly configured record-period key.
    pub fn new(period_key: String) -> Result<Self> {
        if period_key.is_empty() || period_key.len() > 256 {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self { period_key })
    }
}

struct CurrentRecord {
    material: PublicVerifierMaterial,
    period: u64,
    owner: [u8; 32],
    member: String,
    scope: String,
    credential: Vec<u8>,
    origin: String,
    devices: Vec<[u8; 32]>,
}
fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

fn current(
    configuration: &RecordConfiguration,
    charter: &cchr::VerifiedCharter,
    member: &Observation,
    credential: &[u8],
    origin: &str,
    checked: u64,
) -> Result<CurrentRecord> {
    if charter.community() == "wallet" || credential.is_empty() || checked >= member.expires {
        return Err(ErrorCode::Unauthorized);
    }
    if charter
        .revocations()
        .passkey_revoked(credential)
        .map_err(|_| ErrorCode::Unauthorized)?
    {
        return Err(ErrorCode::Unauthorized);
    }
    let balance = charter.balance().ok_or(ErrorCode::Unavailable)?;
    if checked >= balance.valid_until() {
        return Err(ErrorCode::Unauthorized);
    }
    let material: PublicVerifierMaterial =
        serde_json::from_slice(balance.payload()).map_err(|_| ErrorCode::Unauthorized)?;
    material
        .validate_at(charter.community(), checked)
        .map_err(|_| ErrorCode::Unauthorized)?;
    if material.revision != balance.revision() || material.policy_epoch != charter.policy_epoch() {
        return Err(ErrorCode::Unauthorized);
    }
    let period = crbk::RecordEpochSettings::from_snapshot(
        charter
            .settings(checked)
            .map_err(|_| ErrorCode::Unauthorized)?,
        &configuration.period_key,
    )
    .map_err(|_| ErrorCode::Unauthorized)?
    .period_seconds;
    let epoch = material
        .record_epoch
        .as_ref()
        .ok_or(ErrorCode::Unavailable)?;
    let community: [u8; 32] = Sha256::digest(charter.community().as_bytes()).into();
    epoch
        .validate(&community, period)
        .map_err(|_| ErrorCode::Unauthorized)?;
    epoch
        .check_time(checked)
        .map_err(|_| ErrorCode::Unauthorized)?;
    let pseudonym: [u8; 48] = HEX
        .decode(member.member.as_bytes())
        .map_err(|_| ErrorCode::Unauthorized)?
        .try_into()
        .map_err(|_| ErrorCode::Unauthorized)?;
    let owner = B64
        .decode(cblc::admission::member_id(&pseudonym).as_bytes())
        .map_err(|_| ErrorCode::Unauthorized)?
        .try_into()
        .map_err(|_| ErrorCode::Unauthorized)?;
    Ok(CurrentRecord {
        material,
        period,
        owner,
        member: member.member.clone(),
        scope: charter.community().into(),
        credential: credential.to_vec(),
        origin: origin.into(),
        devices: member
            .device_keys
            .iter()
            .copied()
            .filter(|device| !charter.revocations().device_revoked(device))
            .collect(),
    })
}
impl CurrentRecord {
    fn check(&self, other: &Self, device: [u8; 32]) -> Result<()> {
        // A still-valid frozen frontier may be re-endorsed by newer material.
        // Its exact descriptor and the authenticated period/owner never change.
        if self.material.record_epoch != other.material.record_epoch
            || self.period != other.period
            || self.owner != other.owner
            || self.member != other.member
            || self.scope != other.scope
            || self.credential != other.credential
            || self.origin != other.origin
            || !other.devices.contains(&device)
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }
}

async fn account<B, C, E, A, R, W>(
    vault: &mut Vault<B, C, E, A, R, W>,
    expected: &CurrentRecord,
) -> Result<(
    ckmg::Lineage,
    ckmg::wallet_engine::account_key::Projection,
    [u8; 32],
)>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    W: AccountSlot,
{
    let projection = vault
        .account_projection()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let lineage = vault
        .keys()
        .lineage()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let reference = vault
        .keys()
        .device_info()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let device = *vault
        .keys()
        .device_public_key()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?
        .value();
    if lineage.binding.community() != expected.scope
        || lineage.binding.member() != expected.member
        || reference.authority_reference() != expected.credential
        || !expected.devices.contains(&device)
    {
        return Err(ErrorCode::Unauthorized);
    }
    Ok((lineage, projection, device))
}

/// Receive one opaque transport packet from the complete anonymous common object.
/// The source must be an independently authenticated same-key community Foyer:
/// Keys' retained lineage owner cannot re-lock its own held session guard.
/// No caller descriptor, owner hash, resource URL, private key or ciphertext
/// selector is accepted. This does not initialize an account or admit a proof.
pub async fn receive_common_record<B, C, E, A, R, W>(
    mut source: CommonRecordLease<'_, Transport>,
    vault: &mut Vault<B, C, E, A, R, W>,
    configuration: &RecordConfiguration,
) -> Result<ckmg::wallet_engine::ReceivedRecord>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    W: AccountSlot,
{
    let expected = source
        .with_current(now, |charter, member, credential, origin, checked| {
            current(configuration, charter, member, credential, origin, checked)
        })
        .map_err(|_| ErrorCode::Unauthorized)??;
    let original = account(vault, &expected).await?;
    let length = expected
        .material
        .record_epoch
        .as_ref()
        .ok_or(ErrorCode::Unavailable)?
        .download_bytes
        .try_into()
        .map_err(|_| ErrorCode::Unavailable)?;
    let object = source
        .download(length, now)
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    if account(vault, &expected).await? != original {
        return Err(ErrorCode::Unauthorized);
    }
    let received = vault
        .keys()
        .with_record_recipient(|recipient| {
            source
                .with_current(now, |charter, member, credential, origin, checked| {
                    let observed =
                        current(configuration, charter, member, credential, origin, checked)?;
                    expected.check(&observed, original.2)?;
                    let epoch = observed
                        .material
                        .record_epoch
                        .as_ref()
                        .ok_or(ErrorCode::Unavailable)?;
                    // Authenticate the real descriptor and full object digest BEFORE HPKE.
                    epoch
                        .check_object(&object)
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    recipient
                        .receive(epoch, observed.period, observed.owner, &object, checked)
                        .map_err(|_| ErrorCode::Unauthorized)
                })
                .map_err(|_| ErrorCode::Unauthorized)?
        })
        .await
        .map_err(|_| ErrorCode::Unauthorized)??;
    if account(vault, &expected).await? != original {
        return Err(ErrorCode::Unauthorized);
    }
    let (observed, completed) = source
        .with_current_checked(now, |charter, member, credential, origin, checked| {
            let observed = current(configuration, charter, member, credential, origin, checked)?;
            expected.check(&observed, original.2)?;
            received
                .check(
                    observed
                        .material
                        .record_epoch
                        .as_ref()
                        .ok_or(ErrorCode::Unavailable)?,
                    observed.owner,
                    checked,
                )
                .map_err(|_| ErrorCode::Unauthorized)?;
            Ok::<_, ErrorCode>(observed)
        })
        .map_err(|_| ErrorCode::Unauthorized)?;
    let observed = observed?;
    observed
        .material
        .validate_at(&observed.scope, completed)
        .map_err(|_| ErrorCode::Unauthorized)?;
    received
        .check(
            observed
                .material
                .record_epoch
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?,
            observed.owner,
            completed,
        )
        .map_err(|_| ErrorCode::Unauthorized)?;
    // No await follows the original owner completion sample/object lifetime cut.
    Ok(received)
}

/// Prove this epoch's record from a received packet and cache it in the Vault
/// (decided 2026-10-05: once per epoch, in the background; members never wait on
/// it at a Forum). A ready cache returns at once. The epoch key is persisted
/// before proving, the proof runs on a blocking worker without the Store, and
/// only the verified prover output is committed.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub async fn prove_received_record<B, C, E, A, R>(
    vault: &mut Vault<B, C, E, A, R, cvlt::WalletCustody>,
    received: &ckmg::wallet_engine::ReceivedRecord,
    prover: &ckmg::wallet_engine::native_prover::NativeProver,
) -> Result<()>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    let operation = || -> Result<[u8; 32]> {
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| ErrorCode::Unavailable)?;
        Ok(id)
    };
    let epoch = received.epoch().clone();
    if vault
        .record_ready(&epoch, now())
        .await
        .map_err(|_| ErrorCode::Unauthorized)?
    {
        return Ok(());
    }
    let accepted = vault
        .restore_accepted_account()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let key = vault
        .begin_record_epoch(&epoch, accepted.owner(), now(), operation()?)
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let evidence = accepted
        .record_epoch(received, key, now())
        .map_err(|_| ErrorCode::Unauthorized)?;
    let record = evidence.record().clone();
    let prover = prover.clone();
    let proof = tokio::task::spawn_blocking(move || prover.prove_record_epoch(&evidence))
        .await
        .map_err(|_| ErrorCode::Unavailable)?
        .map_err(|_| ErrorCode::Unavailable)?;
    vault
        .finish_record_epoch(record, proof, operation()?)
        .await
        .map_err(|_| ErrorCode::Unauthorized)
}
