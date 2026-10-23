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
    let owner = account_owner(&member.member).ok_or(ErrorCode::Unauthorized)?;
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

/// The epoch the community's current signed material names, authenticated exactly
/// as a reception would authenticate it, read before any download so a ready
/// cache costs no transfer.
pub fn current_epoch(
    source: &mut CommonRecordLease<'_, Transport>,
    configuration: &RecordConfiguration,
) -> Result<czkp::record::Epoch> {
    source
        .with_current(now, |charter, member, credential, origin, checked| {
            current(configuration, charter, member, credential, origin, checked)?
                .material
                .record_epoch
                .ok_or(ErrorCode::Unavailable)
        })
        .map_err(|_| ErrorCode::Unauthorized)?
}

/// The validity window of one record epoch, as the community's current signed
/// material names it (public data: no record, key or proof).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordWindow {
    pub starts_at: u64,
    /// Exclusive.
    pub expires_at: u64,
}

impl RecordWindow {
    fn of(epoch: &czkp::record::Epoch) -> Self {
        Self {
            starts_at: epoch.starts_at,
            expires_at: epoch.expires_at,
        }
    }
}

/// G2 for the member's own record: the epoch whose record the background job last
/// found (or made) cached in the Vault, for the authenticated current epoch. It is
/// marked only after that check; the wave ports read it while the Door is locked,
/// so they never call the account actor themselves. Empty until the first check.
#[derive(Clone, Default)]
pub struct RecordCurrent(std::sync::Arc<std::sync::Mutex<Option<RecordWindow>>>);

impl RecordCurrent {
    /// The job saw this epoch's record cached for the current signed epoch.
    pub fn mark(&self, window: RecordWindow) {
        if let Ok(mut current) = self.0.lock() {
            *current = Some(window);
        }
    }

    /// `Ok` only while `now` lies inside the window of the epoch last found cached:
    /// past its end a newer epoch commitment exists and the cached record is stale.
    pub fn check_at(&self, now: u64) -> Result<()> {
        let window = self
            .0
            .lock()
            .map_err(|_| ErrorCode::Unavailable)?
            .ok_or(ErrorCode::Unavailable)?;
        if now < window.starts_at || now >= window.expires_at {
            return Err(ErrorCode::Unavailable);
        }
        Ok(())
    }
}

/// The wave ports' G2 check: this member's own record matches the newest epoch
/// commitment (decided G2 rows: per community and epoch, staleness bounded by one
/// epoch). The ports are bound per member origin, as is this cell.
impl super::inbox_waves::production::OwnRecordCheck for RecordCurrent {
    fn check<'a>(&'a self, _binding: &'a ckmg::Binding) -> super::facades::OwnedFuture<'a, ()> {
        Box::pin(async move { self.check_at(SystemClock.now().map_err(|_| ErrorCode::Clock)?) })
    }
}

/// What the trusted embedding lends the background record job: the record-period
/// key of the signed Rulebook, the record-epoch prover of the retained group, and
/// the G2 cell the job marks after each successful check.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub struct RecordJob {
    pub configuration: RecordConfiguration,
    pub prover: ckmg::wallet_engine::native_prover::NativeProver,
    pub current: RecordCurrent,
}

/// One begun epoch whose proof is still to be made: owned data only, so the
/// proof runs off the Store, the account actor and the Door.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub struct RecordWork {
    evidence: ckmg::wallet_engine::account::RecordEpochEvidence,
    record: cwlt::record::Record,
    prover: ckmg::wallet_engine::native_prover::NativeProver,
}

/// The verified prover output of one [`RecordWork`], ready to commit.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub struct RecordProof {
    record: cwlt::record::Record,
    proof: String,
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
impl RecordWork {
    /// Prove (blocking, seconds). Nothing is committed here.
    pub fn prove(self) -> Result<RecordProof> {
        let proof = self
            .prover
            .prove_record_epoch(&self.evidence)
            .map_err(|_| ErrorCode::Unavailable)?;
        Ok(RecordProof {
            record: self.record,
            proof,
        })
    }
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
fn operation() -> Result<[u8; 32]> {
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(|_| ErrorCode::Unavailable)?;
    Ok(id)
}

/// Persist (or keep) the epoch key of a received packet and build the proof work.
/// `None` when this epoch's record is already cached.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub async fn begin_received_record<B, C, E, A, R>(
    vault: &mut Vault<B, C, E, A, R, cvlt::WalletCustody>,
    received: &ckmg::wallet_engine::ReceivedRecord,
    prover: &ckmg::wallet_engine::native_prover::NativeProver,
) -> Result<Option<RecordWork>>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    let epoch = received.epoch().clone();
    if vault
        .record_ready(&epoch, now())
        .await
        .map_err(|_| ErrorCode::Unauthorized)?
    {
        return Ok(None);
    }
    let accepted = vault
        .restore_accepted_account()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    // The key is durable before proving: a restart proves again with the same key.
    let key = vault
        .begin_record_epoch(&epoch, accepted.owner(), now(), operation()?)
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let evidence = accepted
        .record_epoch(received, key, now())
        .map_err(|_| ErrorCode::Unauthorized)?;
    Ok(Some(RecordWork {
        record: evidence.record().clone(),
        evidence,
        prover: prover.clone(),
    }))
}

/// Commit a verified proof for the begun epoch; presentations become available.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub async fn finish_record<B, C, E, A, R>(
    vault: &mut Vault<B, C, E, A, R, cvlt::WalletCustody>,
    proof: RecordProof,
) -> Result<()>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    vault
        .finish_record_epoch(proof.record, proof.proof, operation()?)
        .await
        .map_err(|_| ErrorCode::Unauthorized)
}

/// The per-epoch preparation the background job runs: skip when the current
/// epoch is cached, otherwise receive this epoch's packet from the independent
/// source and begin it. Interrupted anywhere, the next run starts over silently.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub async fn prepare_record<B, C, E, A, R>(
    mut source: CommonRecordLease<'_, Transport>,
    vault: &mut Vault<B, C, E, A, R, cvlt::WalletCustody>,
    configuration: &RecordConfiguration,
    prover: &ckmg::wallet_engine::native_prover::NativeProver,
) -> Result<(RecordWindow, Option<RecordWork>)>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    let epoch = current_epoch(&mut source, configuration)?;
    let window = RecordWindow::of(&epoch);
    if vault
        .record_ready(&epoch, now())
        .await
        .map_err(|_| ErrorCode::Unauthorized)?
    {
        return Ok((window, None));
    }
    let received = receive_common_record(source, vault, configuration).await?;
    // The packet must be of the epoch just authenticated; its window is the one marked.
    if RecordWindow::of(received.epoch()) != window {
        return Err(ErrorCode::Unavailable);
    }
    Ok((window, begin_received_record(vault, &received, prover).await?))
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
    let Some(work) = begin_received_record(vault, received, prover).await? else {
        return Ok(());
    };
    let proof = tokio::task::spawn_blocking(move || work.prove())
        .await
        .map_err(|_| ErrorCode::Unavailable)??;
    finish_record(vault, proof).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::inbox_waves::production::OwnRecordCheck;

    const WINDOW: RecordWindow = RecordWindow {
        starts_at: 1_000,
        expires_at: 2_000,
    };

    #[test]
    fn g2_refuses_until_the_job_marked_a_cached_epoch() {
        let current = RecordCurrent::default();
        assert_eq!(current.check_at(1_500).err(), Some(ErrorCode::Unavailable));
        current.mark(WINDOW);
        assert!(current.check_at(1_000).is_ok(), "the window start is inside");
        assert!(current.check_at(1_999).is_ok());
    }

    #[test]
    fn g2_refuses_outside_the_marked_epoch_window() {
        let current = RecordCurrent::default();
        current.mark(WINDOW);
        assert_eq!(current.check_at(999).err(), Some(ErrorCode::Unavailable));
        assert_eq!(
            current.check_at(2_000).err(),
            Some(ErrorCode::Unavailable),
            "past the end a newer epoch commitment exists"
        );
        // The next epoch's mark replaces the old window; the clones share the cell.
        let seen = current.clone();
        current.mark(RecordWindow {
            starts_at: 2_000,
            expires_at: 3_000,
        });
        assert!(seen.check_at(2_500).is_ok());
        assert!(seen.check_at(1_500).is_err());
    }

    #[tokio::test]
    async fn the_port_checks_against_the_device_clock() {
        let binding = ckmg::Binding::new("omega", &"ab".repeat(48)).unwrap();
        let current = RecordCurrent::default();
        assert!(current.check(&binding).await.is_err());
        let now = SystemClock.now().unwrap();
        current.mark(RecordWindow {
            starts_at: now - 10,
            expires_at: now + 3_600,
        });
        assert!(current.check(&binding).await.is_ok());
        current.mark(RecordWindow {
            starts_at: now - 3_600,
            expires_at: now - 1,
        });
        assert!(current.check(&binding).await.is_err());
    }

    #[test]
    fn the_account_owner_is_the_sha256_of_the_48_byte_pseudonym() {
        let pseudonym = [7u8; 48];
        let expected: [u8; 32] = Sha256::digest(pseudonym).into();
        assert_eq!(account_owner(&HEX.encode(&pseudonym)), Some(expected));
        // A 32-byte id or no hex at all is not a pseudonym.
        assert_eq!(account_owner(&HEX.encode(&[7u8; 32])), None);
        assert_eq!(account_owner("not hex"), None);
    }
}

/// The account owner of a member: cblc's member id, SHA-256 of the canonical 48-byte
/// community pseudonym (lowercase hex, as the lobby and the identity binding name it).
/// This is the id the accounting ledger and the enrollment roster know the member by.
pub(super) fn account_owner(pseudonym: &str) -> Option<[u8; 32]> {
    let pseudonym: [u8; 48] = HEX.decode(pseudonym.as_bytes()).ok()?.try_into().ok()?;
    B64.decode(cblc::admission::member_id(&pseudonym).as_bytes())
        .ok()?
        .try_into()
        .ok()
}
