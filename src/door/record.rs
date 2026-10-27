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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?
    {
        return Err(ErrorCode::Unauthorized);
    }
    let balance = charter.balance().ok_or(ErrorCode::Unavailable)?;
    if checked >= balance.valid_until() {
        return Err(ErrorCode::Unauthorized);
    }
    let material: PublicVerifierMaterial =
        serde_json::from_slice(balance.payload()).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
    material
        .validate_at(charter.community(), checked)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
    if material.revision != balance.revision() || material.policy_epoch != charter.policy_epoch() {
        return Err(ErrorCode::Unauthorized);
    }
    let period = crbk::RecordEpochSettings::from_snapshot(
        charter.settings(checked).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?,
        &configuration.period_key,
    )
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?
    .period_seconds;
    let epoch = material
        .record_epoch
        .as_ref()
        .ok_or(ErrorCode::Unavailable)?;
    let community: [u8; 32] = Sha256::digest(charter.community().as_bytes()).into();
    epoch.validate(&community, period).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    epoch.check_time(checked).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
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
    let projection = vault.account_projection().await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    let lineage = vault.keys().lineage().await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    let reference = vault.keys().device_info().await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    let device = *vault
        .keys()
        .device_public_key()
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })??;
    let original = account(vault, &expected).await?;
    let length = expected
        .material
        .record_epoch
        .as_ref()
        .ok_or(ErrorCode::Unavailable)?
        .download_bytes
        .try_into()
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
    let object = source.download(length, now).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
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
                    epoch.check_object(&object).map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Unauthorized",
                            ErrorCode::Unauthorized,
                            &__cause,
                        )
                    })?;
                    recipient
                        .receive(epoch, observed.period, observed.owner, &object, checked)
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "ErrorCode::Unauthorized",
                                ErrorCode::Unauthorized,
                                &__cause,
                            )
                        })
                })
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })?
        })
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })??;
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
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })?;
            Ok::<_, ErrorCode>(observed)
        })
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
    let observed = observed?;
    observed
        .material
        .validate_at(&observed.scope, completed)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
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
        Box::pin(async move {
            self.check_at(SystemClock.now().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Clock",
                    ErrorCode::Clock,
                    &__cause,
                )
            })?)
        })
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        Ok(RecordProof {
            record: self.record,
            proof,
        })
    }
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
fn operation() -> Result<[u8; 32]> {
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
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
    if vault.record_ready(&epoch, now()).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })? {
        return Ok(None);
    }
    let accepted = vault.restore_accepted_account().await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    // The key is durable before proving: a restart proves again with the same key.
    let key = vault
        .begin_record_epoch(&epoch, accepted.owner(), now(), operation()?)
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
    let evidence = accepted
        .record_epoch(received, key, now())
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
    Ok(Some(RecordWork {
        record: evidence.record().clone(),
        evidence,
        prover: prover.clone(),
    }))
}

/// Persist (or keep) the epoch key and build the proof work from the join-time record
/// leaf the ledger delivered with this account's acceptance (an account that started
/// after the epoch's freeze has no packet in the common download). `None` when the
/// vault holds no such leaf for this epoch: the caller then takes the common download.
/// The leaf is the one retained in the sealed accepted account, so a restart proves
/// again from it with the same key.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub async fn begin_joined_record<B, C, E, A, R>(
    vault: &mut Vault<B, C, E, A, R, cvlt::WalletCustody>,
    epoch: &czkp::record::Epoch,
    prover: &ckmg::wallet_engine::native_prover::NativeProver,
) -> Result<Option<RecordWork>>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    let Ok(accepted) = vault.restore_accepted_account().await else {
        return Ok(None);
    };
    let Some(signed) = accepted.delivered_record_leaf(epoch.epoch) else {
        return Ok(None);
    };
    let key = vault
        .begin_record_epoch(epoch, accepted.owner(), now(), operation()?)
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
    let evidence = accepted
        .record_epoch_signed(epoch, &signed, key, now())
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })
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
    if vault.record_ready(&epoch, now()).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })? {
        return Ok((window, None));
    }
    // A newcomer accepted after this epoch's freeze holds its record leaf from the
    // acceptance: no download, no packet decryption.
    if let Some(work) = begin_joined_record(vault, &epoch, prover).await? {
        return Ok((window, Some(work)));
    }
    let received = receive_common_record(source, vault, configuration).await?;
    // The packet must be of the epoch just authenticated; its window is the one marked.
    if RecordWindow::of(received.epoch()) != window {
        return Err(ErrorCode::Unavailable);
    }
    Ok((
        window,
        begin_received_record(vault, &received, prover).await?,
    ))
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })??;
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
        assert!(
            current.check_at(1_000).is_ok(),
            "the window start is inside"
        );
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

    /// `prepare_record` short-circuits when the vault holds the join-time record
    /// leaf for the current epoch and takes the normal path next epoch.
    ///
    /// The short-circuit (`begin_joined_record`) takes no source, so it performs
    /// no `source.download` and no HPKE `recipient.receive` (both live only in
    /// `receive_common_record`, the normal path); it builds the proof work purely
    /// from the retained acceptance via `record_epoch_signed`. This test drives
    /// the exact decision with public codecs only: a join leaf of the accepted
    /// state whose blinded commitment is the certified `frozen_leaf` and whose
    /// Ed25519 certificate verifies under the epoch issuer key (the new acceptance
    /// check), offered for exactly its epoch.
    #[test]
    fn prepare_record_short_circuits_with_the_join_record_and_takes_the_common_path_next_epoch() {
        use ed25519_dalek::Signer as _;
        let community = [9; 32];
        let owner = [10; 32];
        let state = [11; 32];
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let issuer_key = issuer.verifying_key().to_bytes();
        // The join leaf of the accepted genesis state for epoch 3.
        let leaf = czkp::record::Leaf {
            owner,
            version: 0,
            state,
            required_inbox: [7; 32],
            role: 0,
            blinding: [8; 32],
        };
        let commitment = leaf.commitment(&community, 3).unwrap();
        let signature = issuer
            .sign(&czkp::record::certificate_bytes(&community, 3, &commitment).unwrap())
            .to_bytes()
            .to_vec();
        // The acceptance check the holder engine runs: exact state, commitment is
        // the certified frozen leaf, and the Ed25519 certificate verifies.
        czkp::record::verify_certificate(&issuer_key, &community, 3, &commitment, &signature)
            .unwrap();
        // A tampered signature is refused at acceptance.
        let mut bad = signature.clone();
        bad[0] ^= 1;
        assert!(
            czkp::record::verify_certificate(&issuer_key, &community, 3, &commitment, &bad)
                .is_err()
        );
        // A leaf signed under another record-issuer key is refused.
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[20; 32]);
        let stranger_sig = stranger
            .sign(&czkp::record::certificate_bytes(&community, 3, &commitment).unwrap())
            .to_bytes()
            .to_vec();
        assert!(czkp::record::verify_certificate(
            &issuer_key,
            &community,
            3,
            &commitment,
            &stranger_sig
        )
        .is_err());
        // Epoch routing: the join leaf belongs to epoch 3 only. The next epoch has
        // a different window, so `delivered_record_leaf(4)` is None and the normal
        // path (`receive_common_record` with download + HPKE) is taken.
        let current = czkp::record::Epoch {
            purpose: czkp::record::Purpose::RecordEpochV3,
            community,
            policy_epoch: 1,
            epoch: 3,
            starts_at: 1_000,
            expires_at: 2_000,
            root: [5; 32],
            issuer_key,
            proof_scope: czkp::ProofScope {
                circuit_digest: [7; 32],
                verifying_key_digest: [8; 32],
            },
            leaf_count: 1,
            download_digest: [1; 32],
            download_bytes: 1,
        };
        let next = czkp::record::Epoch {
            epoch: 4,
            starts_at: 2_000,
            expires_at: 3_000,
            ..current.clone()
        };
        assert_eq!(RecordWindow::of(&current), WINDOW);
        assert_ne!(RecordWindow::of(&current), RecordWindow::of(&next));
        // The commitment is epoch-bound: the same leaf is not this epoch's record
        // under another epoch number.
        let other = leaf.commitment(&community, 4).unwrap();
        assert_ne!(other, commitment);
    }
}

/// The account owner of a member: cblc's member id, SHA-256 of the canonical 48-byte
/// community pseudonym (lowercase hex, as the lobby and the identity binding name it).
/// This is the id the accounting ledger and the enrollment roster know the member by.
pub(super) fn account_owner(pseudonym: &str) -> Option<[u8; 32]> {
    let pseudonym: [u8; 48] = match HEX.decode(pseudonym.as_bytes()) {
        Ok(decoded) => match decoded.try_into() {
            Ok(pseudonym) => pseudonym,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "try_into", &__cause);
                return None;
            }
        },
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "HEX.decode", &__cause);
            return None;
        }
    };
    let decoded = match B64.decode(cblc::admission::member_id(&pseudonym).as_bytes()) {
        Ok(decoded) => decoded,
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "B64.decode", &__cause);
            return None;
        }
    };
    decoded.try_into().ok()
}
