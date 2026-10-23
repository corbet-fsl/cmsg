//! Recovery publication of one actual acknowledged initial operation.
use super::initial::SharedClock;
use super::*;

/// Dedicated current same-key authority for the one authenticated initial ACK.
/// Construction is restricted to original recovery composition. Fixed account
/// device authorization additionally requires a separately enabled exact intent;
/// no general root signer, creation or arbitrary certificate adoption exists.
pub struct InitialRecoveryAuthority<'a, 'p, C, N: cdht::Network> {
    pub(super) candidate: &'a cvlt::AcknowledgedInitialCandidate,
    pub(super) initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    pub(super) clock: C,
    pub(super) records: Option<cvlt::LineageRecords<cvlt::TorLineageRecord<'a, N>>>,
    pub(super) closed: bool,
    pub(super) account_intent: Option<ckmg::IntentVerifier>,
    pub(super) delegation_intent: Option<ckmg::IntentVerifier>,
    /// Third single-use channel: the account request signature. Both it and the
    /// delegation are `SignDeviceEd25519`, so they are told apart by order: the
    /// delegation is always signed first and its attempt (success or refusal)
    /// is spent before this channel is consulted. One approval never covers
    /// two signatures.
    pub(super) request_intent: Option<ckmg::IntentVerifier>,
    pub(super) delegation_spent: bool,
    pub(super) account_signing: Option<(Action, Vec<u8>, u64)>,
    /// The wallet's stamp trust for a device-key member, whose genesis evidence is a stamp
    /// and whose lease holds its device key instead of a passkey certificate. Present exactly
    /// when the lease is a device lease (`lease.device_key()`); the passkey path keeps None.
    pub(super) stamps: Option<cvlt::StampTrust>,
}
/// Which single-use account channel one account Keys call consumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountChannel {
    Root,
    Delegation,
    Request,
}

/// A root authorization (`AuthorizeAccountDevice`) consumes the root channel
/// and starts a new delegation round, as the member owner does: the first
/// device signature after it is the delegation (spent by that attempt whatever
/// its outcome), every later one the account request. Without the reset, a
/// later round (a record-recipient registration after the account request) would
/// consult the request channel, find nothing admitted, and the refusal locks
/// the Keys.
fn account_channel(authorize: bool, delegation_spent: &mut bool) -> AccountChannel {
    if authorize {
        *delegation_spent = false;
        AccountChannel::Root
    } else if *delegation_spent {
        AccountChannel::Request
    } else {
        *delegation_spent = true;
        AccountChannel::Delegation
    }
}

impl<C: Clock, N: cdht::Network> InitialRecoveryAuthority<'_, '_, C, N> {
    fn current(&mut self, request: &Authorization<'_>) -> Result<u64, Error> {
        let signing = match request.action {
            Action::AuthorizeAccountDevice | Action::SignDeviceEd25519
                if ((request.action == Action::AuthorizeAccountDevice
                    && self.account_intent.is_some())
                    || (request.action == Action::SignDeviceEd25519
                        && self.delegation_intent.is_some()))
                    && request.statement.is_none()
                    && request.evidence.is_empty() =>
            {
                Some(request.signing.ok_or(Error::Unauthorized)?)
            }
            Action::ReadLineage | Action::Use if request.signing.is_none() => None,
            _ => return Err(Error::Unauthorized),
        };
        if request.target.is_some()
            || (!(matches!(
                request.action,
                Action::Use | Action::AuthorizeAccountDevice | Action::SignDeviceEd25519
            ) && request.evidence.is_empty()
                && request.statement.is_none())
                && request.evidence
                    != self
                        .candidate
                        .evidence()
                        .to_bytes()
                        .map_err(|_| Error::Unauthorized)?)
            || self.initial.seed().map_err(|_| Error::Unauthorized)?
                != self.candidate.enrollment_commitment()
            || self
                .initial
                .publication()
                .map_err(|_| Error::Unauthorized)?
                != Some(self.candidate.publication_commitment())
        {
            return Err(Error::Unauthorized);
        }
        let now = self.clock.now()?;
        if now < request.now {
            return Err(Error::Clock);
        }
        if signing.is_some_and(|signing| now >= signing.expires) {
            return Err(Error::Expired);
        }
        let observation = self
            .initial
            .observation()
            .map_err(|_| Error::Unauthorized)?;
        if observation.member != request.binding.member()
            || !observation.device_keys.contains(request.device.value())
        {
            return Err(Error::Unauthorized);
        }
        // A device lease (no passkey certificate) is reauthorized by its stamp genesis with
        // the wallet's stamp trust, and only then; a passkey lease only by its certificate.
        let device = self.initial.device_key().map_err(|_| Error::Unauthorized)?;
        let certificate = match (device, &self.stamps) {
            (Some(_), Some(_)) => Vec::new(),
            (None, None) => self
                .initial
                .certificate_bytes()
                .map_err(|_| Error::Unauthorized)?
                .to_vec(),
            _ => return Err(Error::Unauthorized),
        };
        // The authority reference: the passkey credential, or for a device lease its device
        // key (the lease's credential), which must be the stamp genesis' author.
        let credential = self
            .initial
            .credential_id()
            .map_err(|_| Error::Unauthorized)?
            .to_vec();
        if device.is_some_and(|key| credential != key) {
            return Err(Error::Unauthorized);
        }
        let stamps = self.stamps.as_ref();
        let candidate = self.candidate;
        let mut failed = false;
        let clock = &mut self.clock;
        self.initial
            .with_current(
                || {
                    clock.now().unwrap_or_else(|_| {
                        failed = true;
                        u64::MAX
                    })
                },
                |current| {
                    if current.revocations().device_revoked(request.device.value()) {
                        return Err(Error::Unauthorized);
                    }
                    let verified = match stamps {
                        Some(stamps) => candidate.reauthorize_with_stamps(
                            current,
                            stamps,
                            request.binding.member(),
                            now,
                        ),
                        None => candidate.reauthorize(
                            current,
                            &certificate,
                            request.binding.member(),
                            now,
                        ),
                    }
                    .map_err(|_| Error::Unauthorized)?;
                    let reference = match stamps {
                        Some(_) => verified
                            .author(now)
                            .map_err(|_| Error::Unauthorized)?
                            .value()
                            .to_vec(),
                        None => verified
                            .credential_id(now)
                            .map_err(|_| Error::Unauthorized)?
                            .to_vec(),
                    };
                    if signing.is_some_and(|signing| signing.expires > verified.valid_until()) {
                        return Err(Error::Expired);
                    }
                    let lineage = verified.lineage(now).map_err(|_| Error::Unauthorized)?;
                    if &lineage.binding != request.binding
                        || Some(lineage.root) != request.root
                        || lineage.epoch != request.epoch
                        || verified.author(now).map_err(|_| Error::Unauthorized)? != request.device
                        || reference != credential
                        || request
                            .statement
                            .is_some_and(|digest| lineage.digest().ok() != Some(digest))
                        || (request.action == Action::ReadLineage && request.statement.is_none())
                    {
                        return Err(Error::Unauthorized);
                    }
                    Ok(())
                },
            )
            .map_err(|_| Error::Unauthorized)??;
        if failed {
            return Err(Error::Clock);
        }
        let completed = self.clock.now()?;
        if completed < now {
            return Err(Error::Clock);
        }
        if let Some(signing) = signing {
            if completed >= signing.expires
                || signing.expires > self.initial.expires().map_err(|_| Error::Unauthorized)?
            {
                return Err(Error::Expired);
            }
        }
        Ok(completed)
    }
    fn current_signing(
        &mut self,
        request: Authorization<'_>,
        action: Action,
    ) -> Result<u64, Error> {
        if self.closed || self.records.is_none() || request.action != action {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        let (admitted_action, transcript, expires) =
            self.account_signing.take().ok_or(Error::Unauthorized)?;
        let signing = request.signing.ok_or(Error::Unauthorized)?;
        if admitted_action != action
            || signing.transcript != transcript
            || signing.expires != expires
        {
            return Err(Error::Unauthorized);
        }
        let now = self.current(&request)?;
        self.closed = false;
        Ok(now)
    }
    async fn refresh(&mut self) -> Result<(), Error> {
        let mut failed = false;
        let clock = &mut self.clock;
        self.initial
            .refresh(|| {
                clock.now().unwrap_or_else(|_| {
                    failed = true;
                    u64::MAX
                })
            })
            .await
            .map_err(|_| Error::Unauthorized)?;
        if failed {
            return Err(Error::Clock);
        }
        Ok(())
    }
}
impl<C: Clock, N: cdht::Network> ckmg::Authority for InitialRecoveryAuthority<'_, '_, C, N> {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        self.account_signing = None;
        self.refresh().await?;
        self.current(&request)?;
        match request.action {
            Action::ReadLineage if self.records.is_none() => {}
            Action::Use | Action::AuthorizeAccountDevice | Action::SignDeviceEd25519 => {
                let read = self
                    .records
                    .as_mut()
                    .ok_or(Error::Unauthorized)?
                    .read()
                    .await
                    .map_err(|_| Error::Unavailable)?;
                if read.evidence().len() != 1
                    || read.evidence()[0]
                        .to_bytes()
                        .map_err(|_| Error::Unauthorized)?
                        != self
                            .candidate
                            .evidence()
                            .to_bytes()
                            .map_err(|_| Error::Unauthorized)?
                {
                    return Err(Error::Unauthorized);
                }
                self.refresh().await?;
                self.current(&request)?;
            }
            _ => return Err(Error::Unauthorized),
        }
        if matches!(
            request.action,
            Action::AuthorizeAccountDevice | Action::SignDeviceEd25519
        ) {
            let mut current_request = request;
            current_request.now = self.clock.now()?;
            self.current(&current_request)?;
            let origin = self
                .initial
                .origin()
                .map_err(|_| Error::Unauthorized)?
                .to_owned();
            let verifier = match account_channel(
                current_request.action == Action::AuthorizeAccountDevice,
                &mut self.delegation_spent,
            ) {
                AccountChannel::Root => self.account_intent.as_mut(),
                AccountChannel::Delegation => self.delegation_intent.as_mut(),
                AccountChannel::Request => self.request_intent.as_mut(),
            };
            verifier
                .ok_or(Error::Unauthorized)?
                .consume(&current_request, &origin)?;
            let signing = current_request.signing.ok_or(Error::Unauthorized)?;
            self.account_signing = Some((
                current_request.action,
                signing.transcript.to_vec(),
                signing.expires,
            ));
        }
        self.closed = false;
        Ok(())
    }
    fn check_account_device_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.current_signing(request, Action::AuthorizeAccountDevice)
    }
    fn check_device_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.current_signing(request, Action::SignDeviceEd25519)
    }
    fn check_record_recipient_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        if self.records.is_none()
            || request.action != Action::Use
            || request.binding.community() == "wallet"
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
            || !request.evidence.is_empty()
        {
            return Err(Error::Unauthorized);
        }
        // The preceding original Use check forced the exact ACK lineage and
        // refreshed the held HTTPS owner. Reborrow that same genuine session,
        // current Charter/certificate and clock after Keys' final Store await;
        // an INITIAL ACK or cached observation is never enough by itself.
        let checked = self.current(&request)?;
        self.closed = false;
        Ok(checked)
    }
    fn check_checkpoint_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        if self.closed || self.records.is_none() || request.action != Action::Use {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        let now = self.current(&request)?;
        self.closed = false;
        Ok(now)
    }
}

/// Publish the original recovery records and retire only the exact acknowledged
/// outer operation after forced authenticated winner reads. Each publication
/// result is durably retained by Vault before the next output. Cancellation or
/// failure consumes this live attempt; reopen the same encrypted operation.
///
/// The result is not a usable Vault. Its normal recovery/Store opening remains
/// a separate owner join; no old certificate or unfinished intent is renewed.
/// Production Tor callers must obtain `network` from `Network::initial_records`
/// before moving `initial`, so transport never re-locks its held Foyer session.
pub async fn complete_initial_recovery<B: cwst::backend::Backend, N: cdht::Network + Clone>(
    creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::RetiredInitial, cvlt::InitialError> {
    complete_recovery(creation, initial, network, None, clock, entropy).await
}

/// [`complete_initial_recovery`] of a device-key member: `initial` is its device lease and
/// its genesis evidence by stamp is reauthorized with the wallet's stamp trust
/// (`GlobalWalletLease::stamp_trust`), the device key standing in for a passkey credential.
pub async fn complete_device_initial_recovery<
    B: cwst::backend::Backend,
    N: cdht::Network + Clone,
>(
    creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
    stamps: &cvlt::StampTrust,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::RetiredInitial, cvlt::InitialError> {
    complete_recovery(
        creation,
        initial,
        network,
        Some(stamps.clone()),
        clock,
        entropy,
    )
    .await
}

async fn complete_recovery<B: cwst::backend::Backend, N: cdht::Network + Clone>(
    mut creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
    stamps: Option<cvlt::StampTrust>,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::RetiredInitial, cvlt::InitialError> {
    let candidate = creation.acknowledged_candidate()?;
    let mut clock = SharedClock::new(clock);
    let mut authority = InitialRecoveryAuthority {
        candidate: &candidate,
        initial,
        clock: clock.clone(),
        records: None,
        closed: false,
        account_intent: None,
        delegation_intent: None,
        request_intent: None,
        delegation_spent: false,
        account_signing: None,
        stamps,
    };
    let reader = candidate.read_lineage(&mut clock, &mut authority).await?;
    let backend = cvlt::TorLineageRecord::provisional_lineage(network.clone(), reader)
        .await
        .map_err(cvlt::InitialError::Publication)?;
    let record = cdht::runtime::Record::new(backend).map_err(cvlt::InitialError::Publication)?;
    authority.records =
        Some(cvlt::LineageRecords::new(vec![record]).map_err(cvlt::InitialError::Records)?);
    if creation.phase()? == cvlt::InitialPhase::Acknowledged {
        creation = creation
            .stage_recovery(network.clone(), &mut clock, entropy, &mut authority)
            .await?;
    }
    while matches!(
        creation.phase()?,
        cvlt::InitialPhase::RecoveryStaged | cvlt::InitialPhase::RecoveryProgress
    ) && creation.pending_recovery_outputs()? > 0
    {
        let before = creation.pending_recovery_outputs()?;
        let (next, report) = creation
            .publish_next_recovery(network.clone(), &mut clock, &mut authority)
            .await?;
        creation = next;
        if report.written == 0 && report.stale.is_empty() && report.remaining >= before {
            return Err(cvlt::InitialError::Publication(cdht::Error::Unavailable));
        }
    }
    creation
        .retire_recovery(network, &mut clock, &mut authority)
        .await
}

#[cfg(test)]
mod account_channel_tests {
    use super::{AccountChannel::*, account_channel};

    /// Row 17: enrollment (authorize, delegation), the account request, then a
    /// record-recipient round (authorize, device signature) after activation.
    /// The second round's device signature is its delegation again, never the
    /// request channel.
    #[test]
    fn every_root_authorization_starts_a_new_delegation_round() {
        let mut spent = false;
        let calls = [true, false, false, true, false, false, true, false];
        let seen: Vec<_> = calls
            .iter()
            .map(|authorize| account_channel(*authorize, &mut spent))
            .collect();
        assert_eq!(
            seen,
            [Root, Delegation, Request, Root, Delegation, Request, Root, Delegation]
        );
    }
}
