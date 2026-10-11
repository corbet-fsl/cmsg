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
    pub(super) account_signing: Option<(Vec<u8>, u64)>,
}
impl<C: Clock, N: cdht::Network> InitialRecoveryAuthority<'_, '_, C, N> {
    fn current(&mut self, request: &Authorization<'_>) -> Result<u64, Error> {
        let signing = match request.action {
            Action::AuthorizeAccountDevice
                if self.account_intent.is_some()
                    && request.statement.is_none()
                    && request.evidence.is_empty() =>
            {
                Some(request.signing.ok_or(Error::Unauthorized)?)
            }
            Action::ReadLineage | Action::Use if request.signing.is_none() => None,
            _ => return Err(Error::Unauthorized),
        };
        if request.target.is_some()
            || (!(matches!(request.action, Action::Use | Action::AuthorizeAccountDevice)
                && request.evidence.is_empty()
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
        let certificate = self
            .initial
            .certificate_bytes()
            .map_err(|_| Error::Unauthorized)?
            .to_vec();
        let credential = self
            .initial
            .credential_id()
            .map_err(|_| Error::Unauthorized)?
            .to_vec();
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
                    let verified = candidate
                        .reauthorize(current, &certificate, request.binding.member(), now)
                        .map_err(|_| Error::Unauthorized)?;
                    if signing.is_some_and(|signing| signing.expires > verified.valid_until()) {
                        return Err(Error::Expired);
                    }
                    let lineage = verified.lineage(now).map_err(|_| Error::Unauthorized)?;
                    if &lineage.binding != request.binding
                        || Some(lineage.root) != request.root
                        || lineage.epoch != request.epoch
                        || verified.author(now).map_err(|_| Error::Unauthorized)? != request.device
                        || verified
                            .credential_id(now)
                            .map_err(|_| Error::Unauthorized)?
                            != credential
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
            Action::Use | Action::AuthorizeAccountDevice => {
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
        if request.action == Action::AuthorizeAccountDevice {
            let mut current_request = request;
            current_request.now = self.clock.now()?;
            self.current(&current_request)?;
            self.account_intent
                .as_mut()
                .ok_or(Error::Unauthorized)?
                .consume(
                    &current_request,
                    self.initial.origin().map_err(|_| Error::Unauthorized)?,
                )?;
            let signing = current_request.signing.ok_or(Error::Unauthorized)?;
            self.account_signing = Some((signing.transcript.to_vec(), signing.expires));
        }
        self.closed = false;
        Ok(())
    }
    fn check_account_device_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        if self.closed || self.records.is_none() || request.action != Action::AuthorizeAccountDevice
        {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        let (transcript, expires) = self.account_signing.take().ok_or(Error::Unauthorized)?;
        let signing = request.signing.ok_or(Error::Unauthorized)?;
        if signing.transcript != transcript || signing.expires != expires {
            return Err(Error::Unauthorized);
        }
        let now = self.current(&request)?;
        self.closed = false;
        Ok(now)
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
    mut creation: cvlt::InitialCreation<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    network: N,
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
        account_signing: None,
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
