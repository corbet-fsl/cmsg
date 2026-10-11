//! Recovery publication of one actual acknowledged initial operation.
use super::initial::SharedClock;
use super::*;

struct InitialRecoveryAuthority<'a, 'p, C, N: cdht::Network> {
    candidate: &'a cvlt::AcknowledgedInitialCandidate,
    initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    clock: C,
    records: Option<cvlt::LineageRecords<cvlt::TorLineageRecord<'a, N>>>,
    closed: bool,
}
impl<C: Clock, N: cdht::Network> InitialRecoveryAuthority<'_, '_, C, N> {
    fn current(&mut self, request: &Authorization<'_>) -> Result<u64, Error> {
        if !matches!(request.action, Action::ReadLineage | Action::Use)
            || request.target.is_some()
            || request.signing.is_some()
            || request.evidence
                != self
                    .candidate
                    .evidence()
                    .to_bytes()
                    .map_err(|_| Error::Unauthorized)?
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
                    let lineage = verified.lineage(now).map_err(|_| Error::Unauthorized)?;
                    if &lineage.binding != request.binding
                        || Some(lineage.root) != request.root
                        || lineage.epoch != request.epoch
                        || verified.author(now).map_err(|_| Error::Unauthorized)? != request.device
                        || verified
                            .credential_id(now)
                            .map_err(|_| Error::Unauthorized)?
                            != credential
                        || request.statement != Some(lineage.digest()?)
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
impl<C: Clock, N: cdht::Network> Authority for InitialRecoveryAuthority<'_, '_, C, N> {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        self.closed = true;
        self.refresh().await?;
        self.current(&request)?;
        match request.action {
            Action::ReadLineage if self.records.is_none() => {}
            Action::Use => {
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
        self.closed = false;
        Ok(())
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
