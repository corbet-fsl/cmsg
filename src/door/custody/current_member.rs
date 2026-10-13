//! Actual post-read local owners retained only by targeted custody attempts.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    RecordRecipient,
    DeviceSigning,
}
pub(super) struct PendingCurrent {
    lease: cfyr::membership::MembershipLease<Transport>,
    read: cvlt::LineageRead,
    binding: Binding,
    root: PublicKey,
    device: PublicKey,
    epoch: u64,
    purpose: Purpose,
    signing: Option<(Vec<u8>, u64)>,
}

fn shape(request: &Authorization<'_>, purpose: Purpose) -> Result<(), Error> {
    if request.binding.community() == "wallet"
        || request.root.is_none()
        || request.epoch == 0
        || request.target.is_some()
        || request.statement.is_some()
        || !request.evidence.is_empty()
    {
        return Err(Error::Unauthorized);
    }
    match purpose {
        Purpose::RecordRecipient if request.action == Action::Use && request.signing.is_none() => {
            Ok(())
        }
        Purpose::DeviceSigning
            if request.action == Action::SignDeviceEd25519 && request.signing.is_some() =>
        {
            Ok(())
        }
        _ => Err(Error::Unauthorized),
    }
}

fn verify_read(
    read: &cvlt::LineageRead,
    lifetime: &CustodyLifetime,
    request: &Authorization<'_>,
    charter: &cchr::VerifiedCharter,
    observed: &cfyr::membership::Observation,
    credential: &[u8],
    now: u64,
) -> Result<u64, Error> {
    lifetime.check(request)?;
    if charter.community() != request.binding.community()
        || observed.member != request.binding.member()
        || !observed.device_keys.contains(request.device.value())
        || charter.revocations().device_revoked(request.device.value())
        || charter
            .revocations()
            .passkey_revoked(credential)
            .map_err(|_| Error::Unauthorized)?
    {
        return Err(Error::Revoked);
    }
    let mut selected: Option<cvlt::VerifiedLineageObservation<'_>> = None;
    for evidence in read.evidence() {
        let candidate = evidence
            .verify(charter, lifetime.binding.member(), now)
            .map_err(|_| Error::Unauthorized)?;
        let wins = match &selected {
            None => true,
            Some(previous) => candidate
                .compare_conflict(previous, now)
                .map_err(|_| Error::Unauthorized)?
                .is_gt(),
        };
        if wins {
            selected = Some(candidate);
        }
    }
    let selected = selected.ok_or(Error::Unavailable)?;
    lifetime.observe_lineage(&selected, now)?;
    let lineage = selected.lineage(now).map_err(|_| Error::Unauthorized)?;
    if &lineage.binding != request.binding
        || request.root != Some(lineage.root)
        || request.epoch != lineage.epoch
    {
        return Err(Error::Unauthorized);
    }
    let mut until = selected
        .valid_until()
        .min(charter.valid_until())
        .min(observed.expires);
    if now >= until
        || request
            .signing
            .is_some_and(|signing| signing.expires > until || now >= signing.expires)
    {
        return Err(Error::Expired);
    }
    if let Some(signing) = request.signing {
        until = until.min(signing.expires);
    }
    Ok(until)
}

impl<C: Clock, B: cdht::runtime::Backend> MemberAuthority<C, B> {
    pub(super) fn discard_pending_current(&mut self) {
        if self.pending_current.take().is_some() {
            // Only an unfinished genuine attempt can be here. Cleanup releases
            // its held session and permanently closes the same custody lifetime.
            self.live.lifetime.close();
        }
    }

    pub(super) async fn check_scoped_current(
        &mut self,
        mut request: Authorization<'_>,
        purpose: Purpose,
    ) -> Result<(), Error> {
        self.discard_pending_current();
        self.live.lifetime.check(&request)?;
        let mut guard = CheckGuard {
            closed: self.live.lifetime.closed.clone(),
            accepted: false,
        };
        shape(&request, purpose)?;
        if purpose == Purpose::DeviceSigning && self.intent.is_none() {
            return Err(Error::Unauthorized);
        }
        self.live.observe(&request).await?;
        // The node transport can check its own owner while this forced read
        // awaits: no source session guard is retained until after the read.
        let read = self.records.read().await.map_err(|_| Error::Unavailable)?;
        let started = self.live.clock.now()?;
        if started < request.now || started < self.live.last_time {
            return Err(Error::Clock);
        }
        self.live.last_time = started;
        let mut floor = started;
        let mut failed = false;
        let membership = self.live.membership.clone();
        let observed = membership
            .lock()
            .await
            .observe_lease(|| match self.live.clock.now() {
                Ok(now) if now >= floor => {
                    floor = now;
                    now
                }
                _ => {
                    failed = true;
                    u64::MAX
                }
            })
            .await;
        self.live.last_time = floor;
        if failed {
            return Err(Error::Clock);
        }
        let mut lease = observed.map_err(|_| Error::Unavailable)?;
        let lifetime = &self.live.lifetime;
        let expected_origin = &self.live.origin;
        let clock = &mut self.live.clock;
        let checked = lease.with_community_policy(
            &mut self.policy,
            || match clock.now() {
                Ok(now) if now >= floor => {
                    floor = now;
                    now
                }
                _ => {
                    failed = true;
                    u64::MAX
                }
            },
            |charter, observed, credential, origin, now| {
                if origin != expected_origin {
                    return Err(Error::Unauthorized);
                }
                verify_read(
                    &read, lifetime, &request, charter, observed, credential, now,
                )
            },
        );
        self.live.last_time = floor;
        if failed {
            return Err(Error::Clock);
        }
        let (until, completed) = checked.map_err(|_| Error::Unavailable)?;
        if completed >= until? {
            return Err(Error::Expired);
        }
        request.now = completed;
        let signing = if purpose == Purpose::DeviceSigning {
            self.intent
                .as_mut()
                .ok_or(Error::Unauthorized)?
                .consume(&request, &self.live.origin)?;
            let signing = request.signing.ok_or(Error::Unauthorized)?;
            Some((signing.transcript.to_vec(), signing.expires))
        } else {
            None
        };
        self.pending_current = Some(PendingCurrent {
            lease,
            read,
            binding: request.binding.clone(),
            root: request.root.ok_or(Error::Unauthorized)?,
            device: request.device,
            epoch: request.epoch,
            purpose,
            signing,
        });
        // Test-only scheduling notice: the genuine owner has already retained
        // its session. This carries no identity, verdict or authority.
        #[cfg(all(test, not(target_arch = "wasm32")))]
        if let Some(reached) = self.reached_current.take() {
            let _ = reached.send(());
        }
        guard.accepted = true;
        Ok(())
    }

    pub(super) fn finish_scoped_current(
        &mut self,
        request: Authorization<'_>,
        purpose: Purpose,
    ) -> Result<u64, Error> {
        let mut pending = self.pending_current.take().ok_or(Error::Unauthorized)?;
        let mut guard = CheckGuard {
            closed: self.live.lifetime.closed.clone(),
            accepted: false,
        };
        shape(&request, purpose)?;
        if pending.purpose != purpose
            || &pending.binding != request.binding
            || Some(pending.root) != request.root
            || pending.device != request.device
            || pending.epoch != request.epoch
            || pending
                .signing
                .as_ref()
                .map(|(bytes, expires)| (bytes.as_slice(), *expires))
                != request
                    .signing
                    .map(|signing| (signing.transcript, signing.expires))
        {
            return Err(Error::Unauthorized);
        }
        let mut floor = self.live.last_time.max(request.now);
        let mut failed = false;
        let lifetime = &self.live.lifetime;
        let origin = &self.live.origin;
        let clock = &mut self.live.clock;
        let checked = pending.lease.with_community_policy(
            &mut self.policy,
            || match clock.now() {
                Ok(now) if now >= floor => {
                    floor = now;
                    now
                }
                _ => {
                    failed = true;
                    u64::MAX
                }
            },
            |charter, observed, credential, actual_origin, now| {
                if actual_origin != origin {
                    return Err(Error::Unauthorized);
                }
                verify_read(
                    &pending.read,
                    lifetime,
                    &request,
                    charter,
                    observed,
                    credential,
                    now,
                )
            },
        );
        self.live.last_time = floor;
        if failed {
            return Err(Error::Clock);
        }
        let (until, completed) = checked.map_err(|_| Error::Unavailable)?;
        if completed >= until? {
            return Err(Error::Expired);
        }
        self.live.lifetime.check(&request)?;
        guard.accepted = true;
        // Taking the attempt releases the held original session on every exit.
        Ok(completed)
    }
}

// The fixture drives a live owner world over TLS; no gateway fixture stands in
// front of it, so it cannot run through the Oblivious HTTP transport.
#[cfg(all(test, not(target_arch = "wasm32"), not(feature = "ohttp")))]
#[path = "../../../tests/support/current_member.rs"]
mod tests;
