//! Actual post-read local owners retained only by targeted custody attempts.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    RecordRecipient,
    DeviceSigning,
    /// One account-key signature over an exact digest (`SignContact`, `SignResolution`,
    /// `SignAcknowledgment`), against single-use intent naming that action and digest.
    AccountSigning,
    /// Root authorization of the fixed account device (account actor only).
    AccountDevice,
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
    statement: Option<[u8; 32]>,
}

fn shape(request: &Authorization<'_>, purpose: Purpose) -> Result<(), Error> {
    if request.binding.community() == "wallet"
        || request.root.is_none()
        || request.epoch == 0
        || request.target.is_some()
        || (request.statement.is_some() != (purpose == Purpose::AccountSigning))
        || !request.evidence.is_empty()
    {
        crate::door::cause::print(
            file!(),
            line!(),
            "current_member refusal",
            &Error::Unauthorized,
        );
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
        Purpose::AccountSigning
            if matches!(
                request.action,
                Action::SignContact | Action::SignResolution | Action::SignAcknowledgment
            ) && request.signing.is_none() =>
        {
            Ok(())
        }
        Purpose::AccountDevice
            if request.action == Action::AuthorizeAccountDevice && request.signing.is_some() =>
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
    stamps: Option<&cvlt::StampTrust>,
    now: u64,
) -> Result<u64, Error> {
    lifetime
        .check(request)
        .inspect_err(|__e| crate::door::cause::print(file!(), line!(), "current_member", __e))?;
    if charter.community() != request.binding.community()
        || observed.member != request.binding.member()
        || !observed.device_keys.contains(request.device.value())
        || charter.revocations().device_revoked(request.device.value())
        || charter
            .revocations()
            .passkey_revoked(credential)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })
            .inspect_err(|__e| crate::door::cause::print(file!(), line!(), "current_member", __e))?
    {
        crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Revoked);
        return Err(Error::Revoked);
    }
    let mut selected: Option<cvlt::VerifiedLineageObservation<'_>> = None;
    for evidence in read.evidence() {
        let candidate = evidence
            .verify_for(charter, stamps, lifetime.binding.member(), now)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })
            .inspect_err(|__e| {
                crate::door::cause::print(file!(), line!(), "current_member", __e)
            })?;
        let wins = match &selected {
            None => true,
            Some(previous) => candidate
                .compare_conflict(previous, now)
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Unauthorized",
                        Error::Unauthorized,
                        &__cause,
                    )
                })
                .inspect_err(|__e| {
                    crate::door::cause::print(file!(), line!(), "current_member", __e)
                })?
                .is_gt(),
        };
        if wins {
            selected = Some(candidate);
        }
    }
    let selected = selected
        .ok_or(Error::Unavailable)
        .inspect_err(|__e| crate::door::cause::print(file!(), line!(), "current_member", __e))?;
    lifetime
        .observe_lineage(&selected, now)
        .inspect_err(|__e| crate::door::cause::print(file!(), line!(), "current_member", __e))?;
    let lineage = selected
        .lineage(now)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })
        .inspect_err(|__e| crate::door::cause::print(file!(), line!(), "current_member", __e))?;
    if &lineage.binding != request.binding
        || request.root != Some(lineage.root)
        || request.epoch != lineage.epoch
    {
        crate::door::cause::print(
            file!(),
            line!(),
            "current_member refusal",
            &Error::Unauthorized,
        );
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
        crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Expired);
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
        request: Authorization<'_>,
        purpose: Purpose,
    ) -> Result<(), Error> {
        self.discard_pending_current();
        self.live.lifetime.check(&request).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        let mut guard = CheckGuard::new(&self.live.lifetime);
        let result = self.scoped_current(request, purpose).await;
        guard.settle(&result);
        result
    }

    /// One fresh, uncached check. Each step reports its own typed verdict: only an
    /// undetermined one (`Error::Unavailable`) leaves the lifetime open.
    async fn scoped_current(
        &mut self,
        mut request: Authorization<'_>,
        purpose: Purpose,
    ) -> Result<(), Error> {
        shape(&request, purpose).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        let account_armed = self.account.as_ref().is_some_and(|a| a.armed.get());
        match purpose {
            Purpose::DeviceSigning if self.intent.is_none() && !account_armed => {
                crate::door::cause::print(
                    file!(),
                    line!(),
                    "current_member refusal",
                    &Error::Unauthorized,
                );
                return Err(Error::Unauthorized);
            }
            Purpose::AccountSigning if self.intent.is_none() => return Err(Error::Unauthorized),
            Purpose::AccountDevice if !account_armed => return Err(Error::Unauthorized),
            _ => {}
        }
        self.live.observe(&request).await?;
        // The node transport can check its own owner while this forced read
        // awaits: no source session guard is retained until after the read.
        let read = self
            .records
            .read()
            .await
            .map_err(records_refusal)
            .inspect_err(|__e| {
                crate::door::cause::print(file!(), line!(), "current_member", __e)
            })?;
        let started = self.live.clock.now().inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        if started < request.now || started < self.live.last_time {
            crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Clock);
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
            crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Clock);
            return Err(Error::Clock);
        }
        let mut lease = observed.map_err(foyer_refusal).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        let lifetime = &self.live.lifetime;
        let expected_origin = &self.live.origin;
        let clock = &mut self.live.clock;
        let stamps = self.stamps.as_ref();
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
                    crate::door::cause::print(
                        file!(),
                        line!(),
                        "current_member refusal",
                        &Error::Unauthorized,
                    );
                    return Err(Error::Unauthorized);
                }
                verify_read(
                    &read, lifetime, &request, charter, observed, credential, stamps, now,
                )
            },
        );
        self.live.last_time = floor;
        if failed {
            crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Clock);
            return Err(Error::Clock);
        }
        let (until, completed) = checked.map_err(foyer_refusal).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        if completed >= until? {
            crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Expired);
            return Err(Error::Expired);
        }
        request.now = completed;
        let signing = if purpose == Purpose::DeviceSigning || purpose == Purpose::AccountDevice {
            let origin = self.live.origin.clone();
            match (&mut self.account, account_armed) {
                // The account actor armed its own channels: root authorization, then the
                // delegation (spent by its attempt whatever the outcome), then the request.
                (Some(account), true) => {
                    let verifier = match super::account_channel(
                        purpose == Purpose::AccountDevice,
                        &mut account.delegation_spent,
                    ) {
                        super::AccountChannel::Root => &mut account.root,
                        super::AccountChannel::Delegation => &mut account.delegation,
                        super::AccountChannel::Request => &mut account.request,
                    };
                    verifier.consume(&request, &origin).inspect_err(|__e| {
                        crate::door::cause::print(file!(), line!(), "current_member", __e)
                    })?;
                }
                _ => self
                    .intent
                    .as_mut()
                    .ok_or(Error::Unauthorized)
                    .inspect_err(|__e| {
                        crate::door::cause::print(file!(), line!(), "current_member", __e)
                    })?
                    .consume(&request, &origin)
                    .inspect_err(|__e| {
                        crate::door::cause::print(file!(), line!(), "current_member", __e)
                    })?,
            }
            let signing = request
                .signing
                .ok_or(Error::Unauthorized)
                .inspect_err(|__e| {
                    crate::door::cause::print(file!(), line!(), "current_member", __e)
                })?;
            Some((signing.transcript.to_vec(), signing.expires))
        } else {
            if purpose == Purpose::AccountSigning {
                self.intent
                    .as_mut()
                    .ok_or(Error::Unauthorized)
                    .inspect_err(|__e| {
                        crate::door::cause::print(file!(), line!(), "current_member", __e)
                    })?
                    .consume(&request, &self.live.origin)
                    .inspect_err(|__e| {
                        crate::door::cause::print(file!(), line!(), "current_member", __e)
                    })?;
            }
            None
        };
        self.pending_current = Some(PendingCurrent {
            lease,
            read,
            binding: request.binding.clone(),
            root: request.root.ok_or(Error::Unauthorized).inspect_err(|__e| {
                crate::door::cause::print(file!(), line!(), "current_member", __e)
            })?,
            device: request.device,
            epoch: request.epoch,
            purpose,
            signing,
            statement: request.statement,
        });
        // Test-only scheduling notice: the genuine owner has already retained
        // its session. This carries no identity, verdict or authority.
        #[cfg(all(test, not(target_arch = "wasm32")))]
        if let Some(reached) = self.reached_current.take() {
            let _ = reached.send(());
        }
        Ok(())
    }

    pub(super) fn finish_scoped_current(
        &mut self,
        request: Authorization<'_>,
        purpose: Purpose,
    ) -> Result<u64, Error> {
        let pending = self
            .pending_current
            .take()
            .ok_or(Error::Unauthorized)
            .inspect_err(|__e| {
                crate::door::cause::print(file!(), line!(), "current_member", __e)
            })?;
        let mut guard = CheckGuard::new(&self.live.lifetime);
        let result = self.finish_pending(pending, request, purpose);
        guard.settle(&result);
        result
    }

    fn finish_pending(
        &mut self,
        mut pending: PendingCurrent,
        request: Authorization<'_>,
        purpose: Purpose,
    ) -> Result<u64, Error> {
        shape(&request, purpose).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        if pending.purpose != purpose
            || pending.statement != request.statement
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
            crate::door::cause::print(
                file!(),
                line!(),
                "current_member refusal",
                &Error::Unauthorized,
            );
            return Err(Error::Unauthorized);
        }
        let mut floor = self.live.last_time.max(request.now);
        let mut failed = false;
        let lifetime = &self.live.lifetime;
        let origin = &self.live.origin;
        let clock = &mut self.live.clock;
        let stamps = self.stamps.as_ref();
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
                    crate::door::cause::print(
                        file!(),
                        line!(),
                        "current_member refusal",
                        &Error::Unauthorized,
                    );
                    return Err(Error::Unauthorized);
                }
                verify_read(
                    &pending.read,
                    lifetime,
                    &request,
                    charter,
                    observed,
                    credential,
                    stamps,
                    now,
                )
            },
        );
        self.live.last_time = floor;
        if failed {
            crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Clock);
            return Err(Error::Clock);
        }
        let (until, completed) = checked.map_err(foyer_refusal).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        if completed >= until? {
            crate::door::cause::print(file!(), line!(), "current_member refusal", &Error::Expired);
            return Err(Error::Expired);
        }
        self.live.lifetime.check(&request).inspect_err(|__e| {
            crate::door::cause::print(file!(), line!(), "current_member", __e)
        })?;
        // Taking the attempt releases the held original session on every exit.
        Ok(completed)
    }
}

// The fixture drives a live owner world over TLS; no gateway fixture stands in
// front of it, so it cannot run through the Oblivious HTTP transport.
#[cfg(all(test, not(target_arch = "wasm32"), not(feature = "ohttp")))]
#[path = "../../../tests/support/current_member.rs"]
mod tests;
