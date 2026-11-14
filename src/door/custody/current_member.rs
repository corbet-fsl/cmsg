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
    grant: Option<super::super::accounting::VerifiedGrantEnd>,
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
    lifetime.bound.note(observed.expires);
    deadline(
        request,
        selected.valid_until(),
        charter.valid_until(),
        observed.expires,
        grant,
        now,
    )
}

/// The time rule of one current check at `now`: the operation's exclusive deadline, the
/// minimum of the lineage, Charter and membership lease bounds (and the signature's own
/// expiry). A signature's expiry must lie within the lineage and Charter bounds and within
/// [`super::signature_bound`]: the lease, or for exactly the two account signatures the
/// grant end the arm carries, capped at now + 24 h (L20261114b). The lease bound stays in the
/// deadline, so no live lease means no signature.
fn deadline(
    request: &Authorization<'_>,
    lineage: u64,
    charter: u64,
    lease: u64,
    grant: Option<super::super::accounting::VerifiedGrantEnd>,
    now: u64,
) -> Result<u64, Error> {
    let until = lineage.min(charter).min(lease);
    let signable = lineage
        .min(charter)
        .min(super::signature_bound(request, grant, lease, now));
    if now >= until
        || request
            .signing
            .is_some_and(|signing| signing.expires > signable || now >= signing.expires)
    {
        // Which bound refused (names only, never values).
        let bound = if until == lease {
            "verify_read Expired bound: membership"
        } else if until == charter {
            "verify_read Expired bound: charter"
        } else {
            "verify_read Expired bound: lineage"
        };
        let reason = if now >= until {
            "verify_read Expired reason: now past bound"
        } else if request
            .signing
            .is_some_and(|signing| signing.expires > signable)
        {
            "verify_read Expired reason: signing expires past bound"
        } else {
            "verify_read Expired reason: signing expired"
        };
        crate::door::cause::print(file!(), line!(), bound, &Error::Expired);
        crate::door::cause::print(file!(), line!(), reason, &Error::Expired);
        return Err(Error::Expired);
    }
    Ok(match request.signing {
        Some(signing) => until.min(signing.expires),
        None => until,
    })
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
        let account_armed = self.account.as_ref().is_some_and(|a| a.arm.is_armed());
        let grant = self.account.as_ref().and_then(|a| a.arm.grant_end());
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
                    &read, lifetime, &request, charter, observed, credential, stamps, grant, now,
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
        let grant = self.account.as_ref().and_then(|a| a.arm.grant_end());
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
                    grant,
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

#[cfg(test)]
mod account_expiry_tests {
    use super::super::{signing_request, AccountArm, ACCOUNT_SIGNATURE_MAX_SECONDS};
    use super::*;
    use crate::door::accounting::VerifiedGrantEnd;

    const NOW: u64 = 1_000;
    const LEASE: u64 = NOW + 900;
    const GRANT: u64 = NOW + 20 * 3_600;
    /// Lineage and Charter bounds well past the grant: only the lease or the grant decides.
    const LONG: u64 = NOW + 30 * 24 * 3_600;

    fn account(binding: &Binding, delegation: bool, expires: u64) -> Authorization<'_> {
        if delegation {
            signing_request(
                binding,
                Action::SignDeviceEd25519,
                Some(ckmg::DeviceFormat::AccountingDelegation),
                expires,
                NOW,
            )
        } else {
            signing_request(binding, Action::AuthorizeAccountDevice, None, expires, NOW)
        }
    }

    fn check(
        request: &Authorization<'_>,
        grant: Option<VerifiedGrantEnd>,
        now: u64,
    ) -> Result<u64, Error> {
        deadline(request, LONG, LONG, LEASE, grant, now)
    }

    /// Both account signatures may expire at the carried grant end, past the lease; the
    /// operation itself must still complete inside the lease.
    #[test]
    fn both_account_signatures_are_accepted_up_to_the_grant_end() {
        let binding = Binding::new("c", "m").unwrap();
        let grant = Some(VerifiedGrantEnd::for_test(GRANT));
        for delegation in [false, true] {
            assert_eq!(
                check(&account(&binding, delegation, GRANT), grant, NOW),
                Ok(LEASE)
            );
        }
    }

    /// Every other signature keeps the lease bound, also while a grant is carried.
    #[test]
    fn any_other_signature_past_the_lease_is_refused() {
        let binding = Binding::new("c", "m").unwrap();
        let grant = Some(VerifiedGrantEnd::for_test(GRANT));
        for format in [
            ckmg::DeviceFormat::AccountRequest,
            ckmg::DeviceFormat::DeviceSession,
        ] {
            let past = signing_request(
                &binding,
                Action::SignDeviceEd25519,
                Some(format),
                LEASE + 1,
                NOW,
            );
            assert_eq!(check(&past, grant, NOW), Err(Error::Expired));
            let within = signing_request(
                &binding,
                Action::SignDeviceEd25519,
                Some(format),
                LEASE,
                NOW,
            );
            assert_eq!(check(&within, grant, NOW), Ok(LEASE));
        }
    }

    /// An account signature past the grant end is refused.
    #[test]
    fn an_account_signature_past_the_grant_end_is_refused() {
        let binding = Binding::new("c", "m").unwrap();
        let grant = Some(VerifiedGrantEnd::for_test(GRANT));
        for delegation in [false, true] {
            assert_eq!(
                check(&account(&binding, delegation, GRANT + 1), grant, NOW),
                Err(Error::Expired)
            );
        }
    }

    /// The one-day cap holds even when the carried grant claims a longer end.
    #[test]
    fn an_account_signature_past_one_day_is_refused_even_under_a_longer_grant() {
        let binding = Binding::new("c", "m").unwrap();
        let cap = NOW + ACCOUNT_SIGNATURE_MAX_SECONDS;
        let grant = Some(VerifiedGrantEnd::for_test(
            NOW + 3 * ACCOUNT_SIGNATURE_MAX_SECONDS,
        ));
        for delegation in [false, true] {
            assert_eq!(
                check(&account(&binding, delegation, cap + 1), grant, NOW),
                Err(Error::Expired)
            );
            assert_eq!(
                check(&account(&binding, delegation, cap), grant, NOW),
                Ok(LEASE)
            );
        }
    }

    /// The lineage and Charter bounds still cap an account signature.
    #[test]
    fn the_lineage_and_charter_bounds_still_cap_an_account_signature() {
        let binding = Binding::new("c", "m").unwrap();
        let grant = Some(VerifiedGrantEnd::for_test(GRANT));
        let request = account(&binding, true, GRANT);
        assert_eq!(
            deadline(&request, GRANT - 1, LONG, LEASE, grant, NOW),
            Err(Error::Expired)
        );
        assert_eq!(
            deadline(&request, LONG, GRANT - 1, LEASE, grant, NOW),
            Err(Error::Expired)
        );
    }

    /// No live lease, no signature; and a disarmed arm carries no grant, so the account
    /// signatures fall back to the lease bound.
    #[test]
    fn no_lease_or_a_disarmed_arm_gives_no_signature() {
        let binding = Binding::new("c", "m").unwrap();
        let grant = Some(VerifiedGrantEnd::for_test(GRANT));
        for delegation in [false, true] {
            let request = account(&binding, delegation, GRANT);
            assert_eq!(check(&request, grant, LEASE), Err(Error::Expired));
            let arm = AccountArm::default();
            let state = arm.state();
            drop(arm.arm_carrying(grant));
            assert_eq!(check(&request, state.grant_end(), NOW), Err(Error::Expired));
        }
    }
}

// The fixture drives a live owner world over TLS; no gateway fixture stands in
// front of it, so it cannot run through the Oblivious HTTP transport.
#[cfg(all(test, not(target_arch = "wasm32"), not(feature = "ohttp")))]
#[path = "../../../tests/support/current_member.rs"]
mod tests;
