//! Provisional restore admission without recursively reading member lineage.
use super::*;

/// One restore attempt's admission port. It borrows the original policy port
/// and grants only ReadLineage. It never grants transport or member-purpose use.
pub struct RecoveryAuthority<'attempt, C> {
    live: TransportAuthority<C>,
    policy: &'attempt mut cfyr::policy::CurrentPolicy<Transport>,
}

/// Original recovery and normal member owners. No accepting result is cached:
/// opening the Store and every later member operation check authority again.
pub struct RecoveryOwners<'attempt, N: cdht::Network> {
    pub recovery: cvlt::PreparedRecovery<'attempt>,
    pub authority: MemberAuthority<SystemClock, cvlt::TorLineageRecord<'static, N>>,
    pub intent: ckmg::IntentAdmission,
}

/// Original recovered Vault with concrete fresh authority and Tor Records.
pub type RecoveredVault<B, N> = cvlt::Vault<
    B,
    SystemClock,
    ckmg::SystemEntropy,
    MemberAuthority<SystemClock, cvlt::TorLineageRecord<'static, N>>,
    cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
    cvlt::WalletCustody,
>;

/// Recovered original owners, still unbound to any Door or runtime-ready status.
pub struct RestoredVault<B: cwst::backend::Backend, N: cdht::Network> {
    pub vault: RecoveredVault<B, N>,
    pub intent: ckmg::IntentAdmission,
    /// The exact same session lifetime checked by this Vault's member authority.
    pub lifetime: CustodyLifetime,
}

impl<N: cdht::Network + Clone> RecoveryOwners<'_, N> {
    /// Open the existing local compound Store, or restore it from this retained
    /// Tor network when the local backend is empty. No missing checkpoint or Wallet record initializes
    /// replacement state. The caller must retain the network and bind the actual
    /// Vault before it can complete login; this result is not a readiness grant.
    pub async fn open<B: cwst::backend::Backend>(
        mut self,
        network: N,
        backend: B,
    ) -> super::super::Result<RestoredVault<B, N>> {
        let lifetime = self.authority.live.lifetime.clone();
        let mut guard = CheckGuard {
            closed: self.authority.live.lifetime.closed.clone(),
            accepted: false,
        };
        let records = self
            .recovery
            .tor_passkey_records(network.clone(), &mut SystemClock, &mut self.authority)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let retained = if backend
            .read()
            .await
            .map_err(|_| ErrorCode::Unavailable)?
            .is_some()
        {
            None
        } else {
            Some(
                self.recovery
                    .tor_checkpoint(network, &mut SystemClock, &mut self.authority)
                    .await
                    .map_err(|_| ErrorCode::Unavailable)?,
            )
        };
        let owners = cvlt::Owners {
            clock: SystemClock,
            entropy: ckmg::SystemEntropy,
            authority: self.authority,
            records,
            wallet: (),
        };
        let vault = match retained {
            Some(retained) => self.recovery.restore(retained, backend, owners).await,
            None => self.recovery.open_existing(backend, owners).await,
        }
        .map_err(|_| ErrorCode::Unavailable)?;
        let vault = vault
            .restore_wallet_custody()
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        guard.accepted = true;
        Ok(RestoredVault {
            vault,
            intent: self.intent,
            lifetime,
        })
    }
}

impl MemberAuthorityBuilder {
    /// Complete the approved read-only bootstrap over this runtime's original
    /// Tor Records network, then replace provisional custody with normal member
    /// read custody. No Store is opened and no Keys/Wallet readiness is claimed.
    pub async fn prepare_recovery<'attempt, N: cdht::Network + Clone>(
        mut self,
        candidate: &'attempt cvlt::RecoveryCandidate,
        network: N,
    ) -> super::super::Result<RecoveryOwners<'attempt, N>> {
        let mut guard = CheckGuard {
            closed: self.lifetime.closed.clone(),
            accepted: false,
        };
        let reader = {
            let mut admission = self.recovery_authority(SystemClock)?;
            candidate
                .read_lineage(&mut SystemClock, &mut admission)
                .await
                .map_err(|_| ErrorCode::Unauthorized)?
        };
        let backend = cvlt::TorLineageRecord::provisional_lineage(network.clone(), reader)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let record = cdht::runtime::Record::new(backend).map_err(|_| ErrorCode::Unavailable)?;
        let records =
            cvlt::LineageRecords::new(vec![record]).map_err(|_| ErrorCode::Unavailable)?;
        let mut provisional = self.bind(records, SystemClock)?;
        // This normal member check forces the DHT read and then fresh HTTPS and
        // current certificate/assertion verification, before any Store cipher.
        let recovery = candidate
            .authorize(&mut SystemClock, &mut provisional)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let MemberAuthority {
            live,
            policy,
            records,
            intent,
            pending_current,
            #[cfg(all(test, not(target_arch = "wasm32")))]
                reached_current: _,
        } = provisional;
        if pending_current.is_some() {
            return Err(ErrorCode::Unauthorized);
        }
        drop(records); // provisional read custody ends here, before Store restore
        drop(intent);
        let builder = MemberAuthorityBuilder {
            lifetime: live.lifetime,
            membership: live.membership,
            origin: live.origin,
            policy,
            last_time: live.last_time,
        };
        let reader = recovery
            .lineage_reader()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let backend = cvlt::TorLineageRecord::member_lineage(network, reader)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let record = cdht::runtime::Record::new(backend).map_err(|_| ErrorCode::Unavailable)?;
        let records =
            cvlt::LineageRecords::new(vec![record]).map_err(|_| ErrorCode::Unavailable)?;
        let (authority, intent) = builder.bind_with_intent(records, SystemClock)?;
        guard.accepted = true;
        Ok(RecoveryOwners {
            recovery,
            authority,
            intent,
        })
    }

    /// Borrow a temporary recovery port before attaching the genuine lineage
    /// records. No successful observation is retained or reused by member checks.
    pub fn recovery_authority<C: Clock>(
        &mut self,
        clock: C,
    ) -> super::super::Result<RecoveryAuthority<'_, C>> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(RecoveryAuthority {
            live: TransportAuthority {
                lifetime: self.lifetime.clone(),
                membership: self.membership.clone(),
                origin: self.origin.clone(),
                clock,
                last_time: self.last_time,
            },
            policy: &mut self.policy,
        })
    }
}

impl<C: Clock> ckmg::Authority for RecoveryAuthority<'_, C> {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.live.lifetime.check(&request)?;
        if request.action != Action::ReadLineage
            || request.root.is_none()
            || request.epoch == 0
            || request.statement.is_none()
            || request.target.is_some()
            || request.signing.is_some()
            || request.evidence.is_empty()
            || request.evidence.len() > ckmg::MAX_MESSAGE_BYTES
        {
            return Err(Error::Unauthorized);
        }
        let mut guard = CheckGuard {
            closed: self.live.lifetime.closed.clone(),
            accepted: false,
        };
        let evidence =
            cvlt::LineageEvidence::from_bytes(request.evidence).map_err(|_| Error::Unauthorized)?;
        let (now, membership_expires) = self.live.observe(&request).await?;
        let lifetime = &self.live.lifetime;
        let clock = &mut self.live.clock;
        let completed = self
            .policy
            .with_current(now, |current| {
                if current.revocations().device_revoked(request.device.value()) {
                    return Err(Error::Unauthorized);
                }
                // This certificate/assertion authenticates the retained checkpoint;
                // it says nothing about the current lineage in the DHT.
                let observed = evidence
                    .verify(current, lifetime.binding.member(), now)
                    .map_err(|_| Error::Unauthorized)?;
                let completed = clock.now()?;
                if completed < now {
                    return Err(Error::Clock);
                }
                if completed >= membership_expires {
                    return Err(Error::Unauthorized);
                }
                let lineage = observed
                    .lineage(completed)
                    .map_err(|_| Error::Unauthorized)?;
                if &lineage.binding != request.binding
                    || request.root != Some(lineage.root)
                    || request.epoch != lineage.epoch
                    || request.statement != Some(lineage.digest()?)
                    || !lineage.devices.contains(&request.device)
                {
                    return Err(Error::Unauthorized);
                }
                Ok(completed)
            })
            .map_err(|_| Error::Unavailable)??;
        self.live.last_time = completed;
        self.live.lifetime.check(&request)?;
        guard.accepted = true;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../../tests/support/lineage_recovery.rs"]
mod tests;

impl Door {
    /// Consume the original login result and obtain its community pseudonym from
    /// a fresh original HTTPS lobby/device observation. The user UUID, action
    /// body and constructor configuration never choose this member binding.
    /// Transport and later member operations still perform their own fresh checks.
    pub async fn prepare_login_recovery(
        &mut self,
        origin: &str,
        token: &super::super::ClientToken,
        now: u64,
    ) -> super::super::Result<(cvlt::PreparedOpen, Binding)> {
        let prepared = self.prepare_login_custody(origin, token, now)?;
        let device = prepared.device().map_err(|_| ErrorCode::Unauthorized)?;
        let mut membership = self.live_membership(origin)?;
        let mut clock = SystemClock;
        let mut floor = now;
        let mut clock_failed = false;
        let observed = membership
            .observe(|| match clock.now() {
                Ok(time) if time >= floor => {
                    floor = time;
                    time
                }
                _ => {
                    clock_failed = true;
                    u64::MAX
                }
            })
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let completed = clock.now().map_err(|_| ErrorCode::Clock)?;
        if clock_failed || completed < floor {
            return Err(ErrorCode::Clock);
        }
        if completed >= observed.expires || !observed.device_keys.contains(device.value()) {
            return Err(ErrorCode::Unauthorized);
        }
        let binding = Binding::new(&self.config.community, &observed.member)
            .map_err(|_| ErrorCode::Unauthorized)?;
        Ok((prepared, binding))
    }
}
