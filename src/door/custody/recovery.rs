//! Provisional restore admission without recursively reading member lineage.
use super::*;

/// One restore attempt's admission port. It borrows the original policy port
/// and grants only ReadLineage. It never grants transport or member-purpose use.
pub struct RecoveryAuthority<'attempt, C> {
    live: TransportAuthority<C>,
    policy: &'attempt mut cfyr::policy::CurrentPolicy<Transport>,
    stamps: Option<&'attempt cvlt::StampTrust>,
}

/// Original recovery and normal member owners. No accepting result is cached:
/// opening the Store and every later member operation check authority again.
pub struct RecoveryOwners<'attempt, N: cdht::Network> {
    pub recovery: cvlt::PreparedRecovery<'attempt>,
    pub authority: MemberAuthority<SystemClock, cvlt::TorLineageRecord<'static, N>>,
    pub intent: ckmg::IntentAdmission,
    pub account: AccountWiring,
}

/// What the account actor of this member session is lent besides the Door's Vault:
/// its three one-use signing channels and the arm that selects them on the member
/// authority of that same Vault. Consumed by `account_open::bind_member_account`.
pub struct AccountWiring {
    pub(crate) intents: super::super::accounting::AccountingIntents,
    pub(crate) request: ckmg::IntentAdmission,
    pub(crate) arm: AccountArm,
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
    pub account: AccountWiring,
    /// The exact same session lifetime checked by this Vault's member authority.
    pub lifetime: CustodyLifetime,
}

impl<N: cdht::Network + Clone> RecoveryOwners<'_, N> {
    /// Open the existing local compound Store, or restore it from this retained
    /// Tor network when the local backend is empty. No missing checkpoint or Wallet record initializes
    /// replacement state. The caller must retain the network and bind the actual
    /// Vault before it can complete login; this result is not a readiness grant.
    pub async fn open<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<RestoredVault<B, N>> {
        self.open_custody(network, backend, false).await
    }

    /// [`Self::open`] for a device-key member's community Store, enrolled through the
    /// account path: it holds the account capsule only (the passport lives in the wallet).
    pub async fn open_account_only<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<RestoredVault<B, N>> {
        self.open_custody(network, backend, true).await
    }

    async fn open_custody<B: cwst::backend::Backend>(
        mut self,
        network: N,
        backend: B,
        account_only: bool,
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let retained = if backend
            .read()
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
            .is_some()
        {
            None
        } else {
            Some(
                self.recovery
                    .tor_checkpoint(network, &mut SystemClock, &mut self.authority)
                    .await
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Unavailable",
                            ErrorCode::Unavailable,
                            &__cause,
                        )
                    })?,
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let vault = if account_only {
            vault.restore_account_only_custody().await
        } else {
            vault.restore_wallet_custody().await
        }
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        guard.accepted = true;
        Ok(RestoredVault {
            vault,
            intent: self.intent,
            account: self.account,
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
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })?
        };
        let backend = cvlt::TorLineageRecord::provisional_lineage(network.clone(), reader)
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let record = cdht::runtime::Record::new(backend).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let records = cvlt::LineageRecords::new(vec![record]).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let mut provisional = self.bind(records, SystemClock)?;
        // This normal member check forces the DHT read and then fresh HTTPS and
        // current certificate/assertion verification, before any Store cipher.
        let recovery = candidate
            .authorize(&mut SystemClock, &mut provisional)
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
        let MemberAuthority {
            live,
            policy,
            records,
            stamps,
            intent,
            account: _,
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
            stamps,
        };
        let reader = recovery.lineage_reader().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        let backend = cvlt::TorLineageRecord::member_lineage(network, reader)
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let record = cdht::runtime::Record::new(backend).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let records = cvlt::LineageRecords::new(vec![record]).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let (authority, intent, intents, request, arm) =
            builder.bind_with_account_intents(records, SystemClock)?;
        guard.accepted = true;
        Ok(RecoveryOwners {
            recovery,
            authority,
            intent,
            account: AccountWiring {
                intents,
                request,
                arm,
            },
        })
    }

    /// Borrow a temporary recovery port before attaching the genuine lineage
    /// records. No successful observation is retained or reused by member checks.
    pub fn recovery_authority<C: Clock>(
        &mut self,
        clock: C,
    ) -> super::super::Result<RecoveryAuthority<'_, C>> {
        if self.lifetime.is_closed() {
            crate::door::cause::print(
                file!(),
                line!(),
                "recovery authority: custody lifetime closed",
                &ErrorCode::Unauthorized,
            );
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
            stamps: self.stamps.as_ref(),
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
        let evidence = cvlt::LineageEvidence::from_bytes(request.evidence).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        let (now, membership_expires) = self.live.observe(&request).await?;
        let lifetime = &self.live.lifetime;
        let clock = &mut self.live.clock;
        let stamps = self.stamps;
        let completed = self
            .policy
            .with_current(now, |current| {
                if current.revocations().device_revoked(request.device.value()) {
                    return Err(Error::Unauthorized);
                }
                // This certificate/assertion authenticates the retained checkpoint;
                // it says nothing about the current lineage in the DHT.
                let observed = evidence
                    .verify_for(current, stamps, lifetime.binding.member(), now)
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "Error::Unauthorized",
                            Error::Unauthorized,
                            &__cause,
                        )
                    })?;
                let completed = clock.now()?;
                if completed < now {
                    return Err(Error::Clock);
                }
                if completed >= membership_expires {
                    return Err(Error::Unauthorized);
                }
                let lineage = observed.lineage(completed).map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Unauthorized",
                        Error::Unauthorized,
                        &__cause,
                    )
                })?;
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unavailable",
                    Error::Unavailable,
                    &__cause,
                )
            })??;
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
    /// A device-key login also returns the wallet's stamp trust it retained: the
    /// recovery verifies the member's stamp lineage evidence with it.
    pub async fn prepare_login_recovery(
        &mut self,
        origin: &str,
        token: &super::super::ClientToken,
        now: u64,
    ) -> super::super::Result<(cvlt::PreparedOpen, Binding, Option<cvlt::StampTrust>)> {
        let (prepared, stamps) = self.take_login_custody(origin, token, now)?;
        let device = prepared.device().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let completed = clock.now().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Clock",
                ErrorCode::Clock,
                &__cause,
            )
        })?;
        if clock_failed || completed < floor {
            return Err(ErrorCode::Clock);
        }
        if completed >= observed.expires || !observed.device_keys.contains(device.value()) {
            return Err(ErrorCode::Unauthorized);
        }
        let binding =
            Binding::new(&self.config.community, &observed.member).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unauthorized",
                    ErrorCode::Unauthorized,
                    &__cause,
                )
            })?;
        Ok((prepared, binding, stamps))
    }

    /// The login's Vault recovery once its records network runs: read the vault checkpoint
    /// of `prepared`, prepare the recovery candidate (stamp checkpoints only with `stamps`),
    /// complete the forced lineage read through `member` (which verifies stamp lineage
    /// evidence with the same trust) and open or restore the Store into `backend`. Nothing
    /// is bound to this Door yet; missing records never create new state.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_login_vault<N, B>(
        &self,
        origin: &str,
        prepared: cvlt::PreparedOpen,
        binding: &Binding,
        stamps: Option<cvlt::StampTrust>,
        member: MemberAuthorityBuilder,
        network: N,
        backend: B,
        now: u64,
    ) -> super::super::Result<RestoredVault<B, N>>
    where
        N: cdht::Network + Clone,
        B: cwst::backend::Backend,
    {
        let candidate = self
            .login_recovery_candidate(origin, prepared, binding, stamps.as_ref(), &network, now)
            .await?;
        // Original recovery performs forced lineage reads and fresh HTTPS checks
        // before lending Store custody. A device-key member (the stamp trust is held)
        // enrolled its community Store through the account path: account custody only.
        let account_only = stamps.is_some();
        let owners = member
            .bind_recovery(stamps, &candidate, network.clone())
            .await?;
        if account_only {
            owners.open_account_only(network, backend).await
        } else {
            owners.open(network, backend).await
        }
    }

    /// The recovery candidate of this login: the retained checkpoint judged at the current
    /// policy. It exists only for a device that is a member of the community's current
    /// lineage; every other device is refused here (`Unauthorized`).
    async fn login_recovery_candidate<N>(
        &self,
        origin: &str,
        prepared: cvlt::PreparedOpen,
        binding: &Binding,
        stamps: Option<&cvlt::StampTrust>,
        network: &N,
        now: u64,
    ) -> super::super::Result<cvlt::RecoveryCandidate>
    where
        N: cdht::Network + Clone,
    {
        let checkpoint = {
            let mut record = prepared
                .tor_records(network.clone())
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })?;
            record
                .checkpoint(&prepared.locator())
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })?
        }; // Release the borrowed record before consuming PreparedOpen.
        let completed = SystemClock.now().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Clock",
                ErrorCode::Clock,
                &__cause,
            )
        })?;
        if completed < now {
            return Err(ErrorCode::Clock);
        }
        self.current_policy(origin)?
            .with_current(completed, |current| {
                prepared.prepare_recovery(&checkpoint, current, stamps, binding.member(), completed)
            })
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
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

    /// Give the Board's device signing of an already opened Vault (the open path binds
    /// its community Vault at app start under the initial recovery authority) the same
    /// member authority the restore path binds: the very candidate and bind of
    /// [`Self::recover_login_vault`], without opening a Store again. Refused
    /// (`Unauthorized`) unless this device is in the community's current lineage, in which
    /// case Board signing stays refused. Returns the Board's fresh signing admission.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_member_authority<N>(
        &self,
        origin: &str,
        prepared: cvlt::PreparedOpen,
        binding: &Binding,
        stamps: Option<cvlt::StampTrust>,
        member: MemberAuthorityBuilder,
        network: N,
        slot: &MemberSlot,
        now: u64,
    ) -> super::super::Result<ckmg::IntentAdmission>
    where
        N: cdht::Network + Clone + 'static,
    {
        let candidate = self
            .login_recovery_candidate(origin, prepared, binding, stamps.as_ref(), &network, now)
            .await?;
        let RecoveryOwners {
            authority, intent, ..
        } = member.bind_recovery(stamps, &candidate, network).await?;
        slot.install(binding.clone(), authority)?;
        Ok(intent)
    }
}

impl MemberAuthorityBuilder {
    /// The ONE bind of a login's member authority, for the restore path (which then opens
    /// the Store) and the open path (which installs it into its already opened Vault).
    async fn bind_recovery<'attempt, N: cdht::Network + Clone>(
        self,
        stamps: Option<cvlt::StampTrust>,
        candidate: &'attempt cvlt::RecoveryCandidate,
        network: N,
    ) -> super::super::Result<RecoveryOwners<'attempt, N>> {
        match stamps {
            Some(stamps) => self.with_stamps(stamps),
            None => self,
        }
        .prepare_recovery(candidate, network)
        .await
    }
}
