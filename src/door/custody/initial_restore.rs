//! Cold recovery of an authenticated original ACK without historical time claims.
use super::initial_recovery::InitialRecoveryAuthority;
use super::*;

/// Original restored Vault under a retained, freshly checked same-key lease.
/// Its owner refuses any operation outside the exact initial lineage; later
/// rotated lineages require their original normal recovery path.
pub type InitialRecoveredVault<'a, 'p, B, N> = cvlt::Vault<
    B,
    SystemClock,
    ckmg::SystemEntropy,
    InitialRecoveryAuthority<'a, 'p, SystemClock, N>,
    cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
    cvlt::WalletCustody,
>;

/// Original common-root custody after the complete initial ACK recovery join.
/// Wallet restoration/initialization remains a separate mandatory owner step.
pub type InitialRootVault<'a, 'p, B, N> = cvlt::Vault<
    B,
    SystemClock,
    ckmg::SystemEntropy,
    InitialRecoveryAuthority<'a, 'p, SystemClock, N>,
    cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
    (),
>;

/// The Door's community Vault of a composed member device: initial recovery custody, with
/// Board device signing handed to a member authority once the start restore installs it
/// (`MemberSlot`, see `LateMemberAuthority`).
pub type MemberVault<'a, 'p, B, N> = cvlt::Vault<
    B,
    SystemClock,
    ckmg::SystemEntropy,
    LateMemberAuthority<InitialRecoveryAuthority<'a, 'p, SystemClock, N>>,
    cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
    cvlt::WalletCustody,
>;

/// The Door's one Vault of a freshly composed member device: the community Store
/// with its account-only custody, the account actor's channels for
/// `account_open::bind_member_account` and this custody session's lifetime.
pub struct ComposedMemberVault<'a, 'p, B: cwst::backend::Backend, N: cdht::Network> {
    pub vault: MemberVault<'a, 'p, B, N>,
    /// Board signing intent. The initial authority admits no Board signing, so its
    /// verifier is not kept: a Board signature on this Vault is refused until the start
    /// restore installs a member authority in `member` and a fresh admission here.
    pub intent: ckmg::IntentAdmission,
    /// Where the start restore installs the member authority (once this device is in
    /// the community's current lineage).
    pub member: MemberSlot,
    pub account: AccountWiring,
    pub lifetime: CustodyLifetime,
}

/// Current original owners retained until actual Store and network recovery
/// agree. This preparation is neither a Vault nor a runtime readiness signal.
pub struct InitialRecoveryOwners<'a, 'p, N: cdht::Network> {
    recovery: cvlt::PreparedRecovery<'a>,
    authority: InitialRecoveryAuthority<'a, 'p, SystemClock, N>,
}

/// Authenticate the original ACK, refresh its genuine same-key HTTPS lease,
/// force the original lineage read, then acquire ordinary bootstrap authority.
/// `candidate` must come from `PreparedOpen::prepare_initial_recovery`; fresh
/// certificates cannot grant this route to pending or legacy checkpoints.
///
/// Tor callers must obtain `network` through `Network::initial_records` before
/// moving `initial`, preserving the enforced independent transport Foyer.
pub async fn prepare_initial_recovery<'a, 'p, N: cdht::Network + Clone>(
    candidate: &'a cvlt::RecoveryCandidate,
    initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    network: N,
) -> super::super::Result<InitialRecoveryOwners<'a, 'p, N>> {
    prepare_recovery(candidate, initial, network, None).await
}

/// [`prepare_initial_recovery`] of a device-key member: `initial` is its device lease and
/// every check reauthorizes its stamp genesis with the wallet's stamp trust.
pub async fn prepare_device_initial_recovery<'a, 'p, N: cdht::Network + Clone>(
    candidate: &'a cvlt::RecoveryCandidate,
    initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    network: N,
    stamps: &cvlt::StampTrust,
) -> super::super::Result<InitialRecoveryOwners<'a, 'p, N>> {
    prepare_recovery(candidate, initial, network, Some(stamps.clone())).await
}

async fn prepare_recovery<'a, 'p, N: cdht::Network + Clone>(
    candidate: &'a cvlt::RecoveryCandidate,
    initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    network: N,
    stamps: Option<cvlt::StampTrust>,
) -> super::super::Result<InitialRecoveryOwners<'a, 'p, N>> {
    let acknowledged = candidate.acknowledged_initial().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    let mut authority = InitialRecoveryAuthority {
        candidate: acknowledged,
        initial,
        clock: SystemClock,
        records: None,
        closed: false,
        account_intent: None,
        delegation_intent: None,
        request_intent: None,
        delegation_spent: false,
        account_signing: None,
        stamps,
    };
    let reader = candidate
        .read_lineage(&mut SystemClock, &mut authority)
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
    let backend = cvlt::TorLineageRecord::provisional_lineage(network, reader)
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
    authority.records = Some(cvlt::LineageRecords::new(vec![record]).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?);
    let recovery = candidate
        .authorize(&mut SystemClock, &mut authority)
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
    Ok(InitialRecoveryOwners {
        recovery,
        authority,
    })
}

impl<'a, 'p, N: cdht::Network + Clone> InitialRecoveryOwners<'a, 'p, N> {
    /// Enable only fixed account-device authorization after normal recovery.
    /// The trusted Door retains the returned admission channel and must admit
    /// the exact Keys-prepared transcript at this owner's authenticated origin.
    /// It is not an INITIAL ACK signing grant; every attempt still performs fresh
    /// HTTPS, forced lineage, same-key certificate and final live-owner checks.
    pub fn with_account_device_intent(
        mut self,
    ) -> super::super::Result<(Self, ckmg::IntentAdmission)> {
        if self.authority.closed || self.authority.account_intent.is_some() {
            return Err(ErrorCode::Unauthorized);
        }
        self.authority.initial.origin().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        let (admission, verifier) = ckmg::intent_channel();
        self.authority.account_intent = Some(verifier);
        Ok((self, admission))
    }

    /// Enable the fixed account enrollment composer with three separate one-use
    /// admission channels: root authorization, the complete delegation, and the
    /// account request signature. One approval never authorizes two signatures.
    /// The returned owner exposes no arbitrary transcript-admission method.
    pub fn with_accounting_intents(
        mut self,
    ) -> super::super::Result<(
        Self,
        super::super::accounting::AccountingIntents,
        ckmg::IntentAdmission,
    )> {
        if self.authority.closed
            || self.authority.account_intent.is_some()
            || self.authority.delegation_intent.is_some()
            || self.authority.request_intent.is_some()
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.authority.initial.origin().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        let (root, root_verifier) = ckmg::intent_channel();
        let (device, device_verifier) = ckmg::intent_channel();
        let (request, request_verifier) = ckmg::intent_channel();
        self.authority.account_intent = Some(root_verifier);
        self.authority.delegation_intent = Some(device_verifier);
        self.authority.request_intent = Some(request_verifier);
        let expires = self.authority.initial.expires().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        Ok((
            self,
            super::super::accounting::AccountingIntents {
                root,
                device,
                expires,
            },
            request,
        ))
    }

    /// Open only the actual authenticated local winner, or restore the selected
    /// original network checkpoint to an empty destination. Durable read floors
    /// are installed before passkey/compound reads; the exact inner ACK carrier
    /// is checked before Keys, Wallet custody or Vault can escape.
    pub async fn open_root<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<InitialRootVault<'a, 'p, B, N>> {
        self.open_root_with(network, backend, |authority| authority)
            .await
    }

    /// [`Self::open_root`] with the Vault's authority wrapped by `wrap`; the
    /// recovery reads themselves always run under the initial authority.
    async fn open_root_with<B: cwst::backend::Backend, A: ckmg::Authority>(
        mut self,
        network: N,
        backend: B,
        wrap: impl FnOnce(InitialRecoveryAuthority<'a, 'p, SystemClock, N>) -> A,
    ) -> super::super::Result<
        cvlt::Vault<
            B,
            SystemClock,
            ckmg::SystemEntropy,
            A,
            cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
            (),
        >,
    > {
        let occupied = backend
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
            .is_some();
        if occupied {
            self.recovery
                .load_existing_read_floors(&backend, &mut SystemClock, &mut self.authority)
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
        }
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
        let retained = if occupied {
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
            authority: wrap(self.authority),
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
        Ok(vault)
    }

    /// Restore the existing global holder and retain its genuine recovery origin.
    /// No caller endpoint or generic Vault can construct this sealed pairing.
    pub async fn open_global_passport<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<
        super::super::passport::GlobalPassport<
            B,
            SystemClock,
            ckmg::SystemEntropy,
            InitialRecoveryAuthority<'a, 'p, SystemClock, N>,
            cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
        >,
    > {
        let origin = self
            .authority
            .initial
            .origin()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unauthorized",
                    ErrorCode::Unauthorized,
                    &__cause,
                )
            })?
            .to_owned();
        let vault = self
            .open_root(network, backend)
            .await?
            .restore_global_passport()
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
        super::super::passport::GlobalPassport::recovered(origin, vault).await
    }

    /// Restore only the existing community account and seal its actual recovery
    /// origin into the local account composer. No caller origin, new key or
    /// ordinary missing-state initialization is accepted by this constructor.
    pub async fn open_community_account<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<
        super::super::accounting::CommunityAccount<
            B,
            SystemClock,
            ckmg::SystemEntropy,
            InitialRecoveryAuthority<'a, 'p, SystemClock, N>,
            cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
        >,
    > {
        let origin = self
            .authority
            .initial
            .origin()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unauthorized",
                    ErrorCode::Unauthorized,
                    &__cause,
                )
            })?
            .to_owned();
        let vault = self
            .open_root(network, backend)
            .await?
            .restore_account_only_custody()
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
        super::super::accounting::CommunityAccount::recovered(
            origin,
            super::super::accounting::AccountVault::Owned(vault),
        )
        .await
    }

    /// Open the community Store ONCE for the Door (single owner per Store): the
    /// account-only custody, plus the three account channels the actor spends
    /// through its port. The initial authority spends those channels by itself,
    /// so the port's arm selects nothing here.
    pub async fn open_member_vault<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<ComposedMemberVault<'a, 'p, B, N>> {
        let (owners, intents, request) = self.with_accounting_intents()?;
        let arm = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut member = None;
        let mut vault = owners
            .open_root_with(network, backend, |initial| {
                let (late, slot) = LateMemberAuthority::new(initial, arm.clone());
                member = Some(slot);
                late
            })
            .await?
            .restore_account_only_custody()
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
        let binding = vault
            .keys()
            .lineage()
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
            .binding;
        let device = vault.keys().device_public_key().await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let (intent, _) = ckmg::intent_channel();
        // The late member authority reports its bound here; this Vault's grants clamp to it.
        let slot_bound = member
            .as_ref()
            .map(MemberSlot::signing_bound)
            .unwrap_or_default();
        Ok(ComposedMemberVault {
            vault,
            intent,
            member: member.ok_or(ErrorCode::Unavailable)?,
            account: AccountWiring {
                intents,
                request,
                arm: AccountArm(arm),
            },
            lifetime: CustodyLifetime {
                binding,
                device,
                closed: std::rc::Rc::new(std::cell::Cell::new(false)),
                bound: slot_bound,
            },
        })
    }

    /// Restore both original existing Wallet owners after the complete root
    /// recovery join. Missing accounting or passport custody refuses unchanged.
    pub async fn open<B: cwst::backend::Backend>(
        self,
        network: N,
        backend: B,
    ) -> super::super::Result<InitialRecoveredVault<'a, 'p, B, N>> {
        self.open_root(network, backend)
            .await?
            .restore_wallet_custody()
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })
    }
}
