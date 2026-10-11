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
    let acknowledged = candidate
        .acknowledged_initial()
        .map_err(|_| ErrorCode::Unauthorized)?;
    let mut authority = InitialRecoveryAuthority {
        candidate: acknowledged,
        initial,
        clock: SystemClock,
        records: None,
        closed: false,
        account_intent: None,
        account_signing: None,
    };
    let reader = candidate
        .read_lineage(&mut SystemClock, &mut authority)
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let backend = cvlt::TorLineageRecord::provisional_lineage(network, reader)
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    let record = cdht::runtime::Record::new(backend).map_err(|_| ErrorCode::Unavailable)?;
    authority.records =
        Some(cvlt::LineageRecords::new(vec![record]).map_err(|_| ErrorCode::Unavailable)?);
    let recovery = candidate
        .authorize(&mut SystemClock, &mut authority)
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
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
        self.authority
            .initial
            .origin()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let (admission, verifier) = ckmg::intent_channel();
        self.authority.account_intent = Some(verifier);
        Ok((self, admission))
    }

    /// Open only the actual authenticated local winner, or restore the selected
    /// original network checkpoint to an empty destination. Durable read floors
    /// are installed before passkey/compound reads; the exact inner ACK carrier
    /// is checked before Keys, Wallet custody or Vault can escape.
    pub async fn open_root<B: cwst::backend::Backend>(
        mut self,
        network: N,
        backend: B,
    ) -> super::super::Result<InitialRootVault<'a, 'p, B, N>> {
        let occupied = backend
            .read()
            .await
            .map_err(|_| ErrorCode::Unavailable)?
            .is_some();
        if occupied {
            self.recovery
                .load_existing_read_floors(&backend, &mut SystemClock, &mut self.authority)
                .await
                .map_err(|_| ErrorCode::Unavailable)?;
        }
        let records = self
            .recovery
            .tor_passkey_records(network.clone(), &mut SystemClock, &mut self.authority)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let retained = if occupied {
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
        Ok(vault)
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
            .map_err(|_| ErrorCode::Unavailable)
    }
}
