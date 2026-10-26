//! Original durable candidate joined only to the current accepted first key.
use super::*;
use std::cell::RefCell;

/// Original Passkeys registration tuple retained as one encrypted candidate.
/// No constructor accepts an independently supplied PRF, credential ID or
/// already assembled lower-level candidate.
pub struct InitialEnrollment<B: cwst::backend::Backend> {
    candidate: cvlt::UnenrolledInitial<B>,
    device: PublicKey,
    finish: FinishScope,
}

#[derive(Clone, Copy)]
enum FinishScope {
    Community,
    Wallet,
    /// A device-key member's creation: no passkey ceremony, nothing to finish.
    Device,
}

/// Original owner refusal; a failed or uncertain step never retries creation.
#[derive(Debug)]
pub enum EnrollmentError {
    Foyer(cfyr::Error),
    Vault(cvlt::InitialError),
    Passkey(cfyr::passkeys::Error),
}

impl<B: cwst::backend::Backend> InitialEnrollment<B> {
    /// Original PRF-derived public device coordinate, not device authorization.
    pub fn device(&self) -> PublicKey {
        self.device
    }
    /// Resubmit only the original public ceremony retained in the same durable
    /// envelope. A lost reply still requires fresh same-key owner reconciliation.
    pub async fn resume_finish(
        &self,
        foyer: &mut cfyr::Foyer<Transport>,
        clock: impl FnMut() -> u64,
    ) -> Result<(), EnrollmentError> {
        let bytes = self
            .candidate
            .finish_continuation()
            .map_err(EnrollmentError::Vault)?;
        match self.finish {
            FinishScope::Community => {
                let finish = cfyr::registration::FinishContinuation::from_bytes(bytes)
                    .map_err(EnrollmentError::Foyer)?;
                foyer
                    .resume_initial_registration(finish, clock)
                    .await
                    .map_err(EnrollmentError::Foyer)
            }
            FinishScope::Wallet => {
                let finish = cfyr::registration::GlobalFinishContinuation::from_bytes(bytes)
                    .map_err(EnrollmentError::Foyer)?;
                foyer
                    .resume_global_initial_registration(finish, clock)
                    .await
                    .map_err(EnrollmentError::Foyer)
            }
            FinishScope::Device => Err(EnrollmentError::Vault(cvlt::InitialError::Invalid)),
        }
    }

    /// The creation's opaque seed commitment (the one `device_join` registers).
    pub fn seed(&self) -> Result<[u8; 32], cvlt::InitialError> {
        self.candidate.commitment()
    }

    /// A device-key creation's committed time, which its genesis stamp binds.
    pub fn genesis_at(&self) -> Result<u64, cvlt::InitialError> {
        self.candidate.genesis_at()
    }

    /// The `lineage_genesis` stamp action of this device-key creation with the device's salt,
    /// for the same stamp request as the join (one confirmation).
    pub fn lineage_genesis_action(
        &self,
        salt: [u8; 32],
    ) -> Result<cwlt::passport::StampAction, cvlt::InitialError> {
        self.candidate.lineage_genesis_action(salt)
    }

    /// The device signer before activation (join, session, salts): fixed purposes only, the
    /// tag prepended by ckmg. Crate-private: the device producer is its only caller.
    pub(crate) fn sign_device(
        &self,
        format: ckmg::DeviceFormat,
        payload: &[u8],
    ) -> Result<[u8; 64], cvlt::InitialError> {
        self.candidate.sign_device(format, payload)
    }

    /// The candidate device key's stamp salt over `payload` (ckmg's device salt).
    pub(crate) fn device_salt(&self, payload: &[u8]) -> Result<[u8; 32], cvlt::InitialError> {
        self.candidate.device_salt(payload)
    }

    /// [`Self::sign_device`] as `device_join`'s signer.
    pub(crate) fn device_signer(
        &self,
    ) -> impl FnMut(
        crate::door::device_join::DeviceUse,
        Vec<u8>,
    ) -> std::future::Ready<crate::door::Result<Vec<u8>>>
           + '_ {
        move |what, payload| {
            std::future::ready(
                match what {
                    crate::door::device_join::DeviceUse::Sign(format) => self
                        .sign_device(format, &payload)
                        .map(|signature| signature.to_vec()),
                    crate::door::device_join::DeviceUse::Salt => {
                        self.device_salt(&payload).map(|salt| salt.to_vec())
                    }
                }
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "crate::door::ErrorCode::Unauthorized",
                        crate::door::ErrorCode::Unauthorized,
                        &__cause,
                    )
                }),
            )
        }
    }
}

/// Retain a device-key member's first community creation before it joins: the candidate's
/// authority reference is this scope's device key and its genesis time is committed with it.
/// No passkey ceremony and no server mutation happen here; `device_join` (one stamp for the
/// join and the genesis) follows, then the device session and activation.
pub async fn retain_device_enrollment<B: cwst::backend::Backend>(
    opening: cvlt::PreparedOpen,
    seed: ckmg::EnrollmentSeed,
    backend: B,
    name: &str,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    if seed.binding().community() == "wallet" {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
    }
    let device = opening
        .device()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let candidate = opening
        .retain_device_enrollment(backend, seed, name, clock, entropy)
        .await
        .map_err(EnrollmentError::Vault)?;
    Ok(InitialEnrollment {
        candidate,
        device,
        finish: FinishScope::Device,
    })
}

/// Reopen a retained device-key creation after a restart; a passkey candidate refuses.
pub async fn reopen_device_enrollment<B: cwst::backend::Backend>(
    opening: cvlt::PreparedOpen,
    backend: B,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    let device = opening
        .device()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let candidate = opening
        .reopen_enrollment(backend)
        .await
        .map_err(EnrollmentError::Vault)?;
    candidate.genesis_at().map_err(EnrollmentError::Vault)?;
    Ok(InitialEnrollment {
        candidate,
        device,
        finish: FinishScope::Device,
    })
}

/// Join the inseparable original Passkeys registration outputs before persisting
/// any candidate. The credential metadata is read from that same actual result;
/// a caller cannot combine key A's PRF with key B's credential reference here.
/// No accepting server mutation happens until `resume_finish` is called after
/// this returns from the real backend's durable compare-and-set.
#[allow(clippy::too_many_arguments)]
pub async fn retain_initial_enrollment<B: cwst::backend::Backend>(
    foyer: &cfyr::Foyer<Transport>,
    pending: cfyr::registration::PendingInitialRegistration<Transport>,
    registration: cfyr::passkeys::Registration,
    seed: ckmg::EnrollmentSeed,
    backend: B,
    name: &str,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    if seed
        .commitment()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Keys(e)))?
        != pending.seed()
    {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
    }
    let scope = pending.community().to_owned();
    if scope == "wallet" {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
    }
    let (credential, unlock) = registration.into_parts();
    let id = credential
        .credential_id()
        .map_err(EnrollmentError::Passkey)?;
    let info = ckmg::DeviceInfo::new(name, &id)
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Keys(e)))?;
    let mut failed_clock = false;
    let finish = pending
        .prepare_finish(foyer, credential, || match clock.now() {
            Ok(now) => now,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "failed_clock true u64::MAX", &__cause);
                {
                    failed_clock = true;
                    u64::MAX
                }
            }
        })
        .await
        .map_err(EnrollmentError::Foyer)?;
    if failed_clock {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Keys(
            Error::Clock,
        )));
    }
    let bytes = finish.to_bytes().map_err(EnrollmentError::Foyer)?;
    let opening = cvlt::PreparedOpen::new(unlock, &scope)
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let device = opening
        .device()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let candidate = opening
        .retain_enrollment(backend, seed, info, &bytes, clock, entropy)
        .await
        .map_err(EnrollmentError::Vault)?;
    Ok(InitialEnrollment {
        candidate,
        device,
        finish: FinishScope::Community,
    })
}

/// Retain the genuine first Wallet registration tuple under its already frozen
/// UUID/seed binding before the original server finish can be sent. The same
/// encrypted candidate CAS holds its original global finish continuation; this
/// grants neither a session nor certified Create/Use or passport custody.
#[allow(clippy::too_many_arguments)]
pub async fn retain_global_initial_enrollment<B: cwst::backend::Backend>(
    foyer: &cfyr::Foyer<Transport>,
    pending: cfyr::registration::PendingGlobalInitialRegistration<Transport>,
    registration: cfyr::passkeys::Registration,
    seed: ckmg::EnrollmentSeed,
    backend: B,
    name: &str,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    let (credential, unlock) = registration.into_parts();
    let opening = cvlt::PreparedOpen::new(unlock, "wallet")
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    retain_global_initial_enrollment_opened(
        foyer, pending, credential, opening, seed, backend, name, clock, entropy,
    )
    .await
}

/// [`retain_global_initial_enrollment`] with the registration's PRF already held by the
/// device's unlock (`DeviceUnlock::wallet_opening`): the one-ceremony registration keeps
/// that unlock for the birth signatures and every vault, so the create ceremony's PRF is
/// split once and never asked for again. `credential` is the same ceremony's public part.
#[allow(clippy::too_many_arguments)]
pub async fn retain_global_initial_enrollment_opened<B: cwst::backend::Backend>(
    foyer: &cfyr::Foyer<Transport>,
    pending: cfyr::registration::PendingGlobalInitialRegistration<Transport>,
    credential: cfyr::passkeys::PublicCredential,
    opening: cvlt::PreparedOpen,
    seed: ckmg::EnrollmentSeed,
    backend: B,
    name: &str,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    if seed.binding().community() != "wallet"
        || seed.binding().member() != pending.account()
        || seed
            .commitment()
            .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Keys(e)))?
            != pending.seed()
    {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
    }
    let id = credential
        .credential_id()
        .map_err(EnrollmentError::Passkey)?;
    let info = ckmg::DeviceInfo::new(name, &id)
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Keys(e)))?;
    let mut failed_clock = false;
    let finish = pending
        .prepare_finish(foyer, credential, || match clock.now() {
            Ok(now) => now,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "failed_clock true u64::MAX", &__cause);
                {
                    failed_clock = true;
                    u64::MAX
                }
            }
        })
        .await
        .map_err(EnrollmentError::Foyer)?;
    if failed_clock {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Keys(
            Error::Clock,
        )));
    }
    let bytes = finish.to_bytes().map_err(EnrollmentError::Foyer)?;
    let device = opening
        .device()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let candidate = opening
        .retain_enrollment(backend, seed, info, &bytes, clock, entropy)
        .await
        .map_err(EnrollmentError::Vault)?;
    Ok(InitialEnrollment {
        candidate,
        device,
        finish: FinishScope::Wallet,
    })
}

/// Reopen the same encrypted candidate using one original Passkeys assertion
/// tuple. This accepts no server-session claim and returns no authority: its
/// public credential must match the exact retained original finish data. It may
/// therefore recover the pre-finish cancellation cut without inventing login.
pub async fn reopen_initial_enrollment<B: cwst::backend::Backend>(
    authentication: cfyr::passkeys::Authentication,
    scope: &str,
    backend: B,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    let (credential, vault) = authentication.into_parts();
    let id = credential
        .credential_id()
        .map_err(EnrollmentError::Passkey)?;
    let cfyr::passkeys::VaultOutcome::Ready(unlock) = vault else {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Keys(
            Error::Unauthorized,
        )));
    };
    let opening = cvlt::PreparedOpen::new(unlock, scope)
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    reopen_initial_enrollment_opened(&id, opening, scope, backend).await
}

/// [`reopen_initial_enrollment`] from an assertion already split (C7: the restart's ONE
/// assertion also logs the session in, so its credential goes to the login and only its id
/// and PRF opening come here). `id` must be the retained original credential.
pub async fn reopen_initial_enrollment_opened<B: cwst::backend::Backend>(
    id: &[u8],
    opening: cvlt::PreparedOpen,
    scope: &str,
    backend: B,
) -> Result<InitialEnrollment<B>, EnrollmentError> {
    let device = opening
        .device()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let candidate = opening
        .reopen_enrollment(backend)
        .await
        .map_err(EnrollmentError::Vault)?;
    let bytes = candidate
        .finish_continuation()
        .map_err(EnrollmentError::Vault)?;
    let commitment = candidate.commitment().map_err(EnrollmentError::Vault)?;
    // Select by the exact scope used to authenticate the original encrypted
    // Store. Never try another codec after one parser refuses.
    let finish = if scope == "wallet" {
        let finish = cfyr::registration::GlobalFinishContinuation::from_bytes(bytes)
            .map_err(EnrollmentError::Foyer)?;
        if finish.original_credential_id() != id || finish.seed() != commitment {
            return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
        }
        FinishScope::Wallet
    } else {
        let finish = cfyr::registration::FinishContinuation::from_bytes(bytes)
            .map_err(EnrollmentError::Foyer)?;
        if finish.original_credential_id() != id || finish.seed() != commitment {
            return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
        }
        FinishScope::Community
    };
    Ok(InitialEnrollment {
        candidate,
        device,
        finish,
    })
}

pub(super) struct SharedClock<'a, C>(Rc<RefCell<ClockState<'a, C>>>);
struct ClockState<'a, C> {
    clock: &'a mut C,
    floor: Option<u64>,
    failed: bool,
}
impl<'a, C> SharedClock<'a, C> {
    pub(super) fn new(clock: &'a mut C) -> Self {
        Self(Rc::new(RefCell::new(ClockState {
            clock,
            floor: None,
            failed: false,
        })))
    }
}
impl<C> Clone for SharedClock<'_, C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<C: Clock> Clock for SharedClock<'_, C> {
    fn now(&mut self) -> Result<u64, Error> {
        let mut state = self.0.borrow_mut();
        if state.failed {
            return Err(Error::Clock);
        }
        // Keep every observed sample across owner and operation clones. A clock
        // error, regression or unwind permanently fences this live attempt.
        state.failed = true;
        let now = state.clock.now()?;
        if state.floor.is_some_and(|floor| now < floor) {
            return Err(Error::Clock);
        }
        state.floor = Some(now);
        state.failed = false;
        Ok(now)
    }
}

struct Activation<'p, C> {
    initial: cfyr::membership::InitialCreationLease<'p, Transport>,
    clock: C,
    seed: [u8; 32],
    durable: ckmg::InitialActivationIntent,
    closed: bool,
}
impl<C: Clock> Activation<'_, C> {
    fn current(&mut self, request: ckmg::InitialActivationAuthorization<'_>) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Unauthorized);
        }
        // Every refusal is terminal for this attempt, including after durable CAS.
        self.closed = true;
        if request.seed != &self.seed
            || request.durable.generation != self.durable.generation
            || request.durable.digest != self.durable.digest
            || request.authority_reference
                != self.initial.credential_id().map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Unauthorized",
                        Error::Unauthorized,
                        &__cause,
                    )
                })?
        {
            return Err(Error::Unauthorized);
        }
        let observation = self.initial.observation().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        if observation.member != request.binding.member()
            || !observation
                .device_keys
                .iter()
                .any(|key| request.device == PublicKey::new(ckmg::VLD0, *key))
        {
            return Err(Error::Unauthorized);
        }
        let mut failed_clock = false;
        let clock = &mut self.clock;
        let mut sample = || match clock.now() {
            Ok(now) => now,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "failed_clock true u64::MAX", &__cause);
                {
                    failed_clock = true;
                    u64::MAX
                }
            }
        };
        let scope = self.initial.with_current(&mut sample, |current| {
            current.community() == request.binding.community()
                && !current.revocations().device_revoked(request.device.value())
        });
        let completed = self.initial.check(&mut sample);
        if failed_clock {
            return Err(Error::Clock);
        }
        if !scope.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })? {
            return Err(Error::Unauthorized);
        }
        let completed = completed.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        if completed < request.now {
            return Err(Error::Clock);
        }
        self.closed = false;
        Ok(completed)
    }
}
impl<C: Clock> ckmg::Authority for Activation<'_, C> {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
    async fn check_initial_activation(
        &mut self,
        request: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.current(request)
    }
    fn check_initial_activation_current(
        &mut self,
        request: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.current(request)
    }
}

/// Activate only the original encrypted candidate that is already durable before
/// server registration acceptance. The same authenticated first key must carry
/// its immutable seed and currently authorize the original device in this exact
/// community. No registration/session JSON or arbitrary certificate is accepted.
///
/// This produces only the original pending creation. Ordinary Use, genesis
/// signing and recovery remain denied until their separate owner joins succeed.
/// Cancellation or an unknown durable outcome requires reopening the original
/// backend; this function never creates a seed, key, operation or replacement root.
pub async fn activate_initial<B: cwst::backend::Backend>(
    enrollment: InitialEnrollment<B>,
    initial: cfyr::membership::InitialCreationLease<'_, Transport>,
    clock: &mut impl Clock,
    entropy: &mut impl ckmg::Entropy,
) -> Result<cvlt::InitialCreation<B>, cvlt::InitialError> {
    let candidate = enrollment.candidate;
    let seed = candidate.commitment()?;
    if initial.seed().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "cvlt::InitialError::Keys Error::Unauthorized",
            cvlt::InitialError::Keys(Error::Unauthorized),
            &__cause,
        )
    })? != seed
    {
        return Err(cvlt::InitialError::Keys(Error::Unauthorized));
    }
    let durable = candidate.activation_intent()?;
    let mut shared = SharedClock::new(clock);
    let mut authority = Activation {
        initial,
        clock: shared.clone(),
        seed,
        durable,
        closed: false,
    };
    candidate
        .activate(&mut shared, entropy, &mut authority)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Samples(VecDeque<Result<u64, Error>>);
    impl Clock for Samples {
        fn now(&mut self) -> Result<u64, Error> {
            self.0.pop_front().expect("declared clock sample")
        }
    }

    #[test]
    fn original_owner_and_operation_clones_share_a_terminal_monotonic_floor() {
        let mut source = Samples(VecDeque::from([Ok(100), Ok(90), Ok(110)]));
        let mut operation = SharedClock::new(&mut source);
        let mut owner = operation.clone();
        assert_eq!(operation.now().unwrap(), 100);
        assert_eq!(owner.now().unwrap_err(), Error::Clock);
        assert_eq!(operation.now().unwrap_err(), Error::Clock);
        drop((owner, operation));
        assert_eq!(source.0.front(), Some(&Ok(110)));
    }

    #[test]
    fn original_clock_error_cannot_be_cleared_by_a_later_success() {
        let mut source = Samples(VecDeque::from([Ok(100), Err(Error::Clock), Ok(110)]));
        let mut operation = SharedClock::new(&mut source);
        let mut owner = operation.clone();
        assert_eq!(owner.now().unwrap(), 100);
        assert_eq!(operation.now().unwrap_err(), Error::Clock);
        assert_eq!(owner.now().unwrap_err(), Error::Clock);
    }
}
