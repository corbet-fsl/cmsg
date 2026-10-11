//! Original durable candidate joined only to the current accepted first key.
use super::*;
use std::cell::RefCell;

/// Original Passkeys registration tuple retained as one encrypted candidate.
/// No constructor accepts an independently supplied PRF, credential ID or
/// already assembled lower-level candidate.
pub struct InitialEnrollment<B: cwst::backend::Backend> {
    candidate: cvlt::UnenrolledInitial<B>,
    device: PublicKey,
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
        let finish = cfyr::registration::FinishContinuation::from_bytes(bytes)
            .map_err(EnrollmentError::Foyer)?;
        foyer
            .resume_initial_registration(finish, clock)
            .await
            .map_err(EnrollmentError::Foyer)
    }
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
            Err(_) => {
                failed_clock = true;
                u64::MAX
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
    Ok(InitialEnrollment { candidate, device })
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
    let device = opening
        .device()
        .map_err(|e| EnrollmentError::Vault(cvlt::InitialError::Open(e)))?;
    let candidate = opening
        .reopen_enrollment(backend)
        .await
        .map_err(EnrollmentError::Vault)?;
    let finish = cfyr::registration::FinishContinuation::from_bytes(
        candidate
            .finish_continuation()
            .map_err(EnrollmentError::Vault)?,
    )
    .map_err(EnrollmentError::Foyer)?;
    if finish.original_credential_id() != id
        || finish.seed() != candidate.commitment().map_err(EnrollmentError::Vault)?
    {
        return Err(EnrollmentError::Vault(cvlt::InitialError::Invalid));
    }
    Ok(InitialEnrollment { candidate, device })
}

struct SharedClock<'a, C>(Rc<RefCell<&'a mut C>>);
impl<C> Clone for SharedClock<'_, C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<C: Clock> Clock for SharedClock<'_, C> {
    fn now(&mut self) -> Result<u64, Error> {
        self.0.borrow_mut().now()
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
                != self
                    .initial
                    .credential_id()
                    .map_err(|_| Error::Unauthorized)?
        {
            return Err(Error::Unauthorized);
        }
        let observation = self
            .initial
            .observation()
            .map_err(|_| Error::Unauthorized)?;
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
            Err(_) => {
                failed_clock = true;
                u64::MAX
            }
        };
        let scope = self.initial.with_current(&mut sample, |current| {
            current.community() == request.binding.community()
        });
        let completed = self.initial.check(&mut sample);
        if failed_clock {
            return Err(Error::Clock);
        }
        if !scope.map_err(|_| Error::Unauthorized)? {
            return Err(Error::Unauthorized);
        }
        let completed = completed.map_err(|_| Error::Unauthorized)?;
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
    if initial
        .seed()
        .map_err(|_| cvlt::InitialError::Keys(Error::Unauthorized))?
        != seed
    {
        return Err(cvlt::InitialError::Keys(Error::Unauthorized));
    }
    let durable = candidate.activation_intent()?;
    let mut shared = SharedClock(Rc::new(RefCell::new(clock)));
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
