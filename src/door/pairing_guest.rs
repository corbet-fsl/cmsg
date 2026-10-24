//! The NEW device's concrete steps of a pairing ([`GuestSteps`]) over cvlt: one
//! [`DeviceUnlock`] (the ONE wallet passkey ceremony of the new device) opens every
//! community's vault, for the request AND for the adoption, so three scopes are one
//! confirmation on this device too.
//!
//! The device only ever signs proof of possession of its own pairing key
//! (`cvlt::PairingGuest::sign_possession`); the community's identity (its founding-key
//! fingerprint, which names the vault) comes from the caller's [`Targets`], resolved from the
//! community itself, never from the existing device. The pending request and the adopted grant
//! live in this value for the pairing session: the existing device loses its offer on a
//! restart too, so a restarted pairing starts again with a new link, and the durable Keys
//! output is cleared by [`DoorGuest::finish`] once every scope is active.
use super::pairing_roles::{GuestSteps, Scope};
use super::device_pair::StepChallenge;
use super::unlock_once::DeviceUnlock;
use super::*;
use ckmg::{Clock, Entropy, PairingPossession, PairingStep};
use cvlt::{AcceptedPairing, PairingGuest};
use std::collections::BTreeMap;

/// Where one community's vault of the new device lives.
pub struct Target<B> {
    /// The vault's record store (empty for a new device).
    pub backend: B,
    /// The community's identity: its founding-key fingerprint.
    pub fingerprint: [u8; 32],
}

/// Resolves the vault of a community scope (by community name).
pub trait Targets<B> {
    /// The target of community `name`, or `None` when the device cannot reach it.
    fn target(&mut self, name: &str) -> Option<Target<B>>;
}

enum Phase<B: cwst::backend::Backend, C: Clock, E: Entropy> {
    /// Requested; waiting for the grant.
    Requested(PairingGuest<B, C, E>),
    /// The grant is adopted; waiting for the key to become active.
    Accepted(AcceptedPairing<B, C, E>),
}

/// [`GuestSteps`] for the new device: one unlock, one phase per community scope.
pub struct DoorGuest<B, C, E, T>
where
    B: cwst::backend::Backend + Clone,
    C: Clock + Clone,
    E: Entropy + Clone,
{
    unlock: DeviceUnlock,
    info: ckmg::DeviceInfo,
    targets: T,
    clock: C,
    entropy: E,
    phases: BTreeMap<Scope, Phase<B, C, E>>,
}

impl<B, C, E, T> DoorGuest<B, C, E, T>
where
    B: cwst::backend::Backend + Clone,
    C: Clock + Clone,
    E: Entropy + Clone,
    T: Targets<B>,
{
    /// The new device with its ONE wallet `unlock`, describing itself as `info`.
    pub fn new(unlock: DeviceUnlock, info: ckmg::DeviceInfo, targets: T, clock: C, entropy: E) -> Self {
        Self {
            unlock,
            info,
            targets,
            clock,
            entropy,
            phases: BTreeMap::new(),
        }
    }

    fn name(scope: &Scope) -> Result<&str> {
        match scope {
            // The wallet scope has no server pairing action (see `SessionHost`).
            Scope::Wallet => Err(ErrorCode::Unavailable),
            Scope::Community(name) => Ok(name),
        }
    }

    /// Clear the durable output of every adopted scope. Call once the run ended `Ok`.
    pub async fn finish(&mut self) -> Result<()> {
        for (_, phase) in std::mem::take(&mut self.phases) {
            if let Phase::Accepted(accepted) = phase {
                accepted.acknowledge().await.map_err(|_| ErrorCode::Unavailable)?;
            }
        }
        Ok(())
    }
}

fn possession<'a>(
    name: &'a str,
    step: PairingStep,
    challenge: &'a StepChallenge,
    device: &[u8; 32],
) -> Result<PairingPossession<'a>> {
    PairingPossession::new(name, step, &challenge.id, device).map_err(|_| ErrorCode::InvalidRequest)
}

impl<B, C, E, T> GuestSteps for DoorGuest<B, C, E, T>
where
    B: cwst::backend::Backend + Clone,
    C: Clock + Clone,
    E: Entropy + Clone,
    T: Targets<B>,
{
    async fn request(&mut self, scope: &Scope, anchor: ckmg::Lineage) -> Result<ckmg::PairingRequest> {
        let name = Self::name(scope)?.to_owned();
        if self.phases.contains_key(scope) {
            return Err(ErrorCode::InvalidRequest);
        }
        let target = self.targets.target(&name).ok_or(ErrorCode::Unavailable)?;
        let opening = self.unlock.community_opening(&target.fingerprint, &name)?;
        let (request, guest) = opening
            .request_pairing(
                target.backend,
                &anchor,
                self.info.clone(),
                self.clock.clone(),
                self.entropy.clone(),
            )
            .await
            .map_err(|_| ErrorCode::Refused)?;
        self.phases.insert(scope.clone(), Phase::Requested(guest));
        Ok(request)
    }

    async fn possess(&mut self, scope: &Scope, challenge: StepChallenge) -> Result<Vec<u8>> {
        let name = Self::name(scope)?;
        let Some(Phase::Requested(guest)) = self.phases.get(scope) else {
            return Err(ErrorCode::InvalidRequest);
        };
        let message = possession(name, PairingStep::Add, &challenge, guest.request().device.value())?;
        Ok(guest
            .sign_possession(&message)
            .map_err(|_| ErrorCode::Refused)?
            .to_vec())
    }

    async fn accept(
        &mut self,
        scope: &Scope,
        grant: ckmg::PairingGrant,
        challenge: StepChallenge,
    ) -> Result<Vec<u8>> {
        let name = Self::name(scope)?.to_owned();
        let Some(Phase::Requested(guest)) = self.phases.remove(scope) else {
            return Err(ErrorCode::InvalidRequest);
        };
        let accepted = guest.accept(&grant).await.map_err(|_| ErrorCode::Refused)?;
        let device = *grant.request.device.value();
        let signature = {
            let message = possession(&name, PairingStep::Activate, &challenge, &device)?;
            accepted
                .sign_possession(&message)
                .map_err(|_| ErrorCode::Refused)?
                .to_vec()
        };
        self.phases.insert(scope.clone(), Phase::Accepted(accepted));
        Ok(signature)
    }
}
