//! The native device's wave proof capabilities: the circuit provers of the extension
//! group ([`NativeWaveProver`], a [`WaveProver`]) and the update transport over the
//! member's account actor ([`ActorTransport`], an [`UpdateTransport`]).
//!
//! Both are small adapters the background wave worker composes into its
//! [`AccountWallet`](super::wallet::AccountWallet); neither holds a key, an opening or
//! a policy. A proof runs on a blocking worker thread, never on the Door's task; the
//! Door is locked only for the one short account-actor call of an update or settle.
use super::super::{
    account::{Answer, Applied, Command, Shared},
    accounting::ProvenUpdate,
    courier::SharedDoor,
    registry, Door, ErrorCode, Result,
};
use super::super::facades::OwnedFuture;
use super::account_ports::AccountView;
use super::wallet::{WalletState, WaveProver};
use super::witness::UpdateTransport;
use ckmg::wallet_engine::account::{Account, Checkpoint, Evidence, UpdateInput};
use ckmg::wallet_engine::native_prover::{NativeProver, PreparedProof, Program};
use std::{cell::RefCell, rc::Rc, sync::Arc};

/// The three provers of one extension group: the account update (reserve, activate,
/// settle) and the `wave` and `outcome` evidence. Each is bound to its own member.
pub struct NativeWaveProver {
    update: NativeProver,
    wave: NativeProver,
    outcome: NativeProver,
}

impl NativeWaveProver {
    /// Refuses unless every prover runs the member it is used for.
    pub fn new(update: NativeProver, wave: NativeProver, outcome: NativeProver) -> Result<Self> {
        if update.program() != Program::Update
            || wave.program() != Program::Wave
            || outcome.program() != Program::Outcome
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            update,
            wave,
            outcome,
        })
    }
}

/// Prove off the current task. A failed or cancelled proof is `Unavailable`: the job
/// stays recorded and is offered again.
async fn run(job: PreparedProof) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || job.run())
        .await
        .map_err(|_| ErrorCode::Unavailable)?
        .map_err(|_| ErrorCode::Unavailable)
}

impl WaveProver for NativeWaveProver {
    async fn prove_update(&mut self, input: &UpdateInput) -> Result<Vec<u8>> {
        let job = self
            .update
            .prepare_update(input)
            .map_err(|_| ErrorCode::Refused)?;
        run(job).await
    }
    async fn prove_evidence(&mut self, evidence: &Evidence) -> Result<Vec<u8>> {
        let prover = if evidence.is_outcome() {
            &self.outcome
        } else {
            &self.wave
        };
        let job = prover
            .prepare_wave_evidence(evidence)
            .map_err(|_| ErrorCode::Refused)?;
        run(job).await
    }
}

/// The D2 update actor of one member origin, reached through the shared Door. The
/// actor stores the signed update before the first send and re-sends the identical
/// bytes on any retry, so a restart between the calls never proves or signs twice.
pub struct ActorTransport {
    pub door: SharedDoor,
    pub origin: String,
}

impl UpdateTransport for ActorTransport {
    async fn update(&mut self, proven: ProvenUpdate) -> Result<Shared<Applied>> {
        let mut door = self.door.lock().await;
        match registry::account_call_at(&mut door, &self.origin, Command::Update(Shared::new(proven)))
            .await?
        {
            Answer::Updated(applied) => Ok(applied),
            _ => Err(ErrorCode::Unavailable),
        }
    }
    async fn settle(&mut self, request_id: [u8; 32]) -> Result<()> {
        let mut door = self.door.lock().await;
        match registry::account_call_at(&mut door, &self.origin, Command::Settle(request_id)).await? {
            Answer::Settled => Ok(()),
            _ => Err(ErrorCode::Unavailable),
        }
    }
}

/// The verified current common roster (every member's enrollment row under the
/// published root) of the member at `origin`, current for each witness load: a
/// counterpart enrolled after the last load must be found.
pub trait RosterSource {
    fn roster<'a>(&'a self, door: &'a SharedDoor, origin: &'a str) -> OwnedFuture<'a, Arc<Checkpoint>>;
}

/// The roster through the member's account actor (`Command::Roster`: a fresh
/// admission, the signed current publication verified row by row). A publication is
/// frozen for its slot, so it is kept until the slot ends and read again after:
/// within a slot no counterpart can be added, and a new slot is always read.
#[derive(Clone, Default)]
pub struct ActorRoster(Rc<RefCell<Option<(Arc<Checkpoint>, u64)>>>);

impl ActorRoster {
    fn cached(&self, now: u64) -> Option<Arc<Checkpoint>> {
        match &*self.0.borrow() {
            Some((roster, expires_at)) if now < *expires_at => Some(Arc::clone(roster)),
            _ => None,
        }
    }
}

impl RosterSource for ActorRoster {
    fn roster<'a>(&'a self, door: &'a SharedDoor, origin: &'a str) -> OwnedFuture<'a, Arc<Checkpoint>> {
        Box::pin(async move {
            let now = || ckmg::Clock::now(&mut super::super::custody::SystemClock).map_err(|_| ErrorCode::Clock);
            if let Some(roster) = self.cached(now()?) {
                return Ok(roster);
            }
            let answer = {
                let mut door = door.lock().await;
                registry::account_call_at(&mut door, origin, Command::Roster).await?
            };
            let Answer::Roster(read) = answer else {
                return Err(ErrorCode::Unavailable);
            };
            // A slot that already ended by now is never kept.
            if now()? >= read.expires_at {
                return Err(ErrorCode::Unavailable);
            }
            *self.0.borrow_mut() = Some((Arc::clone(&read.checkpoint), read.expires_at));
            Ok(Arc::clone(&read.checkpoint))
        })
    }
}

/// The newest witness the wave ports read (contact digests, the recipient's terms). The
/// wallet refreshes it on every load and store; it is empty, and every port that needs
/// it refuses, until the first load. The ports run while the Door is locked, so they
/// read this view and never call the account actor themselves.
#[derive(Clone, Default)]
pub struct WitnessView(Rc<RefCell<Option<Account>>>);

impl WitnessView {
    fn set(&self, account: &Account) {
        *self.0.borrow_mut() = Some(account.clone());
    }
}

impl AccountView for WitnessView {
    fn current<'a>(&'a self) -> OwnedFuture<'a, Account> {
        Box::pin(async move { self.0.borrow().clone().ok_or(ErrorCode::Unavailable) })
    }
}

/// The wave wallet's state in the account's own Vault custody (the sealed witness
/// record), reached through the account actor.
pub struct ActorWitness<R> {
    pub door: SharedDoor,
    pub origin: String,
    pub roster: R,
    pub view: WitnessView,
}

impl<R: RosterSource> WalletState for ActorWitness<R> {
    async fn load(&mut self) -> Result<Account> {
        let roster = self.roster.roster(&self.door, &self.origin).await?;
        let mut door = self.door.lock().await;
        match registry::account_call_at(
            &mut door,
            &self.origin,
            Command::WitnessLoad(Shared::new(roster)),
        )
        .await?
        {
            Answer::Witness(account) => {
                self.view.set(&account);
                Ok((*account).clone())
            }
            _ => Err(ErrorCode::Unavailable),
        }
    }
    async fn store(&mut self, account: &Account) -> Result<()> {
        let mut door = self.door.lock().await;
        match registry::account_call_at(
            &mut door,
            &self.origin,
            Command::WitnessStore(Shared::new(account.clone())),
        )
        .await?
        {
            Answer::WitnessStored => {
                self.view.set(account);
                Ok(())
            }
            _ => Err(ErrorCode::Unavailable),
        }
    }
}

/// The native device's wave worker: each round reopens the account witness under the
/// verified current roster (refreshing the ports' view), derives the wave trust from
/// the verified feed (refreshing the ports' trust), and drains the job journal with an
/// [`AccountWallet`](super::wallet::AccountWallet) over the extension group's provers
/// and the D2 actor. `view` and `trust` are the same cells the device's ports read.
pub fn device_worker<R>(
    provers: Rc<dyn Fn() -> Result<NativeWaveProver>>,
    roster: R,
    view: WitnessView,
    trust: super::feed_trust::FeedTrust,
) -> Rc<dyn super::super::wave_job::WaveWorker>
where
    R: RosterSource + Clone + 'static,
{
    use super::wallet::{AccountWallet, RosterContactAuthority, WaveScope};
    use super::witness::DoorUpdateSink;
    let clock = || ckmg::Clock::now(&mut super::super::custody::SystemClock).unwrap_or(u64::MAX);
    Rc::new(super::super::wave_job::WalletWorker(
        move |door: SharedDoor, origin: String| {
            let provers = provers.clone();
            let roster = roster.clone();
            let view = view.clone();
            let trust = trust.clone();
            async move {
                let mut state = ActorWitness {
                    door: door.clone(),
                    origin: origin.clone(),
                    roster,
                    view,
                };
                let account = state.load().await?;
                let now = clock();
                let leaf = account.owner().leaf;
                let fresh = {
                    let guard = door.lock().await;
                    guard
                        .current_policy(&origin)?
                        .with_current(now, |charter| super::feed_trust::derive(charter, leaf, now))
                        .map_err(|_| ErrorCode::Unavailable)??
                };
                trust.set(fresh.clone());
                // The circuit's issuer key is the ring key of the period that holds the
                // acceptance of the states this round produces (now).
                let issuer_key = czkp::issuer_keys::key_at(&fresh.wave.certificate_keys, now)
                    .map_err(|_| ErrorCode::Unavailable)?;
                Ok(AccountWallet {
                    state,
                    prover: provers()?,
                    sink: DoorUpdateSink::new(
                        ActorTransport {
                            door: door.clone(),
                            origin: origin.clone(),
                        },
                        fresh.wave.proof_scope.clone(),
                    ),
                    authority: RosterContactAuthority,
                    clock,
                    wave: WaveScope {
                        scope: fresh.wave.proof_scope.circuit_digest,
                        issuer_key,
                    },
                })
            }
        },
    ))
}

/// What the trusted embedding hands the Door at login for the wave stack of one member
/// origin: the retained extension group and the record-currency mark of the background
/// record job. The restoring composer, which alone holds the member's network, turns it
/// into the ports and the worker ([`bind_device`]).
#[derive(Clone)]
pub struct WaveDevice {
    pub artifacts: super::super::composer::ProverArtifacts,
    pub record: super::super::record::RecordCurrent,
}

/// Install the wave capabilities and the wave worker of a restored native device.
///
/// Nothing is bound (`Ok(false)`) unless the settings carry both the `wave` and the
/// `outcome` circuit. Otherwise everything is built before anything is installed: a
/// verifier group that does not authenticate, or any refusal of the Door, leaves the
/// origin without ports and without a worker, so a device never half-runs waves.
/// `opener` reads the peers' retained handles over the member's network and `charter`
/// is the Door's verified view of the community's current Charter.
pub fn bind_device<O, V>(
    door: &mut Door,
    origin: &str,
    device: &WaveDevice,
    opener: O,
    charter: V,
) -> Result<bool>
where
    O: super::super::inbox_lineage::HandleOpener + Clone + 'static,
    V: super::super::inbox_lineage::CharterView + 'static,
{
    use super::account_ports::{AccountContact, AccountTerms};
    use super::feed_trust::FeedTrust;
    use super::production::ProductionPorts;
    use super::super::inbox_lineage::{HandleBook, WavePeerLineage};
    let (Some(_), Some(_)) = (&device.artifacts.wave, &device.artifacts.outcome) else {
        return Ok(false);
    };
    if door.waves_installed(origin) {
        return Err(ErrorCode::Unauthorized);
    }
    let verifier = device
        .artifacts
        .wave_verifier_factory()
        .map_err(|_| ErrorCode::Unavailable)?;
    let view = WitnessView::default();
    let trust = FeedTrust::default();
    let clock = || ckmg::Clock::now(&mut super::super::custody::SystemClock).ok();
    let entropy = || -> Result<[u8; 32]> {
        let mut nonce = [0u8; 32];
        ckmg::Entropy::fill(&mut ckmg::SystemEntropy, &mut nonce)
            .map_err(|_| ErrorCode::Unavailable)?;
        Ok(nonce)
    };
    let ports = ProductionPorts::new(
        Box::new(trust.clone()),
        Box::new(AccountTerms {
            view: view.clone(),
            entropy,
        }),
        Box::new(AccountContact { view: view.clone() }),
        Box::new(device.record.clone()),
        Box::new(WavePeerLineage::new(HandleBook::default(), opener, charter)),
        verifier,
        Box::new(clock),
    );
    let artifacts = device.artifacts.clone();
    let provers: Rc<dyn Fn() -> Result<NativeWaveProver>> = Rc::new(move || {
        artifacts
            .wave_provers()
            .map_err(|_| ErrorCode::Unavailable)?
            .ok_or(ErrorCode::Unavailable)
    });
    let worker = device_worker(provers, ActorRoster::default(), view, trust);
    door.bind_waves(origin, Box::new(ports))?;
    // Cannot be refused: the origin was free of both when it was checked above.
    door.set_wave_worker(origin, worker)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::{Configuration, Door, Role};
    use ckmg::wallet_engine::account::RosterRow;
    use std::collections::{BTreeMap, BTreeSet};

    const ORIGIN: &str = "https://omega.example.test";

    fn door() -> SharedDoor {
        let configuration = Configuration::new(
            "omega".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
        )
        .unwrap();
        Rc::new(tokio::sync::Mutex::new(Door::new(configuration)))
    }

    fn checkpoint() -> Arc<Checkpoint> {
        let mut community = [0; 32];
        community[31] = 3;
        let mut secret_hash = [0; 32];
        secret_hash[31] = 7;
        let row = RosterRow {
            member: [1; 32],
            key: [2; 64],
            secret_hash,
            issued_at: 1,
            expires_at: 2,
            delegation_digest: [4; 32],
        };
        Arc::new(Checkpoint::from_verified(&community, &[row]).unwrap())
    }

    fn now() -> u64 {
        ckmg::Clock::now(&mut crate::door::custody::SystemClock).unwrap()
    }

    mod binding {
        use super::*;
        use crate::door::inbox_lineage::{CharterView, HandleOpener, PeerUnavailable};
        use crate::door::inbox_waves::verifier::fixture::{fixture, Files};
        use crate::door::inbox_waves::WavePorts;
        use crate::door::record::RecordCurrent;

        #[derive(Clone)]
        struct NoPeers;
        impl HandleOpener for NoPeers {
            async fn read(
                &mut self,
                _: &ckmg::Binding,
                _: &[u8],
            ) -> std::result::Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
                Err(PeerUnavailable)
            }
        }
        struct NoCharter;
        impl CharterView for NoCharter {
            fn with_current<T>(
                &mut self,
                _: &str,
                _: u64,
                _: impl FnOnce(&cchr::VerifiedCharter) -> std::result::Result<T, cnbx::ContactError>,
            ) -> std::result::Result<T, cnbx::ContactError> {
                Err(cnbx::ContactError::Authority)
            }
        }

        fn bare() -> Door {
            let configuration = Configuration::new(
                "omega".into(),
                BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
            )
            .unwrap();
            Door::new(configuration)
        }
        fn device(files: &Files) -> WaveDevice {
            WaveDevice {
                artifacts: files.artifacts.clone(),
                record: RecordCurrent::default(),
            }
        }

        #[test]
        fn a_device_without_the_wave_circuits_binds_nothing() {
            for strip in [
                |artifacts: &mut crate::door::composer::ProverArtifacts| artifacts.wave = None,
                |artifacts: &mut crate::door::composer::ProverArtifacts| artifacts.outcome = None,
            ] {
                let mut files = fixture();
                strip(&mut files.artifacts);
                let mut door = bare();
                assert_eq!(
                    bind_device(&mut door, ORIGIN, &device(&files), NoPeers, NoCharter),
                    Ok(false)
                );
                assert!(!door.waves_installed(ORIGIN));
            }
        }

        #[test]
        fn a_configured_device_gets_closed_ports_and_one_worker_once() {
            let files = fixture();
            let mut door = bare();
            assert_eq!(
                bind_device(&mut door, ORIGIN, &device(&files), NoPeers, NoCharter),
                Ok(true)
            );
            assert!(door.wave_worker(ORIGIN).is_some());
            // No trust is derived before the first worker round: the ports answer nothing.
            let ports = door.wave_ports.get(ORIGIN).unwrap();
            assert_eq!(ports.policy(now()).err(), Some(ErrorCode::Unavailable));
            // Set once, never replaced.
            assert_eq!(
                bind_device(&mut door, ORIGIN, &device(&files), NoPeers, NoCharter),
                Err(ErrorCode::Unauthorized)
            );
            assert!(door.waves_installed(ORIGIN));
        }

        #[test]
        fn a_group_that_does_not_authenticate_binds_nothing() {
            let files = fixture();
            files.write("g2.dat", &[7u8; 128]);
            let mut door = bare();
            assert_eq!(
                bind_device(&mut door, ORIGIN, &device(&files), NoPeers, NoCharter),
                Err(ErrorCode::Unavailable)
            );
            assert!(!door.waves_installed(ORIGIN));
        }

        #[test]
        fn an_origin_that_is_no_member_origin_gets_neither_ports_nor_worker() {
            let files = fixture();
            let mut door = bare();
            let other = "https://elsewhere.example.test";
            assert_eq!(
                bind_device(&mut door, other, &device(&files), NoPeers, NoCharter),
                Err(ErrorCode::Unauthorized)
            );
            assert!(!door.waves_installed(other));
        }
    }

    #[tokio::test]
    async fn a_roster_of_the_current_slot_is_kept_without_asking_the_actor() {
        let roster = ActorRoster::default();
        let held = checkpoint();
        *roster.0.borrow_mut() = Some((Arc::clone(&held), now() + 3_600));
        // No account actor is bound: any call to it would be Unavailable.
        let read = roster.roster(&door(), ORIGIN).await.unwrap();
        assert!(Arc::ptr_eq(&read, &held));
    }

    #[tokio::test]
    async fn an_ended_slot_is_read_again_and_never_served() {
        let roster = ActorRoster::default();
        *roster.0.borrow_mut() = Some((checkpoint(), now()));
        assert_eq!(
            roster.roster(&door(), ORIGIN).await.err(),
            Some(ErrorCode::Unavailable),
            "the ended slot went to the actor, which this origin lacks"
        );
        assert!(ActorRoster::default().roster(&door(), ORIGIN).await.is_err());
    }
}
