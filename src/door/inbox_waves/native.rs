//! The native device's wave proof capabilities: the circuit provers of the extension
//! group ([`NativeWaveProver`], a [`WaveProver`]) and the counterpart verifier over the
//! retained group; the ports and the worker they go into are the device's own
//! (`inbox_waves::device`, shared with the browser).
//!
//! The provers are small adapters the background wave worker composes into its
//! [`AccountWallet`](super::wallet::AccountWallet); neither holds a key, an opening or
//! a policy. A proof runs on a blocking worker thread, never on the Door's task; the
//! Door is locked only for the one short account-actor call of an update or settle.
use super::super::{Door, ErrorCode, Result};
use super::wallet::WaveProver;
use ckmg::wallet_engine::account::{Evidence, UpdateInput};
use ckmg::wallet_engine::native_prover::{NativeProver, PreparedProof, Program};
use std::rc::Rc;

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
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })
}

impl WaveProver for NativeWaveProver {
    async fn prove_update(&mut self, input: &UpdateInput) -> Result<Vec<u8>> {
        let job = self.update.prepare_update(input).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Refused",
                ErrorCode::Refused,
                &__cause,
            )
        })?;
        run(job).await
    }
    async fn prove_evidence(&mut self, evidence: &Evidence) -> Result<Vec<u8>> {
        let prover = if evidence.is_outcome() {
            &self.outcome
        } else {
            &self.wave
        };
        let job = prover.prepare_wave_evidence(evidence).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Refused",
                ErrorCode::Refused,
                &__cause,
            )
        })?;
        run(job).await
    }
}

pub use super::device::{
    device_worker, ActorRoster, ActorTransport, ActorWitness, RosterSource, WitnessView,
};

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
    let (Some(_), Some(_)) = (&device.artifacts.wave, &device.artifacts.outcome) else {
        return Ok(false);
    };
    if door.waves_installed(origin) {
        return Err(ErrorCode::Unauthorized);
    }
    let verifier = device
        .artifacts
        .wave_verifier_factory()
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
    let artifacts = device.artifacts.clone();
    let provers: Rc<dyn Fn() -> Result<NativeWaveProver>> = Rc::new(move || {
        artifacts
            .wave_provers()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
            .ok_or(ErrorCode::Unavailable)
    });
    super::device::bind(
        door,
        origin,
        super::device::WaveCapabilities { provers, verifier },
        device.record.clone(),
        opener,
        charter,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::courier::SharedDoor;
    use crate::door::{Configuration, Door, Role};
    use ckmg::wallet_engine::account::Checkpoint;
    use ckmg::wallet_engine::account::RosterRow;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

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
        assert!(ActorRoster::default()
            .roster(&door(), ORIGIN)
            .await
            .is_err());
    }
}
