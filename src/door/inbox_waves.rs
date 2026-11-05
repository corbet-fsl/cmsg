//! Wave actions of the Inbox door: send, answer, close and punish a wave, the
//! messages of the other device, and the two short calls of the background
//! proof worker. Thin: every fact and mutation is an owner's (Waves, Contacts,
//! Threads); this module only orders them, and records the member's action
//! durably before any proof exists. A proof never blocks the member.
//!
//! The verifier, policy, G2 and peer-lineage capabilities arrive as a
//! [`WavePorts`] bundle installed per member origin by the trusted embedding
//! runtime ([`Door::bind_waves`]); no client can supply or replace them. The
//! prover is a host component that holds the wallet openings: it calls
//! `inbox.wave_job_next`, proves WITHOUT holding the Door, and returns the
//! result through `inbox.wave_job_done`.
pub mod account_ports;
mod desk;
/// The device side (ports and worker), shared by the native device and the browser.
#[cfg(any(
    all(feature = "native-prover", not(target_arch = "wasm32")),
    all(feature = "browser-prover", target_arch = "wasm32")
))]
pub mod device;
pub(crate) mod engine;
pub mod feed_trust;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod native;
mod ports;
pub mod production;
mod signing;
pub mod types;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod verifier;
pub mod wallet;
pub mod witness;
pub mod worker;

use super::*;
pub use ports::{
    verify_outcome_with, verify_reservation_with, AccountSigner, ContactRequest, HandleRequest,
    Policy, ReceiptRequest, WavePorts,
};
pub use types::*;

/// One request to the bound Vault. The Vault answers with the matching variant.
pub(crate) enum Command {
    Send(WaveSend),
    Decide(WaveDecide),
    Punish(WavePunish),
    Receive(WaveIncoming),
    List,
    Outbox,
    Delivered(Delivered),
    NextJob,
    JobDone(JobDone),
    Retry([u8; 32]),
    Recover,
}
pub(crate) enum Answer {
    Status(WaveStatus),
    List(WaveList),
    Outbox(Outbox),
    Relation(cnbx::Relation),
    Job(Box<JobOffer>),
    Done,
}

impl Door {
    /// Trusted embedding control, absent from every callable projection: install
    /// the wave capabilities of an already configured member origin.
    pub fn bind_waves(&mut self, origin: &str, ports: Box<dyn WavePorts>) -> Result<()> {
        if !self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|set| set.contains(origin))
            || self.wave_ports.contains_key(origin)
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.wave_ports.insert(origin.into(), ports);
        Ok(())
    }

    /// Trusted embedding control, absent from every callable projection: install what a
    /// compose may warm on this device for an already configured member origin (see
    /// [`WavePrewarm`]).
    pub fn bind_wave_prewarm(
        &mut self,
        origin: &str,
        prewarm: std::rc::Rc<dyn WavePrewarm>,
    ) -> Result<()> {
        if !self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|set| set.contains(origin))
            || self.wave_prewarm.contains_key(origin)
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.wave_prewarm.insert(origin.into(), prewarm);
        Ok(())
    }
}

/// Speculative sender reservation, option (b) (decided 2026-11-05): while the member composes,
/// the device warms only what the send will need locally (witness load, prover, setup). It sends
/// nothing: no Hello, no reserve, no request to the counterpart, the Mesh, the forum or the issuer.
/// The reserve still follows the counterpart's Terms after the member sends.
pub trait WavePrewarm {
    /// Warm, best effort; a failed warm-up only means the send loads everything itself.
    fn prewarm(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;
}

/// `inbox.wave_prewarm`: the member started composing. Inside the same current-policy and
/// clock bracket as every other Inbox action (refused below the signed minimum version), it
/// wakes the origin's wave worker for a round now and starts the origin's bound warm-up in the
/// background, then answers at once. It records nothing in the vault and sends nothing: no
/// Hello, no reserve, no request to the counterpart, the Mesh, the forum or the issuer.
pub(super) async fn wave_prewarm(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Empty, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let mut policy = door.current_policy(&origin)?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let ((), completed) = current::read(
        vault.as_mut(),
        &mut policy,
        current::Scope {
            community: &door.config.community,
            expires,
            floor: door.clock_floor,
        },
        |_| Box::pin(async { Ok(()) }),
    )
    .await?;
    door.observe(completed)?;
    if let Some(prewarm) = door.wave_prewarm.get(&origin) {
        let warm = prewarm.prewarm();
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(warm);
        #[cfg(not(target_arch = "wasm32"))]
        warm.await;
    }
    Ok((Empty {}, vec![]))
}

#[cfg(test)]
mod prewarm_tests {
    use super::*;
    use std::{cell::Cell, collections::BTreeSet, rc::Rc};

    const ORIGIN: &str = "https://omega.example.test";

    fn door() -> Door {
        let configuration = Configuration::new(
            "omega".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
        )
        .unwrap();
        Door::new(configuration)
    }

    struct Counting(Rc<Cell<u32>>);
    impl WavePrewarm for Counting {
        fn prewarm(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
            self.0.set(self.0.get() + 1);
            Box::pin(async {})
        }
    }

    async fn compose(door: &mut Door, origin: &str) -> Result<serde_json::Value> {
        let key = [7u8; 32];
        door.grants.insert(
            key,
            Grant {
                origin: origin.to_owned(),
                actions: BTreeSet::from(["inbox.wave_prewarm".to_owned()]),
                expires: u64::MAX,
            },
        );
        let action = super::super::registry::action("inbox.wave_prewarm").unwrap();
        let outcome = (action.handler)(door, &key, "{}").await.map(|(v, _)| v);
        door.grants.remove(&key);
        outcome
    }

    #[tokio::test]
    async fn a_compose_outside_the_current_policy_bracket_warms_nothing() {
        // Without a bound vault there is no current-policy bracket: the action is refused
        // like every Inbox action, and the bound warm-up never runs.
        let mut door = door();
        let warmed = Rc::new(Cell::new(0));
        door.bind_wave_prewarm(ORIGIN, Rc::new(Counting(warmed.clone())))
            .unwrap();
        assert_eq!(
            compose(&mut door, ORIGIN).await,
            Err(ErrorCode::Unavailable)
        );
        assert_eq!(warmed.get(), 0);
        // The action reads nothing and records nothing: it is a Read of the Inbox family.
        let described = super::super::registry::catalog()
            .into_iter()
            .find(|action| action.action == "inbox.wave_prewarm")
            .unwrap();
        assert!(matches!(
            described.effect,
            super::super::registry::Effect::Read
        ));
        assert_eq!(described.family, super::super::registry::Family::Inbox);
    }

    #[test]
    fn only_a_member_origin_gets_one_warm_up() {
        let mut door = door();
        let warm = || Rc::new(Counting(Rc::new(Cell::new(0))));
        assert_eq!(
            door.bind_wave_prewarm("https://other.example.test", warm()),
            Err(ErrorCode::Unauthorized)
        );
        assert_eq!(door.bind_wave_prewarm(ORIGIN, warm()), Ok(()));
        assert_eq!(
            door.bind_wave_prewarm(ORIGIN, warm()),
            Err(ErrorCode::Unauthorized)
        );
    }
}
