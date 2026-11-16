//! The device side of the wave stack, the same on the native device and in the browser
//! vault frame: the wave ports over the member's account witness and verified feed, and
//! the background wave worker over the account actor. Only the provers and the
//! counterpart verifier differ per runtime; the embedding hands them in as
//! [`WaveCapabilities`] (native: `inbox_waves::native`, browser: `browser::waves`).
//!
//! Nothing is bound unless both are supplied, and everything is built before anything is
//! installed: a device never half-runs waves.
use super::super::facades::OwnedFuture;
use super::super::{
    account::{Answer, Applied, Command, Shared},
    accounting::ProvenUpdate,
    courier::SharedDoor,
    registry, Door, ErrorCode, Result,
};
use super::account_ports::AccountView;
use super::production::VerifierFactory;
use super::wallet::{WalletState, WaveProver};
use super::witness::UpdateTransport;
use ckmg::wallet_engine::account::{Account, Checkpoint};
use cwlt::wave::ProofCheck;
use std::{cell::RefCell, rc::Rc, sync::Arc};

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
        match registry::account_call_at(
            &mut door,
            &self.origin,
            Command::Update(Shared::new(proven)),
        )
        .await?
        {
            Answer::Updated(applied) => Ok(applied),
            _ => Err(ErrorCode::Unavailable),
        }
    }
    async fn settle(&mut self, request_id: [u8; 32]) -> Result<()> {
        let mut door = self.door.lock().await;
        match registry::account_call_at(&mut door, &self.origin, Command::Settle(request_id))
            .await?
        {
            Answer::Settled => Ok(()),
            _ => Err(ErrorCode::Unavailable),
        }
    }
}

/// The verified current common roster (every member's enrollment row under the
/// published root) of the member at `origin`, current for each witness load: a
/// counterpart enrolled after the last load must be found.
pub trait RosterSource {
    fn roster<'a>(
        &'a self,
        door: &'a SharedDoor,
        origin: &'a str,
    ) -> OwnedFuture<'a, Arc<Checkpoint>>;
}

/// The roster through the member's account actor (`Command::Roster`: a fresh
/// admission, the signed current publication verified row by row). A publication is
/// frozen for its slot, so it is kept until the slot ends and read again after:
/// within a slot no counterpart can be added, and a new slot is always read.
#[derive(Clone, Default)]
pub struct ActorRoster(pub(super) Rc<RefCell<Option<(Arc<Checkpoint>, u64)>>>);

impl ActorRoster {
    fn cached(&self, now: u64) -> Option<Arc<Checkpoint>> {
        match &*self.0.borrow() {
            Some((roster, expires_at)) if now < *expires_at => Some(Arc::clone(roster)),
            _ => None,
        }
    }
}

impl RosterSource for ActorRoster {
    fn roster<'a>(
        &'a self,
        door: &'a SharedDoor,
        origin: &'a str,
    ) -> OwnedFuture<'a, Arc<Checkpoint>> {
        Box::pin(async move {
            let now = || {
                ckmg::Clock::now(&mut super::super::custody::SystemClock).map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Clock",
                        ErrorCode::Clock,
                        &__cause,
                    )
                })
            };
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

/// The device's wave worker (native and browser): each round reopens the account witness under the
/// verified current roster (refreshing the ports' view), derives the wave trust from
/// the verified feed (refreshing the ports' trust), and drains the job journal with an
/// [`AccountWallet`](super::wallet::AccountWallet) over the extension group's provers
/// and the D2 actor. `view` and `trust` are the same cells the device's ports read.
pub fn device_worker<R, P>(
    provers: Rc<dyn Fn() -> Result<P>>,
    roster: R,
    view: WitnessView,
    trust: super::feed_trust::FeedTrust,
) -> Rc<dyn super::super::wave_job::WaveWorker>
where
    R: RosterSource + Clone + 'static,
    P: WaveProver + 'static,
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
                let leaf = account.owner().leaf;
                let (fresh, now) =
                    super::feed_trust::with_door_current(&door, &origin, clock, |charter, now| {
                        super::feed_trust::derive(charter, leaf, now)
                    })
                    .await?;
                trust.set(fresh.clone());
                // The circuit's issuer key is the ring key of the period that holds the
                // acceptance of the states this round produces (now).
                let issuer_key = czkp::issuer_keys::key_at(&fresh.wave.certificate_keys, now)
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Unavailable",
                            ErrorCode::Unavailable,
                            &__cause,
                        )
                    })?;
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

/// What a runtime contributes to the wave stack of one member origin: its provers of the
/// extension group (built per round, so a lent prover that went away fails the round,
/// never the bind) and the counterpart verifier for one trusted policy and instant.
pub struct WaveCapabilities<P, C: ProofCheck> {
    pub provers: Rc<dyn Fn() -> Result<P>>,
    pub verifier: VerifierFactory<C>,
}

/// Install the wave ports and the wave worker of a restored device for `origin`.
///
/// `record` is the record-currency mark of the device's record job; `opener` reads the
/// peers' retained handles over the member's network and `charter` is the Door's
/// verified view of the community's current Charter. A second bind, or any refusal of
/// the Door, leaves the origin as it was.
pub fn bind<P, C, O, V>(
    door: &mut Door,
    origin: &str,
    capabilities: WaveCapabilities<P, C>,
    record: super::super::record::RecordCurrent,
    opener: O,
    charter: V,
) -> Result<()>
where
    P: WaveProver + 'static,
    C: ProofCheck + 'static,
    O: super::super::inbox_lineage::HandleOpener + Clone + 'static,
    V: super::super::inbox_lineage::CharterView + 'static,
{
    use super::super::inbox_lineage::{HandleBook, WavePeerLineage};
    use super::account_ports::{AccountContact, AccountTerms};
    use super::feed_trust::FeedTrust;
    use super::production::ProductionPorts;
    if door.waves_installed(origin) {
        return Err(ErrorCode::Unauthorized);
    }
    let view = WitnessView::default();
    let trust = FeedTrust::default();
    let clock = || ckmg::Clock::now(&mut super::super::custody::SystemClock).ok();
    let entropy = || -> Result<[u8; 32]> {
        let mut nonce = [0u8; 32];
        ckmg::Entropy::fill(&mut ckmg::SystemEntropy, &mut nonce).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        Ok(nonce)
    };
    let ports = ProductionPorts::new(
        Box::new(trust.clone()),
        Box::new(AccountTerms {
            view: view.clone(),
            entropy,
        }),
        Box::new(AccountContact { view: view.clone() }),
        Box::new(record),
        Box::new(WavePeerLineage::new(HandleBook::default(), opener, charter)),
        capabilities.verifier,
        Box::new(clock),
    );
    let worker = device_worker(capabilities.provers, ActorRoster::default(), view, trust);
    door.bind_waves(origin, Box::new(ports))?;
    // Cannot be refused: the origin was free of both when it was checked above.
    door.set_wave_worker(origin, worker)?;
    Ok(())
}
