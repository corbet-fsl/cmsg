//! The wave capabilities of a device whose pinned group loads on first use, with a retry.
//!
//! The browser fetches and authenticates the wave group (about 4 MB) only when a member's device
//! first needs it (the worker's first round after unlock, a verification, a compose warm-up), never
//! at page construction. Until it is loaded the provers, the counterpart verifier and the warm-up
//! answer `Unavailable` (the job stays recorded and is offered again), never a weaker check. A load
//! that fails is tried again on a later use after a backoff (`wave_job::Cadence` retry doubling up
//! to its ceiling), so one failed download does not leave waves unavailable for the whole session.

use super::{
    device::WaveCapabilities, production::VerifierFactory, wave_job::Cadence, WavePrewarm,
};
use crate::door::{tasks, ErrorCode, Result};
use cwlt::wave::ProofCheck;
use std::{cell::RefCell, future::Future, pin::Pin, rc::Rc};

/// What a successful load yields.
pub struct Loaded<P, C: ProofCheck> {
    pub provers: Rc<dyn Fn() -> Result<P>>,
    pub verifier: VerifierFactory<C>,
    pub prewarm: Rc<dyn WavePrewarm>,
}

/// A load attempt; the error is the cause, for the log.
pub type Load<P, C> = Pin<Box<dyn Future<Output = std::result::Result<Loaded<P, C>, String>>>>;

struct State<P, C: ProofCheck> {
    loaded: Option<Loaded<P, C>>,
    loading: bool,
    next_try: u64,
    backoff: u64,
}

struct Shared<P, C: ProofCheck> {
    state: RefCell<State<P, C>>,
    load: Box<dyn Fn() -> Load<P, C>>,
    now: Box<dyn Fn() -> u64>,
    log: Box<dyn Fn(&str)>,
}

impl<P: 'static, C: ProofCheck + 'static> Shared<P, C> {
    /// Start a load when none is loaded, none is running and the backoff has passed.
    fn ensure(self: &Rc<Self>) {
        {
            let mut state = self.state.borrow_mut();
            if state.loaded.is_some() || state.loading || (self.now)() < state.next_try {
                return;
            }
            state.loading = true;
        }
        let shared = Rc::clone(self);
        let attempt = (self.load)();
        let _ = tasks::spawn(async move {
            let outcome = attempt.await;
            let mut state = shared.state.borrow_mut();
            state.loading = false;
            match outcome {
                Ok(loaded) => state.loaded = Some(loaded),
                Err(cause) => {
                    (shared.log)(&format!("wave group refused: {cause}"));
                    let ceiling = Cadence::default().ceiling;
                    state.next_try = (shared.now)().saturating_add(state.backoff);
                    state.backoff = state.backoff.saturating_mul(2).min(ceiling);
                }
            }
        });
    }
}

struct LazyPrewarm<P, C: ProofCheck>(Rc<Shared<P, C>>);

impl<P: 'static, C: ProofCheck + 'static> WavePrewarm for LazyPrewarm<P, C> {
    fn prewarm(&self) -> Pin<Box<dyn Future<Output = ()>>> {
        self.0.ensure();
        match self.0.state.borrow().loaded.as_ref() {
            Some(loaded) => loaded.prewarm.prewarm(),
            None => Box::pin(async {}),
        }
    }
}

/// The capabilities and the warm-up handle of a group that loads on first use. `now` is the
/// device clock in seconds (it times the retry backoff only) and `log` receives a refusal's cause.
pub fn lazy<P: 'static, C: ProofCheck + 'static>(
    load: impl Fn() -> Load<P, C> + 'static,
    now: impl Fn() -> u64 + 'static,
    log: impl Fn(&str) + 'static,
) -> (WaveCapabilities<P, C>, Rc<dyn WavePrewarm>) {
    let shared = Rc::new(Shared {
        state: RefCell::new(State {
            loaded: None,
            loading: false,
            next_try: 0,
            backoff: Cadence::default().retry,
        }),
        load: Box::new(load),
        now: Box::new(now),
        log: Box::new(log),
    });
    let for_provers = Rc::clone(&shared);
    let for_verifier = Rc::clone(&shared);
    let capabilities = WaveCapabilities {
        provers: Rc::new(move || {
            for_provers.ensure();
            match for_provers.state.borrow().loaded.as_ref() {
                Some(loaded) => (loaded.provers)(),
                None => Err(ErrorCode::Unavailable),
            }
        }),
        verifier: Box::new(move |policy, now, until| {
            for_verifier.ensure();
            match for_verifier.state.borrow().loaded.as_ref() {
                Some(loaded) => (loaded.verifier)(policy, now, until),
                None => Err(ErrorCode::Unavailable),
            }
        }),
    };
    (capabilities, Rc::new(LazyPrewarm(shared)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Counting(Rc<Cell<u32>>);
    impl WavePrewarm for Counting {
        fn prewarm(&self) -> Pin<Box<dyn Future<Output = ()>>> {
            self.0.set(self.0.get() + 1);
            Box::pin(async {})
        }
    }

    struct Rig {
        capabilities: WaveCapabilities<u32, NoCheck>,
        prewarm: Rc<dyn WavePrewarm>,
        attempts: Rc<Cell<u32>>,
        clock: Rc<Cell<u64>>,
        warmed: Rc<Cell<u32>>,
        logged: Rc<RefCell<Vec<String>>>,
        fail: Rc<Cell<bool>>,
    }

    struct NoCheck;
    impl ProofCheck for NoCheck {
        async fn check(
            &self,
            _: &[cwlt::wave::PublicField],
            _: &[u8],
        ) -> std::result::Result<(), czkp::Error> {
            Err(czkp::Error::InvalidInput)
        }
    }

    fn rig() -> Rig {
        let attempts = Rc::new(Cell::new(0));
        let clock = Rc::new(Cell::new(1000));
        let warmed = Rc::new(Cell::new(0));
        let logged = Rc::new(RefCell::new(Vec::new()));
        let fail = Rc::new(Cell::new(true));
        let (a, w, f) = (attempts.clone(), warmed.clone(), fail.clone());
        let (c, l) = (clock.clone(), logged.clone());
        let (capabilities, prewarm) = lazy(
            move || {
                a.set(a.get() + 1);
                let (w, failing) = (w.clone(), f.get());
                Box::pin(async move {
                    if failing {
                        return Err("download failed".to_owned());
                    }
                    Ok(Loaded {
                        provers: Rc::new(|| Ok(7)),
                        verifier: Box::new(|_, _, _| Err(ErrorCode::Refused)),
                        prewarm: Rc::new(Counting(w)),
                    })
                })
            },
            move || c.get(),
            move |cause| l.borrow_mut().push(cause.to_owned()),
        );
        Rig {
            capabilities,
            prewarm,
            attempts,
            clock,
            warmed,
            logged,
            fail,
        }
    }

    async fn settle() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn nothing_loads_before_first_use_and_a_failed_load_retries_with_backoff() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let rig = rig();
                settle().await;
                assert_eq!(rig.attempts.get(), 0, "no load before first use");
                // First use starts the load; it fails and answers Unavailable meanwhile.
                assert_eq!(
                    (rig.capabilities.provers)().err(),
                    Some(ErrorCode::Unavailable)
                );
                settle().await;
                assert_eq!(rig.attempts.get(), 1);
                assert_eq!(rig.logged.borrow().len(), 1);
                // Use inside the backoff starts nothing.
                let _ = (rig.capabilities.provers)();
                settle().await;
                assert_eq!(rig.attempts.get(), 1);
                // After the first backoff (30 s) the next use retries; that failure doubles it.
                rig.clock.set(1030);
                let _ = (rig.capabilities.provers)();
                settle().await;
                assert_eq!(rig.attempts.get(), 2);
                rig.clock.set(1030 + 59);
                let _ = (rig.capabilities.provers)();
                settle().await;
                assert_eq!(rig.attempts.get(), 2, "the backoff doubled");
                // The download works now: the retry loads, and everything delegates.
                rig.fail.set(false);
                rig.clock.set(1030 + 60);
                let _ = (rig.capabilities.provers)();
                settle().await;
                assert_eq!(rig.attempts.get(), 3);
                assert_eq!((rig.capabilities.provers)().ok(), Some(7));
                assert_eq!(
                    (rig.capabilities.verifier)(
                        super::super::production::tests::wave_policy(),
                        0,
                        0
                    )
                    .err(),
                    Some(ErrorCode::Refused)
                );
                rig.prewarm.prewarm().await;
                assert_eq!(rig.warmed.get(), 1);
                assert_eq!(
                    rig.attempts.get(),
                    3,
                    "a loaded group is never loaded again"
                );
            })
            .await;
    }

    #[tokio::test]
    async fn the_backoff_stops_at_the_ceiling_and_a_running_load_is_not_doubled() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let rig = rig();
                // Two uses in the same turn start one load.
                let _ = (rig.capabilities.provers)();
                let _ = (rig.capabilities.provers)();
                assert_eq!(rig.attempts.get(), 1);
                settle().await;
                // The warm-up before load is a no-op that also asks for a load once the backoff passed.
                rig.prewarm.prewarm().await;
                assert_eq!(rig.warmed.get(), 0);
                let mut at = 1000;
                for _ in 0..8 {
                    at += 301;
                    rig.clock.set(at);
                    let _ = (rig.capabilities.provers)();
                    settle().await;
                }
                // 30, 60, 120, 240, then 300 each: eight uses 301 s apart each find a passed backoff.
                assert_eq!(rig.attempts.get(), 9);
            })
            .await;
    }
}
