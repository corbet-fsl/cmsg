//! One in-process actor: a future that owns borrowed state across calls.
//!
//! Account custody must keep a held HTTPS lease and its policy borrow alive
//! between two user-visible actions. A future can own those borrows on its own
//! stack, so the actor is such a future, driven inline by the caller through a
//! one-slot mailbox. No task is spawned, no thread or timer is needed (it runs
//! on wasm as well), and exactly one call is in flight by construction.
//!
//! A call that is cancelled leaves the actor in the middle of its operation. The
//! call owns the actor future while it runs, so the cancellation drops it: the
//! actor is fenced permanently instead of interleaving a new command with an
//! unfinished one.
#![cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
use std::{
    cell::RefCell,
    future::{poll_fn, Future},
    pin::Pin,
    rc::Rc,
    task::Poll,
};

struct Slots<C, R> {
    command: Option<C>,
    reply: Option<R>,
}

/// The actor's side of the mailbox: receive one command, answer it.
pub(super) struct Mailbox<C, R>(Rc<RefCell<Slots<C, R>>>);

impl<C, R> Clone for Mailbox<C, R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C, R> Mailbox<C, R> {
    /// Wait for the next command. Pending until a call supplies one.
    pub(super) async fn next(&self) -> C {
        poll_fn(|_| match self.0.borrow_mut().command.take() {
            Some(command) => Poll::Ready(command),
            None => Poll::Pending,
        })
        .await
    }

    /// Answer the command being served.
    pub(super) fn reply(&self, reply: R) {
        self.0.borrow_mut().reply = Some(reply);
    }
}

/// The actor has finished or was fenced; its state is gone.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Ended;

/// Caller's side: owns the actor future and with it everything it holds.
pub(super) struct Actor<C, R> {
    task: Option<Pin<Box<dyn Future<Output = ()>>>>,
    mailbox: Mailbox<C, R>,
}

impl<C: 'static, R: 'static> Actor<C, R> {
    /// Build the actor future from its mailbox. Nothing runs until the first call.
    pub(super) fn new<F>(start: impl FnOnce(Mailbox<C, R>) -> F) -> Self
    where
        F: Future<Output = ()> + 'static,
    {
        let mailbox = Mailbox(Rc::new(RefCell::new(Slots {
            command: None,
            reply: None,
        })));
        Self {
            task: Some(Box::pin(start(mailbox.clone()))),
            mailbox,
        }
    }

    /// False once the actor finished or was fenced.
    pub(super) fn is_live(&self) -> bool {
        self.task.is_some()
    }

    /// Give the actor one command and drive it until it answers. The only
    /// state change a caller observes is the reply. While a call is in flight the
    /// future is owned by that call, so cancelling the call drops the actor and
    /// everything it holds: a half-finished operation can never be resumed.
    pub(super) async fn call(&mut self, command: C) -> Result<R, Ended> {
        let Some(mut task) = self.task.take() else {
            return Err(Ended);
        };
        self.mailbox.0.borrow_mut().command = Some(command);
        let (reply, finished) = poll_fn(|cx| {
            let finished = task.as_mut().poll(cx).is_ready();
            match self.mailbox.0.borrow_mut().reply.take() {
                Some(reply) => Poll::Ready((Some(reply), finished)),
                None if finished => Poll::Ready((None, true)),
                None => Poll::Pending,
            }
        })
        .await;
        if !finished {
            self.task = Some(task);
        }
        reply.ok_or(Ended)
    }

    /// Drop the actor and everything it owns; later calls fail.
    pub(super) fn fence(&mut self) {
        self.task = None;
        let mut slots = self.mailbox.0.borrow_mut();
        slots.command = None;
        slots.reply = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::task::noop_waker;
    use std::{
        cell::Cell,
        task::{Context, Poll},
    };

    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = Box::pin(future);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..1000 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return value;
            }
        }
        panic!("actor call did not complete");
    }

    /// Pending once, then ready: stands for real I/O inside the actor.
    struct Suspend(bool);
    impl Future for Suspend {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn counter() -> Actor<u32, u32> {
        Actor::new(|mailbox| async move {
            let mut total = 0;
            loop {
                let add = mailbox.next().await;
                Suspend(false).await;
                total += add;
                mailbox.reply(total);
            }
        })
    }

    #[test]
    fn state_lives_across_calls_and_suspensions() {
        let mut actor = counter();
        assert!(actor.is_live());
        assert_eq!(run(actor.call(2)), Ok(2));
        assert_eq!(run(actor.call(5)), Ok(7));
        assert!(actor.is_live());
    }

    #[test]
    fn finishing_with_a_reply_ends_the_actor_afterwards() {
        let mut actor = Actor::new(|mailbox: Mailbox<u8, u8>| async move {
            let command = mailbox.next().await;
            mailbox.reply(command + 1);
        });
        assert_eq!(run(actor.call(1)), Ok(2));
        assert!(!actor.is_live());
        assert_eq!(run(actor.call(1)), Err(Ended));
    }

    #[test]
    fn finishing_without_a_reply_is_ended_not_a_hang() {
        let mut actor =
            Actor::new(|mailbox: Mailbox<u8, u8>| async move { drop(mailbox.next().await) });
        assert_eq!(run(actor.call(1)), Err(Ended));
        assert!(!actor.is_live());
    }

    #[test]
    fn a_cancelled_call_fences_the_actor_and_drops_its_state() {
        let owned = Rc::new(Cell::new(0));
        let held = owned.clone();
        let mut actor = Actor::new(move |mailbox: Mailbox<u8, u8>| async move {
            let _custody = held;
            loop {
                let command = mailbox.next().await;
                Suspend(false).await;
                mailbox.reply(command);
            }
        });
        assert_eq!(Rc::strong_count(&owned), 2);
        {
            // Poll once, then cancel while the actor is mid-operation.
            let mut call = Box::pin(actor.call(1));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        assert!(!actor.is_live());
        assert_eq!(Rc::strong_count(&owned), 1);
        assert_eq!(run(actor.call(2)), Err(Ended));
    }

    #[test]
    fn dropping_the_actor_drops_everything_it_owns() {
        let owned = Rc::new(Cell::new(0));
        let held = owned.clone();
        let mut actor = Actor::new(move |mailbox: Mailbox<u8, u8>| async move {
            let _custody = held;
            loop {
                let command = mailbox.next().await;
                mailbox.reply(command);
            }
        });
        assert_eq!(run(actor.call(9)), Ok(9));
        assert_eq!(Rc::strong_count(&owned), 2);
        drop(actor);
        assert_eq!(Rc::strong_count(&owned), 1);
    }

    #[test]
    fn fence_is_idempotent() {
        let mut actor = counter();
        actor.fence();
        actor.fence();
        assert_eq!(run(actor.call(1)), Err(Ended));
    }
}
