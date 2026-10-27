//! The operation scope of authority reuse (manager decision, 2026-10-27, opus-r4t).
//!
//! Every Vault access inside one Door action runs a full authority check: the held
//! session's owner reads (lobby, device keys, initial creation) and the Tor lineage
//! read. Over Tor one action with ~30 accesses spent more than a minute in strictly
//! serial rereads of the same authority. Inside ONE operation (one `Door::dispatch`)
//! a successful read may stand in for the same read again; nothing is reused across
//! operations, outside any operation, or across a session renewal. The expiry check
//! against the clock still runs on every check, and a failed read is never recorded,
//! so a transient error still refuses the next check by reading again.
use std::sync::atomic::{AtomicU64, Ordering};

/// The live operation of a process: 0 when none runs. Ids are never reused.
pub struct Scope {
    current: AtomicU64,
    next: AtomicU64,
}

/// The scope every `Door::dispatch` opens.
pub static DISPATCH: Scope = Scope::new();

impl Scope {
    pub const fn new() -> Self {
        Self {
            current: AtomicU64::new(0),
            next: AtomicU64::new(0),
        }
    }

    fn fresh_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Open an operation; it ends when the guard drops.
    pub fn begin(&'static self) -> Guard {
        self.current.store(self.fresh_id(), Ordering::SeqCst);
        Guard(self)
    }

    /// The live operation, `None` outside any operation.
    pub fn current(&self) -> Option<u64> {
        match self.current.load(Ordering::SeqCst) {
            0 => None,
            id => Some(id),
        }
    }

    /// A session renewal inside an operation: nothing read before it is reused after it.
    pub fn renew(&self) {
        if self.current().is_some() {
            self.current.store(self.fresh_id(), Ordering::SeqCst);
        }
    }
}

/// Ends the operation. An overlapping operation (another Door of the process) loses
/// its reuse too: the scope only ever errs towards reading again.
pub struct Guard(&'static Scope);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.current.store(0, Ordering::SeqCst);
    }
}

/// One read's reuse inside the live operation.
pub struct Reused {
    scope: &'static Scope,
    at: Option<u64>,
}

impl Reused {
    pub fn new(scope: &'static Scope) -> Self {
        Self { scope, at: None }
    }

    /// Whether the read must run now. When it must, the earlier record is dropped
    /// first, so a read that then fails leaves nothing to reuse.
    pub fn needed(&mut self) -> bool {
        let live = self.scope.current();
        if live.is_some() && self.at == live {
            return false;
        }
        self.at = None;
        true
    }

    /// The read succeeded inside the live operation.
    pub fn record(&mut self) {
        self.at = self.scope.current();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_is_reused_only_inside_the_operation_that_made_it() {
        static SCOPE: Scope = Scope::new();
        let mut read = Reused::new(&SCOPE);
        // Outside any operation every check reads.
        assert!(read.needed());
        read.record();
        assert!(read.needed());
        {
            let _op = SCOPE.begin();
            assert!(read.needed());
            read.record();
            assert!(!read.needed());
            assert!(!read.needed());
        }
        assert!(read.needed(), "the operation ended");
        let _next = SCOPE.begin();
        assert!(read.needed(), "a new operation reads again");
    }

    #[test]
    fn a_failed_read_is_never_reused() {
        static SCOPE: Scope = Scope::new();
        let mut read = Reused::new(&SCOPE);
        let _op = SCOPE.begin();
        assert!(read.needed());
        read.record();
        assert!(!read.needed());
        // A later read that must run (e.g. after a renewal) and fails records nothing.
        SCOPE.renew();
        assert!(read.needed());
        assert!(read.needed(), "the failed read left nothing to reuse");
    }

    #[test]
    fn a_session_renewal_inside_an_operation_ends_the_reuse() {
        static SCOPE: Scope = Scope::new();
        let mut read = Reused::new(&SCOPE);
        let _op = SCOPE.begin();
        assert!(read.needed());
        read.record();
        assert!(!read.needed());
        SCOPE.renew();
        assert!(read.needed(), "renewed: read again");
        read.record();
        assert!(!read.needed(), "reused inside the renewed operation");
    }

    #[test]
    fn renewing_outside_an_operation_opens_none() {
        static SCOPE: Scope = Scope::new();
        SCOPE.renew();
        assert_eq!(SCOPE.current(), None);
    }
}
