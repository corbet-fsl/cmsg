//! Separate fresh transport and member checks over the original Foyer/Records.
use super::{foyer::Transport, Door, ErrorCode};
use ckmg::{Action, Authorization, Binding, Clock, Error, PublicKey};
use futures_util::lock::Mutex;
use std::{cell::Cell, rc::Rc};

mod genesis;
mod initial_recovery;
pub use initial_recovery::{
    complete_device_initial_recovery, complete_initial_recovery, InitialRecoveryAuthority,
};
mod initial_restore;
pub use initial_restore::{
    prepare_device_initial_recovery, prepare_initial_recovery, ComposedMemberVault,
    InitialRecoveredVault, InitialRecoveryOwners, InitialRootVault, MemberVault,
};
mod late_member;
pub use late_member::{BindInputs, LateMemberAuthority, MemberBinder, MemberSlot};
mod initial;
pub use genesis::{
    acknowledge_device_initial_publication, acknowledge_initial_publication,
    prepare_birth_publication, prepare_device_initial_publication, prepare_initial_publication,
    reopen_device_initial_publication, reopen_initial_publication,
    reopen_initial_publication_opened, retain_device_initial_publication,
    retain_initial_publication, InitialPublicationError, Opening,
};
mod current_member;

/// Which single-use account channel one account Keys call consumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccountChannel {
    Root,
    Delegation,
    Request,
}

/// A root authorization (`AuthorizeAccountDevice`) consumes the root channel
/// and starts a new delegation round, the same rule for every custody owner: the first
/// device signature after it is the delegation (spent by that attempt whatever
/// its outcome), every later one the account request. Without the reset, a
/// later round (a record-recipient registration after the account request) would
/// consult the request channel, find nothing admitted, and the refusal locks
/// the Keys. The ONE copy of this rule: the member owner (current_member) and
/// the initial custody owner (initial_recovery) both call it; never copy it.
pub(super) fn account_channel(authorize: bool, delegation_spent: &mut bool) -> AccountChannel {
    if authorize {
        *delegation_spent = false;
        AccountChannel::Root
    } else if *delegation_spent {
        AccountChannel::Request
    } else {
        *delegation_spent = true;
        AccountChannel::Delegation
    }
}

mod recovery;
pub use initial::{
    activate_initial, reopen_device_enrollment, reopen_initial_enrollment,
    reopen_initial_enrollment_opened, retain_device_enrollment, retain_global_initial_enrollment,
    retain_global_initial_enrollment_opened, retain_initial_enrollment, EnrollmentError,
    InitialEnrollment,
};
pub use recovery::{
    AccountWiring, RecoveredVault, RecoveryAuthority, RecoveryOwners, RestoredVault,
};

/// The member authority's own validity bound, as its latest live membership observation
/// reported it. A caller requesting a device-signed grant clamps the grant's expiry to it,
/// so the grant never outlives its authority (the authority's strict check stays the
/// judge: this value can only SHORTEN a request, never admit one). A renewed observation
/// replaces it, so the next grant re-binds to the renewed bound.
#[derive(Clone, Default)]
pub struct SigningBound(Rc<Cell<Option<u64>>>);
impl SigningBound {
    /// Record the bound of a live membership observation (the latest one replaces).
    pub(crate) fn note(&self, until: u64) {
        self.0.set(Some(until));
    }
    /// The shared clamp of every device-signed grant: `min(wanted, until)`. With no
    /// observation yet, `wanted` unchanged (the strict check decides). A bound already
    /// passed refuses as `Unavailable` (undetermined until the authority renews), before
    /// the authority sees the request, so it ends only this operation.
    pub(crate) fn clamp(&self, wanted: u64, now: u64) -> super::Result<u64> {
        match self.0.get() {
            None => Ok(wanted),
            Some(until) if until <= now => {
                crate::door::cause::print(
                    file!(),
                    line!(),
                    "signing bound passed; waits for renewal",
                    &ErrorCode::Unavailable,
                );
                Err(ErrorCode::Unavailable)
            }
            Some(until) => Ok(wanted.min(until)),
        }
    }
}

/// Shared negative state for one unlocked custody session. Observed removal,
/// explicit lock or a cancelled check invalidates both authority paths. There is
/// deliberately no method to restore acceptance; a new login needs new owners.
#[derive(Clone)]
pub struct CustodyLifetime {
    binding: Binding,
    device: PublicKey,
    closed: Rc<Cell<bool>>,
    bound: SigningBound,
}
impl CustodyLifetime {
    /// This session's signing bound (shared with every clone of this lifetime).
    pub fn signing_bound(&self) -> SigningBound {
        self.bound.clone()
    }
    /// Report observations into `bound` (the bound a late-bound Vault's grants clamp to).
    pub(crate) fn share_signing_bound(&mut self, bound: SigningBound) {
        self.bound = bound;
    }
    /// Close this exact session after an original verified removal or local lock.
    pub fn close(&self) {
        self.closed.set(true);
    }
    /// Record only negative information from original certified lineage. This
    /// cannot reopen a session or grant member authority, even if the device
    /// appears in the observed set. Revalidation/current selection belongs to
    /// the member authority at every use.
    pub fn observe_lineage(
        &self,
        observed: &cvlt::VerifiedLineageObservation<'_>,
        now: u64,
    ) -> Result<(), Error> {
        let lineage = observed.lineage(now).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        if lineage.binding != self.binding {
            return Err(Error::Unauthorized);
        }
        if !lineage.devices.contains(&self.device) {
            self.close();
        }
        if self.closed.get() {
            Err(Error::Revoked)
        } else {
            Ok(())
        }
    }
    pub(super) fn check_owner(&self, binding: &Binding, device: PublicKey) -> Result<(), Error> {
        if self.closed.get() {
            return Err(Error::Revoked);
        }
        if binding != &self.binding || device != self.device {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub(super) fn is_closed(&self) -> bool {
        self.closed.get()
    }
    fn check(&self, request: &Authorization<'_>) -> Result<(), Error> {
        if self.closed.get() {
            return Err(Error::Revoked);
        }
        if request.binding != &self.binding || request.device != self.device {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

/// Unix seconds, independently polled while the member owner awaits Records.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&mut self) -> Result<u64, Error> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Clock",
                        Error::Clock,
                        &__cause,
                    )
                })?
                .as_secs())
        }
        #[cfg(target_arch = "wasm32")]
        {
            let now = js_sys::Date::now() / 1000.0;
            if !now.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&now) {
                return Err(Error::Clock);
            }
            Ok(now as u64)
        }
    }
}

/// Weak port into the same original Foyer. This owner cannot renew a session,
/// replace its bearer, access a root or authorize an application operation.
pub struct TransportAuthority<C> {
    lifetime: CustodyLifetime,
    membership: Rc<Mutex<cfyr::membership::LiveMembership<Transport>>>,
    origin: String,
    clock: C,
    last_time: u64,
}

/// Closes the session lifetime for good unless the check was accepted or could not
/// be determined. An undetermined check (`Error::Unavailable`: Records, membership
/// or policy could not be read right now) refuses only this operation: the lifetime
/// stays open, nothing is cached, and the next operation checks afresh. Every
/// definite negative (revoked, unauthorized, expired, clock) and any cancelled
/// check close it, as before.
struct CheckGuard {
    closed: Rc<Cell<bool>>,
    accepted: bool,
}
impl CheckGuard {
    fn new(lifetime: &CustodyLifetime) -> Self {
        Self {
            closed: lifetime.closed.clone(),
            accepted: false,
        }
    }
    /// The verdict comes from the check's own result type, never from a message.
    fn settle<T>(&mut self, result: &Result<T, Error>) {
        self.accepted = matches!(result, Ok(_) | Err(Error::Unavailable));
    }
}

/// A Foyer (membership) refusal: only "cannot be determined now" is undetermined.
fn foyer_refusal(error: cfyr::Error) -> Error {
    match error {
        cfyr::Error::Unavailable | cfyr::Error::Throttled => Error::Unavailable,
        cfyr::Error::Expired => Error::Expired,
        _ => Error::Unauthorized,
    }
}
/// A Records refusal: only an unreachable record engine is undetermined.
fn records_refusal(error: cvlt::RecordError) -> Error {
    match error {
        cvlt::RecordError::Unavailable => Error::Unavailable,
        cvlt::RecordError::Invalid | cvlt::RecordError::Limit => Error::Unauthorized,
    }
}
/// A community policy (trust feed) refusal: not yet current or momentarily busy or
/// unreachable is undetermined; a trust failure is a definite negative.
fn policy_refusal(error: cfyr::trust::Error) -> Error {
    match error {
        cfyr::trust::Error::Unavailable
        | cfyr::trust::Error::Busy
        | cfyr::trust::Error::Timeout
        | cfyr::trust::Error::Network
        | cfyr::trust::Error::Trust(cchr::Error::Unavailable) => Error::Unavailable,
        _ => Error::Unauthorized,
    }
}
impl Drop for CheckGuard {
    fn drop(&mut self) {
        if !self.accepted {
            self.closed.set(true);
        }
    }
}
impl<C: Clock> ckmg::Authority for TransportAuthority<C> {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.lifetime.check(&request)?;
        // The enum is closed: only tor.onion / VLD0 are representable here.
        if !matches!(request.action, Action::UseTransport(_))
            || request.root.is_some()
            || request.epoch != 0
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
            || !request.evidence.is_empty()
        {
            return Err(Error::Unauthorized);
        }
        let mut guard = CheckGuard::new(&self.lifetime);
        let result = self.observe(&request).await.map(|_| ());
        guard.settle(&result);
        result
    }
}

impl<C: Clock> TransportAuthority<C> {
    // Mutex covers HTTPS only. It is released before any member DHT read, so
    // the independent transport owner can use this same live session meanwhile.
    async fn observe(&mut self, request: &Authorization<'_>) -> Result<(u64, u64), Error> {
        let started = self.clock.now()?;
        if started < request.now || started < self.last_time {
            return Err(Error::Clock);
        }
        self.last_time = started;
        let mut failed_clock = false;
        let mut floor = started;
        let observed = self
            .membership
            .lock()
            .await
            .observe(|| match self.clock.now() {
                Ok(now) if now >= floor => {
                    floor = now;
                    now
                }
                _ => {
                    failed_clock = true;
                    u64::MAX // refusal sentinel; never an accepted observation
                }
            })
            .await;
        if failed_clock {
            return Err(Error::Clock);
        }
        let observed = observed.map_err(foyer_refusal)?;
        let after = self.clock.now()?;
        if after < floor {
            return Err(Error::Clock);
        }
        self.last_time = after;
        self.lifetime.check(request)?;
        if after >= observed.expires
            || observed.member != self.lifetime.binding.member()
            || !observed.device_keys.contains(self.lifetime.device.value())
        {
            return Err(Error::Revoked);
        }
        self.lifetime.bound.note(observed.expires);
        Ok((after, observed.expires))
    }
}

/// Member use requires a new forced Records observation and current policy on
/// every call. Only rollback floors and negative session state are retained.
/// Exact device signing additionally consumes the Door-owned one-use intent.
/// Pairing needs a separately admitted single-use Pair command for one exact
/// target and request digest; rotation and broader signer loans remain refused.
pub struct MemberAuthority<C, B: cdht::runtime::Backend> {
    live: TransportAuthority<C>,
    policy: cfyr::policy::CurrentPolicy<Transport>,
    records: cvlt::LineageRecords<B>,
    /// The wallet's stamp trust: a device-key member's lineage (genesis evidence by stamp)
    /// verifies only with it; None keeps the passkey-only verification.
    stamps: Option<cvlt::StampTrust>,
    intent: Option<ckmg::IntentVerifier>,
    /// The account actor's own one-use channels; never shared with `intent`.
    account: Option<AccountVerifiers>,
    pending_current: Option<current_member::PendingCurrent>,
    #[cfg(all(test, not(target_arch = "wasm32")))]
    reached_current: Option<tokio::sync::oneshot::Sender<()>>,
}
struct AccountVerifiers {
    root: ckmg::IntentVerifier,
    delegation: ckmg::IntentVerifier,
    request: ckmg::IntentVerifier,
    delegation_spent: bool,
    armed: Rc<Cell<bool>>,
}

/// Held by the account port around each of its Vault calls: while armed, the
/// member owner spends the account channels instead of the Board's.
#[derive(Clone)]
pub struct AccountArm(Rc<Cell<bool>>);
impl AccountArm {
    /// Arm until the returned guard drops.
    pub fn arm(&self) -> ArmGuard {
        self.0.set(true);
        ArmGuard(self.0.clone())
    }
}
/// Disarms on drop.
pub struct ArmGuard(Rc<Cell<bool>>);
impl Drop for ArmGuard {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// Retained original Foyer ports for constructing member authority after Tor
/// starts and Records handles exist. No root, accepted lineage or grant is held.
/// Its temporary recovery authority admits only the provisional lineage read.
pub struct MemberAuthorityBuilder {
    lifetime: CustodyLifetime,
    membership: Rc<Mutex<cfyr::membership::LiveMembership<Transport>>>,
    origin: String,
    policy: cfyr::policy::CurrentPolicy<Transport>,
    last_time: u64,
    stamps: Option<cvlt::StampTrust>,
}
impl MemberAuthorityBuilder {
    /// Verify stamp (device-key genesis) evidence with the wallet's authenticated stamp
    /// trust, judged at the receipt's signed time; passkey evidence verifies as before.
    #[must_use]
    pub fn with_stamps(mut self, stamps: cvlt::StampTrust) -> Self {
        self.stamps = Some(stamps);
        self
    }
    /// Attach genuine root-owned Records after network construction.
    pub fn bind<C: Clock, B: cdht::runtime::Backend>(
        self,
        records: cvlt::LineageRecords<B>,
        clock: C,
    ) -> super::Result<MemberAuthority<C, B>> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(MemberAuthority {
            live: TransportAuthority {
                lifetime: self.lifetime,
                membership: self.membership,
                origin: self.origin,
                clock,
                last_time: self.last_time,
            },
            policy: self.policy,
            records,
            stamps: self.stamps,
            intent: None,
            account: None,
            pending_current: None,
            #[cfg(all(test, not(target_arch = "wasm32")))]
            reached_current: None,
        })
    }
    /// Like [`Self::bind_with_intent`], plus the THREE distinct single-use channels
    /// of the account actor (root authorization, device delegation, account
    /// request) and the arm that selects them. They are consumed only while the
    /// account port holds the arm around its own Vault call, so the Board's
    /// signing channel is never spent by the account and the reverse.
    pub fn bind_with_account_intents<C: Clock, B: cdht::runtime::Backend>(
        self,
        records: cvlt::LineageRecords<B>,
        clock: C,
    ) -> super::Result<(
        MemberAuthority<C, B>,
        ckmg::IntentAdmission,
        super::accounting::AccountingIntents,
        ckmg::IntentAdmission,
        AccountArm,
    )> {
        let (mut authority, board) = self.bind_with_intent(records, clock)?;
        let (root, root_verifier) = ckmg::intent_channel();
        let (device, device_verifier) = ckmg::intent_channel();
        let (request, request_verifier) = ckmg::intent_channel();
        let armed = Rc::new(Cell::new(false));
        authority.account = Some(AccountVerifiers {
            root: root_verifier,
            delegation: device_verifier,
            request: request_verifier,
            delegation_spent: false,
            armed: armed.clone(),
        });
        Ok((
            authority,
            board,
            super::accounting::AccountingIntents {
                root,
                device,
                // The actor lives as long as the member session (the custody lifetime).
                expires: u64::MAX,
            },
            request,
            AccountArm(armed),
        ))
    }
    /// Construct exact local signing admission with this same member owner.
    pub fn bind_with_intent<C: Clock, B: cdht::runtime::Backend>(
        self,
        records: cvlt::LineageRecords<B>,
        clock: C,
    ) -> super::Result<(MemberAuthority<C, B>, ckmg::IntentAdmission)> {
        let mut authority = self.bind(records, clock)?;
        let (admission, verifier) = ckmg::intent_channel();
        authority.intent = Some(verifier);
        Ok((authority, admission))
    }
}
/// A Pair is bound to the lineage it extends: the evidence is that lineage's digest and must be
/// exactly the live selected head, so a stale or replayed Pair never applies to another one.
fn pair_base_matches(evidence: &[u8], live: Option<[u8; 32]>) -> bool {
    live.is_some_and(|digest| evidence == digest.as_slice())
}

/// Whether a refused dispatch ends the session. Only an `Unavailable` refusal of an
/// application operation (not a login step) is undetermined: it refuses that
/// operation and leaves the session open for the next, freshly checked one.
pub(crate) fn refusal_ends_session(action: &str, error: ErrorCode) -> bool {
    error != ErrorCode::Unavailable || action.starts_with("login.")
}

#[cfg(test)]
mod verdict_tests {
    use super::{foyer_refusal, policy_refusal, records_refusal, CheckGuard};
    use ckmg::Error;
    use std::{cell::Cell, rc::Rc};

    /// Settles one check with `result`, drops the guard and reports whether the
    /// session lifetime was closed for good.
    fn closed_after(result: Result<(), Error>) -> bool {
        let closed = Rc::new(Cell::new(false));
        let mut guard = CheckGuard {
            closed: closed.clone(),
            accepted: false,
        };
        guard.settle(&result);
        drop(guard);
        closed.get()
    }

    #[test]
    fn only_an_unavailable_application_operation_leaves_the_session_open() {
        use super::{refusal_ends_session, ErrorCode};
        assert!(!refusal_ends_session(
            "board.attend",
            ErrorCode::Unavailable
        ));
        assert!(!refusal_ends_session("inbox.send", ErrorCode::Unavailable));
        // A refused login step, and every definite or uncertain refusal, end it.
        for action in ["login.start", "login.poll", "login.cancel"] {
            assert!(refusal_ends_session(action, ErrorCode::Unavailable));
        }
        for error in [
            ErrorCode::Unauthorized,
            ErrorCode::Refused,
            ErrorCode::Reconcile,
            ErrorCode::Capacity,
            ErrorCode::InvalidRequest,
        ] {
            assert!(refusal_ends_session("board.attend", error), "{error:?}");
        }
    }

    #[test]
    fn an_undetermined_check_refuses_the_operation_and_keeps_the_session_open() {
        assert!(!closed_after(Ok(())));
        assert!(!closed_after(Err(Error::Unavailable)));
        // The next operation checks afresh on the same open lifetime.
        let closed = Rc::new(Cell::new(false));
        for result in [
            Err(Error::Unavailable),
            Ok(()),
            Err(Error::Unavailable),
            Ok(()),
        ] {
            let mut guard = CheckGuard {
                closed: closed.clone(),
                accepted: false,
            };
            guard.settle(&result);
        }
        assert!(!closed.get());
    }

    #[test]
    fn a_definite_negative_or_a_cancelled_check_closes_the_session_for_good() {
        for error in [
            Error::Revoked,
            Error::Unauthorized,
            Error::Expired,
            Error::Clock,
            Error::Limit,
        ] {
            assert!(closed_after(Err(error)), "{error:?}");
        }
        // A closed lifetime stays closed even when a later check is accepted.
        let closed = Rc::new(Cell::new(false));
        let mut guard = CheckGuard {
            closed: closed.clone(),
            accepted: false,
        };
        guard.settle(&Err::<(), _>(Error::Revoked));
        drop(guard);
        let mut guard = CheckGuard {
            closed: closed.clone(),
            accepted: false,
        };
        guard.settle(&Ok(()));
        drop(guard);
        assert!(closed.get());
        // A check dropped before it settled (cancelled) closes.
        let cancelled = Rc::new(Cell::new(false));
        drop(CheckGuard {
            closed: cancelled.clone(),
            accepted: false,
        });
        assert!(cancelled.get());
    }

    #[test]
    fn an_undetermined_verdict_comes_from_the_typed_refusal_not_from_a_message() {
        use cfyr::trust::Error as Policy;
        // Undetermined: the answer could not be had right now.
        assert_eq!(foyer_refusal(cfyr::Error::Unavailable), Error::Unavailable);
        assert_eq!(foyer_refusal(cfyr::Error::Throttled), Error::Unavailable);
        assert_eq!(
            records_refusal(cvlt::RecordError::Unavailable),
            Error::Unavailable
        );
        for undetermined in [
            Policy::Unavailable,
            Policy::Busy,
            Policy::Timeout,
            Policy::Network,
            Policy::Trust(cchr::Error::Unavailable),
        ] {
            assert_eq!(policy_refusal(undetermined), Error::Unavailable);
        }
        // Definite: never reported as undetermined, so the session closes.
        for definite in [
            cfyr::Error::Unauthorized,
            cfyr::Error::Forbidden,
            cfyr::Error::Refused,
            cfyr::Error::Reconcile,
            cfyr::Error::HeldInLobby,
            cfyr::Error::WrongHost,
            cfyr::Error::Invalid,
        ] {
            assert_eq!(foyer_refusal(definite), Error::Unauthorized, "{definite:?}");
        }
        assert_eq!(foyer_refusal(cfyr::Error::Expired), Error::Expired);
        for definite in [cvlt::RecordError::Invalid, cvlt::RecordError::Limit] {
            assert_eq!(records_refusal(definite), Error::Unauthorized);
        }
        for definite in [
            Policy::Configuration,
            Policy::Stopped,
            Policy::Obsolete,
            Policy::Response,
            Policy::Exhausted,
            Policy::ClockRegression,
            Policy::BehindAnnouncement,
            Policy::Trust(cchr::Error::Unauthenticated),
        ] {
            assert_eq!(
                policy_refusal(definite),
                Error::Unauthorized,
                "{definite:?}"
            );
        }
    }
}

#[cfg(test)]
mod pair_tests {
    use super::pair_base_matches;

    #[test]
    fn a_pair_applies_only_to_the_exact_live_lineage_it_extends() {
        let base = [7u8; 32];
        assert!(pair_base_matches(&base, Some(base)));
        // A later revision (stale base), a different lineage, empty or truncated evidence,
        // and an unreadable live head all refuse.
        assert!(!pair_base_matches(&base, Some([8u8; 32])));
        assert!(!pair_base_matches(&[], Some(base)));
        assert!(!pair_base_matches(&base[..31], Some(base)));
        assert!(!pair_base_matches(&base, None));
    }
}

impl<C: Clock, B: cdht::runtime::Backend> ckmg::Authority for MemberAuthority<C, B> {
    async fn check(&mut self, mut request: Authorization<'_>) -> Result<(), Error> {
        if request.action == Action::AuthorizeAccountDevice {
            return self
                .check_scoped_current(request, current_member::Purpose::AccountDevice)
                .await;
        }
        self.discard_pending_current();
        self.live.lifetime.check(&request)?;
        let pair = request.action == Action::Pair;
        let signing = match request.action {
            Action::Use if request.signing.is_none() => false,
            // Device pairing: the existing device adds exactly one proven new device. Only
            // against a distinct, single-use admitted command naming that target and the
            // digest of the exact pairing request; the lineage digest is not the statement.
            Action::Pair
                if request.signing.is_none()
                    && request.target.is_some()
                    && request.statement.is_some()
                    && self.intent.is_some() =>
            {
                true
            }
            Action::SignDeviceEd25519
                if request.signing.is_some()
                    && request.statement.is_none()
                    && self.intent.is_some() =>
            {
                true
            }
            // Next lineage record revision for a pending device authorization: only against a
            // distinct single-use admitted command, and the statement (the previous head's
            // digest) must be the live selected head, exactly like any other statement.
            Action::PublishLineage
                if request.signing.is_none()
                    && request.statement.is_some()
                    && self.intent.is_some() =>
            {
                true
            }
            // Profile signer plus Envelope custody: only against a distinct,
            // single-use admitted command for exactly this action.
            Action::LendProfileCustody
                if request.signing.is_none()
                    && request.statement.is_none()
                    && self.intent.is_some() =>
            {
                true
            }
            _ => return Err(Error::Unauthorized),
        };
        if request.root.is_none()
            || request.epoch == 0
            || (request.target.is_some() && !pair)
            || request.evidence.len() > ckmg::MAX_MESSAGE_BYTES
        {
            return Err(Error::Unauthorized);
        }
        let mut guard = CheckGuard::new(&self.live.lifetime);
        let result = self.current_lineage(request, signing, pair).await;
        guard.settle(&result);
        result
    }

    async fn check_record_recipient(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.check_scoped_current(request, current_member::Purpose::RecordRecipient)
            .await
    }
    async fn check_device_signing(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.check_scoped_current(request, current_member::Purpose::DeviceSigning)
            .await
    }
    async fn check_account_signing(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.check_scoped_current(request, current_member::Purpose::AccountSigning)
            .await
    }
    fn discard_current_attempt(&mut self) {
        self.discard_pending_current();
    }
    fn check_account_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.finish_scoped_current(request, current_member::Purpose::AccountSigning)
    }
    fn check_record_recipient_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.finish_scoped_current(request, current_member::Purpose::RecordRecipient)
    }
    fn check_device_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.finish_scoped_current(request, current_member::Purpose::DeviceSigning)
    }
    fn check_account_device_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.finish_scoped_current(request, current_member::Purpose::AccountDevice)
    }
}

impl<C: Clock, B: cdht::runtime::Backend> MemberAuthority<C, B> {
    /// The fresh, uncached current check of the generic member actions: live
    /// membership, the Records lineage and the community policy, then the one-use
    /// intent. Each step reports its own typed verdict (see `CheckGuard`).
    async fn current_lineage(
        &mut self,
        mut request: Authorization<'_>,
        signing: bool,
        pair: bool,
    ) -> Result<(), Error> {
        self.live.observe(&request).await?;
        // No HTTPS/Store/custody guard survives into this network await. The
        // independent node owner can perform its own fresh transport checks.
        let read = self.records.read().await.map_err(records_refusal)?;
        let (now, membership_expires) = self.live.observe(&request).await?;
        let lifetime = &self.live.lifetime;
        let clock = &mut self.live.clock;
        let stamps = self.stamps.as_ref();
        let completed = self
            .policy
            .with_current(now, |current| {
                if current.revocations().device_revoked(request.device.value()) {
                    return Err(Error::Unauthorized);
                }
                let mut selected: Option<cvlt::VerifiedLineageObservation<'_>> = None;
                for evidence in read.evidence() {
                    // Invalid observed material refuses the observation; never roll
                    // back to an older accepting head after a failed verification.
                    let candidate = evidence
                        .verify_for(current, stamps, lifetime.binding.member(), now)
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "Error::Unauthorized",
                                Error::Unauthorized,
                                &__cause,
                            )
                        })?;
                    let wins = match &selected {
                        None => true,
                        Some(previous) => candidate
                            .compare_conflict(previous, now)
                            .map_err(|__cause| {
                                crate::door::cause::emit(
                                    file!(),
                                    line!(),
                                    "Error::Unauthorized",
                                    Error::Unauthorized,
                                    &__cause,
                                )
                            })?
                            .is_gt(),
                    };
                    if wins {
                        selected = Some(candidate);
                    }
                }
                let selected = selected.ok_or(Error::Unavailable)?;
                let completed = clock.now()?;
                if completed < now {
                    return Err(Error::Clock);
                }
                if completed >= membership_expires {
                    return Err(Error::Unauthorized);
                }
                lifetime.observe_lineage(&selected, completed)?;
                let lineage = selected.lineage(completed).map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Unauthorized",
                        Error::Unauthorized,
                        &__cause,
                    )
                })?;
                if request.root != Some(lineage.root)
                    || request.epoch != lineage.epoch
                    || (!pair
                        && request
                            .statement
                            .is_some_and(|digest| lineage.digest().ok() != Some(digest)))
                    // Pair: the statement is the pairing request, so the pre-pairing lineage
                    // digest travels as the evidence and must equal the live selected head.
                    || (pair && !pair_base_matches(request.evidence, lineage.digest().ok()))
                {
                    return Err(Error::Unauthorized);
                }
                Ok(completed)
            })
            .map_err(policy_refusal)??;
        self.live.last_time = completed;
        self.live.lifetime.check(&request)?;
        if signing {
            // Intent must survive the actual freshness waits, including its
            // expiry. The original Keys request time preceded those waits.
            request.now = completed;
            self.intent
                .as_mut()
                .ok_or(Error::Unauthorized)?
                .consume(&request, &self.live.origin)?;
        }
        Ok(())
    }
}

impl Door {
    /// Bind a completed original root-owned Records capability to the same
    /// session as transport. This does not solve provisional read-key bootstrap
    /// or create/read a missing record; the trusted composer supplies the owner.
    pub fn member_authority<C: Clock, T, B: cdht::runtime::Backend>(
        &self,
        origin: &str,
        transport: &TransportAuthority<T>,
        records: cvlt::LineageRecords<B>,
        clock: C,
    ) -> super::Result<MemberAuthority<C, B>> {
        self.member_authority_builder(origin, transport)?
            .bind(records, clock)
    }

    /// Capture weak current-policy and serialized live-membership ports BEFORE
    /// transport authority moves into its independent credential task. Records
    /// are attached later, without borrowing back that task's secret owner.
    pub fn member_authority_builder<T>(
        &self,
        origin: &str,
        transport: &TransportAuthority<T>,
    ) -> super::Result<MemberAuthorityBuilder> {
        self.member_origin(origin)?;
        if origin != transport.origin
            || transport.lifetime.is_closed()
            || transport.lifetime.binding.community() != self.config.community
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(MemberAuthorityBuilder {
            lifetime: transport.lifetime.clone(),
            membership: transport.membership.clone(),
            origin: origin.into(),
            policy: self.custody_current_policy(origin)?,
            last_time: transport.last_time,
            stamps: None,
        })
    }

    /// Create both original intent-channel halves with this same authority.
    /// Retain admission in the bound Vault, never in generated caller input.
    pub fn member_authority_with_intent<C: Clock, T, B: cdht::runtime::Backend>(
        &self,
        origin: &str,
        transport: &TransportAuthority<T>,
        records: cvlt::LineageRecords<B>,
        clock: C,
    ) -> super::Result<(MemberAuthority<C, B>, ckmg::IntentAdmission)> {
        self.member_authority_builder(origin, transport)?
            .bind_with_intent(records, clock)
    }

    /// Construct transport authority for one passkey-unlocked session. Binding
    /// and device are original Keys observations supplied by the trusted host,
    /// never action JSON. Keep this owner independent of the serial Door queue.
    pub fn transport_authority<C: Clock>(
        &self,
        origin: &str,
        binding: Binding,
        device: PublicKey,
        clock: C,
    ) -> super::Result<(TransportAuthority<C>, CustodyLifetime)> {
        self.member_origin(origin)?;
        if binding.community() != self.config.community {
            return Err(ErrorCode::Unauthorized);
        }
        let lifetime = CustodyLifetime {
            binding,
            device,
            closed: Rc::new(Cell::new(false)),
            bound: SigningBound::default(),
        };
        let authority = TransportAuthority {
            lifetime: lifetime.clone(),
            membership: Rc::new(Mutex::new(self.custody_membership(origin)?)),
            origin: origin.into(),
            clock,
            last_time: 0,
        };
        Ok((authority, lifetime))
    }
}

#[cfg(test)]
mod account_channel_tests {
    use super::{account_channel, AccountChannel::*};

    /// Row 17: enrollment (authorize, delegation), the account request, then a
    /// record-recipient round (authorize, device signature) after activation.
    /// The second round's device signature is its delegation again, never the
    /// request channel.
    #[test]
    fn every_root_authorization_starts_a_new_delegation_round() {
        let mut spent = false;
        let calls = [true, false, false, true, false, false, true, false];
        let seen: Vec<_> = calls
            .iter()
            .map(|authorize| account_channel(*authorize, &mut spent))
            .collect();
        assert_eq!(
            seen,
            [Root, Delegation, Request, Root, Delegation, Request, Root, Delegation]
        );
    }
}

#[cfg(test)]
mod signing_bound_tests {
    use super::*;

    #[test]
    fn a_short_membership_lease_clamps_the_grant_to_the_authority_bound() {
        let bound = SigningBound::default();
        // A newcomer's lease runs out long before the session grant.
        bound.note(100);
        assert_eq!(bound.clamp(1_000, 50), Ok(100));
        // A grant already inside the bound stays as wanted.
        assert_eq!(bound.clamp(80, 50), Ok(80));
    }

    #[test]
    fn the_grant_re_binds_to_the_renewed_bound() {
        let bound = SigningBound::default();
        bound.note(100);
        assert_eq!(bound.clamp(1_000, 50), Ok(100));
        // The authority renews: the next grant follows the renewed bound.
        bound.note(400);
        assert_eq!(bound.clamp(1_000, 150), Ok(400));
    }

    #[test]
    fn a_passed_bound_refuses_and_no_observation_leaves_the_strict_check_to_decide() {
        let bound = SigningBound::default();
        assert_eq!(bound.clamp(1_000, 50), Ok(1_000));
        bound.note(100);
        assert_eq!(bound.clamp(1_000, 100), Err(ErrorCode::Unavailable));
        assert_eq!(bound.clamp(1_000, 150), Err(ErrorCode::Unavailable));
    }

    #[test]
    fn every_clone_of_a_lifetime_and_its_slot_share_one_bound() {
        let slot = MemberSlot::default();
        let shared = slot.signing_bound();
        shared.note(70);
        assert_eq!(slot.signing_bound().clamp(1_000, 10), Ok(70));
    }
}
