//! The account update protocol of the actor, free of any network or Vault type.
//!
//! One signed update is driven in two durable steps that survive any
//! interruption: the exact signed bytes are written to custody BEFORE the first
//! send, and they stay there until the caller confirms it applied the operator's
//! acceptance (`settle`). A retry, a restart or a lost answer therefore always
//! re-sends the identical bytes, and the operator answers an exact retry with
//! the original acceptance; the update is never signed or proven twice.
//!
//! The same module holds the login renewal rule of the community credential.
use super::super::accounting::{
    outbox_request_id, AcceptedResponse, ProvenUpdate, SignedApplyExtended,
};
use super::super::{ErrorCode, Result};
use std::sync::Arc;

/// A value handed through the actor mailbox. Equality is identity: the mailbox
/// types need `Eq`, the proof material does not.
pub struct Shared<T>(Arc<T>);

impl<T> Shared<T> {
    pub(in crate::door) fn new(value: T) -> Self {
        Self(Arc::new(value))
    }
}
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl<T> PartialEq for Shared<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl<T> Eq for Shared<T> {}
impl<T> std::fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}
impl<T> std::ops::Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// An update the operator accepted, with the verified response. The certificate
/// inside is what the caller needs for its next proof; it is not custody yet.
pub struct Applied {
    request_id: [u8; 32],
    response: AcceptedResponse,
}

impl Applied {
    pub(super) fn new(request_id: [u8; 32], response: AcceptedResponse) -> Self {
        Self {
            request_id,
            response,
        }
    }
    /// Identifier of the signed request this acceptance belongs to; `settle` takes it.
    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }
    /// The verified operator response (acceptance, state certificate, ancestry).
    pub fn response(&self) -> &AcceptedResponse {
        &self.response
    }
}

/// The durable side: the outbox of an update that is not settled yet.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) trait UpdateStore {
    /// The stored outbox, if one is owed.
    async fn stored(&mut self) -> Result<Option<Vec<u8>>>;
    /// Write the outbox durably; returns only once it is stored.
    async fn persist(&mut self, outbox: &[u8]) -> Result<()>;
    /// Forget the stored outbox.
    async fn clear(&mut self) -> Result<()>;
}

/// The signing and sending side, through one held admission.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) trait UpdateWire {
    /// Sign the proven update exactly once.
    async fn sign(&mut self, proven: &ProvenUpdate) -> Result<SignedApplyExtended>;
    /// Rebuild a stored outbox without signing.
    async fn restore(&mut self, outbox: Vec<u8>) -> Result<SignedApplyExtended>;
    /// Send the bytes and verify the answer; any failure is `Reconcile`.
    async fn send(&mut self, signed: &SignedApplyExtended) -> Result<AcceptedResponse>;
}

fn same(signed: &SignedApplyExtended, proven: &ProvenUpdate) -> bool {
    signed.statement() == &proven.statement && signed.update() == &proven.update
}

/// Send this proven update. With nothing owed it is signed, stored, then sent.
/// If this very update is already stored (a retry after a lost answer or a
/// restart) the stored bytes are re-sent unchanged. If a DIFFERENT update is
/// still owed, nothing is signed or sent: `Reconcile`, and the caller first
/// takes `resume` and `settle` of the owed one (its proof was built on a state
/// that this acceptance changes).
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn apply<S: UpdateStore + UpdateWire>(
    seam: &mut S,
    proven: &ProvenUpdate,
) -> Result<Applied> {
    let signed = match seam.stored().await? {
        Some(outbox) => {
            let signed = seam.restore(outbox).await?;
            if !same(&signed, proven) {
                return Err(ErrorCode::Reconcile);
            }
            signed
        }
        None => {
            let signed = seam.sign(proven).await?;
            seam.persist(signed.outbox()).await?;
            signed
        }
    };
    let response = seam.send(&signed).await?;
    Ok(Applied::new(signed.request_id(), response))
}

/// Finish an owed update: re-send the stored bytes and return the original
/// acceptance, or `None` when nothing is owed.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn resume<S: UpdateStore + UpdateWire>(seam: &mut S) -> Result<Option<Applied>> {
    let Some(outbox) = seam.stored().await? else {
        return Ok(None);
    };
    let signed = seam.restore(outbox).await?;
    let response = seam.send(&signed).await?;
    Ok(Some(Applied::new(signed.request_id(), response)))
}

/// The caller applied the acceptance of `request_id`: forget the stored bytes.
/// Settling nothing is a no-op; settling another request is refused.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn settle<S: UpdateStore>(seam: &mut S, request_id: [u8; 32]) -> Result<()> {
    let Some(outbox) = seam.stored().await? else {
        return Ok(());
    };
    if outbox_request_id(&outbox)? != request_id {
        return Err(ErrorCode::Refused);
    }
    seam.clear().await
}

/// A credential that ends within this many seconds is renewed on login.
pub(super) const RENEW_WITHIN: u64 = 3600;

/// The expiry claim of a community credential, read WITHOUT verifying it: only
/// a hint when to ask for a new one (a forged hint can only cause a renewal; the
/// credential itself is verified by whoever relies on it). `None` when the
/// bytes are not a COSE_Sign1 carrying CWT claims.
pub(super) fn credential_valid_until(cose: &[u8]) -> Option<u64> {
    const CWT_CLAIMS: u64 = 15;
    const EXP: u64 = 4;
    let mut input = cose;
    let (mut major, mut argument) = head(&mut input)?;
    if major == 6 {
        (major, argument) = head(&mut input)?;
    }
    if (major, argument) != (4, 4) {
        return None;
    }
    let (major, length) = head(&mut input)?;
    if major != 2 {
        return None;
    }
    let mut protected = take(&mut input, length)?;
    let (major, entries) = head(&mut protected)?;
    if major != 5 {
        return None;
    }
    for _ in 0..entries {
        let (key_major, key) = head(&mut protected)?;
        if key_major == 0 && key == CWT_CLAIMS {
            let (major, claims) = head(&mut protected)?;
            if major != 5 {
                return None;
            }
            for _ in 0..claims {
                let (key_major, key) = head(&mut protected)?;
                let (value_major, value) = head(&mut protected)?;
                if key_major == 0 && key == EXP && value_major == 0 {
                    return Some(value);
                }
                skip_body(&mut protected, value_major, value, 0)?;
            }
            return None;
        }
        skip_body(&mut protected, key_major, key, 0)?;
        skip(&mut protected, 0)?;
    }
    None
}

fn take<'a>(input: &mut &'a [u8], length: u64) -> Option<&'a [u8]> {
    let length = match usize::try_from(length) {
        Ok(length) => length,
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "usize::try_from", &__cause);
            return None;
        }
    };
    if input.len() < length {
        return None;
    }
    let (head, rest) = input.split_at(length);
    *input = rest;
    Some(head)
}

/// One CBOR item head: the major type and its argument (definite lengths only).
fn head(input: &mut &[u8]) -> Option<(u8, u64)> {
    let first = *input.first()?;
    *input = &input[1..];
    let (major, info) = (first >> 5, first & 31);
    let width = match info {
        0..=23 => return Some((major, u64::from(info))),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let bytes = take(input, width)?;
    Some((
        major,
        bytes
            .iter()
            .fold(0, |sum, byte| sum << 8 | u64::from(*byte)),
    ))
}

fn skip(input: &mut &[u8], depth: u8) -> Option<()> {
    let (major, argument) = head(input)?;
    skip_body(input, major, argument, depth)
}

/// Skip what follows an already read head. Nesting is bounded.
fn skip_body(input: &mut &[u8], major: u8, argument: u64, depth: u8) -> Option<()> {
    if depth > 8 {
        return None;
    }
    match major {
        0 | 1 | 7 => Some(()),
        2 | 3 => take(input, argument).map(|_| ()),
        4 => (0..argument).try_for_each(|_| skip(input, depth + 1)),
        5 => (0..argument).try_for_each(|_| {
            skip(input, depth + 1)?;
            skip(input, depth + 1)
        }),
        6 => skip(input, depth + 1),
        _ => None,
    }
}

/// Whether the stored credential must be renewed now: none stored, unreadable,
/// or ending within `RENEW_WITHIN` seconds.
pub(super) fn renewal_due(stored: Option<&[u8]>, now: u64) -> bool {
    stored
        .and_then(credential_valid_until)
        .is_none_or(|until| until <= now.saturating_add(RENEW_WITHIN))
}

/// What the login renewal needs: the stored credential and a way to ask for a
/// new one through a fresh admission.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) trait Credentials {
    async fn stored(&mut self) -> Result<Option<Vec<u8>>>;
    /// Admit afresh and keep the credential the server issues (stored in custody).
    async fn renew(&mut self) -> Result<()>;
}

/// Renew the credential on login when it is due. Network trouble leaves the
/// old credential in place for the next login; a refusal is reported.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn renew_on_login<C: Credentials>(credentials: &mut C, now: u64) -> Result<bool> {
    let stored = credentials.stored().await?;
    if !renewal_due(stored.as_deref(), now) {
        return Ok(false);
    }
    match credentials.renew().await {
        Ok(()) => Ok(true),
        Err(ErrorCode::Unavailable | ErrorCode::Reconcile) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::accounting::update_fixtures as fixtures;
    use super::*;

    fn block<T>(future: impl std::future::Future<Output = T>) -> T {
        futures_executor::block_on(future)
    }

    /// A scripted account: custody in memory, a log of every step, and an
    /// operator that answers an exact retry with the original acceptance and
    /// can lose answers.
    #[derive(Default)]
    struct Script {
        stored: Option<Vec<u8>>,
        log: Vec<&'static str>,
        sent: Vec<Vec<u8>>,
        /// Answers still to be lost (the request reaches the operator).
        lose: usize,
        refuse_persist: bool,
        /// The operator's record: first accepted_at per request id.
        accepted: Vec<([u8; 32], u64)>,
        clock: u64,
    }

    impl UpdateStore for Script {
        async fn stored(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.stored.clone())
        }
        async fn persist(&mut self, outbox: &[u8]) -> Result<()> {
            if self.refuse_persist {
                return Err(ErrorCode::Unavailable);
            }
            self.log.push("persist");
            self.stored = Some(outbox.to_vec());
            Ok(())
        }
        async fn clear(&mut self) -> Result<()> {
            self.log.push("clear");
            self.stored = None;
            Ok(())
        }
    }

    impl UpdateWire for Script {
        async fn sign(&mut self, proven: &ProvenUpdate) -> Result<SignedApplyExtended> {
            self.log.push("sign");
            Ok(fixtures::signed(
                u8::try_from(proven.statement.next_version - 5).unwrap(),
            ))
        }
        async fn restore(&mut self, outbox: Vec<u8>) -> Result<SignedApplyExtended> {
            Ok(fixtures::restore(outbox))
        }
        async fn send(&mut self, signed: &SignedApplyExtended) -> Result<AcceptedResponse> {
            self.log.push("send");
            self.sent.push(signed.outbox().to_vec());
            self.clock += 1;
            let at = match self
                .accepted
                .iter()
                .find(|(id, _)| *id == signed.request_id())
            {
                Some((_, at)) => *at,
                None => {
                    let at = 150 + self.clock;
                    self.accepted.push((signed.request_id(), at));
                    at
                }
            };
            if self.lose > 0 {
                self.lose -= 1;
                return Err(ErrorCode::Reconcile);
            }
            Ok(fixtures::accepted(signed, at))
        }
    }

    #[test]
    fn a_signed_update_is_stored_before_it_is_sent() {
        let mut script = Script::default();
        let applied = block(apply(&mut script, &fixtures::proven(0))).unwrap();
        assert_eq!(script.log, ["sign", "persist", "send"]);
        assert_eq!(script.stored.as_deref(), Some(script.sent[0].as_slice()));
        assert_eq!(applied.request_id(), fixtures::signed(0).request_id());
        // A store that cannot write stops before anything leaves the device.
        let mut refusing = Script {
            refuse_persist: true,
            ..Script::default()
        };
        assert_eq!(
            block(apply(&mut refusing, &fixtures::proven(0))).err(),
            Some(ErrorCode::Unavailable)
        );
        assert_eq!(refusing.log, ["sign"]);
        assert!(refusing.sent.is_empty());
    }

    #[test]
    fn a_retry_sends_identical_bytes_and_never_signs_again() {
        let mut script = Script {
            lose: 2,
            ..Script::default()
        };
        let proven = fixtures::proven(0);
        for _ in 0..2 {
            assert_eq!(
                block(apply(&mut script, &proven)).err(),
                Some(ErrorCode::Reconcile)
            );
        }
        let applied = block(apply(&mut script, &proven)).unwrap();
        assert_eq!(script.sent.len(), 3);
        assert!(script.sent.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(script.log.iter().filter(|step| **step == "sign").count(), 1);
        assert_eq!(
            script.log.iter().filter(|step| **step == "persist").count(),
            1
        );
        assert_eq!(applied.request_id(), fixtures::signed(0).request_id());
    }

    #[test]
    fn a_lost_answer_reconciles_to_the_original_acceptance_after_a_restart() {
        let mut script = Script {
            lose: 1,
            ..Script::default()
        };
        assert!(block(apply(&mut script, &fixtures::proven(0))).is_err());
        let original = script.accepted[0].1;
        // The device restarts: nothing but the stored bytes remains.
        let resumed = block(resume(&mut script)).unwrap().unwrap();
        assert_eq!(resumed.response().acceptance().accepted_at, original);
        assert_eq!(resumed.response().certificate().accepted_at, original);
        assert_eq!(script.sent[0], script.sent[1]);
        // Still owed until the caller settles; asking again gives the same answer.
        let again = block(resume(&mut script)).unwrap().unwrap();
        assert_eq!(again.response().acceptance().accepted_at, original);
        block(settle(&mut script, resumed.request_id())).unwrap();
        assert_eq!(block(resume(&mut script)).unwrap().map(|_| ()), None);
    }

    #[test]
    fn another_update_waits_until_the_owed_one_is_settled() {
        let mut script = Script {
            lose: 1,
            ..Script::default()
        };
        assert!(block(apply(&mut script, &fixtures::proven(0))).is_err());
        let signs = script.log.iter().filter(|step| **step == "sign").count();
        let sends = script.sent.len();
        assert_eq!(
            block(apply(&mut script, &fixtures::proven(1))).err(),
            Some(ErrorCode::Reconcile)
        );
        // Nothing was signed or sent for the second one.
        assert_eq!(
            script.log.iter().filter(|step| **step == "sign").count(),
            signs
        );
        assert_eq!(script.sent.len(), sends);
        let done = block(resume(&mut script)).unwrap().unwrap();
        // The wrong request cannot settle it; the right one can.
        assert_eq!(
            block(settle(&mut script, [9; 32])).err(),
            Some(ErrorCode::Refused)
        );
        assert!(script.stored.is_some());
        block(settle(&mut script, done.request_id())).unwrap();
        assert!(script.stored.is_none());
        block(apply(&mut script, &fixtures::proven(1))).unwrap();
        block(settle(&mut script, fixtures::signed(1).request_id())).unwrap();
        // Settling with nothing owed is a no-op.
        block(settle(&mut script, fixtures::signed(1).request_id())).unwrap();
    }

    #[test]
    fn shared_values_compare_by_identity_and_hide_their_content() {
        let one = Shared::new(5u8);
        assert_eq!(one, one.clone());
        assert_ne!(one, Shared::new(5u8));
        assert_eq!(*one, 5);
        assert!(!format!("{one:?}").contains('5'));
    }

    fn credential(issued: u64, until: u64) -> Vec<u8> {
        let mut signer = csgn::Signer::new(
            "cmty",
            csgn::SecretKey::from_seed(&mut [1; 32]),
            issued,
            86_400 * 30,
        )
        .unwrap();
        signer
            .sign(csgn::Kind::Credential, b"payload", issued, until)
            .unwrap()
    }

    #[test]
    fn the_expiry_of_a_credential_is_read_from_its_claims() {
        assert_eq!(credential_valid_until(&credential(1000, 5000)), Some(5000));
        assert_eq!(credential_valid_until(&credential(7, 90_000)), Some(90_000));
        for bad in [
            &b""[..],
            b"x",
            &[0xd2, 0x84],
            &[0xa0],
            &[0x84, 0x40, 0xa0, 0x40, 0x40],
        ] {
            assert_eq!(credential_valid_until(bad), None);
        }
        let mut cut = credential(1000, 5000);
        cut.truncate(20);
        assert_eq!(credential_valid_until(&cut), None);
    }

    #[test]
    fn a_credential_within_an_hour_of_its_end_is_due() {
        let cose = credential(1000, 100_000);
        assert!(!renewal_due(Some(&cose), 1000));
        assert!(!renewal_due(Some(&cose), 100_000 - RENEW_WITHIN - 1));
        assert!(renewal_due(Some(&cose), 100_000 - RENEW_WITHIN));
        assert!(renewal_due(Some(&cose), 100_000));
        assert!(renewal_due(Some(&cose), u64::MAX));
        assert!(renewal_due(None, 0));
        assert!(renewal_due(Some(b"unreadable"), 0));
    }

    struct Vault {
        stored: Option<Vec<u8>>,
        renewals: usize,
        outcome: Result<()>,
    }
    impl Credentials for Vault {
        async fn stored(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.stored.clone())
        }
        async fn renew(&mut self) -> Result<()> {
            self.renewals += 1;
            self.outcome
        }
    }

    #[test]
    fn login_renews_a_due_credential_and_leaves_a_fresh_one_alone() {
        let now = 50_000;
        let mut fresh = Vault {
            stored: Some(credential(1000, now + 86_400)),
            renewals: 0,
            outcome: Ok(()),
        };
        assert_eq!(block(renew_on_login(&mut fresh, now)), Ok(false));
        assert_eq!(fresh.renewals, 0);
        let mut due = Vault {
            stored: Some(credential(1000, now + 1800)),
            renewals: 0,
            outcome: Ok(()),
        };
        assert_eq!(block(renew_on_login(&mut due, now)), Ok(true));
        assert_eq!(due.renewals, 1);
        // No network: the old credential stays and the next login tries again.
        due.outcome = Err(ErrorCode::Unavailable);
        assert_eq!(block(renew_on_login(&mut due, now)), Ok(false));
        // A refusal is the member's to hear.
        due.outcome = Err(ErrorCode::Refused);
        assert_eq!(
            block(renew_on_login(&mut due, now)),
            Err(ErrorCode::Refused)
        );
    }
}
