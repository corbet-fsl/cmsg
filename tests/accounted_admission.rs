mod common;
use cmsg::{
    Error, FirstContactPolicy, FirstContactRole, Inbox, Member, MemberIdentity, ReservationContext,
    ReservationContexts, ReservationPolicy, ReservationVerifier, VerifiedReservation,
};
use common::accounting::{device, Time, CONTEXT, KEY};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

// Scripted proof verdicts test only cmsg admission/storage gates. Actual peer
// proofs are exercised separately by the pinned cfrm browser composition.
struct Scripted {
    contexts: ReservationContexts,
    current: bool,
}
impl ReservationVerifier for Scripted {
    fn verify_remote(
        &mut self,
        evidence: &[u8],
        _: &ReservationContext,
    ) -> Result<VerifiedReservation, Error> {
        let expected = match evidence {
            b"outgoing" => self.contexts.outgoing.expected.clone(),
            b"incoming" => self.contexts.incoming.expected.clone(),
            _ => return Err(Error::Admission),
        };
        Ok(VerifiedReservation {
            valid_until: expected.expires_at,
            expected,
            state_policy_digest: [7; 32],
            state_version: 3,
            state_commitment: [8; 32],
            presentation_binding: [9; 32],
            owner_authority: [10; 32],
        })
    }
    fn verify_current_local(
        &mut self,
        evidence: &[u8],
        context: &ReservationContext,
    ) -> Result<VerifiedReservation, Error> {
        if !self.current {
            return Err(Error::Admission);
        }
        self.verify_remote(evidence, context)
    }
}
fn contact_policy() -> FirstContactPolicy {
    FirstContactPolicy {
        response_deadline: 500,
        max_intro_bytes: 128,
    }
}
fn reservation_policy() -> ReservationPolicy {
    ReservationPolicy {
        state_policy_digest: [7; 32],
        opened_at: 100,
        abandon_after: 300,
    }
}
struct Pair {
    a: Member,
    b: Member,
    ai: Inbox,
    bi: Inbox,
    sender: String,
    recipient: String,
    welcome: Vec<u8>,
    time: Arc<Time>,
}
impl Pair {
    fn new() -> Self {
        let time = Arc::new(Time(AtomicU64::new(100)));
        let ar = MemberIdentity::new("synthetic-community").unwrap();
        let br = MemberIdentity::new("synthetic-community").unwrap();
        let mut a = device(&ar, &time, 10_000);
        let mut b = device(&br, &time, 10_000);
        a.create_group().unwrap();
        let welcome = a.add(&b.key_package().unwrap()).unwrap().welcome;
        let ai = Inbox::new_accounted(&a).unwrap();
        let bi = Inbox::new_accounted(&b).unwrap();
        Self {
            a,
            b,
            ai,
            bi,
            sender: ar.member_id().to_owned(),
            recipient: br.member_id().to_owned(),
            welcome,
            time,
        }
    }
    fn stage(&mut self) -> ReservationContexts {
        self.bi
            .stage_accounted_invitation(
                &mut self.b,
                &self.welcome,
                &[21; 32],
                contact_policy(),
                reservation_policy(),
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap()
    }
    fn configure_sender(&mut self, recipient: &ReservationContexts) -> Scripted {
        self.ai
            .begin_first_contact(
                &self.recipient,
                &[21; 32],
                FirstContactRole::Initiator,
                contact_policy(),
                &self.a,
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap();
        let sender = self
            .ai
            .require_active_reservations(&self.a, reservation_policy(), &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        self.ai
            .set_own_reservation_challenge(
                &self.a,
                &recipient.outgoing.expected.challenge,
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap();
        self.bi
            .set_own_reservation_challenge(
                &self.b,
                &sender.incoming.expected.challenge,
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap();
        let contexts = self.bi.reservation_contexts(&self.b).unwrap();
        assert_eq!(contexts, self.ai.reservation_contexts(&self.a).unwrap());
        Scripted {
            contexts,
            current: true,
        }
    }
    fn live(&mut self) {
        let a = self
            .ai
            .begin_live_session(
                &mut self.a,
                &self.b.chat_public_key(),
                350,
                &KEY,
                CONTEXT,
                |_, _| Ok(()),
            )
            .unwrap();
        let b = self
            .bi
            .begin_live_session(
                &mut self.b,
                &self.a.chat_public_key(),
                350,
                &KEY,
                CONTEXT,
                |_, _| Ok(()),
            )
            .unwrap();
        self.bi
            .receive_contact(&mut self.b, &a, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        self.ai
            .receive_contact(&mut self.a, &b, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        for _ in 0..4 {
            for wire in self.ai.pending_live_controls() {
                self.bi
                    .receive_contact(&mut self.b, &wire, &KEY, CONTEXT, |_| Ok(()))
                    .unwrap();
            }
            self.ai
                .clear_live_controls(&self.a, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
            for wire in self.bi.pending_live_controls() {
                self.ai
                    .receive_contact(&mut self.a, &wire, &KEY, CONTEXT, |_| Ok(()))
                    .unwrap();
            }
            self.bi
                .clear_live_controls(&self.b, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
        }
    }
}

#[test]
fn staged_welcome_persists_exact_context_without_known_contact_or_legacy_spend() {
    let mut p = Pair::new();
    assert!(p
        .bi
        .stage_accounted_invitation(
            &mut p.b,
            &p.welcome,
            &[21; 32],
            contact_policy(),
            reservation_policy(),
            &KEY,
            CONTEXT,
            |_| Err(Error::InvalidStore)
        )
        .is_err());
    assert!(
        p.b.participants().is_err(),
        "failed durable stage rolls back MLS join"
    );
    assert!(!p.bi.is_known(&p.sender));
    let context = p.stage();
    assert!(!p.bi.is_known(&p.sender));
    assert_eq!(
        context.outgoing.device_public_key.as_slice(),
        p.a.chat_public_key()
    );
    assert_eq!(
        context.incoming.device_public_key.as_slice(),
        p.b.chat_public_key()
    );
    assert_eq!(context.outgoing.expected.nonce, [21; 32]);
    let sealed = p.bi.snapshot(&p.b, &KEY, CONTEXT).unwrap();
    (p.bi, p.b) = Inbox::restore_with_clock(&sealed, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert!(!p.bi.is_known(&p.sender));
    assert_eq!(
        context,
        p.stage(),
        "exact durable retry preserves recipient challenge"
    );
    let mut changed = p.welcome.clone();
    changed[0] ^= 1;
    assert!(p
        .bi
        .stage_accounted_invitation(
            &mut p.b,
            &changed,
            &[21; 32],
            contact_policy(),
            reservation_policy(),
            &KEY,
            CONTEXT,
            |_| panic!("changed Welcome")
        )
        .is_err());
    assert!(p
        .bi
        .stage_accounted_invitation(
            &mut p.b,
            &p.welcome,
            &[22; 32],
            contact_policy(),
            reservation_policy(),
            &KEY,
            CONTEXT,
            |_| panic!("changed introduction")
        )
        .is_err());
}

#[test]
fn completion_needs_consent_current_own_proof_and_final_durable_write() {
    let mut p = Pair::new();
    let context = p.stage();
    let mut verifier = p.configure_sender(&context);
    p.live();
    assert!(p
        .bi
        .complete_accounted_invitation(
            &p.b,
            b"outgoing",
            b"incoming",
            &mut verifier,
            &KEY,
            CONTEXT,
            |_| panic!("missing incoming consent")
        )
        .is_err());
    verifier.contexts.outgoing.expected.challenge[0] ^= 1;
    assert!(p
        .bi
        .authorize_incoming_reservation(
            &p.b,
            b"outgoing",
            &mut verifier,
            &KEY,
            CONTEXT,
            |_| panic!("wrong proof challenge")
        )
        .is_err());
    verifier.contexts.outgoing.expected.challenge[0] ^= 1;
    p.bi.authorize_incoming_reservation(
        &p.b,
        b"outgoing",
        &mut verifier,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    verifier.current = false;
    assert!(p
        .bi
        .complete_accounted_invitation(
            &p.b,
            b"outgoing",
            b"incoming",
            &mut verifier,
            &KEY,
            CONTEXT,
            |_| panic!("superseded own account")
        )
        .is_err());
    verifier.current = true;
    p.ai.bind_active_reservations(
        &p.a,
        b"outgoing",
        b"incoming",
        &mut verifier,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    p.bi.bind_active_reservations(
        &p.b,
        b"outgoing",
        b"incoming",
        &mut verifier,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    let wire =
        p.ai.send_contact(&mut p.a, b"protected", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(p
        .bi
        .receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| panic!(
            "generic binding cannot bypass pending admission"
        ))
        .is_err());
    assert!(p
        .bi
        .complete_accounted_invitation(
            &p.b,
            b"outgoing",
            b"incoming",
            &mut verifier,
            &KEY,
            CONTEXT,
            |_| Err(Error::InvalidStore)
        )
        .is_err());
    assert!(!p.bi.is_known(&p.sender));
    p.bi.complete_accounted_invitation(
        &p.b,
        b"outgoing",
        b"incoming",
        &mut verifier,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    assert!(p.bi.is_known(&p.sender));
    p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
}

#[test]
fn cancelled_expired_and_wrong_recipient_invitations_fail_closed() {
    for cancel in [false, true] {
        let mut p = Pair::new();
        let context = p.stage();
        let mut verifier = p.configure_sender(&context);
        p.bi.authorize_incoming_reservation(
            &p.b,
            b"outgoing",
            &mut verifier,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
        if cancel {
            p.bi.cancel_accounted_invitation(&p.b, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
        } else {
            p.time.0.store(400, Ordering::Relaxed);
        }
        let sealed = p.bi.snapshot(&p.b, &KEY, CONTEXT).unwrap();
        (p.bi, p.b) = Inbox::restore_with_clock(&sealed, &KEY, CONTEXT, p.time.clone()).unwrap();
        assert!(!p.bi.is_known(&p.sender));
        assert!(p
            .bi
            .complete_accounted_invitation(
                &p.b,
                b"outgoing",
                b"incoming",
                &mut verifier,
                &KEY,
                CONTEXT,
                |_| panic!("closed admission cannot complete")
            )
            .is_err());
    }
    let p = Pair::new();
    let root = MemberIdentity::new("synthetic-community").unwrap();
    let mut other = device(&root, &p.time, 10_000);
    let mut inbox = Inbox::new_accounted(&other).unwrap();
    assert!(inbox
        .stage_accounted_invitation(
            &mut other,
            &p.welcome,
            &[21; 32],
            contact_policy(),
            reservation_policy(),
            &KEY,
            CONTEXT,
            |_| panic!("wrong recipient")
        )
        .is_err());
}
