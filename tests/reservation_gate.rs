mod common;
use cmsg::{
    Error, ReservationContext, ReservationPolicy, ReservationVerifier, VerifiedReservation,
};
use common::accounting::{Pair, CONTEXT, KEY};
// Storage/authorization boundary test double; these tests do not prove ZK validity.
struct Verifier {
    bad_role: bool,
    local_current: bool,
}
impl ReservationVerifier for Verifier {
    fn verify_remote(
        &mut self,
        _: &[u8],
        c: &ReservationContext,
    ) -> Result<VerifiedReservation, Error> {
        let mut expected = c.expected.clone();
        if self.bad_role {
            expected.phase = 1;
        }
        Ok(VerifiedReservation {
            expected,
            state_policy_digest: [7; 32],
            state_version: 3,
            state_commitment: [8; 32],
            presentation_binding: [9; 32],
            owner_authority: [10; 32],
            valid_until: c.expected.expires_at,
        })
    }
    fn verify_current_local(
        &mut self,
        e: &[u8],
        c: &ReservationContext,
    ) -> Result<VerifiedReservation, Error> {
        if !self.local_current {
            return Err(Error::Admission);
        }
        self.verify_remote(e, c)
    }
}
fn configure(p: &mut Pair) {
    let policy = ReservationPolicy {
        state_policy_digest: [7; 32],
        opened_at: 100,
        abandon_after: 400,
    };
    let a =
        p.ai.require_active_reservations(&p.a, policy.clone(), &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    let b =
        p.bi.require_active_reservations(&p.b, policy, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    p.ai.set_own_reservation_challenge(&p.a, &b.outgoing.expected.challenge, &KEY, CONTEXT, |_| {
        Ok(())
    })
    .unwrap();
    p.bi.set_own_reservation_challenge(&p.b, &a.incoming.expected.challenge, &KEY, CONTEXT, |_| {
        Ok(())
    })
    .unwrap();
    assert_eq!(
        p.ai.reservation_contexts(&p.a).unwrap(),
        p.bi.reservation_contexts(&p.b).unwrap()
    );
}
#[test]
fn prepared_or_missing_local_state_or_unconsented_incoming_never_releases_payload() {
    let mut p = Pair::configured(10_000);
    configure(&mut p);
    let mut verifier = Verifier {
        bad_role: false,
        local_current: true,
    };
    assert!(p
        .ai
        .send_contact(&mut p.a, b"not active", &KEY, CONTEXT, |_, _| panic!(
            "no publication"
        ))
        .is_err());
    assert!(p
        .bi
        .bind_active_reservations(&p.b, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| panic!(
            "explicit consent required"
        ))
        .is_err());
    verifier.bad_role = true;
    assert!(p
        .bi
        .authorize_incoming_reservation(
            &p.b,
            b"prepared",
            &mut verifier,
            &KEY,
            CONTEXT,
            |_| panic!("Prepared is insufficient")
        )
        .is_err());
    verifier.bad_role = false;
    p.bi.authorize_incoming_reservation(&p.b, b"active", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    verifier.local_current = false;
    assert!(p
        .ai
        .bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| panic!(
            "own accepted state superseded"
        ))
        .is_err());
    verifier.local_current = true;
    assert!(p
        .ai
        .bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert!(p
        .ai
        .send_contact(&mut p.a, b"not committed", &KEY, CONTEXT, |_, _| panic!(
            "no publication"
        ))
        .is_err());
    p.ai.bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let intro =
        p.ai.send_contact(&mut p.a, b"protected", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(p
        .bi
        .receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| panic!(
            "recipient requires both Active"
        ))
        .is_err());
    p.bi.bind_active_reservations(&p.b, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p
        .ai
        .send_contact(&mut p.a, b"second intro", &KEY, CONTEXT, |_, _| panic!(
            "proof cannot reset quota"
        ))
        .is_err());
}
#[test]
fn restore_close_and_reopening_keep_old_proofs_from_reauthorizing_another_contact() {
    let mut p = Pair::configured(10_000);
    configure(&mut p);
    let mut v = Verifier {
        bad_role: false,
        local_current: true,
    };
    p.bi.authorize_incoming_reservation(&p.b, b"a", &mut v, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.ai.bind_active_reservations(&p.a, b"a", b"b", &mut v, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let sealed = p.ai.snapshot(&p.a, &KEY, CONTEXT).unwrap();
    let (ai, a) = cmsg::Inbox::restore_with_clock(&sealed, &KEY, CONTEXT, p.time.clone()).unwrap();
    p.ai = ai;
    p.a = a;
    assert!(p
        .ai
        .send_contact(&mut p.a, b"restored proof", &KEY, CONTEXT, |_, _| panic!(
            "reverify current local slot"
        ))
        .is_err());
    let close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p
        .ai
        .bind_active_reservations(&p.a, b"a", b"b", &mut v, &KEY, CONTEXT, |_| panic!(
            "closed context"
        ))
        .is_err());
    let fresh =
        p.bi.initiate_contact(
            &mut p.b,
            &[95; 32],
            cmsg::FirstContactPolicy {
                response_deadline: 1000,
                max_intro_bytes: 128,
            },
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.ai.receive_contact(&mut p.a, &fresh, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p.ai.reservation_contexts(&p.a).is_err());
    assert!(p
        .bi
        .send_contact(&mut p.b, b"fresh but unpaid", &KEY, CONTEXT, |_, _| panic!(
            "new nonce needs new matched reservations"
        ))
        .is_err());
}
#[test]
fn pending_accounted_contact_is_bound_to_one_recipient_device_and_roster() {
    let mut p = Pair::configured(10_000);
    configure(&mut p);
    let mut sibling = common::accounting::device(&p.br, &p.time, 10_000);
    let incoming = p.bi.export_contact_sync(&p.b).unwrap();
    let mut sibling_inbox = cmsg::Inbox::new_accounted(&sibling).unwrap();
    sibling_inbox
        .merge_contact_sync(&incoming, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut v = Verifier {
        bad_role: false,
        local_current: true,
    };
    assert!(sibling_inbox
        .bind_active_reservations(&sibling, b"a", b"b", &mut v, &KEY, CONTEXT, |_| panic!(
            "sibling cannot become designated recipient"
        ))
        .is_err());
    let mut staged = cmsg::Member::restore_with_clock(
        &p.a.snapshot(&KEY, CONTEXT).unwrap(),
        &KEY,
        CONTEXT,
        p.time.clone(),
    )
    .unwrap();
    staged.add(&sibling.key_package().unwrap()).unwrap();
    assert!(
        p.ai.check_group(&staged).is_err(),
        "pending first payload roster cannot expand"
    );
    p.bi.authorize_incoming_reservation(&p.b, b"a", &mut v, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.ai.bind_active_reservations(&p.a, b"a", b"b", &mut v, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.bi.bind_active_reservations(&p.b, b"a", b"b", &mut v, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.send_intro();
    let answer = p.send_answer();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        p.ai.check_group(&staged).is_ok(),
        "established roster may add independent devices"
    );
}
#[test]
fn remote_verification_precedes_refreshed_own_check_and_expired_verdicts_never_publish() {
    struct Sequenced {
        time: std::sync::Arc<common::accounting::Time>,
        calls: Vec<(&'static str, u64)>,
        advance: u64,
        remote_until: u64,
    }
    impl ReservationVerifier for Sequenced {
        fn verify_remote(
            &mut self,
            _: &[u8],
            c: &ReservationContext,
        ) -> Result<VerifiedReservation, Error> {
            self.calls.push(("remote", c.now));
            self.time
                .0
                .store(self.advance, std::sync::atomic::Ordering::Relaxed);
            let mut value = Verifier {
                bad_role: false,
                local_current: true,
            }
            .verify_remote(b"", c)?;
            value.valid_until = self.remote_until;
            Ok(value)
        }
        fn verify_current_local(
            &mut self,
            _: &[u8],
            c: &ReservationContext,
        ) -> Result<VerifiedReservation, Error> {
            self.calls.push(("local", c.now));
            Verifier {
                bad_role: false,
                local_current: true,
            }
            .verify_remote(b"", c)
        }
    }
    for recipient in [false, true] {
        let mut p = Pair::configured(10_000);
        configure(&mut p);
        if recipient {
            p.bi.authorize_incoming_reservation(
                &p.b,
                b"a",
                &mut Verifier {
                    bad_role: false,
                    local_current: true,
                },
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap();
        }
        let mut verifier = Sequenced {
            time: p.time.clone(),
            calls: vec![],
            advance: 101,
            remote_until: 150,
        };
        let (inbox, member) = if recipient {
            (&mut p.bi, &p.b)
        } else {
            (&mut p.ai, &p.a)
        };
        inbox
            .bind_active_reservations(member, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        assert_eq!(verifier.calls, vec![("remote", 100), ("local", 101)]);
        assert_eq!(
            inbox.reservation_contexts(member).unwrap().outgoing.now,
            101
        );
    }
    let mut p = Pair::configured(10_000);
    configure(&mut p);
    let mut verifier = Sequenced {
        time: p.time.clone(),
        calls: vec![],
        advance: 150,
        remote_until: 150,
    };
    assert!(p
        .ai
        .bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| panic!(
            "expired proof must not publish"
        ))
        .is_err());
    assert_eq!(verifier.calls, vec![("remote", 100), ("local", 150)]);
    assert!(p
        .ai
        .send_contact(&mut p.a, b"expired", &KEY, CONTEXT, |_, _| panic!(
            "no release"
        ))
        .is_err());
    let mut p = Pair::configured(10_000);
    configure(&mut p);
    let mut verifier = Sequenced {
        time: p.time.clone(),
        calls: vec![],
        advance: 101,
        remote_until: 150,
    };
    p.ai.bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.time.0.store(150, std::sync::atomic::Ordering::Relaxed);
    assert!(p
        .ai
        .send_contact(&mut p.a, b"later expiry", &KEY, CONTEXT, |_, _| panic!(
            "release rechecks verifier expiry independently of lease"
        ))
        .is_err());
}

#[test]
fn original_reservation_expiry_and_capacity_release_never_restart_the_contact() {
    for recipient_closed in [false, true] {
        let mut p = Pair::configured(10_000);
        configure(&mut p); // The immutable reservation deadline is 100 + 400.
        let mut verifier = Verifier {
            bad_role: false,
            local_current: true,
        };
        p.bi.authorize_incoming_reservation(&p.b, b"a", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        p.ai.bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        p.bi.bind_active_reservations(&p.b, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        let queued =
            p.ai.send_contact(&mut p.a, b"original introduction", &KEY, CONTEXT, |_, _| {
                Ok(())
            })
            .unwrap();
        if recipient_closed {
            p.bi.receive_contact(&mut p.b, &queued, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
            let close =
                p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
                    .unwrap();
            p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
        }
        p.time.0.store(500, std::sync::atomic::Ordering::Relaxed);
        // The embedding invalidates its gate after an external capacity release.
        // This tests cmsg's journal boundary, not an accounting refund proof.
        p.ai.invalidate_reservation(&p.a, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        let sealed = p.ai.snapshot(&p.a, &KEY, CONTEXT).unwrap();
        let (inbox, member) =
            cmsg::Inbox::restore_with_clock(&sealed, &KEY, CONTEXT, p.time.clone()).unwrap();
        p.ai = inbox;
        p.a = member;
        assert_eq!(p.ai.is_closed(p.br.member_id()), recipient_closed);
        assert_eq!(
            p.ai.awaiting_peer_resolution(p.br.member_id()),
            !recipient_closed
        );
        assert!(p
            .ai
            .bind_active_reservations(&p.a, b"a", b"b", &mut verifier, &KEY, CONTEXT, |_| panic!(
                "old Active evidence cannot restart its deadline"
            ),)
            .is_err());
        assert!(p
            .ai
            .require_active_reservations(
                &p.a,
                ReservationPolicy {
                    state_policy_digest: [7; 32],
                    opened_at: 500,
                    abandon_after: 400,
                },
                &KEY,
                CONTEXT,
                |_| panic!("same introduction cannot get a later deadline"),
            )
            .is_err());
        assert!(p
            .ai
            .begin_first_contact(
                p.br.member_id(),
                &[96; 32],
                cmsg::FirstContactRole::Initiator,
                cmsg::FirstContactPolicy {
                    response_deadline: 1000,
                    max_intro_bytes: 128
                },
                &p.a,
                &KEY,
                CONTEXT,
                |_| panic!("capacity release is not a new turn"),
            )
            .is_err());
        assert!(p
            .ai
            .initiate_contact(
                &mut p.a,
                &[96; 32],
                cmsg::FirstContactPolicy {
                    response_deadline: 1000,
                    max_intro_bytes: 128
                },
                &KEY,
                CONTEXT,
                |_, _| panic!("sender cannot override silence or recipient block"),
            )
            .is_err());
        assert!(p
            .bi
            .receive_contact(&mut p.b, &queued, &KEY, CONTEXT, |_| panic!(
                "queued old data cannot arrive after its reservation deadline"
            ),)
            .is_err());
    }
}

#[test]
fn waiting_default_changes_apply_only_to_new_gates_and_expiry_is_verified() {
    let mut p = Pair::configured(10_000);
    configure(&mut p);
    let original = p.ai.reservation_contexts(&p.a).unwrap();
    assert_eq!(original.outgoing.expected.expires_at, 500);
    assert_eq!(original.incoming.expected.expires_at, 500);
    let prospective = ReservationPolicy {
        state_policy_digest: [7; 32],
        opened_at: 100,
        abandon_after: 200,
    };
    assert!(p
        .ai
        .require_active_reservations(&p.a, prospective.clone(), &KEY, CONTEXT, |_| panic!(
            "waiting default cannot shorten an existing lease"
        ),)
        .is_err());
    let sealed = p.ai.snapshot(&p.a, &KEY, CONTEXT).unwrap();
    let (restored, member) =
        cmsg::Inbox::restore_with_clock(&sealed, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert_eq!(restored.reservation_contexts(&member).unwrap(), original);
    let mut next = Pair::configured(10_000);
    let future = next
        .ai
        .require_active_reservations(&next.a, prospective, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(future.outgoing.expected.expires_at, 300);

    struct WrongExpiry;
    impl ReservationVerifier for WrongExpiry {
        fn verify_remote(
            &mut self,
            e: &[u8],
            c: &ReservationContext,
        ) -> Result<VerifiedReservation, Error> {
            let mut value = Verifier {
                bad_role: false,
                local_current: true,
            }
            .verify_remote(e, c)?;
            value.expected.expires_at += 1;
            Ok(value)
        }
        fn verify_current_local(
            &mut self,
            e: &[u8],
            c: &ReservationContext,
        ) -> Result<VerifiedReservation, Error> {
            self.verify_remote(e, c)
        }
    }
    assert!(p
        .bi
        .authorize_incoming_reservation(
            &p.b,
            b"changed expiry",
            &mut WrongExpiry,
            &KEY,
            CONTEXT,
            |_| panic!("a different authenticated expiry cannot authorize incoming capacity"),
        )
        .is_err());
}
