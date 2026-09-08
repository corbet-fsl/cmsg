use cmsg::{Member, Received, MAX_WIRE_BYTES};
use cmsg_first_contact_release_experiment::{
    Context, Error, OperatorTrust, Peer, PendingRelease, RecipientRedemption, ReleasedMaterial,
    SenderCommit,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};

#[path = "../../../tests/common/mod.rs"]
mod common;

fn context() -> Context {
    Context {
        community_id: common::trust().community_id,
        policy_digest: common::trust().policy_digest,
        cohort_id: "synthetic-cohort-1".into(),
        not_before: 100,
        expires_at: 200,
    }
}

fn peer(member: &Member) -> Peer {
    Peer {
        member_id: member.member_id().unwrap(),
        chat_public_key: B64.encode(&member.chat_public_key()),
    }
}

// Synthetic operator signatures prove only the client's verification boundary.
// They are not outputs of the current cfrm ledger or evidence of real debits.
fn trust() -> OperatorTrust {
    OperatorTrust {
        sender_commit_key: SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        recipient_redemption_key: SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
    }
}

fn sign_sender(value: &mut SenderCommit) {
    value.signature = B64.encode(
        &SigningKey::from_bytes(&[31; 32])
            .sign(&value.signing_bytes())
            .to_bytes(),
    );
}

fn sign_recipient(value: &mut RecipientRedemption) {
    value.signature = B64.encode(
        &SigningKey::from_bytes(&[32; 32])
            .sign(&value.signing_bytes())
            .to_bytes(),
    );
}

fn attest(pending: &mut PendingRelease) -> (SenderCommit, RecipientRedemption) {
    let preflight = pending.preflight();
    let mut sender = pending.bind_request(&B64.encode(&[55; 32])).unwrap();
    sign_sender(&mut sender);
    let mut recipient = RecipientRedemption {
        context: preflight.context,
        recipient: preflight.recipient,
        release_nonce: preflight.release_nonce,
        signature: String::new(),
    };
    sign_recipient(&mut recipient);
    (sender, recipient)
}

fn exchange() -> (Member, Member, PendingRelease, ReleasedMaterial) {
    let mut sender = common::member();
    let recipient = common::member();
    sender.create_group().unwrap();
    let invite = sender.add(&recipient.key_package().unwrap()).unwrap();
    let material = ReleasedMaterial {
        welcome: invite.welcome,
        first_ciphertext: sender.send(b"private first text").unwrap(),
    };
    let pending = PendingRelease::prepare(
        context(),
        peer(&sender),
        peer(&recipient),
        material.clone(),
        100,
    )
    .unwrap();
    (sender, recipient, pending, material)
}

fn assert_text(member: &mut Member, wire: &[u8], expected: &str) {
    match member.receive(wire).unwrap() {
        Received::Text(text) => assert_eq!(text.text, expected),
        _ => panic!("expected authenticated text"),
    }
}

#[test]
fn modified_recipient_lacks_the_mls_join_input_until_both_attestations() {
    let (_, mut recipient, mut pending, material) = exchange();
    // Even disclosing the ciphertext alone does not supply the withheld Welcome.
    assert!(recipient.receive(&material.first_ciphertext).is_err());
    assert!(recipient.join(&[]).is_err());
    let (sender_commit, mut redemption) = attest(&mut pending);
    redemption.signature.clear();
    assert!(pending
        .release(&sender_commit, &redemption, &trust(), 100)
        .is_err());
    assert!(recipient.receive(&material.first_ciphertext).is_err());
    sign_recipient(&mut redemption);
    let released = pending
        .release(&sender_commit, &redemption, &trust(), 100)
        .unwrap();
    recipient.join(&released.welcome).unwrap();
    assert_text(
        &mut recipient,
        &released.first_ciphertext,
        "private first text",
    );
}

#[test]
fn release_retries_recover_exact_material_without_another_action() {
    let (_, _, mut pending, original) = exchange();
    let (sender_commit, redemption) = attest(&mut pending);
    let first = pending
        .release(&sender_commit, &redemption, &trust(), 100)
        .unwrap();
    let retry = pending
        .release(&sender_commit, &redemption, &trust(), 101)
        .unwrap();
    assert!(first == original && retry == original);
    assert!(pending.bind_request(&B64.encode(&[56; 32])).is_err());
}

#[test]
fn independent_sender_commit_is_required_even_with_valid_receive_attestation() {
    let (_, _, mut pending, _) = exchange();
    let (mut sender_commit, redemption) = attest(&mut pending);
    sender_commit.signature.clear();
    assert!(pending
        .release(&sender_commit, &redemption, &trust(), 100)
        .is_err());
    sign_sender(&mut sender_commit);
    assert!(pending
        .release(&sender_commit, &redemption, &trust(), 100)
        .is_ok());
}

#[test]
fn separately_signed_sender_substitutions_do_not_match_the_pending_authorization() {
    let (_, _, mut pending, _) = exchange();
    let (valid, redemption) = attest(&mut pending);
    for field in 0..8 {
        let mut changed = valid.clone();
        match field {
            0 => changed.context.community_id.push('x'),
            1 => changed.context.policy_digest = B64.encode(&[5; 32]),
            2 => changed.context.cohort_id.push('x'),
            3 => changed.sender.member_id = B64.encode(&[6; 32]),
            4 => changed.sender.chat_public_key = B64.encode(&[7; 32]),
            5 => changed.authorization_nonce = B64.encode(&[8; 32]),
            6 => changed.blinded_request_hash = B64.encode(&[9; 32]),
            _ => changed.context.expires_at += 1,
        }
        sign_sender(&mut changed);
        assert!(pending
            .release(&changed, &redemption, &trust(), 100)
            .is_err());
    }
    assert!(pending.release(&valid, &redemption, &trust(), 100).is_ok());
}

#[test]
fn separately_signed_recipient_substitutions_cannot_unlock_another_counterpart() {
    let (_, _, mut pending, _) = exchange();
    let (sender, valid) = attest(&mut pending);
    for field in 0..8 {
        let mut changed = valid.clone();
        match field {
            0 => changed.context.community_id.push('x'),
            1 => changed.context.policy_digest = B64.encode(&[5; 32]),
            2 => changed.context.cohort_id.push('x'),
            3 => changed.recipient.member_id = B64.encode(&[6; 32]),
            4 => changed.recipient.chat_public_key = B64.encode(&[7; 32]),
            5 => changed.release_nonce = B64.encode(&[8; 32]),
            6 => changed.context.not_before -= 1,
            _ => changed.context.expires_at += 1,
        }
        sign_recipient(&mut changed);
        assert!(pending.release(&sender, &changed, &trust(), 100).is_err());
    }
    assert!(pending.release(&sender, &valid, &trust(), 100).is_ok());
}

#[test]
fn purpose_separation_rejects_wrong_keys_wrong_domains_and_signature_tampering() {
    let (_, _, mut pending, _) = exchange();
    let (sender, recipient) = attest(&mut pending);
    let mut bad = recipient.clone();
    bad.signature = sender.signature.clone();
    assert!(pending.release(&sender, &bad, &trust(), 100).is_err());
    bad.signature = B64.encode(
        &SigningKey::from_bytes(&[31; 32])
            .sign(&bad.signing_bytes())
            .to_bytes(),
    );
    assert!(pending.release(&sender, &bad, &trust(), 100).is_err());
    let mut wrong_domain: serde_json::Value = serde_json::from_slice(&bad.signing_bytes()).unwrap();
    wrong_domain[0] = "cfrm.directional.redeem.v1".into();
    bad.signature = B64.encode(
        &SigningKey::from_bytes(&[32; 32])
            .sign(&serde_json::to_vec(&wrong_domain).unwrap())
            .to_bytes(),
    );
    assert!(pending.release(&sender, &bad, &trust(), 100).is_err());
    let mut bytes = B64.decode(recipient.signature.as_bytes()).unwrap();
    bytes[0] ^= 1;
    bad.signature = B64.encode(&bytes);
    assert!(pending.release(&sender, &bad, &trust(), 100).is_err());
    let wrong_trust = OperatorTrust {
        recipient_redemption_key: trust().sender_commit_key,
        ..trust()
    };
    assert!(pending
        .release(&sender, &recipient, &wrong_trust, 100)
        .is_err());
    assert!(pending.release(&sender, &recipient, &trust(), 100).is_ok());
}

#[test]
fn release_attestations_cannot_be_replayed_into_another_pending_invitation() {
    let (sender, recipient, mut first, material) = exchange();
    let mut second =
        PendingRelease::prepare(context(), peer(&sender), peer(&recipient), material, 100).unwrap();
    let (s1, r1) = attest(&mut first);
    let (s2, r2) = attest(&mut second);
    assert_ne!(r1.release_nonce, r2.release_nonce);
    assert_ne!(s1.authorization_nonce, s2.authorization_nonce);
    assert!(second.release(&s1, &r1, &trust(), 100).is_err());
    assert!(second.release(&s2, &r1, &trust(), 100).is_err());
    assert!(second.release(&s2, &r2, &trust(), 100).is_ok());
}

#[test]
fn not_before_and_expiry_bound_even_previously_successful_releases() {
    let (_, _, mut pending, _) = exchange();
    let (sender, recipient) = attest(&mut pending);
    assert!(matches!(
        pending.release(&sender, &recipient, &trust(), 99),
        Err(Error::Expired)
    ));
    assert!(pending.release(&sender, &recipient, &trust(), 100).is_ok());
    assert!(pending.release(&sender, &recipient, &trust(), 199).is_ok());
    assert!(matches!(
        pending.release(&sender, &recipient, &trust(), 200),
        Err(Error::Expired)
    ));
}

#[test]
fn declined_preflight_releases_nothing_and_needs_no_operator_call() {
    let (_, _, mut pending, _) = exchange();
    pending.decline();
    assert!(pending.bind_request(&B64.encode(&[55; 32])).is_err());
    let restored =
        PendingRelease::restore(&pending.seal(&[9; 32]).unwrap(), &[9; 32], &context()).unwrap();
    assert!(restored.preflight().recipient.member_id.len() == 43);
    // No attestation fixture, ledger or network callback was invoked to decline.
}

#[test]
fn encrypted_pending_restore_preserves_nonce_binding_and_exact_release_material() {
    let (_, mut recipient, mut pending, original) = exchange();
    let (sender, redemption) = attest(&mut pending);
    let encoded = pending.seal(&[11; 32]).unwrap();
    assert!(!encoded
        .windows(redemption.recipient.member_id.len())
        .any(|p| p == redemption.recipient.member_id.as_bytes()));
    assert!(!encoded
        .windows(original.welcome.len())
        .any(|p| p == original.welcome.as_slice()));
    drop(pending);
    let mut restored = PendingRelease::restore(&encoded, &[11; 32], &context()).unwrap();
    assert_eq!(restored.preflight().release_nonce, redemption.release_nonce);
    let released = restored
        .release(&sender, &redemption, &trust(), 100)
        .unwrap();
    assert!(released == original);
    recipient.join(&released.welcome).unwrap();
    assert_text(
        &mut recipient,
        &released.first_ciphertext,
        "private first text",
    );
    let again = restored.seal(&[11; 32]).unwrap();
    let mut restarted = PendingRelease::restore(&again, &[11; 32], &context()).unwrap();
    assert!(
        restarted
            .release(&sender, &redemption, &trust(), 101)
            .unwrap()
            == original
    );
}

#[test]
fn encrypted_restore_rejects_wrong_key_context_tampering_and_oversize() {
    let (_, _, pending, _) = exchange();
    let sealed = pending.seal(&[12; 32]).unwrap();
    assert!(PendingRelease::restore(&sealed, &[13; 32], &context()).is_err());
    let mut other = context();
    other.community_id.push('x');
    assert!(PendingRelease::restore(&sealed, &[12; 32], &other).is_err());
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(PendingRelease::restore(&tampered, &[12; 32], &context()).is_err());
    assert!(PendingRelease::restore(&vec![0; 9 * MAX_WIRE_BYTES], &[12; 32], &context()).is_err());
    assert!(PendingRelease::restore(&sealed, &[12; 32], &context()).is_ok());
}

#[test]
fn operator_statements_have_no_explicit_pair_or_shared_nonce_join() {
    let (_, _, mut pending, _) = exchange();
    let (sender, recipient) = attest(&mut pending);
    let s = String::from_utf8(sender.signing_bytes()).unwrap();
    let r = String::from_utf8(recipient.signing_bytes()).unwrap();
    assert!(!s.contains(&recipient.recipient.member_id));
    assert!(!s.contains(&recipient.recipient.chat_public_key));
    assert!(!s.contains(&recipient.release_nonce));
    assert!(!r.contains(&sender.sender.member_id));
    assert!(!r.contains(&sender.sender.chat_public_key));
    assert!(!r.contains(&sender.authorization_nonce));
    assert!(!r.contains(&sender.blinded_request_hash));
    assert!(pending.release(&sender, &recipient, &trust(), 100).is_ok());
}

#[test]
fn ordinary_conversation_replies_need_no_additional_release_attestation() {
    let (mut sender, mut recipient, mut pending, _) = exchange();
    let (s, r) = attest(&mut pending);
    let released = pending.release(&s, &r, &trust(), 100).unwrap();
    recipient.join(&released.welcome).unwrap();
    assert_text(
        &mut recipient,
        &released.first_ciphertext,
        "private first text",
    );
    let reply = recipient.send(b"ordinary reply").unwrap();
    assert_text(&mut sender, &reply, "ordinary reply");
    let next = sender.send(b"continuation").unwrap();
    assert_text(&mut recipient, &next, "continuation");
    // No second attestation or permit operation is part of this ordinary exchange.
}

#[test]
fn operator_attestation_does_not_force_a_dishonest_sender_to_deliver() {
    let (_, mut recipient, mut pending, material) = exchange();
    let (_sender_commit, _committed_receive) = attest(&mut pending);
    // Synthetic attestations represent counters having committed. The sender can
    // still discard its state rather than release; this is deliberately allowed.
    drop(pending);
    assert!(recipient.receive(&material.first_ciphertext).is_err());
    assert!(recipient.history().is_empty());
}

#[test]
fn hundred_member_group_requires_recipient_bindings_but_welcome_sharing_bypasses_them() {
    let mut sender = common::member();
    sender.create_group().unwrap();
    let mut members: Vec<Member> = (0..99).map(|_| common::member()).collect();
    let packages: Vec<Vec<u8>> = members.iter().map(|m| m.key_package().unwrap()).collect();
    let invitation = sender.add_many(&packages).unwrap();
    let material = ReleasedMaterial {
        welcome: invitation.welcome,
        first_ciphertext: sender.send(b"group first text").unwrap(),
    };
    let mut one = PendingRelease::prepare(
        context(),
        peer(&sender),
        peer(&members[0]),
        material.clone(),
        100,
    )
    .unwrap();
    let mut two =
        PendingRelease::prepare(context(), peer(&sender), peer(&members[1]), material, 100)
            .unwrap();
    let (s1, r1) = attest(&mut one);
    let (s2, _r2) = attest(&mut two);
    assert!(two.release(&s2, &r1, &trust(), 100).is_err());
    let shared = one.release(&s1, &r1, &trust(), 100).unwrap();
    members[0].join(&shared.welcome).unwrap();
    assert_text(
        &mut members[0],
        &shared.first_ciphertext,
        "group first text",
    );
    // The same multi-recipient Welcome contains the second member's encrypted
    // group secrets too. A cooperating first member can forward it around a gate.
    members[1].join(&shared.welcome).unwrap();
    assert_text(
        &mut members[1],
        &shared.first_ciphertext,
        "group first text",
    );
    assert_eq!(members[1].participants().unwrap().len(), 100);
}
