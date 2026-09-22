mod common;
use cmsg::{
    verify_accounting_acknowledgment, verify_accounting_delegation, verify_accounting_receipt,
    AccountingAcknowledgment, AccountingDelegation, AccountingKey, AccountingReceipt,
    ContactResolutionKind, Error, Inbox,
};
use common::accounting::{Pair, CONTEXT, KEY, SCHEME};
use std::sync::atomic::Ordering;

fn copy<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    serde_json::from_slice(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn real_answer_and_original_sender_acknowledgment_bind_separate_authorities() {
    let mut p = Pair::pending();
    let wire = p.send_answer();
    let receipt =
        p.bi.accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
            .unwrap();
    verify_accounting_receipt(&receipt, &common::trust(), 100).unwrap();
    assert_eq!(receipt.signing_bytes().unwrap().len(), 357);
    assert!(
        p.ai.accounting_acknowledgment(p.br.member_id(), &p.a, &p.ak, &p.ad, &receipt)
            .is_err(),
        "receipt alone cannot acknowledge an MLS answer not received"
    );
    assert!(
        p.bi.accounting_acknowledgment(p.ar.member_id(), &p.b, &p.bk, &p.bd, &receipt)
            .is_err(),
        "recipient cannot supply original sender acknowledgment"
    );
    p.ai.receive_contact(&mut p.a, &wire, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let ack =
        p.ai.accounting_acknowledgment(p.br.member_id(), &p.a, &p.ak, &p.ad, &receipt)
            .unwrap();
    verify_accounting_acknowledgment(&ack, &common::trust(), 100).unwrap();
    assert_eq!(ack.signing_bytes().unwrap().len(), 255);
    let mut substituted: AccountingAcknowledgment = copy(&ack);
    substituted.delegation = p.bd.clone();
    assert!(verify_accounting_acknowledgment(&substituted, &common::trust(), 100).is_err());
    assert!(p
        .ai
        .accounting_receipt(p.br.member_id(), &p.a, &p.ak, &p.ad)
        .is_err());
    let saved = p.bi.snapshot(&p.b, &KEY, CONTEXT).unwrap();
    let (restored, member) =
        Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    let again = restored
        .accounting_receipt(p.ar.member_id(), &member, &p.bk, &p.bd)
        .unwrap();
    assert_eq!(receipt.digest().unwrap(), again.digest().unwrap());
}

#[test]
fn failed_answer_persistence_cannot_mint_recipient_evidence() {
    let mut p = Pair::pending();
    assert_eq!(
        p.bi.send_contact(&mut p.b, b"answer", &KEY, CONTEXT, |_, _| Err(
            Error::InvalidStore
        )),
        Err(Error::InvalidStore)
    );
    assert!(p
        .bi
        .accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
        .is_err());
    let wire = p.send_answer();
    p.ai.receive_contact(&mut p.a, &wire, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p
        .bi
        .accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
        .is_ok());
}

#[test]
fn every_context_substitution_breaks_actual_signature_and_delegation_binding() {
    let p = Pair::established();
    let receipt =
        p.bi.accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
            .unwrap();
    for field in 0..11 {
        let mut bad: AccountingReceipt = copy(&receipt);
        match field {
            0 => bad.resolution.introduction_id[0] ^= 1,
            1 => bad.contact.group_id[0] ^= 1,
            2 => bad.contact.policy.response_deadline += 1,
            3 => bad.contact.policy.max_intro_bytes += 1,
            4 => bad.contact.responder_history_tip[0] ^= 1,
            5 => bad.contact.peer_history_tip[0] ^= 1,
            6 => bad.contact.initiator_id = p.br.member_id().to_owned(),
            7 => bad.resolution.kind = ContactResolutionKind::ClosedForever,
            8 => bad.resolution.signature[0] ^= 1,
            9 => bad.delegation = p.ad.clone(),
            _ => bad.issued_at = 99,
        }
        assert!(
            verify_accounting_receipt(&bad, &common::trust(), 100).is_err(),
            "mutation {field}"
        );
    }
    for field in 0..5 {
        let mut bad: AccountingDelegation = copy(&p.bd);
        match field {
            0 => bad.state_secret_commitment.replace_range(..2, "03"),
            1 => bad.hash_scheme.push_str(".other"),
            2 => bad.authorization = p.ad.authorization.clone(),
            3 => bad.issued_at = 99,
            _ => bad.expires_at += 1,
        }
        assert!(verify_accounting_delegation(&bad, &common::trust(), 100).is_err());
    }
    assert!(verify_accounting_receipt(&receipt, &common::trust(), 10_000).is_err());
}

#[test]
fn recipient_close_does_not_need_expired_silent_peers_renewal() {
    let mut p = Pair::configured(200);
    p.send_intro();
    p.time.0.store(300, Ordering::Relaxed);
    p.bi.resolve_introduction(
        p.ar.member_id(),
        ContactResolutionKind::ClosedForever,
        &p.b,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    let receipt =
        p.bi.accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
            .unwrap();
    verify_accounting_receipt(&receipt, &common::trust(), 300).unwrap();
    assert_eq!(
        receipt.resolution.kind,
        ContactResolutionKind::ClosedForever
    );
    assert!(verify_accounting_delegation(&p.ad, &common::trust(), 300).is_err());
}

#[test]
fn accounting_key_recovery_is_pinned_to_root_public_key_and_context() {
    let p = Pair::pending();
    let public = p.bk.public_key();
    let sealed = p.bk.seal(&KEY, CONTEXT).unwrap();
    let restored = AccountingKey::restore(
        &sealed,
        &KEY,
        "synthetic-community",
        p.br.member_id(),
        &public,
        CONTEXT,
    )
    .unwrap();
    assert_eq!(public, restored.public_key());
    assert!(AccountingKey::restore(
        &sealed,
        &KEY,
        "synthetic-community",
        p.ar.member_id(),
        &public,
        CONTEXT
    )
    .is_err());
    assert!(AccountingKey::restore(
        &sealed,
        &KEY,
        "synthetic-community",
        p.br.member_id(),
        &p.ak.public_key(),
        CONTEXT
    )
    .is_err());
    assert!(AccountingKey::restore(
        &sealed,
        &KEY,
        "synthetic-community",
        p.br.member_id(),
        &public,
        b"other"
    )
    .is_err());
    assert!(p
        .a
        .delegate_accounting(&restored, SCHEME, &[2; 32], 10_000)
        .is_err());
}

#[test]
fn a_different_mls_group_cannot_be_substituted_for_the_journaled_introduction() {
    let p = Pair::established();
    let mut replacement = common::accounting::device(&p.br, &p.time, 10_000);
    replacement.create_group().unwrap();
    assert!(p
        .bi
        .prepare_accounting_contact(p.ar.member_id(), &replacement)
        .is_err());
    assert!(p
        .bi
        .prepare_accounting_receipt(p.ar.member_id(), &replacement, &p.bd)
        .is_err());
}

#[test]
fn high_s_malleation_is_rejected_even_though_it_is_an_ecdsa_signature() {
    let p = Pair::established();
    let mut receipt =
        p.bi.accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
            .unwrap();
    let order = data_encoding::HEXLOWER
        .decode(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        .unwrap();
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let value = order[index] as i16 - receipt.signature[32 + index] as i16 - borrow;
        receipt.signature[32 + index] = value.rem_euclid(256) as u8;
        borrow = i16::from(value < 0);
    }
    assert!(verify_accounting_receipt(&receipt, &common::trust(), 100).is_err());
}

#[test]
fn archived_receipt_and_ack_need_retained_delegation_anchors_after_expiry() {
    let p = Pair::established();
    let receipt =
        p.bi.accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
            .unwrap();
    let ack =
        p.ai.accounting_acknowledgment(p.br.member_id(), &p.a, &p.ak, &p.ad, &receipt)
            .unwrap();
    assert!(verify_accounting_receipt(&receipt, &common::trust(), 10_001).is_err());
    assert!(verify_accounting_acknowledgment(&ack, &common::trust(), 10_001).is_err());
    cmsg::verify_accounting_receipt_historical(
        &receipt,
        &common::trust(),
        &p.bd.digest().unwrap(),
        10_001,
    )
    .unwrap();
    cmsg::verify_accounting_acknowledgment_historical(
        &ack,
        &common::trust(),
        &p.bd.digest().unwrap(),
        &p.ad.digest().unwrap(),
        10_001,
    )
    .unwrap();
    assert!(cmsg::verify_accounting_receipt_historical(
        &receipt,
        &common::trust(),
        &p.ad.digest().unwrap(),
        10_001
    )
    .is_err());
    assert!(cmsg::verify_accounting_acknowledgment_historical(
        &ack,
        &common::trust(),
        &p.bd.digest().unwrap(),
        &[0; 32],
        10_001
    )
    .is_err());
    assert!(cmsg::verify_accounting_receipt_historical(
        &receipt,
        &common::trust(),
        &p.bd.digest().unwrap(),
        99
    )
    .is_err());
}

#[test]
fn valid_p256_signature_cannot_cover_a_forged_ed25519_decision_or_backdated_delegation() {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let p = Pair::established();
    let external = SigningKey::from_slice(&[7; 32]).unwrap();
    let public: [u8; 64] = external.verifying_key().to_encoded_point(false).as_bytes()[1..]
        .try_into()
        .unwrap();
    let delegation =
        p.b.delegate_accounting_public_key(&public, SCHEME, &[2; 32], 10_000)
            .unwrap();
    let receipt =
        p.bi.prepare_accounting_receipt(p.ar.member_id(), &p.b, &delegation)
            .unwrap();
    for mode in 0..2 {
        let mut bad: AccountingReceipt = copy(&receipt);
        if mode == 0 {
            bad.resolution.signature[0] ^= 1;
        } else {
            bad.issued_at = 99;
        }
        let signature: Signature = external.sign(&bad.signing_bytes().unwrap());
        bad.signature = signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .to_vec();
        assert!(verify_accounting_receipt(&bad, &common::trust(), 100).is_err());
    }
}

#[test]
fn named_account_request_signature_binds_exact_proof_statement_and_device_lifetime() {
    use data_encoding::BASE64URL_NOPAD as B64;
    let p = Pair::pending();
    let request =
        p.a.authorize_account_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 100, 200)
            .unwrap();
    let public: [u8; 32] = p.a.chat_public_key().try_into().unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&B64.decode(request.signature.as_bytes()).unwrap())
            .unwrap();
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
    verifier
        .verify_strict(&request.signing_bytes().unwrap(), &signature)
        .unwrap();
    let mut changed: cmsg::AccountRequestAuthorization = copy(&request);
    changed.proof_digest[0] ^= 1;
    assert!(verifier
        .verify_strict(&changed.signing_bytes().unwrap(), &signature)
        .is_err());
    assert!(p
        .a
        .authorize_account_request(&[0; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 100, 200)
        .is_err());
    assert!(p
        .a
        .authorize_account_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 101, 200)
        .is_err());
    assert!(p
        .a
        .authorize_account_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 100, 10_001)
        .is_err());
}

#[test]
fn account_status_signer_binds_owner_challenge_lookup_and_authority_lifetime() {
    use data_encoding::BASE64URL_NOPAD as B64;
    use sha2::{Digest, Sha256};
    let p = Pair::pending();
    let status =
        p.a.authorize_account_status(Some([7; 32]), &[8; 32], 100, 200)
            .unwrap();
    assert_eq!(B64.encode(&status.owner), p.a.member_id().unwrap());
    let community: [u8; 32] = Sha256::digest(common::trust().community_id.as_bytes()).into();
    assert_eq!(status.community, community);
    let public: [u8; 32] = p.a.chat_public_key().try_into().unwrap();
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&B64.decode(status.signature.as_bytes()).unwrap())
            .unwrap();
    verifier
        .verify_strict(&status.signing_bytes().unwrap(), &signature)
        .unwrap();
    for field in ["community", "owner", "challenge", "requestId", "expiresAt"] {
        let mut changed: cmsg::AccountStatusAuthorization = copy(&status);
        match field {
            "community" => changed.community[0] ^= 1,
            "owner" => changed.owner[0] ^= 1,
            "challenge" => changed.challenge[0] ^= 1,
            "requestId" => changed.request_id = None,
            "expiresAt" => changed.expires_at += 1,
            _ => unreachable!(),
        }
        assert!(verifier
            .verify_strict(&changed.signing_bytes().unwrap(), &signature)
            .is_err());
    }
    let latest =
        p.a.authorize_account_status(None, &[9; 32], 100, 200)
            .unwrap();
    assert!(latest.request_id.is_none());
    for (request, challenge, issued, expires) in [
        (Some([0; 32]), [8; 32], 100, 200),
        (None, [0; 32], 100, 200),
        (None, [8; 32], 101, 200),
        (None, [8; 32], 100, 100),
        (None, [8; 32], 100, 10_001),
        (None, [8; 32], 0, 200),
    ] {
        assert!(p
            .a
            .authorize_account_status(request, &challenge, issued, expires)
            .is_err());
    }
    let request =
        p.a.authorize_account_request(&[7; 32], &[8; 32], &[9; 32], &[10; 32], &[11; 32], 100, 200)
            .unwrap();
    assert!(verifier
        .verify_strict(&request.signing_bytes().unwrap(), &signature)
        .is_err());
}
