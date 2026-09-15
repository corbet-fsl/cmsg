use cfrm::allocation::{policy_digest, AllocationLedger, AllocationPolicy};
use cfrm::board::{BoardLimits, MeetingBoard, PresenceUpdate};
use cmsg::{AdmissionGrant, AdmissionTrust, DeviceAuthorization, Member, MemberIdentity};
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use ed25519_dalek::{Signer, SigningKey};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::sync::Arc;

const NOW: u64 = 1_000;
struct TestClock;
impl cmsg::Clock for TestClock {
    fn now(&self) -> Result<u64, cmsg::Error> {
        Ok(NOW)
    }
}

fn wire<T: DeserializeOwned>(value: &impl Serialize) -> T {
    serde_json::from_slice(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn trust() -> AdmissionTrust {
    AdmissionTrust {
        community_id: "composition-test".into(),
        policy_digest: BASE64URL_NOPAD.encode(&[42; 32]),
        issuer_public_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes(),
    }
}

fn board_trust() -> cfrm::admission::AdmissionTrust {
    let pinned = trust();
    cfrm::admission::AdmissionTrust {
        community_id: pinned.community_id,
        policy_digest: pinned.policy_digest,
        issuer_public_key: pinned.issuer_public_key,
    }
}

fn sign_grant(grant: &mut AdmissionGrant) {
    let statement = serde_json::to_vec(&serde_json::json!([
        "cvld.admission.v1",
        grant.issuer_key_id,
        grant.community_id,
        grant.member_id,
        grant.chat_public_key,
        grant.policy_digest,
        grant.issued_at,
        grant.expires_at,
    ]))
    .unwrap();
    grant.signature = BASE64URL_NOPAD.encode(
        &SigningKey::from_bytes(&[17; 32])
            .sign(&statement)
            .to_bytes(),
    );
}

fn device(identity: &MemberIdentity) -> (Member, AdmissionGrant, DeviceAuthorization) {
    let configured = trust();
    let mut member = Member::new_with_clock(Arc::new(TestClock)).unwrap();
    let authorization = identity
        .authorize_device(&member.chat_public_key(), 900, 2_000)
        .unwrap();
    let mut grant = AdmissionGrant {
        version: 1,
        issuer_key_id: BASE64URL_NOPAD.encode(&Sha256::digest(configured.issuer_public_key)),
        community_id: configured.community_id.clone(),
        member_id: identity.member_id().into(),
        chat_public_key: BASE64URL_NOPAD.encode(&member.chat_public_key()),
        policy_digest: configured.policy_digest.clone(),
        issued_at: 900,
        expires_at: 2_000,
        signature: String::new(),
    };
    sign_grant(&mut grant);
    member
        .bind_device_admission(grant.clone(), configured, authorization.clone(), NOW)
        .unwrap();
    (member, grant, authorization)
}

fn endpoint() -> cmsg::OnionEndpoint {
    let key = [51; 32];
    let mut checksum = Sha3_256::new();
    checksum.update(b".onion checksum");
    checksum.update(key);
    checksum.update([3]);
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&checksum.finalize()[..2]);
    bytes.push(3);
    let host = format!("{}.onion", BASE32_NOPAD.encode(&bytes).to_ascii_lowercase());
    cmsg::OnionEndpoint::parse(&host, 443).unwrap()
}

fn policy() -> AllocationPolicy {
    AllocationPolicy {
        initial_credits: 1,
        periodic_credits: 1,
        period_seconds: 100,
        credit_cap: 1,
        max_authorization_seconds: 60,
        max_request_bytes: 416,
    }
}

#[test]
fn actual_cmsg_device_statements_form_one_independently_verifiable_public_member() {
    let identity = MemberIdentity::new("composition-test").unwrap();
    let (first, first_grant, first_auth) = device(&identity);
    let (second, second_grant, second_auth) = device(&identity);
    assert_ne!(first.chat_public_key(), second.chat_public_key());
    let configured = board_trust();
    let mut board = MeetingBoard::new(
        configured,
        BoardLimits {
            max_members: 10,
            max_devices_per_member: 2,
            max_lease_seconds: 60,
            max_replay_entries: 20,
        },
    )
    .unwrap();
    let first_update: PresenceUpdate =
        wire(&first.sign_presence(Some(&endpoint()), 1, 1_050).unwrap());
    board
        .apply(&wire(&first_grant), &wire(&first_auth), &first_update, NOW)
        .unwrap();
    board
        .apply(
            &wire(&second_grant),
            &wire(&second_auth),
            &wire(&second.sign_presence(Some(&endpoint()), 1, 1_050).unwrap()),
            NOW,
        )
        .unwrap();
    let snapshot = board.snapshot(NOW).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].member_id, identity.member_id());
    assert_eq!(snapshot[0].devices.len(), 2);
    for row in &snapshot[0].devices {
        cfrm::board::verify_presence(
            &row.admission,
            &row.authorization,
            &row.update,
            &board_trust(),
            60,
            NOW,
        )
        .unwrap();
    }
    let mut attacker_edit = first_update.clone();
    attacker_edit.endpoint.as_mut().unwrap().port = 80;
    assert_eq!(
        board.apply(&wire(&first_grant), &wire(&first_auth), &attacker_edit, NOW),
        Err(cfrm::Error::Signature)
    );
    assert_eq!(snapshot, board.snapshot(NOW).unwrap());

    // Even the genuine eligibility issuer cannot add its own key to Alice.
    let evil_root = MemberIdentity::new("composition-test").unwrap();
    let (evil_device, mut evil_grant, evil_auth) = device(&evil_root);
    evil_grant.member_id = identity.member_id().into();
    sign_grant(&mut evil_grant);
    assert_eq!(
        board.apply(
            &wire(&evil_grant),
            &wire(&evil_auth),
            &wire(
                &evil_device
                    .sign_presence(Some(&endpoint()), 1, 1_050)
                    .unwrap()
            ),
            NOW
        ),
        Err(cfrm::Error::Admission)
    );
}

#[test]
fn device_count_and_exact_retries_cannot_multiply_a_members_allowance() {
    let identity = MemberIdentity::new("composition-test").unwrap();
    let (first, first_grant, first_auth) = device(&identity);
    let (second, second_grant, second_auth) = device(&identity);
    let path = tempfile::tempdir().unwrap();
    let database = path.path().join("allocations.sqlite");
    let policy = policy();
    let policy_id = policy_digest(&policy).unwrap();
    // A reservation is not a token. Actual blind signing is checked separately.
    let request = wire(
        &first
            .authorize_allocation(&policy_id, &[1; 32], &[2; 416], 1_050)
            .unwrap(),
    );
    let mut ledger = AllocationLedger::open(&database, board_trust(), policy.clone()).unwrap();
    let reserved = ledger
        .reserve(&wire(&first_grant), &wire(&first_auth), &request, || NOW)
        .unwrap();
    assert_eq!(reserved.remaining_credits, 0);
    drop(ledger);
    let mut ledger = AllocationLedger::open(&database, board_trust(), policy).unwrap();
    assert_eq!(
        ledger
            .reserve(&wire(&first_grant), &wire(&first_auth), &request, || NOW)
            .unwrap(),
        reserved
    );
    let other_request = wire(
        &second
            .authorize_allocation(&policy_id, &[3; 32], &[4; 416], 1_050)
            .unwrap(),
    );
    assert_eq!(
        ledger.reserve(
            &wire(&second_grant),
            &wire(&second_auth),
            &other_request,
            || NOW
        ),
        Err(cfrm::Error::NoAllowance)
    );
    assert_eq!(
        ledger.resolve_private(b"unverified-answer-proof"),
        Err(cfrm::Error::UnsupportedCapability)
    );
}

#[test]
fn typed_board_signers_refuse_legacy_identity_and_expired_authorizations() {
    let identity = MemberIdentity::new("composition-test").unwrap();
    let (member, mut grant, _) = device(&identity);
    assert!(member.sign_presence(Some(&endpoint()), 0, 1_050).is_err());
    assert!(member.sign_presence(Some(&endpoint()), 1, NOW).is_err());
    assert!(member.sign_presence(Some(&endpoint()), 1, 2_001).is_err());
    assert!(member
        .authorize_allocation(
            &policy_digest(&policy()).unwrap(),
            &[1; 32],
            &[2; 415],
            1_050
        )
        .is_err());
    let mut legacy = Member::new_with_clock(Arc::new(TestClock)).unwrap();
    grant.chat_public_key = BASE64URL_NOPAD.encode(&legacy.chat_public_key());
    sign_grant(&mut grant);
    legacy.bind_admission(grant, trust(), NOW).unwrap();
    assert!(legacy.sign_presence(Some(&endpoint()), 1, 1_050).is_err());
    assert!(legacy
        .authorize_allocation(
            &policy_digest(&policy()).unwrap(),
            &[1; 32],
            &[2; 416],
            1_050
        )
        .is_err());
}

#[test]
fn actual_blind_permits_gate_initial_and_replacement_groups_without_reuse() {
    use cfrm::permit_issuer::{PermitIssuer, PermitRedeemer};
    use cfrm::permits::{PermitEpoch, PreparedPermit, RecipientClaim};
    use cmsg::{Acceptance, FirstContactPolicy, FirstContactRole, Inbox, Received, Redemption};
    use openssl::rsa::Rsa;
    use std::cell::RefCell;

    let alice_identity = MemberIdentity::new("composition-test").unwrap();
    let bob_identity = MemberIdentity::new("composition-test").unwrap();
    let (mut alice, alice_grant, alice_auth) = device(&alice_identity);
    let (mut bob, _, _) = device(&bob_identity);
    let stamp_key = SigningKey::from_bytes(&[71; 32]);
    let rsa = Rsa::generate(3072).unwrap();
    let epoch = PermitEpoch {
        community_id: "composition-test".into(),
        epoch_id: "shared-test-epoch".into(),
        valid_from: 900,
        issue_until: 1_200,
        expires_at: 1_300,
        public_key_der: BASE64URL_NOPAD.encode(&rsa.public_key_to_der().unwrap()),
        redemption_public_key: BASE64URL_NOPAD.encode(&stamp_key.verifying_key().to_bytes()),
    };
    let issuer = PermitIssuer::from_pkcs1_der(&epoch, &rsa.private_key_to_der().unwrap()).unwrap();
    let prepared = PreparedPermit::new(&epoch, NOW).unwrap();
    let request = wire(
        &alice
            .authorize_allocation(
                &policy_digest(&policy()).unwrap(),
                &[19; 32],
                &prepared.issuance_request(),
                1_050,
            )
            .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let mut ledger = AllocationLedger::open(
        directory.path().join("allowances.sqlite"),
        board_trust(),
        policy(),
    )
    .unwrap();
    let issued = issuer
        .issue(
            &mut ledger,
            &wire(&alice_grant),
            &wire(&alice_auth),
            &request,
            || NOW,
        )
        .unwrap();
    let permit = prepared.finalize(&issued.blind_signature, NOW).unwrap();
    let mut redeemer =
        PermitRedeemer::open(directory.path().join("spent.sqlite"), &epoch, stamp_key).unwrap();

    alice.create_group().unwrap();
    let invitation = alice.add(&bob.key_package().unwrap()).unwrap();
    let inviter = bob.invitation_sender(&invitation.welcome).unwrap();
    assert_eq!(inviter, alice_identity.member_id());
    let claim = RecipientClaim::new(
        &epoch,
        permit.clone(),
        &inviter,
        &bob.member_id().unwrap(),
        [23; 32],
        [24; 32],
        NOW,
    )
    .unwrap();
    let mut bob_inbox = Inbox::new(&bob).unwrap();
    let mut alice_inbox = Inbox::new(&alice).unwrap();
    let storage_key = [31; 32];
    let context = b"composition-inbox";
    let contact_policy = FirstContactPolicy {
        response_deadline: 1_100,
        max_intro_bytes: 1024,
    };
    alice_inbox
        .begin_first_contact(
            bob_identity.member_id(),
            &[23; 32],
            FirstContactRole::Initiator,
            contact_policy.clone(),
            &alice,
            &storage_key,
            context,
            |_| Ok(()),
        )
        .unwrap();
    bob_inbox
        .begin_first_contact(
            alice_identity.member_id(),
            &[23; 32],
            FirstContactRole::Recipient,
            contact_policy,
            &bob,
            &storage_key,
            context,
            |_| Ok(()),
        )
        .unwrap();
    let mut saved_bob = Vec::new();
    let ordering = RefCell::new(Vec::new());
    assert_eq!(
        bob_inbox
            .accept(
                &mut bob,
                &invitation.welcome,
                Some(&serde_json::to_vec(&claim).unwrap()),
                &storage_key,
                context,
                |checkpoint| {
                    saved_bob = checkpoint.to_vec();
                    ordering.borrow_mut().push("durable");
                    Ok(())
                },
                |local_claim| {
                    assert_eq!(ordering.borrow().as_slice(), ["durable"]);
                    let claim: RecipientClaim = serde_json::from_slice(local_claim).unwrap();
                    assert_eq!(claim.binding.sender_id, inviter);
                    assert_eq!(claim.binding.recipient_id, bob_identity.member_id());
                    // Only the anonymous request crosses the operator boundary.
                    let transmitted = serde_json::to_string(&claim.request).unwrap();
                    assert!(!transmitted.contains(&inviter));
                    assert!(!transmitted.contains(bob_identity.member_id()));
                    let stamp = redeemer
                        .redeem(&serde_json::from_str(&transmitted).unwrap(), || NOW)
                        .unwrap();
                    claim.verify_stamp(&epoch, &stamp, NOW).unwrap();
                    ordering.borrow_mut().push("redeemed");
                    Redemption::Accepted
                }
            )
            .unwrap(),
        Acceptance::Joined
    );
    assert_eq!(
        ordering.borrow().as_slice(),
        ["durable", "redeemed", "durable"]
    );
    let (mut bob_inbox, mut bob) =
        Inbox::restore_with_clock(&saved_bob, &storage_key, context, Arc::new(TestClock)).unwrap();
    assert!(bob_inbox.is_known(alice_identity.member_id()));
    let ciphertext = alice_inbox
        .send_contact_bytes(
            &mut alice,
            b"synthetic first contact",
            &storage_key,
            context,
            |_, _| Ok(()),
        )
        .unwrap();
    match bob_inbox
        .receive_contact(&mut bob, &ciphertext, &storage_key, context, |_| Ok(()))
        .unwrap()
    {
        Received::Bytes(message) => assert_eq!(message.bytes, b"synthetic first contact"),
        _ => panic!("expected authenticated opaque payload"),
    }
    assert!(alice_inbox
        .send_contact_bytes(
            &mut alice,
            b"repeat before answer",
            &storage_key,
            context,
            |_, _| panic!("repeated introduction must not persist")
        )
        .is_err());
    let malicious_repeat = alice
        .send_bytes(b"sender bypassed its local policy")
        .unwrap();
    assert!(bob_inbox
        .receive_contact(
            &mut bob,
            &malicious_repeat,
            &storage_key,
            context,
            |_| panic!("recipient must reject repeated introduction")
        )
        .is_err());
    let answer = bob_inbox
        .send_contact_bytes(&mut bob, b"actual answer", &storage_key, context, |_, _| {
            Ok(())
        })
        .unwrap();
    alice_inbox
        .receive_contact(&mut alice, &answer, &storage_key, context, |_| Ok(()))
        .unwrap();
    assert!(!alice_inbox.awaiting_peer_resolution(bob_identity.member_id()));

    let charlie_identity = MemberIdentity::new("composition-test").unwrap();
    let (mut charlie, _, _) = device(&charlie_identity);
    let (mut another_alice, _, _) = device(&alice_identity);
    another_alice.create_group().unwrap();
    let invitation = another_alice.add(&charlie.key_package().unwrap()).unwrap();
    let inviter = charlie.invitation_sender(&invitation.welcome).unwrap();
    let stolen = RecipientClaim::new(
        &epoch,
        permit,
        &inviter,
        &charlie.member_id().unwrap(),
        [25; 32],
        [26; 32],
        NOW,
    )
    .unwrap();
    let mut charlie_inbox = Inbox::new(&charlie).unwrap();
    assert_eq!(
        charlie_inbox
            .accept(
                &mut charlie,
                &invitation.welcome,
                Some(&serde_json::to_vec(&stolen).unwrap()),
                &storage_key,
                context,
                |_| Ok(()),
                |local_claim| {
                    let claim: RecipientClaim = serde_json::from_slice(local_claim).unwrap();
                    assert_eq!(
                        redeemer.redeem(&claim.request, || NOW),
                        Err(cfrm::Error::Replay)
                    );
                    Redemption::Rejected
                }
            )
            .unwrap(),
        Acceptance::Rejected
    );
    assert!(!charlie_inbox.is_known(alice_identity.member_id()));
    assert!(charlie.send_bytes(b"not admitted").is_err());

    // The original recipient owns the block and initiates a replacement after
    // group loss. Admission binds the nonce authenticated inside the new group.
    let close = bob_inbox
        .close_contact(&mut bob, &storage_key, context, |_, _| Ok(()))
        .unwrap();
    alice_inbox
        .receive_contact(&mut alice, &close, &storage_key, context, |_| Ok(()))
        .unwrap();
    let (mut recovered_bob, recovered_grant, recovered_auth) = device(&bob_identity);
    let (mut recovered_alice, _, _) = device(&alice_identity);
    let recovered_key_package = recovered_alice.key_package().unwrap();
    let reopening = bob_inbox
        .initiate_replacement(
            &mut recovered_bob,
            &recovered_key_package,
            &[27; 32],
            FirstContactPolicy {
                response_deadline: 1_100,
                max_intro_bytes: 1024,
            },
            &storage_key,
            context,
            |_, _| Ok(()),
        )
        .unwrap();
    let preview = alice_inbox
        .preview_replacement(&recovered_alice, &reopening.welcome, &reopening.control)
        .unwrap();
    assert_eq!(preview.inviter, bob_identity.member_id());
    assert_eq!(preview.introduction_id, [27; 32]);
    assert!(!preview.group_id.is_empty());
    assert_eq!(
        alice_inbox
            .accept_replacement(
                &mut recovered_alice,
                &reopening.welcome,
                &reopening.control,
                None,
                &storage_key,
                context,
                |_| panic!("missing permit must not persist"),
                |_| panic!("missing permit must not redeem"),
            )
            .unwrap(),
        Acceptance::NeedsPermit
    );

    let prepared = PreparedPermit::new(&epoch, NOW).unwrap();
    let request = wire(
        &recovered_bob
            .authorize_allocation(
                &policy_digest(&policy()).unwrap(),
                &[29; 32],
                &prepared.issuance_request(),
                1_050,
            )
            .unwrap(),
    );
    let issued = issuer
        .issue(
            &mut ledger,
            &wire(&recovered_grant),
            &wire(&recovered_auth),
            &request,
            || NOW,
        )
        .unwrap();
    let replacement_permit = prepared.finalize(&issued.blind_signature, NOW).unwrap();
    let replacement_claim = RecipientClaim::new(
        &epoch,
        replacement_permit,
        &preview.inviter,
        alice_identity.member_id(),
        preview.introduction_id,
        [28; 32],
        NOW,
    )
    .unwrap();
    ordering.borrow_mut().clear();
    assert_eq!(
        alice_inbox
            .accept_replacement(
                &mut recovered_alice,
                &reopening.welcome,
                &reopening.control,
                Some(&serde_json::to_vec(&replacement_claim).unwrap()),
                &storage_key,
                context,
                |_| {
                    ordering.borrow_mut().push("durable");
                    Ok(())
                },
                |local_claim| {
                    assert_eq!(ordering.borrow().as_slice(), ["durable"]);
                    let claim: RecipientClaim = serde_json::from_slice(local_claim).unwrap();
                    assert_eq!(claim.binding.sender_id, preview.inviter);
                    assert_eq!(claim.binding.recipient_id, alice_identity.member_id());
                    assert_eq!(
                        claim.binding.introduction_id,
                        BASE64URL_NOPAD.encode(&preview.introduction_id)
                    );
                    let transmitted = serde_json::to_string(&claim.request).unwrap();
                    assert!(!transmitted.contains(&preview.inviter));
                    assert!(!transmitted.contains(alice_identity.member_id()));
                    let stamp = redeemer
                        .redeem(&serde_json::from_str(&transmitted).unwrap(), || NOW)
                        .unwrap();
                    claim.verify_stamp(&epoch, &stamp, NOW).unwrap();
                    ordering.borrow_mut().push("redeemed");
                    Redemption::Accepted
                },
            )
            .unwrap(),
        Acceptance::Joined
    );
    assert_eq!(
        ordering.borrow().as_slice(),
        ["durable", "redeemed", "durable"]
    );
    assert!(alice_inbox
        .receive_contact(
            &mut recovered_alice,
            &ciphertext,
            &storage_key,
            context,
            |_| panic!("old group ciphertext cannot revive")
        )
        .is_err());
    let new_intro = bob_inbox
        .send_contact_bytes(
            &mut recovered_bob,
            b"new admitted introduction",
            &storage_key,
            context,
            |_, _| Ok(()),
        )
        .unwrap();
    alice_inbox
        .receive_contact(
            &mut recovered_alice,
            &new_intro,
            &storage_key,
            context,
            |_| Ok(()),
        )
        .unwrap();
    let new_answer = alice_inbox
        .send_contact_bytes(
            &mut recovered_alice,
            b"answer in the replacement group",
            &storage_key,
            context,
            |_, _| Ok(()),
        )
        .unwrap();
    bob_inbox
        .receive_contact(
            &mut recovered_bob,
            &new_answer,
            &storage_key,
            context,
            |_| Ok(()),
        )
        .unwrap();
}
