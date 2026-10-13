//! The group owner on the retained Vault of a real member: its consent is a
//! single-use device signature over exactly the statement Groups built, it
//! verifies only through the member's freshly read lineage, contacts come from
//! the Contacts journal and the pending desk survives in the encrypted Store.
use super::profile_owner_tests::{open_as, ProfileOwner};
use crate::door::board::CommittedOwner;
use cbrd::cgrp::Consent;
use std::collections::BTreeSet;

fn member(byte: &str) -> String {
    byte.repeat(48)
}

fn consent(member: &str, now: u64) -> Consent {
    Consent {
        community: "alpha".into(),
        member: member.into(),
        operation: [7; 32],
        policy_epoch: 1,
        command_digest: [9; 32],
        profile_visibility: false,
        valid_until: now + 600,
        signature: vec![],
        authority: vec![],
    }
}

async fn owner(byte: &str, with_intent: bool) -> ProfileOwner {
    let (mut owner, _, _) = open_as(&member(byte), with_intent).await;
    owner.enable_groups(None).unwrap();
    owner
}

#[tokio::test]
async fn a_consent_is_signed_for_the_exact_statement_and_verifies_through_the_own_lineage() {
    let me = member("a");
    let mut owner = owner("a", true).await;
    let groups = owner.groups().unwrap();
    let now = groups.now().unwrap();
    groups
        .refresh(&BTreeSet::new(), &BTreeSet::from([me.clone()]))
        .await
        .unwrap();
    let mut consent = consent(&me, now);
    let signed = groups
        .sign_consent(&me, &consent.signing_bytes().unwrap(), consent.valid_until)
        .await
        .unwrap();
    consent.signature = signed.signature;
    consent.authority = signed.authority;
    assert_eq!(groups.authority().consent(&consent, now), Ok(()));
    // Any change of the signed statement, or of whose consent it is, fails.
    let mut other_command = consent.clone();
    other_command.command_digest = [8; 32];
    assert!(groups.authority().consent(&other_command, now).is_err());
    let mut other_member = consent.clone();
    other_member.member = member("b");
    assert!(groups.authority().consent(&other_member, now).is_err());
    // A consent expires with its window.
    assert!(groups
        .authority()
        .consent(&consent, consent.valid_until)
        .is_err());
}

#[tokio::test]
async fn this_device_never_signs_for_another_member_and_needs_its_own_admission() {
    let me = member("a");
    let mut owner = owner("a", true).await;
    let groups = owner.groups().unwrap();
    let now = groups.now().unwrap();
    let stranger = consent(&member("b"), now);
    assert!(groups
        .sign_consent(
            &stranger.member,
            &stranger.signing_bytes().unwrap(),
            stranger.valid_until
        )
        .await
        .is_err());
    // Without the Door's intent channel nothing can be signed at all.
    let mut bare = self::owner("a", false).await;
    let groups = bare.groups().unwrap();
    let own = consent(&me, now);
    assert!(groups
        .sign_consent(&me, &own.signing_bytes().unwrap(), own.valid_until)
        .await
        .is_err());
}

#[tokio::test]
async fn an_unknown_member_is_no_contact_and_no_lineage_means_no_verification() {
    let me = member("a");
    let peer = member("c");
    let mut owner = owner("a", true).await;
    let groups = owner.groups().unwrap();
    let now = groups.now().unwrap();
    groups
        .refresh(
            &BTreeSet::from([peer.clone()]),
            &BTreeSet::from([peer.clone()]),
        )
        .await
        .unwrap();
    assert!(groups
        .authority()
        .contact("alpha", &me, &peer, now)
        .is_err());
    // Other members' contacts are no evidence this device holds.
    assert!(groups
        .authority()
        .contact("alpha", &peer, &me, now)
        .is_err());
    // Standing rooms are refused until the Rulebook evidence exists.
    assert!(groups.authority().seed("alpha", &[1; 32], now).is_err());
    // A peer whose lineage could not be read cannot have consented.
    let mut forged = consent(&peer, now);
    forged.signature = vec![0; 64];
    forged.authority = vec![1; 32];
    assert!(groups.authority().consent(&forged, now).is_err());
}

#[tokio::test]
async fn the_desk_and_the_checkpoint_live_in_the_encrypted_store() {
    let mut owner = owner("a", true).await;
    let groups = owner.groups().unwrap();
    assert_eq!(groups.desk_load().await, Ok(None));
    let empty = groups.snapshot().await.unwrap();
    assert_eq!(empty.community(), "alpha");
    groups
        .desk_save(b"{\"proposals\":[],\"invitations\":[]}")
        .await
        .unwrap();
    assert_eq!(
        groups.desk_load().await.unwrap().as_deref(),
        Some(&b"{\"proposals\":[],\"invitations\":[]}"[..])
    );
    // The desk write moved the Store; the checkpoint is read fresh each time.
    assert_eq!(groups.snapshot().await.unwrap().revision(), 0);
}
