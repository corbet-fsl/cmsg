//! The group owner on the retained Vault of a real member: its consent is a
//! single-use device signature over exactly the statement Groups built, it
//! verifies only through the member's freshly read lineage, contacts come from
//! the Contacts journal and the pending desk survives in the encrypted Store.
use super::profile_owner_tests::{open_as, ProfileOwner};
use crate::door::board::CommittedOwner;
use cbrd::cgrp::Consent;
use std::collections::{BTreeMap, BTreeSet};

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
        key_package: vec![],
        lineage_handle: vec![],
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

struct Dead;
impl crate::door::inbox_lineage::HandleOpener for Dead {
    async fn read(
        &mut self,
        _: &ckmg::Binding,
        _: &[u8],
    ) -> std::result::Result<Vec<cvlt::LineageEvidence>, crate::door::inbox_lineage::PeerUnavailable>
    {
        Err(crate::door::inbox_lineage::PeerUnavailable)
    }
}
struct NoTrust;
impl crate::door::inbox_lineage::CharterView for NoTrust {
    fn with_current<T>(
        &mut self,
        _: &str,
        _: u64,
        _: impl FnOnce(&cchr::VerifiedCharter) -> std::result::Result<T, cnbx::ContactError>,
    ) -> std::result::Result<T, cnbx::ContactError> {
        Err(cnbx::ContactError::Unavailable)
    }
}

#[tokio::test]
async fn an_unreadable_or_untrusted_peer_has_no_lineage() {
    use super::super::group_custody::{GroupPeers, VerifiedPeers};
    let binding = ckmg::Binding::new("alpha", &member("c")).unwrap();
    let mut peers = VerifiedPeers::new(Dead, NoTrust, || Some(1_000));
    assert!(peers.lineage(&binding, b"handle").await.is_none());
}

/// A network with no reachable node: any use of it is `Unavailable`.
#[derive(Clone)]
struct DeadNetwork;
impl cdht::Network for DeadNetwork {
    fn now_ms(&self) -> u64 {
        0
    }
    async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn descriptor(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn get(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
        _: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn set(
        &self,
        _: &cdht::NodeId,
        _: &cdht::Descriptor,
        _: u32,
        _: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn watch(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
    ) -> Result<cdht::WatchId, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<(), cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn changes(
        &self,
        _: &cdht::NodeId,
        _: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}

#[tokio::test]
async fn the_production_composer_peers_fail_closed_without_charter_trust_or_network() {
    use crate::door::inbox_lineage::CharterView;
    let foyer = cfyr::Foyer::new(crate::door::foyer::fixture_transport(
        "http://127.0.0.1:1",
        "127.0.0.1",
    ));
    // A Foyer that never followed a Charter has no trust to inspect.
    let mut view = foyer.current_policy();
    assert_eq!(
        CharterView::with_current(&mut view, "alpha", 1_000, |_| Ok(())),
        Err(cnbx::ContactError::Unavailable)
    );
    let me = member("a");
    let peer = member("c");
    let (mut owner, _, _) = open_as(&me, true).await;
    owner
        .enable_verified_groups(DeadNetwork, foyer.current_policy())
        .unwrap();
    let groups = owner.groups().unwrap();
    let now = groups.now().unwrap();
    groups
        .refresh(
            &BTreeSet::from([peer.clone()]),
            &BTreeSet::from([peer.clone()]),
        )
        .await
        .unwrap();
    // The own consent is still verifiable through the own lineage only.
    let mut forged = consent(&peer, now);
    forged.signature = vec![0; 64];
    forged.authority = vec![1; 32];
    assert!(groups.authority().consent(&forged, now).is_err());
    // Once the Foyer is gone the view stays closed.
    drop(foyer);
    assert_eq!(
        CharterView::with_current(&mut view, "alpha", 1_000, |_| Ok(())),
        Err(cnbx::ContactError::Unavailable)
    );
}

#[tokio::test]
async fn a_key_package_is_made_by_the_real_threads_store_and_never_repeats() {
    let mut owner = owner("a", true).await;
    let groups = owner.groups().unwrap();
    let first = groups.key_package([1; 32], [2; 32]).await.unwrap();
    assert!(!first.is_empty());
    // A second package for the same group is a different one (fresh key).
    let second = groups.key_package([1; 32], [3; 32]).await;
    // Threads keeps one pending package per group slot: a second request for
    // the same slot is either fresh or refused, never a copy of the first.
    if let Ok(second) = second {
        assert_ne!(first, second);
    }
}

/// Serves one fixed lineage for any asked member, as a hostile or confused
/// locator target would.
struct Serves(ckmg::Lineage);
impl super::super::group_custody::GroupPeers for Serves {
    fn lineage<'a>(
        &'a mut self,
        _: &'a ckmg::Binding,
        _: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<ckmg::Lineage>> + 'a>> {
        let lineage = self.0.clone();
        Box::pin(async move { Some(lineage) })
    }
}

#[tokio::test]
async fn a_locator_for_a_co_member_yields_trust_only_for_that_exact_member() {
    use crate::door::board::CommittedOwner;
    let (mut other, _, _) = open_as(&member("c"), true).await;
    other.enable_groups(None).unwrap();
    let lineage_c = {
        let mut retained = other.retained.lock().await;
        retained
            .as_mut()
            .unwrap()
            .vault
            .keys()
            .lineage()
            .await
            .unwrap()
    };
    let (mut me, _, _) = open_as(&member("a"), true).await;
    me.enable_groups(Some(Box::new(Serves(lineage_c)))).unwrap();
    let theirs = other.groups().unwrap();
    let now = theirs.now().unwrap();
    let mut genuine = consent(&member("c"), now);
    let signed = theirs
        .sign_consent(
            &member("c"),
            &genuine.signing_bytes().unwrap(),
            genuine.valid_until,
        )
        .await
        .unwrap();
    genuine.signature = signed.signature;
    genuine.authority = signed.authority;
    // The same signature claimed for another member: its locator leads to
    // member c's lineage, which does not bind to that member.
    let mut claimed = genuine.clone();
    claimed.member = member("b");

    let groups = me.groups().unwrap();
    groups.provide_handles(BTreeMap::from([
        (member("b"), b"locator-b".to_vec()),
        (member("c"), b"locator-c".to_vec()),
    ]));
    groups
        .refresh(
            &BTreeSet::new(),
            &BTreeSet::from([member("b"), member("c")]),
        )
        .await
        .unwrap();
    assert_eq!(groups.authority().consent(&genuine, now), Ok(()));
    assert!(groups.authority().consent(&claimed, now).is_err());
}
