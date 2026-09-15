mod common;
use cmsg::{Inbox, Member, MemberIdentity, Received};

const KEY: [u8; 32] = [53; 32];
const CONTEXT: &[u8] = b"synthetic-device-sync";

fn device(identity: &MemberIdentity) -> Member {
    let mut member = Member::new().unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = identity.member_id().to_owned();
    common::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            common::trust(),
            identity.authorize_device(&key, 1, 9_000_000_000).unwrap(),
            100,
        )
        .unwrap();
    member
}

#[test]
fn independently_keyed_sibling_catches_up_from_peer_held_control_and_ciphertexts() {
    let owner = MemberIdentity::new("synthetic-community").unwrap();
    let peer = MemberIdentity::new("synthetic-community").unwrap();
    let mut phone = device(&owner);
    let mut laptop = device(&owner);
    let mut remote = device(&peer);
    assert_ne!(phone.chat_public_key(), laptop.chat_public_key());
    assert_eq!(phone.member_id().unwrap(), laptop.member_id().unwrap());
    phone.create_group().unwrap();
    laptop
        .join(&phone.add(&laptop.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    // Laptop is now offline. Its sibling retains exact MLS control and payload
    // bytes for direct retransmission; no MLS state or secret key is cloned.
    let addition = phone.add(&remote.key_package().unwrap()).unwrap();
    remote.join(&addition.welcome).unwrap();
    let first = phone.send_bytes(b"peer-held catch-up record").unwrap();
    let second = remote.send(b"missed while disconnected").unwrap();
    assert!(laptop.receive(&first).is_err());
    assert!(matches!(
        laptop.receive(&addition.commit).unwrap(),
        Received::MembershipChanged
    ));
    assert!(
        matches!(laptop.receive(&first).unwrap(), Received::Bytes(message)
        if message.member_id == owner.member_id() && message.bytes == b"peer-held catch-up record")
    );
    assert!(
        matches!(laptop.receive(&second).unwrap(), Received::Text(message)
        if message.member_id == peer.member_id() && message.text == "missed while disconnected")
    );
    assert!(laptop.receive(&addition.commit).is_err());
    assert!(laptop.receive(&first).is_err());
    assert!(laptop.receive(&second).is_err());
    let response = laptop
        .send(b"same member, independent send ratchet")
        .unwrap();
    assert!(
        matches!(phone.receive(&response).unwrap(), Received::Text(message) if message.member_id == owner.member_id())
    );
    assert!(
        matches!(remote.receive(&response).unwrap(), Received::Text(message) if message.member_id == owner.member_id())
    );
}

#[test]
fn issuer_alone_cannot_substitute_a_device_or_downgrade_a_root_bound_group() {
    let identity = MemberIdentity::new("synthetic-community").unwrap();
    let legitimate = device(&identity);
    let key = legitimate.chat_public_key();
    let mut forged = Member::new().unwrap();
    let mut grant = common::grant(&forged.chat_public_key(), 1);
    grant.member_id = identity.member_id().to_owned();
    common::sign(&mut grant);
    assert!(forged
        .bind_device_admission(
            grant.clone(),
            common::trust(),
            identity.authorize_device(&key, 1, 9_000_000_000).unwrap(),
            100
        )
        .is_err());
    forged.bind_admission(grant, common::trust(), 100).unwrap();
    let mut owner = legitimate;
    owner.create_group().unwrap();
    assert!(
        owner.add(&forged.key_package().unwrap()).is_err(),
        "legacy issuer-only leaf must not enter a root-bound group"
    );
    let sibling = device(&identity);
    assert!(owner.add(&sibling.key_package().unwrap()).is_ok());
}

#[test]
fn permanent_closures_sync_only_from_root_authorized_sibling_devices_and_merge_monotonically() {
    let owner = MemberIdentity::new("synthetic-community").unwrap();
    let outsider = MemberIdentity::new("synthetic-community").unwrap();
    let peer = MemberIdentity::new("synthetic-community").unwrap();
    let phone = device(&owner);
    let laptop = device(&owner);
    let unrelated = device(&outsider);
    let mut phone_inbox = Inbox::new(&phone).unwrap();
    let mut laptop_inbox = Inbox::new(&laptop).unwrap();
    let stale = phone_inbox.export_contact_sync(&phone).unwrap();
    phone_inbox
        .close_forever(peer.member_id(), &phone, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let closed = phone_inbox.export_contact_sync(&phone).unwrap();
    let mut saved = Vec::new();
    laptop_inbox
        .merge_contact_sync(&closed, &laptop, &KEY, CONTEXT, |state| {
            saved = state.to_vec();
            Ok(())
        })
        .unwrap();
    assert!(laptop_inbox.is_closed(peer.member_id()));
    laptop_inbox
        .merge_contact_sync(&stale, &laptop, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        laptop_inbox.is_closed(peer.member_id()),
        "stale signed state cannot reopen"
    );
    let (restored, _) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert!(restored.is_closed(peer.member_id()));
    let mut unauthorized = Inbox::new(&unrelated).unwrap();
    assert!(unauthorized
        .merge_contact_sync(&closed, &unrelated, &KEY, CONTEXT, |_| panic!(
            "other identity cannot import policy"
        ))
        .is_err());
    let mut changed: serde_json::Value = serde_json::from_slice(&closed).unwrap();
    changed["closed"] = serde_json::json!([outsider.member_id()]);
    assert!(laptop_inbox
        .merge_contact_sync(
            &serde_json::to_vec(&changed).unwrap(),
            &laptop,
            &KEY,
            CONTEXT,
            |_| panic!("tampering must not persist")
        )
        .is_err());
    assert!(!laptop_inbox.is_closed(outsider.member_id()));
}

#[test]
fn authentic_old_device_stores_need_a_current_peer_or_external_freshness_anchor() {
    let owner = MemberIdentity::new("synthetic-community").unwrap();
    let peer = MemberIdentity::new("synthetic-community").unwrap();
    let member = device(&owner);
    let mut inbox = Inbox::new(&member).unwrap();
    let mut before = Vec::new();
    inbox
        .set_blocked(peer.member_id(), false, &member, &KEY, CONTEXT, |state| {
            before = state.to_vec();
            Ok(())
        })
        .unwrap();
    inbox
        .close_forever(peer.member_id(), &member, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let (mut rolled_back, restored_member) = Inbox::restore(&before, &KEY, CONTEXT).unwrap();
    assert!(
        !rolled_back.is_closed(peer.member_id()),
        "authenticated encryption alone cannot detect old valid storage"
    );
    rolled_back
        .merge_contact_sync(
            &inbox.export_contact_sync(&member).unwrap(),
            &restored_member,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    assert!(rolled_back.is_closed(peer.member_id()));
}

#[test]
fn introduction_decisions_sync_without_reopening_or_replacing_the_shared_nonce() {
    let owner = MemberIdentity::new("synthetic-community").unwrap();
    let peer = MemberIdentity::new("synthetic-community").unwrap();
    let phone = device(&owner);
    let laptop = device(&owner);
    let mut phone_inbox = Inbox::new(&phone).unwrap();
    let mut laptop_inbox = Inbox::new(&laptop).unwrap();
    let nonce = [77; 32];
    phone_inbox
        .begin_introduction(peer.member_id(), &nonce, &phone, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let pending = phone_inbox.export_contact_sync(&phone).unwrap();
    laptop_inbox
        .merge_contact_sync(&pending, &laptop, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(laptop_inbox.needs_resolution(peer.member_id()));
    assert!(laptop_inbox
        .begin_introduction(
            peer.member_id(),
            &[78; 32],
            &laptop,
            &KEY,
            CONTEXT,
            |_| panic!("sibling cannot replace first introduction")
        )
        .is_err());
    phone_inbox
        .resolve_introduction(
            peer.member_id(),
            cmsg::ContactResolutionKind::Answered,
            &phone,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    let resolved = phone_inbox.export_contact_sync(&phone).unwrap();
    laptop_inbox
        .merge_contact_sync(&resolved, &laptop, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    laptop_inbox
        .merge_contact_sync(&pending, &laptop, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        !laptop_inbox.needs_resolution(peer.member_id()),
        "stale signed journal cannot reset resolution"
    );
    let mut issuer_only = Member::new().unwrap();
    let mut forged = common::grant(&issuer_only.chat_public_key(), 1);
    forged.member_id = owner.member_id().to_owned();
    common::sign(&mut forged);
    issuer_only
        .bind_admission(forged, common::trust(), 100)
        .unwrap();
    assert!(laptop_inbox
        .close_forever(peer.member_id(), &issuer_only, &KEY, CONTEXT, |_| panic!(
            "secure inbox cannot downgrade owner authentication"
        ))
        .is_err());
}
