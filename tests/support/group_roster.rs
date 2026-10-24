//! The roster of a member room (row 14.8): the lineages of its members are read
//! and Charter-verified once and kept across operations, but they only certify
//! the MLS leaves of the room. A consent decision never uses them: it reads the
//! fresh per-operation cache. Whatever Threads refuses makes the owner forget.
use super::*;
use cbrd::Devices as _;
use cnbx::DeviceAuthority as _;
use ed25519_dalek::{Signer, SigningKey};

const COMMUNITY: &str = "alpha";

fn member(letter: &str) -> String {
    letter.repeat(96)
}

/// A lineage that names `device` (the root signature is not checked by the
/// ports under test: a lineage only reaches them after the Charter verified it).
fn lineage(member: &str, device: &SigningKey) -> ckmg::Lineage {
    ckmg::Lineage {
        version: 2,
        binding: ckmg::Binding::new(COMMUNITY, member).unwrap(),
        epoch: 1,
        revision: 1,
        root: ckmg::PublicKey::new(ckmg::VLD0, [1; 32]),
        identity: None,
        devices: vec![ckmg::PublicKey::new(
            ckmg::VLD0,
            device.verifying_key().to_bytes(),
        )],
        delegates: Vec::new(),
        signature: ckmg::Signature::new(ckmg::VLD0, [0; 64]),
    }
}

fn now() -> u64 {
    ckmg::Clock::now(&mut crate::door::custody::SystemClock).unwrap()
}

struct Scene {
    cache: Rc<RefCell<Cache>>,
    roster: Rc<RefCell<Roster>>,
    peer: ckmg::Lineage,
    device: SigningKey,
}

fn scene() -> Scene {
    let device = SigningKey::from_bytes(&[7; 32]);
    let peer = lineage(&member("p"), &device);
    let roster = Rc::new(RefCell::new(Roster::default()));
    roster
        .borrow_mut()
        .lineages
        .insert(member("p"), peer.clone());
    Scene {
        cache: Rc::new(RefCell::new(Cache::default())),
        roster,
        peer,
        device,
    }
}

fn devices(scene: &Scene, with_roster: bool) -> GroupDevices {
    GroupDevices {
        own: lineage(&member("o"), &SigningKey::from_bytes(&[9; 32])),
        cache: scene.cache.clone(),
        roster: with_roster.then(|| scene.roster.clone()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_roster_certifies_leaves_only_in_a_room_operation() {
    let scene = scene();
    let mut room = devices(&scene, true);
    let found = room.current(&scene.peer.binding).await.unwrap();
    assert_eq!(found.binding, scene.peer.binding);
    assert_eq!(found.devices, scene.peer.devices);
    // Outside a room operation (a hidden group's fork) only a fresh read counts.
    let mut hidden = devices(&scene, false);
    assert!(matches!(
        hidden.current(&scene.peer.binding).await,
        Err(cnbx::ContactError::Unavailable)
    ));
    // A lineage stored for another binding of the same member name is not served.
    let other = ckmg::Binding::new("beta", &member("p")).unwrap();
    assert!(matches!(
        room.current(&other).await,
        Err(cnbx::ContactError::Unavailable)
    ));
    // A member nobody read is unavailable.
    let stranger = ckmg::Binding::new(COMMUNITY, &member("s")).unwrap();
    assert!(matches!(
        room.current(&stranger).await,
        Err(cnbx::ContactError::Unavailable)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn a_fresh_read_wins_over_the_roster() {
    let scene = scene();
    // The member's lineage moved on: the fresh read names another device.
    let moved = lineage(&member("p"), &SigningKey::from_bytes(&[8; 32]));
    scene
        .cache
        .borrow_mut()
        .lineages
        .insert(member("p"), (moved.clone(), now()));
    let mut room = devices(&scene, true);
    let found = room.current(&scene.peer.binding).await.unwrap();
    assert_eq!(found.devices, moved.devices);
    assert_ne!(found.devices, scene.peer.devices);
}

#[test]
fn a_consent_decision_never_uses_the_roster() {
    let scene = scene();
    let message = b"consent statement";
    let signature = scene.device.sign(message).to_bytes();
    let key = scene.device.verifying_key().to_bytes();
    let judge = CacheDevices(scene.cache.clone());
    let verify = |at: u64| judge.verify(COMMUNITY, &member("p"), message, &signature, &key, at);
    // The roster holds the very lineage that signed, yet the decision needs a
    // read of its own.
    assert!(scene.roster.borrow().lineages.contains_key(&member("p")));
    assert!(matches!(verify(now()), Err(cgrp::Error::Authority)));
    // A fresh read decides ...
    scene
        .cache
        .borrow_mut()
        .lineages
        .insert(member("p"), (scene.peer.clone(), now()));
    verify(now()).unwrap();
    // ... and one that is no longer fresh does not.
    assert!(matches!(
        verify(now() + LINEAGE_FRESH_SECONDS + 1),
        Err(cgrp::Error::Authority)
    ));
}

#[test]
fn forgetting_drops_the_lineages_and_keeps_the_handles() {
    let scene = scene();
    scene
        .roster
        .borrow_mut()
        .handles
        .insert(member("p"), vec![1, 2, 3]);
    scene.roster.borrow_mut().forget();
    assert!(scene.roster.borrow().lineages.is_empty());
    assert_eq!(
        scene.roster.borrow().handles.get(&member("p")),
        Some(&vec![1, 2, 3])
    );
}
