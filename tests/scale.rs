mod common;
use cmsg::{Member, Received};
use std::time::Instant;

#[test]
fn hundred_members_exchange_rekey_and_exclude_a_removed_member() {
    let start = Instant::now();
    let mut owner = common::member();
    owner.create_group().unwrap();
    let mut peers: Vec<Member> = (0..99).map(|_| common::member()).collect();
    let packages: Vec<Vec<u8>> = peers.iter().map(|p| p.key_package().unwrap()).collect();
    let invitation = owner.add_many(&packages).expect("bulk group invitation");
    for peer in &mut peers {
        peer.join(&invitation.welcome).unwrap();
    }
    let setup_ms = start.elapsed().as_millis();
    let start = Instant::now();
    let wire = owner.send(b"one hundred synthetic participants").unwrap();
    for peer in &mut peers {
        assert!(
            matches!(peer.receive(&wire).unwrap(), Received::Text(t) if t.text == "one hundred synthetic participants")
        );
    }
    let fanout_ms = start.elapsed().as_millis();
    let start = Instant::now();
    let commit = owner.remove(50).unwrap();
    for peer in &mut peers {
        let _ = peer.receive(&commit);
    }
    let wire = owner.send(b"remaining members only").unwrap();
    for (index, peer) in peers.iter_mut().enumerate() {
        if index == 49 {
            assert!(peer.receive(&wire).is_err());
        } else {
            assert!(
                matches!(peer.receive(&wire).unwrap(), Received::Text(t) if t.text == "remaining members only")
            );
        }
    }
    let rekey_fanout_ms = start.elapsed().as_millis();
    let peak = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let peak = peak
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap_or("VmHWM: unavailable");
    println!("members=100 setup_ms={setup_ms} fanout_ms={fanout_ms} rekey_fanout_ms={rekey_fanout_ms} {peak}");
}
