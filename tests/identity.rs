use cmsg::{member_id_for_root, verify_device_authorization, MemberIdentity};
use ed25519_dalek::SigningKey;

fn device(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

#[test]
fn member_root_authorizes_independent_devices_without_changing_identity() {
    let identity = MemberIdentity::new("community-a").unwrap();
    for key in [device(1), device(2)] {
        let certificate = identity.authorize_device(&key, 100, 200).unwrap();
        verify_device_authorization(&certificate, "community-a", identity.member_id(), &key, 150)
            .unwrap();
    }
    assert_ne!(
        identity.member_id(),
        member_id_for_root("community-b", &identity.public_key()).unwrap()
    );
}

#[test]
fn another_root_cannot_authorize_a_device_under_the_original_identity() {
    let identity = MemberIdentity::new("community-a").unwrap();
    let attacker = MemberIdentity::new("community-a").unwrap();
    let key = device(3);
    let mut forged = attacker.authorize_device(&key, 100, 200).unwrap();
    forged.member_id = identity.member_id().into();
    assert!(
        verify_device_authorization(&forged, "community-a", identity.member_id(), &key, 150)
            .is_err()
    );
    forged.root_public_key = data_encoding::BASE64URL_NOPAD.encode(&identity.public_key());
    assert!(
        verify_device_authorization(&forged, "community-a", identity.member_id(), &key, 150)
            .is_err()
    );
}

#[test]
fn certificate_is_bound_to_device_community_and_exact_lifetime() {
    let identity = MemberIdentity::new("community-a").unwrap();
    let key = device(4);
    let certificate = identity.authorize_device(&key, 100, 200).unwrap();
    assert!(verify_device_authorization(
        &certificate,
        "community-a",
        identity.member_id(),
        &key,
        99
    )
    .is_err());
    assert!(verify_device_authorization(
        &certificate,
        "community-a",
        identity.member_id(),
        &key,
        200
    )
    .is_err());
    assert!(verify_device_authorization(
        &certificate,
        "community-b",
        identity.member_id(),
        &key,
        150
    )
    .is_err());
    assert!(verify_device_authorization(
        &certificate,
        "community-a",
        identity.member_id(),
        &device(5),
        150
    )
    .is_err());
    let mut altered = certificate.clone();
    altered.expires_at += 1;
    assert!(
        verify_device_authorization(&altered, "community-a", identity.member_id(), &key, 150)
            .is_err()
    );
    altered = certificate.clone();
    altered.version = 2;
    assert!(
        verify_device_authorization(&altered, "community-a", identity.member_id(), &key, 150)
            .is_err()
    );
    assert!(identity.authorize_device(&key, 0, 200).is_err());
    assert!(identity.authorize_device(&key, 200, 200).is_err());
    assert!(identity.authorize_device(&key, 100, u64::MAX).is_err());
    assert!(identity.authorize_device(&[1; 31], 100, 200).is_err());
}

#[test]
fn sealed_identity_recovery_requires_the_pinned_identity_and_wrapping_context() {
    let identity = MemberIdentity::new("community-a").unwrap();
    let wrapping_key = [47u8; 32];
    let sealed = identity.seal(&wrapping_key, b"identity-vault").unwrap();
    let second = identity.seal(&wrapping_key, b"identity-vault").unwrap();
    assert_ne!(sealed, second);
    let restored = MemberIdentity::restore(
        &sealed,
        &wrapping_key,
        "community-a",
        identity.member_id(),
        b"identity-vault",
    )
    .unwrap();
    assert_eq!(restored.member_id(), identity.member_id());
    let certificate = restored.authorize_device(&device(7), 100, 200).unwrap();
    verify_device_authorization(
        &certificate,
        "community-a",
        identity.member_id(),
        &device(7),
        150,
    )
    .unwrap();
    assert!(MemberIdentity::restore(
        &sealed,
        &[48u8; 32],
        "community-a",
        identity.member_id(),
        b"identity-vault"
    )
    .is_err());
    assert!(MemberIdentity::restore(
        &sealed,
        &wrapping_key,
        "community-a",
        identity.member_id(),
        b"wrong-context"
    )
    .is_err());
    let other = MemberIdentity::new("community-a").unwrap();
    assert!(MemberIdentity::restore(
        &sealed,
        &wrapping_key,
        "community-a",
        other.member_id(),
        b"identity-vault"
    )
    .is_err());
    let mut tampered = sealed;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(MemberIdentity::restore(
        &tampered,
        &wrapping_key,
        "community-a",
        identity.member_id(),
        b"identity-vault"
    )
    .is_err());
    assert_eq!(format!("{identity:?}"), "MemberIdentity([redacted])");
    assert_eq!(
        format!("{certificate:?}"),
        "DeviceAuthorization([redacted])"
    );
}
