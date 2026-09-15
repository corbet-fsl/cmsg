mod common;
use cmsg::{MemberIdentity, Received};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

#[test]
fn malicious_root_authorized_peer_cannot_downgrade_its_leaf_through_a_valid_mls_commit() {
    let owner_root = MemberIdentity::new("synthetic-community").unwrap();
    let receiver_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut receiver = common::root_device(&receiver_root);
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let signer =
        openmls_basic_credential::SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
    let key = signer.to_public_vec();
    let mut grant = common::grant(&key, 1);
    grant.member_id = owner_root.member_id().to_owned();
    common::sign(&mut grant);
    let authorized = serde_json::to_vec(&serde_json::json!({
        "admission": grant,
        "device_authorization": owner_root.authorize_device(&key, 1, 9_000_000_000).unwrap(),
    }))
    .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(authorized).into(),
        signature_key: key.clone().into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let package = KeyPackageIn::tls_deserialize_exact(&receiver.key_package().unwrap())
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (_, welcome, _) = group.add_members(&provider, &signer, &[package]).unwrap();
    group.merge_pending_commit(&provider).unwrap();
    receiver
        .join(&welcome.tls_serialize_detached().unwrap())
        .unwrap();

    // Bypass every cmsg outgoing check with upstream MLS and remove the root
    // authorization while retaining a valid issuer certificate and MLS signer.
    let candidate_provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    *candidate_provider.storage().values.write().unwrap() =
        provider.storage().values.read().unwrap().clone();
    let mut candidate = MlsGroup::load(candidate_provider.storage(), group.group_id())
        .unwrap()
        .unwrap();
    let downgraded = CredentialWithKey {
        credential: BasicCredential::new(serde_json::to_vec(&grant).unwrap()).into(),
        signature_key: key.into(),
    };
    let invalid = candidate
        .commit_builder()
        .consume_proposal_store(false)
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_credential_with_key(downgraded)
                .build(),
        )
        .load_psks(candidate_provider.storage())
        .unwrap()
        .build(
            candidate_provider.rand(),
            candidate_provider.crypto(),
            &signer,
            |_| false,
        )
        .unwrap()
        .stage_commit(&candidate_provider)
        .unwrap()
        .into_commit()
        .tls_serialize_detached()
        .unwrap();
    assert!(receiver.receive(&invalid).is_err());
    let valid = group
        .create_message(
            &provider,
            &signer,
            b"cmsg-payload-v1\0\0still authenticated at the original epoch",
        )
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert!(
        matches!(receiver.receive(&valid).unwrap(), Received::Text(message)
        if message.member_id == owner_root.member_id() && message.text == "still authenticated at the original epoch")
    );
}
