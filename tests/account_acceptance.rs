//! The wallet-side reconstruction of the issuer acceptance message must equal the
//! original Balance transcript. The wallet owner asserts the same golden digest
//! and verifies the same operator signature over its own reconstruction.
#![cfg(not(target_arch = "wasm32"))]
use cblc::accounting::{
    account_acceptance_bytes, verify_account_acceptance, AccountAcceptance, AccountPolicy,
    AccountProofScope, AccountStatement,
};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use sha2::{Digest, Sha256};

const GOLDEN_MESSAGE_DIGEST: &str =
    "a9189a36a90839b5a224f459ea8ca880194d26f4f439b2ace7b70e912bf8bc3a";
const GOLDEN_SIGNATURE: &str = "1f722ba31f953dc655a6f1247d616798bd8d227427c3cf1358bf780082a3012db4ea429443439188e9c14ff78fa56f7a2dd38bce7e7d04273d016022f2562f08";
const GOLDEN_OPERATOR: &str = "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1";

fn acceptance(accepted_at: u64) -> AccountAcceptance {
    let community: [u8; 32] = Sha256::digest(b"community").into();
    let policy = AccountPolicy {
        initial_credit: 20,
        maximum_available: 100,
        outgoing_reservation: 5,
        incoming_reservation: 5,
        policy_revision: 1,
        policy_valid_from: 1,
        policy_valid_until: 10_000,
        newcomer_period: 100,
        rate_window: 100,
        newcomer_admissions: 2,
        maximum_admissions: 10,
        refill_period: 100,
        refill_units: 2,
        abandon_after: 200,
    };
    let mut root = [0; 32];
    root[31] = 7;
    let mut next = [0; 32];
    next[31] = 9;
    AccountAcceptance {
        statement: AccountStatement {
            protocol_version: 2,
            community,
            owner: [2; 32],
            policy_digest: policy.digest(&community).unwrap(),
            enrollment_root: root,
            now: 101,
            valid_until: 200,
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: next,
            settlement_marker: [0; 32],
            policy,
        },
        request_id: [0xA1; 32],
        request_digest: [0xB2; 32],
        proof_scope: AccountProofScope {
            circuit_digest: [0xC3; 32],
            verifying_key_digest: [0xD4; 32],
        },
        accepted_at,
        signature: B64.encode(&HEX.decode(GOLDEN_SIGNATURE.as_bytes()).unwrap()),
    }
}

#[test]
fn original_balance_transcript_matches_the_wallet_golden_message() {
    let message = account_acceptance_bytes(&acceptance(150)).unwrap();
    assert_eq!(HEX.encode(&Sha256::digest(message)), GOLDEN_MESSAGE_DIGEST);
}

#[test]
fn original_balance_verifier_accepts_the_golden_signature_only_for_its_message() {
    let operator: [u8; 32] = HEX
        .decode(GOLDEN_OPERATOR.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    verify_account_acceptance(&acceptance(150), &operator).unwrap();
    assert!(verify_account_acceptance(&acceptance(151), &operator).is_err());
    let mut changed = acceptance(150);
    changed.request_digest[0] ^= 1;
    assert!(verify_account_acceptance(&changed, &operator).is_err());
}
