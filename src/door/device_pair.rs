//! Pair a further device key into a membership with ONE wallet confirmation: the member's
//! stamp covers BOTH pairing steps for exactly this key (`device_add` registers it PENDING,
//! `device_activate` makes it ACTIVE once its lineage revision is published), so approving a
//! new device costs the approving device exactly one wallet ceremony, like `device_join`.
//!
//! The roles are split because the key and the member are on two devices:
//!
//! * the APPROVING device (the existing member device) holds the wallet passport and the
//!   stamp, picks the stamp salts from its own device key, and sends both steps;
//! * the NEW device only proves possession: its key signs the community's one-use challenge
//!   of each step ([`sign_possession`]).
//!
//! Each step needs its own fresh community challenge (they live 60 seconds), so the approving
//! device fetches a challenge ([`begin`]), the new device signs it, and [`send`] presents the
//! passport and the already issued stamp over it.
use super::{
    composer_core::DeviceKeys,
    custody::SystemClock,
    device_join::{derived_salt, payload, stamp_scope, DeviceSign},
    foyer::Transport,
    passport::GlobalPassport,
    stamp::{pending_request, request_stamp, resend_stamp},
    ErrorCode, Result,
};
use cfyr::Foyer;
use ckmg::{Clock, Entropy};
use cvlt::Records;
use cwlt::passport::{
    self, ActionKind, AuthenticatedCommunity, PayloadDigest, StampAction, StampSalt, StampScope,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

/// Label of the first slot's salt (`device_add`); the labels separate the two slots' salts so
/// the published stamp reveals nothing about one slot's salt from the other's.
pub const ADD_SALT_LABEL: &[u8] = b"pair-add";
/// Label of the second slot's salt (`device_activate`).
pub const ACTIVATE_SALT_LABEL: &[u8] = b"pair-activate";

/// One of the two stamped pairing steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Register the key PENDING (`device_add`): it grants nothing.
    Add,
    /// Make the pending key ACTIVE (`device_activate`), after its lineage revision exists.
    Activate,
}

impl Step {
    fn kind(self) -> &'static str {
        match self {
            Self::Add => cfyr::device_session::ADD_ACTION,
            Self::Activate => cfyr::device_session::ACTIVATE_ACTION,
        }
    }
}

/// The two stamp actions of pairing one key into one community: what ONE stamp must cover.
#[derive(Clone)]
pub struct PairingActions {
    scope: StampScope,
    key: [u8; 32],
    add: StampAction,
    activate: StampAction,
}

impl PairingActions {
    /// The actions of pairing `key` in `scope`, with one salt per slot.
    pub fn new(
        scope: StampScope,
        key: [u8; 32],
        add_salt: [u8; 32],
        activate_salt: [u8; 32],
    ) -> Result<Self> {
        let action = |step: Step, salt: [u8; 32]| -> Result<StampAction> {
            Ok(StampAction::new(
                ActionKind::new(step.kind()).map_err(|_| ErrorCode::Unavailable)?,
                PayloadDigest::from_bytes(cfyr::device_session::pairing_payload(step.kind(), &key)),
                StampSalt::from_bytes(salt),
            ))
        };
        Ok(Self {
            add: action(Step::Add, add_salt)?,
            activate: action(Step::Activate, activate_salt)?,
            scope,
            key,
        })
    }

    /// The actions of pairing `new_key` into community `name`. The salts come from the
    /// APPROVING device's key signature (`approver`) over the community, the new key and the
    /// slot's label: the wallet cannot guess them, and the approving device rebuilds them after
    /// any restart, so a retained stamp still covers and the wallet is not asked again.
    pub async fn derive(
        community: &mut Foyer<Transport>,
        name: &str,
        new_key: &ckmg::PublicKey,
        approver: &mut impl DeviceSign,
    ) -> Result<Self> {
        let scope = stamp_scope(community, name).await?;
        let add = derived_salt(name, new_key, ADD_SALT_LABEL, approver).await?;
        let activate = derived_salt(name, new_key, ACTIVATE_SALT_LABEL, approver).await?;
        Self::new(scope, *new_key.value(), add, activate)
    }

    /// The key being paired.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// The community's stamp scope.
    pub fn scope(&self) -> &StampScope {
        &self.scope
    }

    /// The stamp action of `step`.
    pub fn action(&self, step: Step) -> &StampAction {
        match step {
            Step::Add => &self.add,
            Step::Activate => &self.activate,
        }
    }

    /// Both actions as the slots of ONE stamp request.
    pub fn slots(&self) -> Vec<(StampScope, StampAction)> {
        vec![
            (self.scope.clone(), self.add.clone()),
            (self.scope.clone(), self.activate.clone()),
        ]
    }
}

/// The ONE wallet confirmation of a pairing: unless the wallet already holds (or has durably
/// begun) a stamp covering both slots, a single user-verifying ceremony — counted by
/// [`DeviceKeys::confirm`] — obtains the stamp that covers `device_add` AND `device_activate`
/// for this key. Resumable: a stamp that covers asks nothing, an interrupted request is sent
/// again, never confirmed twice.
pub async fn confirm<A, B, C, E, Au, R>(
    actions: &PairingActions,
    wallet_api: &Foyer<Transport>,
    wallet_origin: &str,
    wallet: &mut GlobalPassport<B, C, E, Au, R>,
    keys: &mut DeviceKeys<A>,
) -> Result<()>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    Au: ckmg::Authority,
    R: Records,
{
    let slots = actions.slots();
    let covered = wallet
        .with_global_passport(|holder| {
            slots
                .iter()
                .all(|(scope, action)| holder.stamp_covers(scope, action, now()))
        })
        .await?;
    if covered {
        return Ok(());
    }
    let issuance = || async {
        wallet_api
            .live_global_wallet(wallet_origin.into())
            .observe_lease(now)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?
            .stamp_challenge(now)
            .await
            .map_err(|_| ErrorCode::Unauthorized)
    };
    let mut rng = passport::rand::rngs::OsRng;
    // An earlier attempt was interrupted after its request was durably begun: send the SAME
    // request again, never a new confirmation.
    let resent = match pending_request(wallet, &slots).await? {
        Some(request) => resend_stamp(issuance().await?, wallet, request, &mut rng).await?,
        None => false,
    };
    if !resent {
        let assertion = |options: Value| async move {
            let (credential, _) = keys
                .confirm("pairing stamp")
                .map_err(|_| ErrorCode::Refused)?
                .sign_in(options)
                .await
                .map_err(|_| ErrorCode::Refused)?
                .into_parts();
            // A pairing stamp always carries its own passkey assertion (never the birth grant).
            Ok(Some(credential.as_json().clone()))
        };
        request_stamp(issuance().await?, wallet, &slots, assertion, &mut rng).await?;
    }
    Ok(())
}

/// The community's one-use challenge of one pairing step: its id and the signed request the
/// passport presentation answers. The approving device fetches it and hands it to the new
/// device to sign; it is valid for 60 seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepChallenge {
    /// The server's challenge id (part of the signed message).
    pub id: String,
    /// The community's signed presentation request.
    pub request: Vec<u8>,
}

/// Ask the community (a session-less Foyer of it) for the challenge of the next step.
pub async fn begin(community: &mut Foyer<Transport>) -> Result<StepChallenge> {
    let request = community
        .call("presentation_challenge", json!({}))
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    Ok(StepChallenge {
        id: request["challenge"]
            .as_str()
            .ok_or(ErrorCode::Unavailable)?
            .to_owned(),
        request: serde_json::from_value(request["request"].clone())
            .map_err(|_| ErrorCode::Unavailable)?,
    })
}

/// The NEW device's proof of possession for one step: its key's signature (purpose
/// `DeviceJoin`) over the community, the step's challenge id and the key.
pub async fn sign_possession(
    name: &str,
    challenge: &StepChallenge,
    device: &ckmg::PublicKey,
    sign: &mut impl DeviceSign,
) -> Result<Vec<u8>> {
    sign.sign(
        ckmg::DevicePurpose::DeviceJoin,
        payload(
            ckmg::DevicePurpose::DeviceJoin,
            cfyr::device_session::join_message(name, &challenge.id, device.value()),
        )?,
    )
    .await
}

/// Send one pairing step: a fresh passport presentation over `challenge`, the stamp
/// presentation for the step's action (the stamp [`confirm`] obtained), and the new key's
/// `signature` (from [`sign_possession`] over this same `challenge`). The community applies
/// `device_add` or `device_activate`; both are idempotent for the same key.
pub async fn send<B, C, E, Au, R>(
    community: &mut Foyer<Transport>,
    wallet: &mut GlobalPassport<B, C, E, Au, R>,
    actions: &PairingActions,
    step: Step,
    challenge: &StepChallenge,
    signature: Vec<u8>,
) -> Result<()>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    Au: ckmg::Authority,
    R: Records,
{
    let action = actions.action(step);
    let mut policy = community.current_policy();
    let expected = policy
        .with_current(now(), |current| {
            AuthenticatedCommunity::from_authenticated_origin(
                actions.scope().community().clone(),
                current.key_ring().clone(),
            )
        })
        .map_err(|_| ErrorCode::Unavailable)?;
    let (proof, stamp) = wallet
        .with_global_passport(|holder| -> Result<_> {
            let mut rng = passport::rand::rngs::OsRng;
            let proof = holder
                .present(&mut rng, &expected, &challenge.request, now())
                .map_err(|_| ErrorCode::Unauthorized)?;
            let stamp = holder
                .present_stamp(&mut rng, actions.scope(), action, now())
                .map_err(|_| ErrorCode::Unauthorized)?;
            Ok((proof.to_bytes(), stamp.to_bytes()))
        })
        .await??;
    let request = json!({
        "passport": {"challenge": challenge.id, "proof": proof},
        "stamp": stamp,
        "salt": action.salt().to_bytes(),
        "device_key": actions.key(),
        "signature": signature,
    });
    match step {
        Step::Add => community.device_add(request).await,
        Step::Activate => community.device_activate(request).await,
    }
    .map_err(|_| ErrorCode::Reconcile)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// A device signer that, like ckmg's, prepends the purpose's tag.
    fn signer(
        seed: u8,
    ) -> impl FnMut(ckmg::DevicePurpose, Vec<u8>) -> std::future::Ready<Result<Vec<u8>>> {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        move |purpose: ckmg::DevicePurpose, payload: Vec<u8>| {
            let message = [purpose.tag(), &payload[..]].concat();
            std::future::ready(Ok(key.sign(&message).to_bytes().to_vec()))
        }
    }

    fn scope() -> StampScope {
        StampScope::of_community(passport::CommunityId::new(b"alpha").unwrap(), None)
    }

    #[test]
    fn one_stamp_covers_the_add_and_the_activate_step_of_exactly_one_key() {
        let actions = PairingActions::new(scope(), [7; 32], [1; 32], [2; 32]).unwrap();
        let slots = actions.slots();
        assert_eq!(slots.len(), 2, "two slots of ONE stamp request");
        assert!(slots.iter().all(|(slot_scope, _)| slot_scope == &scope()));
        let (add, activate) = (actions.action(Step::Add), actions.action(Step::Activate));
        assert_eq!(add.kind().as_str(), "device_add");
        assert_eq!(activate.kind().as_str(), "device_activate");
        assert_eq!(
            add.payload().to_bytes(),
            cfyr::device_session::pairing_payload("device_add", &[7; 32])
        );
        assert_eq!(
            activate.payload().to_bytes(),
            cfyr::device_session::pairing_payload("device_activate", &[7; 32])
        );
        // The two steps and two keys never share a digest: a stamp approves exactly one of each.
        let other = PairingActions::new(scope(), [8; 32], [1; 32], [2; 32]).unwrap();
        assert_ne!(add.payload().to_bytes(), activate.payload().to_bytes());
        assert_ne!(
            add.payload().to_bytes(),
            other.action(Step::Add).payload().to_bytes()
        );
        assert_ne!(add.salt().to_bytes(), activate.salt().to_bytes());
        assert_eq!(actions.key(), &[7; 32]);
    }

    #[tokio::test]
    async fn the_approver_rebuilds_the_salts_after_a_restart_and_the_slots_differ() {
        let new_key = ckmg::PublicKey::new(ckmg::VLD0, [7; 32]);
        let salts = |seed: u8, key: &ckmg::PublicKey, name: &str| {
            let key = key.clone();
            let name = name.to_owned();
            async move {
                let mut sign = signer(seed);
                (
                    derived_salt(&name, &key, ADD_SALT_LABEL, &mut sign)
                        .await
                        .unwrap(),
                    derived_salt(&name, &key, ACTIVATE_SALT_LABEL, &mut sign)
                        .await
                        .unwrap(),
                )
            }
        };
        let first = salts(1, &new_key, "alpha").await;
        // The same approving device after a restart: the same salts, so a retained stamp covers.
        assert_eq!(first, salts(1, &new_key, "alpha").await);
        assert_ne!(first.0, first.1, "the slots are separated by their labels");
        assert_ne!(first, salts(2, &new_key, "alpha").await, "another approver");
        assert_ne!(first, salts(1, &new_key, "beta").await, "another community");
        let other_key = ckmg::PublicKey::new(ckmg::VLD0, [8; 32]);
        assert_ne!(first, salts(1, &other_key, "alpha").await, "another key");
    }

    #[tokio::test]
    async fn the_new_key_signs_the_join_message_of_exactly_the_challenge_it_was_given() {
        use ed25519_dalek::Verifier as _;
        let challenge = StepChallenge {
            id: "one-use".into(),
            request: vec![1, 2, 3],
        };
        let device = ckmg::PublicKey::new(
            ckmg::VLD0,
            ed25519_dalek::SigningKey::from_bytes(&[5; 32])
                .verifying_key()
                .to_bytes(),
        );
        let signature = sign_possession("alpha", &challenge, &device, &mut signer(5))
            .await
            .unwrap();
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(device.value()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        // The signature is over the exact message the server rebuilds (`cvld` `join_message`).
        let message = cfyr::device_session::join_message("alpha", "one-use", device.value());
        verifying.verify(&message, &signature).unwrap();
        let other = cfyr::device_session::join_message("alpha", "another", device.value());
        assert!(verifying.verify(&other, &signature).is_err());
    }
}
