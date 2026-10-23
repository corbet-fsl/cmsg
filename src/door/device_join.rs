//! Join a community by device key with ONE wallet confirmation: the global passport proves
//! membership eligibility, one stamp approves binding exactly this device key, and the device
//! key proves possession. No community passkey is created; the key then opens sessions
//! silently (`open_device_session`).
use super::{
    ErrorCode, Result, custody::SystemClock, foyer::Transport, passport::GlobalPassport,
    stamp::{pending_request, request_stamp, resend_stamp},
};
use cfyr::Foyer;
use ckmg::{Authority, Clock, Entropy};
use cvlt::Records;
use cwlt::passport::{
    self, ActionKind, AuthenticatedCommunity, CommunityId, PayloadDigest, StampAction, StampSalt,
    StampScope,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::future::Future;

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

/// Domain tag of the message whose device signature derives a stamp salt: ckmg's fixed
/// `DevicePurpose::SaltDerivation` tag, which the device signer prepends itself.
pub const SALT_TAG: &[u8] = ckmg::DevicePurpose::SaltDerivation.tag();

/// Label that separates the lineage-genesis slot's salt from the join slot's salt (whose
/// label is empty), so the published genesis salt reveals nothing about the join's.
pub const GENESIS_SALT_LABEL: &[u8] = b"lineage-genesis";

/// The device key's signature over `payload` for one fixed purpose; the signer prepends the
/// purpose's domain tag (before activation `cvlt::UnenrolledInitial::sign_device`).
pub trait DeviceSign {
    /// Sign `payload` under `purpose`'s tag.
    fn sign(
        &mut self,
        purpose: ckmg::DevicePurpose,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>>>;
}
impl<S, SFut> DeviceSign for S
where
    S: FnMut(ckmg::DevicePurpose, Vec<u8>) -> SFut,
    SFut: Future<Output = Result<Vec<u8>>>,
{
    fn sign(
        &mut self,
        purpose: ckmg::DevicePurpose,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>>> {
        self(purpose, payload)
    }
}

/// `message` without `purpose`'s tag: the payload the device signer signs under that tag.
pub(crate) fn payload(purpose: ckmg::DevicePurpose, message: Vec<u8>) -> Result<Vec<u8>> {
    message
        .strip_prefix(purpose.tag())
        .map(<[u8]>::to_vec)
        .ok_or(ErrorCode::Unavailable)
}

/// The community's stamp scope: its founding fingerprint as the current verified Charter
/// reports it (the identity U_c uses), or the tagged id of a community without a founding
/// document. A founded community whose Charter is not anchored on its founding fingerprint is
/// refused here: its scope cannot be computed from verified data. A wrong value would only
/// make the community refuse the stamp.
pub async fn stamp_scope(community: &mut Foyer<Transport>, name: &str) -> Result<StampScope> {
    let id = CommunityId::new(name.as_bytes()).map_err(|_| ErrorCode::Unavailable)?;
    let founding = community
        .current_policy()
        .with_current(now(), |current| current.fingerprint().copied())
        .map_err(|_| ErrorCode::Unavailable)?;
    if founding.is_none() {
        let feed = community
            .call("trust_feed", json!({}))
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        if feed
            .get("genesis")
            .is_some_and(|genesis| !genesis.is_null())
        {
            return Err(ErrorCode::Unavailable);
        }
    }
    Ok(StampScope::of_community(id, founding.as_ref()))
}

/// A stamp salt the wallet cannot guess and this device can rebuild after any restart:
/// SHA-256 of the device key's signature (purpose `SaltDerivation`) over the community, the
/// key and `label` (empty for the join slot, [`GENESIS_SALT_LABEL`] for the genesis slot).
/// The length prefix keeps the encoding injective.
pub async fn derived_salt(
    name: &str,
    device: &ckmg::PublicKey,
    label: &[u8],
    sign: &mut impl DeviceSign,
) -> Result<[u8; 32]> {
    let mut salted = (name.len() as u16).to_be_bytes().to_vec();
    salted.extend_from_slice(name.as_bytes());
    salted.extend_from_slice(device.value());
    salted.extend_from_slice(label);
    Ok(Sha256::digest(
        sign.sign(ckmg::DevicePurpose::SaltDerivation, salted)
            .await?,
    )
    .into())
}

/// Open the community session of a device-key member before its creation is activated: the
/// device signs the server's one-use nonce (purpose `DeviceSession`). After activation the
/// Vault's Keys sign instead (`Door::open_device_session`), or the community opening's
/// session signature. Returns the opened session.
pub async fn open_session(
    community: &mut Foyer<Transport>,
    name: &str,
    user: &str,
    device: &ckmg::PublicKey,
    sign: &mut impl DeviceSign,
) -> Result<cfyr::SessionInfo> {
    let challenge = community
        .begin_device_session()
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    let signature = sign
        .sign(
            ckmg::DevicePurpose::DeviceSession,
            payload(ckmg::DevicePurpose::DeviceSession, challenge.message(name))?,
        )
        .await?;
    community
        .finish_device_session(challenge.nonce, user, *device.value(), signature)
        .await
        .map_err(|_| ErrorCode::Unauthorized)
}

/// Join `name` through `community` (a session-less Foyer of that community) and return the
/// member id the device key belongs to.
///
/// * `wallet_api`/`wallet_origin`: the wallet's authenticated Foyer, for the one stamp.
/// * `sign`: the community device key's signer for fixed purposes (before activation the
///   enrollment's `sign_device`).
/// * `assertion`: the ONE wallet-passkey assertion for the options it receives.
/// * `seed`: the Keys creation receipt's seed commitment (nonzero), made locally first; the
///   join's stamp covers it and the community keeps it for `initial_creation`.
/// * `also`: further actions of this same community the same stamp must cover (the lineage
///   genesis), presented later by their owner with `present_stamp`.
///
/// Resumable without a second confirmation: the stamp salt is derived from the device key's
/// signature, so after an interruption the retained stamp still covers the join and the
/// wallet is not asked again. A retried join returns the same member. `resumed`: an earlier
/// attempt may have reached the community; when no retained stamp covers the join any more
/// (its cohort ended), the community is first asked to re-confirm that already applied join
/// (no stamp sent), and only a join it never applied asks the wallet again.
#[allow(clippy::too_many_arguments)]
pub async fn join<B, C, E, A, R, F, Fut>(
    community: &mut Foyer<Transport>,
    name: &str,
    wallet_api: &Foyer<Transport>,
    wallet_origin: &str,
    wallet: &mut GlobalPassport<B, C, E, A, R>,
    device: &ckmg::PublicKey,
    seed: [u8; 32],
    also: &[StampAction],
    resumed: bool,
    sign: &mut impl DeviceSign,
    assertion: F,
) -> Result<String>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    if seed == [0; 32] {
        return Err(ErrorCode::Unavailable);
    }
    let key: [u8; 32] = *device.value();
    let scope = stamp_scope(community, name).await?;
    // Unguessable for the wallet, stable across restarts of this device.
    let salt = derived_salt(name, device, b"", sign).await?;
    let action = StampAction::new(
        ActionKind::new(cfyr::device_session::JOIN_ACTION).map_err(|_| ErrorCode::Unavailable)?,
        PayloadDigest::from_bytes(cfyr::device_session::join_payload(&key, &seed)),
        StampSalt::from_bytes(salt),
    );
    let actions: Vec<(StampScope, StampAction)> = std::iter::once(&action)
        .chain(also)
        .map(|action| (scope.clone(), action.clone()))
        .collect();
    let covered = wallet
        .with_global_passport(|holder| {
            actions
                .iter()
                .all(|(scope, action)| holder.stamp_covers(scope, action, now()))
        })
        .await?;
    if !covered && resumed {
        let reconfirmed = send(community, name, wallet, &scope, None, &key, seed, salt, sign).await;
        if let Ok(user) = reconfirmed {
            return Ok(user);
        }
    }
    if !covered {
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
        // An earlier attempt was interrupted after its request was durably begun (possibly
        // after the wallet answered): send the SAME request again, never a new confirmation.
        let resent = match pending_request(wallet, &actions).await? {
            Some(request) => resend_stamp(issuance().await?, wallet, request, &mut rng).await?,
            None => false,
        };
        if !resent {
            request_stamp(issuance().await?, wallet, &actions, assertion, &mut rng).await?;
        }
    }
    send(
        community,
        name,
        wallet,
        &scope,
        Some(&action),
        &key,
        seed,
        salt,
        sign,
    )
    .await
}

/// Restore on a new device: have the community re-confirm the device-key join it already
/// applied for this passport, this (wallet-derived, hence unchanged) device key and the
/// creation's seed commitment from its checkpoint. No stamp is sent, nothing changes at the
/// community and the wallet is not asked: the answer is only the member id that join kept.
/// A join the community never applied is refused.
pub async fn reconfirm<B, C, E, A, R>(
    community: &mut Foyer<Transport>,
    name: &str,
    wallet: &mut GlobalPassport<B, C, E, A, R>,
    device: &ckmg::PublicKey,
    seed: [u8; 32],
    sign: &mut impl DeviceSign,
) -> Result<String>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    if seed == [0; 32] {
        return Err(ErrorCode::Unavailable);
    }
    let key: [u8; 32] = *device.value();
    let scope = stamp_scope(community, name).await?;
    let salt = derived_salt(name, device, b"", sign).await?;
    send(community, name, wallet, &scope, None, &key, seed, salt, sign).await
}

/// Send one join: a fresh passport presentation over this community's signed challenge, the
/// stamp presentation for `action` (none: re-confirm an already applied join), the device
/// key's signature over the join message.
#[allow(clippy::too_many_arguments)]
async fn send<B, C, E, A, R>(
    community: &mut Foyer<Transport>,
    name: &str,
    wallet: &mut GlobalPassport<B, C, E, A, R>,
    scope: &StampScope,
    action: Option<&StampAction>,
    key: &[u8; 32],
    seed: [u8; 32],
    salt: [u8; 32],
    sign: &mut impl DeviceSign,
) -> Result<String>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    // Passport presentation over this community's signed challenge.
    let request = community
        .call("presentation_challenge", json!({}))
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    let challenge = request["challenge"]
        .as_str()
        .ok_or(ErrorCode::Unavailable)?
        .to_owned();
    let signed: Vec<u8> =
        serde_json::from_value(request["request"].clone()).map_err(|_| ErrorCode::Unavailable)?;
    let mut policy = community.current_policy();
    let expected = policy
        .with_current(now(), |current| {
            AuthenticatedCommunity::from_authenticated_origin(
                scope.community().clone(),
                current.key_ring().clone(),
            )
        })
        .map_err(|_| ErrorCode::Unavailable)?;
    let (proof, stamp) = wallet
        .with_global_passport(|holder| -> Result<_> {
            let mut rng = passport::rand::rngs::OsRng;
            let proof = holder
                .present(&mut rng, &expected, &signed, now())
                .map_err(|_| ErrorCode::Unauthorized)?;
            let stamp = match action {
                Some(action) => holder
                    .present_stamp(&mut rng, scope, action, now())
                    .map_err(|_| ErrorCode::Unauthorized)?
                    .to_bytes(),
                None => Vec::new(),
            };
            Ok((proof.to_bytes(), stamp))
        })
        .await??;
    let signature = sign
        .sign(
            ckmg::DevicePurpose::DeviceJoin,
            payload(
                ckmg::DevicePurpose::DeviceJoin,
                cfyr::device_session::join_message(name, &challenge, key),
            )?,
        )
        .await?;
    community
        .device_join(json!({
            "passport": {"challenge": challenge, "proof": proof},
            "stamp": stamp,
            "salt": salt,
            "device_key": key,
            "seed": seed,
            "signature": signature,
        }))
        .await
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

    #[tokio::test]
    async fn the_salt_is_rebuilt_after_a_restart_and_separates_slots_communities_and_keys() {
        let device = ckmg::PublicKey::new(ckmg::VLD0, [7; 32]);
        let first = derived_salt("alpha", &device, b"", &mut signer(1))
            .await
            .unwrap();
        // The same device key after a restart: the same salt, so a retained stamp still covers.
        let again = derived_salt("alpha", &device, b"", &mut signer(1))
            .await
            .unwrap();
        assert_eq!(first, again);
        // The join salt keeps its bytes: tag || len || name || key, signed under SaltDerivation.
        let mut legacy = SALT_TAG.to_vec();
        legacy.extend_from_slice(&5u16.to_be_bytes());
        legacy.extend_from_slice(b"alpha");
        legacy.extend_from_slice(device.value());
        let signature = {
            use ed25519_dalek::Signer as _;
            ed25519_dalek::SigningKey::from_bytes(&[1; 32]).sign(&legacy)
        };
        assert_eq!(first, <[u8; 32]>::from(Sha256::digest(signature.to_bytes())));
        let genesis = derived_salt("alpha", &device, GENESIS_SALT_LABEL, &mut signer(1))
            .await
            .unwrap();
        let other_community = derived_salt("beta", &device, b"", &mut signer(1))
            .await
            .unwrap();
        let other_key = derived_salt(
            "alpha",
            &ckmg::PublicKey::new(ckmg::VLD0, [8; 32]),
            b"",
            &mut signer(1),
        )
        .await
        .unwrap();
        let other_signer = derived_salt("alpha", &device, b"", &mut signer(2))
            .await
            .unwrap();
        for salt in [genesis, other_community, other_key, other_signer] {
            assert_ne!(salt, first);
        }
    }

    #[test]
    fn signed_payloads_are_the_messages_without_their_purpose_tag() {
        let join = cfyr::device_session::join_message("alpha", "challenge", &[7; 32]);
        let stripped = payload(ckmg::DevicePurpose::DeviceJoin, join.clone()).unwrap();
        assert_eq!([ckmg::DevicePurpose::DeviceJoin.tag(), &stripped[..]].concat(), join);
        // A message of another purpose is never signed under this one.
        assert!(payload(ckmg::DevicePurpose::DeviceSession, join).is_err());
    }
}
