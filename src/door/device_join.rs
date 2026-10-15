//! Join a community by device key with ONE wallet confirmation: the global passport proves
//! membership eligibility, one stamp approves binding exactly this device key, and the device
//! key proves possession. No community passkey is created; the key then opens sessions
//! silently (`open_device_session`).
use super::{
    ErrorCode, Result, custody::SystemClock, foyer::Transport, passport::GlobalPassport,
    stamp::request_stamp,
};
use cfyr::Foyer;
use ckmg::{Authority, Clock, Entropy};
use cvlt::Records;
use cwlt::passport::{
    self, ActionKind, AuthenticatedCommunity, CommunityFingerprint, CommunityId, PayloadDigest,
    StampAction, StampSalt, StampScope,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::future::Future;

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

/// Domain tag of the message whose device signature derives a join's stamp salt.
pub const SALT_TAG: &[u8] = b"cmsg.device-join.salt.v1\0";

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
    Ok(StampScope::new(
        id,
        CommunityFingerprint::from_bytes(cfyr::device_session::scope_fingerprint(
            name,
            founding.as_ref(),
        )),
    ))
}

/// A stamp salt the wallet cannot guess and this device can rebuild after any restart:
/// SHA-256 of the device key's signature over `tag`, the community and the key.
pub async fn derived_salt<S, SFut>(
    name: &str,
    device: &ckmg::PublicKey,
    tag: &[u8],
    sign: &mut S,
) -> Result<[u8; 32]>
where
    S: FnMut(Vec<u8>) -> SFut,
    SFut: Future<Output = Result<Vec<u8>>>,
{
    let mut salted = tag.to_vec();
    salted.extend_from_slice(&(name.len() as u16).to_be_bytes());
    salted.extend_from_slice(name.as_bytes());
    salted.extend_from_slice(device.value());
    Ok(Sha256::digest(sign(salted).await?).into())
}

/// Join `name` through `community` (a session-less Foyer of that community) and return the
/// member id the device key belongs to.
///
/// * `wallet_api`/`wallet_origin`: the wallet's authenticated Foyer, for the one stamp.
/// * `sign`: the community device key's ed25519 signature over the given bytes (Vault).
/// * `assertion`: the ONE wallet-passkey assertion for the options it receives.
/// * `seed`: the Keys creation receipt's seed commitment (nonzero), made locally first; the
///   join's stamp covers it and the community keeps it for `initial_creation`.
/// * `also`: further actions of this same community the same stamp must cover (the lineage
///   genesis), presented later by their owner with `present_stamp`.
///
/// Resumable without a second confirmation: the stamp salt is derived from the device key's
/// signature, so after an interruption the retained stamp still covers the join and the
/// wallet is not asked again. A retried join returns the same member.
#[allow(clippy::too_many_arguments)]
pub async fn join<B, C, E, A, R, S, SFut, F, Fut>(
    community: &mut Foyer<Transport>,
    name: &str,
    wallet_api: &Foyer<Transport>,
    wallet_origin: &str,
    wallet: &mut GlobalPassport<B, C, E, A, R>,
    device: &ckmg::PublicKey,
    seed: [u8; 32],
    also: &[StampAction],
    mut sign: S,
    assertion: F,
) -> Result<String>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    S: FnMut(Vec<u8>) -> SFut,
    SFut: Future<Output = Result<Vec<u8>>>,
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    if seed == [0; 32] {
        return Err(ErrorCode::Unavailable);
    }
    let key: [u8; 32] = *device.value();
    let scope = stamp_scope(community, name).await?;
    // Unguessable for the wallet, stable across restarts of this device.
    let salt = derived_salt(name, device, SALT_TAG, &mut sign).await?;
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
    if !covered {
        let issuance = wallet_api
            .live_global_wallet(wallet_origin.into())
            .observe_lease(now)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?
            .stamp_challenge(now)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        request_stamp(
            issuance,
            wallet,
            &actions,
            assertion,
            &mut passport::rand::rngs::OsRng,
        )
        .await?;
    }
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
            let stamp = holder
                .present_stamp(&mut rng, &scope, &action, now())
                .map_err(|_| ErrorCode::Unauthorized)?;
            Ok((proof.to_bytes(), stamp.to_bytes()))
        })
        .await??;
    let signature = sign(cfyr::device_session::join_message(name, &challenge, &key)).await?;
    let joined = community
        .call(
            "device_join",
            json!({
                "passport": {"challenge": challenge, "proof": proof},
                "stamp": stamp,
                "salt": salt,
                "device_key": key,
                "seed": seed,
                "signature": signature,
            }),
        )
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    joined["user"]
        .as_str()
        .map(str::to_owned)
        .ok_or(ErrorCode::Reconcile)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn signer(seed: u8) -> impl FnMut(Vec<u8>) -> std::future::Ready<Result<Vec<u8>>> {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        move |message: Vec<u8>| std::future::ready(Ok(key.sign(&message).to_bytes().to_vec()))
    }

    #[tokio::test]
    async fn the_salt_is_rebuilt_after_a_restart_and_separates_tags_communities_and_keys() {
        let device = ckmg::PublicKey::new(ckmg::VLD0, [7; 32]);
        let first = derived_salt("alpha", &device, SALT_TAG, &mut signer(1))
            .await
            .unwrap();
        // The same device key after a restart: the same salt, so a retained stamp still covers.
        let again = derived_salt("alpha", &device, SALT_TAG, &mut signer(1))
            .await
            .unwrap();
        assert_eq!(first, again);
        let other_tag = derived_salt("alpha", &device, b"other\0", &mut signer(1))
            .await
            .unwrap();
        let other_community = derived_salt("beta", &device, SALT_TAG, &mut signer(1))
            .await
            .unwrap();
        let other_key = derived_salt(
            "alpha",
            &ckmg::PublicKey::new(ckmg::VLD0, [8; 32]),
            SALT_TAG,
            &mut signer(1),
        )
        .await
        .unwrap();
        let other_signer = derived_salt("alpha", &device, SALT_TAG, &mut signer(2))
            .await
            .unwrap();
        for salt in [other_tag, other_community, other_key, other_signer] {
            assert_ne!(salt, first);
        }
    }
}
