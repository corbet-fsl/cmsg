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
const SALT_TAG: &[u8] = b"cmsg.device-join.salt.v1\0";

/// The community's stamp scope: its founding-document fingerprint (the anchored trust, else
/// the published founding document), or the tagged id of a community without one. A wrong
/// value only makes the community refuse the stamp.
async fn scope(community: &mut Foyer<Transport>, name: &str) -> Result<StampScope> {
    let id = CommunityId::new(name.as_bytes()).map_err(|_| ErrorCode::Unavailable)?;
    let anchored = community
        .trust()
        .ok()
        .and_then(|trust| trust.fingerprint().copied());
    let fingerprint = match anchored {
        Some(fingerprint) => fingerprint,
        None => {
            let feed = community
                .call("trust_feed", json!({}))
                .await
                .map_err(|_| ErrorCode::Unavailable)?;
            match feed.get("genesis").filter(|genesis| !genesis.is_null()) {
                Some(genesis) => {
                    let genesis: Vec<u8> = serde_json::from_value(genesis.clone())
                        .map_err(|_| ErrorCode::Unavailable)?;
                    Sha256::digest(genesis).into()
                }
                None => {
                    let mut hasher = Sha256::new();
                    hasher.update(cfyr::device_session::UNFOUNDED_FINGERPRINT_TAG);
                    hasher.update(name.as_bytes());
                    hasher.finalize().into()
                }
            }
        }
    };
    Ok(StampScope::new(
        id,
        CommunityFingerprint::from_bytes(fingerprint),
    ))
}

/// Join `name` through `community` (a session-less Foyer of that community) and return the
/// member id the device key belongs to.
///
/// * `wallet_api`/`wallet_origin`: the wallet's authenticated Foyer, for the one stamp.
/// * `sign`: the community device key's ed25519 signature over the given bytes (Vault).
/// * `assertion`: the ONE wallet-passkey assertion for the options it receives.
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
    let key: [u8; 32] = *device.value();
    let scope = scope(community, name).await?;
    // Unguessable for the wallet, stable across restarts of this device.
    let mut salted = SALT_TAG.to_vec();
    salted.extend_from_slice(&(name.len() as u16).to_be_bytes());
    salted.extend_from_slice(name.as_bytes());
    salted.extend_from_slice(&key);
    let salt: [u8; 32] = Sha256::digest(sign(salted).await?).into();
    let action = StampAction::new(
        ActionKind::new(cfyr::device_session::JOIN_ACTION).map_err(|_| ErrorCode::Unavailable)?,
        PayloadDigest::from_bytes(key),
        StampSalt::from_bytes(salt),
    );
    let covered = wallet
        .with_global_passport(|holder| holder.stamp_covers(&scope, &action, now()))
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
            &[(scope.clone(), action.clone())],
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
