//! Silent community sessions. The device signs the server's one-use nonce with its community
//! device key from the Vault; there is no WebAuthn prompt. Opening and renewing are the same
//! exchange. The member's community user id comes from the caller (the account record).
use super::*;

/// Seconds the signing admission stays valid; the server's nonce lives a minute.
const SIGN_SECONDS: u64 = 60;

impl Door {
    /// Open or renew the community session of `origin`; returns its exclusive deadline.
    pub async fn open_device_session(&mut self, origin: &str, user: &str) -> Result<u64> {
        let challenge = self
            .foyers
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?
            .begin_device_session()
            .await?;
        let message = challenge.message(&self.config.community);
        let started = ckmg::Clock::now(&mut custody::SystemClock).map_err(|_| ErrorCode::Clock)?;
        let (signature, device, _) = self
            .vaults
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?
            .sign_endorsement(
                &message,
                origin,
                started,
                started.saturating_add(SIGN_SECONDS),
            )
            .await?;
        let device_key: [u8; 32] = device.try_into().map_err(|_| ErrorCode::Unavailable)?;
        self.foyers
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?
            .finish_device_session(challenge.nonce, user, device_key, signature)
            .await
    }
}

/// Stamp salt of an admin session: SHA-256 of the device key's signature over the garden
/// message. The wallet cannot guess it and each one-use nonce yields a different one.
pub(crate) fn garden_salt(signature: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(signature).into()
}

impl Door {
    /// Open the ADMIN session of `origin` with the device key and ONE wallet confirmation: the
    /// stamp covers exactly this key and the server's one-use nonce, so signing in is the
    /// step-up; there is no admin passkey. No special case for any role: the server checks the
    /// member's real role. Returns the session's exclusive deadline.
    pub async fn open_garden_session<B, C, E, A, R, F, Fut>(
        &mut self,
        origin: &str,
        user: &str,
        wallet_api: &cfyr::Foyer<foyer::Transport>,
        wallet_origin: &str,
        wallet: &mut passport::GlobalPassport<B, C, E, A, R>,
        assertion: F,
    ) -> Result<u64>
    where
        B: cwst::backend::Backend,
        C: ckmg::Clock,
        E: ckmg::Entropy,
        A: ckmg::Authority,
        R: cvlt::Records,
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value>>,
    {
        use cwlt::passport::{ActionKind, PayloadDigest, StampAction, StampSalt};
        let community = self.config.community.clone();
        let foyer = self.foyers.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
        let challenge = foyer.begin_device_session().await?;
        let scope = device_join::stamp_scope(foyer.community_client()?, &community).await?;
        let started = ckmg::Clock::now(&mut custody::SystemClock).map_err(|_| ErrorCode::Clock)?;
        let (signature, device, _) = self
            .vaults
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?
            .sign_endorsement(
                &challenge.garden_message(&community),
                origin,
                started,
                started.saturating_add(SIGN_SECONDS),
            )
            .await?;
        let device_key: [u8; 32] = device.try_into().map_err(|_| ErrorCode::Unavailable)?;
        let salt = garden_salt(&signature);
        let action = StampAction::new(
            ActionKind::new(cfyr::device_session::GARDEN_ACTION)
                .map_err(|_| ErrorCode::Unavailable)?,
            PayloadDigest::from_bytes(cfyr::device_session::garden_payload(
                &device_key,
                &challenge.nonce,
            )),
            StampSalt::from_bytes(salt),
        );
        let actions = [(scope.clone(), action.clone())];
        let now = || ckmg::Clock::now(&mut custody::SystemClock).unwrap_or(u64::MAX);
        let issuance = wallet_api
            .live_global_wallet(wallet_origin.into())
            .observe_lease(now)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?
            .stamp_challenge(now)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let mut rng = cwlt::passport::rand::rngs::OsRng;
        // An admin session always confirms by assertion: it is never a registration's birth.
        let assertion = move |options| {
            let asserted = assertion(options);
            async move { asserted.await.map(Some) }
        };
        stamp::request_stamp(issuance, wallet, &actions, assertion, &mut rng).await?;
        let stamp = wallet
            .with_global_passport(|holder| {
                let mut rng = cwlt::passport::rand::rngs::OsRng;
                holder
                    .present_stamp(&mut rng, &scope, &action, now())
                    .map(|presented| presented.to_bytes())
                    .map_err(|_| ErrorCode::Unauthorized)
            })
            .await??;
        self.foyers
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?
            .finish_garden_session(challenge.nonce, user, device_key, signature, stamp, salt)
            .await
    }
}
