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
