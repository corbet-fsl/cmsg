//! Unlock once per device (DESIGN-one-confirmation-2026-10-14): the wallet
//! passkey's ONE confirmation at app start unlocks the wallet vault and every
//! community vault. Community operations afterwards never start a WebAuthn
//! ceremony for the vault: each community's opening is derived from the held
//! wallet unlock (`cvlt::WalletUnlock`, per-community secret, own records).
//!
//! Browser and native take this same path: the platform authenticator differs
//! (`cpky` browser or native/software port), the custody code does not.
//! The per-community passkey path (`login`, `custody::initial`) stays until the
//! device-key sessions replace it (critical path package 7).
use super::{ErrorCode, Result};
use cfyr::passkeys::{Authenticator, Client, PublicCredential, VaultOutcome};

/// The device's unlocked state for one app session. Holding it is not a
/// session or authority at any service; dropping it locks every derived vault.
pub struct DeviceUnlock {
    wallet: cvlt::WalletUnlock,
}

impl DeviceUnlock {
    /// The one confirmation of this app start: a wallet passkey assertion with PRF.
    /// Returns the public credential for the wallet login finish. A ceremony
    /// without a PRF result unlocks nothing.
    pub async fn sign_in<A: Authenticator>(
        client: &mut Client<A>,
        options: serde_json::Value,
    ) -> Result<(PublicCredential, Self)> {
        let (credential, outcome) = client
            .sign_in(options)
            .await
            .map_err(|_| ErrorCode::Refused)?
            .into_parts();
        let VaultOutcome::Ready(unlock) = outcome else {
            return Err(ErrorCode::Unavailable);
        };
        Ok((credential, Self::from_unlock(unlock)))
    }

    /// Hold an already completed wallet ceremony's PRF result.
    pub fn from_unlock(unlock: cfyr::passkeys::UnlockSecret) -> Self {
        Self {
            wallet: cvlt::WalletUnlock::new(unlock),
        }
    }

    /// The wallet vault's opening (unchanged derivation).
    pub fn wallet_opening(&self) -> Result<cvlt::PreparedOpen> {
        self.wallet.wallet().map_err(|_| ErrorCode::Refused)
    }

    /// One community vault's opening, without any ceremony.
    pub fn community_opening(&self, scope: &str) -> Result<cvlt::PreparedOpen> {
        self.wallet
            .community(scope)
            .map_err(|_| ErrorCode::InvalidRequest)
    }

    /// The community device key (lineage device) this device presents in `scope`:
    /// what the community's device-key registry binds at join.
    pub fn community_device(&self, scope: &str) -> Result<ckmg::PublicKey> {
        self.community_opening(scope)?
            .device()
            .map_err(|_| ErrorCode::InvalidRequest)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use cfyr::passkeys::software::{SoftwareAuthenticator, TestConfiguration};
    use cfyr::passkeys::{Client, Context};
    use serde_json::json;

    const ORIGIN: &str = "https://wallet.example.test";
    const RP: &str = "wallet.example.test";

    fn b64(bytes: &[u8]) -> String {
        data_encoding::BASE64URL_NOPAD.encode(bytes)
    }

    async fn wallet_passkey() -> Client<SoftwareAuthenticator> {
        let platform = SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap();
        let mut client = Client::new(Context::new(ORIGIN, RP).unwrap(), platform);
        client.register_member(json!({"publicKey": {
            "rp":{"id":RP,"name":"Wallet"},
            "user":{"id":b64(&[17;16]),"name":"member","displayName":"Member"},
            "challenge":b64(&[41;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required","authenticatorAttachment":"platform"},
            "timeout":42000,"excludeCredentials":[],"attestation":"none",
            "extensions":{"credProps":true},"hints":["client-device"]
        }})).await.unwrap();
        client
    }

    fn options() -> serde_json::Value {
        json!({"publicKey": {"challenge":b64(&[55;32]),"rpId":RP,
            "userVerification":"required","allowCredentials":[],"timeout":21000}})
    }

    #[test]
    fn one_wallet_confirmation_serves_every_community() {
        futures_executor::block_on(async {
            let mut client = wallet_passkey().await;
            let (_credential, unlock) = DeviceUnlock::sign_in(&mut client, options()).await.unwrap();
            drop(client); // no further ceremony is possible
            let garden = unlock.community_device("garden").unwrap();
            let orchard = unlock.community_device("orchard").unwrap();
            assert_ne!(garden.value(), orchard.value());
            // Repeated community operations derive the same device, still without a prompt.
            assert_eq!(unlock.community_device("garden").unwrap().value(), garden.value());
            assert!(unlock.wallet_opening().is_ok());
            assert_eq!(unlock.community_opening("wallet").err(), Some(ErrorCode::InvalidRequest));
        });
    }

    #[test]
    fn another_wallet_passkey_derives_other_community_devices() {
        futures_executor::block_on(async {
            let (_, mine) = DeviceUnlock::sign_in(&mut wallet_passkey().await, options()).await.unwrap();
            let (_, other) = DeviceUnlock::sign_in(&mut wallet_passkey().await, options()).await.unwrap();
            assert_ne!(
                mine.community_device("garden").unwrap().value(),
                other.community_device("garden").unwrap().value()
            );
        });
    }
}
