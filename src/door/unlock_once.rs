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

    /// One community vault's opening, without any ceremony. `fingerprint` is the
    /// community's identity (founding-key fingerprint, as the vault pins it), never
    /// its address; `scope` is the address the vault's Store is named by.
    pub fn community_opening(
        &self,
        fingerprint: &[u8; 32],
        scope: &str,
    ) -> Result<cvlt::PreparedOpen> {
        self.wallet
            .community(fingerprint, scope)
            .map_err(|_| ErrorCode::InvalidRequest)
    }

    /// Add this community to the wallet's membership index (a record only the wallet
    /// secret locates) and wait for its replication: a restore on a new device finds the
    /// community through it. Idempotent; `Queued` means "ask again", never "proceed".
    pub async fn index_membership<N: cdht::Network>(
        &self,
        network: N,
        address: &str,
        fingerprint: &[u8; 32],
    ) -> Result<cvlt::Outcome> {
        let (mut record, cipher) = self
            .wallet
            .index_record(network)
            .map_err(|_| ErrorCode::Unavailable)?;
        let entry = cvlt::MembershipEntry::new(address, *fingerprint)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        cvlt::add_entry(&mut record, &cipher, &mut ckmg::SystemEntropy, entry)
            .await
            .map_err(|_| ErrorCode::Unavailable)
    }

    /// The memberships the wallet's index lists. `None`: the record is unavailable, which is
    /// not proof that there are none.
    pub async fn indexed_memberships<N: cdht::Network>(
        &self,
        network: N,
    ) -> Result<Option<cvlt::MembershipIndex>> {
        let (mut record, cipher) = self
            .wallet
            .index_record(network)
            .map_err(|_| ErrorCode::Unavailable)?;
        cvlt::read_index(&mut record, &cipher)
            .await
            .map(|read| read.map(|(_, index)| index))
            .map_err(|_| ErrorCode::Unavailable)
    }

    /// The community device key (lineage device) this device presents in `scope`:
    /// what the community's device-key registry binds at join.
    pub fn community_device(&self, fingerprint: &[u8; 32], scope: &str) -> Result<ckmg::PublicKey> {
        self.community_opening(fingerprint, scope)?
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
            let (_credential, unlock) =
                DeviceUnlock::sign_in(&mut client, options()).await.unwrap();
            drop(client); // no further ceremony is possible
            let garden = unlock.community_device(&[1; 32], "garden").unwrap();
            let orchard = unlock.community_device(&[2; 32], "orchard").unwrap();
            assert_ne!(garden.value(), orchard.value());
            // Repeated community operations derive the same device, still without a prompt.
            assert_eq!(
                unlock.community_device(&[1; 32], "garden").unwrap().value(),
                garden.value()
            );
            // A new community at a reused address is another identity: another device.
            assert_ne!(
                unlock.community_device(&[3; 32], "garden").unwrap().value(),
                garden.value()
            );
            assert!(unlock.wallet_opening().is_ok());
            assert_eq!(
                unlock.community_opening(&[1; 32], "wallet").err(),
                Some(ErrorCode::InvalidRequest)
            );
        });
    }

    #[test]
    fn another_wallet_passkey_derives_other_community_devices() {
        futures_executor::block_on(async {
            let (_, mine) = DeviceUnlock::sign_in(&mut wallet_passkey().await, options())
                .await
                .unwrap();
            let (_, other) = DeviceUnlock::sign_in(&mut wallet_passkey().await, options())
                .await
                .unwrap();
            assert_ne!(
                mine.community_device(&[1; 32], "garden").unwrap().value(),
                other.community_device(&[1; 32], "garden").unwrap().value()
            );
        });
    }
}
