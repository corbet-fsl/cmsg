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
    held: Held,
}

/// Where this app start's unlock came from.
enum Held {
    /// The wallet passkey's PRF output: every vault, and new communities.
    Ceremony(cvlt::WalletUnlock),
    /// The persisted unlock (DESIGN-secure-convenience M6): only the communities this
    /// device had already joined; the wallet vault and a new community need the passkey.
    Resumed(cvlt::ResumeBundle),
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
            held: Held::Ceremony(cvlt::WalletUnlock::new(unlock)),
        }
    }

    /// Whether this start was resumed from the persisted unlock (no ceremony).
    pub fn is_resumed(&self) -> bool {
        matches!(self.held, Held::Resumed(_))
    }

    /// The wallet vault's opening (unchanged derivation). A resumed start does not
    /// hold it: the wallet vault needs the passkey (`Unauthorized`).
    pub fn wallet_opening(&self) -> Result<cvlt::PreparedOpen> {
        match &self.held {
            Held::Ceremony(wallet) => wallet.wallet().map_err(|_| ErrorCode::Refused),
            Held::Resumed(_) => Err(ErrorCode::Unauthorized),
        }
    }

    /// One community vault's opening, without any ceremony. `fingerprint` is the
    /// community's identity (founding-key fingerprint, as the vault pins it), never
    /// its address; `scope` is the address the vault's Store is named by. A resumed
    /// start opens only the communities it had joined.
    pub fn community_opening(
        &self,
        fingerprint: &[u8; 32],
        scope: &str,
    ) -> Result<cvlt::PreparedOpen> {
        match &self.held {
            Held::Ceremony(wallet) => wallet.community(fingerprint, scope),
            Held::Resumed(bundle) => bundle.community(fingerprint, scope),
        }
        .map_err(|_| ErrorCode::InvalidRequest)
    }

    /// The wallet passkey's unlock. A resumed start does not hold it: the wallet vault
    /// and its records (membership index) need the passkey (`Unauthorized`).
    fn wallet_unlock(&self) -> Result<&cvlt::WalletUnlock> {
        match &self.held {
            Held::Ceremony(wallet) => Ok(wallet),
            Held::Resumed(_) => Err(ErrorCode::Unauthorized),
        }
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
            .wallet_unlock()?
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
            .wallet_unlock()?
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

/// The OS key store service under which the native persistent unlock keeps its wrapping
/// key: the client binary's name.
pub const KEYRING_SERVICE: &str = "cmeet";

/// Persistent unlock (DESIGN-secure-convenience part 4): a device stays unlocked across
/// restarts. The persisted bundle holds only the openings of the communities this
/// device has joined, never the wallet PRF output. There is no automatic lock; the
/// user locks explicitly, or opts into "ask for my passkey at every start".
pub trait UnlockStore {
    /// Seal the bundle, replacing any earlier one.
    fn save(
        &self,
        bundle: &cvlt::ResumeBundle,
    ) -> impl std::future::Future<Output = std::result::Result<(), cvlt::ResumeError>>;
    /// The persisted bundle, if one opens (anything else reads as none).
    fn load(&self) -> impl std::future::Future<Output = Option<cvlt::ResumeBundle>>;
    /// Delete the persisted unlock.
    fn forget(
        &self,
    ) -> impl std::future::Future<Output = std::result::Result<(), cvlt::ResumeError>>;
}

#[cfg(not(target_arch = "wasm32"))]
impl UnlockStore for cvlt::NativeResume {
    async fn save(
        &self,
        bundle: &cvlt::ResumeBundle,
    ) -> std::result::Result<(), cvlt::ResumeError> {
        cvlt::NativeResume::save(self, bundle)
    }
    async fn load(&self) -> Option<cvlt::ResumeBundle> {
        cvlt::NativeResume::load(self)
    }
    async fn forget(&self) -> std::result::Result<(), cvlt::ResumeError> {
        cvlt::NativeResume::forget(self)
    }
}

#[cfg(target_arch = "wasm32")]
impl UnlockStore for cvlt::BrowserResume {
    async fn save(
        &self,
        bundle: &cvlt::ResumeBundle,
    ) -> std::result::Result<(), cvlt::ResumeError> {
        cvlt::BrowserResume::save(self, bundle).await
    }
    async fn load(&self) -> Option<cvlt::ResumeBundle> {
        cvlt::BrowserResume::load(self).await
    }
    async fn forget(&self) -> std::result::Result<(), cvlt::ResumeError> {
        cvlt::BrowserResume::forget(self).await
    }
}

/// The native persistent unlock of one wallet binding (wallet host and account) in the
/// device's private vault directory: the OS key store under [`KEYRING_SERVICE`] where one
/// is usable, else the user-only key file.
#[cfg(not(target_arch = "wasm32"))]
pub fn native_store(dir: &std::path::Path, binding: &[u8]) -> cvlt::NativeResume {
    cvlt::NativeResume::new(dir, binding, Some(KEYRING_SERVICE))
}

/// This device's local data, erased when the device learns it was revoked.
pub trait LocalData {
    /// Erase every local vault store of this device (the network copy remains).
    fn erase(&self) -> impl std::future::Future<Output = Result<()>>;
}

/// Native local data: the device's private vault directory.
#[cfg(not(target_arch = "wasm32"))]
pub struct LocalDirectory(pub std::path::PathBuf);

#[cfg(not(target_arch = "wasm32"))]
impl LocalData for LocalDirectory {
    async fn erase(&self) -> Result<()> {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ErrorCode::Unavailable),
        }
    }
}

/// Browser local data: the vault's IndexedDB databases on the wallet origin.
#[cfg(target_arch = "wasm32")]
pub struct LocalDatabases(pub Vec<String>);

#[cfg(target_arch = "wasm32")]
impl LocalData for LocalDatabases {
    async fn erase(&self) -> Result<()> {
        let names: Vec<&str> = self.0.iter().map(String::as_str).collect();
        cvlt::erase_local_databases(&names)
            .await
            .map_err(|_| ErrorCode::Unavailable)
    }
}

/// The user's persistent-unlock choice. Default: stay unlocked across restarts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnlockPolicy {
    /// "Ask for my passkey at every start": nothing is persisted.
    pub ask_every_start: bool,
}

/// App start: the persisted unlock, with NO ceremony, unless the user opted out.
/// `None` means one passkey confirmation follows ([`DeviceUnlock::sign_in`]).
pub async fn resume<S: UnlockStore>(store: &S, policy: UnlockPolicy) -> Option<DeviceUnlock> {
    if policy.ask_every_start {
        let _ = store.forget().await;
        return None;
    }
    store.load().await.map(|bundle| DeviceUnlock {
        held: Held::Resumed(bundle),
    })
}

/// After a passkey ceremony: persist the openings of the communities this device has
/// joined (fingerprint, scope), or wipe the persisted unlock if the user opted out.
pub async fn persist<S: UnlockStore>(
    store: &S,
    unlock: &DeviceUnlock,
    joined: &[([u8; 32], &str)],
    policy: UnlockPolicy,
) -> Result<()> {
    if policy.ask_every_start {
        return store.forget().await.map_err(|_| ErrorCode::Unavailable);
    }
    let bundle = match &unlock.held {
        Held::Ceremony(wallet) => wallet
            .resume_bundle(joined)
            .map_err(|_| ErrorCode::InvalidRequest)?,
        // A resumed start already persisted its bundle; it cannot add communities.
        Held::Resumed(_) => return Ok(()),
    };
    store
        .save(&bundle)
        .await
        .map_err(|_| ErrorCode::Unavailable)
}

/// "Lock this device" (placeholder wording): wipe the persisted unlock and drop the
/// held one (zeroized). The next start needs the passkey. Ending the wallet family and
/// the community sessions is the caller's logout.
pub async fn lock<S: UnlockStore>(store: &S, unlock: DeviceUnlock) -> Result<()> {
    drop(unlock);
    store.forget().await.map_err(|_| ErrorCode::Unavailable)
}

/// The device learned it was revoked (always ordered by the user from another device):
/// wipe the unlock AND the local data. The network copy remains; restore brings it back.
pub async fn revoked<S: UnlockStore, L: LocalData>(
    store: &S,
    unlock: Option<DeviceUnlock>,
    local: &L,
) -> Result<()> {
    drop(unlock);
    let forgotten = store.forget().await;
    local.erase().await?;
    forgotten.map_err(|_| ErrorCode::Unavailable)
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

    /// One app start as the composer takes it: resume first, else ONE ceremony, then
    /// persist. Every ceremony increments `ceremonies`.
    async fn start(
        store: &cvlt::NativeResume,
        client: &mut Client<SoftwareAuthenticator>,
        policy: UnlockPolicy,
        ceremonies: &mut u32,
    ) -> DeviceUnlock {
        if let Some(unlock) = resume(store, policy).await {
            return unlock;
        }
        *ceremonies += 1;
        let (_, unlock) = DeviceUnlock::sign_in(client, options()).await.unwrap();
        persist(store, &unlock, &JOINED, policy).await.unwrap();
        unlock
    }

    const JOINED: [([u8; 32], &str); 2] = [([1; 32], "garden"), ([2; 32], "orchard")];

    /// Tests keep the wrapping key in the user-only file: never the real OS key store.
    fn store(dir: &std::path::Path) -> cvlt::NativeResume {
        cvlt::NativeResume::new(dir, b"wallet.example.test\0member", None)
    }

    #[test]
    fn native_store_names_the_client_binary_service() {
        assert_eq!(KEYRING_SERVICE, "cmeet");
        let dir = tempfile::tempdir().unwrap();
        let _ = native_store(dir.path(), b"binding");
    }

    #[test]
    fn restart_resumes_without_a_ceremony() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let mut client = wallet_passkey().await;
            let mut ceremonies = 0;
            let first = start(
                &store(dir.path()),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            assert_eq!(ceremonies, 1);
            assert!(!first.is_resumed());
            let garden = first.community_device(&[1; 32], "garden").unwrap();
            drop(first);
            // Restart: ceremony count 0 for the resumed start.
            let resumed = start(
                &store(dir.path()),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            assert_eq!(ceremonies, 1);
            assert!(resumed.is_resumed());
            assert_eq!(
                resumed
                    .community_device(&[1; 32], "garden")
                    .unwrap()
                    .value(),
                garden.value()
            );
            assert!(resumed.community_device(&[2; 32], "orchard").is_ok());
            // Narrower bundle: no wallet vault, no new community without the passkey.
            assert_eq!(
                resumed.wallet_opening().err(),
                Some(ErrorCode::Unauthorized)
            );
            assert_eq!(resumed.wallet_unlock().err(), Some(ErrorCode::Unauthorized));
            assert_eq!(
                resumed.community_device(&[3; 32], "meadow").err(),
                Some(ErrorCode::InvalidRequest)
            );
            // Persisting from a resumed start keeps the bundle as it is.
            persist(&store(dir.path()), &resumed, &[], UnlockPolicy::default())
                .await
                .unwrap();
            assert!(store(dir.path()).load().is_some());
        });
    }

    #[test]
    fn explicit_lock_forces_a_ceremony() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let mut client = wallet_passkey().await;
            let mut ceremonies = 0;
            let unlock = start(
                &store(dir.path()),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            lock(&store(dir.path()), unlock).await.unwrap();
            let next = start(
                &store(dir.path()),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            assert_eq!(ceremonies, 2);
            assert!(!next.is_resumed());
        });
    }

    #[test]
    fn opt_out_asks_for_the_passkey_at_every_start() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let mut client = wallet_passkey().await;
            let mut ceremonies = 0;
            // Unlocked across restarts first, then the user opts out: the bundle is wiped.
            start(
                &store(dir.path()),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            let ask = UnlockPolicy {
                ask_every_start: true,
            };
            for expected in 2..=3 {
                let unlock = start(&store(dir.path()), &mut client, ask, &mut ceremonies).await;
                assert_eq!(ceremonies, expected);
                assert!(!unlock.is_resumed());
                assert!(store(dir.path()).load().is_none());
            }
        });
    }

    #[test]
    fn revocation_wipes_the_unlock_and_local_data() {
        futures_executor::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let vault = root.path().join("vault");
            std::fs::create_dir_all(vault.join("records")).unwrap();
            std::fs::write(vault.join("records/checkpoint"), b"sealed").unwrap();
            let mut client = wallet_passkey().await;
            let mut ceremonies = 0;
            let unlock = start(
                &store(&vault),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            revoked(&store(&vault), Some(unlock), &LocalDirectory(vault.clone()))
                .await
                .unwrap();
            assert!(!vault.exists());
            assert!(store(&vault).load().is_none());
            start(
                &store(&vault),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            assert_eq!(ceremonies, 2);
            // Erasing data that is already gone is not an error.
            revoked(
                &store(&root.path().join("none")),
                None,
                &LocalDirectory(root.path().join("none")),
            )
            .await
            .unwrap();
        });
    }
}
