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
    /// The persisted unlock v2 (U2b): one `ckmg::DeviceDelegation` per community this
    /// device had already joined. It opens community sessions as the delegate only; the
    /// wallet, account actions and a new community need the passkey (D1).
    Resumed(cvlt::ResumeBundle),
}

/// The typed refusal of a resumed start (no ceremony this run): the action needs the
/// wallet passkey (D1: wallet, account signing, stamps, new communities, restore).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedsPasskey;

impl NeedsPasskey {
    /// Its wire code where an `ErrorCode` is expected (no `From`: keeps `?` inference).
    pub const fn code(self) -> ErrorCode {
        ErrorCode::NeedsPasskey
    }
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Refused",
                    ErrorCode::Refused,
                    &__cause,
                )
            })?
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
    /// hold it: the wallet vault needs the passkey (`NeedsPasskey`).
    pub fn wallet_opening(&self) -> Result<cvlt::PreparedOpen> {
        match &self.held {
            Held::Ceremony(wallet) => wallet.wallet().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Refused",
                    ErrorCode::Refused,
                    &__cause,
                )
            }),
            Held::Resumed(_) => Err(NeedsPasskey.code()),
        }
    }

    /// One community vault's opening, without any ceremony. `fingerprint` is the
    /// community's identity (founding-key fingerprint, as the vault pins it), never
    /// its address; `scope` is the address the vault's Store is named by. A resumed
    /// start holds no opening (no PRF material): it signs sessions through
    /// [`Self::resumed_session`], anything else needs the passkey.
    pub fn community_opening(
        &self,
        fingerprint: &[u8; 32],
        scope: &str,
    ) -> Result<cvlt::PreparedOpen> {
        let wallet = self.wallet().map_err(NeedsPasskey::code)?;
        wallet.community(fingerprint, scope).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })
    }

    /// The wallet passkey's unlock. A resumed start does not hold it: the wallet vault,
    /// its records (membership index) and every account action need the passkey.
    pub fn wallet(&self) -> std::result::Result<&cvlt::WalletUnlock, NeedsPasskey> {
        match &self.held {
            Held::Ceremony(wallet) => Ok(wallet),
            Held::Resumed(_) => Err(NeedsPasskey),
        }
    }

    fn wallet_unlock(&self) -> Result<&cvlt::WalletUnlock> {
        self.wallet().map_err(NeedsPasskey::code)
    }

    /// A resumed start's custody in one joined community: this device's delegation,
    /// which signs the community device session (class `Delegate`) and nothing that
    /// needs the root, identity or passkey. A ceremony start, or a community not in the
    /// bundle, has none (`NeedsPasskey`: open it through the passkey ceremony).
    pub fn resumed_session(
        &self,
        fingerprint: &[u8; 32],
        scope: &str,
    ) -> std::result::Result<&ckmg::DeviceDelegation, NeedsPasskey> {
        match &self.held {
            Held::Resumed(bundle) => bundle.delegation(fingerprint, scope).ok_or(NeedsPasskey),
            Held::Ceremony(_) => Err(NeedsPasskey),
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
        let (mut record, cipher) =
            self.wallet_unlock()?
                .index_record(network)
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })?;
        let entry = cvlt::MembershipEntry::new(address, *fingerprint).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        cvlt::add_entry(&mut record, &cipher, &mut ckmg::SystemEntropy, entry)
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })
    }

    /// The memberships the wallet's index lists. `None`: the record is unavailable, which is
    /// not proof that there are none.
    pub async fn indexed_memberships<N: cdht::Network>(
        &self,
        network: N,
    ) -> Result<Option<cvlt::MembershipIndex>> {
        let (mut record, cipher) =
            self.wallet_unlock()?
                .index_record(network)
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })?;
        cvlt::read_index(&mut record, &cipher)
            .await
            .map(|read| read.map(|(_, index)| index))
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })
    }

    /// The community device key (lineage device) this device presents in `scope`:
    /// what the community's device-key registry binds at join. A resumed start answers
    /// for a community its bundle does not hold with the typed `NeedsPasskey`, like every
    /// other path of a resumed start (L7).
    pub fn community_device(&self, fingerprint: &[u8; 32], scope: &str) -> Result<ckmg::PublicKey> {
        if let Held::Resumed(bundle) = &self.held {
            return bundle
                .delegation(fingerprint, scope)
                .map(ckmg::DeviceDelegation::device_public_key)
                .ok_or(NeedsPasskey.code());
        }
        self.community_opening(fingerprint, scope)?
            .device()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::InvalidRequest",
                    ErrorCode::InvalidRequest,
                    &__cause,
                )
            })
    }
}

/// The OS key store service under which the native persistent unlock keeps its wrapping
/// key: the client binary's name.
pub const KEYRING_SERVICE: &str = "cmeet";

/// Persistent unlock (DESIGN-secure-convenience part 4): a device stays unlocked across
/// restarts. The persisted bundle (v2) holds one delegation per community this device
/// has joined, never `U_c` or the wallet PRF output. There is no automatic lock; the
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
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "Err ErrorCode::Unavailable", &__cause);
                Err(ErrorCode::Unavailable)
            }
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })
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

/// After a passkey ceremony: persist the delegations enrolled while it was open (one per
/// joined community, `ckmg::Keys::delegate_device` riding on that ceremony: no extra
/// prompt), or wipe the persisted unlock if the user opted out. A resumed start enrols
/// nothing: its bundle stays until the next natural ceremony.
pub async fn persist<S: UnlockStore>(
    store: &S,
    unlock: &DeviceUnlock,
    enrolled: &cvlt::ResumeBundle,
    policy: UnlockPolicy,
) -> Result<()> {
    if policy.ask_every_start {
        return store.forget().await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        });
    }
    if unlock.is_resumed() {
        return Ok(());
    }
    store.save(enrolled).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}

/// "Lock this device" (placeholder wording): wipe the persisted unlock and drop the
/// held one (zeroized). The next start needs the passkey. Ending the wallet family and
/// the community sessions is the caller's logout.
pub async fn lock<S: UnlockStore>(store: &S, unlock: DeviceUnlock) -> Result<()> {
    drop(unlock);
    store.forget().await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
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
    forgotten.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}

/// Real community delegations for tests: a `ckmg::Keys` over an in-memory store enrols one per
/// joined community, exactly as a ceremony does. Shared by the unlock and the Door tests.
#[cfg(test)]
pub(crate) mod fixture {
    /// Test-only key store of the community custody a ceremony opens.
    #[derive(Clone, Default)]
    struct Memory(
        std::rc::Rc<std::cell::RefCell<std::collections::HashMap<ckmg::Locator, Vec<u8>>>>,
    );
    impl ckmg::SecureStore for Memory {
        async fn load(
            &mut self,
            location: &ckmg::Locator,
        ) -> std::result::Result<Option<Vec<u8>>, ckmg::Error> {
            Ok(self.0.borrow().get(location).cloned())
        }
        async fn compare_exchange(
            &mut self,
            location: &ckmg::Locator,
            expected: Option<[u8; 32]>,
            next: &[u8],
        ) -> std::result::Result<ckmg::Commit, ckmg::Error> {
            let mut data = self.0.borrow_mut();
            if data.get(location).map(|v| *ckmg::hash(v).value()) != expected {
                return Ok(ckmg::Commit::Conflict);
            }
            data.insert(*location, next.to_vec());
            Ok(ckmg::Commit::Committed)
        }
    }
    #[derive(Clone)]
    struct Time;
    impl ckmg::Clock for Time {
        fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
            Ok(1000)
        }
    }
    /// Permissive test authority; not production membership.
    struct Live;
    impl ckmg::Authority for Live {
        async fn check(
            &mut self,
            _: ckmg::Authorization<'_>,
        ) -> std::result::Result<(), ckmg::Error> {
            Ok(())
        }
    }

    /// The delegations a ceremony enrols while its community custody is open (the
    /// ceremony happens anyway; `Action::DelegateDevice` rides on its evidence).
    pub(crate) async fn enrolled(joined: &[([u8; 32], &str)]) -> cvlt::ResumeBundle {
        let mut bundle = cvlt::ResumeBundle::new();
        for (fingerprint, scope) in joined {
            let prf = ckmg::passkey::PrfOutput::from_bytes(&[fingerprint[0] ^ 0x40; 32]).unwrap();
            let mut keys = ckmg::Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Live);
            let receipt = keys
                .create_scope(
                    &prf,
                    ckmg::Binding::new(scope, "member").unwrap(),
                    ckmg::DeviceInfo::new("device", b"credential").unwrap(),
                    b"registration",
                )
                .await
                .unwrap();
            keys.acknowledge(receipt.operation).await.unwrap();
            let purposes = [ckmg::Purpose::new(ckmg::Scope::Member, "board", 1).unwrap()];
            let (receipt, delegation) = keys.delegate_device(&purposes, b"ceremony").await.unwrap();
            keys.acknowledge(receipt.operation).await.unwrap();
            bundle.insert(*fingerprint, scope, delegation).unwrap();
        }
        bundle
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::fixture::enrolled;
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
        persist(store, &unlock, &enrolled(&JOINED).await, policy)
            .await
            .unwrap();
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
            assert_eq!(
                first.resumed_session(&[1; 32], "garden").err(),
                Some(NeedsPasskey)
            );
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
            // Community session with 0 prompts: the delegate signs it (class Delegate).
            let delegate = resumed.resumed_session(&[1; 32], "garden").unwrap();
            let key = delegate.device_public_key();
            assert_eq!(resumed.community_device(&[1; 32], "garden").unwrap(), key);
            let payload = b"session challenge";
            let signature = delegate.sign_device_session(payload).unwrap();
            let message = [ckmg::DeviceFormat::DeviceSession.tag(), payload].concat();
            let public: [u8; 32] = key.value()[..].try_into().unwrap();
            ckmg::verify_ed25519(&public, &message, &signature).unwrap();
            assert!(resumed.resumed_session(&[2; 32], "orchard").is_ok());
            // The delegated Door, opened from this resume with 0 prompts: it reaches the
            // foyer step (no owner is bound here, so `Unavailable`), where a full Door
            // refuses to sign as a delegate at all.
            let config = |community: &str| {
                crate::door::Configuration::new(
                    community.into(),
                    std::collections::BTreeMap::from([(
                        crate::door::Role::Member,
                        std::collections::BTreeSet::from(["https://m.example".to_string()]),
                    )]),
                )
                .unwrap()
            };
            let mut full = crate::door::Door::new(config("garden"));
            assert_eq!(
                full.open_delegated_session("https://m.example", "u", delegate)
                    .await,
                Err(ErrorCode::NeedsPasskey)
            );
            // L9: `from_delegation` is the only way to a delegated Door, and only for the
            // delegation's own community.
            assert_eq!(
                crate::door::Door::from_delegation(config("orchard"), delegate).err(),
                Some(ErrorCode::Unauthorized)
            );
            let mut restricted =
                crate::door::Door::from_delegation(config("garden"), delegate).unwrap();
            assert!(restricted.is_delegated());
            assert_eq!(
                restricted
                    .open_delegated_session("https://m.example", "u", delegate)
                    .await,
                Err(ErrorCode::Unavailable)
            );
            assert_eq!(ceremonies, 1, "no ceremony for the delegated session");
            // v2 holds no opening and no PRF: the wallet and account actions, community
            // openings and new communities answer "needs the passkey" (D1).
            assert_eq!(resumed.wallet().err(), Some(NeedsPasskey));
            assert_eq!(
                resumed.wallet_opening().err(),
                Some(ErrorCode::NeedsPasskey)
            );
            assert_eq!(resumed.wallet_unlock().err(), Some(ErrorCode::NeedsPasskey));
            assert_eq!(
                resumed.community_opening(&[1; 32], "garden").err(),
                Some(ErrorCode::NeedsPasskey)
            );
            assert_eq!(
                resumed.resumed_session(&[3; 32], "meadow").err(),
                Some(NeedsPasskey)
            );
            // The same typed state on every path of a resumed start (L7), also for a
            // community the bundle does not hold.
            assert_eq!(
                resumed.community_device(&[3; 32], "meadow").err(),
                Some(ErrorCode::NeedsPasskey)
            );
            // Persisting from a resumed start keeps the bundle as it is.
            persist(
                &store(dir.path()),
                &resumed,
                &cvlt::ResumeBundle::new(),
                UnlockPolicy::default(),
            )
            .await
            .unwrap();
            assert!(store(dir.path()).load().is_some());
            // A tampered bundle opens nothing: the next start costs one ceremony.
            let path = dir.path().join("resume.v2");
            let mut record = std::fs::read(&path).unwrap();
            let last = record.len() - 1;
            record[last] ^= 1;
            std::fs::write(&path, record).unwrap();
            assert!(resume(&store(dir.path()), UnlockPolicy::default())
                .await
                .is_none());
            let again = start(
                &store(dir.path()),
                &mut client,
                UnlockPolicy::default(),
                &mut ceremonies,
            )
            .await;
            assert_eq!(ceremonies, 2);
            assert!(!again.is_resumed());
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

    const NONCE: [u8; 32] = [9; 32];
    const ISSUED: u64 = 1000;
    const COMMUNITY: &str = "alpha";

    /// The community service's answer to `device_session_finish`, as cvld's
    /// `CommunityService::device_session_finish` gives it: the one-use nonce, then the
    /// signature over cvld's own message under `verify_strict`, then the registry row of the
    /// key (`registered`, and whether it was `revoked`). The verification is never skipped:
    /// a signature over any other bytes is `unauthorized`, whatever the row says.
    fn finish(
        registered: [u8; 32],
        revoked: bool,
        body: &serde_json::Value,
    ) -> (u16, serde_json::Value) {
        use cvld::error::{Error, ErrorBody};
        let refuse = |error: Error| {
            (
                error.http_status(),
                serde_json::to_value(ErrorBody::from(error)).unwrap(),
            )
        };
        let nonce: [u8; 32] = serde_json::from_value(body["nonce"].clone()).unwrap();
        let device: [u8; 32] = serde_json::from_value(body["device_key"].clone()).unwrap();
        let signature: Vec<u8> = serde_json::from_value(body["signature"].clone()).unwrap();
        let (Ok(key), Ok(signature)) = (
            ed25519_dalek::VerifyingKey::from_bytes(&device),
            ed25519_dalek::Signature::from_slice(&signature),
        ) else {
            return refuse(Error::Unauthorized);
        };
        let message = cvld::device_session::message(COMMUNITY, &nonce, ISSUED);
        if nonce != NONCE || key.verify_strict(&message, &signature).is_err() {
            return refuse(Error::Unauthorized);
        }
        if device != registered {
            return refuse(Error::Unauthorized);
        }
        if revoked {
            return refuse(Error::DelegateRevoked);
        }
        (
            200,
            json!({"token": "session", "user": body["user"], "role": "member",
                   "expires": ISSUED + 600}),
        )
    }

    /// A community service stand-in on a loopback port; returns its base URL.
    async fn serve_community(registered: [u8; 32], revoked: bool) -> String {
        use http_body_util::{BodyExt, Full};
        use hyper::{body::Bytes, service::service_fn, Request, Response};
        use hyper_util::rt::TokioIo;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let handler =
                        service_fn(move |request: Request<hyper::body::Incoming>| async move {
                            let name = request.uri().path().trim_start_matches("/v1/").to_owned();
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let body = serde_json::from_slice(&bytes).unwrap_or_default();
                            let (status, reply) = match name.as_str() {
                                "device_session_begin" => {
                                    (200, json!({"nonce": NONCE, "issued": ISSUED}))
                                }
                                "device_session_finish" => finish(registered, revoked, &body),
                                _ => (404, json!({})),
                            };
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(reply.to_string())))
                                    .unwrap(),
                            )
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), handler)
                        .await;
                });
            }
        });
        base
    }

    /// M1 (review 2026-11-05): the delegate signs the challenge so that the community
    /// service's own check holds. `Challenge::message` already starts with the device-session
    /// tag and ckmg prepends it again, so the payload behind the tag is what is signed. The
    /// stand-in service verifies with cvld's message and `verify_strict`; a key the row lists
    /// opens the session, a revoked delegate is told so (the distinct reason is reachable only
    /// through a signature that verified), and another key's row stays a plain refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delegated_session_verifies_at_the_community_service() {
        let bundle = fixture::enrolled(&[([1; 32], COMMUNITY)]).await;
        let delegation = bundle.delegation(&[1; 32], COMMUNITY).unwrap();
        let key: [u8; 32] = delegation.device_public_key().value().to_owned();
        let origin = "https://member.example";
        let open = |registered: [u8; 32], revoked: bool| async move {
            let base = serve_community(registered, revoked).await;
            let config = crate::door::Configuration::new(
                COMMUNITY.into(),
                std::collections::BTreeMap::from([(
                    crate::door::Role::Member,
                    std::collections::BTreeSet::from([origin.to_string()]),
                )]),
            )
            .unwrap();
            let mut door = crate::door::Door::from_delegation(config, delegation).unwrap();
            let transport = crate::door::foyer::fixture_transport(&base, "alpha.example.test");
            door.bind_foyer(
                origin,
                crate::door::Role::Member,
                crate::door::foyer::Sessions::new(
                    crate::door::foyer::Scope::Community,
                    cfyr::Foyer::new(transport),
                ),
            )
            .unwrap();
            door.open_delegated_session(origin, "member", delegation)
                .await
        };
        // A message that does not lead with the device-session tag is never signed.
        assert_eq!(
            crate::door::device_session::sign_delegated_challenge(delegation, b"other bytes"),
            Err(ErrorCode::Unauthorized)
        );
        assert_eq!(open(key, false).await, Ok(ISSUED + 600));
        assert_eq!(open(key, true).await, Err(ErrorCode::DelegateRevoked));
        assert_eq!(open([5; 32], true).await, Err(ErrorCode::Unauthorized));
    }
}
