use super::*;
use futures_util::FutureExt;

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(11)
    }
}
struct RefusedAuthority;
impl ckmg::Authority for RefusedAuthority {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> std::result::Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
}
struct UnavailableRecords;
impl cvlt::Records for UnavailableRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn close_waits_for_original_store_then_revokes_retained_checkpoint_reads() {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[19; 32]).unwrap();
    let cipher = ckmg::passkey::store_cipher(&prf, "alpha").unwrap();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap();
    store
        .commit(
            store.version().unwrap(),
            [1; 32],
            &[cwst::Change::Put {
                owner: "fixture",
                key: b"checkpoint",
                value: b"private fixture",
            }],
            &[],
        )
        .await
        .unwrap();
    let read = store.read_handle("fixture").unwrap();
    let vault = cvlt::Vault::new(
        store,
        "alpha",
        Clock,
        ckmg::SystemEntropy,
        RefusedAuthority,
        UnavailableRecords,
        (),
    )
    .unwrap();
    let storage = vault.storage().clone();
    let mut door = Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([(
                Role::Member,
                BTreeSet::from(["https://alpha.example.test".into()]),
            )]),
        )
        .unwrap(),
    );
    // Internal cleanup fixture only: the real Vault has locked Keys and an
    // always-refusing authority. No public binding or member operation succeeds.
    // Cleanup must revoke even such partially initialized owned storage.
    let binding = ckmg::Binding::new("alpha", "fixture").unwrap();
    door.vaults.insert(
        "https://alpha.example.test".into(),
        Box::new(Custody {
            vault,
            inbox: cnbx::Inbox::new(binding.clone()),
            binding,
            intent: None,
        }),
    );
    let guard = storage.lock().await;
    let mut close = Box::pin(door.close_owned());
    assert!(close.as_mut().now_or_never().is_none());
    assert_eq!(
        read.read(b"checkpoint", 64).unwrap().unwrap(),
        b"private fixture"
    );
    drop(guard);
    close.await;
    assert!(!storage.lock().await.is_scope("alpha"));
    assert!(!read.is_scope("alpha"));
    assert!(read.read(b"checkpoint", 64).is_err());
}
