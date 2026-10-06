//! Original Store/Vault cleanup only: Keys stay locked and Authority refuses.
use super::*;
use crate::door::board::CommittedOwner;
use futures_util::FutureExt;
use std::cell::Cell;

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(11)
    }
}
struct Refused;
impl ckmg::Authority for Refused {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> std::result::Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
}
struct Missing;
impl cvlt::Records for Missing {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}

#[tokio::test]
async fn sibling_board_refuses_before_lock_is_polled_and_retained_store_is_revoked_afterward() {
    const ORIGIN: &str = "https://member.example.test";
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[19; 32]).unwrap();
    let cipher = ckmg::passkey::store_cipher(&prf, "alpha").unwrap();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap();
    store
        .commit(
            0,
            [1; 32],
            &[cwst::Change::Put {
                owner: "fixture",
                key: b"record",
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
        Refused,
        Missing,
        (),
    )
    .unwrap();
    let storage = vault.storage().clone();
    let binding = ckmg::Binding::new("alpha", "fixture").unwrap();
    let mut door = Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    );
    // Original Foyer is configured but never logged in; it grants no authority.
    let foyer = foyer::Foyer::new(
        foyer::Transport::new(
            "https://keyhole.example.test".into(),
            "keyhole.example.test".into(),
            None,
        )
        .unwrap(),
    );
    door.bind_foyer(
        ORIGIN,
        Role::Member,
        foyer::Sessions::new(foyer::Scope::Community, foyer),
    )
    .unwrap();
    let (_, lifetime) = door
        .transport_authority(
            ORIGIN,
            binding.clone(),
            ckmg::PublicKey::new(ckmg::VLD0, [7; 32]),
            Clock,
        )
        .unwrap();
    let mut owner = VaultBoardOwner {
        retained: Rc::new(Mutex::new(Some(Custody {
            vault,
            binding: binding.clone(),
            inbox: cnbx::Inbox::new(binding),
            intent: None,
        }))),
        lifetime,
        origin: ORIGIN.into(),
    };
    // Internal partial-owner fixture only; public bind would reject locked Keys.
    let mut closing = Box::new(owner.clone()).lock();
    let disclosed = Cell::new(false);
    assert!(matches!(
        owner
            .with_current(|_| {
                disclosed.set(true);
                Ok(())
            })
            .await,
        Err(ErrorCode::Unauthorized)
    ));
    assert!(!disclosed.get());
    assert!(matches!(
        BoundVault::history(
            &mut owner,
            Conversation {
                conversation: [1; 32]
            }
        )
        .await,
        Err(ErrorCode::Unauthorized)
    ));
    assert!(read.is_scope("alpha"));
    let guard = storage.lock().await;
    assert!(closing.as_mut().now_or_never().is_none());
    drop(guard);
    closing.await;
    assert!(owner.retained.lock().await.is_none());
    assert_eq!(storage.lock().await.version(), Err(cwst::Error::Locked));
    assert_eq!(read.read(b"record", 64), Err(cwst::Error::Locked));
    assert!(matches!(
        owner.with_current(|_| Ok(())).await,
        Err(ErrorCode::Unauthorized)
    ));
}
