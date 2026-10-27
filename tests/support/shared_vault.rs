//! Original Store/Vault cleanup only: Keys stay locked and Authority refuses.
#[path = "current.rs"]
mod current_tests;
#[path = "group_owner.rs"]
mod group_owner_tests;
#[path = "inbox_waves_owner.rs"]
mod inbox_waves_tests;
#[path = "profile_owner.rs"]
mod profile_owner_tests;
#[path = "room_door.rs"]
mod room_door_tests;
#[path = "voucher_thread_owner.rs"]
mod voucher_thread_tests;
use super::*;
use crate::door::board::CommittedOwner;
use futures_util::FutureExt;
use std::cell::{Cell, RefCell};

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
    let foyer = foyer::Foyer::new(foyer::fixture_transport(
        "https://keyhole.example.test",
        "keyhole.example.test",
    ));
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
            bound: Default::default(),
        }))),
        lifetime,
        origin: ORIGIN.into(),
        groups: None,
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

// Exact fixture-only Create/Use authority. Real Keys create and authenticate
// their encrypted checkpoint; this adapter provides no signing, networking or
// production membership and cannot approve another binding/device/root.
struct FixtureAuthority {
    binding: ckmg::Binding,
    device: ckmg::PublicKey,
    root: Rc<RefCell<Option<ckmg::PublicKey>>>,
    created: bool,
    gate: Rc<Mutex<()>>,
    checks: Rc<Cell<usize>>,
}
impl ckmg::Authority for FixtureAuthority {
    async fn check(
        &mut self,
        request: ckmg::Authorization<'_>,
    ) -> std::result::Result<(), ckmg::Error> {
        if request.binding != &self.binding
            || request.device != self.device
            || request.now != 11
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
        {
            return Err(ckmg::Error::Unauthorized);
        }
        let root = *self.root.borrow();
        match request.action {
            ckmg::Action::Create
                if !self.created
                    && request.root.is_none()
                    && request.epoch == 0
                    && request.evidence == b"shared-vault-fixture" =>
            {
                self.created = true;
                Ok(())
            }
            ckmg::Action::Use
                if request.root == root
                    && request.root.is_some()
                    && request.epoch == 1
                    && request.evidence.is_empty() =>
            {
                self.checks.set(self.checks.get() + 1);
                let _guard = self.gate.lock().await;
                Ok(())
            }
            _ => Err(ckmg::Error::Unauthorized),
        }
    }
}
type FixtureOwner = VaultBoardOwner<
    cwst::backend::Memory,
    Clock,
    ckmg::SystemEntropy,
    FixtureAuthority,
    Missing,
    (),
>;

async fn open_fixture() -> (FixtureOwner, Rc<Mutex<()>>, Rc<Cell<usize>>) {
    const ORIGIN: &str = "https://member.example.test";
    let binding = ckmg::Binding::new("alpha", "fixture").unwrap();
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[19; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, "alpha").unwrap();
    let root = Rc::new(RefCell::new(None));
    let gate = Rc::new(Mutex::new(()));
    let checks = Rc::new(Cell::new(0));
    let cipher = ckmg::passkey::store_cipher(&prf, "alpha").unwrap();
    let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap();
    let authority = FixtureAuthority {
        binding: binding.clone(),
        device,
        root: root.clone(),
        created: false,
        gate: gate.clone(),
        checks: checks.clone(),
    };
    let mut vault = cvlt::Vault::new(
        store,
        "alpha",
        Clock,
        ckmg::SystemEntropy,
        authority,
        Missing,
        (),
    )
    .unwrap();
    let batch = |expected, byte| cvlt::Batch {
        expected,
        operation: [byte; 32],
        mutations: vec![],
        outputs: vec![],
    };
    let staged = vault.stage_keys(batch(0, 1)).unwrap();
    let receipt = vault
        .keys()
        .create_scope(
            &prf,
            binding.clone(),
            ckmg::DeviceInfo::new("fixture", b"credential").unwrap(),
            b"shared-vault-fixture",
        )
        .await
        .unwrap();
    drop(staged);
    let ckmg::Change::Created(lineage) = &receipt.change else {
        panic!("expected original genesis")
    };
    *root.borrow_mut() = Some(lineage.root);
    // Explicit local test setup acknowledgement, never network acceptance.
    let staged = vault.stage_keys(batch(1, 2)).unwrap();
    vault.keys().acknowledge(receipt.operation).await.unwrap();
    drop(staged);
    let mut door = Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    );
    let foyer = foyer::Foyer::new(foyer::fixture_transport(
        "https://keyhole.example.test",
        "keyhole.example.test",
    ));
    door.bind_foyer(
        ORIGIN,
        Role::Member,
        foyer::Sessions::new(foyer::Scope::Community, foyer),
    )
    .unwrap();
    let (_, lifetime) = door
        .transport_authority(ORIGIN, binding.clone(), device, Clock)
        .unwrap();
    let owner = VaultBoardOwner {
        retained: Rc::new(Mutex::new(Some(Custody {
            vault,
            binding: binding.clone(),
            inbox: cnbx::Inbox::new(binding),
            intent: None,
            bound: Default::default(),
        }))),
        lifetime,
        origin: ORIGIN.into(),
        groups: None,
    };
    (owner, gate, checks)
}

#[derive(Clone, Copy)]
enum Read {
    Identity,
    Snapshot,
    History,
    Thread,
    Relation,
    Delivery,
}
const READS: [Read; 6] = [
    Read::Identity,
    Read::Snapshot,
    Read::History,
    Read::Thread,
    Read::Relation,
    Read::Delivery,
];
async fn read(owner: &mut FixtureOwner, operation: Read) -> Result<()> {
    match operation {
        Read::Identity => {
            let identity = owner.current_identity().await?;
            assert_eq!(
                identity.binding,
                ckmg::Binding::new("alpha", "fixture").unwrap()
            );
        }
        Read::Snapshot => {
            let snapshot = owner
                .snapshot(Relation {
                    conversation: [1; 32],
                    peer: "peer".into(),
                })
                .await?;
            assert!(snapshot.history.is_empty());
        }
        Read::History => assert!(owner
            .history(Conversation {
                conversation: [1; 32]
            })
            .await?
            .is_empty()),
        Read::Thread => assert!(owner
            .thread(Conversation {
                conversation: [1; 32]
            })
            .await?
            .is_empty()),
        Read::Relation => {
            owner
                .relation(Relation {
                    conversation: [1; 32],
                    peer: "peer".into(),
                })
                .await?;
        }
        Read::Delivery => assert!(owner
            .delivery(Delivery {
                conversation: [1; 32],
                message: [2; 32]
            })
            .await?
            .is_none()),
    }
    Ok(())
}

#[tokio::test]
async fn open_shared_vault_returns_original_owner_views() {
    let (mut owner, _, checks) = open_fixture().await;
    for operation in READS {
        read(&mut owner, operation).await.unwrap();
    }
    assert_eq!(checks.get(), 7); // identity checks lineage and device separately
    assert!(matches!(
        owner
            .history(Conversation {
                conversation: [0; 32]
            })
            .await,
        Err(ErrorCode::Refused)
    ));
    assert!(matches!(
        owner
            .thread(Conversation {
                conversation: [0; 32]
            })
            .await,
        Err(ErrorCode::Refused)
    ));
}

#[tokio::test]
async fn closed_shared_vault_refuses_each_read_before_checking_keys() {
    let (mut owner, _, checks) = open_fixture().await;
    owner.lifetime.close();
    for operation in READS {
        assert_eq!(
            read(&mut owner, operation).await,
            Err(ErrorCode::Unauthorized)
        );
    }
    assert_eq!(checks.get(), 0);
}

#[tokio::test]
async fn reads_queued_for_retained_vault_refuse_before_checking_keys_after_sibling_lock() {
    for operation in READS {
        let (mut owner, _, checks) = open_fixture().await;
        let retained = owner.retained.clone();
        let guard = retained.lock().await;
        let sibling = owner.clone();
        let mut pending = Box::pin(read(&mut owner, operation));
        assert!(pending.as_mut().now_or_never().is_none());
        let closing = Box::new(sibling).lock();
        drop(guard);
        assert_eq!(pending.await, Err(ErrorCode::Unauthorized));
        assert_eq!(checks.get(), 0);
        closing.await;
    }
}

#[tokio::test]
async fn reads_waiting_for_store_refuse_disclosure_after_sibling_lock() {
    for operation in READS {
        let (mut owner, _, _) = open_fixture().await;
        let storage = owner
            .retained
            .lock()
            .await
            .as_ref()
            .unwrap()
            .vault
            .storage()
            .clone();
        let guard = storage.lock().await;
        let sibling = owner.clone();
        let mut pending = Box::pin(read(&mut owner, operation));
        assert!(pending.as_mut().now_or_never().is_none());
        let closing = Box::new(sibling).lock();
        drop(guard);
        assert_eq!(pending.await, Err(ErrorCode::Unauthorized));
        closing.await;
    }
}

#[tokio::test]
async fn reads_waiting_for_original_keys_authority_refuse_disclosure_after_sibling_lock() {
    for operation in READS {
        let (mut owner, gate, checks) = open_fixture().await;
        let guard = gate.lock().await;
        let sibling = owner.clone();
        let mut pending = Box::pin(read(&mut owner, operation));
        assert!(pending.as_mut().now_or_never().is_none());
        assert_eq!(checks.get(), 1);
        let closing = Box::new(sibling).lock();
        drop(guard);
        assert_eq!(pending.await, Err(ErrorCode::Unauthorized));
        closing.await;
    }
}
