//! Restore-host preparation and one real Vault's shared lifetime, without Tor.
//! Fixture Create/Use authority proves custody composition, never production G3.
use super::*;
use crate::door::{browser, facades::BoundVault};
use std::{cell::Cell, rc::Rc};

const ORIGIN: &str = "https://alpha.example.test";

fn forum() -> Configuration {
    Configuration {
        forum_origin: "https://forum.alpha.example.test".into(),
        maximum_response_bytes: 65_536,
        timeout_millis: 5_000,
        search_candidates: 8,
        search_publication_bytes: 65_536,
        tls_root_files: vec![],
        member_origin: None,
        read_policy: ReadPolicy {
            admission_action: "fixture".into(),
        },
        #[cfg(feature = "ohttp")]
        ohttp: crate::door::ohttp::fixture_endpoint(),
    }
}

fn configuration(forum: Option<Configuration>) -> browser::Configuration {
    browser::Configuration {
        community: "alpha".into(),
        origin: ORIGIN.into(),
        role: Role::Member,
        root_board: false,
        primary: foyer::Scope::Community,
        services: vec![browser::Service {
            scope: foyer::Scope::Community,
            base: "https://keyhole.alpha.example.test".into(),
            host: "keyhole.alpha.example.test".into(),
            #[cfg(feature = "ohttp")]
            ohttp: crate::door::ohttp::fixture_endpoint(),
        }],
        forum,
        trust: None,
        login: None,
    }
}

#[tokio::test]
async fn restoring_host_retains_validated_board_until_custody_is_bound() {
    let ordinary = configuration(Some(forum())).construct().unwrap();
    assert!(ordinary.boards.contains_key(ORIGIN));
    let (door, pending) = configuration(Some(forum())).construct_restoring().unwrap();
    assert!(door.boards.is_empty());
    assert!(door.vaults.is_empty());
    let pending = pending.unwrap();
    assert_eq!(pending.policy.admission_action, "fixture");
    assert_eq!(pending.board.community(), "alpha");
    assert_eq!(pending.board.status().connection, clnk::State::Disconnected);
    let (door, pending) = configuration(None).construct_restoring().unwrap();
    assert!(pending.is_none());
    assert!(door.boards.is_empty());
}

#[tokio::test]
async fn restoring_host_refuses_invalid_forum_policy_before_creating_custody() {
    {
        let mut invalid = forum();
        invalid.read_policy.admission_action = String::new();
        assert!(matches!(
            configuration(Some(invalid)).construct_restoring(),
            Err(ErrorCode::InvalidRequest)
        ));
    }
    let mut invalid = forum();
    invalid.forum_origin = "http://forum.alpha.example.test".into();
    assert!(configuration(Some(invalid)).construct_restoring().is_err());
    let mut wire = serde_json::to_value(forum()).unwrap();
    wire.as_object_mut().unwrap().remove("read_policy");
    assert!(serde_json::from_value::<Configuration>(wire).is_err());
    let mut wire = serde_json::to_value(forum()).unwrap();
    wire["read_policy"]["accepted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Configuration>(wire).is_err());
    // The snapshot age limit is a code constant: a configuration naming it is refused.
    let mut wire = serde_json::to_value(forum()).unwrap();
    wire["read_policy"]["maximum_snapshot_age"] = serde_json::json!(60);
    assert!(serde_json::from_value::<Configuration>(wire).is_err());
}

#[tokio::test]
async fn restoring_host_refuses_admin_and_root_roles_before_deferring_forum() {
    for role in [Role::Admin, Role::Root] {
        for forum in [None, Some(forum())] {
            let mut config = configuration(forum);
            config.role = role;
            assert!(matches!(
                config.construct_restoring(),
                Err(ErrorCode::Unauthorized)
            ));
        }
    }
}

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(11)
    }
}
struct Missing;
impl cvlt::Records for Missing {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
struct FixtureAuthority {
    binding: ckmg::Binding,
    device: ckmg::PublicKey,
    root: Rc<Cell<Option<ckmg::PublicKey>>>,
    created: bool,
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
        match request.action {
            ckmg::Action::Create
                if !self.created
                    && request.root.is_none()
                    && request.epoch == 0
                    && request.evidence == b"board-fixture" =>
            {
                self.created = true;
                Ok(())
            }
            ckmg::Action::Use
                if request.root.is_some()
                    && request.root == self.root.get()
                    && request.epoch == 1
                    && request.evidence.is_empty() =>
            {
                Ok(())
            }
            _ => Err(ckmg::Error::Unauthorized),
        }
    }
}

type Owner = crate::door::facades::VaultBoardOwner<
    cwst::backend::Memory,
    Clock,
    ckmg::SystemEntropy,
    FixtureAuthority,
    Missing,
    (),
>;

async fn bind_fixture(door: &mut Door) -> (Owner, custody::CustodyLifetime) {
    let binding = ckmg::Binding::new("alpha", "fixture").unwrap();
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[29; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, "alpha").unwrap();
    let root = Rc::new(Cell::new(None));
    let cipher = ckmg::passkey::store_cipher(&prf, "alpha").unwrap();
    let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap();
    let mut vault = cvlt::Vault::new(
        store,
        "alpha",
        Clock,
        ckmg::SystemEntropy,
        FixtureAuthority {
            binding: binding.clone(),
            device,
            root: root.clone(),
            created: false,
        },
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
            b"board-fixture",
        )
        .await
        .unwrap();
    drop(staged);
    let ckmg::Change::Created(lineage) = &receipt.change else {
        panic!("original genesis required")
    };
    root.set(Some(lineage.root));
    let staged = vault.stage_keys(batch(1, 2)).unwrap();
    vault.keys().acknowledge(receipt.operation).await.unwrap();
    drop(staged);
    let (_, lifetime) = door
        .transport_authority(ORIGIN, binding, device, Clock)
        .unwrap();
    let (intent, _) = ckmg::intent_channel();
    let owner = door
        .bind_vault_with_board_owner(ORIGIN, vault, intent, lifetime.clone())
        .await
        .unwrap();
    (owner, lifetime)
}

#[tokio::test]
async fn deferred_board_and_door_share_the_same_vault_and_synchronous_lock() {
    let (mut door, pending) = configuration(Some(forum())).construct_restoring().unwrap();
    let (mut owner, lifetime) = bind_fixture(&mut door).await;
    pending
        .unwrap()
        .bind(&mut door, ORIGIN, owner.clone())
        .unwrap();
    assert!(door.boards.get(ORIGIN).unwrap().require_committed().is_ok());
    owner
        .with_current(|read| {
            assert!(read.store.is_scope("alpha"));
            assert_eq!(read.binding.member(), "fixture");
            assert_eq!((read.contact)("text"), cshm::ContactCheck::Unavailable);
            Ok(())
        })
        .await
        .unwrap();
    let closing = door.vaults.remove(ORIGIN).unwrap().lock();
    assert!(lifetime.is_closed());
    assert_eq!(
        owner.with_current(|_| Ok(())).await,
        Err(ErrorCode::Unauthorized)
    );
    closing.await;
    assert_eq!(
        owner.current_identity().await.err(),
        Some(ErrorCode::Unauthorized)
    );
}

#[tokio::test]
async fn deferred_board_never_replaces_an_existing_original_board() {
    let (mut door, pending) = configuration(Some(forum())).construct_restoring().unwrap();
    let (owner, _) = bind_fixture(&mut door).await;
    door.configure_board(ORIGIN, forum(), SystemClock).unwrap();
    assert_eq!(
        pending.unwrap().bind(&mut door, ORIGIN, owner),
        Err(ErrorCode::InvalidRequest)
    );
    assert!(matches!(
        door.boards.get(ORIGIN).unwrap().require_committed(),
        Err(ErrorCode::Unavailable)
    ));
    door.close_owned().await;
}

struct RefusingForum(Rc<Cell<usize>>);
impl clnk::Transport for RefusingForum {
    async fn post(&self, _: &str, body: Vec<u8>) -> std::result::Result<Vec<u8>, clnk::ErrorCode> {
        self.0.set(self.0.get() + 1);
        let call = cfrm::Call::decode(&body, MAX_BODY_BYTES)?;
        let error = cfrm::execute(&call).unwrap_err();
        Ok(serde_json::to_vec(&cfrm::Failure { error }).unwrap())
    }
}

#[tokio::test]
async fn watch_with_real_vault_but_no_current_foyer_refuses_before_forum_send() {
    let (mut door, _) = configuration(None).construct_restoring().unwrap();
    let (owner, _) = bind_fixture(&mut door).await;
    let calls = Rc::new(Cell::new(0));
    let board = cbrd::Board::new(
        "alpha".into(),
        clnk::Link::at(
            RefusingForum(calls.clone()),
            "alpha".into(),
            ORIGIN.into(),
            SystemClock,
        )
        .unwrap(),
    )
    .unwrap()
    .with_search(cbrd::ViewLimits {
        candidates: 8,
        publication_bytes: MAX_BODY_BYTES,
    })
    .unwrap();
    door.bind_board_with_owner(ORIGIN, board, owner, forum().read_policy)
        .unwrap();
    let now = clnk::Clock::now(&SystemClock).unwrap() / 1000;
    let token = door
        .pair_client(
            ORIGIN,
            Role::Member,
            BTreeSet::from(["board.watch".into()]),
            now,
            now + 60,
        )
        .unwrap();
    let request = br#"{"action":"board.watch","version":1,"body":{"cursor":[1]}}"#;
    let result = door
        .dispatch(ORIGIN, token.expose_for_transport(), request, now)
        .await;
    assert!(matches!(
        result,
        Output::Error {
            error: ErrorCode::Unavailable
        }
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(
        door.boards.get(ORIGIN).unwrap().status().connection,
        clnk::State::Disconnected
    );
    door.close_owned().await;
}
