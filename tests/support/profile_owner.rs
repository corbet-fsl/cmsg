//! Profile custody on the retained Vault: lent only against a distinct admitted
//! command, together with the credential and block list of the same snapshot.
use super::*;
use crate::door::board::CommittedOwner;
use std::cell::RefCell;

pub(super) struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        // The owner admits custody against the system clock; Keys must agree.
        ckmg::Clock::now(&mut crate::door::custody::SystemClock)
    }
}
pub(super) struct Missing;
impl cvlt::Records for Missing {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}

// Fixture-only: Create once, Use for the exact root, and the custody lend only
// by consuming the admitted command (as MemberAuthority does).
pub(super) struct IntentAuthority {
    binding: ckmg::Binding,
    device: ckmg::PublicKey,
    root: Rc<RefCell<Option<ckmg::PublicKey>>>,
    created: bool,
    verifier: ckmg::IntentVerifier,
    lends: Rc<Cell<usize>>,
}
impl ckmg::Authority for IntentAuthority {
    async fn check(
        &mut self,
        request: ckmg::Authorization<'_>,
    ) -> std::result::Result<(), ckmg::Error> {
        if request.binding != &self.binding
            || request.device != self.device
            || request.target.is_some()
            || request.statement.is_some()
            || (request.signing.is_some() != (request.action == ckmg::Action::SignDeviceEd25519))
        {
            return Err(ckmg::Error::Unauthorized);
        }
        let root = *self.root.borrow();
        match request.action {
            ckmg::Action::Create
                if !self.created && request.root.is_none() && request.epoch == 0 =>
            {
                self.created = true;
                Ok(())
            }
            ckmg::Action::Use if request.root == root && request.epoch == 1 => Ok(()),
            ckmg::Action::LendProfileCustody if request.root == root && request.epoch == 1 => {
                self.lends.set(self.lends.get() + 1);
                self.verifier
                    .consume(&request, "https://member.example.test")
            }
            ckmg::Action::SignDeviceEd25519 if request.root == root && request.epoch == 1 => {
                self.verifier
                    .consume(&request, "https://member.example.test")
            }
            _ => Err(ckmg::Error::Unauthorized),
        }
    }
}
pub(super) type ProfileOwner = VaultBoardOwner<
    cwst::backend::Memory,
    Clock,
    ckmg::SystemEntropy,
    IntentAuthority,
    Missing,
    (),
>;

async fn open(with_intent: bool) -> (ProfileOwner, ckmg::PublicKey, Rc<Cell<usize>>) {
    open_as("fixture", with_intent).await
}

/// The same fixture for an arbitrary member string (the wave tests need the
/// canonical 96-character pseudonym).
pub(super) async fn open_as(
    member: &str,
    with_intent: bool,
) -> (ProfileOwner, ckmg::PublicKey, Rc<Cell<usize>>) {
    open_with(member, with_intent, 23).await
}

/// As `open_as`, with the passkey PRF byte chosen so that two members of one
/// test have different device keys.
pub(super) async fn open_with(
    member: &str,
    with_intent: bool,
    prf_byte: u8,
) -> (ProfileOwner, ckmg::PublicKey, Rc<Cell<usize>>) {
    const ORIGIN: &str = "https://member.example.test";
    let binding = ckmg::Binding::new("alpha", member).unwrap();
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[prf_byte; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, "alpha").unwrap();
    let root = Rc::new(RefCell::new(None));
    let lends = Rc::new(Cell::new(0));
    let cipher = ckmg::passkey::store_cipher(&prf, "alpha").unwrap();
    let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap();
    let (admission, verifier) = ckmg::intent_channel();
    let mut vault = cvlt::Vault::new(
        store,
        "alpha",
        Clock,
        ckmg::SystemEntropy,
        IntentAuthority {
            binding: binding.clone(),
            device,
            root: root.clone(),
            created: false,
            verifier,
            lends: lends.clone(),
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
            b"profile-owner-fixture",
        )
        .await
        .unwrap();
    drop(staged);
    let ckmg::Change::Created(lineage) = &receipt.change else {
        panic!("expected original genesis")
    };
    *root.borrow_mut() = Some(lineage.root);
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
            intent: with_intent.then_some(admission),
        }))),
        lifetime,
        origin: ORIGIN.into(),
        groups: None,
    };
    (owner, device, lends)
}

#[tokio::test]
async fn custody_is_lent_with_credential_and_block_list_of_the_same_snapshot() {
    let (mut owner, device, lends) = open(true).await;
    // Nothing stored yet: the committed publication's credential is re-used.
    let first = owner
        .with_profile(|parts| {
            assert!(parts.credential.is_none() && parts.blocked.is_empty());
            assert_eq!(parts.signer.public_key(), device.value());
            assert!(parts.read.store.is_scope("alpha"));
            Ok(())
        })
        .await;
    assert_eq!(first, Ok(()));
    assert_eq!(
        owner
            .store_community_credential(None, b"credential-one")
            .await,
        Ok(cvlt::CredentialWrite::Stored)
    );
    owner
        .contact_act(inbox::ContactAct {
            peer: "peer-one".into(),
            action: cnbx::OwnAction::Block,
        })
        .await
        .unwrap();
    assert_eq!(owner.is_blocked("peer-one").await, Ok(true));
    assert_eq!(owner.is_blocked("peer-two").await, Ok(false));
    // A read of any peer refuses a blocked sender before it opens anything.
    let refused = owner
        .with_current(|read| {
            Ok((
                read.refuse_blocked("peer-one"),
                read.refuse_blocked("peer-two"),
            ))
        })
        .await
        .unwrap();
    assert_eq!(refused, (Err(ErrorCode::Refused), Ok(())));
    // A second lend needs a second admission, which the owner makes itself.
    let second = owner
        .with_profile(|parts| Ok((parts.credential.clone(), parts.blocked.clone())))
        .await
        .unwrap();
    assert_eq!(second.0.as_deref(), Some(&b"credential-one"[..]));
    assert_eq!(second.1, vec!["peer-one".to_string()]);
    assert_eq!(lends.get(), 2);
}

#[tokio::test]
async fn custody_is_refused_without_the_admission_channel_or_a_closed_lifetime() {
    let (mut owner, _, lends) = open(false).await;
    let refused = owner.with_profile(|_| Ok(())).await;
    assert_eq!(refused, Err(ErrorCode::Unavailable));
    assert_eq!(lends.get(), 0);
    let (mut owner, _, lends) = open(true).await;
    owner.lifetime.close();
    assert_eq!(
        owner.with_profile(|_| Ok(())).await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        owner
            .store_community_credential(None, b"credential-one")
            .await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        owner.is_blocked("peer-one").await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(lends.get(), 0);
}

#[tokio::test]
async fn credential_replacement_is_compare_and_swap_through_the_owner() {
    let (mut owner, _, _) = open(true).await;
    owner
        .store_community_credential(None, b"one")
        .await
        .unwrap();
    assert_eq!(
        owner.store_community_credential(None, b"one").await,
        Ok(cvlt::CredentialWrite::Unchanged)
    );
    assert_eq!(
        owner
            .store_community_credential(Some(b"other"), b"two")
            .await,
        Err(ErrorCode::Reconcile)
    );
    assert_eq!(
        owner.store_community_credential(Some(b"one"), b"two").await,
        Ok(cvlt::CredentialWrite::Stored)
    );
    assert_eq!(
        owner.store_community_credential(Some(b"two"), b"").await,
        Err(ErrorCode::InvalidRequest)
    );
}
