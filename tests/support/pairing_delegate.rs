//! The A11 ceremony end to end in process: the CLI's [`Delegate`] behind a real `cvpr1.`
//! offer, the wallet's [`Delegator`] with real ckmg custody (synthetic test authority only, not
//! production membership) and a test community that checks the possession proofs exactly as
//! the server does (plain Ed25519 strict over the pairing message). The community server
//! itself is exercised in cvld's own end-to-end test.
// Single-threaded tests: the shared wallet, CLI and kept list are never borrowed re-entrantly.
#![allow(clippy::await_holding_refcell_ref)]
use super::*;
use std::cell::RefCell;
use std::rc::Rc;

const NOW: u64 = 1_000;
const CEREMONY: &[u8] = b"the one wallet confirmation";
const PRF: [u8; 32] = [0x5a; 32];

#[derive(Clone, Default)]
struct Memory(Rc<RefCell<std::collections::HashMap<ckmg::Locator, Vec<u8>>>>);
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
        Ok(NOW)
    }
}

/// Test authority: a delegation needs exactly the ceremony evidence, a target and a statement.
struct Allow;
impl ckmg::Authority for Allow {
    async fn check(
        &mut self,
        request: ckmg::Authorization<'_>,
    ) -> std::result::Result<(), ckmg::Error> {
        if request.action == ckmg::Action::DelegateDevice
            && (request.evidence != CEREMONY
                || request.target.is_none()
                || request.statement.is_none())
        {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}

type Keys = ckmg::Keys<Memory, Time, ckmg::SystemEntropy, Allow>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Row {
    Pending,
    Active,
    Revoked,
}

/// One community's registry as the test server holds it: key -> (state, delegated).
#[derive(Default)]
struct Community {
    rows: BTreeMap<[u8; 32], (Row, bool)>,
    issued: u32,
    last: Option<StepChallenge>,
}

impl Community {
    fn challenge(&mut self) -> StepChallenge {
        self.issued += 1;
        let challenge = StepChallenge {
            id: format!("challenge-{}", self.issued),
            request: vec![7; 4],
        };
        self.last = Some(challenge.clone());
        challenge
    }

    /// The server's possession check: Ed25519 strict over the typed pairing message.
    fn possessed(&self, name: &str, step: PairingStep, key: &[u8; 32], signature: &[u8]) -> bool {
        let Some(challenge) = &self.last else {
            return false;
        };
        let message = PairingPossession::new(name, step, &challenge.id, key)
            .unwrap()
            .message();
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        ckmg::verify_ed25519(key, &message, &signature).is_ok()
    }
}

/// What the wallet holds: full custody per community, the test communities, and a log of
/// everything it sent towards the CLI.
struct Wallet {
    keys: BTreeMap<String, Keys>,
    communities: BTreeMap<String, Community>,
    offers: BTreeMap<String, DelegationOffer>,
    sealed: BTreeMap<String, ckmg::SealedDelegation>,
    confirmations: usize,
    sent: Vec<Vec<u8>>,
    /// Corrupt the grant of this community (seal it to a stranger's key).
    stranger: Option<String>,
}

impl Wallet {
    async fn new(names: &[&str]) -> Self {
        let mut keys = BTreeMap::new();
        let mut communities = BTreeMap::new();
        for name in names {
            let mut custody = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Allow);
            let prf = ckmg::passkey::PrfOutput::from_bytes(&PRF).unwrap();
            let receipt = custody
                .create_scope(
                    &prf,
                    ckmg::Binding::new(name, "member").unwrap(),
                    ckmg::DeviceInfo::new("wallet", b"credential").unwrap(),
                    b"registration",
                )
                .await
                .unwrap();
            custody.acknowledge(receipt.operation).await.unwrap();
            keys.insert(name.to_string(), custody);
            communities.insert(name.to_string(), Community::default());
        }
        Self {
            keys,
            communities,
            offers: BTreeMap::new(),
            sealed: BTreeMap::new(),
            confirmations: 0,
            sent: Vec::new(),
            stranger: None,
        }
    }
}

impl DelegatorSteps for Rc<RefCell<Wallet>> {
    async fn confirm_all(&mut self, offers: Vec<(Target, DelegationOffer)>) -> Result<()> {
        let mut wallet = self.borrow_mut();
        wallet.confirmations += 1;
        for (target, offer) in offers {
            offer.check().map_err(|_| ErrorCode::Unauthorized)?;
            let purposes = [ckmg::Purpose::new(ckmg::Scope::Member, "board", 1).unwrap()];
            let custody = wallet.keys.get_mut(&target.community).unwrap();
            let (receipt, mut sealed) = custody
                .delegate_remote_device(&offer, &purposes, CEREMONY)
                .await
                .map_err(|_| ErrorCode::Unauthorized)?;
            custody.acknowledge(receipt.operation).await.unwrap();
            if wallet.stranger.as_deref() == Some(target.community.as_str()) {
                let stranger = DelegationRequest::new(&mut ckmg::SystemEntropy, None).unwrap();
                let custody = wallet.keys.get_mut(&target.community).unwrap();
                let (receipt, other) = custody
                    .delegate_remote_device(&stranger.offer(), &purposes, CEREMONY)
                    .await
                    .unwrap();
                custody.acknowledge(receipt.operation).await.unwrap();
                sealed = other;
            }
            wallet.offers.insert(target.community.clone(), offer);
            wallet.sealed.insert(target.community, sealed);
        }
        Ok(())
    }

    async fn challenge(&mut self, target: &Target) -> Result<StepChallenge> {
        let mut wallet = self.borrow_mut();
        let challenge = wallet
            .communities
            .get_mut(&target.community)
            .unwrap()
            .challenge();
        wallet.sent.push(serde_json::to_vec(&challenge).unwrap());
        Ok(challenge)
    }

    async fn register(&mut self, target: &Target, signature: Vec<u8>) -> Result<Grant> {
        let mut wallet = self.borrow_mut();
        let offer = wallet.offers[&target.community].clone();
        let key = *offer.device.value();
        let community = wallet.communities.get_mut(&target.community).unwrap();
        if !community.possessed(&target.community, PairingStep::Add, &key, &signature) {
            return Err(ErrorCode::Unauthorized);
        }
        // The previous delegate leaves the registry in the same ceremony (L2).
        if let Some(old) = offer.replaces {
            if let Some(row) = community.rows.get_mut(old.value()) {
                row.0 = Row::Revoked;
            }
        }
        community.rows.insert(key, (Row::Pending, true));
        let grant = Grant {
            user: format!("user-of-{}", target.community),
            sealed: wallet.sealed[&target.community].clone(),
        };
        wallet.sent.push(serde_json::to_vec(&grant).unwrap());
        Ok(grant)
    }

    async fn activate(&mut self, target: &Target, signature: Vec<u8>) -> Result<()> {
        let mut wallet = self.borrow_mut();
        let key = *wallet.offers[&target.community].device.value();
        let community = wallet.communities.get_mut(&target.community).unwrap();
        if !community.possessed(&target.community, PairingStep::Activate, &key, &signature) {
            return Err(ErrorCode::Unauthorized);
        }
        let row = community
            .rows
            .get_mut(&key)
            .ok_or(ErrorCode::Unauthorized)?;
        if row.0 != Row::Pending {
            return Err(ErrorCode::Unauthorized);
        }
        row.0 = Row::Active;
        Ok(())
    }
}

type Kept = Rc<RefCell<Vec<Delegated>>>;
type Cli = Delegate<Box<dyn FnMut(Vec<Delegated>) -> Result<()>>>;

/// The in-process carrier: each call is answered by the CLI's offer, as over the onion.
struct Wire(Rc<RefCell<Cli>>);
impl Channel for Wire {
    async fn call(&mut self, _: &cmsh::Address, message: &[u8]) -> Result<Vec<u8>> {
        let mut cli = self.0.borrow_mut();
        cli.serve(message, NOW).await
    }
}

fn address() -> cmsh::Address {
    cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap()
}

/// A CLI offer whose kept delegations land in `kept`; `current` is its resume bundle's keys.
fn cli(current: BTreeMap<String, ckmg::PublicKey>) -> (Rc<RefCell<Cli>>, String, Kept) {
    let (offer, link) = Offer::new(&address(), NOW).unwrap();
    let kept: Kept = Rc::default();
    let sink = kept.clone();
    let keep: Box<dyn FnMut(Vec<Delegated>) -> Result<()>> = Box::new(move |delegated| {
        sink.borrow_mut().extend(delegated);
        Ok(())
    });
    (
        Rc::new(RefCell::new(Delegate::new(offer, current, keep))),
        link,
        kept,
    )
}

fn target(name: &str) -> Target {
    Target {
        community: name.into(),
        fingerprint: [name.len() as u8; 32],
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn one_confirmation_delegates_the_cli_which_then_opens_sessions_with_no_prompt() {
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden", "orchard"]).await));
    let (delegate, link, kept) = cli(BTreeMap::new());
    let mut driver = Delegator::new(wallet.clone(), Wire(delegate.clone()));
    driver
        .run(&link, vec![target("orchard"), target("garden")])
        .await
        .unwrap();
    assert!(delegate.borrow().finished());
    let wallet = wallet.borrow();
    // ONE confirmation for both communities (one stamp, the DelegateDevice evidence).
    assert_eq!(wallet.confirmations, 1);
    let kept = kept.borrow();
    assert_eq!(kept.len(), 2);
    for entry in kept.iter() {
        let name = entry.target.community.as_str();
        let key = entry.delegation.device_public_key();
        // The CLI holds a delegation of ITS OWN K_d (the offer it made), listed as a
        // delegate and never as a device, registered ACTIVE and Delegated.
        assert_eq!(key, wallet.offers[name].device);
        assert_eq!(entry.delegation.community(), name);
        assert!(entry.delegation.lineage().delegates.contains(&key));
        assert!(!entry.delegation.lineage().devices.contains(&key));
        assert_eq!(
            wallet.communities[name].rows[key.value()],
            (Row::Active, true)
        );
        assert_eq!(entry.user, format!("user-of-{name}"));
        // 0 further prompts: K_d signs the community session (DeviceSession, Delegate class)
        // and the signature verifies as the server checks it.
        let payload = b"community nonce and time";
        let signature = entry.delegation.sign_device_session(payload).unwrap();
        let message = [ckmg::DeviceFormat::DeviceSession.tag(), &payload[..]].concat();
        ckmg::verify_ed25519(key.value(), &message, &signature).unwrap();
        // The sealed material opens only with the CLI's one-time key.
        let stranger = DelegationRequest::new(&mut ckmg::SystemEntropy, None).unwrap();
        assert!(stranger.open(&wallet.sealed[name]).is_err());
    }
    // The CLI never receives the PRF or the root: nothing the wallet sent holds the PRF, and
    // what the CLI keeps opens Delegated custody only, where every root operation refuses.
    let prf = ckmg::passkey::PrfOutput::from_bytes(&PRF).unwrap();
    for sent in &wallet.sent {
        assert!(!contains(sent, &PRF));
    }
    for entry in kept.iter() {
        let bytes = entry.delegation.to_sealed_bytes().unwrap();
        assert!(!contains(&bytes, &PRF));
        let prf_device = ckmg::passkey::device_public_key(&prf, &entry.target.community).unwrap();
        assert_ne!(entry.delegation.device_public_key(), prf_device);
        let mut custody = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Allow);
        custody.unlock_delegated(&entry.delegation).unwrap();
        assert_eq!(custody.state(), ckmg::State::Delegated);
        let purposes = [ckmg::Purpose::new(ckmg::Scope::Member, "board", 1).unwrap()];
        assert!(custody.delegate_device(&purposes, CEREMONY).await.is_err());
        let offer = DelegationRequest::new(&mut ckmg::SystemEntropy, None)
            .unwrap()
            .offer();
        assert!(custody
            .delegate_remote_device(&offer, &purposes, CEREMONY)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn re_delegation_revokes_the_previous_key_and_merges_into_the_stored_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let store = cvlt::NativeResume::new(dir.path(), b"wallet.example.test\0member", None);
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden", "orchard"]).await));
    // First ceremony: both communities, merged into an empty bundle.
    let (delegate, link, kept) = cli(BTreeMap::new());
    Delegator::new(wallet.clone(), Wire(delegate))
        .run(&link, vec![target("garden"), target("orchard")])
        .await
        .unwrap();
    let first: Vec<Delegated> = kept.borrow_mut().drain(..).collect();
    let old_garden = first[0].delegation.device_public_key();
    let orchard = first[1].delegation.device_public_key();
    merge_into(&store, first).await.unwrap();
    // Second ceremony for garden only: the CLI names its current key there.
    let current = BTreeMap::from([("garden".to_string(), old_garden)]);
    let (delegate, link, kept) = cli(current);
    Delegator::new(wallet.clone(), Wire(delegate))
        .run(&link, vec![target("garden")])
        .await
        .unwrap();
    let second: Vec<Delegated> = kept.borrow_mut().drain(..).collect();
    let new_garden = second[0].delegation.device_public_key();
    assert_ne!(new_garden, old_garden);
    // The lineage dropped the old key, the registry revoked it, the new key is active.
    assert!(!second[0]
        .delegation
        .lineage()
        .delegates
        .contains(&old_garden));
    {
        let wallet = wallet.borrow();
        let rows = &wallet.communities["garden"].rows;
        assert_eq!(rows[old_garden.value()], (Row::Revoked, true));
        assert_eq!(rows[new_garden.value()], (Row::Active, true));
        assert_eq!(wallet.confirmations, 2);
    }
    merge_into(&store, second).await.unwrap();
    // Merged, not replaced: orchard is still held, garden holds the new delegation.
    let bundle = cvlt::NativeResume::load(&store).unwrap();
    let garden = target("garden");
    let orchard_target = target("orchard");
    assert_eq!(
        bundle
            .delegation(&garden.fingerprint, "garden")
            .unwrap()
            .device_public_key(),
        new_garden
    );
    assert_eq!(
        bundle
            .delegation(&orchard_target.fingerprint, "orchard")
            .unwrap()
            .device_public_key(),
        orchard
    );
    assert_eq!(bundle.memberships().count(), 2);
}

#[tokio::test]
async fn a_grant_the_cli_cannot_open_activates_nothing_and_keeps_nothing() {
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    wallet.borrow_mut().stranger = Some("garden".into());
    let (delegate, link, kept) = cli(BTreeMap::new());
    let result = Delegator::new(wallet.clone(), Wire(delegate.clone()))
        .run(&link, vec![target("garden")])
        .await;
    assert!(result.is_err());
    assert!(kept.borrow().is_empty());
    assert!(!delegate.borrow().finished());
    // The key was registered PENDING but never activated: it expires and grants nothing.
    let wallet = wallet.borrow();
    let key = wallet.offers["garden"].device;
    assert_eq!(
        wallet.communities["garden"].rows[key.value()],
        (Row::Pending, true)
    );
}

#[tokio::test]
async fn the_cli_refuses_the_wallet_scope_and_unordered_or_oversized_targets() {
    for targets in [
        vec![target("wallet")],
        vec![],
        (0..=MAX_TARGETS)
            .map(|n| target(&format!("c{n:02}")))
            .collect(),
    ] {
        let wallet = Rc::new(RefCell::new(Wallet::new(&[]).await));
        let (delegate, link, _) = cli(BTreeMap::new());
        assert_eq!(
            Delegator::new(wallet.clone(), Wire(delegate))
                .run(&link, targets)
                .await
                .err(),
            Some(ErrorCode::InvalidRequest)
        );
        assert_eq!(wallet.borrow().confirmations, 0);
    }
    // The CLI itself refuses a duplicate or the wallet scope sent around the driver.
    let (delegate, link, _) = cli(BTreeMap::new());
    let link = Link::parse(&link).unwrap();
    for bad in [
        vec![target("garden"), target("garden")],
        vec![target("garden"), target("wallet")],
    ] {
        let (message, _) = link
            .seal_round(1, &encode(&TargetsMessage { delegate: bad }).unwrap())
            .unwrap();
        assert_eq!(
            delegate.borrow_mut().serve(&message, NOW).await.err(),
            Some(ErrorCode::InvalidRequest)
        );
    }
}
