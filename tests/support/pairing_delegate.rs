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
/// The `DelegateDevice` admission evidence (production: the pre-delegation lineage digest).
const CEREMONY: &[u8] = b"the pre-delegation lineage digest";
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

/// Test authority: a delegation needs exactly that evidence, a target and a statement.
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
    /// Drop the key the CLI asks to replace (a wallet of another identity, which does not
    /// list it).
    ignore_replaces: bool,
    /// The CLI's kept delegations, counted at each activation.
    watch: Option<Kept>,
    /// How many delegations the CLI had kept at each activation.
    kept_at_activation: Vec<usize>,
    /// Every activation fails (the community is unreachable).
    fail_activation: bool,
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
            ignore_replaces: false,
            watch: None,
            kept_at_activation: Vec::new(),
            fail_activation: false,
        }
    }
}

impl DelegatorSteps for Rc<RefCell<Wallet>> {
    async fn confirm_all(&mut self, offers: Vec<(Target, DelegationOffer)>) -> Result<()> {
        let mut wallet = self.borrow_mut();
        wallet.confirmations += 1;
        for (target, mut offer) in offers {
            offer.check().map_err(|_| ErrorCode::Unauthorized)?;
            if wallet.ignore_replaces {
                offer.replaces = None;
            }
            let purposes = [ckmg::Purpose::new(ckmg::Scope::Member, "board", 1).unwrap()];
            let custody = wallet.keys.get_mut(&target.community).unwrap();
            let (receipt, mut sealed) = custody
                .delegate_remote_device(&offer, &purposes, CEREMONY)
                .await
                .map_err(|_| ErrorCode::Unauthorized)?;
            custody.acknowledge(receipt.operation).await.unwrap();
            if wallet.stranger.as_deref() == Some(target.community.as_str()) {
                let stranger =
                    DelegationRequest::new(&mut ckmg::SystemEntropy, &target.community, None)
                        .unwrap();
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
        let seen = wallet.watch.as_ref().map(|kept| kept.borrow().len());
        wallet.kept_at_activation.extend(seen);
        if wallet.fail_activation {
            return Err(ErrorCode::Unavailable);
        }
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
struct Wire<K: FnMut(Vec<Delegated>) -> Result<()>>(Rc<RefCell<Delegate<K>>>);
impl<K: FnMut(Vec<Delegated>) -> Result<()>> Channel for Wire<K> {
    async fn call(&mut self, _: &cmsh::Address, message: &[u8]) -> Result<Vec<u8>> {
        let mut cli = self.0.borrow_mut();
        cli.serve(message, NOW).await
    }
}

fn address() -> cmsh::Address {
    cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap()
}

/// A CLI offer whose kept delegations land in `kept`; `current` is what its resume bundle holds.
fn cli(current: BTreeMap<String, Held>) -> (Rc<RefCell<Cli>>, String, Kept) {
    let kept: Kept = Rc::default();
    let sink = kept.clone();
    let (delegate, link) = cli_with(
        current,
        Box::new(move |delegated| {
            sink.borrow_mut().extend(delegated);
            Ok(())
        }),
    );
    (delegate, link, kept)
}

/// A CLI offer with its own `keep`.
fn cli_with(
    current: BTreeMap<String, Held>,
    keep: Box<dyn FnMut(Vec<Delegated>) -> Result<()>>,
) -> (Rc<RefCell<Cli>>, String) {
    let (offer, link) = Offer::new(&address(), NOW).unwrap();
    (
        Rc::new(RefCell::new(Delegate::new(offer, current, keep))),
        link,
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
    // ONE confirmation for both communities (one stamp over both pairing slots).
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
        let stranger = DelegationRequest::new(&mut ckmg::SystemEntropy, name, None).unwrap();
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
        let offer = DelegationRequest::new(&mut ckmg::SystemEntropy, &entry.target.community, None)
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
    let held = Held::of(target("garden").fingerprint, &first[0].delegation);
    let orchard = first[1].delegation.device_public_key();
    merge_into(&store, first).await.unwrap();
    // Second ceremony for garden only: the CLI names its current key there.
    let current = BTreeMap::from([("garden".to_string(), held)]);
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

/// The CLI after one ceremony of `wallet` for garden: its held delegation there.
async fn delegated_garden(wallet: &Rc<RefCell<Wallet>>) -> Delegated {
    let (delegate, link, kept) = cli(BTreeMap::new());
    Delegator::new(wallet.clone(), Wire(delegate))
        .run(&link, vec![target("garden")])
        .await
        .unwrap();
    let mut kept = kept.borrow_mut();
    assert_eq!(kept.len(), 1);
    kept.remove(0)
}

/// Review a11 F1a (L2: a re-delegation replaces the member's OWN previous key). Whoever reads
/// the link of a CLI that holds garden cannot replace that delegation with one of another
/// identity: a second wallet with its own root drives the link and ignores the key it is asked
/// to replace (it does not list it). The CLI refuses the grant, signs no activation and keeps
/// nothing.
#[tokio::test]
async fn a_delegation_of_another_identity_never_replaces_the_held_one() {
    let first = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    let held = delegated_garden(&first).await;
    let other = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    other.borrow_mut().ignore_replaces = true;
    let theirs = other
        .borrow_mut()
        .keys
        .get_mut("garden")
        .unwrap()
        .lineage()
        .await
        .unwrap();
    assert_ne!(theirs.root, held.delegation.lineage().root);
    assert_ne!(theirs.identity, held.delegation.lineage().identity);
    let current = BTreeMap::from([(
        "garden".to_string(),
        Held::of(target("garden").fingerprint, &held.delegation),
    )]);
    let (delegate, link, kept) = cli(current);
    let result = Delegator::new(other.clone(), Wire(delegate.clone()))
        .run(&link, vec![target("garden")])
        .await;
    assert_eq!(result.err(), Some(ErrorCode::Unauthorized));
    assert!(kept.borrow().is_empty());
    assert!(!delegate.borrow().finished());
    let other = other.borrow();
    let key = other.offers["garden"].device;
    assert_eq!(
        other.communities["garden"].rows[key.value()],
        (Row::Pending, true)
    );
}

/// Review a11 F1a: a target that names another fingerprint for a community the CLI holds is
/// refused before anything is asked. It would add a second entry of that community, which the
/// delegated start refuses.
#[tokio::test]
async fn a_target_with_another_fingerprint_for_a_held_community_is_refused() {
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    let held = delegated_garden(&wallet).await;
    let current = BTreeMap::from([(
        "garden".to_string(),
        Held::of(target("garden").fingerprint, &held.delegation),
    )]);
    let (delegate, link, kept) = cli(current);
    let mut moved = target("garden");
    moved.fingerprint = [0xee; 32];
    let result = Delegator::new(wallet.clone(), Wire(delegate))
        .run(&link, vec![moved])
        .await;
    assert_eq!(result.err(), Some(ErrorCode::Unauthorized));
    assert!(kept.borrow().is_empty());
    assert_eq!(wallet.borrow().confirmations, 1);
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

/// One community's device configuration as a deployment file names it.
fn configuration(community: &str) -> crate::door::browser::Configuration {
    serde_json::from_value(serde_json::json!({
        "community": community, "origin": format!("https://{community}.example.test"),
        "role": "member", "primary": "community",
        "services": [{"scope": "community", "base": format!("https://api.{community}.example.test"),
            "host": format!("api.{community}.example.test")}],
    }))
    .unwrap()
}

/// L9: the delegated CLI's start finds exactly its community's delegation in the resume bundle
/// and the member's user in the users file, and every Door it builds comes from
/// `Door::from_delegation`: delegated, of the delegation's own community, never the wallet.
#[tokio::test]
async fn the_delegated_start_builds_its_door_from_the_delegation_and_the_users_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = cvlt::NativeResume::new(dir.path(), b"wallet.example.test\0delegated", None);
    // No bundle yet: this is no delegated device.
    assert!(delegated_start(&store, dir.path(), "garden")
        .await
        .unwrap()
        .is_none());
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden", "orchard"]).await));
    let (delegate, link, kept) = cli(BTreeMap::new());
    Delegator::new(wallet, Wire(delegate))
        .run(&link, vec![target("garden"), target("orchard")])
        .await
        .unwrap();
    let delegated: Vec<Delegated> = kept.borrow_mut().drain(..).collect();
    let users: BTreeMap<String, String> = delegated
        .iter()
        .map(|entry| (entry.target.community.clone(), entry.user.clone()))
        .collect();
    merge_into(&store, delegated).await.unwrap();
    // A delegation without its user is refused, not guessed.
    assert_eq!(
        delegated_start(&store, dir.path(), "garden").await.err(),
        Some(ErrorCode::Unavailable)
    );
    write_private(&dir.path().join(USERS_FILE), &encode(&users).unwrap()).unwrap();
    let start = delegated_start(&store, dir.path(), "garden")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(start.user(), "user-of-garden");
    assert!(delegated_start(&store, dir.path(), "meadow")
        .await
        .unwrap()
        .is_none());
    // The Door of the start: delegated (L9); another community's or the wallet's refused.
    let bundle = cvlt::NativeResume::load(&store).unwrap();
    let garden = bundle
        .delegation(&target("garden").fingerprint, "garden")
        .unwrap();
    let door = configuration("garden")
        .construct_delegated_with_roots(&[], garden)
        .unwrap();
    assert!(door.is_delegated());
    assert_eq!(
        configuration("orchard")
            .construct_delegated_with_roots(&[], garden)
            .err(),
        Some(ErrorCode::Unauthorized)
    );
    assert_eq!(
        configuration("wallet")
            .construct_delegated_with_roots(&[], garden)
            .err(),
        Some(ErrorCode::NeedsPasskey)
    );
    assert!(!configuration("garden").construct().unwrap().is_delegated());
    // The users file is the CLI's own: user-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join(USERS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}

/// Review a11 F3: the CLI keeps its delegations BEFORE any activation possession leaves it, so
/// no key is ever activated for a delegation the CLI did not keep.
#[tokio::test]
async fn the_cli_keeps_its_delegations_before_any_key_is_activated() {
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden", "orchard"]).await));
    let (delegate, link, kept) = cli(BTreeMap::new());
    wallet.borrow_mut().watch = Some(kept.clone());
    Delegator::new(wallet.clone(), Wire(delegate.clone()))
        .run(&link, vec![target("garden"), target("orchard")])
        .await
        .unwrap();
    assert!(delegate.borrow().finished());
    assert_eq!(wallet.borrow().kept_at_activation, vec![2, 2]);
}

/// Review a11 F3: a CLI that cannot keep what it was granted signs no activation. The keys
/// stay PENDING (they expire and grant nothing) and the wallet is never told it is done.
#[tokio::test]
async fn a_cli_that_cannot_keep_its_delegations_activates_nothing() {
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    let (delegate, link) = cli_with(BTreeMap::new(), Box::new(|_| Err(ErrorCode::Unavailable)));
    let result = Delegator::new(wallet.clone(), Wire(delegate.clone()))
        .run(&link, vec![target("garden")])
        .await;
    assert_eq!(result.err(), Some(ErrorCode::Unavailable));
    assert!(!delegate.borrow().finished());
    let wallet = wallet.borrow();
    let key = wallet.offers["garden"].device;
    assert_eq!(
        wallet.communities["garden"].rows[key.value()],
        (Row::Pending, true)
    );
}

const BINDING: &[u8] = b"wallet.example.test\0delegated";

/// The CLI's vault in `dir`, opened as `login_delegated` opens it (without the OS key store).
fn vault(dir: &std::path::Path) -> Result<CliVault> {
    CliVault::with_store(cvlt::NativeResume::new(dir, BINDING, None), dir)
}

/// One ceremony of `wallet` for `targets`, served by `cli` and settled as `login_delegated`
/// settles it: the delegated communities, or the settlement's or the ceremony's error.
async fn ceremony(
    cli: &CliVault,
    wallet: &Rc<RefCell<Wallet>>,
    targets: Vec<Target>,
) -> Result<Vec<String>> {
    let (offer, link) = Offer::new(&address(), NOW).unwrap();
    let delegate = Rc::new(RefCell::new(cli.delegate(offer)));
    let served = Delegator::new(wallet.clone(), Wire(delegate.clone()))
        .run(&link, targets)
        .await;
    let finished = delegate.borrow().finished();
    let communities = cli.settle(finished)?;
    served.map(|()| communities)
}

/// Review a11 F4: a users file that does not parse is refused before any link is shown, and
/// it is never overwritten (the other delegations would lose their user).
#[tokio::test]
async fn an_unreadable_users_file_is_refused_and_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(USERS_FILE), b"not json").unwrap();
    assert_eq!(vault(dir.path()).err(), Some(ErrorCode::Unavailable));
    assert_eq!(
        std::fs::read(dir.path().join(USERS_FILE)).unwrap(),
        b"not json"
    );
}

/// Review a11 F3: the users file is written before the resume bundle, so a failure between the
/// two never leaves a delegation without its user (the delegated start refuses that, and cmeet
/// could not start). Here the users file cannot be written: the ceremony does not complete,
/// nothing is activated and the start finds no delegation.
#[tokio::test]
async fn a_delegation_is_never_kept_without_its_user() {
    let dir = tempfile::tempdir().unwrap();
    // The users file's temporary name is taken, so writing the users file fails.
    std::fs::create_dir(dir.path().join(USERS_FILE).with_extension("tmp")).unwrap();
    let cli = vault(dir.path()).unwrap();
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    assert!(ceremony(&cli, &wallet, vec![target("garden")])
        .await
        .is_err());
    let store = cvlt::NativeResume::new(dir.path(), BINDING, None);
    assert!(delegated_start(&store, dir.path(), "garden")
        .await
        .unwrap()
        .is_none());
    let wallet = wallet.borrow();
    let key = wallet.offers["garden"].device;
    assert_eq!(
        wallet.communities["garden"].rows[key.value()],
        (Row::Pending, true)
    );
}

/// Review a11 F3: what the CLI kept for a ceremony that then does not finish (here every
/// activation fails) is withdrawn. The resume bundle and the users file are as they were, so
/// the CLI keeps no delegation whose key never became active.
#[tokio::test]
async fn an_unfinished_ceremony_leaves_the_vault_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Rc::new(RefCell::new(Wallet::new(&["garden", "orchard"]).await));
    let orchard = target("orchard");
    assert_eq!(
        ceremony(&vault(dir.path()).unwrap(), &wallet, vec![orchard.clone()])
            .await
            .unwrap(),
        vec!["orchard".to_string()]
    );
    let users = std::fs::read(dir.path().join(USERS_FILE)).unwrap();
    let store = cvlt::NativeResume::new(dir.path(), BINDING, None);
    let held = store
        .load()
        .unwrap()
        .delegation(&orchard.fingerprint, "orchard")
        .unwrap()
        .device_public_key();
    wallet.borrow_mut().fail_activation = true;
    assert_eq!(
        ceremony(&vault(dir.path()).unwrap(), &wallet, vec![target("garden")])
            .await
            .err(),
        Some(ErrorCode::Unavailable)
    );
    assert_eq!(std::fs::read(dir.path().join(USERS_FILE)).unwrap(), users);
    let bundle = store.load().unwrap();
    assert_eq!(bundle.memberships().count(), 1);
    assert_eq!(
        bundle
            .delegation(&orchard.fingerprint, "orchard")
            .unwrap()
            .device_public_key(),
        held
    );
    assert!(delegated_start(&store, dir.path(), "garden")
        .await
        .unwrap()
        .is_none());
}

/// Review a11 F1a at the CLI's vault: a ceremony of another identity leaves the held
/// delegation and the users file untouched.
#[tokio::test]
async fn a_ceremony_of_another_identity_leaves_the_vault_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let first = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    ceremony(&vault(dir.path()).unwrap(), &first, vec![target("garden")])
        .await
        .unwrap();
    let users = std::fs::read(dir.path().join(USERS_FILE)).unwrap();
    let store = cvlt::NativeResume::new(dir.path(), BINDING, None);
    let garden = target("garden");
    let held = store
        .load()
        .unwrap()
        .delegation(&garden.fingerprint, "garden")
        .unwrap()
        .device_public_key();
    let other = Rc::new(RefCell::new(Wallet::new(&["garden"]).await));
    other.borrow_mut().ignore_replaces = true;
    assert_eq!(
        ceremony(&vault(dir.path()).unwrap(), &other, vec![garden.clone()])
            .await
            .err(),
        Some(ErrorCode::Unauthorized)
    );
    assert_eq!(std::fs::read(dir.path().join(USERS_FILE)).unwrap(), users);
    assert_eq!(
        store
            .load()
            .unwrap()
            .delegation(&garden.fingerprint, "garden")
            .unwrap()
            .device_public_key(),
        held
    );
}
