//! The CLI delegation ceremony (A11) over the EXISTING device-pairing transport (D2: agents are
//! devices like any other): the same `cvpr1.` link, the same four HPKE-PSK sealed rounds of
//! [`super::pairing`], the same ephemeral onion carrier, the same community pairing steps
//! (`device_add` with the community's one stamp slot, then `device_activate`) and the same
//! possession proofs. Only the custody differs: the new device is DELEGATED (U2a, D1), so the
//! wallet enrols its key in `lineage.delegates` and the community registers a `Delegated` row,
//! approved by an active full device of the member (option B).
//!
//! The roles follow from who can host an onion service: the CLI (native) shows the link and
//! serves the rounds ([`Delegate`]); the wallet page opens the link and drives them
//! ([`Delegator`]). Round by round:
//!
//! 1. the wallet names the communities the member chose; the CLI answers with one
//!    [`ckmg::DelegationOffer`] per community: a fresh `K_d` and a fresh one-time HPKE key made
//!    ON the CLI (D3), plus the delegate it held before there (re-delegation, [`Held`]: the
//!    same community fingerprint only);
//! 2. after Keys enrolled each `K_d` under its single-use `Action::DelegateDevice` admission
//!    (the evidence is the pre-delegation lineage digest) and the member's ONE confirmation
//!    (the one stamp covering every community's pairing slot), the wallet sends each
//!    community's fresh add challenge; the CLI answers with `K_d`'s possession signatures;
//! 3. the wallet registers each `K_d` PENDING as `Delegated` and sends the grants: the
//!    delegation material SEALED to the CLI's one-time key, and the member's user there; the
//!    CLI opens and checks each delegation (where it holds one, the new one must be the same
//!    member's: root, identity and binding), keeps them (merged into its resume bundle, A10b)
//!    and only then answers with the activation possessions, so no key is ever activated for a
//!    delegation the CLI does not hold;
//! 4. the wallet activates the keys and says so, which finishes the ceremony. A ceremony that
//!    ends before this leaves the CLI's vault as it was (`CliVault::settle`, native).
//!
//! The CLI never receives the PRF, the root, the identity, history or anything derived from
//! them, and the wallet never receives `K_d`. A CLI that restarts loses its offer: the member
//! starts a new link. Online first: both sides are online for the whole ceremony.
use super::device_pair::StepChallenge;
use super::pairing::{Link, Offer, Received, ROUNDS};
use super::pairing_roles::Channel;
use super::*;
use ckmg::{DelegationOffer, DelegationRequest, DeviceDelegation, PairingPossession, PairingStep};
use std::collections::BTreeMap;

/// Most communities one ceremony delegates: one stamp of 16 slots, so ONE confirmation.
pub const MAX_TARGETS: usize = super::device_pair::STAMP_SLOTS;

/// One community the wallet delegates: its name and its founding-key fingerprint, which keys
/// the CLI's resume entry. Ordered by name; the wallet scope is never a target (D1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// The community name.
    pub community: String,
    /// The community's founding-key fingerprint.
    pub fingerprint: [u8; 32],
}

/// What the wallet hands the CLI for one community after the key is registered: the
/// delegation sealed to the CLI's one-time key, and the member's user in that community
/// (the CLI opens its community sessions as that user).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The member's user id in the community (`device_session_finish`).
    pub user: String,
    /// The delegation material, sealed to the CLI's offer.
    pub sealed: ckmg::SealedDelegation,
}

/// One community's value inside a round.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry<T> {
    community: String,
    value: T,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetsMessage {
    delegate: Vec<Target>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OffersMessage {
    offers: Vec<Entry<DelegationOffer>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengesMessage {
    challenges: Vec<Entry<StepChallenge>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturesMessage {
    signatures: Vec<Entry<Vec<u8>>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsMessage {
    grants: Vec<Entry<Grant>>,
    challenges: Vec<Entry<StepChallenge>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    done: u8,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })
}

/// The entries' values, once their communities are exactly those of `targets`, in order.
fn values<T>(targets: &[Target], entries: Vec<Entry<T>>) -> Result<Vec<T>> {
    if entries.len() != targets.len()
        || entries
            .iter()
            .zip(targets)
            .any(|(entry, target)| entry.community != target.community)
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(entries.into_iter().map(|entry| entry.value).collect())
}

fn entries<T>(targets: &[Target], values: Vec<T>) -> Vec<Entry<T>> {
    targets
        .iter()
        .zip(values)
        .map(|(target, value)| Entry {
            community: target.community.clone(),
            value,
        })
        .collect()
}

/// A target list the CLI accepts: 1..=[`MAX_TARGETS`] communities in strict name order,
/// never the wallet (D1: the wallet needs the passkey).
fn checked_targets(targets: &[Target]) -> Result<()> {
    if targets.is_empty()
        || targets.len() > MAX_TARGETS
        || targets
            .windows(2)
            .any(|pair| pair[0].community >= pair[1].community)
        || targets
            .iter()
            .any(|target| target.community.is_empty() || target.community == "wallet")
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}

/// K_d's possession signature over one community challenge of `step`.
fn possess(
    request: &DelegationRequest,
    community: &str,
    step: PairingStep,
    challenge: &StepChallenge,
) -> Result<Vec<u8>> {
    let device = *request.offer().device.value();
    let possession =
        PairingPossession::new(community, step, &challenge.id, &device).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
    request
        .sign_possession(&possession)
        .map(|signature| signature.to_vec())
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })
}

/// What the CLI already holds in one community (its resume bundle's entry). A new delegation
/// there must be the same member's (L2: a re-delegation replaces the member's OWN previous
/// key): the same community fingerprint, and a lineage of the same root, identity and binding.
/// Whoever reads the link therefore cannot replace the CLI's delegation with one of another
/// identity.
#[derive(Clone)]
pub struct Held {
    /// The community's founding-key fingerprint of the held entry.
    pub fingerprint: [u8; 32],
    /// The held delegation key, which a new delegation there replaces.
    pub device: ckmg::PublicKey,
    /// The held delegation's lineage.
    pub lineage: ckmg::Lineage,
}

impl Held {
    /// The held entry of `delegation`, kept under `fingerprint`.
    pub fn of(fingerprint: [u8; 32], delegation: &DeviceDelegation) -> Self {
        Self {
            fingerprint,
            device: delegation.device_public_key(),
            lineage: delegation.lineage().clone(),
        }
    }

    /// Whether `lineage` belongs to the member of this entry: same root, identity and binding.
    /// A root rotation changes the root, so a delegation of another epoch is refused as well.
    fn same_member(&self, lineage: &ckmg::Lineage) -> bool {
        lineage.root == self.lineage.root
            && lineage.identity == self.lineage.identity
            && lineage.binding == self.lineage.binding
    }
}

/// One community the CLI is delegated in, kept in round 3 before any activation is signed.
pub struct Delegated {
    /// The community and its fingerprint.
    pub target: Target,
    /// The member's user there.
    pub user: String,
    /// The CLI's delegation: K_d, the granted epoch's Store cipher and member purposes.
    pub delegation: DeviceDelegation,
}

/// The CLI's side of one ceremony: the open offer behind the link it shows and the requests it
/// made. `keep` is called in round 3 with every delegation of this ceremony, once each is
/// opened and checked and BEFORE any activation possession leaves the CLI (the caller persists
/// them); its failure leaves round 3 unanswered, so no key is activated for a delegation the
/// CLI does not hold. Only round 4, the wallet's word that every key is ACTIVE, finishes the
/// ceremony: a caller whose ceremony ends unfinished withdraws what it kept
/// (`CliVault::settle`, native).
pub struct Delegate<K: FnMut(Vec<Delegated>) -> Result<()>> {
    offer: Offer,
    /// What the CLI holds per community (from its resume bundle): a new delegation there
    /// replaces that key and must be the same member's.
    current: BTreeMap<String, Held>,
    targets: Vec<Target>,
    requests: Vec<DelegationRequest>,
    /// `keep` accepted this ceremony's delegations.
    kept: bool,
    keep: K,
}

impl<K: FnMut(Vec<Delegated>) -> Result<()>> Delegate<K> {
    /// Serve `offer`; `current` maps each community the CLI already holds a delegation in to
    /// that entry.
    pub fn new(offer: Offer, current: BTreeMap<String, Held>, keep: K) -> Self {
        Self {
            offer,
            current,
            targets: Vec::new(),
            requests: Vec::new(),
            kept: false,
            keep,
        }
    }

    /// Unix seconds this offer stays open.
    pub fn expires(&self) -> u64 {
        self.offer.expires()
    }

    /// Every round is answered: the delegations are kept and their keys ACTIVE.
    pub fn finished(&self) -> bool {
        self.offer.finished()
    }

    /// Answer one sealed message of the wallet: the sealed reply to send back.
    pub async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>> {
        let (round, payload, reply_to) = match self.offer.open_round(message, now)? {
            Received::Repeat(reply) => return Ok(reply),
            Received::Round {
                round,
                payload,
                reply_to,
            } => (round, payload, reply_to),
        };
        let reply = match round {
            1 => {
                let TargetsMessage { delegate } = decode(&payload)?;
                checked_targets(&delegate)?;
                let mut requests = Vec::with_capacity(delegate.len());
                for target in &delegate {
                    let held = self.current.get(&target.community);
                    // A held community keeps its fingerprint: another one would make a second
                    // entry of the same community, which the delegated start refuses.
                    if held.is_some_and(|held| held.fingerprint != target.fingerprint) {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let replaces = held.map(|held| held.device);
                    requests.push(
                        DelegationRequest::new(
                            &mut ckmg::SystemEntropy,
                            &target.community,
                            replaces,
                        )
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "ErrorCode::Unavailable",
                                ErrorCode::Unavailable,
                                &__cause,
                            )
                        })?,
                    );
                }
                let offers = requests.iter().map(DelegationRequest::offer).collect();
                let reply = encode(&OffersMessage {
                    offers: entries(&delegate, offers),
                })?;
                self.targets = delegate;
                self.requests = requests;
                reply
            }
            2 => {
                let ChallengesMessage { challenges } = decode(&payload)?;
                let challenges = values(&self.targets, challenges)?;
                let mut signatures = Vec::with_capacity(challenges.len());
                for ((target, request), challenge) in
                    self.targets.iter().zip(&self.requests).zip(&challenges)
                {
                    signatures.push(possess(
                        request,
                        &target.community,
                        PairingStep::Add,
                        challenge,
                    )?);
                }
                encode(&SignaturesMessage {
                    signatures: entries(&self.targets, signatures),
                })?
            }
            3 => {
                let GrantsMessage { grants, challenges } = decode(&payload)?;
                let grants = values(&self.targets, grants)?;
                let challenges = values(&self.targets, challenges)?;
                // Every delegation opens and names its community before any activation is
                // signed: a key is never activated for material the CLI cannot use. Where the
                // CLI holds a delegation, the new one must be the same member's.
                let mut opened = Vec::with_capacity(grants.len());
                for ((target, request), grant) in
                    self.targets.iter().zip(&self.requests).zip(&grants)
                {
                    let delegation = request.open(&grant.sealed).map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Unauthorized",
                            ErrorCode::Unauthorized,
                            &__cause,
                        )
                    })?;
                    if delegation.community() != target.community
                        || grant.user.is_empty()
                        || self
                            .current
                            .get(&target.community)
                            .is_some_and(|held| !held.same_member(delegation.lineage()))
                    {
                        return Err(ErrorCode::Unauthorized);
                    }
                    opened.push((grant.user.clone(), delegation));
                }
                let mut signatures = Vec::with_capacity(challenges.len());
                for ((target, request), challenge) in
                    self.targets.iter().zip(&self.requests).zip(&challenges)
                {
                    signatures.push(possess(
                        request,
                        &target.community,
                        PairingStep::Activate,
                        challenge,
                    )?);
                }
                // Kept BEFORE any activation possession leaves the CLI: if keeping fails the
                // round stays unanswered and no key is activated for a delegation the CLI
                // does not hold.
                let delegated = self
                    .targets
                    .iter()
                    .cloned()
                    .zip(opened)
                    .map(|(target, (user, delegation))| Delegated {
                        target,
                        user,
                        delegation,
                    })
                    .collect();
                (self.keep)(delegated)?;
                self.kept = true;
                encode(&SignaturesMessage {
                    signatures: entries(&self.targets, signatures),
                })?
            }
            4 => {
                let Done { done } = decode(&payload)?;
                if done != 1 || !self.kept {
                    return Err(ErrorCode::InvalidRequest);
                }
                // The requests held K_d before the delegations did; nothing of them is needed.
                self.requests.clear();
                encode(&Done { done: 1 })?
            }
            _ => return Err(ErrorCode::Refused),
        };
        self.offer.answer(message, &reply_to, &reply)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<K: FnMut(Vec<Delegated>) -> Result<()>> super::pairing_onion::Serve for Delegate<K> {
    async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>> {
        Delegate::serve(self, message, now).await
    }
    fn finished(&self) -> bool {
        Delegate::finished(self)
    }
    fn expires(&self) -> u64 {
        Delegate::expires(self)
    }
}

/// What the wallet does for the ceremony. Each method is one authority-bearing or
/// human-facing step; a failure ends the ceremony (the member starts a new link).
#[allow(async_fn_in_trait)]
pub trait DelegatorSteps {
    /// Enrol every offer's `K_d` (Keys, under its single-use `Action::DelegateDevice`
    /// admission, whose evidence is the pre-delegation lineage digest), then the member's ONE
    /// confirmation over every offer together: the one stamp that covers each community's
    /// pairing slot of its `K_d`. Each offer is checked before anything is asked of the member.
    async fn confirm_all(&mut self, offers: Vec<(Target, DelegationOffer)>) -> Result<()>;
    /// A fresh one-use community challenge of `target`, fetched after the round's human
    /// steps so it is fresh when the CLI signs it.
    async fn challenge(&mut self, target: &Target) -> Result<StepChallenge>;
    /// Register `K_d` PENDING as `Delegated` (`signature` proves possession over the add
    /// challenge; an active full device of the member approves), revoke the delegate it
    /// replaces, publish the lineage revision; answer with the grant.
    async fn register(&mut self, target: &Target, signature: Vec<u8>) -> Result<Grant>;
    /// Make the PENDING `K_d` ACTIVE (`signature` over the activation challenge).
    async fn activate(&mut self, target: &Target, signature: Vec<u8>) -> Result<()>;
}

/// The wallet's side: it opens the CLI's link and drives the four rounds.
pub struct Delegator<S: DelegatorSteps, C: Channel> {
    steps: S,
    channel: C,
}

impl<S: DelegatorSteps, C: Channel> Delegator<S, C> {
    /// Drive the ceremony with `steps` over `channel`.
    pub fn new(steps: S, channel: C) -> Self {
        Self { steps, channel }
    }

    /// Take the steps back.
    pub fn into_steps(self) -> S {
        self.steps
    }

    async fn exchange(&mut self, link: &Link, round: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let (message, awaiting) = link.seal_round(round, payload)?;
        let reply = self.channel.call(link.address(), &message).await?;
        Ok(awaiting.open_reply(&reply)?.to_vec())
    }

    async fn challenges(&mut self, targets: &[Target]) -> Result<Vec<Entry<StepChallenge>>> {
        let mut challenges = Vec::with_capacity(targets.len());
        for target in targets {
            challenges.push(self.steps.challenge(target).await?);
        }
        Ok(entries(targets, challenges))
    }

    /// Delegate `targets` to the CLI behind `link` (the `cvpr1.` text it showed).
    pub async fn run(&mut self, link: &str, mut targets: Vec<Target>) -> Result<()> {
        targets.sort();
        checked_targets(&targets)?;
        let link = Link::parse(link)?;
        let OffersMessage { offers } = decode(
            &self
                .exchange(
                    &link,
                    1,
                    &encode(&TargetsMessage {
                        delegate: targets.clone(),
                    })?,
                )
                .await?,
        )?;
        let offers = values(&targets, offers)?;
        self.steps
            .confirm_all(targets.iter().cloned().zip(offers).collect())
            .await?;
        let challenges = self.challenges(&targets).await?;
        let SignaturesMessage { signatures } = decode(
            &self
                .exchange(&link, 2, &encode(&ChallengesMessage { challenges })?)
                .await?,
        )?;
        let mut grants = Vec::with_capacity(targets.len());
        for (target, signature) in targets.iter().zip(values(&targets, signatures)?) {
            grants.push(self.steps.register(target, signature).await?);
        }
        let challenges = self.challenges(&targets).await?;
        let SignaturesMessage { signatures } = decode(
            &self
                .exchange(
                    &link,
                    3,
                    &encode(&GrantsMessage {
                        grants: entries(&targets, grants),
                        challenges,
                    })?,
                )
                .await?,
        )?;
        for (target, signature) in targets.iter().zip(values(&targets, signatures)?) {
            self.steps.activate(target, signature).await?;
        }
        let Done { done } = decode(
            &self
                .exchange(&link, ROUNDS, &encode(&Done { done: 1 })?)
                .await?,
        )?;
        if done != 1 {
            return Err(ErrorCode::Reconcile);
        }
        Ok(())
    }
}

/// Merge the delegations of one ceremony into the CLI's persisted resume bundle (L2): every
/// community already held keeps its entry unless this ceremony delegated it again, in which
/// case the new delegation replaces the old one (whose key the wallet revoked).
pub async fn merge_into<S: super::unlock_once::UnlockStore>(
    store: &S,
    delegated: Vec<Delegated>,
) -> Result<()> {
    let mut bundle = store.load().await.unwrap_or_default();
    insert_all(&mut bundle, delegated)?;
    store.save(&bundle).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}

/// Insert each delegation into `bundle`, replacing the entry of its community and fingerprint.
fn insert_all(bundle: &mut cvlt::ResumeBundle, delegated: Vec<Delegated>) -> Result<()> {
    for entry in delegated {
        bundle
            .insert(
                entry.target.fingerprint,
                &entry.target.community,
                entry.delegation,
            )
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::InvalidRequest",
                    ErrorCode::InvalidRequest,
                    &__cause,
                )
            })?;
    }
    Ok(())
}

/// What `bundle` holds per community. A delegation `pending` lists (written ahead, its
/// activation never seen) is not held: a new ceremony there delegates afresh.
#[cfg(not(target_arch = "wasm32"))]
fn held_in(bundle: &cvlt::ResumeBundle, pending: &Pending) -> BTreeMap<String, Held> {
    bundle
        .memberships()
        .filter_map(|(fingerprint, scope)| {
            bundle
                .delegation(fingerprint, scope)
                .filter(|delegation| pending.get(scope) != Some(&delegation.device_public_key()))
                .map(|delegation| (scope.to_owned(), Held::of(*fingerprint, delegation)))
        })
        .collect()
}

/// The fragment route of the wallet-origin page that opens a CLI delegation link. The
/// `cvpr1.` link travels in the fragment, so no server ever receives it.
pub const PAGE_ROUTE: &str = "#/cli-delegate/";

/// What the CLI shows: the wallet-origin page with the link in its fragment.
pub fn page_link(page: &str, link: &str) -> String {
    format!("{page}{PAGE_ROUTE}{link}")
}

/// The member's user per delegated community, kept beside the resume bundle (the CLI opens
/// its community sessions as that user). Public identifiers only, in the CLI's private vault
/// directory.
pub const USERS_FILE: &str = "delegated-users.json";

/// The delegations a ceremony wrote ahead whose activation the CLI has not seen yet: per
/// community, the delegation key. Kept beside the resume bundle from round 3 until round 4
/// arrives. After a crash between the two the entry stays: such a delegation is not held for a
/// new ceremony, and the next start keeps it only if the server knows its key as active.
pub const PENDING_FILE: &str = "delegated-pending.json";

/// The pending file's entries: community -> delegation key.
#[cfg(not(target_arch = "wasm32"))]
type Pending = BTreeMap<String, ckmg::PublicKey>;

/// The CLI's delegations of one deployment (native): the resume bundle of its binding and the
/// users and pending files beside it, in its private vault directory ([`login_delegated`]).
///
/// A ceremony's delegations are written ahead in round 3, before any key is activated: the
/// pending file first (they are unconfirmed until round 4), then the users file, then the
/// bundle, so a failure between two writes never leaves a delegation without its user (the
/// delegated start would refuse it). Every write replaces its file atomically: a temporary
/// file in the same directory, synced, renamed over the file, and the directory synced. What
/// the vault held when it was opened is remembered: a ceremony that ends without round 4
/// (failed, expired, refused, or cancelled, which drops the vault unsettled) restores it.
#[cfg(not(target_arch = "wasm32"))]
pub struct CliVault {
    store: cvlt::NativeResume,
    vault: std::path::PathBuf,
    held: BTreeMap<String, Held>,
    /// The users file as it was (`None`: absent).
    users: Option<Vec<u8>>,
    /// Its entries.
    known: BTreeMap<String, String>,
    /// The pending file as it was (`None`: absent).
    pending_file: Option<Vec<u8>>,
    /// Its entries.
    pending: Pending,
    /// The resume bundle as it was (`None`: none).
    previous: Option<cvlt::ResumeBundle>,
    /// This ceremony's delegations (community and key), once written ahead.
    kept: std::cell::RefCell<Vec<(String, ckmg::PublicKey)>>,
    /// Something of this ceremony was (or may have been) written.
    written: std::cell::Cell<bool>,
    /// The ceremony is settled: finished, or restored.
    settled: std::cell::Cell<bool>,
}

#[cfg(not(target_arch = "wasm32"))]
impl CliVault {
    /// The vault of the resume binding `binding` in the private directory `vault`. A users or
    /// pending file that cannot be read or does not parse is refused (`Unavailable`) and never
    /// overwritten: the other delegations would lose their user.
    pub fn open(vault: &std::path::Path, binding: &[u8]) -> Result<Self> {
        Self::with_store(super::unlock_once::native_store(vault, binding), vault)
    }

    fn with_store(store: cvlt::NativeResume, vault: &std::path::Path) -> Result<Self> {
        let users = read_file(&vault.join(USERS_FILE))?;
        let known = users
            .as_deref()
            .map(parse_json)
            .transpose()?
            .unwrap_or_default();
        let pending_file = read_file(&vault.join(PENDING_FILE))?;
        let pending: Pending = pending_file
            .as_deref()
            .map(parse_json)
            .transpose()?
            .unwrap_or_default();
        let previous = store.load();
        let held = previous
            .as_ref()
            .map(|bundle| held_in(bundle, &pending))
            .unwrap_or_default();
        Ok(Self {
            store,
            vault: vault.to_owned(),
            held,
            users,
            known,
            pending_file,
            pending,
            previous,
            kept: Default::default(),
            written: Default::default(),
            settled: Default::default(),
        })
    }

    /// The CLI's side of one ceremony behind `offer`; it keeps into this vault.
    pub fn delegate(
        &self,
        offer: Offer,
    ) -> Delegate<impl FnMut(Vec<Delegated>) -> Result<()> + '_> {
        Delegate::new(offer, self.held.clone(), move |delegated| {
            self.keep(delegated)
        })
    }

    /// Write one ceremony's delegations ahead: the pending file, the users file, the bundle.
    fn keep(&self, delegated: Vec<Delegated>) -> Result<()> {
        let mut users = self.known.clone();
        let mut pending = self.pending.clone();
        let mut kept = Vec::with_capacity(delegated.len());
        for entry in &delegated {
            let key = entry.delegation.device_public_key();
            users.insert(entry.target.community.clone(), entry.user.clone());
            pending.insert(entry.target.community.clone(), key);
            kept.push((entry.target.community.clone(), key));
        }
        let (users, pending) = (encode(&users)?, encode(&pending)?);
        let mut bundle = self.store.load().unwrap_or_default();
        // A delegation of these communities whose activation was never seen gives way.
        for (community, _) in &kept {
            drop_pending(&mut bundle, &self.pending, community);
        }
        insert_all(&mut bundle, delegated)?;
        self.written.set(true);
        write_private(&self.vault.join(PENDING_FILE), &pending)?;
        write_private(&self.vault.join(USERS_FILE), &users)?;
        save_bundle(&self.store, &self.vault, &bundle)?;
        *self.kept.borrow_mut() = kept;
        Ok(())
    }

    /// After the ceremony: whether it `finished` (round 4: every key is ACTIVE). A finished one
    /// returns the delegated communities and confirms them; an unfinished one restores what the
    /// vault held when it was opened and returns none.
    pub fn settle(&self, finished: bool) -> Result<Vec<String>> {
        if self.settled.get() {
            return Ok(Vec::new());
        }
        if finished {
            self.settled.set(true);
            let kept = self.kept.take();
            // Best effort: a start that still finds an entry pending asks the server.
            let _ = confirm_pending(&self.vault, &kept);
            return Ok(kept.into_iter().map(|(community, _)| community).collect());
        }
        if self.written.get() {
            self.restore()?;
        }
        self.settled.set(true);
        Ok(Vec::new())
    }

    /// Put back what the vault held when it was opened: the bundle first and the pending file
    /// last, so a delegation written ahead stays listed as pending while it exists.
    fn restore(&self) -> Result<()> {
        match &self.previous {
            Some(bundle) => save_bundle(&self.store, &self.vault, bundle)?,
            None => forget_bundle(&self.store, &self.vault)?,
        }
        put_file(&self.vault.join(USERS_FILE), self.users.as_deref())?;
        put_file(&self.vault.join(PENDING_FILE), self.pending_file.as_deref())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for CliVault {
    /// A ceremony dropped unsettled (cancelled) is restored like any unfinished one.
    fn drop(&mut self) {
        if self.written.get() && !self.settled.get() {
            let _ = self.restore();
        }
    }
}

/// Drop from `bundle` the delegation of `community` that `pending` lists as never activated.
#[cfg(not(target_arch = "wasm32"))]
fn drop_pending(bundle: &mut cvlt::ResumeBundle, pending: &Pending, community: &str) {
    let Some(key) = pending.get(community) else {
        return;
    };
    let unconfirmed: Vec<[u8; 32]> = bundle
        .memberships()
        .filter(|(fingerprint, scope)| {
            *scope == community
                && bundle
                    .delegation(fingerprint, scope)
                    .is_some_and(|delegation| delegation.device_public_key() == *key)
        })
        .map(|(fingerprint, _)| *fingerprint)
        .collect();
    for fingerprint in unconfirmed {
        bundle.remove(&fingerprint, community);
    }
}

/// Remove the `kept` entries from the pending file of `vault` (their activation was seen).
#[cfg(not(target_arch = "wasm32"))]
fn confirm_pending(vault: &std::path::Path, kept: &[(String, ckmg::PublicKey)]) -> Result<()> {
    let path = vault.join(PENDING_FILE);
    let mut pending: Pending = read_file(&path)?
        .as_deref()
        .map(parse_json)
        .transpose()?
        .unwrap_or_default();
    for (community, key) in kept {
        if pending.get(community) == Some(key) {
            pending.remove(community);
        }
    }
    put_pending(&path, &pending)
}

/// The pending file at `path`: written, or removed when nothing is pending.
#[cfg(not(target_arch = "wasm32"))]
fn put_pending(path: &std::path::Path, pending: &Pending) -> Result<()> {
    if pending.is_empty() {
        return put_file(path, None);
    }
    write_private(path, &encode(pending)?)
}

/// `cmeet login --delegated`: the CLI's side of the ceremony on this device. It makes the
/// offer behind a fresh ephemeral onion service (never a member key), hands the page link to
/// `show`, serves the four rounds until they finish or the offer expires, and merges what it
/// was granted into the native resume bundle of `binding` in `vault` (L2) before any key is
/// activated ([`CliVault`]); a ceremony that does not finish, including one cancelled by
/// dropping this future, leaves the vault as it was. Returns the delegated communities.
/// Nothing here holds the PRF, a root or a wallet session.
#[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
pub async fn login_delegated(
    tor: &super::native::deployment::TorDeployment,
    page: &str,
    binding: &[u8],
    show: impl FnOnce(&str),
    clock: impl Fn() -> u64,
) -> Result<Vec<String>> {
    use super::pairing_onion::{ephemeral::ephemeral_tor, OnionOffer};
    let cli = CliVault::open(&tor.store_directory, binding)?;
    // The offer's own Tor state, apart from the member's community onion.
    let ephemeral = ephemeral_tor(
        tor_rtcompat::tokio::TokioRustlsRuntime::current().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?,
        Default::default(),
        ctrn::arti::Directories {
            state: tor.state_directory.join("cli-delegation"),
            cache: tor.cache_directory.join("cli-delegation"),
        },
        ctrn::Limits {
            streams: tor.transport.streams,
            bootstrap_ms: tor.transport.bootstrap_ms,
            operation_ms: tor.transport.operation_ms,
        },
    )
    .await?;
    let (service, offer, link) = OnionOffer::open(&*ephemeral.backend, clock()).await?;
    let mut delegate = cli.delegate(offer);
    show(&page_link(page, &link));
    let served = service.serve(&mut delegate, &clock).await;
    let communities = cli.settle(delegate.finished())?;
    served?;
    Ok(communities)
}

/// The resume binding of a delegated CLI: the wallet-origin login page's origin, apart from
/// any passkey device of the same deployment. `None` without a login page.
pub fn cli_binding(runtime: &super::browser::Configuration) -> Option<Vec<u8>> {
    let page = runtime.login.as_ref()?;
    Some([page.origin.as_bytes(), b"\0delegated"].concat())
}

/// The file at `path` as it is (`None`: absent); `Unavailable` when it cannot be read.
#[cfg(not(target_arch = "wasm32"))]
fn read_file(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(__cause) => Err(crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )),
    }
}

/// The entries of a users or pending file; `Unavailable` when it does not parse.
#[cfg(not(target_arch = "wasm32"))]
fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}

/// The users file of `vault`: empty when absent; `Unavailable` when it cannot be read or
/// does not parse.
#[cfg(not(target_arch = "wasm32"))]
fn read_users(vault: &std::path::Path) -> Result<BTreeMap<String, String>> {
    Ok(read_file(&vault.join(USERS_FILE))?
        .as_deref()
        .map(parse_json)
        .transpose()?
        .unwrap_or_default())
}

/// Seal `bundle` into `store` (cvlt replaces its record atomically) and sync `vault`, so the
/// rename is durable too.
#[cfg(not(target_arch = "wasm32"))]
fn save_bundle(
    store: &cvlt::NativeResume,
    vault: &std::path::Path,
    bundle: &cvlt::ResumeBundle,
) -> Result<()> {
    store.save(bundle).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    sync_directory(vault)
}

/// Delete the bundle of `store` and sync `vault`.
#[cfg(not(target_arch = "wasm32"))]
fn forget_bundle(store: &cvlt::NativeResume, vault: &std::path::Path) -> Result<()> {
    store.forget().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    sync_directory(vault)
}

/// Make the file at `path` hold `bytes` (atomically), or remove it for `None`.
#[cfg(not(target_arch = "wasm32"))]
fn put_file(path: &std::path::Path, bytes: Option<&[u8]>) -> Result<()> {
    if let Some(bytes) = bytes {
        return write_private(path, bytes);
    }
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &error,
            ));
        }
    }
    sync_directory(path.parent().unwrap_or(std::path::Path::new(".")))
}

/// What a delegated CLI holds for one community: its delegation (sealed form, for every
/// rebuild of the Door), the member's user there (from [`USERS_FILE`]), and whether its
/// activation was never seen ([`PENDING_FILE`]).
#[cfg(not(target_arch = "wasm32"))]
pub struct DelegatedStart {
    sealed: Zeroizing<Vec<u8>>,
    user: String,
    provisional: Option<Provisional>,
}

/// A delegation written ahead whose activation the CLI never saw (it crashed between round 3
/// and round 4). The first session open decides: the server knows the key as active (it is
/// confirmed and kept), or it refuses the key (it is removed from the vault).
#[cfg(not(target_arch = "wasm32"))]
struct Provisional {
    store: cvlt::NativeResume,
    vault: std::path::PathBuf,
    fingerprint: [u8; 32],
    community: String,
    key: ckmg::PublicKey,
    verdict: std::cell::Cell<Verdict>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Open,
    Confirmed,
    Discarded,
}

#[cfg(not(target_arch = "wasm32"))]
impl Provisional {
    /// The server knows the key as active: it is no longer pending.
    fn confirm(&self) -> Result<()> {
        confirm_pending(&self.vault, &[(self.community.clone(), self.key)])
    }

    /// The server refuses the key: remove the delegation, then its user, then the pending
    /// entry (each write atomic).
    fn discard(&self) -> Result<()> {
        if let Some(mut bundle) = self.store.load() {
            bundle.remove(&self.fingerprint, &self.community);
            if bundle.is_empty() {
                forget_bundle(&self.store, &self.vault)?;
            } else {
                save_bundle(&self.store, &self.vault, &bundle)?;
            }
        }
        let mut users = read_users(&self.vault)?;
        if users.remove(&self.community).is_some() {
            let path = self.vault.join(USERS_FILE);
            if users.is_empty() {
                put_file(&path, None)?;
            } else {
                write_private(&path, &encode(&users)?)?;
            }
        }
        self.confirm()
    }
}

/// The delegated CLI's start (L9) for `community`: its delegation from the resume bundle in
/// `store` and its user from `vault`'s users file. `None` when this device holds no
/// delegation there (it is no delegated device of that community); a delegation without a
/// user, or two of the same community, is refused. A delegation still pending (a crash
/// between round 3 and round 4) is tried once: see [`Provisional`].
#[cfg(not(target_arch = "wasm32"))]
pub fn delegated_start(
    store: cvlt::NativeResume,
    vault: &std::path::Path,
    community: &str,
) -> Result<Option<DelegatedStart>> {
    let Some(bundle) = store.load() else {
        return Ok(None);
    };
    let held: Vec<(&[u8; 32], &DeviceDelegation)> = bundle
        .memberships()
        .filter(|(_, scope)| *scope == community)
        .filter_map(|(fingerprint, scope)| {
            bundle
                .delegation(fingerprint, scope)
                .map(|delegation| (fingerprint, delegation))
        })
        .collect();
    let (fingerprint, delegation) = match held.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        _ => return Err(ErrorCode::InvalidRequest),
    };
    let user = read_users(vault)?
        .remove(community)
        .ok_or(ErrorCode::Unavailable)?;
    let pending: Pending = read_file(&vault.join(PENDING_FILE))?
        .as_deref()
        .map(parse_json)
        .transpose()?
        .unwrap_or_default();
    let sealed = delegation.to_sealed_bytes().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    let key = delegation.device_public_key();
    let fingerprint = *fingerprint;
    let provisional = (pending.get(community) == Some(&key)).then(|| Provisional {
        store,
        vault: vault.to_owned(),
        fingerprint,
        community: community.to_owned(),
        key,
        verdict: std::cell::Cell::new(Verdict::Open),
    });
    Ok(Some(DelegatedStart {
        sealed,
        user,
        provisional,
    }))
}

#[cfg(not(target_arch = "wasm32"))]
impl DelegatedStart {
    /// The member's user the CLI opens its sessions as.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// One delegated Door: the deployment's services and owners through
    /// [`Door::from_delegation`] (L9), with the community session opened by `K_d` (0 prompts;
    /// a revoked delegate answers `DelegateRevoked`).
    pub async fn door(
        &self,
        runtime: super::browser::Configuration,
        roots: &[Vec<u8>],
    ) -> Result<Door> {
        if self.discarded() {
            return Err(ErrorCode::Unauthorized);
        }
        let delegation = DeviceDelegation::from_sealed_bytes(&self.sealed).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::NeedsPasskey",
                ErrorCode::NeedsPasskey,
                &__cause,
            )
        })?;
        let origin = runtime.origin.clone();
        let mut door = runtime.construct_delegated_with_roots(roots, &delegation)?;
        let opened = door
            .open_delegated_session(&origin, &self.user, &delegation)
            .await;
        self.opened(opened)?;
        Ok(door)
    }

    /// The pending delegation was refused by the server and removed: it opens nothing.
    fn discarded(&self) -> bool {
        self.provisional
            .as_ref()
            .is_some_and(|provisional| provisional.verdict.get() == Verdict::Discarded)
    }

    /// The outcome of a session open. For a pending delegation the first answer decides once:
    /// opened, it is confirmed (best effort; the next start asks again otherwise); refused as
    /// `Unauthorized` (the server does not know the key as active), it is removed from the
    /// vault and the start fails with that refusal, so the next start is no delegated one and
    /// a new ceremony delegates afresh. Any other failure (the server unreachable) decides
    /// nothing.
    fn opened(&self, opened: Result<u64>) -> Result<u64> {
        let Some(provisional) = &self.provisional else {
            return opened;
        };
        match (provisional.verdict.get(), &opened) {
            (Verdict::Discarded, _) => Err(ErrorCode::Unauthorized),
            (Verdict::Open, Ok(_)) => {
                provisional.verdict.set(Verdict::Confirmed);
                let _ = provisional.confirm();
                opened
            }
            (Verdict::Open, Err(ErrorCode::Unauthorized)) => {
                provisional.verdict.set(Verdict::Discarded);
                provisional.discard()?;
                Err(ErrorCode::Unauthorized)
            }
            _ => opened,
        }
    }

    /// The native start's Door builder (`Embedded::configured_restore_built`): every build,
    /// the first and each device restart, is [`Self::door`].
    #[cfg(feature = "native-tor")]
    pub fn builder(
        self,
        runtime: super::browser::Configuration,
        roots: Vec<Vec<u8>>,
    ) -> super::native::DoorBuilder {
        Box::new(move || {
            let start = std::rc::Rc::new(self);
            std::rc::Rc::new(move || {
                let (start, runtime, roots) = (start.clone(), runtime.clone(), roots.clone());
                Box::pin(async move { start.door(runtime, &roots).await })
            })
        })
    }
}

/// A user-only file (mode 0600 on unix), replaced atomically: a temporary file in the same
/// directory is written and synced, renamed over `path`, and the directory is synced, so a
/// crash leaves either the old file or the new one, never a half-written one.
#[cfg(not(target_arch = "wasm32"))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let unavailable = |__cause: std::io::Error| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    };
    let temporary = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(unavailable(error));
    }
    sync_directory(path.parent().unwrap_or(std::path::Path::new(".")))
}

/// Sync the directory `dir` itself, so a rename or removal in it is durable.
#[cfg(not(target_arch = "wasm32"))]
fn sync_directory(dir: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/support/pairing_delegate.rs"]
mod tests;
