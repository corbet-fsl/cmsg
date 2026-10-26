//! Pair a further device key into a membership with ONE wallet confirmation: the member's
//! stamp carries ONE slot per community (`device_pair`: community, the member's pseudonym, the
//! new key and the community's own pairing session), which the community accepts at
//! `device_add` and keeps with the PENDING key; `device_activate` then needs no stamp. So
//! approving a new device costs the approving device exactly one wallet ceremony, like
//! `device_join`, and one ceremony covers 16 communities (the stamp's slot count).
//!
//! The roles are split because the key and the member are on two devices:
//!
//! * the APPROVING device (the existing member device) holds the wallet passport and the
//!   stamp, picks the stamp salt and session from its own device key, and sends both steps;
//! * the NEW device only proves possession: its key signs the pairing message of each step
//!   over the community's one-use challenge (`cvlt::PairingGuest::sign_possession`).
//!
//! Each step needs its own fresh community challenge (they live 60 seconds), so the approving
//! device fetches a challenge ([`begin`]), the new device signs it, and [`send`] presents the
//! passport (and, for the add step only, the already issued stamp) over it.
use super::{
    composer_core::DeviceKeys,
    custody::SystemClock,
    device_join::{derived_salt, stamp_scope, DeviceSign},
    foyer::Transport,
    passport::GlobalPassport,
    stamp::{pending_request, request_stamp, resend_stamp},
    ErrorCode, Result,
};
use cfyr::Foyer;
use ckmg::{Clock, Entropy};
use cvlt::Records;
use cwlt::passport::{
    self, ActionKind, AuthenticatedCommunity, PayloadDigest, StampAction, StampSalt, StampScope,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

/// Label of the stamp slot's salt (`device_pair`).
pub const PAIR_SALT_LABEL: &[u8] = b"pair-slot";
/// Label of the community's opaque pairing session value: one per community (the label and the
/// community name are in the signed message), so no value links two memberships.
pub const PAIR_SESSION_LABEL: &[u8] = b"pair-session";

/// One of the two pairing steps (only the first carries the stamp).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Register the key PENDING with the stamp's approval (`device_add`): it grants nothing.
    Add,
    /// Make the approved pending key ACTIVE (`device_activate`, no stamp), after its lineage
    /// revision exists.
    Activate,
}

impl Step {
    fn kind(self) -> &'static str {
        match self {
            Self::Add => cfyr::device_session::ADD_ACTION,
            Self::Activate => cfyr::device_session::ACTIVATE_ACTION,
        }
    }
}

/// The stamp action of pairing one key into one community: what ONE stamp slot must cover.
///
/// It commits to the community (the scope), the member's pseudonym, the new key and the
/// community's own pairing session AND the planned lineage revision (the challenge of the Keys
/// receipt that adds the key). The host therefore runs Keys' `pair_approve` BEFORE the one
/// stamp: the stamp, which is also the revision's public evidence, then approves exactly this
/// key in exactly this revision, and the host device key signs the same digest.
#[derive(Clone)]
pub struct PairingActions {
    name: String,
    member: String,
    revision: [u8; 32],
    digest: [u8; 32],
    salt: [u8; 32],
    scope: StampScope,
    key: [u8; 32],
    session: [u8; 32],
    pair: StampAction,
}

impl PairingActions {
    /// The action of pairing `key` for `member` (the wallet's pseudonym in the community) in
    /// `scope` of community `name`, with the community's `session` value and the slot's `salt`.
    pub fn new(
        scope: StampScope,
        name: &str,
        member: &str,
        key: [u8; 32],
        session: [u8; 32],
        salt: [u8; 32],
        revision: [u8; 32],
    ) -> Result<Self> {
        let digest =
            cfyr::device_session::pair_payload(name, member, &key, &session, Some(&revision));
        let pair = StampAction::new(
            ActionKind::new(cfyr::device_session::PAIR_ACTION).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?,
            PayloadDigest::from_bytes(digest),
            StampSalt::from_bytes(salt),
        );
        Ok(Self {
            name: name.to_owned(),
            member: member.to_owned(),
            revision,
            digest,
            salt,
            pair,
            scope,
            key,
            session,
        })
    }

    /// The actions of pairing `new_key` into community `name` for `member`. The salt and the
    /// session come from the APPROVING device's key signature (`approver`) over the
    /// community, the new key and a label: the wallet cannot guess them, and the approving
    /// device rebuilds them after any restart, so a retained stamp still covers and the
    /// wallet is not asked again.
    pub async fn derive(
        community: &mut Foyer<Transport>,
        name: &str,
        member: &str,
        new_key: &ckmg::PublicKey,
        revision: [u8; 32],
        approver: &mut impl DeviceSign,
    ) -> Result<Self> {
        let scope = stamp_scope(community, name).await?;
        let salt = derived_salt(name, new_key, PAIR_SALT_LABEL, approver).await?;
        let session = derived_salt(name, new_key, PAIR_SESSION_LABEL, approver).await?;
        Self::new(
            scope,
            name,
            member,
            *new_key.value(),
            session,
            salt,
            revision,
        )
    }

    /// The key being paired.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// The pairing digest the stamp slot and the host device key's approval both cover.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The community name.
    pub fn community(&self) -> &str {
        &self.name
    }

    /// The member's pseudonym in the community.
    pub fn member(&self) -> &str {
        &self.member
    }

    /// The planned lineage revision (digest of the Keys receipt challenge).
    pub fn revision(&self) -> &[u8; 32] {
        &self.revision
    }

    /// The slot's salt (public once the stamp is presented).
    pub fn salt(&self) -> [u8; 32] {
        self.salt
    }

    /// The community's pairing session value (sent with `device_add`).
    pub fn session(&self) -> &[u8; 32] {
        &self.session
    }

    /// The community's stamp scope.
    pub fn scope(&self) -> &StampScope {
        &self.scope
    }

    /// The stamp action (the community's one slot).
    pub fn action(&self) -> &StampAction {
        &self.pair
    }

    /// The slot of this community in a stamp request (one per community).
    pub fn slots(&self) -> Vec<(StampScope, StampAction)> {
        vec![(self.scope.clone(), self.pair.clone())]
    }
}

/// The ONE wallet confirmation of a pairing of one community; see [`confirm_all`].
pub async fn confirm<A, B, C, E, Au, R>(
    actions: &PairingActions,
    wallet_api: &Foyer<Transport>,
    wallet_origin: &str,
    wallet: &mut GlobalPassport<B, C, E, Au, R>,
    keys: &mut DeviceKeys<A>,
) -> Result<()>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    Au: ckmg::Authority,
    R: Records,
{
    confirm_all(
        std::slice::from_ref(actions),
        wallet_api,
        wallet_origin,
        wallet,
        keys,
    )
    .await
}

/// Slots of one stamp: mirrors `cpsd::STAMP_SLOTS` (cwlt does not re-export it); a larger chunk
/// would be refused by the stamp request, never silently truncated.
pub const STAMP_SLOTS: usize = 16;

/// How many wallet confirmations (user-verifying ceremonies) pairing `scopes` communities
/// takes: one stamp carries [`STAMP_SLOTS`] slots and a pairing needs one slot per community,
/// so 16 communities are 1 confirmation and 17 are 2. Shown to the person in the CLI/UI.
pub fn confirmations_for(scopes: usize) -> usize {
    scopes.div_ceil(STAMP_SLOTS)
}

/// The text the CLI/UI shows before the wallet confirmation of `scopes` communities.
pub fn confirmation_notice(scopes: usize) -> String {
    let n = confirmations_for(scopes);
    format!(
        "Pairing {scopes} communit{} takes {n} wallet confirmation{} (one confirmation covers up to {STAMP_SLOTS} communities); the new device confirms once.",
        if scopes == 1 { "y" } else { "ies" },
        if n == 1 { "" } else { "s" },
    )
}

/// The wallet confirmations of a pairing over ALL `actions` (one per community): the slots
/// that no retained stamp covers yet go into stamps of at most [`STAMP_SLOTS`] slots, ONE
/// user-verifying ceremony — counted by [`DeviceKeys::confirm`] — per stamp, so 3 communities
/// are 1 confirmation and 17 are 2. Resumable: a covering stamp asks nothing, an interrupted
/// request is sent again, never confirmed twice.
pub async fn confirm_all<A, B, C, E, Au, R>(
    actions: &[PairingActions],
    wallet_api: &Foyer<Transport>,
    wallet_origin: &str,
    wallet: &mut GlobalPassport<B, C, E, Au, R>,
    keys: &mut DeviceKeys<A>,
) -> Result<()>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    Au: ckmg::Authority,
    R: Records,
{
    let all: Vec<_> = actions.iter().flat_map(PairingActions::slots).collect();
    for _ in 0..=all.len().div_ceil(STAMP_SLOTS) {
        let open = wallet
            .with_global_passport(|holder| {
                all.iter()
                    .filter(|(scope, action)| !holder.stamp_covers(scope, action, now()))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .await?;
        if open.is_empty() {
            return Ok(());
        }
        let slots = &open[..open.len().min(STAMP_SLOTS)];
        let issuance = || async {
            wallet_api
                .live_global_wallet(wallet_origin.into())
                .observe_lease(now)
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })?
                .stamp_challenge(now)
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })
        };
        let mut rng = passport::rand::rngs::OsRng;
        // An earlier attempt was interrupted after its request was durably begun: send the
        // SAME request again, never a new confirmation.
        let resent = match pending_request(wallet, slots).await? {
            Some(request) => resend_stamp(issuance().await?, wallet, request, &mut rng).await?,
            None => false,
        };
        if !resent {
            let keys = &mut *keys;
            let assertion = |options: Value| async move {
                let (credential, _) = keys
                    .confirm("pairing stamp")
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Refused",
                            ErrorCode::Refused,
                            &__cause,
                        )
                    })?
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
                // A pairing stamp always carries its own passkey assertion (never the birth grant).
                Ok(Some(credential.as_json().clone()))
            };
            request_stamp(issuance().await?, wallet, slots, assertion, &mut rng).await?;
        }
    }
    // A stamp that does not cover what it was requested for never loops forever.
    Err(ErrorCode::Reconcile)
}

/// The community's one-use challenge of one pairing step: its id and the signed request the
/// passport presentation answers. The approving device fetches it and hands it to the new
/// device to sign; it is valid for 60 seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepChallenge {
    /// The server's challenge id (part of the signed message).
    pub id: String,
    /// The community's signed presentation request.
    pub request: Vec<u8>,
}

/// Ask the community (a session-less Foyer of it) for the challenge of the next step.
pub async fn begin(community: &mut Foyer<Transport>) -> Result<StepChallenge> {
    let request = community
        .call("presentation_challenge", json!({}))
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
    Ok(StepChallenge {
        id: request["challenge"]
            .as_str()
            .ok_or(ErrorCode::Unavailable)?
            .to_owned(),
        request: serde_json::from_value(request["request"].clone()).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?,
    })
}

/// Send one pairing step: a fresh passport presentation over `challenge` and the new key's
/// `signature` (the pairing message of this step, signed by the new device over this same
/// `challenge`). `device_add` also carries the stamp presentation of the community's one slot
/// (the stamp [`confirm`] obtained) and the pairing session; `device_activate` carries no
/// stamp, the PENDING key the add registered is its approval.
pub async fn send<B, C, E, Au, R>(
    community: &mut Foyer<Transport>,
    wallet: &mut GlobalPassport<B, C, E, Au, R>,
    actions: &PairingActions,
    step: Step,
    challenge: &StepChallenge,
    signature: Vec<u8>,
) -> Result<Option<PresentedStamp>>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    Au: ckmg::Authority,
    R: Records,
{
    let action = actions.action();
    let at = now();
    let mut policy = community.current_policy();
    let expected = policy
        .with_current(now(), |current| {
            AuthenticatedCommunity::from_authenticated_origin(
                actions.scope().community().clone(),
                current.key_ring().clone(),
            )
        })
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
    let (proof, stamp) = wallet
        .with_global_passport(|holder| -> Result<_> {
            let mut rng = passport::rand::rngs::OsRng;
            let proof = holder
                .present(&mut rng, &expected, &challenge.request, now())
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unauthorized",
                        ErrorCode::Unauthorized,
                        &__cause,
                    )
                })?;
            let stamp = match step {
                Step::Add => Some(
                    holder
                        .present_stamp(&mut rng, actions.scope(), action, at)
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "ErrorCode::Unauthorized",
                                ErrorCode::Unauthorized,
                                &__cause,
                            )
                        })?
                        .to_bytes(),
                ),
                Step::Activate => None,
            };
            Ok((proof.to_bytes(), stamp))
        })
        .await??;
    let passport = json!({"challenge": challenge.id, "proof": proof});
    match step {
        Step::Add => {
            let stamp = stamp.ok_or(ErrorCode::Unauthorized)?;
            community
                .device_add(json!({
                    "passport": passport,
                    "stamp": &stamp,
                    "salt": action.salt().to_bytes(),
                    "device_key": actions.key(),
                    "session": actions.session(),
                    "revision": actions.revision(),
                    "signature": signature,
                }))
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Reconcile",
                        ErrorCode::Reconcile,
                        &__cause,
                    )
                })?;
            Ok(Some(PresentedStamp {
                presentation: stamp,
                at,
            }))
        }
        Step::Activate => {
            community
                .device_activate(json!({
                    "passport": passport,
                    "device_key": actions.key(),
                    "signature": signature,
                }))
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Reconcile",
                        ErrorCode::Reconcile,
                        &__cause,
                    )
                })?;
            Ok(None)
        }
    }
}

/// The stamp presentation the add step sent, kept as the revision's public evidence, and the
/// time it was presented at.
#[derive(Clone)]
pub struct PresentedStamp {
    /// `StampPresentation::to_bytes`.
    pub presentation: Vec<u8>,
    /// Unix seconds the stamp payload binds.
    pub at: u64,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::super::device_join::DeviceUse;
    use super::*;

    /// A device signer that, like ckmg's, prepends the format's tag and derives the salt.
    fn signer(seed: u8) -> impl FnMut(DeviceUse, Vec<u8>) -> std::future::Ready<Result<Vec<u8>>> {
        use ed25519_dalek::Signer as _;
        use sha2::Digest as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        move |what: DeviceUse, payload: Vec<u8>| {
            std::future::ready(Ok(match what {
                DeviceUse::Sign(format) => key
                    .sign(&[format.tag(), &payload[..]].concat())
                    .to_bytes()
                    .to_vec(),
                DeviceUse::Salt => sha2::Sha256::digest(
                    key.sign(&[&b"cmsg.device-join.salt.v1\0"[..], &payload[..]].concat())
                        .to_bytes(),
                )
                .to_vec(),
            }))
        }
    }

    fn scope() -> StampScope {
        StampScope::of_community(passport::CommunityId::new(b"alpha").unwrap(), None)
    }

    #[test]
    fn one_stamp_slot_per_community_covers_exactly_one_key_of_one_member() {
        let actions =
            PairingActions::new(scope(), "alpha", "m1", [7; 32], [3; 32], [1; 32], [9; 32])
                .unwrap();
        let slots = actions.slots();
        assert_eq!(slots.len(), 1, "ONE slot per community");
        assert_eq!(slots[0].0, scope());
        let pair = actions.action();
        assert_eq!(pair.kind().as_str(), "device_pair");
        assert_eq!(
            pair.payload().to_bytes(),
            cfyr::device_session::pair_payload("alpha", "m1", &[7; 32], &[3; 32], Some(&[9; 32]))
        );
        // Another key, member, session or community never shares the digest.
        let digest = |name: &str, member: &str, key: u8, session: u8| {
            PairingActions::new(
                scope(),
                name,
                member,
                [key; 32],
                [session; 32],
                [1; 32],
                [9; 32],
            )
            .unwrap()
            .action()
            .payload()
            .to_bytes()
        };
        let base = digest("alpha", "m1", 7, 3);
        assert_ne!(base, digest("beta", "m1", 7, 3));
        assert_ne!(base, digest("alpha", "m2", 7, 3));
        assert_ne!(base, digest("alpha", "m1", 8, 3));
        assert_ne!(base, digest("alpha", "m1", 7, 4));
        let other_revision =
            PairingActions::new(scope(), "alpha", "m1", [7; 32], [3; 32], [1; 32], [8; 32])
                .unwrap();
        assert_ne!(base, other_revision.action().payload().to_bytes());
        assert_eq!(actions.key(), &[7; 32]);
        assert_eq!(actions.session(), &[3; 32]);
    }

    #[tokio::test]
    async fn the_approver_rebuilds_salt_and_session_after_a_restart_per_community() {
        let new_key = ckmg::PublicKey::new(ckmg::VLD0, [7; 32]);
        let values = |seed: u8, key: &ckmg::PublicKey, name: &str| {
            let key = key.clone();
            let name = name.to_owned();
            async move {
                let mut sign = signer(seed);
                (
                    derived_salt(&name, &key, PAIR_SALT_LABEL, &mut sign)
                        .await
                        .unwrap(),
                    derived_salt(&name, &key, PAIR_SESSION_LABEL, &mut sign)
                        .await
                        .unwrap(),
                )
            }
        };
        let first = values(1, &new_key, "alpha").await;
        // The same approving device after a restart: the same values, so a retained stamp covers.
        assert_eq!(first, values(1, &new_key, "alpha").await);
        // Salt and session differ, and the session never repeats across communities (it would
        // link the memberships), keys or approving devices.
        assert_ne!(first.0, first.1);
        assert_ne!(first.1, values(1, &new_key, "beta").await.1);
        assert_ne!(first.1, values(2, &new_key, "alpha").await.1);
        let other = ckmg::PublicKey::new(ckmg::VLD0, [8; 32]);
        assert_ne!(first.1, values(1, &other, "alpha").await.1);
    }
}

#[cfg(test)]
mod ceremony_count_tests {
    use super::{confirmation_notice, confirmations_for, STAMP_SLOTS};

    #[test]
    fn up_to_sixteen_communities_are_one_confirmation_seventeen_are_two() {
        assert_eq!(STAMP_SLOTS, 16);
        assert_eq!(
            [1, 3, 16, 17, 32, 33].map(confirmations_for),
            [1, 1, 1, 2, 2, 3]
        );
        assert!(confirmation_notice(3).contains("1 wallet confirmation "));
        assert!(confirmation_notice(17).contains("2 wallet confirmations"));
    }
}
