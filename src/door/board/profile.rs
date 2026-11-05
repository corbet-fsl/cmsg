//! Publish the member's own profile and rules as one signed bundle. The caller
//! names answers and rules only: the reachability descriptor is the device's own Mesh addresses, and the next
//! revision, the profile key, every signature and the admission decision come
//! from the retained owner and the original Profile, Envelope and Guard owners.
//! Profile keys go only to members the rules allow, and only person to person
//! (Exchange); publishing here releases no key to anybody.
use super::handlers::{board_error, with_context, OwnedBoard};
use super::*;

/// Owner-lent inputs for one preparation, valid only inside the callback that
/// receives them: the actual device signer and Envelope custody come from
/// `Keys::with_profile_custody`, the Store read from the committed checkpoint.
pub struct ProfileParts<'p, B: cwst::backend::Backend> {
    pub read: CommittedRead<'p, B>,
    pub signer: ckmg::ProfileSigner<'p>,
    pub custody: cbrd::cnvl::Custodian<'p>,
    /// A freshly issued community credential, when admission just produced one.
    /// `None` re-uses the credential inside the committed publication.
    pub credential: Option<Vec<u8>>,
    /// Members Contacts currently blocks; they become never-match rules.
    pub blocked: Vec<String>,
}

/// The member's answers and rules. Block rules are not accepted here: they come
/// from Contacts only.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfilePublish {
    /// All answers for the current schema: `{community, schema_version, public, private}`.
    pub profile: serde_json::Value,
    /// Personal rules (`{"op":"number_range",...}` and the other Guard rules).
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct ProfilePublished {
    /// Vault checkpoint version after the atomic commit.
    pub version: u64,
}

impl ProfilePublish {
    fn edit(self, reachability: Vec<u8>) -> Result<cbrd::Edit> {
        if self.rules.len() > cbrd::cgrd::MAX_ITEMS {
            return Err(ErrorCode::InvalidRequest);
        }
        let profile = serde_json::from_value(self.profile).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let rules = self
            .rules
            .into_iter()
            .map(|rule| {
                serde_json::from_value(rule).map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::InvalidRequest",
                        ErrorCode::InvalidRequest,
                        &__cause,
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(cbrd::Edit {
            profile,
            rules,
            reachability,
            // A system field: never taken from the request, only from custody.
            vouched_by: None,
            vouched_snapshot: None,
        })
    }
}

impl<T: clnk::Transport, R, O: CommittedOwner> OwnedBoard<T, R, O> {
    /// Prepare, authorize against the CURRENT Charter inside one synchronous
    /// callback, then commit atomically in a later await. The Forum still holds
    /// the previous publication, so the stale presence ends and the member
    /// attends again with the committed one.
    pub(super) async fn publish_profile(&mut self, edit: cbrd::Edit, expires: u64) -> Result<u64> {
        self.idle()?;
        let community = self.inner.board.community().to_owned();
        let board = &self.inner.board;
        let current = &mut self.current;
        let policy = &self.policy;
        let authorized = self
            .owner
            .with_profile(|parts| {
                let ProfileParts {
                    read,
                    mut signer,
                    custody,
                    credential,
                    blocked,
                } = parts;
                with_context(current, policy, &community, expires, read, |context, _| {
                    let candidate = board
                        .prepare_profile(
                            &cbrd::PublishContext {
                                read: context,
                                custody: &custody,
                                credential: credential.as_deref(),
                            },
                            &mut signer,
                            edit,
                            &blocked,
                        )
                        .map_err(board_error)?;
                    board
                        .authorize_profile(context, candidate)
                        .map_err(board_error)
                })
            })
            .await?;
        let version = self.owner.commit_profile(authorized).await?;
        self.inner.board.disconnect();
        Ok(version)
    }
}

/// Publish the member's profile. The member authority reads the server before it
/// lends the signer, so one lost answer on that read (a transient `Unavailable` or
/// `Reconcile` over Tor) refuses the publication although nothing was signed or
/// committed. The publication only replaces the member's own profile, so an exact
/// repeat yields the same state: a transient refusal is repeated inside the origin's
/// account session (`transient::absorb`, decision 2026-10-27), then the typed error.
/// A deterministic refusal is never repeated and nothing here locks a key.
pub(in crate::door) async fn profile_publish(
    door: &mut Door,
    key: &[u8; 32],
    request: ProfilePublish,
) -> Result<(ProfilePublished, Vec<Event>)> {
    let origin = door
        .grants
        .get(key)
        .ok_or(ErrorCode::Unauthorized)?
        .origin
        .clone();
    crate::door::transient::absorb(door, &origin, async |door: &mut Door| {
        publish_once(door, key, request.clone()).await
    })
    .await
}

async fn publish_once(
    door: &mut Door,
    key: &[u8; 32],
    request: ProfilePublish,
) -> Result<(ProfilePublished, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    // A system field: the device's own live Mesh addresses, never request data.
    let reachability = door.reachability(&origin);
    let mut edit = request.edit(reachability)?;
    if let Some((wire, snapshot)) = super::super::vouching::endorsement_wire(door, &origin).await {
        edit.vouched_by = Some(wire);
        edit.vouched_snapshot = snapshot;
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    let version = board.profile_publish(edit, expires).await?;
    Ok((ProfilePublished { version }, vec![]))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! `board.profile_publish` absorbs a transient refusal inside the session
    //! (decision 2026-10-27, journey row 4). The member authority reads the
    //! server before it lends the signer; one lost answer on that read refuses
    //! the whole publication with `Unavailable`. The publication only replaces
    //! the member's own profile, so an exact repeat yields the same state.
    use super::*;
    use crate::door::{
        account, facades,
        facades::{BoundBoard, BoundVault, OwnedFuture, SignedBoard, ThreadEntry, VaultIdentity},
        Configuration, Grant, Role,
    };
    use std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
        future::Future,
        pin::Pin,
        rc::Rc,
        sync::{
            atomic::{AtomicU64, AtomicUsize},
            Arc,
        },
    };

    const ORIGIN: &str = "https://member.example";
    const KEY: [u8; 32] = [7; 32];

    /// A Board whose publication answers `script` in turn, then succeeds.
    struct Scripted {
        script: Vec<ErrorCode>,
        calls: Rc<Cell<usize>>,
    }
    impl BoundBoard for Scripted {
        fn require_committed(&self) -> Result<()> {
            Ok(())
        }
        fn profile_publish(&mut self, _: cbrd::Edit, _: u64) -> OwnedFuture<'_, u64> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            let answer = self.script.get(call).copied().map_or(Ok(7), Err);
            Box::pin(async move { answer })
        }
        fn status(&self) -> cbrd::Status {
            cbrd::Status {
                connection: cbrd::clnk::State::Disconnected,
                groups: cbrd::Availability::Unavailable,
                rooms: cbrd::Availability::Unavailable,
            }
        }
        fn disconnect(&mut self) -> cbrd::Status {
            self.status()
        }
        fn prepare(&mut self, _: cbrd::cfrm::Request, _: [u8; 16]) -> Result<cbrd::Prepared> {
            Err(ErrorCode::Unavailable)
        }
        fn execute(&mut self, _: cbrd::Prepared, _: Vec<u8>) -> OwnedFuture<'_, cbrd::cfrm::Reply> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
    }

    /// A Vault that holds nothing: the publication only needs it to exist.
    struct EmptyVault;
    impl BoundVault for EmptyVault {
        fn current_identity(&mut self) -> OwnedFuture<'_, VaultIdentity> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn snapshot(&mut self, _: facades::Relation) -> OwnedFuture<'_, cnbx::ConversationView> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn history(&mut self, _: facades::Conversation) -> OwnedFuture<'_, Vec<cnbx::Message>> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn thread(&mut self, _: facades::Conversation) -> OwnedFuture<'_, Vec<ThreadEntry>> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn relation(&mut self, _: facades::Relation) -> OwnedFuture<'_, cnbx::Relation> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn delivery(
            &mut self,
            _: facades::Delivery,
        ) -> OwnedFuture<'_, Option<cnbx::DeliveryStatus>> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn sign_board<'a>(
            &'a mut self,
            _: &'a cbrd::Prepared,
            _: &'a str,
            _: u64,
            _: u64,
        ) -> OwnedFuture<'a, SignedBoard> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn lock(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
            Box::pin(async {})
        }
    }

    /// A Door with a live account session (600 s), a Vault and the scripted Board.
    fn door(script: Vec<ErrorCode>) -> (Door, Rc<Cell<usize>>) {
        let mut door = Door::new(
            Configuration::new(
                "alpha".into(),
                BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
            )
            .unwrap(),
        );
        door.grants.insert(
            KEY,
            Grant {
                origin: ORIGIN.into(),
                actions: BTreeSet::new(),
                expires: u64::MAX,
            },
        );
        door.bind_account(
            ORIGIN,
            account::timed_actor(
                Arc::new(AtomicU64::new(1_000)),
                Arc::new(AtomicUsize::new(0)),
                |_, _| Err(ErrorCode::Unavailable),
            ),
        )
        .unwrap();
        door.vaults.insert(ORIGIN.into(), Box::new(EmptyVault));
        let calls = Rc::new(Cell::new(0));
        door.boards.insert(
            ORIGIN.into(),
            Box::new(Scripted {
                script,
                calls: Rc::clone(&calls),
            }),
        );
        (door, calls)
    }

    fn request() -> ProfilePublish {
        ProfilePublish {
            profile: serde_json::json!({
                "community": "alpha", "schema_version": 1, "public": {}, "private": {}
            }),
            rules: vec![],
        }
    }

    async fn publish(door: &mut Door) -> Result<u64> {
        profile_publish(door, &KEY, request())
            .await
            .map(|(published, _)| published.version)
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_refusal_of_the_publication_is_repeated_inside_the_session() {
        let (mut door, calls) = door(vec![ErrorCode::Unavailable, ErrorCode::Reconcile]);
        assert_eq!(publish(&mut door).await, Ok(7));
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_persistent_transient_ends_in_the_typed_error_after_the_bounded_attempts() {
        let (mut door, calls) = door(vec![ErrorCode::Unavailable; 16]);
        assert_eq!(publish(&mut door).await, Err(ErrorCode::Unavailable));
        assert_eq!(calls.get(), crate::door::transient::ATTEMPTS as usize);
    }

    #[tokio::test(start_paused = true)]
    async fn a_deterministic_refusal_is_never_repeated() {
        let (mut door, calls) = door(vec![ErrorCode::Unauthorized]);
        assert_eq!(publish(&mut door).await, Err(ErrorCode::Unauthorized));
        assert_eq!(calls.get(), 1);
    }
}
