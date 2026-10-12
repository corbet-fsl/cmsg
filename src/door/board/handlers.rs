//! Concrete Board orchestration; domain checks remain in the original owners.
use super::*;
use crate::door::facades::{BoardBinding, BoundBoard, OwnedFuture};
use std::{future::Future, pin::Pin};

/// Future on the custody-owning local task; no Send requirement is imposed on
/// Keys, Store guards or their scoped callbacks.
pub type OwnerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Borrowed only after the parent has reconciled the actual compound checkpoint
/// and freshly authorized current Keys. Keep the Store guard through the callback.
/// The contact callback checks profile text for prohibited contact details;
/// it is not the Contacts relationship journal and must refuse if unavailable.
pub struct CommittedRead<'a, B: cwst::backend::Backend> {
    pub store: &'a cwst::Store<B>,
    pub binding: &'a ckmg::Binding,
    pub contact: &'a dyn Fn(&str) -> cshm::ContactCheck,
}

/// Explicit trusted deployment policy. No default action or snapshot age exists;
/// neither field is accepted by a public Board action.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadPolicy {
    pub admission_action: String,
    pub maximum_snapshot_age: u64,
}

/// Original device signature with its live exact-command signing intent. The
/// parent constructs this only through Keys for the original Challenge message.
/// It is not serializable and the intent stays alive through remote completion.
pub struct SignedAttendance {
    pub signature: Vec<u8>,
    pub admitted: ckmg::IntentGuard,
}

/// Parent-owned production capability retained with Board. There is deliberately
/// no default/accepting implementation. It must share Vault's lock/revoke/restore
/// lifetime and check it at each use. Binding this trait does not make an account
/// ready or authenticate a member.
///
/// `with_current` must perform all asynchronous Store/Keys freshness checks before
/// invoking the synchronous callback exactly once, with the actual committed
/// Store and current lineage Binding. It must return the callback's result
/// unchanged, without awaiting afterward or retaining any borrowed input/output.
/// CMSG borrows the one Foyer Charter inside that callback, after those waits.
///
/// `sign_attendance` must admit precisely this origin, expiry and original
/// Challenge transcript, using the original credential-authorized device signer.
/// It must not manufacture an intent, accept a raw signature from JSON, or use a
/// generic policy accepting every signing command. The parent owns that security
/// integration; the existing Prepared-request Vault signer is not a substitute.
pub trait CommittedOwner {
    type Backend: cwst::backend::Backend;

    fn with_current<'a, T: 'a, F>(&'a mut self, read: F) -> OwnerFuture<'a, T>
    where
        F: for<'read> FnOnce(CommittedRead<'read, Self::Backend>) -> Result<T> + 'a;

    fn sign_attendance<'a>(
        &'a mut self,
        challenge: &'a clnk::Challenge,
        origin: &'a str,
        expires: u64,
    ) -> OwnerFuture<'a, SignedAttendance>;

    /// Group membership writes: the owner's encrypted checkpoint, device
    /// signer for consents, current Guard/Contacts authority and the atomic
    /// Threads publication. Owners without this integration refuse writes.
    fn groups(&mut self) -> Option<&mut dyn cbrd::GroupOwner> {
        None
    }
}

struct OwnedBoard<T, R, O> {
    inner: BoardBinding<T, R>,
    owner: O,
    policy: ReadPolicy,
    current: cfyr::policy::CurrentPolicy<foyer::Transport>,
    // Original Link does not expose Enter's request for replay. An interrupted
    // attendance attempt is fenced and requires owner reconciliation, not retry.
    attendance_pending: bool,
}

enum PageKind {
    Search,
    Watch,
}

enum PendingPage {
    Search(cbrd::PendingSearch),
    Watch(cbrd::PendingWatch),
}

impl Door {
    /// Bind an original Board together with the parent's scoped committed-read
    /// and attendance-signing owner. The Board must not already be installed.
    /// Use this in trusted construction instead of bind_board/configure_board;
    /// no generated action can install the owner or choose the policy.
    pub fn bind_board_with_owner<T, R, O>(
        &mut self,
        origin: &str,
        board: cbrd::Board<T, R>,
        owner: O,
        policy: ReadPolicy,
    ) -> Result<()>
    where
        T: clnk::Transport + 'static,
        R: 'static,
        O: CommittedOwner + 'static,
    {
        self.member_origin(origin)?;
        if board.community() != self.config.community
            || self.boards.contains_key(origin)
            || policy.admission_action.is_empty()
            || policy.maximum_snapshot_age == 0
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let current = self.current_policy(origin)?;
        self.boards.insert(
            origin.into(),
            Box::new(OwnedBoard {
                inner: BoardBinding {
                    board,
                    pending: None,
                },
                owner,
                policy,
                current,
                attendance_pending: false,
            }),
        );
        Ok(())
    }
}

fn now(expires: u64) -> Result<u64> {
    let now = clnk::Clock::now(&SystemClock).map_err(|_| ErrorCode::Clock)? / 1000;
    if now >= expires {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(now)
}

/// No await is permitted inside this function. The actual Foyer weak port refuses
/// after disposal, while refreshing, and on stale/invalid original trust state.
fn with_context<B: cwst::backend::Backend, T>(
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    policy: &ReadPolicy,
    community: &str,
    expires: u64,
    read: CommittedRead<'_, B>,
    finish: impl FnOnce(&cbrd::ReadContext<'_, B>, u64) -> Result<T>,
) -> Result<T> {
    if read.binding.community() != community || !read.store.is_scope(community) {
        return Err(ErrorCode::Unauthorized);
    }
    let started = now(expires)?;
    let result = current
        .with_current(started, |charter| {
            if charter.community() != community {
                return Err(ErrorCode::Unauthorized);
            }
            check_version(charter, started)?;
            let context = cbrd::ReadContext {
                store: read.store,
                binding: read.binding,
                charter,
                policy: cbrd::ReadPolicy {
                    admission_action: &policy.admission_action,
                    maximum_snapshot_age: policy.maximum_snapshot_age,
                },
                contact: read.contact,
            };
            let output = finish(&context, started)?;
            if now(expires)? != started {
                return Err(ErrorCode::Clock);
            }
            Ok(output)
        })
        .map_err(|_| ErrorCode::Unavailable)?;
    result
}

fn publication<B: cwst::backend::Backend>(
    context: &cbrd::ReadContext<'_, B>,
    now: u64,
) -> Result<Vec<u8>> {
    let policy = context
        .charter
        .admission_policy(
            context.policy.admission_action,
            now,
            context.policy.maximum_snapshot_age,
        )
        .map_err(|_| ErrorCode::Refused)?;
    let signed_schema = context
        .charter
        .publication(cchr::Kind::Schema)
        .signed_bytes();
    let committed = cpfl::load_current_committed(
        context.store,
        context.binding,
        cpfl::Validation {
            policy,
            signed_schema,
            contact: context.contact,
        },
    )
    .map_err(|_| ErrorCode::Refused)?
    .ok_or(ErrorCode::Unavailable)?;
    // Only the original committed Profile crosses the upcoming network await.
    // It is reloaded and compared after each wait, never accepted as an input.
    Ok(committed.bytes().to_vec())
}
/// Upper bound on groups one device keeps (Groups refuses beyond it).
const MAX_GROUPS: usize = 256;

fn group_error(error: cbrd::cgrp::Error) -> ErrorCode {
    use cbrd::cgrp::Error;
    match error {
        Error::Invalid => ErrorCode::InvalidRequest,
        Error::Policy | Error::Unavailable => ErrorCode::Unavailable,
        Error::Authority => ErrorCode::Unauthorized,
        Error::Conflict | Error::Reconcile => ErrorCode::Reconcile,
        Error::Capacity => ErrorCode::Capacity,
        Error::Clock => ErrorCode::Clock,
    }
}

fn board_error(error: cbrd::Error) -> ErrorCode {
    match error {
        cbrd::Error::Scope => ErrorCode::Unauthorized,
        cbrd::Error::Unavailable => ErrorCode::Unavailable,
        cbrd::Error::Rejected => ErrorCode::Refused,
    }
}

impl<T: clnk::Transport, R, O: CommittedOwner> OwnedBoard<T, R, O> {
    fn idle(&self) -> Result<()> {
        if self.attendance_pending || self.inner.pending.is_some() {
            Err(ErrorCode::Reconcile)
        } else {
            Ok(())
        }
    }

    async fn attendance(&mut self, origin: &str, expires: u64) -> Result<cbrd::Status> {
        self.idle()?;
        let mut attempt = Disclosure {
            board: &mut self.inner.board,
            completed: false,
        };
        let result = attendance(
            attempt.board,
            &mut self.owner,
            &mut self.current,
            &self.policy,
            &mut self.attendance_pending,
            origin,
            expires,
        )
        .await;
        attempt.completed = result.is_ok();
        result
    }

    async fn page(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
        expires: u64,
        kind: PageKind,
    ) -> Result<cbrd::DiscoveryPage> {
        self.idle()?;
        let action = match kind {
            PageKind::Search => "search",
            PageKind::Watch => "watch",
        };
        if prepared.action() != action {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut request = prepared.request().clone();
        request
            .possession_mut()
            .ok_or(ErrorCode::InvalidRequest)?
            .signature = signature.clone();
        self.inner.pending = Some(request);
        let mut disclosure = Disclosure {
            board: &mut self.inner.board,
            completed: false,
        };
        let received = match kind {
            PageKind::Search => disclosure
                .board
                .receive_search(prepared, signature)
                .await
                .map(PendingPage::Search),
            PageKind::Watch => disclosure
                .board
                .receive_watch(prepared, signature)
                .await
                .map(PendingPage::Watch),
        };
        // Board hides Link's completion classification. Retain the original
        // request after failure/cancellation; never infer that it is retryable.
        let pending = received.map_err(|_| ErrorCode::Reconcile)?;
        let community = disclosure.board.community().to_owned();
        let board = &mut *disclosure.board;
        let current = &mut self.current;
        let policy = &self.policy;
        let result = self
            .owner
            .with_current(|read| {
                with_context(current, policy, &community, expires, read, |context, _| {
                    match pending {
                        PendingPage::Search(pending) => {
                            board.finish_search_committed(pending, context)
                        }
                        PendingPage::Watch(pending) => {
                            board.finish_watch_committed(pending, context)
                        }
                    }
                    .map(|page| page.discovery())
                    .map_err(board_error)
                })
            })
            .await;
        // A typed pending page proves the read completed. Local disclosure
        // refusal cannot authorize replay of that original network request.
        self.inner.pending = None;
        disclosure.completed = result.is_ok();
        result
    }
}

/// A cancelled/panicked post-network authority read must clear presence/cache,
/// just like an explicit refusal. No stale Link success survives that await.
struct Disclosure<'a, T: clnk::Transport, R> {
    board: &'a mut cbrd::Board<T, R>,
    completed: bool,
}
impl<T: clnk::Transport, R> Drop for Disclosure<'_, T, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.board.disconnect();
        }
    }
}

async fn current_publication<O: CommittedOwner>(
    owner: &mut O,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    policy: &ReadPolicy,
    community: &str,
    expires: u64,
) -> Result<Vec<u8>> {
    owner
        .with_current(|read| {
            with_context(current, policy, community, expires, read, |context, now| {
                publication(context, now)
            })
        })
        .await
}

async fn attendance<T: clnk::Transport, R, O: CommittedOwner>(
    board: &mut cbrd::Board<T, R>,
    owner: &mut O,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    policy: &ReadPolicy,
    pending: &mut bool,
    origin: &str,
    expires: u64,
) -> Result<cbrd::Status> {
    let community = board.community().to_owned();
    let publication = current_publication(owner, current, policy, &community, expires).await?;
    *pending = true;
    let challenge = board
        .connect(clnk::ChallengeInput {
            publication: publication.clone(),
        })
        .await
        .map_err(after_send)?;
    // These failures precede Enter, so no attendance effect is uncertain.
    let signature = match owner.sign_attendance(&challenge, origin, expires).await {
        Ok(signature) => signature,
        Err(error) => {
            *pending = false;
            return Err(error);
        }
    };
    match current_publication(owner, current, policy, &community, expires).await {
        Ok(current) if current == publication => (),
        Ok(_) => {
            *pending = false;
            return Err(ErrorCode::Refused);
        }
        Err(error) => {
            *pending = false;
            return Err(error);
        }
    }
    let SignedAttendance {
        signature,
        admitted: _admitted,
    } = signature;
    // Preserve uncertainty on every failed/cancelled Enter. Never retry a
    // possibly accepted entry after losing its original response.
    board
        .enter(signature)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    // An accepted network response alone does not permit reporting presence.
    // Reload current Profile/Keys/Contacts and the same Foyer after this await.
    match current_publication(owner, current, policy, &community, expires).await {
        Ok(current) if current == publication => (),
        _ => return Err(ErrorCode::Reconcile),
    }
    let status = board.status();
    if status.connection != clnk::State::Present {
        return Err(ErrorCode::Reconcile);
    }
    *pending = false;
    Ok(status)
}

impl<T: clnk::Transport, R, O: CommittedOwner> BoundBoard for OwnedBoard<T, R, O> {
    fn require_committed(&self) -> Result<()> {
        self.idle()
    }
    fn status(&self) -> cbrd::Status {
        self.inner.status()
    }
    fn disconnect(&mut self) -> cbrd::Status {
        self.inner.disconnect()
    }
    fn prepare(&mut self, request: cfrm::Request, nonce: [u8; 16]) -> Result<cbrd::Prepared> {
        self.idle()?;
        self.inner.prepare(request, nonce)
    }
    fn execute(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, cfrm::Reply> {
        if let Err(error) = self.idle() {
            return Box::pin(async move { Err(error) });
        }
        self.inner.execute(prepared, signature)
    }
    fn attend(&mut self, origin: &str, expires: u64) -> OwnedFuture<'_, cbrd::Status> {
        let origin = origin.to_owned();
        Box::pin(async move {
            let result = self.attendance(&origin, expires).await;
            if result.is_err() {
                self.inner.board.disconnect();
            }
            result
        })
    }
    fn search(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
        expires: u64,
    ) -> OwnedFuture<'_, cbrd::DiscoveryPage> {
        Box::pin(self.page(prepared, signature, expires, PageKind::Search))
    }
    fn watch(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
        expires: u64,
    ) -> OwnedFuture<'_, cbrd::DiscoveryPage> {
        Box::pin(self.page(prepared, signature, expires, PageKind::Watch))
    }
    fn groups(&mut self, expires: u64) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async move {
            self.idle()?;
            let community = self.inner.board.community().to_owned();
            let board = &self.inner.board;
            let current = &mut self.current;
            let policy = &self.policy;
            self.owner
                .with_current(|read| {
                    with_context(current, policy, &community, expires, read, |context, _| {
                        board.read_groups_committed(context).map_err(board_error)
                    })
                })
                .await
        })
    }
    fn group_act(
        &mut self,
        intent: cbrd::GroupIntent,
        visible: bool,
        expires: u64,
    ) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async move {
            self.idle()?;
            if self.owner.groups().is_none() {
                return Err(ErrorCode::Unavailable);
            }
            let community = self.inner.board.community().to_owned();
            let board = &self.inner.board;
            let current = &mut self.current;
            let policy = &self.policy;
            // The signed Rulebook is read synchronously; consent gathering and
            // publication then run against that exact policy, which Groups
            // re-validates against its own expiry at every step.
            let projected = self
                .owner
                .with_current(|read| {
                    with_context(current, policy, &community, expires, read, |context, _| {
                        board.read_group_policy_committed(context).map_err(board_error)
                    })
                })
                .await?;
            let source = cbrd::PolicyAt::new(&community, projected);
            let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
            let (views, _) = cbrd::execute_group_intent(owner, &source, intent, visible, MAX_GROUPS)
                .await
                .map_err(group_error)?;
            Ok(views)
        })
    }
    fn discovery(&mut self, expires: u64) -> OwnedFuture<'_, Vec<cbrd::Discovery>> {
        Box::pin(async move {
            self.idle()?;
            let community = self.inner.board.community().to_owned();
            let mut disclosure = Disclosure {
                board: &mut self.inner.board,
                completed: false,
            };
            let board = &mut *disclosure.board;
            let current = &mut self.current;
            let policy = &self.policy;
            let result = self
                .owner
                .with_current(|read| {
                    with_context(current, policy, &community, expires, read, |context, _| {
                        board.read_discovery_committed(context).map_err(board_error)
                    })
                })
                .await;
            disclosure.completed = result.is_ok();
            result
        })
    }
}

pub(in crate::door) async fn attend(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(cbrd::Status, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    // A Vault removed by lock cannot continue using a retained Board capability.
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    Ok((board.attend(&origin, expires).await?, vec![]))
}
pub(in crate::door) async fn search(
    door: &mut Door,
    key: &[u8; 32],
    request: Search,
) -> Result<(cbrd::DiscoveryPage, Vec<Event>)> {
    page(
        door,
        key,
        cfrm::Request::Search(cfrm::SearchInput {
            possession: possession(),
            cursor: request.cursor,
            page_size: request.page_size,
        }),
    )
    .await
}

pub(in crate::door) async fn watch(
    door: &mut Door,
    key: &[u8; 32],
    request: Watch,
) -> Result<(cbrd::DiscoveryPage, Vec<Event>)> {
    page(
        door,
        key,
        cfrm::Request::Watch(cfrm::WatchInput {
            possession: possession(),
            cursor: request.cursor,
        }),
    )
    .await
}

async fn page(
    door: &mut Door,
    key: &[u8; 32],
    request: cfrm::Request,
) -> Result<(cbrd::DiscoveryPage, Vec<Event>)> {
    let watch = matches!(request, cfrm::Request::Watch(_));
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let foyer = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let now = current::version(foyer, &door.config.community, expires, door.clock_floor)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| ErrorCode::Unavailable)?;
    let prepared = board.prepare(request, nonce)?;
    let facades::SignedBoard {
        signature,
        admitted: _admitted,
    } = vault.sign_board(&prepared, &origin, now, expires).await?;
    current::version(foyer, &door.config.community, expires, now)?;
    let result = if watch {
        board.watch(prepared, signature, expires).await?
    } else {
        board.search(prepared, signature, expires).await?
    };
    Ok((result, vec![]))
}
pub(in crate::door) async fn discovery(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Vec<cbrd::Discovery>, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    Ok((board.discovery(expires).await?, vec![]))
}
