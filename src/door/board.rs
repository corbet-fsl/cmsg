//! Concrete Forum construction and owner-prepared current-device operations.
use super::current::check_version;
use super::*;
use cbrd::{cfrm, clnk};

#[cfg(feature = "ohttp")]
type Transport = clnk::OhttpTransport<super::ohttp::Wire>;
#[cfg(all(not(feature = "ohttp"), target_arch = "wasm32"))]
use clnk::BrowserTransport as Transport;
#[cfg(all(not(feature = "ohttp"), not(target_arch = "wasm32")))]
use clnk::HttpTransport as Transport;

mod group_act;
mod groups;
mod handlers;
mod profile;
pub(in crate::door) mod room_keys;
mod rooms;
pub(super) use group_act::{group_act, group_answer, group_message, group_propose, group_welcome};
pub use group_act::{
    GroupAct, GroupAnswer, GroupAnswered, GroupInbound, GroupInvite, GroupMessageIn, GroupPropose,
    GroupProposed, GroupWelcome, GroupWelcomes,
};
pub(super) use groups::groups;
pub(super) use handlers::{attend, discovery, search, watch};
pub use handlers::{CommittedOwner, CommittedRead, OwnerFuture, ReadPolicy, SignedAttendance};
pub(super) use profile::profile_publish;
pub use profile::{ProfileParts, ProfilePublish, ProfilePublished};
pub(super) use rooms::{room_admit, room_join, room_leave, room_listing, room_refs, room_serve};
pub(in crate::door) use rooms::ListingPlan;
pub use rooms::{
    RoomAdmitted, RoomConnected, RoomJoin, RoomJoinStatus, RoomRef, RoomServed, RoomsListed,
};

/// Only the user's paging choice crosses the public boundary. Link supplies
/// the live session/nonce and Vault signs its exact prepared transcript.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub cursor: Option<Vec<u8>>,
    pub page_size: u16,
}

/// Supply DiscoveryPage.watch from Search or Watch, not its separate paging
/// cursor. Board checks the exact held window; no roster or publication is input.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub cursor: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub forum_origin: String,
    pub maximum_response_bytes: usize,
    pub timeout_millis: u32,
    pub search_candidates: usize,
    pub search_publication_bytes: usize,
    pub read_policy: ReadPolicy,
    /// Extra DER certificate files trusted for the forum origin, added to the public roots
    /// (direct HTTPS on native builds only). Deployment option for private test stacks;
    /// production leaves it empty and no code path differs.
    #[serde(default)]
    pub tls_root_files: Vec<std::path::PathBuf>,
    /// The web origin this member presents to the Forum (`https://<address>.<base>`, one of
    /// the origins the Forum's registry lists for the community). A native device has no page
    /// origin of its own and its door origin is the community's API host, which the Forum does
    /// not admit. Absent: the door's origin, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_origin: Option<String>,
    /// Relay and gateway keys for the forum calls.
    #[cfg(feature = "ohttp")]
    pub ohttp: super::ohttp::OhttpEndpoint,
}

/// Validated original Board retained until the restoring host has real custody.
/// No owner or attendance authority is created by this preparation.
#[cfg(any(feature = "native-tor", feature = "browser-tor", test))]
pub(crate) struct PendingBoard {
    board: RoomBoard,
    policy: ReadPolicy,
    origin: String,
}
#[cfg(any(feature = "native-tor", feature = "browser-tor", test))]
impl Configuration {
    pub(crate) fn prepare(self, community: &str, origin: &str) -> Result<PendingBoard> {
        validate_policy(&self.read_policy)?;
        let policy = self.read_policy.clone();
        Ok(PendingBoard {
            board: construct_board(community, origin, self, SystemClock)?,
            policy,
            origin: origin.into(),
        })
    }
}
#[cfg(any(feature = "native-tor", feature = "browser-tor", test))]
impl PendingBoard {
    pub(crate) fn bind<O: CommittedOwner + 'static>(
        self,
        door: &mut Door,
        origin: &str,
        owner: O,
    ) -> Result<()> {
        if origin != self.origin {
            return Err(ErrorCode::Unauthorized);
        }
        door.bind_board_with_owner(origin, self.board, owner, self.policy)
    }
}

/// Actual Unix milliseconds for Link. Its own clock floor rejects regression.
pub struct SystemClock;
impl clnk::Clock for SystemClock {
    fn now(&self) -> std::result::Result<u64, cmmr::Error> {
        #[cfg(not(target_arch = "wasm32"))]
        let time = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| cmmr::Error::Unavailable)?
                .as_millis(),
        )
        .map_err(|_| cmmr::Error::Unavailable)?;
        #[cfg(target_arch = "wasm32")]
        let time = {
            let time = js_sys::Date::now();
            if !time.is_finite() || !(0.0..=cmmr::MAX_TIME as f64).contains(&time) {
                return Err(cmmr::Error::Unavailable);
            }
            time as u64
        };
        if time > cmmr::MAX_TIME {
            return Err(cmmr::Error::Unavailable);
        }
        Ok(time)
    }
}

impl Door {
    /// Construct the actual target-native HTTPS transport, one scoped Link, and
    /// bounded Board search cache. No connection or custody is fabricated.
    pub fn configure_board(
        &mut self,
        origin: &str,
        config: Configuration,
        clock: impl clnk::Clock + 'static,
    ) -> Result<()> {
        validate_policy(&config.read_policy)?;
        let board = construct_board(&self.config.community, origin, config, clock)?;
        self.bind_board(origin, board)
    }

    /// The same original constructor with the parent's retained committed owner.
    /// Call instead of configure_board; a bound Board is never silently replaced.
    pub fn configure_board_with_owner<O: CommittedOwner + 'static>(
        &mut self,
        origin: &str,
        config: Configuration,
        clock: impl clnk::Clock + 'static,
        owner: O,
    ) -> Result<()> {
        validate_policy(&config.read_policy)?;
        let policy = config.read_policy.clone();
        let board = construct_board(&self.config.community, origin, config, clock)?;
        self.bind_board_with_owner(origin, board, owner, policy)
    }
}

fn validate_policy(policy: &ReadPolicy) -> Result<()> {
    if policy.admission_action.is_empty() || policy.maximum_snapshot_age == 0 {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}

/// One Forum transport. The member's presence transport and the anonymous room
/// transport are two separate instances of it: no cookie, session or circuit
/// state is shared between them.
fn forum_transport(config: &Configuration, origin: &str) -> Result<Transport> {
    #[cfg(feature = "ohttp")]
    {
        let forum = url::Url::parse(&config.forum_origin).map_err(|_| ErrorCode::InvalidRequest)?;
        let authority = forum.host_str().ok_or(ErrorCode::InvalidRequest)?;
        let authority = match forum.port() {
            Some(port) => format!("{authority}:{port}"),
            None => authority.to_owned(),
        };
        Transport::new(
            config.ohttp.wire(&authority)?,
            config.forum_origin.clone(),
            origin.into(),
            config.maximum_response_bytes,
            std::time::Duration::from_millis(config.timeout_millis.into()),
        )
        .map_err(before_send)
    }
    #[cfg(all(not(feature = "ohttp"), not(target_arch = "wasm32")))]
    {
        let mut roots = Vec::new();
        for file in &config.tls_root_files {
            roots.push(std::fs::read(file).map_err(|_| ErrorCode::InvalidRequest)?);
        }
        Transport::with_roots(
            config.forum_origin.clone(),
            origin.into(),
            config.maximum_response_bytes,
            std::time::Duration::from_millis(config.timeout_millis.into()),
            &roots,
        )
        .map_err(before_send)
    }
    #[cfg(all(not(feature = "ohttp"), target_arch = "wasm32"))]
    {
        Transport::new(
            config.forum_origin.clone(),
            origin.into(),
            config.maximum_response_bytes,
            std::time::Duration::from_millis(config.timeout_millis.into()),
        )
        .map_err(before_send)
    }
}

/// The Board every member portal gets: the Forum link plus the anonymous room
/// transport (see `RoomLink`).
type RoomBoard = cbrd::Board<Transport, clnk::AnonymousRooms<Transport>>;

fn construct_board(
    community: &str,
    origin: &str,
    config: Configuration,
    clock: impl clnk::Clock + 'static,
) -> Result<RoomBoard> {
    let origin = config.member_origin.as_deref().unwrap_or(origin);
    let transport = forum_transport(&config, origin)?;
    let rooms = forum_transport(&config, origin)?;
    let link = clnk::Link::at(transport, community.into(), origin.into(), clock)
        .map_err(before_send)?
        .with_anonymous_rooms(rooms);
    cbrd::Board::new(community.into(), link)
        .map_err(|_| ErrorCode::InvalidRequest)?
        .with_search(cbrd::ViewLimits {
            candidates: config.search_candidates,
            publication_bytes: config.search_publication_bytes,
        })
        .map_err(|_| ErrorCode::InvalidRequest)
}

fn possession() -> cfrm::Possession {
    // Link::prepare replaces these fields from its sole current session and
    // exact original request; no caller can submit them to the local registry.
    cfrm::Possession {
        session: vec![],
        request_nonce: vec![],
        signature: vec![],
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/support/board.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/support/restored_board.rs"]
mod restored_tests;

async fn execute(door: &mut Door, key: &[u8; 32], request: cfrm::Request) -> Result<cfrm::Reply> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
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
    // Custody can await its real Store/authority. Reborrow the original Foyer
    // policy and compare the maintained runtime version after that wait too.
    current::version(foyer, &door.config.community, expires, now)?;
    // The actor owns the prepared request, signing intent and remote completion.
    // Neither a dropped caller nor local disposal can produce an implicit retry.
    board.execute(prepared, signature).await
}

/// Connect this device to a member room if it is not connected yet: the common
/// room epoch, one blind room pass for `room` (both signed by the device like any
/// Forum request) and the room's Connect command. A live connection is kept.
pub(super) async fn ensure_room(door: &mut Door, key: &[u8; 32], room: [u8; 16]) -> Result<()> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    if !board.has_rooms() {
        return Err(ErrorCode::Unavailable);
    }
    if board.room_connection(room).is_ok() {
        return Ok(());
    }
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let foyer = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let now = current::version(foyer, &door.config.community, expires, door.clock_floor)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| ErrorCode::Unavailable)?;
    let prepared = board.room_prepare_epoch(nonce)?;
    let facades::SignedBoard {
        signature,
        admitted: epoch,
    } = vault.sign_board(&prepared, &origin, now, expires).await?;
    current::version(foyer, &door.config.community, expires, now)?;
    board.room_receive_epoch(prepared, signature).await?;
    drop(epoch);
    let mut operation = [0; 16];
    getrandom::fill(&mut operation).map_err(|_| ErrorCode::Unavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| ErrorCode::Unavailable)?;
    let prepared = board.room_prepare_pass(room, operation, nonce)?;
    let facades::SignedBoard {
        signature,
        admitted: pass,
    } = vault.sign_board(&prepared, &origin, now, expires).await?;
    current::version(foyer, &door.config.community, expires, now)?;
    let connection = board.room_receive_pass(prepared, signature).await?;
    drop(pass);
    let mut command = [0; 16];
    getrandom::fill(&mut command).map_err(|_| ErrorCode::Unavailable)?;
    command[0] = connection[0];
    board
        .execute_room(cbrd::clnk::cmbl::Request {
            room,
            operation: command,
            action: cbrd::clnk::cmbl::Action::Connect { connection },
        })
        .await
        .map_err(after_send)?;
    Ok(())
}

/// `board.room_connect`: connect to a member room now (the room actions below
/// do this themselves when needed).
pub(super) async fn room_connect(
    door: &mut Door,
    key: &[u8; 32],
    request: RoomRef,
) -> Result<(RoomConnected, Vec<Event>)> {
    ensure_room(door, key, request.room).await?;
    Ok((RoomConnected { connected: true }, vec![]))
}

pub(super) async fn heartbeat(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(cfrm::LiveOutput, Vec<Event>)> {
    let reply = execute(
        door,
        key,
        cfrm::Request::Heartbeat(cfrm::HeartbeatInput {
            possession: possession(),
            expected_revision: vec![],
        }),
    )
    .await?;
    match reply.response {
        cfrm::Output::Heartbeat(live) => Ok((live, vec![])),
        _ => Err(ErrorCode::Reconcile),
    }
}

/// The listed public rooms of this community, one page: opaque room id, public
/// name and description and the here-now count. Find a room to join (`room_join`).
pub(super) async fn room_list(
    door: &mut Door,
    key: &[u8; 32],
    request: Search,
) -> Result<(cfrm::RoomListOutput, Vec<Event>)> {
    let reply = execute(
        door,
        key,
        cfrm::Request::RoomList(cfrm::RoomListInput {
            possession: possession(),
            cursor: request.cursor,
            page_size: request.page_size,
        }),
    )
    .await?;
    match reply.response {
        cfrm::Output::RoomList(page) => Ok((page, vec![])),
        _ => Err(ErrorCode::Reconcile),
    }
}

pub(super) async fn depart(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(cfrm::EmptyOutput, Vec<Event>)> {
    let reply = execute(
        door,
        key,
        cfrm::Request::Depart(cfrm::DepartInput {
            possession: possession(),
        }),
    )
    .await?;
    match reply.response {
        cfrm::Output::Depart(empty) => Ok((empty, vec![Event::BoardDisconnected])),
        _ => Err(ErrorCode::Reconcile),
    }
}

pub(super) fn before_send(error: clnk::ErrorCode) -> ErrorCode {
    match error {
        clnk::ErrorCode::Origin | clnk::ErrorCode::Host => ErrorCode::Unauthorized,
        clnk::ErrorCode::Capacity | clnk::ErrorCode::TooLarge => ErrorCode::Capacity,
        clnk::ErrorCode::AuthorityUnavailable
        | clnk::ErrorCode::Timeout
        | clnk::ErrorCode::Transport => ErrorCode::Unavailable,
        clnk::ErrorCode::Reconcile => ErrorCode::Reconcile,
        clnk::ErrorCode::Rejected | clnk::ErrorCode::ResetRequired => ErrorCode::Refused,
        clnk::ErrorCode::UnsupportedVersion => ErrorCode::UnsupportedVersion,
        clnk::ErrorCode::InvalidRequest | clnk::ErrorCode::MediaType => ErrorCode::InvalidRequest,
    }
}
pub(super) fn after_send(error: clnk::ErrorCode) -> ErrorCode {
    match error {
        clnk::ErrorCode::Transport
        | clnk::ErrorCode::Timeout
        | clnk::ErrorCode::ResetRequired
        | clnk::ErrorCode::TooLarge => ErrorCode::Reconcile,
        other => before_send(other),
    }
}
