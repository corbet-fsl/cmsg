//! Concrete Forum construction and owner-prepared current-device operations.
use super::*;
use cbrd::{cfrm, clnk};

#[cfg(target_arch = "wasm32")]
use clnk::BrowserTransport as Transport;
#[cfg(not(target_arch = "wasm32"))]
use clnk::HttpTransport as Transport;

mod handlers;
pub(super) use handlers::{attend, discovery, search};
pub use handlers::{CommittedOwner, CommittedRead, OwnerFuture, ReadPolicy, SignedAttendance};

/// Only the user's paging choice crosses the public boundary. Link supplies
/// the live session/nonce and Vault signs its exact prepared transcript.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub cursor: Option<Vec<u8>>,
    pub page_size: u16,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub forum_origin: String,
    pub maximum_response_bytes: usize,
    pub timeout_millis: u32,
    pub search_candidates: usize,
    pub search_publication_bytes: usize,
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
        policy: ReadPolicy,
    ) -> Result<()> {
        let board = construct_board(&self.config.community, origin, config, clock)?;
        self.bind_board_with_owner(origin, board, owner, policy)
    }
}

fn construct_board(
    community: &str,
    origin: &str,
    config: Configuration,
    clock: impl clnk::Clock + 'static,
) -> Result<cbrd::Board<Transport>> {
    let transport = Transport::new(
        config.forum_origin,
        origin.into(),
        config.maximum_response_bytes,
        std::time::Duration::from_millis(config.timeout_millis.into()),
    )
    .map_err(before_send)?;
    let link =
        clnk::Link::at(transport, community.into(), origin.into(), clock).map_err(before_send)?;
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

fn current_version(foyer: &mut foyer::Binding, community: &str, expires: u64) -> Result<u64> {
    let now = clnk::Clock::now(&SystemClock).map_err(|_| ErrorCode::Clock)? / 1000;
    if now >= expires {
        return Err(ErrorCode::Unauthorized);
    }
    foyer.current(community, now, |charter| check_version(charter, now))?;
    Ok(now)
}

fn check_version(charter: &cfyr::trust::VerifiedCharter, now: u64) -> Result<()> {
    let settings = cfrm::crbk::ForumSettings::from_snapshot(
        charter.settings(now).map_err(|_| ErrorCode::Refused)?,
    )
    .map_err(|_| ErrorCode::Refused)?;
    let version = env!("CARGO_PKG_VERSION")
        .parse()
        .map_err(|_| ErrorCode::Unavailable)?;
    if !settings.accepts_client(&version) {
        return Err(ErrorCode::UnsupportedVersion);
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/support/board.rs"]
mod tests;

async fn execute(door: &mut Door, key: &[u8; 32], request: cfrm::Request) -> Result<cfrm::Reply> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let foyer = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let now = current_version(foyer, &door.config.community, expires)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| ErrorCode::Unavailable)?;
    let prepared = board.prepare(request, nonce)?;
    let facades::SignedBoard {
        signature,
        admitted: _admitted,
    } = vault.sign_board(&prepared, &origin, now, expires).await?;
    // Custody can await its real Store/authority. Reborrow the original Foyer
    // policy and compare the maintained runtime version after that wait too.
    current_version(foyer, &door.config.community, expires)?;
    // The actor owns the prepared request, signing intent and remote completion.
    // Neither a dropped caller nor local disposal can produce an implicit retry.
    board.execute(prepared, signature).await
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
