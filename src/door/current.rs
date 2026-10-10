//! Current signed runtime requirements, borrowed anew before every disclosure.
use super::*;
use cbrd::clnk;

pub(super) struct Scope<'a> {
    pub community: &'a str,
    pub expires: u64,
    pub floor: u64,
}

pub(super) fn check_version(charter: &cfyr::trust::VerifiedCharter, now: u64) -> Result<()> {
    let settings = clnk::cfrm::crbk::ForumSettings::from_snapshot(
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

fn time(clock: &impl clnk::Clock, expires: u64, floor: u64) -> Result<u64> {
    let now = clock.now().map_err(|_| ErrorCode::Clock)? / 1000;
    if now < floor {
        return Err(ErrorCode::Clock);
    }
    if now >= expires {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(now)
}

pub(super) fn version(
    foyer: &mut foyer::Binding,
    community: &str,
    expires: u64,
    floor: u64,
) -> Result<u64> {
    let now = time(&board::SystemClock, expires, floor)?;
    foyer.current(community, now, |charter| check_version(charter, now))?;
    Ok(now)
}

fn policy(
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    scope: &Scope<'_>,
    now: u64,
) -> Result<()> {
    current
        .with_current(now, |charter| {
            if charter.community() != scope.community {
                return Err(ErrorCode::Unauthorized);
            }
            check_version(charter, now)
        })
        .map_err(|_| ErrorCode::Unavailable)?
}

pub(super) async fn read<T: 'static>(
    vault: &mut dyn facades::BoundVault,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    scope: Scope<'_>,
    read: impl for<'a> FnOnce(&'a mut dyn facades::BoundVault) -> facades::OwnedFuture<'a, T>,
) -> Result<(T, u64)> {
    read_with_clock(vault, current, scope, &board::SystemClock, read).await
}

pub(super) async fn read_with_clock<T: 'static>(
    vault: &mut dyn facades::BoundVault,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    scope: Scope<'_>,
    clock: &impl clnk::Clock,
    read: impl for<'a> FnOnce(&'a mut dyn facades::BoundVault) -> facades::OwnedFuture<'a, T>,
) -> Result<(T, u64)> {
    let started = time(clock, scope.expires, scope.floor)?;
    policy(current, &scope, started)?;
    let result = read(vault).await?;
    let completed = time(clock, scope.expires, started)?;
    policy(current, &scope, completed)?;
    // Reborrow only after the real owner await; no current policy is cached.
    Ok((result, completed))
}
