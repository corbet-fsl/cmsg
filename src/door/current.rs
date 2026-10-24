//! Current signed runtime requirements, borrowed anew before every disclosure.
use super::*;
use cbrd::clnk;

pub(super) struct Scope<'a> {
    pub community: &'a str,
    pub expires: u64,
    pub floor: u64,
}

#[cfg(feature = "client-version-fixture")]
tokio::task_local! {
    static CLIENT_VERSION: std::cell::RefCell<String>;
}

/// Run `future` as a client of the given (older) version. Test fixture only.
#[cfg(feature = "client-version-fixture")]
pub async fn with_client_version<F: std::future::Future>(version: &str, future: F) -> F::Output {
    CLIENT_VERSION
        .scope(std::cell::RefCell::new(version.to_owned()), future)
        .await
}

/// Change the version the running future reports (a requirement raised mid-test).
/// Test fixture only; a no-op outside [`with_client_version`].
#[cfg(feature = "client-version-fixture")]
pub fn set_client_version(version: &str) {
    let _ = CLIENT_VERSION.try_with(|v| *v.borrow_mut() = version.to_owned());
}

fn client_version() -> String {
    #[cfg(feature = "client-version-fixture")]
    if let Ok(version) = CLIENT_VERSION.try_with(|v| v.borrow().clone()) {
        return version;
    }
    env!("CARGO_PKG_VERSION").to_owned()
}

pub(super) fn check_version(charter: &cfyr::trust::VerifiedCharter, now: u64) -> Result<()> {
    let settings = clnk::cfrm::crbk::ForumSettings::from_snapshot(
        charter.settings(now).map_err(|_| ErrorCode::Refused)?,
    )
    .map_err(|_| ErrorCode::Refused)?;
    let version = client_version()
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

/// Like [`read`], for an action that also consumes a capability bundle held by
/// the Door (not by the Vault). The bundle is shared; it cannot be replaced here.
pub(super) async fn read_with<T: 'static, P: ?Sized>(
    vault: &mut dyn facades::BoundVault,
    ports: &P,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    scope: Scope<'_>,
    read: impl for<'a> FnOnce(&'a mut dyn facades::BoundVault, &'a P) -> facades::OwnedFuture<'a, T>,
) -> Result<(T, u64)> {
    let clock = board::SystemClock;
    let started = time(&clock, scope.expires, scope.floor)?;
    policy(current, &scope, started)?;
    let result = read(vault, ports).await?;
    let completed = time(&clock, scope.expires, started)?;
    policy(current, &scope, completed)?;
    Ok((result, completed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbrd::clnk::cfrm::crbk;

    /// The release requirement (`FORUM_MINIMUM_CLIENT_VERSION`) is met by this crate's own
    /// version: a runtime never refuses itself, and a bump of either constant is noticed.
    #[test]
    fn this_runtime_meets_the_forum_minimum() {
        let mut book = crbk::Rulebook::default();
        crbk::define_forum_settings(&mut book).unwrap();
        let snapshot = crbk::Snapshot {
            community: "alpha".into(),
            kind: crbk::SnapshotKind::Settings,
            revision: 1,
            policy_epoch: 1,
            issued: 0,
            content: book.resolve(&crbk::Values::new()).unwrap(),
        };
        let settings = crbk::ForumSettings::from_snapshot(&snapshot).unwrap();
        let own = env!("CARGO_PKG_VERSION").parse().unwrap();
        assert!(settings.accepts_client(&own));
        assert_eq!(client_version(), env!("CARGO_PKG_VERSION"));
    }
}
