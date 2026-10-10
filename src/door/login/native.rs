//! Native platform preparation; completion and fences use the shared owner.
#[cfg(test)]
use super::session::{cancel, poll};
use super::session::{origin, passkey_error, State};
use super::*;
#[cfg(test)]
use cfyr::passkeys::VaultOutcome;
use cfyr::passkeys::{CeremonyKind, CeremonyRequest};
use futures_util::FutureExt;

#[cfg(feature = "test-authenticator")]
mod test_authenticator;

pub(super) async fn start(door: &mut Door, key: &[u8; 32]) -> Result<Status> {
    let origin = origin(door, key)?;
    match door.logins.get(key) {
        Some(State::Cancelled) => {
            door.logins.remove(key);
        }
        Some(State::Refused(error)) if *error != ErrorCode::Reconcile => {
            door.logins.remove(key);
        }
        Some(_) => return Err(ErrorCode::Refused),
        None => {}
    }
    let config = door
        .login_configuration
        .get(&origin)
        .ok_or(ErrorCode::Unavailable)?
        .clone();
    let context = config.context()?;
    let page = url::Url::parse(&config.page).map_err(|_| ErrorCode::InvalidRequest)?;
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    if binding.uncertain {
        return Err(ErrorCode::Reconcile);
    }
    let client = binding
        .sessions
        .clients
        .get_mut(&binding.sessions.primary)
        .ok_or(ErrorCode::Unavailable)?;
    // Fence other forwarded actions before the first awaited operation.
    binding.uncertain = true;
    let challenge = match client.begin_browser_login().await {
        Ok(challenge) => challenge,
        Err(error) => {
            let error = foyer::map_error(error);
            binding.uncertain = matches!(error, ErrorCode::Reconcile);
            return Err(error);
        }
    };
    let pending = match cfyr::passkeys::native::BrowserCeremony::start(
        context,
        page,
        CeremonyRequest {
            kind: CeremonyKind::Authentication,
            options: challenge.options,
        },
    )
    .await
    {
        Ok(pending) => pending,
        Err(error) => {
            binding.uncertain = false;
            return Err(passkey_error(error));
        }
    };
    let Some(expires) = door
        .clock_floor
        .checked_add(pending.remaining_lifetime().as_secs())
    else {
        binding.uncertain = false;
        return Err(ErrorCode::Clock);
    };
    // This trusted test owner is never selected by action/configuration JSON.
    // Keep the original Foyer fence raised across its actual callback await.
    // Cancelling start drops the pending listener/custody and leaves that fence
    // raised, just like cancellation of the earlier owner awaits.
    #[cfg(feature = "test-authenticator")]
    let launched = if let Some(owner) = door.test_authenticators.get(&origin) {
        pending
            .complete_with_test_authenticator(owner.synced_test_device())
            .await
    } else {
        pending.open_browser()
    };
    #[cfg(not(feature = "test-authenticator"))]
    let launched = pending.open_browser();
    if let Err(error) = launched {
        // Even if the local callback accepted a result before its response was
        // lost, no Foyer finish has started. Destroy that result/listener before
        // releasing the fence on this explicit failure path.
        drop(pending);
        binding.uncertain = false;
        return Err(passkey_error(error));
    }
    door.logins.insert(
        *key,
        State::Waiting {
            future: pending.wait().boxed_local(),
            ceremony: challenge.ceremony,
            expires,
        },
    );
    Ok(Status::Pending {
        expires_at: expires,
    })
}

#[cfg(test)]
#[path = "../../../tests/support/login_native.rs"]
mod tests;
