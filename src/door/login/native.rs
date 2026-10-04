//! Native login stays in the same Door actor as its Foyer. Polling advances the
//! actual owner's future; a disappearing HTTP waiter never owns that future.
use super::*;
use cfyr::passkeys::{CeremonyKind, CeremonyRequest, CeremonyResult, VaultOutcome};
use futures_util::{future::LocalBoxFuture, FutureExt};

pub(crate) enum State {
    Waiting {
        future: LocalBoxFuture<'static, std::result::Result<CeremonyResult, cfyr::passkeys::Error>>,
        ceremony: String,
        expires: u64,
    },
    Finishing {
        future: LocalBoxFuture<
            'static,
            (
                foyer::Foyer<foyer::Transport>,
                cfyr::Result<cfyr::SessionInfo>,
            ),
        >,
        scope: foyer::Scope,
        expires: u64,
        custody: VaultOutcome,
    },
    // Retained opaquely until the compound Vault initializer can consume it.
    Authenticated {
        _session: cfyr::SessionInfo,
        _custody: VaultOutcome,
    },
    Cancelled,
    Refused(ErrorCode),
}

fn passkey_error(error: cfyr::passkeys::Error) -> ErrorCode {
    match error {
        cfyr::passkeys::Error::Unavailable => ErrorCode::Unavailable,
        _ => ErrorCode::Refused,
    }
}

fn origin(door: &Door, key: &[u8; 32]) -> Result<String> {
    door.grants
        .get(key)
        .map(|grant| grant.origin.clone())
        .ok_or(ErrorCode::Unauthorized)
}

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
    if let Err(error) = pending.open_browser() {
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

pub(super) fn poll(door: &mut Door, key: &[u8; 32]) -> Result<Status> {
    let origin = origin(door, key)?;
    let Some(state) = door.logins.remove(key) else {
        return if door.login_configuration.contains_key(&origin) {
            Ok(Status::Idle)
        } else {
            Err(ErrorCode::Unavailable)
        };
    };
    let (state, status) = match state {
        State::Waiting {
            mut future,
            ceremony,
            expires,
        } => match future.as_mut().now_or_never() {
            None => (
                State::Waiting {
                    future,
                    ceremony,
                    expires,
                },
                Ok(Status::Pending {
                    expires_at: expires,
                }),
            ),
            Some(Err(error)) => {
                let error = passkey_error(error);
                if let Some(binding) = door.foyers.get_mut(&origin) {
                    binding.uncertain = false;
                }
                (State::Refused(error), Err(error))
            }
            Some(Ok(result)) => {
                let CeremonyResult::Authentication(authentication) = result else {
                    if let Some(binding) = door.foyers.get_mut(&origin) {
                        binding.uncertain = false;
                    }
                    door.logins.insert(*key, State::Refused(ErrorCode::Refused));
                    return Err(ErrorCode::Refused);
                };
                // Only the door composes opaque Passkeys custody with Vault.
                // Foyer receives the public assertion and never the PRF result.
                let (credential, custody) = authentication.into_parts();
                let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
                let scope = binding.sessions.primary;
                let mut client = binding
                    .sessions
                    .clients
                    .remove(&scope)
                    .ok_or(ErrorCode::Unavailable)?;
                let future = async move {
                    let result = client.finish_browser_login(ceremony, credential).await;
                    (client, result)
                }
                .boxed_local();
                (
                    State::Finishing {
                        future,
                        scope,
                        expires,
                        custody,
                    },
                    Ok(Status::Pending {
                        expires_at: expires,
                    }),
                )
            }
        },
        State::Finishing {
            mut future,
            scope,
            expires,
            custody,
        } => match future.as_mut().now_or_never() {
            None => (
                State::Finishing {
                    future,
                    scope,
                    expires,
                    custody,
                },
                Ok(Status::Pending {
                    expires_at: expires,
                }),
            ),
            Some((client, result)) => {
                let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
                match result {
                    Ok(session) => {
                        binding.sessions.clients.insert(scope, client);
                        binding.uncertain = false;
                        (
                            State::Authenticated {
                                _session: session,
                                _custody: custody,
                            },
                            Ok(Status::AuthenticatedPendingCustody),
                        )
                    }
                    Err(error) => {
                        let error = foyer::map_error(error);
                        if !matches!(error, ErrorCode::Reconcile) {
                            binding.sessions.clients.insert(scope, client);
                            binding.uncertain = false;
                        }
                        (State::Refused(error), Err(error))
                    }
                }
            }
        },
        state @ State::Authenticated { .. } => (state, Ok(Status::AuthenticatedPendingCustody)),
        State::Cancelled => (State::Cancelled, Ok(Status::Cancelled)),
        State::Refused(error) => (State::Refused(error), Err(error)),
    };
    door.logins.insert(*key, state);
    status
}

pub(super) fn cancel(door: &mut Door, key: &[u8; 32]) -> Result<Status> {
    let origin = origin(door, key)?;
    let state = door.logins.remove(key);
    match state {
        Some(State::Waiting { .. }) => {
            // No assertion has been sent to login_finish. Dropping the actual
            // wait future closes its listener and discards any opaque result.
            if let Some(binding) = door.foyers.get_mut(&origin) {
                binding.uncertain = false;
            }
            door.logins.insert(*key, State::Cancelled);
            Ok(Status::Cancelled)
        }
        Some(State::Finishing { .. }) => {
            // A session write may already have happened; its transport is not
            // reinstalled and all original Foyer actions remain fenced.
            door.logins
                .insert(*key, State::Refused(ErrorCode::Reconcile));
            Err(ErrorCode::Reconcile)
        }
        Some(state) => {
            door.logins.insert(*key, state);
            poll(door, key)
        }
        None if door.login_configuration.contains_key(&origin) => Ok(Status::Idle),
        None => Err(ErrorCode::Unavailable),
    }
}

pub(crate) fn retire(door: &mut Door, key: &[u8; 32]) {
    let _ = cancel(door, key);
    door.logins.remove(key);
}

/// A closing owner cancels waiting ceremonies but drains a server mutation
/// already admitted by poll, even if its HTTP waiter has disappeared.
pub(crate) async fn drain(door: &mut Door) {
    for (_, state) in std::mem::take(&mut door.logins) {
        if let State::Finishing { future, .. } = state {
            let _ = future.await;
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/support/login_native.rs"]
mod tests;
