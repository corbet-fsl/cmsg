//! Shared retained session completion. Platform adapters supply only original
//! ceremony results; Foyer receives public assertions, never opaque PRF custody.
use super::*;
use cfyr::passkeys::{CeremonyResult, VaultOutcome};
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
    // Retained opaquely until the trusted Vault preparation consumes it once.
    Authenticated {
        session: cfyr::SessionInfo,
        binding: cfyr::session::SessionBinding<foyer::Transport>,
        scope: foyer::Scope,
        custody: Option<VaultOutcome>,
    },
    Cancelled,
    Expired,
    Refused(ErrorCode),
}

pub(super) fn passkey_error(error: cfyr::passkeys::Error) -> ErrorCode {
    match error {
        cfyr::passkeys::Error::Unavailable => ErrorCode::Unavailable,
        _ => ErrorCode::Refused,
    }
}

pub(super) fn origin(door: &Door, key: &[u8; 32]) -> Result<String> {
    door.grants
        .get(key)
        .map(|grant| grant.origin.clone())
        .ok_or(ErrorCode::Unauthorized)
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
        State::Waiting { expires, .. } if door.clock_floor >= expires => {
            // No assertion has reached Foyer yet. Drop even a queued callback
            // before polling it and release only this unsent ceremony's fence.
            if let Some(binding) = door.foyers.get_mut(&origin) {
                binding.uncertain = false;
            }
            (State::Expired, Ok(Status::Expired))
        }
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
                        let stamp = client.session_binding();
                        binding.sessions.clients.insert(scope, client);
                        binding.uncertain = false;
                        match stamp {
                            Ok(stamp) => (
                                State::Authenticated {
                                    session,
                                    binding: stamp,
                                    scope,
                                    custody: Some(custody),
                                },
                                Ok(Status::AuthenticatedPendingCustody),
                            ),
                            Err(error) => {
                                let error = foyer::map_error(error);
                                (State::Refused(error), Err(error))
                            }
                        }
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
        State::Expired => (State::Expired, Ok(Status::Expired)),
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
        Some(State::Authenticated {
            custody: Some(_), ..
        }) => {
            // Public authentication already completed, but no custody owner has
            // taken this result. Cancellation drops only the retained secret.
            door.logins.insert(*key, State::Cancelled);
            Ok(Status::Cancelled)
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

impl Door {
    /// Consume one successful member login directly into the original Vault
    /// preparation. Trusted Rust composition only: absent from every action,
    /// Wasm/JSON projection and callback. This neither opens a Store nor grants
    /// custody/readiness; production Authority, Records and Wallet remain needed.
    ///
    /// A returned preparation has independent ownership. Cancelling or revoking
    /// this login afterwards cannot reclaim it; the trusted composer must drop
    /// it on cancellation and never bind owners from an expired/replaced session.
    pub fn prepare_login_custody(
        &mut self,
        origin: &str,
        token: &ClientToken,
        now: u64,
    ) -> Result<cvlt::PreparedOpen> {
        self.observe(now)?;
        let key = token_hash(token.expose_for_transport());
        let grant = self.grants.get(&key).ok_or(ErrorCode::Unauthorized)?;
        if grant.origin != origin || !grant.actions.contains("login.start") {
            return Err(ErrorCode::Unauthorized);
        }
        let owner = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if owner.role != Role::Member || owner.sessions.primary != foyer::Scope::Community {
            return Err(ErrorCode::Unauthorized);
        }
        if owner.uncertain {
            return Err(ErrorCode::Reconcile);
        }
        let state = self.logins.get_mut(&key).ok_or(ErrorCode::Refused)?;
        let State::Authenticated {
            session,
            binding,
            scope,
            custody,
        } = state
        else {
            return Err(ErrorCode::Refused);
        };
        if *scope != foyer::Scope::Community || now >= session.expires {
            // An expired or mismatched login can never keep a usable secret.
            *state = State::Refused(ErrorCode::Unauthorized);
            return Err(ErrorCode::Unauthorized);
        }
        let current = owner
            .sessions
            .clients
            .get(scope)
            .ok_or(ErrorCode::Unavailable)?;
        if let Err(error) = binding.check(current, now) {
            let error = foyer::map_error(error);
            *state = State::Refused(error);
            return Err(error);
        }
        // Taking happens before the original initializer, including its refusal.
        // A later poll remains authenticated_pending_custody; a retry can never
        // recover a consumed capability or silently start another ceremony.
        match custody.take().ok_or(ErrorCode::Refused)? {
            VaultOutcome::Ready(unlock) => cvlt::PreparedOpen::new(unlock, &self.config.community)
                .map_err(|_| ErrorCode::Refused),
            VaultOutcome::Locked(_) => Err(ErrorCode::Unavailable),
        }
    }
}

impl Door {
    fn recovery_session(&mut self, origin: &str, token: &ClientToken, now: u64) -> Result<()> {
        self.observe(now)?;
        let key = token_hash(token.expose_for_transport());
        let grant = self.grants.get(&key).ok_or(ErrorCode::Unauthorized)?;
        if grant.origin != origin || !grant.actions.contains("login.start") {
            return Err(ErrorCode::Unauthorized);
        }
        let owner = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if owner.role != Role::Member || owner.sessions.primary != foyer::Scope::Community {
            return Err(ErrorCode::Unauthorized);
        }
        if owner.uncertain {
            return Err(ErrorCode::Reconcile);
        }
        let Some(State::Authenticated {
            session,
            binding,
            scope,
            custody: None,
        }) = self.logins.get(&key)
        else {
            return Err(ErrorCode::Refused);
        };
        if *scope != foyer::Scope::Community || now >= session.expires {
            return Err(ErrorCode::Unauthorized);
        }
        binding
            .check(
                owner
                    .sessions
                    .clients
                    .get(scope)
                    .ok_or(ErrorCode::Unavailable)?,
                now,
            )
            .map_err(foyer::map_error)
    }

    /// Report login completion only after fresh checks of the exact original
    /// session, bound Vault and live member/device set. This stores no accepted
    /// state or lease; a later login poll must call this method again. It cannot
    /// bind a Vault, choose an identity or turn a rejected request into success.
    pub async fn complete_login_recovery(
        &mut self,
        origin: &str,
        token: &ClientToken,
        now: u64,
    ) -> Result<Status> {
        use ckmg::Clock as _;
        self.recovery_session(origin, token, now)?;
        let mut membership = self.live_membership(origin)?;
        let mut clock = super::super::custody::SystemClock;
        let mut floor = now;
        let mut clock_failed = false;
        let live = membership
            .observe(|| match clock.now() {
                Ok(time) if time >= floor => {
                    floor = time;
                    time
                }
                _ => {
                    clock_failed = true;
                    u64::MAX
                }
            })
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        if clock_failed {
            return Err(ErrorCode::Clock);
        }
        // Actual Keys forces current lineage and its own new HTTPS check while
        // the original immutable Store is held; no copied Vault snapshot decides.
        let identity = self
            .vaults
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?
            .current_identity()
            .await?;
        let completed = clock.now().map_err(|_| ErrorCode::Clock)?;
        if completed < floor {
            return Err(ErrorCode::Clock);
        }
        if completed >= live.expires
            || identity.binding.community() != self.config.community
            || identity.binding.member() != live.member
            || !live.device_keys.contains(identity.device.value())
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.recovery_session(origin, token, completed)?;
        Ok(Status::Complete)
    }
}

#[cfg(test)]
#[path = "../../../tests/support/login_custody.rs"]
mod custody_tests;
