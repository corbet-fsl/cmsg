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
        custody: Option<Custody>,
    },
    Cancelled,
    Expired,
    Refused(ErrorCode),
}

/// What a completed login holds for the Vault preparation, consumed once.
pub(crate) enum Custody {
    /// The member's community passkey ceremony's PRF outcome.
    Passkey(VaultOutcome),
    /// A device-key member (no community passkey): the community opening derived from
    /// this start's wallet unlock, and the wallet's stamp trust its stamp lineage
    /// evidence verifies with.
    Opening {
        opening: cvlt::PreparedOpen,
        stamps: cvlt::StampTrust,
    },
}

/// A device-key member's login of this start, retained by the trusted composer per origin
/// (`Door::retain_device_login`). The first `login.start` opens the Door's community session
/// by the device key's session signature and moves the opening into that login; it is never
/// a wire value, and no ceremony runs for it.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct DeviceLogin {
    user: String,
    retained: Option<(cvlt::PreparedOpen, cvlt::StampTrust)>,
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
                // A passkey whose user handle does not open with this community's
                // fingerprint belongs to another incarnation of the name: hold it
                // back before anything is sent and tell the browser to forget it.
                let rejected = (scope == foyer::Scope::Community)
                    .then(|| binding.community_fingerprint())
                    .flatten()
                    .and_then(|fingerprint| {
                        identity::guard_assertion(credential.as_json(), &fingerprint).err()
                    });
                if let Some(rejected) = rejected {
                    binding.uncertain = false;
                    if let (Some(id), Some(login)) = (
                        rejected.credential_id.as_deref(),
                        door.login_configuration.get(&origin),
                    ) {
                        identity::signal_unknown_credential(&login.relying_party, id);
                    }
                    door.logins.insert(*key, State::Refused(ErrorCode::Refused));
                    return Err(ErrorCode::Refused);
                }
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
                                    custody: Some(Custody::Passkey(custody)),
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
        self.take_login_custody(origin, token, now)
            .map(|(opening, _)| opening)
    }

    /// [`Self::prepare_login_custody`] plus the wallet's stamp trust a device-key login
    /// retained with its opening (`None` after a passkey ceremony): the recovery verifies
    /// the member's stamp lineage evidence with it.
    pub(crate) fn take_login_custody(
        &mut self,
        origin: &str,
        token: &ClientToken,
        now: u64,
    ) -> Result<(cvlt::PreparedOpen, Option<cvlt::StampTrust>)> {
        self.observe(now)?;
        let key = token_hash(token.expose_for_transport());
        let grant = self.grants.get(&key).ok_or(ErrorCode::Unauthorized)?;
        if grant.origin != origin || !grant.actions.contains("login.start") {
            return Err(ErrorCode::Unauthorized);
        }
        let owner = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        let expected_scope = self.custody_scope();
        if owner.role != Role::Member || owner.sessions.primary != expected_scope {
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
        if *scope != expected_scope || now >= session.expires {
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
            Custody::Passkey(VaultOutcome::Ready(unlock)) => {
                cvlt::PreparedOpen::new(unlock, &self.config.community)
                    .map(|opening| (opening, None))
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Refused",
                            ErrorCode::Refused,
                            &__cause,
                        )
                    })
            }
            Custody::Passkey(VaultOutcome::Locked(_)) => Err(ErrorCode::Unavailable),
            Custody::Opening { opening, stamps } => Ok((opening, Some(stamps))),
        }
    }

    /// Trusted composition only: retain a device-key member's login for `origin` until the
    /// first `login.start` of this start takes it (see [`DeviceLogin`]). `user` is the member
    /// id the device key belongs to; `opening` the community opening derived from the wallet
    /// unlock; `stamps` the wallet's stamp trust. Replaces an earlier, untaken retention.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn retain_device_login(
        &mut self,
        origin: &str,
        user: String,
        opening: cvlt::PreparedOpen,
        stamps: cvlt::StampTrust,
    ) -> Result<()> {
        let binding = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if binding.role != Role::Member || binding.sessions.primary != self.custody_scope() {
            return Err(ErrorCode::Unauthorized);
        }
        opening.device().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        self.device_logins.insert(
            origin.to_owned(),
            DeviceLogin {
                user,
                retained: Some((opening, stamps)),
            },
        );
        Ok(())
    }
}

/// `login.start` of a device-key origin: `None` when `origin` retains no device login (the
/// passkey ceremony applies). Otherwise the Door's community session opens by the device
/// key's session signature from the retained opening and the login is authenticated at once,
/// holding the opening for `prepare_login_custody`. A failed opening keeps the retention, so
/// a repeated start retries silently; a taken one refuses (a new app start signs in again).
#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn start_device(
    door: &mut Door,
    key: &[u8; 32],
    origin: &str,
) -> Option<Result<Status>> {
    let login = door.device_logins.get_mut(origin)?;
    let user = login.user.clone();
    let Some((opening, stamps)) = login.retained.take() else {
        return Some(Err(ErrorCode::Refused));
    };
    let (result, opening) = open_device(door, origin, &user, opening).await;
    Some(match result {
        Ok((session, binding, scope)) => {
            door.logins.insert(
                *key,
                State::Authenticated {
                    session,
                    binding,
                    scope,
                    custody: Some(Custody::Opening { opening, stamps }),
                },
            );
            Ok(Status::AuthenticatedPendingCustody)
        }
        Err(error) => {
            if let Some(login) = door.device_logins.get_mut(origin) {
                login.retained = Some((opening, stamps));
            }
            Err(error)
        }
    })
}

#[cfg(not(target_arch = "wasm32"))]
type Opened = (
    cfyr::SessionInfo,
    cfyr::session::SessionBinding<foyer::Transport>,
    foyer::Scope,
);

#[cfg(not(target_arch = "wasm32"))]
async fn open_device(
    door: &mut Door,
    origin: &str,
    user: &str,
    opening: cvlt::PreparedOpen,
) -> (Result<Opened>, cvlt::PreparedOpen) {
    let expected = door.custody_scope();
    let name = door.config.community.clone();
    let Some(binding) = door.foyers.get_mut(origin) else {
        return (Err(ErrorCode::Unavailable), opening);
    };
    if binding.role != Role::Member || binding.sessions.primary != expected {
        return (Err(ErrorCode::Unauthorized), opening);
    }
    if binding.uncertain {
        return (Err(ErrorCode::Reconcile), opening);
    }
    let Ok(device) = opening.device() else {
        return (Err(ErrorCode::Unauthorized), opening);
    };
    let scope = binding.sessions.primary;
    let Some(client) = binding.sessions.clients.get_mut(&scope) else {
        return (Err(ErrorCode::Unavailable), opening);
    };
    // Fence other forwarded actions across the session's awaited round trips.
    binding.uncertain = true;
    let mut sign = |what: super::super::device_join::DeviceUse, payload: Vec<u8>| {
        std::future::ready(match what {
            super::super::device_join::DeviceUse::Sign(ckmg::DeviceFormat::DeviceSession) => {
                opening
                    .sign_device_session(&payload)
                    .map(|signature| signature.to_vec())
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Unauthorized",
                            ErrorCode::Unauthorized,
                            &__cause,
                        )
                    })
            }
            _ => Err(ErrorCode::Unauthorized),
        })
    };
    let opened =
        super::super::device_join::open_session(client, &name, user, &device, &mut sign).await;
    let result = opened.and_then(|session| {
        client
            .session_binding()
            .map(|stamp| (session, stamp, scope))
            .map_err(foyer::map_error)
    });
    binding.uncertain = false;
    (result, opening)
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
        let expected_scope = self.custody_scope();
        if owner.role != Role::Member || owner.sessions.primary != expected_scope {
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
        if *scope != expected_scope || now >= session.expires {
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
        let mut membership = self.custody_membership(origin)?;
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
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
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
        let completed = clock.now().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Clock",
                ErrorCode::Clock,
                &__cause,
            )
        })?;
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
