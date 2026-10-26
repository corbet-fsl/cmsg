//! Trusted native embedding of an authenticator the host process owns (for example
//! a seed-held operator credential, or a test device). The provider owns its
//! credential state; no enrollment, secret import or authorization verdict is
//! supplied here, and nothing about it is reachable from any action or JSON.
use super::{Door, ErrorCode, Result, Role, State};
use futures_util::future::LocalBoxFuture;

/// One configured portal's authenticator source: a factory, so every login gets
/// a fresh provider instance and a provider need not be cloneable.
pub(in crate::door) struct Embedded {
    role: Role,
    ceremony: Box<dyn Ceremony>,
}

impl Embedded {
    pub(in crate::door) fn role(&self) -> Role {
        self.role
    }
    pub(in crate::door) fn complete<'a>(
        &'a mut self,
        pending: &'a cpky::native::BrowserCeremony,
    ) -> LocalBoxFuture<'a, std::result::Result<(), cpky::Error>> {
        self.ceremony.complete(pending)
    }
    pub(in crate::door) fn assert<'a>(
        &'a mut self,
        context: cpky::Context,
        options: serde_json::Value,
    ) -> LocalBoxFuture<'a, std::result::Result<serde_json::Value, cpky::Error>> {
        self.ceremony.assert(context, options)
    }
}

trait Ceremony {
    fn complete<'a>(
        &'a mut self,
        pending: &'a cpky::native::BrowserCeremony,
    ) -> LocalBoxFuture<'a, std::result::Result<(), cpky::Error>>;
    fn assert<'a>(
        &'a mut self,
        context: cpky::Context,
        options: serde_json::Value,
    ) -> LocalBoxFuture<'a, std::result::Result<serde_json::Value, cpky::Error>>;
}

struct Factory<F>(F);

impl<A: cpky::Authenticator + 'static, F: FnMut() -> A> Ceremony for Factory<F> {
    fn complete<'a>(
        &'a mut self,
        pending: &'a cpky::native::BrowserCeremony,
    ) -> LocalBoxFuture<'a, std::result::Result<(), cpky::Error>> {
        Box::pin(pending.complete_with_authenticator((self.0)()))
    }
    fn assert<'a>(
        &'a mut self,
        context: cpky::Context,
        options: serde_json::Value,
    ) -> LocalBoxFuture<'a, std::result::Result<serde_json::Value, cpky::Error>> {
        let authenticator = (self.0)();
        Box::pin(async move {
            // Only the public assertion leaves; any PRF output is dropped with the client.
            let (credential, _) = cpky::Client::new(context, authenticator)
                .sign_in(options)
                .await?
                .into_parts();
            Ok(credential.into_json())
        })
    }
}

impl Door {
    /// Retain an authenticator source for this exact configured portal origin and
    /// role. Configure its Foyer and native login before binding. Each login asks
    /// `make` for a fresh provider. This method performs no enrollment or
    /// membership check: original Passkeys/Foyer still verify every login.
    ///
    /// The binding is scoped to the portal it names: a Root binding is consulted
    /// only for that Root portal's logins and can never serve a member session.
    /// The provider's own origin must match the configured ceremony origin;
    /// original callback verification enforces that binding at execution. No
    /// provider state, launch capability or PRF is exposed through the registry.
    /// Rebinding is refused while any login for the origin is live or uncertain.
    pub fn bind_authenticator<A, F>(&mut self, origin: &str, role: Role, make: F) -> Result<()>
    where
        A: cpky::Authenticator + 'static,
        F: FnMut() -> A + 'static,
    {
        if !self
            .config
            .origins
            .get(&role)
            .is_some_and(|origins| origins.contains(origin))
        {
            return Err(ErrorCode::Unauthorized);
        }
        let binding = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if binding.role != role {
            return Err(ErrorCode::Unauthorized);
        }
        if binding.uncertain {
            return Err(ErrorCode::Reconcile);
        }
        self.login_configuration
            .get(origin)
            .ok_or(ErrorCode::Unavailable)?
            .context()?;
        // Inspect every local capability for this origin, not just whichever
        // one will start the next login. An orphaned state conservatively fences
        // binding too; no absent grant can establish that it belongs elsewhere.
        let live = self.logins.iter().any(|(key, state)| {
            let same_origin = self
                .grants
                .get(key)
                .is_none_or(|grant| grant.origin == origin);
            let finished = match state {
                State::Cancelled | State::Expired => true,
                State::Refused(error) => *error != ErrorCode::Reconcile,
                _ => false,
            };
            same_origin && !finished
        });
        if live {
            return Err(ErrorCode::Refused);
        }
        self.embedded_authenticators.insert(
            origin.to_owned(),
            Embedded {
                role,
                ceremony: Box::new(Factory(make)),
            },
        );
        Ok(())
    }

    /// Trusted embedding only, never an action: one user-verifying assertion of the bound
    /// authenticator for a server challenge that the caller obtained for ONE exact action
    /// (a step-up ceremony, a lineage receipt challenge). The configured portal fixes the
    /// origin and relying party; the caller holds the ceremony and decides what the
    /// assertion is for. The PRF output of the ceremony is dropped here.
    #[allow(dead_code)] // first caller: the existing device's pairing steps
    pub(in crate::door) async fn passkey_assert(
        &mut self,
        origin: &str,
        options: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let context = self
            .login_configuration
            .get(origin)
            .ok_or(ErrorCode::Unavailable)?
            .context()?;
        let embedded = self
            .embedded_authenticators
            .get_mut(origin)
            .ok_or(ErrorCode::Unavailable)?;
        embedded.assert(context, options).await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })
    }
}
