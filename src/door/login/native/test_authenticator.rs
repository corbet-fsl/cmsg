//! Trusted native test composition only. The original provider owns credential
//! state; no enrollment, secret import or authorization verdict is supplied here.
use super::{Door, ErrorCode, Result, Role, State};
use cpky::software::SoftwareAuthenticator;

impl Door {
    /// Retain an original test authenticator already enrolled against the actual
    /// service, for this exact configured member portal origin. Configure its
    /// Foyer and native login before binding. This method performs no enrollment
    /// or membership check: original Passkeys/Foyer still verify every login.
    ///
    /// The provider's own origin must match the configured ceremony origin;
    /// original callback verification enforces that binding at execution. No
    /// provider state, launch capability or PRF is exposed through the registry.
    /// Rebinding is refused while any login for the origin is live or uncertain.
    pub fn bind_test_authenticator(
        &mut self,
        origin: &str,
        owner: SoftwareAuthenticator,
    ) -> Result<()> {
        if !self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|origins| origins.contains(origin))
        {
            return Err(ErrorCode::Unauthorized);
        }
        let binding = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if binding.role != Role::Member {
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
        self.test_authenticators.insert(origin.to_owned(), owner);
        Ok(())
    }
}
