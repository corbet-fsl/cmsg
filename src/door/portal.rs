//! The admin portal Door. An admin is an ordinary member whose membership
//! carries the admin role gate; the gate's only privilege is this portal. The
//! portal is its own origin (`admin.<community host>`), so a member session can
//! never reach an admin action, and signing in to it with the passkey IS the
//! step-up: there is no sudo session and no extra mechanism. cvld checks the
//! real role; nothing here decides who may do what.
#![cfg(all(feature = "embedded-authenticator", not(target_arch = "wasm32")))]

use super::{Door, ErrorCode, Result, Role, native::DeviceConfiguration};

/// Host label that marks an admin portal origin.
const PORTAL_LABEL: &str = "admin.";

/// Whether `origin` is an admin portal origin: https and `admin.` first label.
pub fn is_portal_origin(origin: &str) -> bool {
    origin
        .strip_prefix("https://")
        .is_some_and(|host| host.starts_with(PORTAL_LABEL) && !host[PORTAL_LABEL.len()..].is_empty())
}

/// Build the admin portal Door from public deployment data and bind the
/// member's authenticator for the portal's logins. `make` yields a fresh
/// provider per login; it is consulted only for this portal's origin and Admin
/// role. Fails closed unless the configuration is an admin portal with a login.
pub fn open<A, F>(config: DeviceConfiguration, roots: &[Vec<u8>], make: F) -> Result<Door>
where
    A: cpky::Authenticator + 'static,
    F: FnMut() -> A + 'static,
{
    if config.role != Role::Admin || config.login.is_none() || !is_portal_origin(&config.origin) {
        return Err(ErrorCode::InvalidRequest);
    }
    let origin = config.origin.clone();
    let mut door = config.construct_with_roots(roots)?;
    door.bind_authenticator(&origin, Role::Admin, make)?;
    Ok(door)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_admin_hosts_are_portal_origins() {
        assert!(is_portal_origin("https://admin.toy.example"));
        assert!(!is_portal_origin("https://toy.example"));
        assert!(!is_portal_origin("http://admin.toy.example"));
        assert!(!is_portal_origin("https://admin."));
        assert!(!is_portal_origin("https://vault.admin.toy.example"));
    }
}
