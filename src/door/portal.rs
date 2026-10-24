//! The admin portal Door. An admin is an ordinary member whose membership
//! carries the admin role gate; the gate's only privilege is this portal. The
//! portal is its own origin (`admin.<community host>`), so a member session can
//! never reach an admin action. Signing in to it IS the step-up: the device key
//! signs the server's nonce and ONE wallet confirmation stamp covers that key and
//! nonce (`Door::open_garden_session`); there is no sudo session, no admin passkey
//! and no extra mechanism. cvld checks the real role; nothing here decides who may
//! do what. [`open`] (admin passkey) is the superseded path.
#![cfg(all(feature = "embedded-authenticator", not(target_arch = "wasm32")))]

use super::{native::DeviceConfiguration, Door, ErrorCode, Result, Role};

/// Host label that marks an admin portal origin.
const PORTAL_LABEL: &str = "admin.";

/// Whether `origin` is an admin portal origin: https and `admin.` first label.
pub fn is_portal_origin(origin: &str) -> bool {
    origin.strip_prefix("https://").is_some_and(|host| {
        host.starts_with(PORTAL_LABEL) && !host[PORTAL_LABEL.len()..].is_empty()
    })
}

/// Build the admin portal Door for a device-key login: no authenticator is bound, the session
/// is opened with `Door::open_garden_session`. Fails closed unless the configuration is an
/// admin portal origin with the Admin role.
pub fn open_device(config: DeviceConfiguration, roots: &[Vec<u8>]) -> Result<Door> {
    if config.role != Role::Admin || !is_portal_origin(&config.origin) {
        return Err(ErrorCode::InvalidRequest);
    }
    config.construct_with_roots(roots)
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

    fn configuration(origin: &str, role: Role) -> DeviceConfiguration {
        DeviceConfiguration {
            community: "alpha".into(),
            origin: origin.into(),
            role,
            primary: super::super::foyer::Scope::Community,
            trust: None,
            login: None,
            root_board: false,
            services: vec![],
            forum: None,
        }
    }

    #[test]
    fn the_device_portal_refuses_a_member_origin_or_role() {
        let member_origin = open_device(configuration("https://toy.example", Role::Admin), &[]);
        assert_eq!(member_origin.err(), Some(ErrorCode::InvalidRequest));
        let member_role = open_device(
            configuration("https://admin.toy.example", Role::Member),
            &[],
        );
        assert_eq!(member_role.err(), Some(ErrorCode::InvalidRequest));
    }

    #[test]
    fn garden_salt_differs_per_signature() {
        use super::super::device_session::garden_salt;
        assert_ne!(garden_salt(b"a"), garden_salt(b"b"));
        assert_eq!(garden_salt(b"a"), garden_salt(b"a"));
    }

    #[test]
    fn only_admin_hosts_are_portal_origins() {
        assert!(is_portal_origin("https://admin.toy.example"));
        assert!(!is_portal_origin("https://toy.example"));
        assert!(!is_portal_origin("http://admin.toy.example"));
        assert!(!is_portal_origin("https://admin."));
        assert!(!is_portal_origin("https://vault.admin.toy.example"));
    }
}
