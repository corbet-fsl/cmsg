//! Community identity on the member device.
//!
//! A community is its founding key: the fingerprint is the SHA-256 digest of its
//! genesis document. The device pins the fingerprint (and, once verified, the
//! key-chain head) per membership. Everything below is device-local policy:
//!
//! * [`Memberships`] holds the pins. A feed that does not chain to the pinned
//!   genesis is a different community ([`Standing::Stranger`]); nothing old is
//!   used or sent for it.
//! * [`user_id`] / [`guard_assertion`] bind passkey user handles to the
//!   fingerprint; a foreign handle is discarded before anything is sent.
//! * [`namespace`] / [`database_name`] keep browser storage apart per fingerprint.
//! * [`Memberships::retire`] deletes a membership's local data once the platform
//!   feed publishes the end of its chain.
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Bytes of the fingerprint that open every passkey user handle.
pub const HANDLE_FINGERPRINT_LEN: usize = 16;
/// Length of a passkey user handle: fingerprint prefix then random bytes.
pub const USER_ID_LEN: usize = 32;

/// SHA-256 digest of a community's genesis document.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// Parse the 64-character lowercase hexadecimal form.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = match HEX.decode(text.as_bytes()) {
            Ok(bytes) => bytes,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "HEX.decode", &__cause);
                return None;
            }
        };
        let bytes = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "try_into", &__cause);
                return None;
            }
        };
        Some(Self(bytes))
    }
    /// Lowercase hexadecimal form.
    pub fn to_hex(&self) -> String {
        HEX.encode(&self.0)
    }
    /// The first eight hex characters, for people.
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_owned()
    }
    /// The prefix that opens every passkey user handle of this community.
    pub fn handle_prefix(&self) -> [u8; HANDLE_FINGERPRINT_LEN] {
        let mut prefix = [0; HANDLE_FINGERPRINT_LEN];
        prefix.copy_from_slice(&self.0[..HANDLE_FINGERPRINT_LEN]);
        prefix
    }
}
impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).ok_or_else(|| serde::de::Error::custom("fingerprint"))
    }
}

/// The key-chain head a feed verified to: ring revision and ring digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Head {
    /// Sequence number of the public key ring.
    pub ring_revision: u64,
    /// Digest of that exact ring.
    pub digest: Fingerprint,
}
impl From<cchr::ChainPin> for Head {
    fn from(pin: cchr::ChainPin) -> Self {
        Self {
            ring_revision: pin.ring_revision,
            digest: Fingerprint(pin.head),
        }
    }
}
impl From<Head> for cchr::ChainPin {
    fn from(head: Head) -> Self {
        Self {
            ring_revision: head.ring_revision,
            head: head.digest.0,
        }
    }
}

/// Passkey user handle: fingerprint prefix (16 bytes) then the random part.
pub fn user_id(
    fingerprint: &Fingerprint,
    random: &[u8; USER_ID_LEN - HANDLE_FINGERPRINT_LEN],
) -> [u8; USER_ID_LEN] {
    let mut id = [0; USER_ID_LEN];
    id[..HANDLE_FINGERPRINT_LEN].copy_from_slice(&fingerprint.handle_prefix());
    id[HANDLE_FINGERPRINT_LEN..].copy_from_slice(random);
    id
}

/// What a returned user handle says about the community it is used for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Handle {
    /// Opens with this community's fingerprint.
    Current,
    /// Well formed, but opens with another fingerprint (or none: an old-style handle).
    Foreign,
    /// No handle was returned, so the credential cannot be tied to the community.
    Absent,
}

/// Classify a returned user handle. Anything that is not exactly one
/// fingerprint prefix followed by the random part is foreign.
pub fn classify_handle(handle: Option<&[u8]>, fingerprint: &Fingerprint) -> Handle {
    match handle {
        None => Handle::Absent,
        Some(bytes)
            if bytes.len() == USER_ID_LEN
                && bytes[..HANDLE_FINGERPRINT_LEN] == fingerprint.handle_prefix() =>
        {
            Handle::Current
        }
        Some(_) => Handle::Foreign,
    }
}

/// An assertion or creation that must not leave the device.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rejected {
    /// Why it was held back.
    pub verdict: Handle,
    /// Raw credential id, for `signalUnknownCredential`, when the JSON carried one.
    pub credential_id: Option<Vec<u8>>,
}

fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Check a public assertion (WebAuthn JSON) before it is sent. Only a handle
/// that opens with the community's current fingerprint passes.
pub fn guard_assertion(credential: &Value, fingerprint: &Fingerprint) -> Result<(), Rejected> {
    let handle =
        text(credential, "/response/userHandle").and_then(|t| B64.decode(t.as_bytes()).ok());
    let verdict = match (text(credential, "/response/userHandle"), &handle) {
        (Some(_), None) => Handle::Foreign, // undecodable
        _ => classify_handle(handle.as_deref(), fingerprint),
    };
    if verdict == Handle::Current {
        return Ok(());
    }
    let credential_id = text(credential, "/rawId")
        .or_else(|| text(credential, "/id"))
        .and_then(|t| B64.decode(t.as_bytes()).ok());
    Err(Rejected {
        verdict,
        credential_id,
    })
}

/// Check registration options before the authenticator is asked: the server
/// must give a `user.id` that opens with the community's fingerprint.
pub fn guard_creation(options: &Value, fingerprint: &Fingerprint) -> Result<(), Rejected> {
    let id = text(options, "/publicKey/user/id")
        .or_else(|| text(options, "/user/id"))
        .and_then(|t| B64.decode(t.as_bytes()).ok());
    match classify_handle(id.as_deref(), fingerprint) {
        Handle::Current => Ok(()),
        verdict => Err(Rejected {
            verdict,
            credential_id: None,
        }),
    }
}

/// Storage namespace of one community incarnation.
pub fn namespace(fingerprint: &Fingerprint) -> String {
    format!("fp-{}", fingerprint.to_hex())
}

/// IndexedDB name of one community incarnation under a deployment base name.
pub fn database_name(base: &str, fingerprint: &Fingerprint) -> String {
    format!("{base}.{}", namespace(fingerprint))
}

/// How the fingerprint a name resolves to compares with the one pinned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standing {
    /// Same founding key: the same community.
    Same,
    /// The name belongs to a different founding key. The member is a stranger
    /// there; nothing old is used or sent.
    Stranger,
    /// No membership under this name.
    Unknown,
}

/// Why a pin could not advance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinError {
    /// No membership under this name.
    Unknown,
    /// The fingerprint is not the pinned one.
    Stranger,
    /// The chain ends below the pinned head.
    Rollback,
    /// Same ring revision, different ring: the chain forked.
    Fork,
}

/// Local data could not be removed; the membership stays for a retry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PurgeFailed;

/// What to write to the vault's pin record after a feed verified to `head` for
/// `fingerprint`: `Ok(None)` when it is already pinned, `Ok(Some(pin))` for a
/// first pin or a forward move. A pin for another founding key, a lower ring
/// revision (rollback) or another ring at the same revision (fork) is an error
/// and nothing may be written. The vault re-checks all of it under its own
/// compare-and-swap.
pub fn next_pin(
    current: Option<&cvlt::CommunityPin>,
    fingerprint: &Fingerprint,
    head: Head,
) -> Result<Option<cvlt::CommunityPin>, PinError> {
    let new = cvlt::CommunityPin {
        fingerprint: fingerprint.0,
        head: Some(cvlt::PinnedHead {
            ring_revision: head.ring_revision,
            digest: head.digest.0,
        }),
    };
    let Some(current) = current else {
        return Ok(Some(new));
    };
    if current.fingerprint != fingerprint.0 {
        return Err(PinError::Stranger);
    }
    match current.head {
        None => Ok(Some(new)),
        Some(old) if head.ring_revision < old.ring_revision => Err(PinError::Rollback),
        Some(old) if head.ring_revision == old.ring_revision => {
            if head.digest.0 == old.digest {
                Ok(None)
            } else {
                Err(PinError::Fork)
            }
        }
        Some(_) => Ok(Some(new)),
    }
}

/// Local data keyed by a community namespace (IndexedDB, caches, vault records).
pub trait LocalData {
    /// Remove everything stored under `namespace`. Removing nothing is success;
    /// an error leaves the membership in place for a later retry.
    fn purge(&mut self, namespace: &str) -> Result<(), PurgeFailed>;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Membership {
    fingerprint: Fingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    head: Option<Head>,
}

/// The pins of one vault, one per membership (community name). Serializable so
/// the vault can keep it inside its encrypted state.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Memberships {
    pins: BTreeMap<String, Membership>,
    /// Fingerprints whose name now belongs to another community; their local
    /// data stays inert (namespaced) until the platform ends that chain.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    superseded: BTreeSet<Fingerprint>,
}

impl Memberships {
    /// Pin a new membership. Refuses a name that is already pinned.
    pub fn join(&mut self, community: &str, fingerprint: Fingerprint) -> Result<(), PinError> {
        if self.pins.contains_key(community) {
            return Err(PinError::Stranger);
        }
        self.pins.insert(
            community.to_owned(),
            Membership {
                fingerprint,
                head: None,
            },
        );
        Ok(())
    }
    /// The pinned fingerprint of a membership.
    pub fn fingerprint(&self, community: &str) -> Option<&Fingerprint> {
        self.pins.get(community).map(|pin| &pin.fingerprint)
    }
    /// The pinned chain head, once a feed has verified.
    pub fn head(&self, community: &str) -> Option<Head> {
        self.pins.get(community).and_then(|pin| pin.head)
    }
    /// Compare what a name resolves to with the pin.
    pub fn standing(&self, community: &str, observed: &Fingerprint) -> Standing {
        match self.fingerprint(community) {
            None => Standing::Unknown,
            Some(pinned) if pinned == observed => Standing::Same,
            Some(_) => Standing::Stranger,
        }
    }
    /// Record a verified chain head. Only forward: a lower ring revision is a
    /// rollback, an equal one with another digest is a fork.
    pub fn advance(
        &mut self,
        community: &str,
        fingerprint: &Fingerprint,
        head: Head,
    ) -> Result<(), PinError> {
        let pin = self.pins.get_mut(community).ok_or(PinError::Unknown)?;
        if &pin.fingerprint != fingerprint {
            return Err(PinError::Stranger);
        }
        if let Some(old) = pin.head {
            if head.ring_revision < old.ring_revision {
                return Err(PinError::Rollback);
            }
            if head.ring_revision == old.ring_revision && head.digest != old.digest {
                return Err(PinError::Fork);
            }
        }
        pin.head = Some(head);
        Ok(())
    }
    /// The name now belongs to another founding key and the member starts as a
    /// complete stranger: the old pin and head are dropped and the new
    /// fingerprint pinned. The old fingerprint is returned; its data stays inert
    /// in its own namespace and is purged when [`Memberships::retire`] sees its
    /// chain end.
    pub fn restart(&mut self, community: &str, fingerprint: Fingerprint) -> Option<Fingerprint> {
        let old = self
            .pins
            .insert(
                community.to_owned(),
                Membership {
                    fingerprint,
                    head: None,
                },
            )
            .map(|pin| pin.fingerprint)
            .filter(|old| *old != fingerprint);
        if let Some(old) = old {
            self.superseded.insert(old);
        }
        old
    }
    /// The platform feed ended these chains (dissolved or banned communities).
    /// Delete the local data of every held membership with such a fingerprint,
    /// then forget it. A failed purge keeps that membership for a later retry.
    /// Returns the fingerprints that were fully deleted.
    pub fn retire(&mut self, ended: &[Fingerprint], data: &mut impl LocalData) -> Vec<Fingerprint> {
        let mut done = Vec::new();
        let held: BTreeSet<Fingerprint> = self
            .pins
            .values()
            .map(|pin| pin.fingerprint)
            .chain(self.superseded.iter().copied())
            .filter(|fingerprint| ended.contains(fingerprint))
            .collect();
        for fingerprint in held {
            if data.purge(&namespace(&fingerprint)).is_ok() {
                self.pins.retain(|_, pin| pin.fingerprint != fingerprint);
                self.superseded.remove(&fingerprint);
                done.push(fingerprint);
            }
        }
        done
    }
    /// [`Memberships::retire`] over the verified end-of-chain entries of the
    /// platform's charter (`VerifiedCharter::ended()`). The reason class changes
    /// nothing: a dissolved and a banned community are deleted alike.
    pub fn retire_ended(
        &mut self,
        ended: &[cchr::Ended],
        data: &mut impl LocalData,
    ) -> Vec<Fingerprint> {
        let fingerprints: Vec<Fingerprint> = ended
            .iter()
            .map(|entry| Fingerprint(entry.fingerprint))
            .collect();
        self.retire(&fingerprints, data)
    }
}

/// Ask the browser to forget a credential the community no longer knows
/// (`PublicKeyCredential.signalUnknownCredential`). A missing API or any error
/// is ignored: the assertion has already been held back.
#[cfg(target_arch = "wasm32")]
pub fn signal_unknown_credential(rp_id: &str, credential_id: &[u8]) {
    use js_sys::{Function, Object, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    let _ = (|| -> Result<(), JsValue> {
        let global = js_sys::global();
        let class = Reflect::get(&global, &JsValue::from_str("PublicKeyCredential"))?;
        let method = Reflect::get(&class, &JsValue::from_str("signalUnknownCredential"))?;
        let method: Function = method.dyn_into()?;
        let options = Object::new();
        Reflect::set(
            &options,
            &JsValue::from_str("rpId"),
            &JsValue::from_str(rp_id),
        )?;
        Reflect::set(
            &options,
            &JsValue::from_str("credentialId"),
            &JsValue::from_str(&B64.encode(credential_id)),
        )?;
        let promise = method.call1(&class, &options)?;
        if let Ok(promise) = promise.dyn_into::<js_sys::Promise>() {
            wasm_bindgen_futures::spawn_local(async move {
                let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
            });
        }
        Ok(())
    })();
}

/// Native hosts have no browser to signal; the assertion is simply discarded.
#[cfg(not(target_arch = "wasm32"))]
pub fn signal_unknown_credential(_rp_id: &str, _credential_id: &[u8]) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fp(byte: u8) -> Fingerprint {
        Fingerprint([byte; 32])
    }
    fn assertion(handle: Option<&[u8]>) -> Value {
        let mut value =
            json!({"id": B64.encode(b"cred"), "rawId": B64.encode(b"cred"), "response": {}});
        if let Some(handle) = handle {
            value["response"]["userHandle"] = json!(B64.encode(handle));
        }
        value
    }
    struct Disk {
        purged: Vec<String>,
        fail: bool,
    }
    impl LocalData for Disk {
        fn purge(&mut self, namespace: &str) -> Result<(), PurgeFailed> {
            if self.fail {
                return Err(PurgeFailed);
            }
            self.purged.push(namespace.to_owned());
            Ok(())
        }
    }

    #[test]
    fn fingerprint_forms_round_trip() {
        let a = Fingerprint([0xab; 32]);
        assert_eq!(Fingerprint::from_hex(&a.to_hex()), Some(a));
        assert_eq!(a.short(), "abababab");
        assert_eq!(Fingerprint::from_hex("zz"), None);
        assert_eq!(Fingerprint::from_hex(&"ab".repeat(31)), None);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<Fingerprint>(&json).unwrap(), a);
        assert!(serde_json::from_str::<Fingerprint>("\"nope\"").is_err());
    }

    #[test]
    fn user_ids_carry_the_fingerprint_prefix_then_the_random_part() {
        let id = user_id(&fp(7), &[9; 16]);
        assert_eq!(&id[..16], &[7; 16]);
        assert_eq!(&id[16..], &[9; 16]);
        assert_eq!(classify_handle(Some(&id), &fp(7)), Handle::Current);
        assert_eq!(classify_handle(Some(&id), &fp(8)), Handle::Foreign);
        assert_eq!(classify_handle(Some(&id[..31]), &fp(7)), Handle::Foreign);
        assert_eq!(classify_handle(Some(b"member-id"), &fp(7)), Handle::Foreign);
        assert_eq!(classify_handle(None, &fp(7)), Handle::Absent);
    }

    #[test]
    fn only_the_current_community_handle_may_be_sent() {
        let ours = user_id(&fp(1), &[2; 16]);
        assert_eq!(guard_assertion(&assertion(Some(&ours)), &fp(1)), Ok(()));
        let foreign = guard_assertion(&assertion(Some(&ours)), &fp(2)).unwrap_err();
        assert_eq!(foreign.verdict, Handle::Foreign);
        assert_eq!(foreign.credential_id.as_deref(), Some(&b"cred"[..]));
        let absent = guard_assertion(&assertion(None), &fp(1)).unwrap_err();
        assert_eq!(absent.verdict, Handle::Absent);
        let mut broken = assertion(None);
        broken["response"]["userHandle"] = json!("***");
        assert_eq!(
            guard_assertion(&broken, &fp(1)).unwrap_err().verdict,
            Handle::Foreign
        );
        let mut bare = assertion(None);
        bare["rawId"] = Value::Null;
        bare["id"] = Value::Null;
        assert_eq!(
            guard_assertion(&bare, &fp(1)).unwrap_err().credential_id,
            None
        );
    }

    #[test]
    fn registration_options_must_open_with_the_fingerprint() {
        let ours = B64.encode(&user_id(&fp(1), &[0; 16]));
        assert_eq!(
            guard_creation(&json!({"publicKey": {"user": {"id": ours}}}), &fp(1)),
            Ok(())
        );
        assert_eq!(
            guard_creation(&json!({"user": {"id": ours}}), &fp(1)),
            Ok(())
        );
        assert!(guard_creation(&json!({"user": {"id": ours}}), &fp(2)).is_err());
        assert!(guard_creation(&json!({}), &fp(1)).is_err());
    }

    #[test]
    fn storage_is_namespaced_by_fingerprint() {
        assert_ne!(namespace(&fp(1)), namespace(&fp(2)));
        assert_eq!(
            database_name("cmeet", &fp(1)),
            format!("cmeet.fp-{}", "01".repeat(32))
        );
    }

    #[test]
    fn pins_only_move_forward() {
        let mut pins = Memberships::default();
        let head = |revision, byte| Head {
            ring_revision: revision,
            digest: fp(byte),
        };
        assert_eq!(
            pins.advance("garden", &fp(1), head(0, 1)),
            Err(PinError::Unknown)
        );
        pins.join("garden", fp(1)).unwrap();
        assert_eq!(pins.join("garden", fp(1)), Err(PinError::Stranger));
        assert_eq!(pins.head("garden"), None);
        assert_eq!(
            pins.advance("garden", &fp(9), head(0, 1)),
            Err(PinError::Stranger)
        );
        pins.advance("garden", &fp(1), head(2, 5)).unwrap();
        pins.advance("garden", &fp(1), head(2, 5)).unwrap();
        pins.advance("garden", &fp(1), head(3, 6)).unwrap();
        assert_eq!(
            pins.advance("garden", &fp(1), head(2, 5)),
            Err(PinError::Rollback)
        );
        assert_eq!(
            pins.advance("garden", &fp(1), head(3, 7)),
            Err(PinError::Fork)
        );
        assert_eq!(pins.head("garden"), Some(head(3, 6)));
        let pin: cchr::ChainPin = head(3, 6).into();
        assert_eq!(Head::from(pin), head(3, 6));
    }

    #[test]
    fn a_reused_name_is_a_stranger_and_starts_from_nothing() {
        let mut pins = Memberships::default();
        assert_eq!(pins.standing("garden", &fp(1)), Standing::Unknown);
        pins.join("garden", fp(1)).unwrap();
        pins.advance(
            "garden",
            &fp(1),
            Head {
                ring_revision: 4,
                digest: fp(3),
            },
        )
        .unwrap();
        assert_eq!(pins.standing("garden", &fp(1)), Standing::Same);
        assert_eq!(pins.standing("garden", &fp(2)), Standing::Stranger);
        assert_eq!(pins.restart("garden", fp(2)), Some(fp(1)));
        assert_eq!(pins.fingerprint("garden"), Some(&fp(2)));
        assert_eq!(pins.head("garden"), None);
        assert_eq!(pins.restart("garden", fp(2)), None);
        assert_eq!(pins.restart("fresh", fp(5)), None);
    }

    #[test]
    fn an_ended_chain_deletes_the_local_data_and_the_membership() {
        let mut pins = Memberships::default();
        pins.join("garden", fp(1)).unwrap();
        pins.join("chess", fp(2)).unwrap();
        assert_eq!(pins.restart("garden", fp(3)), Some(fp(1)));
        let mut disk = Disk {
            purged: vec![],
            fail: true,
        };
        assert!(pins.retire(&[fp(1), fp(2)], &mut disk).is_empty());
        assert_eq!(pins.fingerprint("chess"), Some(&fp(2)));
        disk.fail = false;
        assert!(pins.retire(&[fp(9)], &mut disk).is_empty());
        assert!(disk.purged.is_empty());
        let done = pins.retire(&[fp(1), fp(2)], &mut disk);
        assert_eq!(done, vec![fp(1), fp(2)]);
        assert_eq!(disk.purged, vec![namespace(&fp(1)), namespace(&fp(2))]);
        assert_eq!(pins.fingerprint("chess"), None);
        assert_eq!(pins.fingerprint("garden"), Some(&fp(3)));
        assert!(pins.retire(&[fp(1)], &mut disk).is_empty());
    }

    #[test]
    fn verified_end_entries_delete_whatever_the_reason() {
        let mut pins = Memberships::default();
        pins.join("garden", fp(1)).unwrap();
        pins.join("chess", fp(2)).unwrap();
        pins.join("keep", fp(3)).unwrap();
        let entry = |byte, reason| cchr::Ended {
            fingerprint: [byte; 32],
            reason_class: reason,
            ended_at: 1,
        };
        let mut disk = Disk {
            purged: vec![],
            fail: false,
        };
        let done = pins.retire_ended(
            &[
                entry(1, cchr::EndReason::Banned),
                entry(2, cchr::EndReason::Dissolved),
            ],
            &mut disk,
        );
        assert_eq!(done, vec![fp(1), fp(2)]);
        assert_eq!(pins.fingerprint("keep"), Some(&fp(3)));
        assert_eq!(pins.fingerprint("garden"), None);
    }

    #[test]
    fn a_rolled_back_or_forked_head_never_reaches_the_vault_write() {
        let pinned = |revision, byte| cvlt::CommunityPin {
            fingerprint: [1; 32],
            head: Some(cvlt::PinnedHead {
                ring_revision: revision,
                digest: [byte; 32],
            }),
        };
        let head = |revision, byte| Head {
            ring_revision: revision,
            digest: fp(byte),
        };
        let current = pinned(3, 7);
        assert_eq!(
            next_pin(Some(&current), &fp(1), head(2, 7)),
            Err(PinError::Rollback)
        );
        assert_eq!(
            next_pin(Some(&current), &fp(1), head(3, 8)),
            Err(PinError::Fork)
        );
        assert_eq!(
            next_pin(Some(&current), &fp(2), head(4, 7)),
            Err(PinError::Stranger)
        );
        assert_eq!(next_pin(Some(&current), &fp(1), head(3, 7)), Ok(None));
        assert_eq!(
            next_pin(Some(&current), &fp(1), head(4, 9)),
            Ok(Some(pinned(4, 9)))
        );
        assert_eq!(next_pin(None, &fp(1), head(0, 5)), Ok(Some(pinned(0, 5))));
        let headless = cvlt::CommunityPin {
            fingerprint: [1; 32],
            head: None,
        };
        assert_eq!(
            next_pin(Some(&headless), &fp(1), head(1, 5)),
            Ok(Some(pinned(1, 5)))
        );
    }

    #[test]
    fn pins_survive_serialization() {
        let mut pins = Memberships::default();
        pins.join("garden", fp(1)).unwrap();
        pins.advance(
            "garden",
            &fp(1),
            Head {
                ring_revision: 1,
                digest: fp(2),
            },
        )
        .unwrap();
        pins.restart("chess", fp(4));
        pins.restart("chess", fp(5));
        let text = serde_json::to_string(&pins).unwrap();
        assert_eq!(serde_json::from_str::<Memberships>(&text).unwrap(), pins);
    }
}
