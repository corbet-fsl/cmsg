//! The profile keys this device holds for the members of one room (row 14.5).
//!
//! A key reaches the device as an MLS application message in the epoch where a
//! newcomer is admitted: the newcomer, if it accepted profile visibility, and
//! every existing member with visibility on send their current key. The key is
//! adopted only if the message's MLS sender is exactly the pseudonym that owns
//! the key (Envelope enforces it, never the caller), and it is stored wrapped
//! for this room only: a personal wrap never opens it and the reverse. The
//! record is one keyring per room, so dropping the room, or pruning the members
//! who left, never needs a scan of the Store.
use cbrd::cnvl::{Context, Custodian, ReadKey, RoomHandover, WrappedReadKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The Store owner of the room keyrings: one record per room, keyed by the group.
pub(in crate::door) const OWNER: &str = "profile.room";
/// Most keys a device holds for one room: the hand-over limit. Beyond it a key is
/// fetched on demand, never silently pushed out.
pub(in crate::door) const MAX_KEYS: usize = cthr::MAX_HANDOVER;
/// Upper bound of one stored keyring, read before anything is decoded.
const MAX_RECORD: usize = 256 * 1024;

/// Why a hand-over was not adopted. Nothing is stored for any of them.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::door) enum Refusal {
    /// Not a hand-over, or beyond the bounds of one.
    Malformed,
    /// The MLS sender is not the owner of the key, or the key is this device's
    /// own, or it belongs to another community.
    Sender,
    /// The message predates the sender's membership.
    BeforeJoin,
    /// The device already holds a newer key of that member.
    Stale,
    /// The device already holds as many keys as one room may hand over.
    Full,
    /// Envelope custody refused to wrap the key.
    Custody,
    /// The stored keyring is not a keyring.
    Record,
}

/// One adopted key: the context it opens, the epoch it arrived in and the key
/// wrapped under this device's custody for this room.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Held {
    owner: String,
    epoch: u64,
    profile_revision: u64,
    schema_revision: u64,
    key_generation: u64,
    wrapped: Vec<u8>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::door) struct Keyring {
    keys: Vec<Held>,
}

impl Keyring {
    /// The keyring a Store record holds (`None`: the room has none yet).
    pub(in crate::door) fn decode(record: Option<&[u8]>) -> Result<Self, Refusal> {
        let Some(record) = record else {
            return Ok(Self::default());
        };
        if record.len() > MAX_RECORD {
            return Err(Refusal::Record);
        }
        let ring: Self = serde_json::from_slice(record).map_err(|_| Refusal::Record)?;
        let owners: BTreeSet<_> = ring.keys.iter().map(|held| &held.owner).collect();
        if ring.keys.len() > MAX_KEYS || owners.len() != ring.keys.len() {
            return Err(Refusal::Record);
        }
        Ok(ring)
    }

    pub(in crate::door) fn encode(&self) -> Result<Vec<u8>, Refusal> {
        serde_json::to_vec(self).map_err(|_| Refusal::Record)
    }

    /// The members whose keys this device holds for the room.
    pub(in crate::door) fn owners(&self) -> BTreeSet<String> {
        self.keys.iter().map(|held| held.owner.clone()).collect()
    }

    pub(in crate::door) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Adopt the key `payload` hands over, sent in MLS epoch `epoch` by the leaf
    /// `sender`. `joined` is the first epoch the sender could have sent in, as
    /// this device knows it (an admitted newcomer's admission epoch, else 0).
    pub(in crate::door) fn adopt(
        &mut self,
        custody: &Custodian<'_>,
        group: &[u8; 32],
        sender: &str,
        epoch: u64,
        joined: u64,
        payload: &[u8],
    ) -> Result<(), Refusal> {
        if epoch < joined {
            return Err(Refusal::BeforeJoin);
        }
        let handover = RoomHandover::from_bytes(payload).map_err(|_| Refusal::Malformed)?;
        let context = handover.context().clone();
        // Envelope checks that the key's owner is exactly `sender`, that it is
        // this community's and that it is not this device's own key.
        let key = custody
            .adopt_room(&handover, sender)
            .map_err(|_| Refusal::Sender)?;
        let version = (context.profile_revision, context.key_generation);
        match self.keys.iter().find(|held| held.owner == sender) {
            Some(held) if version < (held.profile_revision, held.key_generation) => {
                return Err(Refusal::Stale);
            }
            None if self.keys.len() >= MAX_KEYS => return Err(Refusal::Full),
            _ => {}
        }
        let wrapped = key
            .wrap_room(group)
            .map_err(|_| Refusal::Custody)?
            .as_bytes()
            .to_vec();
        self.keys.retain(|held| held.owner != sender);
        self.keys.push(Held {
            owner: sender.into(),
            epoch,
            profile_revision: context.profile_revision,
            schema_revision: context.schema_revision,
            key_generation: context.key_generation,
            wrapped,
        });
        self.keys.sort_by(|a, b| a.owner.cmp(&b.owner));
        Ok(())
    }

    /// The key held for `owner`, opened for this room only. The read side that
    /// a room member's private profile will be opened with; tested here, its
    /// product caller is the room profile read.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::door) fn open<'k>(
        &self,
        custody: &Custodian<'k>,
        community: &str,
        group: &[u8; 32],
        owner: &str,
    ) -> Option<ReadKey<'k>> {
        let held = self.keys.iter().find(|held| held.owner == owner)?;
        let context = Context {
            community: community.into(),
            owner: held.owner.clone(),
            profile_revision: held.profile_revision,
            schema_revision: held.schema_revision,
            key_generation: held.key_generation,
        };
        custody
            .restore_room(
                context,
                group,
                &WrappedReadKey::from_bytes(&held.wrapped).ok()?,
            )
            .ok()
    }

    /// Drop the keys of every member that is not in `roster` any more (left or
    /// removed). Returns whether anything was dropped.
    pub(in crate::door) fn prune(&mut self, roster: &BTreeSet<String>) -> bool {
        let before = self.keys.len();
        self.keys.retain(|held| roster.contains(&held.owner));
        self.keys.len() != before
    }
}

/// The bytes of this member's own key as a hand-over, from its personal key.
pub(in crate::door) fn handover(key: &ReadKey<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>, Refusal> {
    key.room_handover()
        .and_then(|handover| handover.to_bytes())
        .map_err(|_| Refusal::Custody)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbrd::cnvl;

    const GROUP: [u8; 32] = [5; 32];

    fn custodian(member: &str, byte: u8) -> Custodian<'static> {
        // Static keys: the tests need only distinct custodies, never secrecy.
        let keys: &'static [[u8; 32]; 2] = Box::leak(Box::new([[byte; 32], [byte + 1; 32]]));
        Custodian::from_keys(&keys[0], &keys[1], "alpha", member, [byte; 32]).unwrap()
    }

    fn context(owner: &str, revision: u64, generation: u64) -> Context {
        Context {
            community: "alpha".into(),
            owner: owner.into(),
            profile_revision: revision,
            schema_revision: 1,
            key_generation: generation,
        }
    }

    /// A member's own key and the hand-over bytes it would send to a room.
    fn sent(
        owner: &Custodian<'static>,
        member: &str,
        revision: u64,
        generation: u64,
    ) -> (cnvl::Envelope, Vec<u8>) {
        let (envelope, key) = owner
            .seal(context(member, revision, generation), b"private profile")
            .unwrap();
        (envelope, handover(&key).unwrap().to_vec())
    }

    #[test]
    fn a_key_is_adopted_only_from_its_owner_and_opens_for_this_room_only() {
        let (owner, reader) = (custodian("m3", 7), custodian("m1", 9));
        let (envelope, payload) = sent(&owner, "m3", 1, 1);
        let mut ring = Keyring::default();
        // Sender is not the owner: refused, nothing stored.
        assert_eq!(
            ring.adopt(&reader, &GROUP, "m2", 4, 0, &payload),
            Err(Refusal::Sender)
        );
        // The owner's own device never adopts its own key.
        assert_eq!(
            ring.adopt(&owner, &GROUP, "m3", 4, 0, &payload),
            Err(Refusal::Sender)
        );
        assert!(ring.is_empty());
        ring.adopt(&reader, &GROUP, "m3", 4, 0, &payload).unwrap();
        assert_eq!(ring.owners(), BTreeSet::from(["m3".to_owned()]));
        // It opens the owner's profile for exactly this room.
        let key = ring.open(&reader, "alpha", &GROUP, "m3").unwrap();
        assert_eq!(
            cnvl::open(&envelope, &key, &context("m3", 1, 1))
                .unwrap()
                .as_slice(),
            b"private profile"
        );
        assert!(ring.open(&reader, "alpha", &[6; 32], "m3").is_none());
        assert!(ring.open(&reader, "alpha", &GROUP, "m2").is_none());
        // The room wrap is no personal wrap: it does not restore as one.
        let held = &ring.keys[0];
        assert!(reader
            .restore(
                context("m3", 1, 1),
                &WrappedReadKey::from_bytes(&held.wrapped).unwrap()
            )
            .is_err());
    }

    #[test]
    fn a_message_from_before_the_senders_join_is_refused() {
        let (owner, reader) = (custodian("m3", 7), custodian("m1", 9));
        let (_, payload) = sent(&owner, "m3", 1, 1);
        let mut ring = Keyring::default();
        assert_eq!(
            ring.adopt(&reader, &GROUP, "m3", 3, 4, &payload),
            Err(Refusal::BeforeJoin)
        );
        assert!(ring.is_empty());
        // The join epoch itself counts.
        ring.adopt(&reader, &GROUP, "m3", 4, 4, &payload).unwrap();
    }

    #[test]
    fn bytes_that_are_no_hand_over_are_refused_before_anything_is_kept() {
        let reader = custodian("m1", 9);
        let mut ring = Keyring::default();
        for payload in [&b""[..], b"profile key", &[0; 5000]] {
            assert_eq!(
                ring.adopt(&reader, &GROUP, "m3", 4, 0, payload),
                Err(Refusal::Malformed)
            );
        }
        // A key of another community is the owner's key but not for this one.
        let foreign = Custodian::from_keys(&[7; 32], &[8; 32], "beta", "m3", [7; 32]).unwrap();
        let (_, key) = foreign
            .seal(
                Context {
                    community: "beta".into(),
                    ..context("m3", 1, 1)
                },
                b"x",
            )
            .unwrap();
        assert_eq!(
            ring.adopt(&reader, &GROUP, "m3", 4, 0, &handover(&key).unwrap()),
            Err(Refusal::Sender)
        );
        assert!(ring.is_empty());
    }

    #[test]
    fn a_newer_key_replaces_and_an_older_one_is_stale() {
        let (owner, reader) = (custodian("m3", 7), custodian("m1", 9));
        let (_, first) = sent(&owner, "m3", 1, 1);
        let (second_envelope, second) = sent(&owner, "m3", 2, 1);
        let mut ring = Keyring::default();
        ring.adopt(&reader, &GROUP, "m3", 4, 0, &first).unwrap();
        ring.adopt(&reader, &GROUP, "m3", 6, 0, &second).unwrap();
        assert_eq!(ring.keys.len(), 1);
        let key = ring.open(&reader, "alpha", &GROUP, "m3").unwrap();
        assert!(cnvl::open(&second_envelope, &key, &context("m3", 2, 1)).is_ok());
        // The same key again is fine; an older revision is not taken back.
        ring.adopt(&reader, &GROUP, "m3", 8, 0, &second).unwrap();
        assert_eq!(
            ring.adopt(&reader, &GROUP, "m3", 8, 0, &first),
            Err(Refusal::Stale)
        );
        assert_eq!(ring.keys[0].epoch, 8);
        assert_eq!(ring.keys[0].profile_revision, 2);
    }

    #[test]
    fn a_room_holds_no_more_keys_than_it_hands_over() {
        let reader = custodian("m1", 9);
        let mut ring = Keyring::default();
        for index in 0..MAX_KEYS {
            let member = format!("o{index:03}");
            let owner =
                Custodian::from_keys(&[7; 32], &[8; 32], "alpha", &member, [7; 32]).unwrap();
            let (_, payload) = sent(&owner, &member, 1, 1);
            ring.adopt(&reader, &GROUP, &member, 4, 0, &payload)
                .unwrap();
        }
        let extra = Custodian::from_keys(&[7; 32], &[8; 32], "alpha", "extra", [7; 32]).unwrap();
        let (_, payload) = sent(&extra, "extra", 1, 1);
        assert_eq!(
            ring.adopt(&reader, &GROUP, "extra", 4, 0, &payload),
            Err(Refusal::Full)
        );
        // A member that is already held can still renew its key.
        let renewed = Custodian::from_keys(&[7; 32], &[8; 32], "alpha", "o000", [7; 32]).unwrap();
        let (_, payload) = sent(&renewed, "o000", 2, 1);
        ring.adopt(&reader, &GROUP, "o000", 5, 0, &payload).unwrap();
        // The whole record survives the Store.
        let again = Keyring::decode(Some(&ring.encode().unwrap())).unwrap();
        assert_eq!(again.owners(), ring.owners());
    }

    #[test]
    fn members_who_left_lose_their_keys_and_a_bad_record_is_refused() {
        let reader = custodian("m1", 9);
        let mut ring = Keyring::default();
        for member in ["m2", "m3", "m4"] {
            let owner = Custodian::from_keys(&[7; 32], &[8; 32], "alpha", member, [7; 32]).unwrap();
            let (_, payload) = sent(&owner, member, 1, 1);
            ring.adopt(&reader, &GROUP, member, 4, 0, &payload).unwrap();
        }
        let roster = BTreeSet::from(["m1".to_owned(), "m3".to_owned()]);
        assert!(ring.prune(&roster));
        assert_eq!(ring.owners(), BTreeSet::from(["m3".to_owned()]));
        assert!(!ring.prune(&roster));
        assert!(ring.prune(&BTreeSet::new()));
        assert!(ring.is_empty());
        for record in [&b"{"[..], b"{\"keys\":[],\"x\":1}"] {
            assert_eq!(Keyring::decode(Some(record)).err(), Some(Refusal::Record));
        }
        assert_eq!(
            Keyring::decode(Some(&vec![b' '; MAX_RECORD + 1])).err(),
            Some(Refusal::Record)
        );
        assert!(Keyring::decode(None).unwrap().is_empty());
    }
}
