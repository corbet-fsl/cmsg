//! Experimental client-side MLS text messaging. No server holds content keys.
//!
//! Signed cvld admission binds community identities to MLS signing keys. [`Member`]
//! is the low-level conversation primitive. [`Inbox`] adds recipient-side
//! first-contact enforcement through a trusted cfrm redemption callback and
//! encrypted local checkpoints. Calling `Member::join` alone does not spend a
//! first-contact allowance.
//!
//! Hosts supply passkey-derived wrapping material, durable storage and verified
//! onion networking. Raw MLS objects must not be routed through an operator's
//! logging relay. This alpha does not provide mobile bindings, storage rollback
//! protection, guaranteed delivery or an audited anonymity system.
mod admission;
mod enrollment;
mod framing;
mod inbox;
mod lifecycle;
mod member;
mod profile;
mod release;
mod rendezvous;
mod roster;
mod transport;
mod vault;

pub use admission::{verify_admission, AdmissionGrant, AdmissionTrust};
pub use enrollment::SemaphoreEnrollmentChallenge;
pub use framing::FramedStream;
pub use inbox::{Acceptance, Inbox, Redemption};
pub use lifecycle::Clock;
pub use member::{Invitation, Member, Received, TextMessage};
pub use profile::ProfileChallenge;
pub use release::{
    DirectionalReceiveAuthorization, DirectionalSendAuthorization, ReleaseAuthorizationTiming,
    ReleaseContext, ReleasePeer, ReleasePreflight, ReleaseReceipt,
};
pub use rendezvous::{RendezvousChallenge, RendezvousEndpoint};
pub use roster::{Participant, ParticipantHandle};
pub use transport::{OnionEndpoint, OnionTransport};

/// Maximum application text length in UTF-8 bytes, not characters.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Bound untrusted serialized MLS objects before parsing.
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;

/// Deliberately coarse errors: never include keys, plaintext or peer identifiers.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidText,
    Admission,
    InvalidMessage,
    InvalidState,
    InvalidStore,
    InvalidRoute,
    Transport,
    Randomness,
}

/// Interpret text literally. This function performs no markup parsing or I/O.
pub fn validate_text(text: &[u8]) -> Result<&str, Error> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(Error::InvalidText);
    }
    std::str::from_utf8(text).map_err(|_| Error::InvalidText)
}
