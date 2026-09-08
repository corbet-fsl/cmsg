//! Experimental client-side MLS text messaging. No server holds content keys.
//!
//! This crate is a cryptographic/transport component, not admission enforcement.
//! Signed cvld admission binds community identity to MLS signing keys. Applications
//! must additionally verify the applicable cfrm capability; this crate does not
//! claim private quota enforcement.
mod admission;
mod inbox;
mod member;
mod profile;
mod rendezvous;
mod transport;
mod vault;

pub use admission::{verify_admission, AdmissionGrant, AdmissionTrust};
pub use inbox::{Acceptance, Inbox, Redemption};
pub use member::{Invitation, Member, Received, TextMessage};
pub use profile::ProfileChallenge;
pub use rendezvous::{RendezvousChallenge, RendezvousEndpoint};
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
