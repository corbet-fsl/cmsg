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
mod accounting;
mod admission;
mod board;
mod enrollment;
mod framing;
mod identity;
mod inbox;
mod lifecycle;
mod live;
mod member;
mod profile;
mod profile_statements;
mod release;
mod rendezvous;
mod reservation;
mod roster;
pub use reservation::{
    ReservationContext, ReservationContexts, ReservationExpectation, ReservationPolicy,
    ReservationVerifier, VerifiedReservation,
};
mod transport;
mod vault;

#[cfg(target_arch = "wasm32")]
pub mod browser;

pub use accounting::{
    verify_accounting_acknowledgment, verify_accounting_acknowledgment_historical,
    verify_accounting_delegation, verify_accounting_receipt, verify_accounting_receipt_historical,
    AccountRequestAuthorization, AccountingAcknowledgment, AccountingContactContext,
    AccountingDelegation, AccountingIntroduction, AccountingKey, AccountingReceipt,
};
pub use admission::{verify_admission, AdmissionGrant, AdmissionTrust};
pub use board::{AllocationRequest, PresenceEndpoint, PresenceUpdate};
pub use enrollment::SemaphoreEnrollmentChallenge;
pub use framing::FrameCodec;
#[cfg(not(target_arch = "wasm32"))]
pub use framing::FramedStream;
pub use identity::{
    member_id_for_root, verify_device_authorization, DeviceAuthorization, MemberIdentity,
};
pub use inbox::{
    Acceptance, FirstContactPolicy, FirstContactRole, Inbox, Redemption, ReopeningInvitation,
    ReplacementPreview,
};
pub use lifecycle::Clock;
pub use live::{DeliveryStatus, LiveDelivery};
pub use member::{DataMessage, Invitation, Member, Received, TextMessage};
pub use profile::ProfileChallenge;
pub use release::{
    ContactDirective, ContactDirectiveKind, ContactResolution, ContactResolutionKind,
    DirectionalReceiveAuthorization, DirectionalSendAuthorization, ReleaseAuthorizationTiming,
    ReleaseContext, ReleasePeer, ReleasePreflight, ReleaseReceipt,
};
pub use rendezvous::{RendezvousChallenge, RendezvousEndpoint};
pub use roster::{Participant, ParticipantHandle};
pub use transport::OnionEndpoint;
#[cfg(not(target_arch = "wasm32"))]
pub use transport::OnionTransport;

/// Maximum application text length in UTF-8 bytes, not characters.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Maximum opaque application payload length in bytes.
pub const MAX_DATA_BYTES: usize = 64 * 1024;
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
