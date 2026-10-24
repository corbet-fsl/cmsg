//! The embedding's account-backed wave capabilities: the contact and receipt signatures
//! ([`AccountContact`], a [`WaveContact`]) and the recipient's terms ([`AccountTerms`], a
//! [`WaveTerms`]), both over the member's accepted account witness.
//!
//! Neither holds a key. Every signature goes through the [`AccountSigner`] the engine lends
//! for one call (the Keys `SignContact`, `SignResolution` and `SignAcknowledgment`
//! admissions and the ledger Keys keeps in its own checkpoint; see `signing.rs`). The wave nonce is the
//! slot.
use super::super::{facades::OwnedFuture, ErrorCode, Result};
use super::ports::AccountSigner;
use super::production::{WaveContact, WaveTerms};
use super::types::{Hello, Terms};
use super::{ContactRequest, ReceiptRequest};
use ckmg::wallet_engine::account::{Account, Acknowledgment, Enrollment, Reserve, Resolution};
use ckmg::Binding;
use ckmg::SigningPhase;

/// The newest accepted account witness, read afresh for each call.
pub trait AccountView {
    fn current<'a>(&'a self) -> OwnedFuture<'a, Account>;
}

fn reserve_of(account: &Account, request: &ContactRequest<'_>) -> Result<Reserve> {
    let peer = cnbx::member_digest_of(request.peer).map_err(|_| ErrorCode::Refused)?;
    let index = account
        .roster()
        .entries()
        .iter()
        .position(|row| row.member == peer)
        .ok_or(ErrorCode::Refused)?;
    Ok(Reserve {
        peer_index: index,
        role: request.role,
        nonce: *request.nonce,
        group: request.hello.group,
        contact_policy: request.hello.contact_policy,
        opened_at: Some(request.hello.opened_at),
        expires_at: Some(request.hello.expires_at),
    })
}

fn resolution_of(request: &ReceiptRequest<'_>) -> Result<Resolution> {
    let mut signature = [0u8; 64];
    if !request.receipt_signature.is_empty() {
        signature = request
            .receipt_signature
            .try_into()
            .map_err(|_| ErrorCode::Refused)?;
    }
    Ok(Resolution {
        kind: request.kind,
        issued_at: request.issued_at,
        history_digest: request.contact.hello.history,
        ed25519_receipt_digest: *request.receipt_digest,
        signature,
    })
}

fn bytes64(signature: &[u8]) -> Result<[u8; 64]> {
    signature.try_into().map_err(|_| ErrorCode::Refused)
}

pub struct AccountContact<V> {
    pub view: V,
}

/// Whether `member` has a roster row whose enrollment window covers `now`
/// (inclusive start, exclusive deadline).
fn enrolled(rows: &[Enrollment], member: &[u8; 32], now: u64) -> bool {
    rows.iter()
        .any(|row| row.member == *member && row.starts_at <= now && now < row.expires_at)
}

/// The counterpart's enrollment window in the account's verified roster.
fn current_member(account: &Account, peer: &Binding, now: u64) -> Result<()> {
    let digest = cnbx::member_digest_of(peer.member()).map_err(|_| ErrorCode::Refused)?;
    enrolled(account.roster().entries(), &digest, now)
        .then_some(())
        .ok_or(ErrorCode::Refused)
}

impl<V: AccountView> WaveContact for AccountContact<V> {
    fn member<'a>(&'a self, peer: &'a Binding, now: u64) -> OwnedFuture<'a, ()> {
        Box::pin(async move { current_member(&self.view.current().await?, peer, now) })
    }
    fn sign<'a>(
        &'a self,
        request: ContactRequest<'a>,
        _: u64,
        signer: &'a dyn AccountSigner,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let account = self.view.current().await?;
            let digest = account
                .contact_digest(&reserve_of(&account, &request)?)
                .map_err(|_| ErrorCode::Refused)?;
            let signature = signer
                .sign(SigningPhase::Contact, *request.nonce, digest)
                .await?;
            Ok(signature.to_vec())
        })
    }
    fn verify<'a>(
        &'a self,
        request: ContactRequest<'a>,
        signature: &'a [u8],
        _: u64,
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async move {
            let account = self.view.current().await?;
            account
                .verify_contact(&reserve_of(&account, &request)?, &bytes64(signature)?)
                .map_err(|_| ErrorCode::Refused)
        })
    }
    fn sign_resolution<'a>(
        &'a self,
        request: ReceiptRequest<'a>,
        _: u64,
        signer: &'a dyn AccountSigner,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let account = self.view.current().await?;
            let reserve = reserve_of(&account, &request.contact)?;
            let digest = account
                .resolution_digest(&reserve, &resolution_of(&request)?)
                .map_err(|_| ErrorCode::Refused)?;
            let signature = signer
                .sign(SigningPhase::Resolution, *request.contact.nonce, digest)
                .await?;
            Ok(signature.to_vec())
        })
    }
    fn verify_resolution<'a>(
        &'a self,
        request: ReceiptRequest<'a>,
        signature: &'a [u8],
        _: u64,
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async move {
            let account = self.view.current().await?;
            let reserve = reserve_of(&account, &request.contact)?;
            let mut receipt = resolution_of(&request)?;
            receipt.signature = bytes64(signature)?;
            account
                .verify_resolution(&reserve, &receipt)
                .map_err(|_| ErrorCode::Refused)
        })
    }
    fn sign_acknowledgment<'a>(
        &'a self,
        request: ReceiptRequest<'a>,
        _: u64,
        signer: &'a dyn AccountSigner,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let account = self.view.current().await?;
            let reserve = reserve_of(&account, &request.contact)?;
            let digest = account
                .acknowledgment_digest(&reserve, &resolution_of(&request)?, request.issued_at)
                .map_err(|_| ErrorCode::Refused)?;
            let signature = signer
                .sign(SigningPhase::Acknowledgment, *request.contact.nonce, digest)
                .await?;
            Ok(signature.to_vec())
        })
    }
    fn verify_acknowledgment<'a>(
        &'a self,
        request: ReceiptRequest<'a>,
        signature: &'a [u8],
        _: u64,
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async move {
            let account = self.view.current().await?;
            let reserve = reserve_of(&account, &request.contact)?;
            let ack = Acknowledgment {
                issued_at: request.issued_at,
                signature: bytes64(signature)?,
            };
            account
                .verify_acknowledgment(&reserve, &resolution_of(&request)?, &ack)
                .map_err(|_| ErrorCode::Refused)
        })
    }
}

/// The recipient's terms: its enrollment leaf as wallet authority and a fresh one-use
/// challenge. The contact signature is added by the ports.
pub struct AccountTerms<V, E> {
    pub view: V,
    /// Fresh random bytes (the embedding's entropy).
    pub entropy: E,
}

impl<V: AccountView, E: Fn() -> Result<[u8; 32]>> WaveTerms for AccountTerms<V, E> {
    fn terms<'a>(
        &'a self,
        _nonce: &'a [u8; 32],
        _hello: &'a Hello,
        _now: u64,
    ) -> OwnedFuture<'a, Terms> {
        Box::pin(async move {
            let account = self.view.current().await?;
            let challenge = (self.entropy)()?;
            if challenge == [0; 32] {
                return Err(ErrorCode::Unavailable);
            }
            Ok(Terms {
                recipient_authority: account.owner().leaf,
                recipient_challenge: challenge,
                contact_signature: vec![],
                recipient_handle: vec![],
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(member: u8, starts_at: u64, expires_at: u64) -> Enrollment {
        Enrollment {
            member: [member; 32],
            key: [0; 64],
            secret_hash: [0; 32],
            starts_at,
            expires_at,
            delegation_digest: [0; 32],
            leaf: [0; 32],
            index: 0,
            path: [[0; 32]; 32],
        }
    }

    #[test]
    fn a_peer_is_a_member_only_inside_its_enrollment_window() {
        let rows = [row(1, 10, 20), row(2, 5, 6)];
        assert!(!enrolled(&rows, &[1; 32], 9));
        assert!(enrolled(&rows, &[1; 32], 10));
        assert!(enrolled(&rows, &[1; 32], 19));
        assert!(!enrolled(&rows, &[1; 32], 20));
        // Another row's window never admits this member; an unknown member never matches.
        assert!(!enrolled(&rows, &[2; 32], 10));
        assert!(!enrolled(&rows, &[3; 32], 5));
        assert!(!enrolled(&[], &[1; 32], 10));
    }
}
