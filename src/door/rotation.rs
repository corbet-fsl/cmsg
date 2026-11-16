//! A custody save refused because the member's lineage rotated (L20261116a).
//!
//! After a device removal rotates the vault keys, the custody still seals under the
//! pre-rotation epoch key, which the removed device holds, so cvlt refuses every save with
//! `WalletRestoreError::Rotated`. The app reopens the custody itself and answers
//! [`ErrorCode::CustodyReopened`], a retryable code: the client repeats the same request and
//! it seals under the current epoch. It is never a fault of the session.
use super::ErrorCode;
use cvlt::WalletRestoreError;
use std::future::Future;

/// A custody that can reopen its owners in place under the current epoch.
pub(crate) trait ReopenAfterRotation {
    fn reopen(&mut self) -> impl Future<Output = Result<(), WalletRestoreError>>;
}

impl<B, C, E, A, R> ReopenAfterRotation for cvlt::Vault<B, C, E, A, R, cvlt::WalletCustody>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    async fn reopen(&mut self) -> Result<(), WalletRestoreError> {
        self.reopen_after_rotation().await
    }
}

/// The refusal a custody save maps to. A rotation reopens the custody and asks for a retry;
/// when the reopen itself is refused (this device lost its authority), and for every other
/// failure, the caller's `fallback` code stands.
pub(crate) async fn custody_refusal<V: ReopenAfterRotation>(
    custody: &mut V,
    error: WalletRestoreError,
    fallback: ErrorCode,
) -> ErrorCode {
    if matches!(error, WalletRestoreError::Rotated) && custody.reopen().await.is_ok() {
        return ErrorCode::CustodyReopened;
    }
    super::cause::emit(file!(), line!(), "custody_refusal", fallback, &error)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        reopens: bool,
        reopened: u32,
    }
    impl ReopenAfterRotation for Fake {
        async fn reopen(&mut self) -> Result<(), WalletRestoreError> {
            self.reopened += 1;
            if self.reopens {
                Ok(())
            } else {
                Err(WalletRestoreError::Scope)
            }
        }
    }
    fn refuse(reopens: bool, error: WalletRestoreError) -> (ErrorCode, u32) {
        let mut fake = Fake {
            reopens,
            reopened: 0,
        };
        let code =
            futures_executor::block_on(custody_refusal(&mut fake, error, ErrorCode::Unauthorized));
        (code, fake.reopened)
    }

    #[test]
    fn a_rotation_reopens_the_custody_and_asks_for_a_retry() {
        assert_eq!(
            refuse(true, WalletRestoreError::Rotated),
            (ErrorCode::CustodyReopened, 1)
        );
    }

    #[test]
    fn a_refused_reopen_keeps_the_fallback_code() {
        assert_eq!(
            refuse(false, WalletRestoreError::Rotated),
            (ErrorCode::Unauthorized, 1)
        );
    }

    #[test]
    fn any_other_failure_keeps_the_fallback_code_and_reopens_nothing() {
        assert_eq!(
            refuse(true, WalletRestoreError::Scope),
            (ErrorCode::Unauthorized, 0)
        );
    }

    #[test]
    fn the_retry_code_is_transient_and_never_ends_the_session() {
        assert_eq!(ErrorCode::CustodyReopened.exit_code(), 75);
        assert!(!crate::door::custody::refusal_ends_session(
            "inbox.record_prepare",
            ErrorCode::CustodyReopened
        ));
        assert_eq!(
            serde_json::to_string(&ErrorCode::CustodyReopened).unwrap(),
            "\"custody_reopened\""
        );
    }
}
