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
    /// `Ok(true)` when the custody was reopened, `Ok(false)` when nothing had rotated.
    fn reopen(&mut self) -> impl Future<Output = Result<bool, WalletRestoreError>>;
}

impl<B, C, E, A, R> ReopenAfterRotation for cvlt::Vault<B, C, E, A, R, cvlt::WalletCustody>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    async fn reopen(&mut self) -> Result<bool, WalletRestoreError> {
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
    if matches!(error, WalletRestoreError::Rotated) {
        match custody.reopen().await {
            Ok(true) => return ErrorCode::CustodyReopened,
            Ok(false) => {}
            Err(cause) => {
                super::cause::print(file!(), line!(), "custody reopen refused", &cause);
            }
        }
    }
    super::cause::emit(file!(), line!(), "custody_refusal", fallback, &error)
}

/// Run one custody save; when it meets a rotation, reopen the custody and run it once more
/// (the refused save had no effect, so the second run is its first execution). The caller sees
/// [`ErrorCode::CustodyReopened`] only if the second run meets a rotation as well, so the hard
/// path stays in the engine and a frontend never retries (owner principle L20261116k).
pub(crate) async fn retry_after_reopen<V, T>(
    custody: &mut V,
    fallback: ErrorCode,
    mut save: impl AsyncFnMut(&mut V) -> Result<T, WalletRestoreError>,
) -> Result<T, ErrorCode>
where
    V: ReopenAfterRotation,
{
    let mut again = true;
    loop {
        let error = match save(custody).await {
            Ok(done) => return Ok(done),
            Err(error) => error,
        };
        let code = custody_refusal(custody, error, fallback).await;
        if code != ErrorCode::CustodyReopened || !again {
            return Err(code);
        }
        again = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        reopens: bool,
        reopened: u32,
    }
    impl ReopenAfterRotation for Fake {
        async fn reopen(&mut self) -> Result<bool, WalletRestoreError> {
            self.reopened += 1;
            if self.reopens {
                Ok(true)
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

    fn run(
        saves: &mut Vec<Result<u8, WalletRestoreError>>,
        reopens: bool,
    ) -> (Result<u8, ErrorCode>, u32) {
        let mut fake = Fake {
            reopens,
            reopened: 0,
        };
        let result = futures_executor::block_on(retry_after_reopen(
            &mut fake,
            ErrorCode::Unauthorized,
            async |_: &mut Fake| saves.remove(0),
        ));
        (result, fake.reopened)
    }

    #[test]
    fn a_save_that_met_a_rotation_runs_once_more_after_the_reopen() {
        let mut saves = vec![Err(WalletRestoreError::Rotated), Ok(7)];
        assert_eq!(run(&mut saves, true), (Ok(7), 1));
        assert!(saves.is_empty());
    }

    #[test]
    fn a_second_rotation_reaches_the_caller_as_the_retry_code() {
        let mut saves = vec![
            Err(WalletRestoreError::Rotated),
            Err(WalletRestoreError::Rotated),
        ];
        assert_eq!(run(&mut saves, true), (Err(ErrorCode::CustodyReopened), 2));
    }

    #[test]
    fn a_save_without_a_rotation_is_never_repeated() {
        let mut saves = vec![Err(WalletRestoreError::Scope)];
        assert_eq!(run(&mut saves, true), (Err(ErrorCode::Unauthorized), 0));
        let mut saves = vec![Err(WalletRestoreError::Rotated)];
        assert_eq!(run(&mut saves, false), (Err(ErrorCode::Unauthorized), 1));
    }
    #[test]
    fn a_refused_reopen_keeps_the_fallback_code() {
        assert_eq!(
            refuse(false, WalletRestoreError::Rotated),
            (ErrorCode::Unauthorized, 1)
        );
    }

    #[test]
    fn a_reopen_that_found_nothing_rotated_is_not_a_retry() {
        struct Unmoved;
        impl ReopenAfterRotation for Unmoved {
            async fn reopen(&mut self) -> Result<bool, WalletRestoreError> {
                Ok(false)
            }
        }
        let code = futures_executor::block_on(custody_refusal(
            &mut Unmoved,
            WalletRestoreError::Rotated,
            ErrorCode::Unauthorized,
        ));
        assert_eq!(code, ErrorCode::Unauthorized);
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
