//! Retained native and browser composition. Never a public action or Wasm port.
use super::*;

/// Trusted custody composition retained by the isolated Vault's owner task.
/// Implementations consume original login custody, bind durable owners and
/// update login output only after the parent-owned acceptance sequence succeeds.
/// A rejected dispatch permits only cleanup/negative observation, never new
/// custody or publication; the actor preserves the original refusal regardless.
/// This Rust-only port is absent from Wasm exports and all generated actions.
pub trait VaultComposer {
    fn after_dispatch<'a>(
        &'a mut self,
        door: &'a mut Door,
        origin: &'a str,
        token: &'a ClientToken,
        action: &'a str,
        output: &'a mut Output,
        now: u64,
    ) -> futures_util::future::LocalBoxFuture<'a, Result<()>>;

    /// Idempotently close independent transport custody on composition failure
    /// or after admitted work drains, before Vault/Store shutdown. Drop must
    /// also close it if the actor unwinds or host attachment fails.
    fn close(&mut self);

    /// Await every retained network/credential task after close, before the
    /// actor locks its Vault/Store. Must be idempotent and cannot reopen custody.
    fn drain(&mut self) -> futures_util::future::LocalBoxFuture<'_, Result<()>>;
}
