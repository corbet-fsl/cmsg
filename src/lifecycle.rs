//! Deterministic authorization time and same-key credential renewal boundary.
use crate::Error;

/// Trusted client time source. Never accept protocol-supplied time as this clock.
/// The source is process state, not part of an encrypted snapshot.
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, Error>;
}

pub(crate) struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Admission)?
            .as_secs())
    }
}
