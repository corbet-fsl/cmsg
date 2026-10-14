//! Ending: when the platform feed states that a community's key chain ended, the
//! device deletes every local trace of that community.
//!
//! `foyer.ending_refresh` follows the PLATFORM feed (the global service's signed
//! Communities snapshot, which stays served when a community's own door is gone),
//! checks the verified end-of-chain entries against the founding fingerprint this
//! device pinned for the community and, on a match, purges the community's local
//! data through the [`LocalData`] the trusted embedder lent, then drops every
//! handle the Door held for the community. The reason class changes nothing: a
//! dissolved and a banned community are deleted alike. Nothing is deleted on a
//! feed that failed verification, and nothing is claimed deleted when the purge
//! failed (the next refresh retries).
use super::foyer::Scope;
use super::identity::{Fingerprint, LocalData, Memberships, PurgeFailed};
use super::*;

/// Answer of `foyer.ending_refresh`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Refreshed {
    /// The platform ended this community: its local data is gone and this Door no
    /// longer serves it.
    pub ended: bool,
}

/// Deletes every file under one directory: the native device keeps one community
/// per storage directory, so the namespace is the directory.
pub struct DirectoryData {
    directory: std::path::PathBuf,
}

impl DirectoryData {
    pub fn new(directory: impl Into<std::path::PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }
}

impl LocalData for DirectoryData {
    fn purge(&mut self, _namespace: &str) -> std::result::Result<(), PurgeFailed> {
        let entries = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            // Nothing stored is nothing to delete.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(PurgeFailed),
        };
        for entry in entries {
            let path = entry.map_err(|_| PurgeFailed)?.path();
            let removed = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            removed.map_err(|_| PurgeFailed)?;
        }
        Ok(())
    }
}

impl Door {
    /// Trusted embedding control: lend the device's local-data deletion. Without
    /// it `foyer.ending_refresh` refuses rather than pretend to delete.
    pub fn set_local_data(&mut self, data: Box<dyn LocalData + Send>) {
        self.local_data = Some(data);
    }
}

/// Follow the platform feed once and return its verified end-of-chain entries.
async fn platform_ended(binding: &mut foyer::Binding) -> Result<Vec<cchr::Ended>> {
    let client = binding
        .sessions
        .clients
        .get_mut(&Scope::Global)
        .ok_or(ErrorCode::Unavailable)?;
    let mut trust = client.trust().map_err(foyer::trust_error)?;
    let failed_clock = std::cell::Cell::new(false);
    let clock = || match cbrd::clnk::Clock::now(&board::SystemClock) {
        Ok(milliseconds) => milliseconds / 1000,
        Err(_) => {
            // An unusable clock must not grant freshness.
            failed_clock.set(true);
            u64::MAX
        }
    };
    let result = if trust.state() == cfyr::trust::State::Stopped {
        trust.start(clock).await
    } else {
        match trust.refresh(clock()) {
            Ok(()) => trust.poll(clock).await.map(|_| ()),
            Err(error) => Err(error),
        }
    };
    if failed_clock.get() {
        return Err(ErrorCode::Clock);
    }
    result.map_err(foyer::trust_error)?;
    drop(trust);
    let now = cbrd::clnk::Clock::now(&board::SystemClock).map_err(|_| ErrorCode::Clock)? / 1000;
    client
        .current(now, |charter| {
            if charter.community() != "wallet" {
                return Err(ErrorCode::Unauthorized);
            }
            Ok(charter.ended().to_vec())
        })
        .map_err(foyer::trust_error)?
}

/// Follow the platform feed and delete this community's local data if it ended.
pub(super) async fn ending_refresh(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Refreshed, Vec<Event>)> {
    let origin = door
        .grants
        .get(key)
        .ok_or(ErrorCode::Unauthorized)?
        .origin
        .clone();
    let community = door.config.community.clone();
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    // The fingerprint this device pinned; nothing pinned means nothing to retire.
    let pinned = binding.community_fingerprint();
    let ended = platform_ended(binding).await?;
    let Some(fingerprint) = pinned else {
        return Ok((Refreshed { ended: false }, vec![]));
    };
    let mut memberships = Memberships::default();
    memberships
        .join(&community, Fingerprint(fingerprint.0))
        .map_err(|_| ErrorCode::Refused)?;
    if !ended
        .iter()
        .any(|entry| Fingerprint(entry.fingerprint) == fingerprint)
    {
        return Ok((Refreshed { ended: false }, vec![]));
    }
    struct Lent(Box<dyn LocalData + Send>);
    impl LocalData for Lent {
        fn purge(&mut self, namespace: &str) -> std::result::Result<(), PurgeFailed> {
            self.0.purge(namespace)
        }
    }
    let mut data = Lent(door.local_data.take().ok_or(ErrorCode::Unavailable)?);
    let done = memberships.retire_ended(&ended, &mut data);
    door.local_data = Some(data.0);
    if done.is_empty() {
        // The purge failed: keep everything and try again at the next refresh.
        return Err(ErrorCode::Unavailable);
    }
    door.foyers.remove(&origin);
    door.boards.remove(&origin);
    door.meshes.remove(&origin);
    door.vaults.remove(&origin);
    door.accounts.remove(&origin);
    door.wave_ports.remove(&origin);
    door.grants.retain(|_, grant| grant.origin != origin);
    Ok((Refreshed { ended: true }, vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_purge_removes_files_and_folders_and_tolerates_nothing_stored() {
        let root = std::env::temp_dir().join(format!("cmsg-ending-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("checkpoint"), b"x").unwrap();
        std::fs::write(root.join("sub").join("record"), b"y").unwrap();
        let mut data = DirectoryData::new(&root);
        data.purge("namespace").unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        // Already empty, and a directory that never existed, are both success.
        data.purge("namespace").unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        data.purge("namespace").unwrap();
    }
}
