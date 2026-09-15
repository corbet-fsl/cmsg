//! In-memory state for one browser onion-service runtime, never serialized.
//!
//! Each instance identity can be acquired exactly once, including after drop.
//! This deliberately forbids restarting an introduction key with a fresh replay
//! filter. Construct a new runtime AND a fresh ephemeral keystore to restart.
//! There is no filesystem emulation and no raw-subdirectory API.
use crate::{err::{Action, Resource}, slug::{SlugRef, TryIntoSlug}, Error, ErrorSource};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, fmt, marker::PhantomData, sync::{Arc, Mutex}};

pub type Result<T> = std::result::Result<T, Error>;
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

fn error(source: impl Into<ErrorSource>, action: Action) -> Error {
    Error::new(source, action, Resource::Manager)
}
fn poisoned(action: Action) -> Error { error(ErrorSource::NoLock, action) }

pub trait InstanceIdentity {
    fn kind() -> &'static str;
    fn write_identity(&self, formatter: &mut fmt::Formatter) -> fmt::Result;
}

#[derive(Clone, Default)]
pub struct StateDirectory { claimed: Arc<Mutex<BTreeSet<String>>> }

impl fmt::Debug for StateDirectory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("StateDirectory(ephemeral)") }
}

impl StateDirectory {
    pub fn new_ephemeral() -> Self { Self::default() }

    pub fn acquire_instance<I: InstanceIdentity>(&self, identity: &I) -> Result<InstanceStateHandle> {
        struct Identity<'a, I>(&'a I);
        impl<I: InstanceIdentity> fmt::Display for Identity<'_, I> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.0.write_identity(f) }
        }
        let kind = I::kind();
        let name = Identity(identity).to_string();
        SlugRef::new(kind)?;
        SlugRef::new(&name)?;
        if kind.is_empty() || name.is_empty() { return Err(poisoned(Action::Initializing)); }
        let mut claimed = self.claimed.lock().map_err(|_| poisoned(Action::Locking))?;
        if !claimed.insert(format!("{kind}/{name}")) {
            return Err(error(ErrorSource::AlreadyLocked, Action::Locking));
        }
        Ok(InstanceStateHandle { state: Arc::new(Mutex::new(InstanceState::default())) })
    }
}

#[derive(Default)]
struct InstanceState {
    keys: BTreeSet<String>,
    values: BTreeMap<String, Vec<u8>>,
    bytes: usize,
}

impl Drop for InstanceState {
    fn drop(&mut self) { for bytes in self.values.values_mut() { bytes.fill(0); } }
}

#[derive(Clone)]
pub struct InstanceStateHandle { state: Arc<Mutex<InstanceState>> }

impl fmt::Debug for InstanceStateHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("InstanceStateHandle(ephemeral)") }
}

impl InstanceStateHandle {
    pub fn storage_handle<T>(&self, key: &(impl TryIntoSlug + ?Sized)) -> Result<StorageHandle<T>> {
        let key = key.try_into_slug()?.to_string();
        let mut state = self.state.lock().map_err(|_| poisoned(Action::Initializing))?;
        if !state.keys.insert(key.clone()) { return Err(error(ErrorSource::AlreadyLocked, Action::Locking)); }
        Ok(StorageHandle { state: self.state.clone(), key, marker: PhantomData })
    }
}

pub struct StorageHandle<T> {
    state: Arc<Mutex<InstanceState>>,
    key: String,
    marker: PhantomData<fn(T) -> T>,
}

impl<T> fmt::Debug for StorageHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("StorageHandle(ephemeral)") }
}

impl<T: DeserializeOwned> StorageHandle<T> {
    pub fn load(&self) -> Result<Option<T>> {
        let state = self.state.lock().map_err(|_| poisoned(Action::Loading))?;
        state.values.get(&self.key).map(|bytes| serde_json::from_slice(bytes)
            .map_err(|e| error(ErrorSource::Serde(Arc::new(e)), Action::Loading))).transpose()
    }
}

impl<T: Serialize> StorageHandle<T> {
    pub fn store(&mut self, value: &T) -> Result<()> {
        let mut encoded = serde_json::to_vec(value)
            .map_err(|e| error(ErrorSource::Serde(Arc::new(e)), Action::Storing))?;
        let mut state = self.state.lock().map_err(|_| poisoned(Action::Storing))?;
        let previous = state.values.get(&self.key).map_or(0, Vec::len);
        let total = state.bytes.checked_sub(previous).and_then(|n| n.checked_add(encoded.len()));
        let Some(total) = total.filter(|n| *n <= MAX_STATE_BYTES) else {
            encoded.fill(0);
            return Err(poisoned(Action::Storing));
        };
        if let Some(mut old) = state.values.insert(self.key.clone(), encoded) { old.fill(0); }
        state.bytes = total;
        Ok(())
    }
}

impl<T> StorageHandle<T> {
    pub fn delete(&mut self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| poisoned(Action::Deleting))?;
        if let Some(mut old) = state.values.remove(&self.key) {
            state.bytes -= old.len();
            old.fill(0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Service;
    impl InstanceIdentity for Service {
        fn kind() -> &'static str { "hss" }
        fn write_identity(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("fixture") }
    }

    #[test]
    fn runtime_never_reacquires_a_service_even_after_all_handles_drop() {
        let directory = StateDirectory::new_ephemeral();
        let instance = directory.acquire_instance(&Service).unwrap();
        assert!(directory.clone().acquire_instance(&Service).is_err());
        drop(instance);
        assert!(directory.acquire_instance(&Service).is_err());
    }

    #[test]
    fn unique_storage_handles_preserve_typed_state_and_delete_atomically() {
        let instance = StateDirectory::new_ephemeral().acquire_instance(&Service).unwrap();
        let mut storage = instance.storage_handle::<Vec<u8>>("fixture").unwrap();
        assert!(instance.clone().storage_handle::<Vec<u8>>("fixture").is_err());
        assert_eq!(storage.load().unwrap(), None);
        storage.store(&vec![0, 255, 1]).unwrap();
        assert_eq!(storage.load().unwrap(), Some(vec![0, 255, 1]));
        storage.delete().unwrap();
        assert_eq!(storage.load().unwrap(), None);
    }

    #[test]
    fn memory_limit_rejects_replacement_without_destroying_previous_state() {
        let instance = StateDirectory::new_ephemeral().acquire_instance(&Service).unwrap();
        let mut storage = instance.storage_handle::<String>("fixture").unwrap();
        storage.store(&"retained".into()).unwrap();
        assert!(storage.store(&"x".repeat(MAX_STATE_BYTES)).is_err());
        assert_eq!(storage.load().unwrap().as_deref(), Some("retained"));
    }
}
