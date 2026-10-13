//! Independent validating original CDHT nodes; only transport is inert here.
//! These native owner cases do not qualify the maintained Tor transport.
use cdht::{Backend, Network};
use std::rc::Rc;

pub struct Verifier;
impl cdht::Verifier for Verifier {
    fn verify(&self, public: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
        ckmg::verify(
            &ckmg::PublicKey::new(ckmg::VLD0, *public),
            data,
            &ckmg::Signature::new(ckmg::VLD0, *signature),
        )
        .is_ok()
    }
}
#[derive(Clone)]
pub struct Nodes(Rc<Vec<cdht::LocalBackend<Verifier>>>);
impl Default for Nodes {
    fn default() -> Self {
        Self::new()
    }
}
impl Nodes {
    pub fn new() -> Self {
        Self(Rc::new(
            (0..5).map(|_| cdht::LocalBackend::new(Verifier)).collect(),
        ))
    }
    fn node(&self, node: &cdht::NodeId) -> Result<&cdht::LocalBackend<Verifier>, cdht::Error> {
        if *node != [node[0]; 32] {
            return Err(cdht::Error::Unavailable);
        }
        self.0
            .get(usize::from(node[0]))
            .ok_or(cdht::Error::Unavailable)
    }
}
impl Network for Nodes {
    fn now_ms(&self) -> u64 {
        1
    }
    async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        Ok((0..5).map(|index| [index; 32]).collect())
    }
    async fn descriptor(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        self.node(node)?.descriptor(key).await
    }
    async fn get(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
        subkey: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        self.node(node)?.get(key, subkey).await
    }
    async fn set(
        &self,
        node: &cdht::NodeId,
        descriptor: &cdht::Descriptor,
        subkey: u32,
        value: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        let node = self.node(node)?;
        node.create(descriptor).await?;
        node.set(&descriptor.key(), subkey, value).await
    }
    async fn watch(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
    ) -> Result<cdht::WatchId, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<(), cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn changes(
        &self,
        _: &cdht::NodeId,
        _: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}
