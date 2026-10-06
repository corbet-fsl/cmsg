//! Compound Tor checkpoint reader regression. Child of `lineage_recovery`; reuses
//! its setup/inspector/observer/clock via `use super::*`. Synthetic transport and
//! setup authority only; never runtime/Tor/G3 evidence.
use super::*;
use cdht::runtime::Backend as RuntimeBackend;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

struct Adapt<'k, 's>(&'s ckmg::Vld0Signer<'k>);
impl cdht::Signer for Adapt<'_, '_> {
    fn public_key(&self) -> [u8; 32] {
        *self.0.public_key()
    }
    fn sign(&self, data: &[u8]) -> Result<[u8; 64], cdht::Error> {
        self.0.sign(data).map_err(|_| cdht::Error::Signer)
    }
}

struct SyntheticNode {
    id: cdht::NodeId,
    descriptor: Option<cdht::Descriptor>,
    values: BTreeMap<u32, cdht::SignedValue>,
}
struct Inner {
    nodes: Vec<SyntheticNode>,
    duplicate: bool,
}
#[derive(Clone)]
struct SyntheticTransport {
    inner: Rc<RefCell<Inner>>,
}
impl SyntheticTransport {
    fn triple(descriptor: cdht::Descriptor, entries: Vec<(u32, cdht::SignedValue)>) -> Self {
        let ids: Vec<cdht::NodeId> = vec![[11u8; 32], [22u8; 32], [33u8; 32]];
        let nodes = ids
            .into_iter()
            .map(|id| SyntheticNode {
                id,
                descriptor: Some(descriptor.clone()),
                values: entries.iter().cloned().collect(),
            })
            .collect();
        Self {
            inner: Rc::new(RefCell::new(Inner {
                nodes,
                duplicate: false,
            })),
        }
    }
    fn set_value(&self, subkey: u32, value: Option<cdht::SignedValue>) {
        for node in &mut self.inner.borrow_mut().nodes {
            match &value {
                Some(v) => {
                    node.values.insert(subkey, v.clone());
                }
                None => {
                    node.values.remove(&subkey);
                }
            }
        }
    }
    fn clear_node_value(&self, index: usize, subkey: u32) {
        self.inner.borrow_mut().nodes[index].values.remove(&subkey);
    }
    fn set_duplicate(&self, duplicate: bool) {
        self.inner.borrow_mut().duplicate = duplicate;
    }
    fn tamper_values(&self) {
        for node in &mut self.inner.borrow_mut().nodes {
            for value in node.values.values_mut() {
                value.signature[0] ^= 1;
            }
        }
    }
    fn install_bad_descriptor(&self, bad: cdht::Descriptor) {
        for node in &mut self.inner.borrow_mut().nodes {
            node.descriptor = Some(bad.clone());
        }
    }
}
impl cdht::Network for SyntheticTransport {
    fn now_ms(&self) -> u64 {
        0
    }
    async fn closest(&self, _key: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        let inner = self.inner.borrow();
        if inner.duplicate {
            let id = inner.nodes[0].id;
            return Ok(vec![id, id, id]);
        }
        Ok(inner.nodes.iter().map(|n| n.id).collect())
    }
    async fn descriptor(
        &self,
        node: &cdht::NodeId,
        _key: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        let inner = self.inner.borrow();
        let found = inner
            .nodes
            .iter()
            .find(|n| &n.id == node)
            .ok_or(cdht::Error::Unavailable)?;
        Ok(found.descriptor.clone())
    }
    async fn get(
        &self,
        node: &cdht::NodeId,
        _key: &cdht::RecordKey,
        subkey: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        let inner = self.inner.borrow();
        let found = inner
            .nodes
            .iter()
            .find(|n| &n.id == node)
            .ok_or(cdht::Error::Unavailable)?;
        Ok(found.values.get(&subkey).cloned())
    }
    async fn set(
        &self,
        _node: &cdht::NodeId,
        _descriptor: &cdht::Descriptor,
        _subkey: u32,
        _value: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn watch(
        &self,
        _node: &cdht::NodeId,
        _key: &cdht::RecordKey,
    ) -> Result<cdht::WatchId, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(
        &self,
        _node: &cdht::NodeId,
        _watch: cdht::WatchId,
    ) -> Result<(), cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn changes(
        &self,
        _node: &cdht::NodeId,
        _watch: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}

struct CompoundMaterial {
    descriptor: cdht::Descriptor,
    owner: [u8; 32],
    plaintext31_a: Vec<u8>,
    value31_a: cdht::SignedValue,
    plaintext31_b: Vec<u8>,
    value31_b: cdht::SignedValue,
    plaintext30: Vec<u8>,
    value30: cdht::SignedValue,
}

async fn checkpoint_bootstrap() -> ckmg::CheckpointBootstrap {
    let (sealed, lineage, _, _) = setup().await;
    let mut clock = FixtureClock(Rc::new(Cell::new(NOW)));
    let mut authority = observer(&lineage, ckmg::Action::Use, false);
    inspector()
        .bootstrap(&sealed, READ_EVIDENCE, &mut clock, &mut authority)
        .await
        .unwrap()
}

fn sign_material(custody: &ckmg::CheckpointRecordCustody<'_>) -> CompoundMaterial {
    custody.with_record(|signer, cipher| {
        let adapt = Adapt(&signer);
        let schema = cdht::Schema::dflt(cvlt::CHECKPOINT_SUBKEYS).unwrap();
        let owner = *custody.public_key().value();
        let descriptor = cdht::Descriptor::create(&schema, &adapt).unwrap();
        let seal = |nonce: [u8; 24], plain: &[u8]| cipher.crypt(&nonce, plain).unwrap().to_vec();
        let plaintext31_a = b"compound tor 31 seq1".to_vec();
        let nonce_a = [31u8; 24];
        let value31_a = cdht::SignedValue::sign_with_nonce(
            &owner,
            31,
            1,
            seal(nonce_a, &plaintext31_a),
            Some(nonce_a),
            &adapt,
        )
        .unwrap();
        let plaintext31_b = b"compound tor 31 seq2".to_vec();
        let nonce_b = [32u8; 24];
        let value31_b = cdht::SignedValue::sign_with_nonce(
            &owner,
            31,
            2,
            seal(nonce_b, &plaintext31_b),
            Some(nonce_b),
            &adapt,
        )
        .unwrap();
        let plaintext30 = b"compound tor 30 seq1".to_vec();
        let nonce30 = [30u8; 24];
        let value30 = cdht::SignedValue::sign_with_nonce(
            &owner,
            30,
            1,
            seal(nonce30, &plaintext30),
            Some(nonce30),
            &adapt,
        )
        .unwrap();
        CompoundMaterial {
            descriptor,
            owner,
            plaintext31_a,
            value31_a,
            plaintext31_b,
            value31_b,
            plaintext30,
            value30,
        }
    })
}

#[tokio::test]
async fn complete_signed_3_holder_read_decrypts_at_subkey31() {
    let bootstrap = checkpoint_bootstrap().await;
    let custody = bootstrap.record(None).unwrap();
    let mat = sign_material(&custody);
    let transport =
        SyntheticTransport::triple(mat.descriptor.clone(), vec![(31, mat.value31_a.clone())]);
    let record = cvlt::TorReadRecord::checkpoint(transport, custody).unwrap();
    let value = record.get(31, true).await.unwrap().unwrap();
    assert_eq!(value.seq, 1);
    assert_eq!(value.writer, mat.owner);
    assert_eq!(value.data.as_slice(), mat.plaintext31_a.as_slice());
    assert_eq!(
        record.get(5, true).await.unwrap_err(),
        cdht::Error::Unavailable
    );
}

#[tokio::test]
async fn fewer_than_3_or_duplicate_identity_cannot_establish_read() {
    let bootstrap = checkpoint_bootstrap().await;
    let custody = bootstrap.record(None).unwrap();
    let mat = sign_material(&custody);
    let transport =
        SyntheticTransport::triple(mat.descriptor.clone(), vec![(31, mat.value31_a.clone())]);
    let handle = transport.clone();
    let record = cvlt::TorReadRecord::checkpoint(transport, custody).unwrap();
    handle.clear_node_value(2, 31);
    assert_eq!(
        record.get(31, true).await.unwrap_err(),
        cdht::Error::Unavailable
    );
    let bootstrap = checkpoint_bootstrap().await;
    let custody = bootstrap.record(None).unwrap();
    let mat = sign_material(&custody);
    let transport =
        SyntheticTransport::triple(mat.descriptor.clone(), vec![(31, mat.value31_a.clone())]);
    transport.set_duplicate(true);
    let record = cvlt::TorReadRecord::checkpoint(transport, custody).unwrap();
    assert_eq!(
        record.get(31, true).await.unwrap_err(),
        cdht::Error::Unavailable
    );
}

#[tokio::test]
async fn tampered_signature_or_wrong_descriptor_refused() {
    let bootstrap = checkpoint_bootstrap().await;
    let custody = bootstrap.record(None).unwrap();
    let mat = sign_material(&custody);
    let transport =
        SyntheticTransport::triple(mat.descriptor.clone(), vec![(31, mat.value31_a.clone())]);
    transport.tamper_values();
    let record = cvlt::TorReadRecord::checkpoint(transport, custody).unwrap();
    assert_eq!(
        record.get(31, true).await.unwrap_err(),
        cdht::Error::Unavailable
    );
    let bootstrap = checkpoint_bootstrap().await;
    let custody = bootstrap.record(None).unwrap();
    let mat = sign_material(&custody);
    let transport =
        SyntheticTransport::triple(mat.descriptor.clone(), vec![(31, mat.value31_a.clone())]);
    let mut bad = mat.descriptor.clone();
    bad.signature[0] ^= 1;
    transport.install_bad_descriptor(bad);
    let record = cvlt::TorReadRecord::checkpoint(transport, custody).unwrap();
    assert_eq!(
        record.get(31, true).await.unwrap_err(),
        cdht::Error::Unavailable
    );
}

#[tokio::test]
async fn independent_sequence_floor_by_subkey_and_readonly_republish_refused() {
    let bootstrap = checkpoint_bootstrap().await;
    let custody = bootstrap.record(None).unwrap();
    let mat = sign_material(&custody);
    let transport = SyntheticTransport::triple(
        mat.descriptor.clone(),
        vec![(31, mat.value31_b.clone()), (30, mat.value30.clone())],
    );
    let handle = transport.clone();
    let record = cvlt::TorReadRecord::checkpoint(transport, custody).unwrap();
    let first = record.get(31, true).await.unwrap().unwrap();
    assert_eq!(first.seq, 2);
    assert_eq!(first.data.as_slice(), mat.plaintext31_b.as_slice());
    let other = record.get(30, true).await.unwrap().unwrap();
    assert_eq!(other.seq, 1);
    assert_eq!(other.data.as_slice(), mat.plaintext30.as_slice());
    handle.set_value(31, Some(mat.value31_a.clone()));
    assert_eq!(
        record.get(31, true).await.unwrap_err(),
        cdht::Error::Conflict
    );
    let again = record.get(30, true).await.unwrap().unwrap();
    assert_eq!(again.seq, 1);
    assert!(matches!(
        record.republish(31, 3, b"x").await,
        Err(cdht::Error::WrongWriter)
    ));
    assert_eq!(record.flush().await.unwrap_err(), cdht::Error::WrongWriter);
    assert!(record.watch().await.is_err());
    assert!(!record.cancel_watch().await.unwrap());
    assert!(record.changes().unwrap().ranges.is_empty());
}
