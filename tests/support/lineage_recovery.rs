//! Pure CKMG checkpoint lineage-read coverage for CMSG restore. Test-only
//! adapters below never claim live HTTPS or G3.
use std::cell::Cell;
use std::rc::Rc;
const SCOPE: &str = "lineage-recovery";
const MEMBER: &str = "fixture-member";
const NOW: u64 = 1_800_000_000;
const CREATE_EVIDENCE: &[u8] = b"fixture-create";
const READ_EVIDENCE: &[u8] = b"recovery-evidence";
struct FixtureClock(Rc<Cell<u64>>);
impl ckmg::Clock for FixtureClock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(self.0.get())
    }
}
struct NoRecords;
impl cvlt::Records for NoRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
// Test-only setup: this binding/device may Create once and Use. No reads.
struct LineageRecoveryTestSetupAuthority {
    binding: ckmg::Binding,
    device: Option<ckmg::PublicKey>,
    created: bool,
}
impl ckmg::Authority for LineageRecoveryTestSetupAuthority {
    async fn check(&mut self, request: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        if request.binding != &self.binding
            || request.now != NOW
            || request.target.is_some()
            || request.signing.is_some()
            || Some(request.device) != self.device
        {
            return Err(ckmg::Error::Unauthorized);
        }
        match request.action {
            ckmg::Action::Create
                if !self.created
                    && request.root.is_none()
                    && request.epoch == 0
                    && request.statement.is_none()
                    && request.evidence == CREATE_EVIDENCE =>
            {
                self.created = true;
                Ok(())
            }
            ckmg::Action::Use if request.statement.is_none() && request.evidence.is_empty() => {
                Ok(())
            }
            _ => Err(ckmg::Error::Unauthorized),
        }
    }
}
// Recording observer: exact checkpoint binding asserted per call; deny still
// refuses. A set regress clock is rewound during admission.
struct Observer {
    lineage: ckmg::Lineage,
    device: ckmg::PublicKey,
    expect: ckmg::Action,
    calls: Cell<usize>,
    deny: bool,
    regress: Option<Rc<Cell<u64>>>,
}
impl ckmg::Authority for Observer {
    async fn check(&mut self, request: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(request.action, self.expect);
        assert_eq!(request.binding, &self.lineage.binding);
        assert_eq!(request.root, Some(self.lineage.root));
        assert_eq!(request.device, self.device);
        assert_eq!(request.epoch, self.lineage.epoch);
        assert_eq!(request.statement, Some(self.lineage.digest()?));
        assert!(request.target.is_none() && request.signing.is_none());
        assert_eq!(request.evidence, READ_EVIDENCE);
        if let Some(clock) = &self.regress {
            clock.set(NOW - 1);
        }
        if self.deny {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}
// Real PRF/Keys/Memory store: create, acknowledge, retain sealed bytes plus a
// vault.lineage record ciphertext sealed via public APIs.
async fn setup() -> (Vec<u8>, ckmg::Lineage, [u8; 24], Vec<u8>) {
    use ckmg::passkey::PrfOutput;
    let prf = PrfOutput::from_bytes(&[7; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, SCOPE).unwrap();
    let authority = LineageRecoveryTestSetupAuthority {
        binding: ckmg::Binding::new(SCOPE, MEMBER).unwrap(),
        device: Some(device),
        created: false,
    };
    let cipher = ckmg::passkey::store_cipher(&prf, SCOPE).unwrap();
    let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, SCOPE)
        .await
        .unwrap();
    let now = Rc::new(Cell::new(NOW));
    let mut vault = cvlt::Vault::new(
        store,
        SCOPE,
        FixtureClock(now),
        ckmg::SystemEntropy,
        authority,
        NoRecords,
        (),
    )
    .unwrap();
    let batch = |expected, operation| cvlt::Batch {
        expected,
        operation,
        mutations: vec![],
        outputs: vec![],
    };
    let guard = vault.stage_keys(batch(0, [61; 32])).unwrap();
    let binding = ckmg::Binding::new(SCOPE, MEMBER).unwrap();
    let info = ckmg::DeviceInfo::new("fixture", b"fixture-credential").unwrap();
    let receipt = vault
        .keys()
        .create_scope(&prf, binding, info, CREATE_EVIDENCE)
        .await
        .unwrap();
    drop(guard);
    let guard = vault.stage_keys(batch(1, [62; 32])).unwrap();
    vault.keys().acknowledge(receipt.operation).await.unwrap();
    drop(guard);
    let sealed = vault.keys().retained_checkpoint().await.unwrap();
    let lineage = vault.keys().lineage().await.unwrap();
    let purpose = ckmg::Purpose::new(ckmg::Scope::Member, "vault.lineage", 0).unwrap();
    let handle = vault.keys().key(purpose).await.unwrap();
    let nonce = [9u8; 24];
    let ciphertext = vault
        .keys()
        .with_vld0_record_cipher(&handle, |c| {
            c.crypt(&nonce, b"lineage fixture").unwrap().to_vec()
        })
        .await
        .unwrap();
    (sealed, lineage, nonce, ciphertext)
}
fn inspector() -> ckmg::CheckpointInspector {
    use ckmg::passkey::PrfOutput;
    let prf = PrfOutput::from_bytes(&[7; 32]).unwrap();
    ckmg::CheckpointInspector::new(&prf, SCOPE).unwrap()
}
fn observer(lineage: &ckmg::Lineage, expect: ckmg::Action, deny: bool) -> Observer {
    Observer {
        lineage: lineage.clone(),
        device: lineage.devices[0],
        expect,
        calls: Cell::new(0),
        deny,
        regress: None,
    }
}
#[tokio::test]
async fn read_lineage_binds_checkpoint_while_bootstrap_stays_use() {
    let (sealed, lineage, nonce, ciphertext) = setup().await;
    let mut authority = observer(&lineage, ckmg::Action::ReadLineage, false);
    let mut clock = FixtureClock(Rc::new(Cell::new(NOW)));
    let reader = inspector()
        .read_lineage(&sealed, READ_EVIDENCE, &mut clock, &mut authority)
        .await
        .unwrap();
    assert_eq!(authority.calls.get(), 1);
    assert_eq!(reader.owner(), lineage.root);
    assert_eq!(
        reader.open(&nonce, &ciphertext).unwrap().as_slice(),
        b"lineage fixture"
    );
    let mut use_authority = observer(&lineage, ckmg::Action::Use, false);
    let mut clock = FixtureClock(Rc::new(Cell::new(NOW)));
    let bootstrap = inspector()
        .bootstrap(&sealed, READ_EVIDENCE, &mut clock, &mut use_authority)
        .await
        .unwrap();
    assert_eq!(use_authority.calls.get(), 1);
    assert_eq!(bootstrap.inspection().lineage(), &lineage);
}
#[tokio::test]
async fn read_lineage_denial_releases_no_reader() {
    let (sealed, lineage, _nonce, _ciphertext) = setup().await;
    let mut authority = observer(&lineage, ckmg::Action::ReadLineage, true);
    let mut clock = FixtureClock(Rc::new(Cell::new(NOW)));
    assert_eq!(
        inspector()
            .read_lineage(&sealed, READ_EVIDENCE, &mut clock, &mut authority)
            .await
            .unwrap_err(),
        ckmg::Error::Unauthorized
    );
    assert_eq!(authority.calls.get(), 1);
}
#[tokio::test]
async fn malformed_tampered_and_rolled_back_clock_refuse_before_authority() {
    let (sealed, lineage, _nonce, _ciphertext) = setup().await;
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    for wire in [b"not-a-checkpoint".to_vec(), tampered] {
        let mut authority = observer(&lineage, ckmg::Action::ReadLineage, false);
        let mut clock = FixtureClock(Rc::new(Cell::new(NOW)));
        assert!(
            inspector()
                .read_lineage(&wire, READ_EVIDENCE, &mut clock, &mut authority)
                .await
                .is_err()
        );
        assert_eq!(authority.calls.get(), 0);
    }
    for (evidence, at, expect) in [
        (vec![], NOW, ckmg::Error::Limit),
        (READ_EVIDENCE.to_vec(), NOW - 3_600, ckmg::Error::Clock),
    ] {
        let mut authority = observer(&lineage, ckmg::Action::ReadLineage, false);
        let mut clock = FixtureClock(Rc::new(Cell::new(at)));
        assert_eq!(
            inspector()
                .read_lineage(&sealed, &evidence, &mut clock, &mut authority)
                .await
                .unwrap_err(),
            expect
        );
        assert_eq!(authority.calls.get(), 0);
    }
    // Regression across the authority await refuses even after admission.
    let shared = Rc::new(Cell::new(NOW));
    let mut authority = observer(&lineage, ckmg::Action::ReadLineage, false);
    authority.regress = Some(shared.clone());
    let mut clock = FixtureClock(shared);
    assert_eq!(
        inspector()
            .read_lineage(&sealed, READ_EVIDENCE, &mut clock, &mut authority)
            .await
            .unwrap_err(),
        ckmg::Error::Clock
    );
    assert_eq!(authority.calls.get(), 1);
}

#[tokio::test]
async fn recovered_passkey_reader_binds_the_original_prf_locator() {
    let (sealed, lineage, _, _) = setup().await;
    let mut authority = observer(&lineage, ckmg::Action::Use, false);
    let mut clock = FixtureClock(Rc::new(Cell::new(NOW)));
    let custody = inspector()
        .bootstrap(&sealed, READ_EVIDENCE, &mut clock, &mut authority)
        .await
        .unwrap();
    let wrong = ckmg::passkey::PrfOutput::from_bytes(&[8; 32]).unwrap();
    assert!(matches!(
        custody.passkey_reader(&wrong),
        Err(ckmg::Error::Unauthorized)
    ));
    let original = ckmg::passkey::PrfOutput::from_bytes(&[7; 32]).unwrap();
    let expected = ckmg::passkey::passkey_record_reader(&original, SCOPE).unwrap();
    let reader = custody.passkey_reader(&original).unwrap();
    assert_eq!(reader.owner(), expected.owner());
    let nonce = [13; 24];
    let ciphertext = expected
        .with_cipher(|c| c.crypt(&nonce, b"retained passkey record"))
        .unwrap();
    assert_eq!(
        reader
            .with_cipher(|c| c.crypt(&nonce, &ciphertext))
            .unwrap()
            .as_slice(),
        b"retained passkey record"
    );
}

#[path = "compound_tor.rs"]
mod compound_tor;
