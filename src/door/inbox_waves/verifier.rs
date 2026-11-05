//! The native counterpart verifier of the wave ports: the `wave` and `outcome` relations
//! of the peer-release group, checked by the owned `czkp-bb-worker` (`cvfy`).
//!
//! The `wave` and `outcome` verification keys are trusted ONLY through the release pins of
//! the device settings (`ProverArtifacts::wave_pins`: circuit, keys and manifest SHA-256,
//! exactly like the browser's `registration.prover.wave` in vault.json), checked at load
//! before anything is used; the pinned manifest then authenticates the SRS files. Nothing
//! served or carried by a policy can choose a key.
//!
//! The community's verified wave policy is judged by `cwlt::wave::WaveVerifier` itself
//! (context, lease, the issuer certificate under the policy's key ring and its account
//! scope). It is not compared with this group: a published policy pins the account
//! (extension) group, never the separate peer-release group (decided 2026-11-05, option 1).
use super::super::composer::{ComposeError, ProverArtifacts, WavePins};
use super::super::{ErrorCode, Result};
use super::production::VerifierFactory;
use ckmg::wallet_engine::native_prover::Program;
use cwlt::wave::{WavePolicy, WaveVerifier};
use data_encoding::HEXLOWER;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};

/// The longest whole-batch limit `cvfy` accepts.
const VERIFY_TIMEOUT_CAP_SECONDS: u64 = 300;
/// The native prover never emits a longer proof.
const MAX_PROOF_BYTES: usize = 1 << 20;

/// The parts of the group manifest the device authenticates its files with.
#[derive(Deserialize)]
struct Manifest {
    // The released conformance manifest spells its keys in camelCase; the snake_case spelling
    // is the test fixture's.
    #[serde(alias = "circuitSha256")]
    circuit_sha256: String,
    #[serde(alias = "vkSha256")]
    vk_sha256: String,
    setup: Vec<Setup>,
}
#[derive(Deserialize)]
struct Setup {
    name: String,
    bytes: usize,
    sha256: String,
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn config(text: &str) -> ComposeError {
    ComposeError::Config(text.into())
}

fn read(path: &Path, maximum: usize) -> std::result::Result<Vec<u8>, ComposeError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ComposeError::Step("verifier artifacts", format!("{e:?}")))?;
    if bytes.len() > maximum {
        return Err(config("verifier artifact too large"));
    }
    Ok(bytes)
}

fn pinned(bytes: &[u8], expected: &str) -> std::result::Result<(), ComposeError> {
    let expected: [u8; 32] = HEXLOWER
        .decode(expected.as_bytes())
        .ok()
        .and_then(|digest| digest.try_into().ok())
        .ok_or_else(|| config("manifest digest"))?;
    if sha(bytes) != expected {
        return Err(config("verifier artifact differs from its manifest"));
    }
    Ok(())
}

/// The hex verification key of `program` inside the group's key file.
fn program_key(keys: &[u8], program: Program) -> std::result::Result<Vec<u8>, ComposeError> {
    let mut group: BTreeMap<String, String> = serde_json::from_slice(keys).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "config group key file",
            config("group key file"),
            &__cause,
        )
    })?;
    let key = HEXLOWER
        .decode(
            group
                .remove(program.key())
                .ok_or_else(|| config("the group carries no key for the program"))?
                .as_bytes(),
        )
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "config group key file",
                config("group key file"),
                &__cause,
            )
        })?;
    if key.is_empty() || key.len() > czkp::native::MAX_KEY_BYTES {
        return Err(config("group key size"));
    }
    Ok(key)
}

/// One authenticated peer-release group, read once and cloned into a verifier per call.
struct Group {
    circuit_digest: [u8; 32],
    wave_key: Vec<u8>,
    outcome_key: Vec<u8>,
    g1: Vec<u8>,
    g2: [u8; 128],
    executable: std::path::PathBuf,
    timeout: Duration,
    threads: usize,
    memory_megabytes: usize,
}

impl Group {
    fn read(artifacts: &ProverArtifacts) -> std::result::Result<Self, ComposeError> {
        let (Some(wave), Some(outcome)) = (&artifacts.wave, &artifacts.outcome) else {
            return Err(config(
                "wave verification needs the wave and outcome circuits",
            ));
        };
        let executable = artifacts
            .verifier_executable
            .clone()
            .ok_or_else(|| config("wave verification needs the verifier worker"))?;
        let manifest_file = artifacts
            .manifest_file
            .as_deref()
            .ok_or_else(|| config("wave verification needs the group manifest"))?;
        let pins: &WavePins = artifacts
            .wave_pins
            .as_ref()
            .ok_or_else(|| config("wave verification needs the release pins"))?;
        let manifest_bytes = read(manifest_file, 65_536)?;
        pinned(&manifest_bytes, &pins.manifest_sha256)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "config group manifest",
                config("group manifest"),
                &__cause,
            )
        })?;
        // The circuit and keys of every program are the one pinned group the manifest names.
        let circuit = read(&wave.circuit_file, 64 << 20)?;
        let keys = read(&wave.keys_file, 1 << 20)?;
        pinned(&circuit, &pins.circuit_sha256)?;
        pinned(&keys, &pins.keys_sha256)?;
        pinned(&circuit, &manifest.circuit_sha256)?;
        pinned(&keys, &manifest.vk_sha256)?;
        if sha(&read(&outcome.circuit_file, 64 << 20)?) != sha(&circuit)
            || sha(&read(&outcome.keys_file, 1 << 20)?) != sha(&keys)
        {
            return Err(config("the outcome files are not the wave group"));
        }
        let setup = |name: &str| -> std::result::Result<&Setup, ComposeError> {
            let mut named = manifest.setup.iter().filter(|setup| setup.name == name);
            match (named.next(), named.next()) {
                (Some(setup), None) => Ok(setup),
                _ => Err(config("group setup entry")),
            }
        };
        let g1 = read(&artifacts.srs_g1_file, 128 << 20)?;
        let g2 = read(&artifacts.srs_g2_file, 128)?;
        for (data, entry) in [(&g1, setup("g1.dat")?), (&g2, setup("g2.dat")?)] {
            if entry.bytes != data.len() {
                return Err(config("group setup size"));
            }
            pinned(data, &entry.sha256)?;
        }
        let group = Self {
            circuit_digest: sha(&circuit),
            wave_key: program_key(&keys, Program::Wave)?,
            outcome_key: program_key(&keys, Program::Outcome)?,
            // The native verifier takes the first authenticated compressed chunk.
            g1: g1
                .get(..czkp::native::SRS_G1_BYTES)
                .ok_or_else(|| config("group setup size"))?
                .to_vec(),
            g2: g2.try_into().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "config group setup size",
                    config("group setup size"),
                    &__cause,
                )
            })?,
            executable,
            timeout: Duration::from_secs(artifacts.timeout_seconds.min(VERIFY_TIMEOUT_CAP_SECONDS)),
            threads: artifacts.threads,
            memory_megabytes: artifacts.memory_megabytes,
        };
        // Refuse unusable limits and a relative worker path now, not at the first wave.
        for program in [Program::Wave, Program::Outcome] {
            cvfy::NativeVerifier::new(group.config(program)).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "config wave verifier settings",
                    config("wave verifier settings"),
                    &__cause,
                )
            })?;
        }
        Ok(group)
    }

    /// The configuration of one program's verifier: this group's circuit digest with the
    /// digest of that program's own key, exactly what `cvfy` pins.
    fn config(&self, program: Program) -> cvfy::NativeVerifierConfig {
        let key = if program == Program::Outcome {
            &self.outcome_key
        } else {
            &self.wave_key
        };
        cvfy::NativeVerifierConfig {
            executable: self.executable.clone(),
            scope: czkp::ProofScope {
                circuit_digest: self.circuit_digest,
                verifying_key_digest: sha(key),
            },
            timeout: self.timeout,
            maximum_parallel: 1,
            max_proof_bytes: MAX_PROOF_BYTES,
            // The compiled program's exact public field count.
            max_public_inputs: program.publics(),
            threads: self.threads,
            memory_megabytes: self.memory_megabytes,
            verification_key: key.clone(),
            srs_g1: self.g1.clone(),
            srs_g2: self.g2,
        }
    }

    fn verifier(
        &self,
        policy: WavePolicy,
        now: u64,
        authority_until: u64,
    ) -> Result<WaveVerifier<cvfy::NativeVerifier>> {
        WaveVerifier::native(
            policy,
            now,
            authority_until,
            self.config(Program::Wave),
            self.config(Program::Outcome),
        )
        .map_err(|error| match error {
            czkp::Error::Expired => ErrorCode::Unavailable,
            _ => ErrorCode::Refused,
        })
    }
}

impl ProverArtifacts {
    /// The counterpart verifier factory of the wave ports, over the pinned peer-release
    /// group. The group is authenticated against the release pins and read once, here;
    /// each call builds the two program verifiers, and `WaveVerifier` judges the policy.
    pub fn wave_verifier_factory(
        &self,
    ) -> std::result::Result<VerifierFactory<cvfy::NativeVerifier>, ComposeError> {
        let group = Group::read(self)?;
        Ok(Box::new(move |policy, now, authority_until| {
            group.verifier(policy, now, authority_until)
        }))
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use crate::door::composer::CircuitFiles;
    use crate::door::composer::WavePins;
    use cwlt::wave::ExtensionPolicy;
    use std::path::PathBuf;

    pub(crate) const NOW: u64 = 5_000;

    pub(crate) struct Files {
        dir: tempfile::TempDir,
        pub(crate) artifacts: ProverArtifacts,
    }
    impl Files {
        pub(crate) fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }
        pub(crate) fn write(&self, name: &str, bytes: &[u8]) {
            std::fs::write(self.path(name), bytes).unwrap();
        }
    }

    pub(crate) fn manifest(circuit: &[u8], keys: &[u8], g1: &[u8], g2: &[u8]) -> Vec<u8> {
        let digest = |bytes: &[u8]| HEXLOWER.encode(&sha(bytes));
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "circuit_sha256": digest(circuit),
            "vk_sha256": digest(keys),
            "setup": [
                {"name": "g1.dat", "bytes": g1.len(), "sha256": digest(g1)},
                {"name": "g2.dat", "bytes": g2.len(), "sha256": digest(g2)},
            ],
        }))
        .unwrap()
    }

    /// A synthetic retained group: the bytes are opaque to the factory (only the worker
    /// parses them), so the digests and sizes are what the tests exercise.
    pub(crate) fn fixture() -> Files {
        let dir = tempfile::tempdir().unwrap();
        let circuit = br#"{"update":"u","wave":"w","outcome":"o"}"#.to_vec();
        let keys = serde_json::to_vec(&serde_json::json!({
            "update": HEXLOWER.encode(&[1; 40]),
            "wave": HEXLOWER.encode(&[2; 40]),
            "outcome": HEXLOWER.encode(&[3; 40]),
        }))
        .unwrap();
        let g1: Vec<u8> = (0..czkp::native::SRS_G1_BYTES + 64)
            .map(|i| i as u8)
            .collect();
        let g2 = vec![9u8; 128];
        let mut files = Files {
            artifacts: ProverArtifacts {
                worker_executable: "/prover-worker".into(),
                circuit_file: dir.path().join("circuits.json"),
                keys_file: dir.path().join("keys.json"),
                srs_g1_file: dir.path().join("g1.dat"),
                srs_g2_file: dir.path().join("g2.dat"),
                wave: Some(CircuitFiles {
                    circuit_file: dir.path().join("circuits.json"),
                    keys_file: dir.path().join("keys.json"),
                }),
                record: None,
                outcome: Some(CircuitFiles {
                    circuit_file: dir.path().join("circuits.json"),
                    keys_file: dir.path().join("keys.json"),
                }),
                verifier_executable: Some("/czkp-bb-worker".into()),
                manifest_file: Some(dir.path().join("manifest.json")),
                wave_pins: None,
                timeout_seconds: 900,
                threads: 2,
                memory_megabytes: 4096,
            },
            dir,
        };
        files.write("circuits.json", &circuit);
        files.write("keys.json", &keys);
        files.write("g1.dat", &g1);
        files.write("g2.dat", &g2);
        files.write("manifest.json", &manifest(&circuit, &keys, &g1, &g2));
        repin(&mut files);
        files
    }

    /// The release pins of the group's current files (what a reviewed release config carries).
    pub(crate) fn repin(files: &mut Files) {
        let digest = |name: &str| HEXLOWER.encode(&sha(&std::fs::read(files.path(name)).unwrap()));
        files.artifacts.wave_pins = Some(WavePins {
            circuit_sha256: digest("circuits.json"),
            keys_sha256: digest("keys.json"),
            manifest_sha256: digest("manifest.json"),
        });
    }

    fn issuer_point(seed: u8) -> Vec<u8> {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()[1..]
            .to_vec()
    }

    /// The community's policy pinning exactly this group.
    pub(crate) fn policy(group: &Files) -> WavePolicy {
        let read = |name: &str| std::fs::read(group.path(name)).unwrap();
        WavePolicy {
            community: [1; 32],
            extension: ExtensionPolicy {
                revision: 1,
                public_record_quorum: 1,
                change_token_cost: 1,
                deposit_delay_seconds: 1,
                minimum_deposit_batch: 2,
                standing_policy_digest: [2; 32],
            },
            proof_scope: czkp::ProofScope {
                circuit_digest: sha(&read("circuits.json")),
                verifying_key_digest: sha(&read("keys.json")),
            },
            certificate_keys: vec![czkp::issuer_keys::CertificateKeyPeriod {
                public_key: issuer_point(0x42),
                valid_from: 1,
                valid_until: None,
            }],
            community_identity: [8; 32],
            manifest_sha256: sha(&read("manifest.json")),
            state_policy: [7; 32],
            valid_from: NOW - 1000,
            valid_until: NOW + 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;
    use crate::door::composer::CircuitFiles;

    fn call(
        factory: &VerifierFactory<cvfy::NativeVerifier>,
        policy: WavePolicy,
    ) -> std::result::Result<(), ErrorCode> {
        factory(policy, NOW, NOW + 500).map(|_| ())
    }

    #[test]
    fn the_released_camel_case_manifest_parses() {
        let released = br#"{"version":1,"circuitSha256":"aa","vkSha256":"bb","numPoints":2,
            "setup":[{"name":"g1.dat","url":"u","bytes":1,"range":true,"sha256":"cc"}]}"#;
        let manifest: Manifest = serde_json::from_slice(released).unwrap();
        assert_eq!(manifest.circuit_sha256, "aa");
        assert_eq!(manifest.vk_sha256, "bb");
        assert_eq!(manifest.setup.len(), 1);
    }

    #[test]
    fn the_policy_that_pins_the_manifest_gets_its_verifier() {
        let group = fixture();
        let factory = group.artifacts.wave_verifier_factory().unwrap();
        let pinned = policy(&group);
        assert_eq!(call(&factory, pinned.clone()), Ok(()));
        // The group was read once: it keeps answering after its files change.
        group.write("keys.json", b"changed");
        assert_eq!(call(&factory, pinned), Ok(()));
    }

    #[test]
    fn a_policy_is_judged_by_the_wave_verifier_and_never_compared_with_the_group() {
        // A published policy pins the account group, not the peer-release group: another
        // manifest, circuit or key digest in the policy does not make the device refuse.
        let group = fixture();
        let factory = group.artifacts.wave_verifier_factory().unwrap();
        let mut manifest = policy(&group);
        manifest.manifest_sha256[0] ^= 1;
        assert_eq!(call(&factory, manifest), Ok(()));
        let mut scope = policy(&group);
        scope.proof_scope.circuit_digest[0] ^= 1;
        scope.proof_scope.verifying_key_digest[0] ^= 1;
        assert_eq!(call(&factory, scope), Ok(()));
    }

    #[test]
    fn a_group_that_differs_from_any_release_pin_is_not_loaded() {
        for pin in ["circuit", "keys", "manifest"] {
            let mut group = fixture();
            let pins = group.artifacts.wave_pins.as_mut().unwrap();
            let field = match pin {
                "circuit" => &mut pins.circuit_sha256,
                "keys" => &mut pins.keys_sha256,
                _ => &mut pins.manifest_sha256,
            };
            let first = if field.starts_with('0') { "1" } else { "0" };
            field.replace_range(0..1, first);
            assert!(group.artifacts.wave_verifier_factory().is_err(), "{pin}");
        }
        // Files the manifest names but no pin does (a served or swapped group) are refused too.
        let group = fixture();
        let circuit = br#"{"update":"u","wave":"w2","outcome":"o"}"#;
        let keys = std::fs::read(group.path("keys.json")).unwrap();
        let g1 = std::fs::read(group.path("g1.dat")).unwrap();
        let g2 = std::fs::read(group.path("g2.dat")).unwrap();
        group.write("circuits.json", circuit);
        group.write("manifest.json", &manifest(circuit, &keys, &g1, &g2));
        assert!(group.artifacts.wave_verifier_factory().is_err());
    }

    #[test]
    fn an_expired_window_or_lease_builds_no_verifier() {
        let group = fixture();
        let factory = group.artifacts.wave_verifier_factory().unwrap();
        assert_eq!(
            factory(policy(&group), NOW + 1000, NOW + 2000).map(|_| ()),
            Err(ErrorCode::Unavailable)
        );
        assert_eq!(
            factory(policy(&group), NOW, NOW).map(|_| ()),
            Err(ErrorCode::Unavailable)
        );
    }

    #[test]
    fn files_that_differ_from_their_manifest_are_not_loaded() {
        for (name, bytes) in [
            ("circuits.json", b"{}".to_vec()),
            ("g2.dat", vec![8u8; 128]),
        ] {
            let group = fixture();
            group.write(name, &bytes);
            assert!(group.artifacts.wave_verifier_factory().is_err(), "{name}");
        }
        // A tampered key file differs from the manifest even when it keeps the wave key.
        let group = fixture();
        let keys = serde_json::to_vec(&serde_json::json!({
            "wave": HEXLOWER.encode(&[2; 40]),
            "outcome": HEXLOWER.encode(&[4; 40]),
        }))
        .unwrap();
        group.write("keys.json", &keys);
        assert!(group.artifacts.wave_verifier_factory().is_err());
        // A flipped bit in the SRS prefix the worker would use.
        let group = fixture();
        let mut g1 = std::fs::read(group.path("g1.dat")).unwrap();
        g1[10] ^= 1;
        group.write("g1.dat", &g1);
        assert!(group.artifacts.wave_verifier_factory().is_err());
    }

    #[test]
    fn a_group_that_lacks_a_program_key_is_not_loaded() {
        let mut group = fixture();
        let circuit = std::fs::read(group.path("circuits.json")).unwrap();
        let keys = serde_json::to_vec(&serde_json::json!({
            "update": HEXLOWER.encode(&[1; 40]),
            "wave": HEXLOWER.encode(&[2; 40]),
        }))
        .unwrap();
        let g1 = std::fs::read(group.path("g1.dat")).unwrap();
        let g2 = std::fs::read(group.path("g2.dat")).unwrap();
        group.write("keys.json", &keys);
        group.write("manifest.json", &manifest(&circuit, &keys, &g1, &g2));
        repin(&mut group);
        assert!(group.artifacts.wave_verifier_factory().is_err());
    }

    #[test]
    fn the_outcome_files_must_be_the_wave_group() {
        let mut group = fixture();
        group.write("other.json", br#"{"update":"u"}"#);
        group.artifacts.outcome = Some(CircuitFiles {
            circuit_file: group.path("other.json"),
            keys_file: group.path("keys.json"),
        });
        assert!(group.artifacts.wave_verifier_factory().is_err());
    }

    #[test]
    fn missing_or_unusable_settings_are_refused_at_load() {
        let mut absent = [fixture(), fixture(), fixture(), fixture(), fixture()];
        absent[0].artifacts.outcome = None;
        absent[1].artifacts.wave = None;
        absent[2].artifacts.manifest_file = None;
        absent[3].artifacts.verifier_executable = None;
        absent[4].artifacts.wave_pins = None;
        for group in &absent {
            assert!(group.artifacts.wave_verifier_factory().is_err());
        }
        let mut relative = fixture();
        relative.artifacts.verifier_executable = Some("czkp-bb-worker".into());
        assert!(relative.artifacts.wave_verifier_factory().is_err());
        let mut idle = fixture();
        idle.artifacts.threads = 0;
        assert!(idle.artifacts.wave_verifier_factory().is_err());
        let mut unbounded = fixture();
        unbounded.artifacts.timeout_seconds = 0;
        assert!(unbounded.artifacts.wave_verifier_factory().is_err());
    }

    #[test]
    fn settings_written_before_the_wave_verifier_still_load() {
        let artifacts: ProverArtifacts = serde_json::from_value(serde_json::json!({
            "worker_executable": "/w",
            "circuit_file": "/c",
            "keys_file": "/k",
            "srs_g1_file": "/g1",
            "srs_g2_file": "/g2",
        }))
        .unwrap();
        assert!(artifacts.outcome.is_none());
        assert!(artifacts.verifier_executable.is_none());
        assert!(artifacts.manifest_file.is_none());
        assert!(artifacts.wave_pins.is_none());
        // Without the wave stack there is no verifier and no wave provers.
        assert!(artifacts.wave_verifier_factory().is_err());
        assert!(artifacts.wave_provers().unwrap().is_none());
    }

    #[test]
    fn each_program_verifier_pins_its_own_key_under_the_group_circuit() {
        let group = fixture();
        let loaded = Group::read(&group.artifacts).unwrap();
        let wave = loaded.config(Program::Wave);
        let outcome = loaded.config(Program::Outcome);
        assert_eq!(wave.scope.circuit_digest, outcome.scope.circuit_digest);
        assert_eq!(wave.scope.verifying_key_digest, sha(&[2; 40]));
        assert_eq!(outcome.scope.verifying_key_digest, sha(&[3; 40]));
        assert_eq!(wave.max_public_inputs, Program::Wave.publics());
        assert_eq!(outcome.max_public_inputs, Program::Outcome.publics());
        // The settings default of 900 s is clamped to what cvfy accepts.
        assert_eq!(wave.timeout, Duration::from_secs(300));
        assert_eq!(wave.srs_g1.len(), czkp::native::SRS_G1_BYTES);
    }
}

/// The retained real wave release (cblc proof-fixtures job, `CBLC_WAVE_FIXTURE`, consumed by its
/// content address): its reservation and Answer proofs through the owned worker. Needs
/// `CMSG_WAVE_FIXTURE` (the fixture directory) and `CMSG_NATIVE_VERIFIER_WORKER` (`czkp-bb-worker`).
#[cfg(test)]
mod release {
    use super::*;
    use crate::door::composer::{CircuitFiles, WavePins};
    use crate::door::inbox_waves::{verify_outcome_with, verify_reservation_with};
    use cwlt::wave::{WaveContext, WaveOutcome, WaveOutcomeStatement, WavePolicy, WaveStatement};
    use std::path::{Path, PathBuf};

    /// The reviewed release pins of wave-fixtures/6bb79d4d (its keys are the group cvld pins).
    const CIRCUIT: &str = "97f20af539b6c0e6c1e03c69f9ebd3ad4b38c4f15de875c6cf4e08d90d1f930b";
    const KEYS: &str = "bad05ec4e71f1770395e04e9acfbdfd873adf433ce4665d95ed1c06d7443aa8e";
    const MANIFEST: &str = "f6e850c6360553667d00acb3b657899681e08afcf1115f9ffd7df48974214172";
    const FIXTURE: &str = "6bb79d4de8c1a9bc4bbcb0e8cd3ddfa3bb6877ea08ceab0a08b085c7fb2643d6";

    fn env(name: &str) -> PathBuf {
        PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
    }

    fn pins() -> WavePins {
        WavePins {
            circuit_sha256: CIRCUIT.into(),
            keys_sha256: KEYS.into(),
            manifest_sha256: MANIFEST.into(),
        }
    }

    /// Settings of a device holding the group in `group` (the release's setup files).
    fn artifacts(release: &Path, group: &Path, pins: WavePins) -> ProverArtifacts {
        let files = || CircuitFiles {
            circuit_file: group.join("circuits.json"),
            keys_file: group.join("keys.json"),
        };
        ProverArtifacts {
            worker_executable: "/prover-worker".into(),
            circuit_file: group.join("circuits.json"),
            keys_file: group.join("keys.json"),
            srs_g1_file: release.join("setup/g1.dat"),
            srs_g2_file: release.join("setup/g2.dat"),
            wave: Some(files()),
            record: None,
            outcome: Some(files()),
            verifier_executable: Some(env("CMSG_NATIVE_VERIFIER_WORKER")),
            manifest_file: Some(group.join("manifest.json")),
            wave_pins: Some(pins),
            timeout_seconds: 300,
            threads: 2,
            memory_megabytes: 4096,
        }
    }

    struct Release {
        dir: PathBuf,
        policy: WavePolicy,
        reservation: WaveStatement,
        reservation_proof: Vec<u8>,
        settled: WaveOutcomeStatement,
        settled_proof: Vec<u8>,
        now: u64,
        until: u64,
    }

    fn release() -> Release {
        let dir = env("CMSG_WAVE_FIXTURE");
        let text = std::fs::read(dir.join("wave-roundtrip.json")).unwrap();
        assert_eq!(
            HEXLOWER.encode(&sha(&text)),
            FIXTURE,
            "the release by its content address"
        );
        let fixture: serde_json::Value = serde_json::from_slice(&text).unwrap();
        let case = |kind: &str| {
            fixture["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["kind"] == kind)
                .unwrap()
                .clone()
        };
        let (wave, outcome) = (case("wave"), case("outcome"));
        let proof = |c: &serde_json::Value| {
            HEXLOWER
                .decode(c["proof"].as_str().unwrap().as_bytes())
                .unwrap()
        };
        let reservation: WaveStatement =
            serde_json::from_value(wave["statement"]["wave"].clone()).unwrap();
        let settled: WaveOutcomeStatement =
            serde_json::from_value(outcome["statement"]["outcome"].clone()).unwrap();
        let now = reservation.accepted_at.max(settled.evidence.accepted_at) + 1;
        let until = reservation.context.expires_at + 1000;
        Release {
            policy: serde_json::from_value(fixture["material"]["waveVerifier"].clone()).unwrap(),
            reservation_proof: proof(&wave),
            settled_proof: proof(&outcome),
            reservation,
            settled,
            now,
            until,
            dir,
        }
    }

    /// Build the verifier from these settings and judge both real statements.
    async fn judge(
        artifacts: &ProverArtifacts,
        r: &Release,
        policy: WavePolicy,
        reservation_proof: &[u8],
    ) -> (Result<()>, Result<()>) {
        let factory = artifacts.wave_verifier_factory().unwrap();
        let verifier = match factory(policy, r.now, r.until) {
            Ok(verifier) => verifier,
            Err(code) => return (Err(code), Err(code)),
        };
        let expected: &WaveContext = &r.reservation.context;
        let wave = verify_reservation_with(
            &verifier,
            &r.reservation,
            reservation_proof,
            expected,
            r.now,
        )
        .await
        .map(|_| ());
        let outcome = verify_outcome_with(
            &verifier,
            &r.settled,
            &r.settled_proof,
            &r.settled.evidence.context,
            WaveOutcome::Answer,
            &r.settled.receipt_digest,
            r.now,
        )
        .await
        .map(|_| ());
        (wave, outcome)
    }

    #[tokio::test]
    async fn the_release_verifies_natively_under_its_pins_and_refuses_every_change() {
        let r = release();
        let pinned = artifacts(&r.dir, &r.dir, pins());
        // The real policy pins the account group; the pinned peer-release keys judge its proofs.
        assert_ne!(
            HEXLOWER.encode(&r.policy.proof_scope.verifying_key_digest),
            KEYS,
            "a published policy pins the account group, not the peer-release group"
        );
        assert_eq!(
            judge(&pinned, &r, r.policy.clone(), &r.reservation_proof).await,
            (Ok(()), Ok(()))
        );
        // A flipped proof.
        let mut flipped = r.reservation_proof.clone();
        flipped[40] ^= 1;
        assert_eq!(
            judge(&pinned, &r, r.policy.clone(), &flipped).await.0,
            Err(ErrorCode::Refused)
        );
        // Another account scope: the issuer certificate does not cover it.
        let mut other = r.policy.clone();
        other.proof_scope.circuit_digest[0] ^= 1;
        let (wave, outcome) = judge(&pinned, &r, other, &r.reservation_proof).await;
        assert!(wave.is_err() && outcome.is_err(), "{wave:?} {outcome:?}");
        // A tampered pin: the release group is not loaded at all.
        for tamper in [0, 1, 2] {
            let mut bad = pins();
            let field = match tamper {
                0 => &mut bad.circuit_sha256,
                1 => &mut bad.keys_sha256,
                _ => &mut bad.manifest_sha256,
            };
            let first = if field.starts_with('0') { "1" } else { "0" };
            field.replace_range(0..1, first);
            assert!(
                artifacts(&r.dir, &r.dir, bad)
                    .wave_verifier_factory()
                    .is_err(),
                "{tamper}"
            );
        }
        // A swapped key group (`wave` and `outcome` keys exchanged, a manifest naming it and pins
        // of its own): it loads, and the real proofs are refused under the other keys.
        let swapped = tempfile::tempdir().unwrap();
        std::fs::copy(
            r.dir.join("circuits.json"),
            swapped.path().join("circuits.json"),
        )
        .unwrap();
        let mut keys: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(r.dir.join("keys.json")).unwrap()).unwrap();
        let wave_key = keys.remove("wave").unwrap();
        let outcome_key = keys.remove("outcome").unwrap();
        let keys = serde_json::to_vec(&BTreeMap::from([
            ("wave", outcome_key),
            ("outcome", wave_key),
        ]))
        .unwrap();
        std::fs::write(swapped.path().join("keys.json"), &keys).unwrap();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(r.dir.join("manifest.json")).unwrap()).unwrap();
        manifest["vkSha256"] = serde_json::json!(HEXLOWER.encode(&sha(&keys)));
        let manifest = serde_json::to_vec(&manifest).unwrap();
        std::fs::write(swapped.path().join("manifest.json"), &manifest).unwrap();
        let swapped_pins = WavePins {
            circuit_sha256: CIRCUIT.into(),
            keys_sha256: HEXLOWER.encode(&sha(&keys)),
            manifest_sha256: HEXLOWER.encode(&sha(&manifest)),
        };
        assert_eq!(
            judge(
                &artifacts(&r.dir, swapped.path(), swapped_pins),
                &r,
                r.policy.clone(),
                &r.reservation_proof
            )
            .await,
            (Err(ErrorCode::Refused), Err(ErrorCode::Refused))
        );
    }
}
