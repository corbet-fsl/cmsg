//! The native counterpart verifier of the wave ports: the `wave` and `outcome` relations
//! of the extension group, checked by the owned `czkp-bb-worker` (`cvfy`).
//!
//! Everything the verifier trusts comes from the device settings (the retained group's
//! manifest, circuit, keys and SRS files) and is bound twice before it can judge a proof:
//!
//! 1. at load, the manifest must authenticate every file it names (circuit digest, key
//!    digest, both SRS digests and sizes), so the files are exactly one published group;
//! 2. per call, the community's verified wave policy must pin that group: its
//!    `manifest_sha256` is the digest of this manifest and its `proof_scope` is this
//!    group's circuit and key digests. A device that holds another group than the
//!    community currently publishes can neither accept nor deny the counterpart's proof,
//!    so the call is `Unavailable` (retried once the settings are updated) and no
//!    verifier is built.
use super::super::composer::{ComposeError, ProverArtifacts};
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

/// One authenticated extension group, read once and cloned into a verifier per call.
struct Group {
    manifest_sha256: [u8; 32],
    scope: czkp::ProofScope,
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
        let manifest_bytes = read(manifest_file, 65_536)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "config group manifest",
                config("group manifest"),
                &__cause,
            )
        })?;
        // The circuit and keys of every program are the one group the manifest names.
        let circuit = read(&wave.circuit_file, 64 << 20)?;
        let keys = read(&wave.keys_file, 1 << 20)?;
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
            manifest_sha256: sha(&manifest_bytes),
            scope: czkp::ProofScope {
                circuit_digest: sha(&circuit),
                verifying_key_digest: sha(&keys),
            },
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
                circuit_digest: self.scope.circuit_digest,
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
        if policy.manifest_sha256 != self.manifest_sha256 || policy.proof_scope != self.scope {
            return Err(ErrorCode::Unavailable);
        }
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
    /// The counterpart verifier factory of the wave ports, over the retained extension
    /// group. The group is authenticated and read once, here; each call then checks the
    /// community's verified policy against it and builds the two program verifiers.
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
        let files = Files {
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
        files
    }

    fn issuer_point(seed: u8) -> Vec<u8> {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
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
    fn a_policy_that_pins_another_manifest_is_not_judged() {
        let group = fixture();
        let factory = group.artifacts.wave_verifier_factory().unwrap();
        let mut other = policy(&group);
        other.manifest_sha256[0] ^= 1;
        assert_eq!(call(&factory, other), Err(ErrorCode::Unavailable));
    }

    #[test]
    fn a_policy_that_pins_another_circuit_or_key_digest_is_not_judged() {
        let group = fixture();
        let factory = group.artifacts.wave_verifier_factory().unwrap();
        let mut circuit = policy(&group);
        circuit.proof_scope.circuit_digest[0] ^= 1;
        assert_eq!(call(&factory, circuit), Err(ErrorCode::Unavailable));
        let mut keys = policy(&group);
        keys.proof_scope.verifying_key_digest[0] ^= 1;
        assert_eq!(call(&factory, keys), Err(ErrorCode::Unavailable));
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
        let group = fixture();
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
        let mut absent = [fixture(), fixture(), fixture(), fixture()];
        absent[0].artifacts.outcome = None;
        absent[1].artifacts.wave = None;
        absent[2].artifacts.manifest_file = None;
        absent[3].artifacts.verifier_executable = None;
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
