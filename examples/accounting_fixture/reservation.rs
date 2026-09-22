//! Test-only trusted process adapter. No executable/path arrives through IPC.
use super::*;
use cmsg::{ReservationContext, ReservationPolicy, ReservationVerifier, VerifiedReservation};
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[derive(Clone)]
pub(super) struct Bridge {
    node: PathBuf,
    script: PathBuf,
    manifest: PathBuf,
    enrollment: PathBuf,
    ledger: PathBuf,
    directory: PathBuf,
}
impl Bridge {
    pub(super) fn configured(pair: &mut Pair) -> Result<Option<Self>> {
        let names = [
            "CMSG_PEER_VERIFIER_NODE",
            "CMSG_PEER_VERIFIER_SCRIPT",
            "CMSG_PEER_VERIFIER_MANIFEST",
            "CMSG_PEER_VERIFIER_ENROLLMENT",
            "CMSG_PEER_VERIFIER_LEDGER",
        ];
        let paths: Vec<_> = names.iter().map(|name| std::env::var_os(name)).collect();
        if paths.iter().all(Option::is_none) {
            return Ok(None);
        }
        let paths: Vec<PathBuf> = paths
            .into_iter()
            .map(|p| {
                p.map(PathBuf::from)
                    .ok_or("incomplete trusted peer verifier configuration")
            })
            .collect::<Result<_>>()?;
        if paths.iter().any(|p| !p.is_absolute()) {
            return Err("trusted peer verifier requires absolute paths");
        }
        let directory = paths[4]
            .parent()
            .ok_or("trusted ledger directory")?
            .join("cmsg-checkpoints");
        std::fs::create_dir_all(&directory).map_err(|_| "checkpoint directory")?;
        let bridge = Self {
            node: paths[0].clone(),
            script: paths[1].clone(),
            manifest: paths[2].clone(),
            enrollment: paths[3].clone(),
            ledger: paths[4].clone(),
            directory,
        };
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(&bridge.manifest).map_err(|_| "trusted manifest")?,
        )
        .map_err(|_| "trusted manifest")?;
        if manifest["accountingMode"] != "account-state-v2" {
            return Err("trusted accounting mode");
        }
        let p = &manifest["accountPolicy"];
        let mut bytes = b"cfrm.account-state-policy.v1\0".to_vec();
        bytes.extend_from_slice(&Sha256::digest(b"synthetic-community"));
        for name in [
            "initialCredit",
            "maximumAvailable",
            "outgoingReservation",
            "incomingReservation",
        ] {
            bytes.extend_from_slice(
                &u32::try_from(number(p, name)?)
                    .map_err(|_| "policy bound")?
                    .to_be_bytes(),
            );
        }
        for name in [
            "policyRevision",
            "policyValidFrom",
            "policyValidUntil",
            "newcomerPeriod",
            "rateWindow",
        ] {
            bytes.extend_from_slice(&number(p, name)?.to_be_bytes());
        }
        for name in ["newcomerAdmissions", "maximumAdmissions"] {
            bytes.extend_from_slice(
                &u32::try_from(number(p, name)?)
                    .map_err(|_| "policy bound")?
                    .to_be_bytes(),
            );
        }
        bytes.extend_from_slice(&number(p, "refillPeriod")?.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(number(p, "refillUnits")?)
                .map_err(|_| "policy bound")?
                .to_be_bytes(),
        );
        let abandon = number(p, "abandonAfter")?;
        bytes.push(32);
        if bytes.len() != 138 {
            return Err("state policy transcript length");
        }
        // The composed fixture uses the actual live Inbox gate. No application is
        // generated during this handshake or before the two Active proofs bind.
        pair.ai = core(cmsg::Inbox::new_live(&pair.a))?;
        pair.bi = core(cmsg::Inbox::new_live(&pair.b))?;
        let contact_policy = cmsg::FirstContactPolicy {
            response_deadline: 5000,
            max_intro_bytes: 128,
        };
        core(pair.ai.begin_first_contact(
            pair.br.member_id(),
            &[84; 32],
            cmsg::FirstContactRole::Initiator,
            contact_policy,
            &pair.a,
            &KEY,
            CONTEXT,
            |checkpoint| bridge.save(0, checkpoint),
        ))?;
        core(pair.bi.begin_first_contact(
            pair.ar.member_id(),
            &[84; 32],
            cmsg::FirstContactRole::Recipient,
            contact_policy,
            &pair.b,
            &KEY,
            CONTEXT,
            |checkpoint| bridge.save(1, checkpoint),
        ))?;
        let until = pair
            .time
            .0
            .load(Ordering::Relaxed)
            .checked_add(abandon)
            .ok_or("lease overflow")?;
        let ah = core(pair.ai.begin_live_session(
            &mut pair.a,
            &pair.b.chat_public_key(),
            until,
            &KEY,
            CONTEXT,
            |checkpoint, _| bridge.save(0, checkpoint),
        ))?;
        let bh = core(pair.bi.begin_live_session(
            &mut pair.b,
            &pair.a.chat_public_key(),
            until,
            &KEY,
            CONTEXT,
            |checkpoint, _| bridge.save(1, checkpoint),
        ))?;
        core(
            pair.ai
                .receive_contact(&mut pair.a, &bh, &KEY, CONTEXT, |checkpoint| {
                    bridge.save(0, checkpoint)
                }),
        )?;
        core(
            pair.bi
                .receive_contact(&mut pair.b, &ah, &KEY, CONTEXT, |checkpoint| {
                    bridge.save(1, checkpoint)
                }),
        )?;
        bridge.flush(pair)?;
        let policy = ReservationPolicy {
            state_policy_digest: Sha256::digest(&bytes).into(),
            opened_at: pair.time.0.load(Ordering::Relaxed),
            abandon_after: abandon,
        };
        let a = core(pair.ai.require_active_reservations(
            &pair.a,
            policy.clone(),
            &KEY,
            CONTEXT,
            |checkpoint| bridge.save(0, checkpoint),
        ))?;
        let b = core(pair.bi.require_active_reservations(
            &pair.b,
            policy,
            &KEY,
            CONTEXT,
            |checkpoint| bridge.save(1, checkpoint),
        ))?;
        core(pair.ai.set_own_reservation_challenge(
            &pair.a,
            &b.outgoing.expected.challenge,
            &KEY,
            CONTEXT,
            |checkpoint| bridge.save(0, checkpoint),
        ))?;
        core(pair.bi.set_own_reservation_challenge(
            &pair.b,
            &a.incoming.expected.challenge,
            &KEY,
            CONTEXT,
            |checkpoint| bridge.save(1, checkpoint),
        ))?;
        Ok(Some(bridge))
    }
    pub(super) fn flush(&self, pair: &mut Pair) -> Result<()> {
        for wire in pair.ai.pending_live_controls() {
            core(
                pair.bi
                    .receive_contact(&mut pair.b, &wire, &KEY, CONTEXT, |checkpoint| {
                        self.save(1, checkpoint)
                    }),
            )?;
        }
        core(
            pair.ai
                .clear_live_controls(&pair.a, &KEY, CONTEXT, |checkpoint| {
                    self.save(0, checkpoint)
                }),
        )?;
        for wire in pair.bi.pending_live_controls() {
            core(
                pair.ai
                    .receive_contact(&mut pair.a, &wire, &KEY, CONTEXT, |checkpoint| {
                        self.save(0, checkpoint)
                    }),
            )?;
        }
        core(
            pair.bi
                .clear_live_controls(&pair.b, &KEY, CONTEXT, |checkpoint| {
                    self.save(1, checkpoint)
                }),
        )?;
        Ok(())
    }
    pub(super) fn load(&self, owner: usize) -> Result<Vec<u8>> {
        let file = std::fs::File::open(self.directory.join(format!("owner{owner}.sealed")))
            .map_err(|_| "checkpoint missing")?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "checkpoint read")?;
        if bytes.len() > 1024 * 1024 {
            return Err("checkpoint bound");
        }
        Ok(bytes)
    }
    pub(super) fn save(&self, owner: usize, bytes: &[u8]) -> std::result::Result<(), cmsg::Error> {
        let final_path = self.directory.join(format!("owner{owner}.sealed"));
        let temporary = self.directory.join(format!("owner{owner}.next"));
        let result = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &final_path)?;
            std::fs::File::open(&self.directory)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result.map_err(|_| cmsg::Error::InvalidStore)
    }
    fn verify(
        &self,
        evidence: &[u8],
        context: &ReservationContext,
        local: bool,
    ) -> std::result::Result<VerifiedReservation, cmsg::Error> {
        let presentation: Value =
            serde_json::from_slice(evidence).map_err(|_| cmsg::Error::Admission)?;
        let input=serde_json::to_vec(&json!({"presentation":presentation,"expectedContext":context,"requireCurrentOwn":local})).map_err(|_|cmsg::Error::Admission)?;
        let mut child = Command::new(&self.node)
            .arg(&self.script)
            .arg(&self.manifest)
            .arg(&self.enrollment)
            .arg(&self.ledger)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| cmsg::Error::Admission)?;
        let mut stdin = child.stdin.take().ok_or(cmsg::Error::Admission)?;
        let writer = std::thread::spawn(move || {
            let result = stdin.write_all(&input);
            drop(stdin);
            result
        });
        let stdout = child.stdout.take().ok_or(cmsg::Error::Admission)?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let start = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if start.elapsed() < std::time::Duration::from_secs(60) => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let written = writer.join().map_err(|_| cmsg::Error::Admission)?;
        let output = reader
            .join()
            .map_err(|_| cmsg::Error::Admission)?
            .map_err(|_| cmsg::Error::Admission)?;
        if !status.is_some_and(|s| s.success()) || written.is_err() || output.len() > 16 * 1024 {
            return Err(cmsg::Error::Admission);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Verified {
            verified: bool,
            statement: Value,
            #[serde(rename = "validUntil")]
            valid_until: u64,
        }
        let value: Verified =
            serde_json::from_slice(&output).map_err(|_| cmsg::Error::Admission)?;
        if !value.verified {
            return Err(cmsg::Error::Admission);
        }
        let mut statement = value.statement;
        if !statement.is_object() || statement.get("validUntil").is_some() {
            return Err(cmsg::Error::Admission);
        }
        statement["validUntil"] = value.valid_until.into();
        serde_json::from_value(statement).map_err(|_| cmsg::Error::Admission)
    }
}
impl ReservationVerifier for Bridge {
    fn verify_remote(
        &mut self,
        e: &[u8],
        c: &ReservationContext,
    ) -> std::result::Result<VerifiedReservation, cmsg::Error> {
        self.verify(e, c, false)
    }
    fn verify_current_local(
        &mut self,
        e: &[u8],
        c: &ReservationContext,
    ) -> std::result::Result<VerifiedReservation, cmsg::Error> {
        self.verify(e, c, true)
    }
}
fn number(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or("trusted policy integer")
}
