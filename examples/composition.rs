//! Local synthetic process seam for cross-language admission and rules experiments.
//! Public chat keys are emitted first; one JSON line supplies signed grants.
use cmsg::{
    Acceptance, AdmissionGrant, AdmissionTrust, Inbox, Member, Received, Redemption,
    RendezvousChallenge,
};
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use std::io::{BufRead, Write};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    grants: [AdmissionGrant; 2],
    trust: AdmissionTrust,
    wrapping_key: Option<[u8; 32]>,
    recipient_redemption: Option<Vec<u8>>,
    #[serde(default)]
    defer_exchange: bool,
    rendezvous_challenges: Option<[RendezvousChallenge; 2]>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = Member::new().map_err(|_| "member creation failed")?;
    let mut b = Member::new().map_err(|_| "member creation failed")?;
    println!(
        "{}",
        serde_json::json!({"chatPublicKeys":[BASE64URL_NOPAD.encode(&a.chat_public_key()),BASE64URL_NOPAD.encode(&b.chat_public_key())]})
    );
    std::io::stdout().flush()?;
    let line = std::io::stdin()
        .lock()
        .lines()
        .next()
        .ok_or("missing admission input")??;
    if line.len() > 16 * 1024 {
        return Err("input limit".into());
    }
    let request: Request = serde_json::from_str(&line)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    a.bind_admission(request.grants[0].clone(), request.trust.clone(), now)
        .map_err(|_| "admission rejected")?;
    b.bind_admission(request.grants[1].clone(), request.trust, now)
        .map_err(|_| "admission rejected")?;
    let signatures = request
        .rendezvous_challenges
        .as_ref()
        .map(|challenges| {
            Ok::<_, &str>([
                a.sign_rendezvous(&challenges[0], now)
                    .map_err(|_| "rendezvous rejected")?,
                b.sign_rendezvous(&challenges[1], now)
                    .map_err(|_| "rendezvous rejected")?,
            ])
        })
        .transpose()?;
    let (wrapping_key, recipient_redemption) = if request.defer_exchange {
        println!(
            "{}",
            serde_json::json!({"admitted":true,"rendezvousSignatures":signatures})
        );
        std::io::stdout().flush()?;
        let next = std::io::stdin()
            .lock()
            .lines()
            .next()
            .ok_or("missing exchange input")??;
        if next.len() > 64 * 1024 {
            return Err("input limit".into());
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Exchange {
            wrapping_key: [u8; 32],
            recipient_redemption: Option<Vec<u8>>,
        }
        let exchange = serde_json::from_str::<Exchange>(&next)?;
        (exchange.wrapping_key, exchange.recipient_redemption)
    } else {
        (
            request.wrapping_key.ok_or("missing wrapping key")?,
            request.recipient_redemption,
        )
    };
    a.create_group().map_err(|_| "group creation failed")?;
    let welcome = a
        .add(&b.key_package().map_err(|_| "key package failed")?)
        .map_err(|_| "member addition failed")?
        .welcome;
    let gated = recipient_redemption.is_some();
    if let Some(attempt) = recipient_redemption {
        let mut inbox = Inbox::new(&b).map_err(|_| "inbox creation failed")?;
        let mut checkpoint = Checkpoint::new()?;
        let result = inbox
            .accept(
                &mut b,
                &welcome,
                Some(&attempt),
                &wrapping_key,
                b"composition-inbox-v1",
                |state| {
                    checkpoint
                        .write(state)
                        .map_err(|_| cmsg::Error::InvalidStore)
                },
                |attempt| {
                    println!("{}", serde_json::json!({"redeemRequest":attempt}));
                    if std::io::stdout().flush().is_err() {
                        return Redemption::Indeterminate;
                    }
                    #[derive(Deserialize)]
                    struct Reply {
                        outcome: String,
                    }
                    let reply = std::io::stdin()
                        .lock()
                        .lines()
                        .next()
                        .and_then(Result::ok)
                        .filter(|line| line.len() < 1024)
                        .and_then(|line| serde_json::from_str::<Reply>(&line).ok());
                    match reply.as_ref().map(|r| r.outcome.as_str()) {
                        Some("accepted") => Redemption::Accepted,
                        Some("rejected") => Redemption::Rejected,
                        _ => Redemption::Indeterminate,
                    }
                },
            )
            .map_err(|_| "recipient gate failed")?;
        if result != Acceptance::Joined {
            return Err("recipient gate did not authorize contact".into());
        }
        let (restored, restored_member) =
            Inbox::restore(&checkpoint.read()?, &wrapping_key, b"composition-inbox-v1")
                .map_err(|_| "recipient checkpoint restore failed")?;
        if !restored.is_known(&request.grants[0].member_id) {
            return Err("known contact not committed".into());
        }
        b = restored_member;
    } else {
        // Backwards-compatible primitive experiment. New client integrations must
        // use Inbox; this branch deliberately makes no recipient-gate claim.
        b.join(&welcome).map_err(|_| "join failed")?;
    }
    let wire = a
        .send(b"synthetic composition text")
        .map_err(|_| "send failed")?;
    let received = b.receive(&wire).map_err(|_| "receive failed")?;
    let valid = matches!(received, Received::Text(t) if t.text == "synthetic composition text" && t.member_id == request.grants[0].member_id);
    let snapshot = b
        .snapshot(&wrapping_key, b"composition-v1")
        .map_err(|_| "snapshot failed")?;
    let mut restored = Member::restore(&snapshot, &wrapping_key, b"composition-v1")
        .map_err(|_| "restore failed")?;
    let replay_rejected = restored.receive(&wire).is_err();
    if !valid || !replay_rejected {
        return Err("composition invariant failed".into());
    }
    let mut output = serde_json::json!({"delivered":true,"stableIdentityBound":true,"encryptedSnapshotRestored":true,"replayRejected":true});
    if gated {
        output["recipientGateEnforced"] = true.into();
        output["recipientCheckpointRestored"] = true.into();
    }
    println!("{output}");
    Ok(())
}

// Owned throwaway directory; only synthetic ciphertext enters this example store.
// Production clients supply platform-appropriate atomic storage to Inbox instead.
struct Checkpoint {
    directory: std::path::PathBuf,
    generation: u64,
}
impl Checkpoint {
    fn new() -> std::io::Result<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(std::io::Error::other)?;
        let directory = std::env::temp_dir().join(format!(
            "cmsg-composition-{}",
            data_encoding::HEXLOWER.encode(&random)
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory)?;
        Ok(Self {
            directory,
            generation: 0,
        })
    }
    fn write(&mut self, state: &[u8]) -> std::io::Result<()> {
        self.generation += 1;
        let pending = self
            .directory
            .join(format!("checkpoint-{}", self.generation));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&pending)?;
        file.write_all(state)?;
        file.sync_all()?;
        std::fs::rename(&pending, self.directory.join("state"))?;
        std::fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    fn read(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.directory.join("state"))
    }
}
impl Drop for Checkpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.directory.join("state"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}
