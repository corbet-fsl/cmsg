//! Synthetic process harness, never an operator relay or a production client API.
//! Two actual chat keys remain inside this child; the driver owns fixture wallets.
use cmsg::{
    verify_admission, AdmissionGrant, AdmissionTrust, Clock, Member, Received,
    ReleaseAuthorizationTiming, ReleaseContext, ReleasePreflight, ReleaseReceipt,
    SemaphoreEnrollmentChallenge,
};
use cmsg_first_contact_release_experiment::{
    Context, OperatorTrust, Peer, PendingRelease, RecipientRedemption, ReleasedMaterial,
    SenderCommit,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAX_LINE_BYTES: usize = 32 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const FIRST_TEXT: &str = "synthetic native counter composition text";
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    op: String,
    args: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Init {
    now: u64,
    community_id: String,
    policy_digest: String,
    issuer_public_key: String,
    sender_commit_public_key: String,
    recipient_redemption_public_key: String,
    expected_wallet_commitments: WalletCommitments,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletCommitments {
    sender: String,
    recipient: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admissions {
    sender: AdmissionGrant,
    recipient: AdmissionGrant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Actor {
    Sender,
    Recipient,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignEnrollment {
    actor: Actor,
    challenge: SemaphoreEnrollmentChallenge,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareRelease {
    context: ReleaseContext,
    preflight_expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorizeSend {
    blinded: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorizeReceive {
    receipt: ReleaseReceipt,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinishRelease {
    sender_commit: SenderCommit,
    recipient_redemption: RecipientRedemption,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestorePending {}

// The fixture's initial clock is pinned once, not accepted from later messages.
struct FixtureClock(u64);
impl Clock for FixtureClock {
    fn now(&self) -> std::result::Result<u64, cmsg::Error> {
        Ok(self.0)
    }
}

struct Actors {
    sender: Member,
    recipient: Member,
    trust: AdmissionTrust,
    operator_trust: OperatorTrust,
    now: u64,
    expected_wallet_commitments: WalletCommitments,
    admissions: Option<Admissions>,
    release: Option<ReleaseSession>,
}

struct ReleaseSession {
    pending: PendingRelease,
    preflight: ReleasePreflight,
    original: ReleasedMaterial,
    wrapping_key: Zeroizing<[u8; 32]>,
    delivered: bool,
}

#[derive(Default)]
struct Harness {
    actors: Option<Actors>,
}

impl Harness {
    fn execute(&mut self, op: &str, args: Value) -> Result<Value> {
        match op {
            "init" => self.init(parse(args)?),
            "bindAdmissions" => self.bind_admissions(parse(args)?),
            "signEnrollment" => self.sign_enrollment(parse(args)?),
            "prepareRelease" => self.prepare_release(parse(args)?),
            "authorizeSend" => self.authorize_send(parse(args)?),
            "authorizeReceive" => self.authorize_receive(parse(args)?),
            "finishRelease" => self.finish_release(parse(args)?),
            "restorePending" => self.restore_pending(parse(args)?),
            _ => Err("unknown-operation"),
        }
    }

    fn init(&mut self, args: Init) -> Result<Value> {
        if self.actors.is_some() {
            return Err("invalid-state");
        }
        if args.now == 0
            || args.now > MAX_SAFE_INTEGER
            || args.community_id.is_empty()
            || args.community_id.len() > 128
            || !args
                .community_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
            || !bounded_commitment(&args.expected_wallet_commitments.sender)
            || !bounded_commitment(&args.expected_wallet_commitments.recipient)
        {
            return Err("invalid-input");
        }
        decode32(&args.policy_digest)?;
        let issuer = public_key(&args.issuer_public_key)?;
        let sender_commit = public_key(&args.sender_commit_public_key)?;
        let recipient_redemption = public_key(&args.recipient_redemption_public_key)?;
        if sender_commit == recipient_redemption {
            return Err("invalid-input");
        }
        let clock = Arc::new(FixtureClock(args.now));
        let sender = Member::new_with_clock(clock.clone()).map_err(|_| "initialization-failed")?;
        let recipient = Member::new_with_clock(clock).map_err(|_| "initialization-failed")?;
        let response = json!({
            "sender": {"chatPublicKey": B64.encode(&sender.chat_public_key())},
            "recipient": {"chatPublicKey": B64.encode(&recipient.chat_public_key())}
        });
        self.actors = Some(Actors {
            sender,
            recipient,
            trust: AdmissionTrust {
                community_id: args.community_id,
                policy_digest: args.policy_digest,
                issuer_public_key: issuer,
            },
            operator_trust: OperatorTrust {
                sender_commit_key: sender_commit,
                recipient_redemption_key: recipient_redemption,
            },
            now: args.now,
            expected_wallet_commitments: args.expected_wallet_commitments,
            admissions: None,
            release: None,
        });
        Ok(response)
    }

    fn bind_admissions(&mut self, args: Admissions) -> Result<Value> {
        let actors = self.actors.as_mut().ok_or("invalid-state")?;
        if actors.admissions.is_some() || args.sender.member_id == args.recipient.member_id {
            return Err("invalid-state");
        }
        // Validate both inputs before mutating either one-time member binding.
        verify_admission(
            &args.sender,
            &actors.trust,
            &actors.sender.chat_public_key(),
            actors.now,
        )
        .map_err(|_| "admission-rejected")?;
        verify_admission(
            &args.recipient,
            &actors.trust,
            &actors.recipient.chat_public_key(),
            actors.now,
        )
        .map_err(|_| "admission-rejected")?;
        actors
            .sender
            .bind_admission(args.sender.clone(), actors.trust.clone(), actors.now)
            .map_err(|_| "admission-rejected")?;
        actors
            .recipient
            .bind_admission(args.recipient.clone(), actors.trust.clone(), actors.now)
            .map_err(|_| "admission-rejected")?;
        let response = json!({
            "sender": {
                "memberId": actors.sender.member_id().map_err(|_| "admission-rejected")?,
                "chatPublicKey": B64.encode(&actors.sender.chat_public_key())
            },
            "recipient": {
                "memberId": actors.recipient.member_id().map_err(|_| "admission-rejected")?,
                "chatPublicKey": B64.encode(&actors.recipient.chat_public_key())
            }
        });
        actors.admissions = Some(args);
        Ok(response)
    }

    fn sign_enrollment(&self, args: SignEnrollment) -> Result<Value> {
        let actors = self.actors.as_ref().ok_or("invalid-state")?;
        if actors.admissions.is_none() {
            return Err("invalid-state");
        }
        // The expected commitment comes from init, never from this challenge.
        let signature = match args.actor {
            Actor::Sender => actors.sender.sign_semaphore_enrollment(
                &args.challenge,
                &actors.expected_wallet_commitments.sender,
            ),
            Actor::Recipient => actors.recipient.sign_semaphore_enrollment(
                &args.challenge,
                &actors.expected_wallet_commitments.recipient,
            ),
        }
        .map_err(|_| "enrollment-rejected")?;
        Ok(json!({"signature": signature}))
    }

    fn prepare_release(&mut self, args: PrepareRelease) -> Result<Value> {
        let actors = self.actors.as_mut().ok_or("invalid-state")?;
        let admissions = actors.admissions.as_ref().ok_or("invalid-state")?;
        if actors.release.is_some() {
            return Err("invalid-state");
        }
        // Check fixture inputs before mutating the actual sender's MLS group.
        let c = &args.context;
        if c.community_id != actors.trust.community_id
            || c.policy_digest != actors.trust.policy_digest
            || c.cohort_id.is_empty()
            || c.cohort_id.len() > 128
            || c.not_before == 0
            || c.not_before > actors.now
            || c.expires_at <= actors.now
            || c.expires_at > MAX_SAFE_INTEGER
            || args.preflight_expires_at <= actors.now
            || args.preflight_expires_at - actors.now > 300
            || args.preflight_expires_at > c.expires_at
            || args.preflight_expires_at > admissions.sender.expires_at
            || args.preflight_expires_at > admissions.recipient.expires_at
        {
            return Err("invalid-input");
        }
        let sender = peer(&actors.sender)?;
        let recipient = peer(&actors.recipient)?;
        let mut wrapping_key = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *wrapping_key).map_err(|_| "release-rejected")?;
        actors
            .sender
            .create_group()
            .map_err(|_| "release-rejected")?;
        let package = actors
            .recipient
            .key_package()
            .map_err(|_| "release-rejected")?;
        let invite = actors
            .sender
            .add(&package)
            .map_err(|_| "release-rejected")?;
        let original = ReleasedMaterial {
            welcome: invite.welcome,
            first_ciphertext: actors
                .sender
                .send(FIRST_TEXT.as_bytes())
                .map_err(|_| "release-rejected")?,
        };
        let pending = PendingRelease::prepare(
            pending_context(c),
            sender,
            recipient,
            original.clone(),
            actors.now,
        )
        .map_err(|_| "release-rejected")?;
        let metadata = pending.preflight();
        let preflight = actors
            .sender
            .sign_release_preflight(
                c,
                &admissions.recipient,
                &metadata.release_nonce,
                args.preflight_expires_at,
            )
            .map_err(|_| "release-rejected")?;
        actors
            .recipient
            .verify_release_preflight(&preflight, &admissions.sender)
            .map_err(|_| "release-rejected")?;
        // The harness chooses acceptance of this authenticated synthetic invite.
        // It has no production consent/block workflow. Even exposing ciphertext
        // to the lower-level recipient still cannot supply the withheld Welcome.
        if actors.recipient.participants().is_ok()
            || actors.recipient.receive(&original.first_ciphertext).is_ok()
            || actors.recipient.join(&[]).is_ok()
        {
            return Err("release-rejected");
        }
        let response = json!({
            "preflight": preflight,
            "recipientHasWelcome": false,
            "ciphertextRejectedBeforeWelcome": true
        });
        actors.release = Some(ReleaseSession {
            pending,
            preflight,
            original,
            wrapping_key,
            delivered: false,
        });
        Ok(response)
    }

    fn authorize_send(&mut self, args: AuthorizeSend) -> Result<Value> {
        let actors = self.actors.as_mut().ok_or("invalid-state")?;
        verify_private_preflight(actors)?;
        let session = actors.release.as_mut().ok_or("invalid-state")?;
        if args.expires_at <= actors.now || args.expires_at > session.preflight.expires_at {
            return Err("release-rejected");
        }
        let blinded = B64
            .decode(args.blinded.as_bytes())
            .map_err(|_| "release-rejected")?;
        if blinded.len() != 384 || B64.encode(&blinded) != args.blinded {
            return Err("release-rejected");
        }
        let request_hash = B64.encode(&Sha256::digest(&blinded));
        let expected = session
            .pending
            .bind_request(&request_hash)
            .map_err(|_| "release-rejected")?;
        let authorization = actors
            .sender
            .authorize_release_send(
                &session.preflight.context,
                &blinded,
                &ReleaseAuthorizationTiming {
                    nonce: expected.authorization_nonce,
                    expires_at: args.expires_at,
                },
            )
            .map_err(|_| "release-rejected")?;
        // The private preflight/challenge is never added to this operator output.
        Ok(json!({"authorization": authorization}))
    }

    fn authorize_receive(&self, args: AuthorizeReceive) -> Result<Value> {
        let actors = self.actors.as_ref().ok_or("invalid-state")?;
        verify_private_preflight(actors)?;
        let session = actors.release.as_ref().ok_or("invalid-state")?;
        if args.expires_at <= actors.now || args.expires_at > session.preflight.expires_at {
            return Err("release-rejected");
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "release-rejected")?;
        let authorization = actors
            .recipient
            .authorize_release_receive(
                &session.preflight.context,
                &args.receipt,
                &session.preflight.release_nonce,
                &ReleaseAuthorizationTiming {
                    nonce: B64.encode(&nonce),
                    expires_at: args.expires_at,
                },
            )
            .map_err(|_| "release-rejected")?;
        Ok(json!({"authorization": authorization}))
    }

    fn finish_release(&mut self, args: FinishRelease) -> Result<Value> {
        let actors = self.actors.as_mut().ok_or("invalid-state")?;
        // The short private-preflight deadline remains distinct from the common
        // operator attestation expiry. Verify current credentials again here.
        verify_private_preflight(actors)?;
        let session = actors.release.as_mut().ok_or("invalid-state")?;
        let material = session
            .pending
            .release(
                &args.sender_commit,
                &args.recipient_redemption,
                &actors.operator_trust,
                actors.now,
            )
            .map_err(|_| "release-rejected")?;
        if material != session.original {
            return Err("release-rejected");
        }
        if !session.delivered {
            actors
                .recipient
                .join(&material.welcome)
                .map_err(|_| "release-rejected")?;
            match actors
                .recipient
                .receive(&material.first_ciphertext)
                .map_err(|_| "release-rejected")?
            {
                Received::Text(text)
                    if text.member_id == session.preflight.sender.member_id
                        && text.text == FIRST_TEXT => {}
                _ => return Err("release-rejected"),
            }
            session.delivered = true;
        }
        // A valid retry checks the same original bytes, without rejoining or
        // attempting to process an MLS application-message replay.
        Ok(json!({
            "released": true, "recipientJoined": true, "decrypted": true,
            "authenticatedSenderMatches": true, "plaintextMatches": true, "sameMaterial": true
        }))
    }

    fn restore_pending(&mut self, _args: RestorePending) -> Result<Value> {
        let actors = self.actors.as_mut().ok_or("invalid-state")?;
        verify_private_preflight(actors)?;
        let session = actors.release.as_mut().ok_or("invalid-state")?;
        if session.delivered || actors.recipient.participants().is_ok() {
            return Err("invalid-state");
        }
        let sealed = session
            .pending
            .seal(&session.wrapping_key)
            .map_err(|_| "release-rejected")?;
        let restored = PendingRelease::restore(
            &sealed,
            &session.wrapping_key,
            &pending_context(&session.preflight.context),
        )
        .map_err(|_| "release-rejected")?;
        let metadata = restored.preflight();
        if metadata.release_nonce != session.preflight.release_nonce
            || metadata.sender.member_id != session.preflight.sender.member_id
            || metadata.sender.chat_public_key != session.preflight.sender.chat_public_key
            || metadata.recipient.member_id != session.preflight.recipient.member_id
            || metadata.recipient.chat_public_key != session.preflight.recipient.chat_public_key
        {
            return Err("release-rejected");
        }
        // This is an in-process encrypted restore, not a process-kill or durable
        // rollback test. The final gate still compares the original held bytes.
        session.pending = restored;
        Ok(json!({"restored": true, "recipientHasWelcome": false}))
    }
}

fn verify_private_preflight(actors: &Actors) -> Result<()> {
    let admissions = actors.admissions.as_ref().ok_or("invalid-state")?;
    let session = actors.release.as_ref().ok_or("invalid-state")?;
    actors
        .recipient
        .verify_release_preflight(&session.preflight, &admissions.sender)
        .map_err(|_| "release-rejected")
}

fn pending_context(value: &ReleaseContext) -> Context {
    Context {
        community_id: value.community_id.clone(),
        policy_digest: value.policy_digest.clone(),
        cohort_id: value.cohort_id.clone(),
        not_before: value.not_before,
        expires_at: value.expires_at,
    }
}

fn peer(member: &Member) -> Result<Peer> {
    Ok(Peer {
        member_id: member.member_id().map_err(|_| "release-rejected")?,
        chat_public_key: B64.encode(&member.chat_public_key()),
    })
}

fn parse<T: DeserializeOwned>(args: Value) -> Result<T> {
    serde_json::from_value(args).map_err(|_| "invalid-input")
}

fn decode32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 43 {
        return Err("invalid-input");
    }
    let bytes = B64.decode(value.as_bytes()).map_err(|_| "invalid-input")?;
    if B64.encode(&bytes) != value {
        return Err("invalid-input");
    }
    bytes.try_into().map_err(|_| "invalid-input")
}

fn public_key(value: &str) -> Result<[u8; 32]> {
    let key = decode32(value)?;
    VerifyingKey::from_bytes(&key).map_err(|_| "invalid-input")?;
    Ok(key)
}

fn bounded_commitment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 77
        && matches!(value.as_bytes()[0], b'1'..=b'9')
        && value.bytes().all(|b| b.is_ascii_digit())
}

fn run() -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut harness = Harness::default();
    let mut next_id = 1;
    loop {
        let mut line = Vec::new();
        let size = Read::take(&mut input, (MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "protocol-failed")?;
        if size == 0 {
            return Ok(());
        }
        if size > MAX_LINE_BYTES || line.last() != Some(&b'\n') {
            return Err("protocol-failed");
        }
        let request: Request = serde_json::from_slice(&line).map_err(|_| "protocol-failed")?;
        if request.id != next_id || request.id > MAX_SAFE_INTEGER {
            return Err("protocol-failed");
        }
        next_id += 1;
        let response = match harness.execute(&request.op, request.args) {
            Ok(result) => json!({"id": request.id, "ok": true, "result": result}),
            Err(error) => json!({"id": request.id, "ok": false, "error": error}),
        };
        serde_json::to_writer(&mut output, &response).map_err(|_| "protocol-failed")?;
        output.write_all(b"\n").map_err(|_| "protocol-failed")?;
        output.flush().map_err(|_| "protocol-failed")?;
    }
}

fn main() {
    // The captured protocol must never print panic payloads or raw envelopes.
    std::panic::set_hook(Box::new(|_| eprintln!("counter-bridge-failed")));
    if run().is_err() {
        eprintln!("counter-bridge-failed");
        std::process::exit(1);
    }
}
