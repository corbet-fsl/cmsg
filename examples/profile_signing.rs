//! Synthetic local owner-key interoperability seam, never a signing server.
use cmsg::{AdmissionGrant, AdmissionTrust, Member, ProfileChallenge};
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use std::io::{BufRead, Read, Write};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    grant: AdmissionGrant,
    trust: AdmissionTrust,
    challenge: ProfileChallenge,
    profile_digest: String,
    now: u64,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut member = Member::new().map_err(|_| "member creation failed")?;
    println!(
        "{}",
        serde_json::json!({"chatPublicKey":BASE64URL_NOPAD.encode(&member.chat_public_key())})
    );
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(16 * 1024 + 1)
        .read_line(&mut line)?;
    if line.is_empty() || line.len() > 16 * 1024 {
        return Err("input limit".into());
    }
    let request: Request = serde_json::from_str(&line)?;
    member
        .bind_admission(request.grant, request.trust, request.now)
        .map_err(|_| "admission rejected")?;
    let challenge_signature = member
        .sign_profile_challenge(&request.challenge, request.now)
        .map_err(|_| "profile challenge rejected")?;
    let response_signature = member
        .sign_profile_response(&request.challenge, &request.profile_digest, request.now)
        .map_err(|_| "profile response rejected")?;
    println!(
        "{}",
        serde_json::json!({"challengeSignature":challenge_signature,"responseSignature":response_signature})
    );
    Ok(())
}
