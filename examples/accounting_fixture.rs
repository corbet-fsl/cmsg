//! TEST ONLY: fixed issuer/time and in-memory roots, actual cmsg MLS decisions.
//! Line-delimited --serve IPC accepts public keys, never client signing secrets.
//! This fixture does not authorize production genesis/reservations or balances.
#[path = "../tests/common/mod.rs"]
mod common;
#[path = "accounting_fixture/reservation.rs"]
mod reservation;
use cmsg::{
    AccountingAcknowledgment, AccountingDelegation, AccountingReceipt, ContactResolutionKind,
};
use common::accounting::{Pair, CONTEXT, KEY, SCHEME};
use data_encoding::HEXLOWER as HEX;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::sync::atomic::Ordering;

type Result<T> = std::result::Result<T, &'static str>;
fn core<T>(result: std::result::Result<T, cmsg::Error>) -> Result<T> {
    result.map_err(|_| "cmsg verification failed")
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = HEX
        .decode(value.as_bytes())
        .map_err(|_| "invalid public key")?;
    if HEX.encode(&bytes) != value {
        return Err("noncanonical encoding");
    }
    bytes.try_into().map_err(|_| "invalid length")
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicKey {
    account_key: String,
    secret_hash: String,
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    Enroll {
        keys: Vec<PublicKey>,
        #[serde(rename = "peerExpires")]
        peer_expires: Option<u64>,
    },
    Answer,
    PrepareGate,
    AuthorizeIncoming {
        #[serde(rename = "outgoingPresentation")]
        outgoing_presentation: Value,
    },
    BindGate {
        #[serde(rename = "outgoingPresentation")]
        outgoing_presentation: Value,
        #[serde(rename = "incomingPresentation")]
        incoming_presentation: Value,
    },
    Advance {
        now: u64,
    },
    Close {
        now: u64,
    },
    Ack {
        answer: AccountingReceipt,
    },
    Verify {
        delegations: Vec<AccountingDelegation>,
    },
    VerifyReceipt {
        receipt: AccountingReceipt,
        now: u64,
    },
    VerifyAcknowledgment {
        acknowledgment: AccountingAcknowledgment,
        now: u64,
    },
    VerifyHistoricalReceipt {
        receipt: AccountingReceipt,
        now: u64,
    },
    VerifyHistoricalAcknowledgment {
        acknowledgment: AccountingAcknowledgment,
        now: u64,
    },
    Authorize {
        owner: usize,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "circuitDigest")]
        circuit_digest: String,
        #[serde(rename = "verifyingKeyDigest")]
        verifying_key_digest: String,
        #[serde(rename = "statementDigest")]
        statement_digest: String,
        #[serde(rename = "proofDigest")]
        proof_digest: String,
        #[serde(rename = "issuedAt")]
        issued_at: u64,
        #[serde(rename = "expiresAt")]
        expires_at: u64,
    },
}
fn entry(d: &AccountingDelegation, now: u64) -> Result<Value> {
    core(cmsg::verify_accounting_delegation(d, &common::trust(), now))?;
    if d.hash_scheme != SCHEME {
        return Err("fixture scheme mismatch");
    }
    let secret = decode::<32>(&d.state_secret_commitment)?;
    if secret >= decode::<32>("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")? {
        return Err("noncanonical state field");
    }
    Ok(
        json!({"memberId": d.admission.member_id, "accountKey": d.account_public_key,
        "secretHash": d.state_secret_commitment, "issuedAt": d.issued_at, "expiresAt": d.expires_at,
        "delegationDigest": HEX.encode(&core(d.digest())?), "originalDelegation": d}),
    )
}
struct State {
    pair: Pair,
    originals: Vec<AccountingDelegation>,
    phase: u8,
    bridge: Option<reservation::Bridge>,
}
fn enroll(keys: &[PublicKey], peer_expires: u64) -> Result<State> {
    if !(2..=16).contains(&keys.len()) || !(101..=10_000).contains(&peer_expires) {
        return Err("fixture bounds");
    }
    let mut pair = Pair::configured(peer_expires);
    let mut originals = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let public = decode::<64>(&key.account_key)?;
        let secret = decode::<32>(&key.secret_hash)?;
        let d = if index == 0 {
            core(
                pair.a
                    .delegate_accounting_public_key(&public, SCHEME, &secret, peer_expires),
            )?
        } else if index == 1 {
            core(
                pair.b
                    .delegate_accounting_public_key(&public, SCHEME, &secret, 10_000),
            )?
        } else {
            let root = core(cmsg::MemberIdentity::new("synthetic-community"))?;
            let member = common::accounting::device(&root, &pair.time, 10_000);
            core(member.delegate_accounting_public_key(&public, SCHEME, &secret, 10_000))?
        };
        entry(&d, 100)?;
        originals.push(d);
    }
    pair.ad = originals[0].clone();
    pair.bd = originals[1].clone();
    let bridge = reservation::Bridge::configured(&mut pair)?;
    Ok(State {
        pair,
        bridge,
        originals,
        phase: 0,
    })
}
fn bound_original(state: &State, d: &AccountingDelegation) -> Result<()> {
    let expected = state
        .originals
        .iter()
        .find(|original| original.admission.member_id == d.admission.member_id)
        .ok_or("unrecognized fixture root")?;
    if core(expected.digest())? != core(d.digest())? {
        return Err("changed original delegation");
    }
    Ok(())
}
fn send_intro(state: &mut State) -> Result<()> {
    let storage = state.bridge.clone();
    let wire = core(state.pair.ai.send_contact(
        &mut state.pair.a,
        b"introduction",
        &KEY,
        CONTEXT,
        |checkpoint, _| match &storage {
            Some(s) => s.save(0, checkpoint),
            None => Ok(()),
        },
    ))?;
    core(
        state
            .pair
            .bi
            .receive_contact(
                &mut state.pair.b,
                &wire,
                &KEY,
                CONTEXT,
                |checkpoint| match &storage {
                    Some(s) => s.save(1, checkpoint),
                    None => Ok(()),
                },
            ),
    )?;
    if let Some(bridge) = &storage {
        bridge.flush(&mut state.pair)?;
    }
    Ok(())
}
fn handle(state: &mut Option<State>, request: Request) -> Result<Value> {
    if let Request::Enroll { keys, peer_expires } = request {
        if state.is_some() {
            return Err("fixture already enrolled");
        }
        let s = enroll(&keys, peer_expires.unwrap_or(10_000))?;
        let context = core(
            s.pair
                .bi
                .prepare_accounting_contact(s.pair.ar.member_id(), &s.pair.b),
        )?;
        let result = json!({"version":1, "synthetic":true, "hashScheme":SCHEME, "now":100,
            "community":HEX.encode(&Sha256::digest(b"synthetic-community")), "acceptedTimes":[100,300,600],
            "trust":common::trust(), "entries":s.originals.iter().map(|d| entry(d,100)).collect::<Result<Vec<_>>>()?,
            "context":context, "groupBinding":HEX.encode(&core(context.contact.group_binding())?),
            "contactPolicyDigest":HEX.encode(&core(context.contact.policy_digest())?),
            "historyDigest":HEX.encode(&context.contact.history_digest())});
        *state = Some(s);
        return Ok(result);
    }
    let state = state.as_mut().ok_or("enroll first")?;
    match request {
        Request::PrepareGate => {
            state
                .bridge
                .as_ref()
                .ok_or("trusted peer verifier is not configured")?;
            let contexts = core(state.pair.ai.reservation_contexts(&state.pair.a))?;
            if contexts != core(state.pair.bi.reservation_contexts(&state.pair.b))? {
                return Err("peer context disagreement");
            }
            serde_json::to_value(contexts).map_err(|_| "context encoding")
        }
        Request::AuthorizeIncoming {
            outgoing_presentation,
        } => {
            let mut verifier = state
                .bridge
                .clone()
                .ok_or("trusted peer verifier is not configured")?;
            let storage = verifier.clone();
            let evidence =
                serde_json::to_vec(&outgoing_presentation).map_err(|_| "presentation encoding")?;
            core(state.pair.bi.authorize_incoming_reservation(
                &state.pair.b,
                &evidence,
                &mut verifier,
                &KEY,
                CONTEXT,
                |checkpoint| storage.save(1, checkpoint),
            ))?;
            Ok(json!({"authorized":true}))
        }
        Request::BindGate {
            outgoing_presentation,
            incoming_presentation,
        } => {
            let mut verifier = state
                .bridge
                .clone()
                .ok_or("trusted peer verifier is not configured")?;
            let storage = verifier.clone();
            let a =
                serde_json::to_vec(&outgoing_presentation).map_err(|_| "presentation encoding")?;
            let b =
                serde_json::to_vec(&incoming_presentation).map_err(|_| "presentation encoding")?;
            core(state.pair.ai.bind_active_reservations(
                &state.pair.a,
                &a,
                &b,
                &mut verifier,
                &KEY,
                CONTEXT,
                |checkpoint| storage.save(0, checkpoint),
            ))?;
            core(state.pair.bi.bind_active_reservations(
                &state.pair.b,
                &a,
                &b,
                &mut verifier,
                &KEY,
                CONTEXT,
                |checkpoint| storage.save(1, checkpoint),
            ))?;
            Ok(json!({"bound":true}))
        }
        Request::Advance { now } => {
            if !matches!(state.phase, 1 | 2)
                || !matches!(now, 300 | 600)
                || state.pair.time.0.load(Ordering::Relaxed) > now
            {
                return Err("fixture clock transition");
            }
            state.pair.time.0.store(now, Ordering::Relaxed);
            Ok(json!({"now":now}))
        }
        Request::Answer => {
            if state.phase != 0 {
                return Err("fixture scenario already used");
            }
            send_intro(state)?;
            let storage = state.bridge.clone();
            let wire = core(state.pair.bi.send_contact(
                &mut state.pair.b,
                b"answer",
                &KEY,
                CONTEXT,
                |checkpoint, _| match &storage {
                    Some(s) => s.save(1, checkpoint),
                    None => Ok(()),
                },
            ))?;
            core(state.pair.ai.receive_contact(
                &mut state.pair.a,
                &wire,
                &KEY,
                CONTEXT,
                |checkpoint| match &storage {
                    Some(s) => s.save(0, checkpoint),
                    None => Ok(()),
                },
            ))?;
            if let Some(bridge) = &state.bridge {
                bridge.flush(&mut state.pair)?;
            }
            state.phase = 1;
            let receipt = core(state.pair.bi.prepare_accounting_receipt(
                state.pair.ar.member_id(),
                &state.pair.b,
                &state.pair.bd,
            ))?;
            Ok(
                json!({"receipt":receipt, "signingBytes":HEX.encode(&core(receipt.signing_bytes())?)}),
            )
        }
        Request::Close { now } => {
            if state.phase != 0 || !(100..10_000).contains(&now) {
                return Err("fixture scenario bounds");
            }
            send_intro(state)?;
            state.pair.time.0.store(now, Ordering::Relaxed);
            let storage = state.bridge.clone();
            core(state.pair.bi.resolve_introduction(
                state.pair.ar.member_id(),
                ContactResolutionKind::ClosedForever,
                &state.pair.b,
                &KEY,
                CONTEXT,
                |checkpoint| match &storage {
                    Some(s) => s.save(1, checkpoint),
                    None => Ok(()),
                },
            ))?;
            if let Some(bridge) = &storage {
                let (restored, member) = core(cmsg::Inbox::restore_with_clock(
                    &bridge.load(1)?,
                    &KEY,
                    CONTEXT,
                    state.pair.time.clone(),
                ))?;
                if !restored.is_closed(state.pair.ar.member_id())
                    || restored.outbound_resolution_receipt(state.pair.ar.member_id())
                        != state
                            .pair
                            .bi
                            .outbound_resolution_receipt(state.pair.ar.member_id())
                {
                    return Err("durable Close recovery mismatch");
                }
                state.pair.bi = restored;
                state.pair.b = member;
            }
            state.phase = 2;
            let receipt = core(state.pair.bi.prepare_accounting_receipt(
                state.pair.ar.member_id(),
                &state.pair.b,
                &state.pair.bd,
            ))?;
            Ok(
                json!({"receipt":receipt, "signingBytes":HEX.encode(&core(receipt.signing_bytes())?)}),
            )
        }
        Request::Ack { answer } => {
            if state.phase != 1 {
                return Err("actual answer required");
            }
            bound_original(state, &answer.delegation)?;
            let ack = core(state.pair.ai.prepare_accounting_acknowledgment(
                state.pair.br.member_id(),
                &state.pair.a,
                &state.pair.ad,
                &answer,
            ))?;
            Ok(
                json!({"acknowledgment":ack, "signingBytes":HEX.encode(&core(ack.signing_bytes())?)}),
            )
        }
        Request::Verify { delegations } => {
            if delegations.len() != state.originals.len() {
                return Err("fixture roster size");
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut entries = Vec::new();
            for d in delegations {
                bound_original(state, &d)?;
                if !seen.insert(d.admission.member_id.clone()) {
                    return Err("duplicate member");
                }
                entries.push(entry(&d, 100)?);
            }
            Ok(json!({"entries":entries,"now":100,"hashScheme":SCHEME}))
        }
        Request::VerifyReceipt { receipt, now } => {
            bound_original(state, &receipt.delegation)?;
            core(cmsg::verify_accounting_receipt(
                &receipt,
                &common::trust(),
                now,
            ))?;
            Ok(json!({"verified":true,"signingBytes":HEX.encode(&core(receipt.signing_bytes())?)}))
        }
        Request::VerifyAcknowledgment {
            acknowledgment,
            now,
        } => {
            bound_original(state, &acknowledgment.delegation)?;
            bound_original(state, &acknowledgment.answer.delegation)?;
            core(cmsg::verify_accounting_acknowledgment(
                &acknowledgment,
                &common::trust(),
                now,
            ))?;
            Ok(
                json!({"verified":true,"signingBytes":HEX.encode(&core(acknowledgment.signing_bytes())?)}),
            )
        }
        Request::VerifyHistoricalReceipt { receipt, now } => {
            bound_original(state, &receipt.delegation)?;
            core(cmsg::verify_accounting_receipt_historical(
                &receipt,
                &common::trust(),
                &core(state.pair.bd.digest())?,
                now,
            ))?;
            Ok(json!({"verified":true,"signingBytes":HEX.encode(&core(receipt.signing_bytes())?)}))
        }
        Request::VerifyHistoricalAcknowledgment {
            acknowledgment,
            now,
        } => {
            bound_original(state, &acknowledgment.delegation)?;
            bound_original(state, &acknowledgment.answer.delegation)?;
            core(cmsg::verify_accounting_acknowledgment_historical(
                &acknowledgment,
                &common::trust(),
                &core(state.pair.bd.digest())?,
                &core(state.pair.ad.digest())?,
                now,
            ))?;
            Ok(
                json!({"verified":true,"signingBytes":HEX.encode(&core(acknowledgment.signing_bytes())?)}),
            )
        }
        Request::Authorize {
            owner,
            request_id,
            circuit_digest,
            verifying_key_digest,
            statement_digest,
            proof_digest,
            issued_at,
            expires_at,
        } => {
            let member = match owner {
                0 => &state.pair.a,
                1 => &state.pair.b,
                _ => return Err("fixture owner"),
            };
            let result = core(member.authorize_account_request(
                &decode(&request_id)?,
                &decode(&circuit_digest)?,
                &decode(&verifying_key_digest)?,
                &decode(&statement_digest)?,
                &decode(&proof_digest)?,
                issued_at,
                expires_at,
            ))?;
            let d = &state.originals[owner];
            Ok(
                json!({"authorization":result, "admission":d.admission, "deviceAuthorization":d.authorization}),
            )
        }
        Request::Enroll { .. } => Err("fixture already enrolled"),
    }
}
fn main() {
    if std::env::args().nth(1).as_deref() != Some("--serve") {
        eprintln!("use --serve; synthetic test fixture only");
        std::process::exit(2);
    }
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut output = std::io::stdout().lock();
    let mut state = None;
    loop {
        let mut line = Vec::new();
        let count = reader
            .by_ref()
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut line)
            .unwrap_or(0);
        if count == 0 {
            break;
        }
        if count > 128 * 1024 || line.last() != Some(&b'\n') {
            break;
        }
        let result = serde_json::from_slice(&line)
            .map_err(|_| "invalid request")
            .and_then(|request| handle(&mut state, request));
        let response = match result {
            Ok(value) => json!({"ok":value}),
            Err(error) => json!({"error":error}),
        };
        if writeln!(output, "{response}").is_err() || output.flush().is_err() {
            break;
        }
    }
}
