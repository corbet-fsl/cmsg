//! Starting a community from the creator's device.
//!
//! `foyer.community_create` obtains one blind creation token from the global
//! service under the member's wallet session, then redeems it for the new
//! community on a separate session-less channel, so the platform learns that
//! someone created a community but not who. `foyer.community_creation_claim` is
//! the second half, run on the new community's own Door: it claims the first
//! admin seat with the bearer secret and arms the account actor so that the
//! creator's admission presents the creation id. The device pins the community
//! by the fingerprint the creation returned; nothing else identifies it.
//!
//! The raw owner operations are used internally and are not republished: a
//! forwarded call could not hold the token between issuance and redemption.
use super::*;
use cfyr::{address, creation_token};

const MESSAGE: usize = creation_token::MESSAGE_LEN;
/// Longest display name, in characters.
const NAME_CHARS: usize = 64;
/// Most gate choices one creation names.
const MAXIMUM_GATES: usize = 16;
/// The gate every community has.
const LEGAL: &str = "legal";

/// Body of `foyer.community_create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Create {
    /// The community address: lowercase letters and digits.
    pub address: String,
    /// Name shown to members; it is not part of the address.
    pub display_name: String,
    /// Admission gates the creator chose; `legal` is always required.
    #[serde(default)]
    pub gates: Vec<String>,
}

/// What the device keeps from a creation. The claim secret is a bearer: it lets
/// the creator seat itself as first admin and nobody else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Created {
    pub address: String,
    pub display_name: String,
    pub gates: Vec<String>,
    /// Opaque creation id (32 hex characters).
    pub id: String,
    /// SHA-256 of the community's founding key document, 64 hex characters.
    /// The device pins this: the community's feed must chain to it.
    pub fingerprint: String,
    pub community_host: String,
    pub vault_host: String,
    /// Bearer secret for `foyer.community_creation_claim`, lowercase hex.
    pub claim: String,
    /// The unclaimed community is discarded after this time (unix seconds).
    pub expires_at: u64,
}

/// Body of `foyer.community_creation_claim`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// The claim secret `foyer.community_create` returned, lowercase hex.
    pub claim: String,
}

/// The first admin seat is claimed; the creator's admission now presents it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claimed {
    pub id: String,
    pub expires_at: u64,
}

#[derive(Deserialize)]
struct WireKey {
    public_key: Vec<u8>,
}
#[derive(Deserialize)]
struct WireSigned {
    blind_signature: Vec<u8>,
}
#[derive(Deserialize)]
struct WireCreated {
    id: String,
    fingerprint: String,
    community_host: String,
    vault_host: String,
    claim: Vec<u8>,
    expires_at: u64,
}
#[derive(Deserialize)]
struct WireClaimed {
    id: String,
    expires_at: u64,
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || text.len() > 128 {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// Check what the device can check before it spends anything: the address rules,
/// the name and the gate list. The service checks the address again (reserved
/// names, availability).
fn checked(request: &Create) -> Result<(String, Vec<String>)> {
    let reserved = address::Reserved::new(std::iter::empty::<&str>());
    address::validate(&request.address, &reserved).map_err(|_| ErrorCode::InvalidRequest)?;
    let name = request.display_name.trim();
    if name.is_empty() || name.chars().count() > NAME_CHARS || name.chars().any(char::is_control) {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut gates: Vec<String> = Vec::new();
    for gate in &request.gates {
        let valid = !gate.is_empty()
            && gate.len() <= 32
            && gate
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !valid || gates.contains(gate) || gates.len() >= MAXIMUM_GATES {
            return Err(ErrorCode::InvalidRequest);
        }
        gates.push(gate.clone());
    }
    if !gates.iter().any(|gate| gate == LEGAL) {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok((name.to_owned(), gates))
}

fn origin_of(door: &Door, key: &[u8; 32]) -> Result<String> {
    door.grants
        .get(key)
        .map(|grant| grant.origin.clone())
        .ok_or(ErrorCode::Unauthorized)
}

async fn owner<T: serde::de::DeserializeOwned>(
    door: &mut Door,
    origin: &str,
    name: &str,
    body: Value,
) -> Result<T> {
    let operation = foyer::owner_operation(name).ok_or(ErrorCode::Unavailable)?;
    let binding = door.foyers.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
    let answer = binding.call(operation, body).await?;
    serde_json::from_value(answer).map_err(|_| ErrorCode::Unavailable)
}

/// Obtain a token (once) and redeem it for the new community.
pub(super) async fn community_create(
    door: &mut Door,
    key: &[u8; 32],
    request: Create,
) -> Result<(Created, Vec<Event>)> {
    let (display_name, gates) = checked(&request)?;
    let origin = origin_of(door, key)?;
    // A token from an earlier attempt that the service refused for its address
    // (not for the token) is reused; issuance is limited per person.
    let token = match door.creation_tokens.get(&origin).cloned() {
        Some(token) => token,
        None => {
            let key: WireKey =
                owner(door, &origin, "creation_token_key", serde_json::json!({})).await?;
            let public =
                creation_token::public_key(&key.public_key).map_err(|_| ErrorCode::Unavailable)?;
            let mut message = [0u8; MESSAGE];
            getrandom::fill(&mut message).map_err(|_| ErrorCode::Unavailable)?;
            let (pending, blinded) =
                creation_token::request(&public, message).map_err(|_| ErrorCode::Unavailable)?;
            let signed: WireSigned = owner(
                door,
                &origin,
                "creation_token_issue",
                serde_json::json!({ "blinded": blinded }),
            )
            .await?;
            let token = creation_token::finish(&public, pending, &signed.blind_signature)
                .map_err(|_| ErrorCode::Unavailable)?;
            door.creation_tokens.insert(origin.clone(), token.clone());
            token
        }
    };
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let answer = binding
        .call_public(
            "community_create",
            serde_json::json!({
                "address": request.address,
                "token": {
                    "message": token.message,
                    "randomizer": token.randomizer,
                    "signature": token.signature,
                },
            }),
        )
        .await;
    let answer = match answer {
        Ok(answer) => answer,
        Err(error) => {
            // The service refused: the token was not spent and stays for a retry
            // with another address. A lost answer is `Reconcile`; the token is kept
            // as well, since the service releases it again when nothing was created.
            return Err(error);
        }
    };
    door.creation_tokens.remove(&origin);
    let created: WireCreated =
        serde_json::from_value(answer).map_err(|_| ErrorCode::Unavailable)?;
    Ok((
        Created {
            address: request.address,
            display_name,
            gates,
            id: created.id,
            fingerprint: created.fingerprint,
            community_host: created.community_host,
            vault_host: created.vault_host,
            claim: to_hex(&created.claim),
            expires_at: created.expires_at,
        },
        vec![],
    ))
}

/// Claim the first admin seat on the new community's Door and arm the admission.
pub(super) async fn community_creation_claim(
    door: &mut Door,
    key: &[u8; 32],
    request: Claim,
) -> Result<(Claimed, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let secret = from_hex(&request.claim).ok_or(ErrorCode::InvalidRequest)?;
    let claimed: WireClaimed = owner(
        door,
        &origin,
        "community_creation_claim",
        serde_json::json!({ "claim": secret }),
    )
    .await?;
    // The next admission of this member presents the creation id. Without an
    // account actor the id is still returned for the embedder to arm later.
    if door.accounts.contains_key(&origin) {
        super::registry::account_call(door, key, account::Command::Creation(claimed.id.clone()))
            .await?;
    }
    Ok((
        Claimed {
            id: claimed.id,
            expires_at: claimed.expires_at,
        },
        vec![],
    ))
}

#[cfg(test)]
#[path = "../../tests/support/creating.rs"]
mod tests;
