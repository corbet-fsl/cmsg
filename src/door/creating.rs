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
use super::vouching;
use super::*;
use cfyr::{address, creation_token};

const MESSAGE: usize = creation_token::MESSAGE_LEN;
/// Longest display name, in characters.
const NAME_CHARS: usize = 64;
/// Most gate choices one creation names.
const MAXIMUM_GATES: usize = 16;
/// The gate every community has.
const LEGAL: &str = "legal";
/// Strong and medium gates of the bot fence; the service enforces the same classes
/// (`cvld::config::CreationPlan`), the device only refuses early.
const STRONG: &[&str] = &["voucher", "eid", "id_document", "payment"];
const MEDIUM: &[&str] = &["phone", "provider"];

/// Body of `foyer.community_create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Create {
    /// The community address: lowercase letters and digits. Empty (with an empty name)
    /// resumes the creation the Vault already holds.
    #[serde(default)]
    pub address: String,
    /// Name shown to members; it is not part of the address.
    #[serde(default)]
    pub display_name: String,
    /// Admission gates the creator chose; `legal` is always required.
    #[serde(default)]
    pub gates: Vec<String>,
}

/// Body of `foyer.address_check`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressQuery {
    /// The address as typed so far.
    pub address: String,
    /// The display name suggestions are derived from.
    #[serde(default)]
    pub display_name: String,
    /// How many suggestions at most (0 to 8).
    #[serde(default)]
    pub suggestions: u8,
}

/// Answer of `foyer.address_check`. `refusal` is one of `too_short`, `too_long`,
/// `charset`, `reserved`, `offensive` or `taken`; `light` is `red`, `amber` or `green`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressReport {
    pub available: bool,
    pub refusal: Option<String>,
    pub light: String,
    pub suggestions: Vec<String>,
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
    let count = |class: &[&str]| gates.iter().filter(|g| class.contains(&g.as_str())).count();
    if count(STRONG) == 0 && count(MEDIUM) < 2 {
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
    let answer = if operation.scope_is_global() {
        binding.call_global(operation, body).await?
    } else {
        binding.call(operation, body).await?
    };
    serde_json::from_value(answer).map_err(|_| ErrorCode::Unavailable)
}

/// Where a creation stands, kept in the Vault from the moment the person has made
/// their choices. The choices (address, name, gates) are human effort and are written
/// first; the system steps after them are repeated silently after an interruption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Record {
    pub address: String,
    pub display_name: String,
    pub gates: Vec<String>,
    /// A blinded message sent (or about to be) to the issuer; asking again with the
    /// same one returns the same answer without a second count.
    #[serde(default)]
    pub pending: Option<creation_token::PendingState>,
    /// The finished token, until the service has made the community.
    #[serde(default)]
    pub token: Option<creation_token::Token>,
    /// The service's answer, with the claim secret.
    #[serde(default)]
    pub created: Option<Created>,
    /// The platform runs accounting: this community needs the device's genesis
    /// proof before it can be created.
    #[serde(default)]
    pub proving: bool,
    /// The finished proof, kept so a restart never proves again; dropped once the
    /// community exists.
    #[serde(default)]
    pub activation: Option<super::accounting::Activation>,
}

impl Record {
    pub(super) fn wipe(&mut self) {
        use zeroize::Zeroize;
        if let Some(pending) = &mut self.pending {
            pending.secret.zeroize();
        }
        if let Some(created) = &mut self.created {
            created.claim.zeroize();
        }
        self.activation = None;
    }
}

/// What the person already chose, so a restarted device never asks again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    /// `None` when no creation is under way.
    pub creation: Option<Created>,
    /// The choices of an unfinished creation, empty strings when there is none.
    pub address: String,
    pub display_name: String,
    pub gates: Vec<String>,
    /// `chosen`, `proving`, `token`, `created`: how far the system steps got.
    pub stage: String,
}

fn stage(record: &Record) -> &'static str {
    if record.created.is_some() {
        "created"
    } else if record.proving && record.activation.is_none() {
        // The device is preparing the community's accounting in the background.
        "proving"
    } else if record.token.is_some() {
        "token"
    } else {
        "chosen"
    }
}

fn token_json(token: &creation_token::Token) -> Value {
    serde_json::json!({
        "message": token.message,
        "randomizer": token.randomizer,
        "signature": token.signature,
    })
}

#[derive(Deserialize)]
struct WireTerms {
    accounting: Option<Value>,
}

/// The accounting genesis step: ask the platform what it must see, start (or poll)
/// the proof in the background and keep the finished proof in the Vault record.
/// Returns whether the community can be created now. A platform without
/// accounting needs nothing. Never blocks the Door; a failed proof starts again.
async fn activation_step(
    door: &mut Door,
    origin: &str,
    loaded: &mut vouching::Loaded,
    record: &mut Record,
    token_message: &[u8],
) -> Result<bool> {
    if record.activation.is_some() {
        return Ok(true);
    }
    let binding = door.foyers.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
    let answer = binding
        .call_public(
            "community_terms",
            serde_json::json!({ "address": record.address }),
        )
        .await?;
    let wire: WireTerms = serde_json::from_value(answer).map_err(|_| ErrorCode::Unavailable)?;
    let Some(terms) = wire.accounting else {
        if record.proving {
            record.proving = false;
            loaded.book.creation = Some(record.clone());
            loaded.save(door, origin).await?;
        }
        return Ok(true);
    };
    if !record.proving {
        record.proving = true;
        loaded.book.creation = Some(record.clone());
        loaded.save(door, origin).await?;
    }
    let prover = door
        .activation_prover
        .clone()
        .ok_or(ErrorCode::Unavailable)?;
    let owner = czkp::activation_owner(&record.address, token_message);
    match prover.poll(&record.address, owner, &terms) {
        super::accounting::ActivationPoll::Ready(activation) => {
            record.activation = Some(activation);
            loaded.book.creation = Some(record.clone());
            loaded.save(door, origin).await?;
            Ok(true)
        }
        super::accounting::ActivationPoll::Pending => Ok(false),
        // The next call asks again and so starts a new proof.
        super::accounting::ActivationPoll::Failed => Err(ErrorCode::Reconcile),
    }
}

/// Make the community, resuming wherever an earlier call stopped. The body is
/// needed once; while a creation is under way the stored choices are used and a
/// body naming another address replaces them only before the service made it.
pub(super) async fn community_create(
    door: &mut Door,
    key: &[u8; 32],
    request: Create,
) -> Result<(Created, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let mut loaded = vouching::load(door, &origin).await?;
    let fresh = request.address.is_empty() && request.display_name.is_empty();
    let record = match loaded.book.creation.clone() {
        Some(record) if fresh || record.address == request.address => record,
        Some(record) if record.created.is_none() => {
            // The person changed their mind before anything was made.
            let (display_name, gates) = checked(&request)?;
            let record = Record {
                address: request.address.clone(),
                display_name,
                gates,
                pending: record.pending,
                token: record.token,
                created: None,
                proving: false,
                activation: None,
            };
            loaded.book.creation = Some(record.clone());
            loaded.save(door, &origin).await?;
            record
        }
        Some(_) => return Err(ErrorCode::Refused),
        None => {
            let (display_name, gates) = checked(&request)?;
            let record = Record {
                address: request.address.clone(),
                display_name,
                gates,
                pending: None,
                token: None,
                created: None,
                proving: false,
                activation: None,
            };
            // Human effort first: nothing below can lose it.
            loaded.book.creation = Some(record.clone());
            loaded.save(door, &origin).await?;
            record
        }
    };
    if let Some(created) = record.created.clone() {
        return Ok((created, vec![]));
    }
    let mut record = record;
    if record.token.is_none() {
        let key: WireKey =
            owner(door, &origin, "creation_token_key", serde_json::json!({})).await?;
        let public =
            creation_token::public_key(&key.public_key).map_err(|_| ErrorCode::Unavailable)?;
        let pending = match record.pending.clone() {
            Some(state) => {
                creation_token::Pending::from_state(state).map_err(|_| ErrorCode::Unavailable)?
            }
            None => {
                let mut message = [0u8; MESSAGE];
                getrandom::fill(&mut message).map_err(|_| ErrorCode::Unavailable)?;
                let (pending, _) = creation_token::request(&public, message)
                    .map_err(|_| ErrorCode::Unavailable)?;
                // Kept before the request leaves: a lost answer is asked for again.
                record.pending = Some(pending.to_state());
                loaded.book.creation = Some(record.clone());
                loaded.save(door, &origin).await?;
                pending
            }
        };
        let signed: WireSigned = owner(
            door,
            &origin,
            "creation_token_issue",
            serde_json::json!({ "blinded": pending.blinded() }),
        )
        .await?;
        let token = creation_token::finish(&public, pending, &signed.blind_signature)
            .map_err(|_| ErrorCode::Unavailable)?;
        record.token = Some(token);
        record.pending = None;
        loaded.book.creation = Some(record.clone());
        loaded.save(door, &origin).await?;
    }
    let token = record.token.clone().ok_or(ErrorCode::Unavailable)?;
    // The accounting proof binds this creation's fresh token message (one-time, so it
    // can never serve a later incarnation of the name). It runs in the background and
    // the person is never held at this step.
    let ready = activation_step(door, &origin, &mut loaded, &mut record, &token.message).await?;
    if !ready {
        // Being prepared: ask again (`foyer.community_create` with an empty body
        // resumes). The person's choices and the token are already kept.
        return Err(ErrorCode::Reconcile);
    }
    let activation = record.activation.clone();
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    // A lost answer is asked again with the same token and address: the service
    // answers a repeated creation from the community it already made.
    let mut body = serde_json::json!({
        "address": record.address,
        "display_name": record.display_name,
        "gates": record.gates,
        "token": token_json(&token),
    });
    if let Some(activation) = &activation {
        body["activation"] = serde_json::json!({
            "statement": activation.statement,
            "proof": activation.proof,
        });
    }
    let answer = match binding.call_public("community_create", body).await {
        Ok(answer) => answer,
        Err(ErrorCode::InvalidRequest) if activation.is_some() => {
            // The proof no longer fits the platform's terms (a day passed): it is
            // system work, so prove again silently.
            record.activation = None;
            loaded.book.creation = Some(record.clone());
            loaded.save(door, &origin).await?;
            return Err(ErrorCode::Reconcile);
        }
        Err(error) => return Err(error),
    };
    let wire: WireCreated = serde_json::from_value(answer).map_err(|_| ErrorCode::Unavailable)?;
    let created = Created {
        address: record.address.clone(),
        display_name: record.display_name.clone(),
        gates: record.gates.clone(),
        id: wire.id,
        fingerprint: wire.fingerprint,
        community_host: wire.community_host,
        vault_host: wire.vault_host,
        claim: to_hex(&wire.claim),
        expires_at: wire.expires_at,
    };
    record.created = Some(created.clone());
    record.token = None;
    record.activation = None;
    record.proving = false;
    loaded.book.creation = Some(record);
    loaded.save(door, &origin).await?;
    Ok((created, vec![]))
}

/// What the person already chose and how far the system got.
pub(super) async fn community_creation(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Draft, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let loaded = vouching::load(door, &origin).await?;
    Ok((
        match &loaded.book.creation {
            Some(record) => Draft {
                creation: record.created.clone(),
                address: record.address.clone(),
                display_name: record.display_name.clone(),
                gates: record.gates.clone(),
                stage: stage(record).into(),
            },
            None => Draft {
                creation: None,
                address: String::new(),
                display_name: String::new(),
                gates: Vec::new(),
                stage: "none".into(),
            },
        },
        vec![],
    ))
}

/// Is this address usable and free? The syntax and the length light are decided on
/// the device; only an address that passes goes to the service, on the session-less
/// channel so the platform cannot tie the question to a person. Nothing is kept.
pub(super) async fn address_check(
    door: &mut Door,
    key: &[u8; 32],
    request: AddressQuery,
) -> Result<(AddressReport, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let light = match address::light(&request.address) {
        address::Light::Red => "red",
        address::Light::Amber => "amber",
        address::Light::Green => "green",
    };
    let local = match address::check_syntax(&request.address) {
        Err(address::Refusal::TooShort) => Some("too_short"),
        Err(address::Refusal::TooLong) => Some("too_long"),
        Err(address::Refusal::Charset) => Some("charset"),
        _ => None,
    };
    if let Some(refusal) = local.filter(|_| request.suggestions == 0 || request.display_name.is_empty()) {
        return Ok((
            AddressReport {
                available: false,
                refusal: Some(refusal.into()),
                light: light.into(),
                suggestions: Vec::new(),
            },
            vec![],
        ));
    }
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let answer = binding
        .call_public(
            "address_check",
            serde_json::json!({
                "address": request.address,
                "display_name": request.display_name,
                "suggestions": request.suggestions.min(8),
            }),
        )
        .await?;
    let report: AddressReport =
        serde_json::from_value(answer).map_err(|_| ErrorCode::Unavailable)?;
    Ok((report, vec![]))
}

/// The new community is joined: forget the creation.
pub(super) async fn community_creation_finish(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Empty, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let mut loaded = vouching::load(door, &origin).await?;
    if loaded.book.creation.take().is_some() {
        loaded.save(door, &origin).await?;
    }
    Ok((Empty {}, vec![]))
}

/// Claim the first admin seat on the new community's Door and arm the admission.
/// Repeating it is harmless; the creation id is kept in this Vault until the
/// admission is done, so a restarted device arms itself again (`rearm`).
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
    let mut loaded = vouching::load(door, &origin).await?;
    if loaded.book.claimed.as_deref() != Some(claimed.id.as_str()) {
        loaded.book.claimed = Some(claimed.id.clone());
        loaded.save(door, &origin).await?;
    }
    arm(door, key, &claimed.id).await?;
    Ok((
        Claimed {
            id: claimed.id,
            expires_at: claimed.expires_at,
        },
        vec![],
    ))
}

async fn arm(door: &mut Door, key: &[u8; 32], id: &str) -> Result<()> {
    let origin = origin_of(door, key)?;
    if door.accounts.contains_key(&origin) {
        super::registry::account_call(door, key, account::Command::Creation(id.to_owned())).await?;
    }
    Ok(())
}

/// Before a join: a restarted device presents the creation id it kept.
pub(super) async fn rearm(door: &mut Door, key: &[u8; 32]) -> Result<()> {
    let origin = origin_of(door, key)?;
    // A Vault without the custody record has nothing to present.
    let Ok(loaded) = vouching::load(door, &origin).await else {
        return Ok(());
    };
    match loaded.book.claimed.clone() {
        Some(id) => arm(door, key, &id).await,
        None => Ok(()),
    }
}

/// The join is done: the creation id has done its work.
pub(super) async fn settle(door: &mut Door, key: &[u8; 32]) -> Result<()> {
    let origin = origin_of(door, key)?;
    let Ok(mut loaded) = vouching::load(door, &origin).await else {
        return Ok(());
    };
    if loaded.book.claimed.take().is_some() {
        loaded.save(door, &origin).await?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/support/creating.rs"]
mod tests;

#[cfg(all(test, not(feature = "ohttp")))]
#[path = "../../tests/support/creating_resume.rs"]
mod resume;
