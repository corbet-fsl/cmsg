//! Voucher links on the member's devices.
//!
//! The issuer's device creates a link, keeps every secret of it in its Vault
//! custody (the link text, the HPKE private key, the bonds, the signed
//! endorsements) and talks to the community only with hashes and the management
//! secret. The community never learns the issuer. These actions are the only way
//! a frontend reaches the raw owner operations: the Door performs them itself so
//! nothing a frontend sends can skip custody.
//!
//! The newcomer's side lives in the account lifecycle (`account`): it keeps the
//! per-link bond nonce and the bond in the same custody record (`Book`).
use super::*;
use cvch::link::{Bond, IssuerSecret, LinkId, Notice, Token, NONCE_BYTES};
use zeroize::Zeroize;

/// Custody schema version inside the opaque record.
const BOOK_VERSION: u8 = 1;
/// How long a signed endorsement may wait to be used by the signer, in seconds.
const SIGN_SECONDS: u64 = 60;
/// Largest number of links one device keeps.
const MAXIMUM_LINKS: usize = 512;
/// Largest number of bonds one device keeps.
const MAXIMUM_BONDS: usize = 4096;

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
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

/// A link this device issued.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Issued {
    pub id: String,
    /// The link text (fragment): secret plus the device's HPKE public key.
    pub fragment: String,
    /// The device's HPKE private key for this link, lowercase hex.
    pub key: String,
    pub uses: u32,
    pub signoff: bool,
    /// Whether an admission through this link is signed "vouched for by".
    pub visible: bool,
    pub created_at: u64,
    pub expires_at: u64,
    /// Created locally, not yet confirmed by the community.
    pub pending: bool,
    pub revoked: bool,
    /// Revoked or expired and read one last time: nothing more to learn.
    pub done: bool,
}

/// One bond this device holds, from either side of a vouching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct BondEntry {
    /// True for the member who issued the link.
    pub sponsor: bool,
    pub link: String,
    /// The vouchee's member id (empty on the vouchee's own device).
    pub member: String,
    pub bond: String,
    /// On the vouchee's device: the sponsor's opaque community member id (hex),
    /// read from the link text. Empty on the issuer's device.
    #[serde(default)]
    pub sponsor_id: String,
}

/// The bond nonce a newcomer chose for a link, kept until the bond exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NonceEntry {
    pub link: String,
    pub nonce: String,
    /// The link text, kept to read the issuer's reply after admission.
    #[serde(default)]
    pub fragment: String,
}

/// An endorsement received from a sponsor whose signature was checked for this
/// community and this member. The sponsor's device is not yet checked against
/// their verified lineage: whoever shows it must do that first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Received {
    pub link: String,
    pub handle: String,
    pub device: String,
    pub signature: String,
}

/// A statement the issuer's device signed in visible mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Endorsement {
    pub link: String,
    pub vouchee: String,
    pub handle: String,
    pub device: String,
    pub signature: String,
    /// Left for the vouchee through the community's sealed relay.
    #[serde(default)]
    pub posted: bool,
}

/// The decoded custody record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Book {
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub issued: Vec<Issued>,
    #[serde(default)]
    pub bonds: Vec<BondEntry>,
    #[serde(default)]
    pub nonces: Vec<NonceEntry>,
    #[serde(default)]
    pub endorsements: Vec<Endorsement>,
    /// A community this member is creating: the human input first, then every
    /// system step as it completes, so an interruption resumes where it stopped.
    #[serde(default)]
    pub creation: Option<super::creating::Record>,
    /// Creation id of a claimed seat in THIS community, until the admission is done.
    #[serde(default)]
    pub claimed: Option<String>,
    #[serde(default)]
    pub received: Vec<Received>,
}

impl Drop for Book {
    fn drop(&mut self) {
        for link in &mut self.issued {
            link.fragment.zeroize();
            link.key.zeroize();
        }
        for bond in &mut self.bonds {
            bond.bond.zeroize();
        }
        for nonce in &mut self.nonces {
            nonce.nonce.zeroize();
            nonce.fragment.zeroize();
        }
        if let Some(record) = &mut self.creation {
            record.wipe();
        }
    }
}

impl Book {
    pub(super) fn decode(record: Option<&[u8]>) -> Result<Self> {
        let Some(record) = record else {
            let mut book = Self::default();
            book.version = BOOK_VERSION;
            return Ok(book);
        };
        let book: Self = serde_json::from_slice(record).map_err(|_| ErrorCode::Unavailable)?;
        if book.version != BOOK_VERSION {
            return Err(ErrorCode::Unavailable);
        }
        Ok(book)
    }

    pub(super) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| ErrorCode::Unavailable)
    }

    fn issued(&self, id: &str) -> Option<&Issued> {
        self.issued.iter().find(|link| link.id == id)
    }

    fn issued_mut(&mut self, id: &str) -> Option<&mut Issued> {
        self.issued.iter_mut().find(|link| link.id == id)
    }

    /// Add a freshly generated link before the community hears of it.
    pub(super) fn add_issued(&mut self, link: Issued) -> Result<()> {
        if self.issued.len() >= MAXIMUM_LINKS || self.issued(&link.id).is_some() {
            return Err(ErrorCode::Capacity);
        }
        self.issued.push(link);
        Ok(())
    }

    /// Record a bond once. A second notice for the same person changes nothing:
    /// the first one fixes the bond.
    pub(super) fn add_bond(&mut self, entry: BondEntry) -> Result<bool> {
        if self.bonds.iter().any(|have| {
            have.sponsor == entry.sponsor && have.link == entry.link && have.member == entry.member
        }) {
            return Ok(false);
        }
        if self.bonds.len() >= MAXIMUM_BONDS {
            return Err(ErrorCode::Capacity);
        }
        self.bonds.push(entry);
        Ok(true)
    }

    /// The bond nonce for `link` (the part after `#`): the stored one, or a new
    /// one that the caller must save before it is used.
    pub(super) fn nonce_for(&mut self, link: &str) -> Result<[u8; NONCE_BYTES]> {
        let token = Token::parse(link.trim().trim_start_matches('#'))
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let id = token.id().as_str().to_owned();
        if let Some(have) = self.nonces.iter().find(|entry| entry.link == id) {
            return from_hex(&have.nonce)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(ErrorCode::Unavailable);
        }
        if self.nonces.len() >= MAXIMUM_BONDS {
            return Err(ErrorCode::Capacity);
        }
        let nonce: [u8; NONCE_BYTES] = cvch::link::entropy().map_err(|_| ErrorCode::Unavailable)?;
        self.nonces.push(NonceEntry {
            link: id,
            nonce: to_hex(&nonce),
            fragment: token.fragment().to_string(),
        });
        Ok(nonce)
    }

    /// The newcomer's device keeps the bond it derived at redemption and drops
    /// the nonce that produced it.
    pub(super) fn add_vouchee_bond(&mut self, link: &str, bond: &Bond) -> Result<()> {
        let token = Token::parse(link.trim().trim_start_matches('#'))
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let id = token.id().as_str().to_owned();
        self.add_bond(BondEntry {
            sponsor: false,
            link: id,
            member: String::new(),
            bond: to_hex(bond.as_bytes()),
            sponsor_id: to_hex(&token.sponsor()),
        })?;
        Ok(())
    }

    /// The bond this newcomer's device derived at redemption, with the sponsor's
    /// opaque member id from the link text: the account genesis binds both.
    pub(super) fn vouchee_bond(&self) -> Option<([u8; 32], [u8; 32])> {
        let entry = self
            .bonds
            .iter()
            .rev()
            .find(|bond| !bond.sponsor && !bond.sponsor_id.is_empty())?;
        Some((
            from_hex(&entry.sponsor_id)?.try_into().ok()?,
            from_hex(&entry.bond)?.try_into().ok()?,
        ))
    }

    /// The issuer's device reads the people the community reports for `link`
    /// and derives the bond of each from their sealed notice.
    fn absorb(&mut self, id: &str, entries: &[WireEntry]) -> Result<Vec<Opened>> {
        let (token, secret) = {
            let link = self.issued(id).ok_or(ErrorCode::Refused)?;
            (
                Token::parse(&link.fragment).map_err(|_| ErrorCode::Unavailable)?,
                from_hex(&link.key)
                    .and_then(|bytes| IssuerSecret::from_bytes(&bytes).ok())
                    .ok_or(ErrorCode::Unavailable)?,
            )
        };
        let link_id = LinkId::parse(id).map_err(|_| ErrorCode::Unavailable)?;
        let mut opened = Vec::new();
        for entry in entries {
            // A notice that does not open, or that names someone else than the
            // community reports, yields no bond. The person is still admitted.
            let notice = from_hex(&entry.notice)
                .and_then(|sealed| Notice::open(&sealed, &secret, &link_id).ok())
                .filter(|notice| notice.member == entry.member);
            if let Some(notice) = notice {
                opened.push(Opened {
                    member: entry.member.clone(),
                    token_bond: token.bond(&notice.member, &notice.nonce),
                });
            }
        }
        Ok(opened)
    }
}

/// A notice the issuer's device opened.
struct Opened {
    member: String,
    token_bond: Bond,
}

// Wire shapes of the community's answers.
#[derive(Deserialize)]
struct WireEntry {
    member: String,
    notice: String,
}
#[derive(Deserialize)]
struct WireCreated {
    expires_at: u64,
    signoff: bool,
}
#[derive(Deserialize)]
struct WireView {
    waiting: Vec<WireEntry>,
    admitted: Vec<WireEntry>,
    revoked: bool,
    expires_at: u64,
    uses: u32,
    signoff: bool,
}
#[derive(Deserialize)]
struct WireWaiting {
    waiting: Vec<WireEntry>,
}
#[derive(Deserialize)]
struct WireDecision {
    admitted: bool,
}
#[derive(Deserialize)]
struct WireReply {
    reply: Option<String>,
}
#[derive(Deserialize)]
struct WireRevoked {
    released: Vec<String>,
}

/// Body of `foyer.voucher_link_create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkCreate {
    /// Admissions the link allows (1 to 1000).
    pub uses: u32,
    /// Lifetime in seconds.
    pub valid_for: u64,
    /// Only admins and roots may change the fixed default (off for a single use,
    /// on for several).
    #[serde(default)]
    pub signoff: Option<bool>,
    /// Sign "vouched for by <handle>" for admissions through this link.
    /// Defaults to visible.
    #[serde(default)]
    pub visible: Option<bool>,
}

/// One link as the issuer's device sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkInfo {
    pub id: String,
    /// The link text: the part after `#` of the invitation URL.
    pub link: String,
    pub uses: u32,
    pub admitted: u32,
    pub waiting: u32,
    pub expires_at: u64,
    pub signoff: bool,
    pub visible: bool,
    /// `open`, `full`, `revoked`, `expired`, `pending` or `unknown`.
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Links {
    pub links: Vec<LinkInfo>,
}

/// Body naming one of this device's links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkRef {
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkRevoked {
    pub link: LinkInfo,
    /// Applicants released from the lobby; completed admissions stay.
    pub released: u32,
}

/// One applicant waiting for the issuer's confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Applicant {
    /// `<link id>:<member>`, the handle to pass to the decision.
    pub id: String,
    pub link: String,
    pub member: String,
    /// The handle the applicant chose, if they told the issuer.
    pub handle: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Applicants {
    pub requests: Vec<Applicant>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Decide {
    pub id: String,
    pub confirm: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Decided {
    pub admitted: bool,
    /// The applicants still waiting after this decision.
    pub requests: Vec<Applicant>,
}

fn now() -> Result<u64> {
    ckmg::Clock::now(&mut super::custody::SystemClock).map_err(|_| ErrorCode::Clock)
}

fn applicant_id(link: &str, member: &str) -> String {
    format!("{link}:{member}")
}

fn split_applicant(id: &str) -> Result<(&str, &str)> {
    let (link, member) = id.split_once(':').ok_or(ErrorCode::InvalidRequest)?;
    LinkId::parse(link).map_err(|_| ErrorCode::InvalidRequest)?;
    if member.is_empty() {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok((link, member))
}

fn state(link: &Issued, taken: u32, now: u64) -> &'static str {
    if link.pending {
        "pending"
    } else if link.revoked {
        "revoked"
    } else if now >= link.expires_at {
        "expired"
    } else if taken >= link.uses {
        "full"
    } else {
        "open"
    }
}

fn info(link: &Issued, admitted: u32, waiting: u32, now: u64) -> LinkInfo {
    LinkInfo {
        id: link.id.clone(),
        link: link.fragment.clone(),
        uses: link.uses,
        admitted,
        waiting,
        expires_at: link.expires_at,
        signoff: link.signoff,
        visible: link.visible,
        state: state(link, admitted.saturating_add(waiting), now).into(),
    }
}

/// Which open links must be revoked because the allowance is used up.
fn exhausted(book: &Book, remaining: Option<u32>, now: u64) -> Vec<String> {
    match remaining {
        Some(0) => book
            .issued
            .iter()
            .filter(|link| !link.pending && !link.revoked && now < link.expires_at)
            .map(|link| link.id.clone())
            .collect(),
        _ => Vec::new(),
    }
}

/// The issuer's open custody record, read together with its raw bytes so the
/// next write is a compare-and-swap against exactly what was read.
pub(super) struct Loaded {
    pub(super) raw: Option<Zeroizing<Vec<u8>>>,
    pub(super) book: Book,
}

pub(super) async fn load(door: &mut Door, origin: &str) -> Result<Loaded> {
    let vault = door.vaults.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
    let raw = vault.voucher_custody().await?;
    let book = Book::decode(raw.as_deref().map(Vec::as_slice))?;
    Ok(Loaded { raw, book })
}

impl Loaded {
    /// Write the book if it changed. A lost race is `Reconcile`; nothing is
    /// overwritten.
    pub(super) async fn save(&mut self, door: &mut Door, origin: &str) -> Result<()> {
        let encoded = self.book.encode()?;
        if self.raw.as_deref().map(Vec::as_slice) == Some(encoded.as_slice()) {
            return Ok(());
        }
        let vault = door.vaults.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
        vault
            .replace_voucher_custody(self.raw.as_deref().map(Vec::as_slice), &encoded)
            .await?;
        self.raw = Some(encoded);
        Ok(())
    }
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

fn manage_body(book: &Book, id: &str) -> Result<Value> {
    let link = book.issued(id).ok_or(ErrorCode::Refused)?;
    let token = Token::parse(&link.fragment).map_err(|_| ErrorCode::Unavailable)?;
    let manage = token.manage();
    Ok(serde_json::json!({ "id": id, "secret": manage.secret_hex().as_str() }))
}

/// Sign "vouched for by <handle>" for an admitted person, when the link is
/// visible. Only this step lets the community see who vouched for whom, and only
/// because the issuer's device chose to.
async fn endorse(
    door: &mut Door,
    origin: &str,
    book: &mut Book,
    link: &str,
    vouchee: &str,
) -> Result<()> {
    if !book.issued(link).is_some_and(|issued| issued.visible)
        || book
            .endorsements
            .iter()
            .any(|have| have.link == link && have.vouchee == vouchee)
    {
        return Ok(());
    }
    let lobby: Value = owner(door, origin, "lobby", serde_json::json!({})).await?;
    let handle = lobby
        .get("handle")
        .and_then(Value::as_str)
        .ok_or(ErrorCode::Refused)?
        .to_owned();
    let message = cvch::link::endorsement_bytes(&door.config.community, vouchee, &handle);
    let started = now()?;
    let vault = door.vaults.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
    let (signature, device) = vault
        .sign_endorsement(
            &message,
            origin,
            started,
            started.saturating_add(SIGN_SECONDS),
        )
        .await?;
    book.endorsements.push(Endorsement {
        link: link.into(),
        vouchee: vouchee.into(),
        handle,
        device: to_hex(&device),
        signature: to_hex(&signature),
        posted: false,
    });
    Ok(())
}

/// Leave every signed endorsement of `id` that is not yet with the community in
/// the sealed relay, sealed with the bond so the community cannot read it.
async fn post_endorsements(door: &mut Door, origin: &str, book: &mut Book, id: &str) -> Result<()> {
    let link_id = LinkId::parse(id).map_err(|_| ErrorCode::Unavailable)?;
    let waiting: Vec<(usize, Vec<u8>, String)> = book
        .endorsements
        .iter()
        .enumerate()
        .filter(|(_, have)| have.link == id && !have.posted)
        .filter_map(|(at, have)| {
            let bond = book
                .bonds
                .iter()
                .find(|bond| bond.sponsor && bond.link == id && bond.member == have.vouchee)?;
            let bond = Bond::from_bytes(from_hex(&bond.bond)?.try_into().ok()?);
            let device: [u8; 32] = from_hex(&have.device)?.try_into().ok()?;
            let signature: [u8; 64] = from_hex(&have.signature)?.try_into().ok()?;
            let plain = cvch::link::Endorsement::new(&have.handle, device, signature)
                .and_then(|endorsement| endorsement.to_bytes())
                .ok()?;
            let sealed = bond.seal_reply(&link_id, &plain).ok()?;
            Some((at, sealed, have.vouchee.clone()))
        })
        .collect();
    for (at, sealed, vouchee) in waiting {
        let mut body = manage_body(book, id)?;
        body["member"] = Value::String(vouchee);
        body["reply"] = Value::String(to_hex(&sealed));
        let _: Value = owner(door, origin, "voucher_reply_post", body).await?;
        book.endorsements[at].posted = true;
    }
    Ok(())
}

/// Establish the bond (and the endorsement) for everyone `link` admitted.
async fn settle_admitted(
    door: &mut Door,
    origin: &str,
    book: &mut Book,
    id: &str,
    admitted: &[WireEntry],
) -> Result<()> {
    for person in book.absorb(id, admitted)? {
        book.add_bond(BondEntry {
            sponsor: true,
            link: id.into(),
            member: person.member.clone(),
            bond: to_hex(person.token_bond.as_bytes()),
            sponsor_id: String::new(),
        })?;
        // A failed signature leaves the bond in place; the endorsement is
        // retried on every sync until it exists.
        match endorse(door, origin, book, id, &person.member).await {
            Ok(()) | Err(ErrorCode::Unavailable | ErrorCode::Refused) => {}
            Err(error) => return Err(error),
        }
    }
    // Retried on every sync until the community holds the sealed reply.
    match post_endorsements(door, origin, book, id).await {
        Ok(()) | Err(ErrorCode::Unavailable | ErrorCode::Refused) => Ok(()),
        Err(error) => Err(error),
    }
}

fn counts(view: &WireView) -> (u32, u32) {
    (
        u32::try_from(view.admitted.len()).unwrap_or(u32::MAX),
        u32::try_from(view.waiting.len()).unwrap_or(u32::MAX),
    )
}

/// Bring every link up to date with the community: confirm pending ones, read
/// the people on each, establish bonds, and stop links whose allowance is used
/// up. Returns the infos in creation order.
async fn sync(door: &mut Door, origin: &str, loaded: &mut Loaded) -> Result<Vec<LinkInfo>> {
    let started = now()?;
    let ids: Vec<String> = loaded
        .book
        .issued
        .iter()
        .map(|link| link.id.clone())
        .collect();
    let mut infos = Vec::new();
    let mut failure = None;
    for id in ids {
        let (done, pending) = {
            let link = loaded.book.issued(&id).ok_or(ErrorCode::Unavailable)?;
            (link.done, link.pending)
        };
        if done {
            let link = loaded.book.issued(&id).ok_or(ErrorCode::Unavailable)?;
            let admitted = u32::try_from(
                loaded
                    .book
                    .bonds
                    .iter()
                    .filter(|bond| bond.sponsor && bond.link == id)
                    .count(),
            )
            .unwrap_or(u32::MAX);
            infos.push(info(link, admitted, 0, started));
            continue;
        }
        let body = manage_body(&loaded.book, &id)?;
        let view: Result<WireView> = owner(door, origin, "voucher_link_view", body).await;
        let view = match view {
            Ok(view) => view,
            // The community does not know the link: a pending one never arrived.
            Err(ErrorCode::Refused) if pending => {
                loaded.book.issued.retain(|link| link.id != id);
                continue;
            }
            Err(error) => {
                failure.get_or_insert(error);
                let link = loaded.book.issued(&id).ok_or(ErrorCode::Unavailable)?;
                infos.push(info(link, 0, 0, started));
                continue;
            }
        };
        settle_admitted(door, origin, &mut loaded.book, &id, &view.admitted).await?;
        let link = loaded.book.issued_mut(&id).ok_or(ErrorCode::Unavailable)?;
        link.pending = false;
        link.revoked = view.revoked;
        link.expires_at = view.expires_at;
        link.uses = view.uses;
        link.signoff = view.signoff;
        link.done = (view.revoked || started >= view.expires_at) && view.waiting.is_empty();
        let (admitted, waiting) = counts(&view);
        let link = loaded.book.issued(&id).ok_or(ErrorCode::Unavailable)?;
        infos.push(info(link, admitted, waiting, started));
    }
    // The allowance is used up: stop every open link.
    let remaining = door.voucher_allowance;
    for id in exhausted(&loaded.book, remaining, started) {
        let body = manage_body(&loaded.book, &id)?;
        let released: Result<WireRevoked> = owner(door, origin, "voucher_link_revoke", body).await;
        match released {
            Ok(_) => {
                if let Some(link) = loaded.book.issued_mut(&id) {
                    link.revoked = true;
                }
                if let Some(entry) = infos.iter_mut().find(|entry| entry.id == id) {
                    entry.state = "revoked".into();
                    entry.waiting = 0;
                }
            }
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    loaded.save(door, origin).await?;
    match failure {
        None => Ok(infos),
        Some(error) => Err(error),
    }
}

/// What a newcomer's device knows about who vouched for them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VouchedBy {
    /// The sponsor's handle, once an endorsement arrived and its signature holds
    /// for this community and this member.
    pub handle: Option<String>,
    /// The sponsor's device key (hex) that signed. Showing the handle needs this
    /// key to belong to the sponsor's charter-verified lineage.
    pub device: Option<String>,
    /// The signature (hex) over the statement, for the profile to carry.
    pub signature: Option<String>,
}

/// The newcomer's device reads the sealed reply the sponsor left, opens it with
/// the bond, checks the signature for this community and member, and keeps it.
pub(super) async fn vouched_by(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(VouchedBy, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let mut loaded = load(door, &origin).await?;
    let lobby: Value = owner(door, &origin, "lobby", serde_json::json!({})).await?;
    let member = lobby
        .get("member_id")
        .and_then(Value::as_str)
        .ok_or(ErrorCode::Unavailable)?
        .to_owned();
    let community = door.config.community.clone();
    let candidates: Vec<(String, String)> = loaded
        .book
        .bonds
        .iter()
        .filter(|bond| !bond.sponsor)
        .filter(|bond| {
            !loaded
                .book
                .received
                .iter()
                .any(|have| have.link == bond.link)
        })
        .filter_map(|bond| {
            let fragment = loaded
                .book
                .nonces
                .iter()
                .find(|nonce| nonce.link == bond.link && !nonce.fragment.is_empty())?
                .fragment
                .clone();
            Some((bond.link.clone(), fragment))
        })
        .collect();
    for (link, fragment) in candidates {
        let token = Token::parse(&fragment).map_err(|_| ErrorCode::Unavailable)?;
        let presentation = token.presentation();
        let body = serde_json::json!({
            "id": link,
            "secret": presentation.secret_hex().as_str(),
        });
        let answer: WireReply = owner(door, &origin, "voucher_reply_get", body).await?;
        let Some(sealed) = answer.reply.as_deref().and_then(from_hex) else {
            continue;
        };
        let bond = loaded
            .book
            .bonds
            .iter()
            .find(|bond| !bond.sponsor && bond.link == link)
            .and_then(|bond| from_hex(&bond.bond))
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(Bond::from_bytes)
            .ok_or(ErrorCode::Unavailable)?;
        let link_id = LinkId::parse(&link).map_err(|_| ErrorCode::Unavailable)?;
        // Anything that does not open, parse or verify is ignored: a sponsor
        // that signs wrongly is no sponsor to show.
        let verified = bond
            .open_reply(&link_id, &sealed)
            .and_then(|plain| cvch::link::Endorsement::from_bytes(&plain))
            .and_then(|endorsement| {
                endorsement.verify(&community, &member)?;
                Ok(endorsement)
            });
        if let Ok(endorsement) = verified {
            loaded.book.received.push(Received {
                link,
                handle: endorsement.handle,
                device: to_hex(&endorsement.device),
                signature: to_hex(&endorsement.signature),
            });
        }
    }
    loaded.save(door, &origin).await?;
    let shown = loaded.book.received.first();
    Ok((
        VouchedBy {
            handle: shown.map(|have| have.handle.clone()),
            device: shown.map(|have| have.device.clone()),
            signature: shown.map(|have| have.signature.clone()),
        },
        vec![],
    ))
}

/// Issue a link: generate it on this device, keep it in custody, then register
/// only its hashes with the community.
pub(super) async fn link_create(
    door: &mut Door,
    key: &[u8; 32],
    request: LinkCreate,
) -> Result<(LinkInfo, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    if let Some(remaining) = door.voucher_allowance {
        if remaining == 0 || request.uses > remaining {
            return Err(ErrorCode::Refused);
        }
    }
    let started = now()?;
    // The link text carries the issuer's opaque community member id so the
    // newcomer's account can bind its sponsor at admission; the community never
    // sees the text.
    let lobby: Value = owner(door, &origin, "lobby", serde_json::json!({})).await?;
    let sponsor: [u8; 32] = lobby
        .get("member_id")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ErrorCode::Unavailable)?;
    let (token, secret) = Token::generate(sponsor).map_err(|_| ErrorCode::Unavailable)?;
    let registration = token.registration();
    let id = registration.id().as_str().to_owned();
    let mut loaded = load(door, &origin).await?;
    loaded.book.add_issued(Issued {
        id: id.clone(),
        fragment: token.fragment().to_string(),
        key: to_hex(secret.as_bytes()),
        uses: request.uses,
        signoff: request
            .signoff
            .unwrap_or(cvch::link::default_signoff(request.uses)),
        visible: request.visible.unwrap_or(true),
        created_at: started,
        expires_at: started.saturating_add(request.valid_for),
        pending: true,
        revoked: false,
        done: false,
    })?;
    // Custody first: a link the community knows must never be lost to a crash.
    loaded.save(door, &origin).await?;
    let body = serde_json::json!({
        "id": id,
        "verifier": registration.verifier(),
        "manage_verifier": registration.manage_verifier(),
        "uses": request.uses,
        "valid_for": request.valid_for,
        "signoff": request.signoff,
    });
    let created: Result<WireCreated> = owner(door, &origin, "voucher_link_create", body).await;
    match created {
        Ok(created) => {
            let link = loaded.book.issued_mut(&id).ok_or(ErrorCode::Unavailable)?;
            link.pending = false;
            link.expires_at = created.expires_at;
            link.signoff = created.signoff;
            loaded.save(door, &origin).await?;
        }
        // A verdict from the community: the link does not exist there.
        Err(error @ (ErrorCode::Refused | ErrorCode::InvalidRequest | ErrorCode::Capacity)) => {
            loaded.book.issued.retain(|link| link.id != id);
            loaded.save(door, &origin).await?;
            return Err(error);
        }
        // Lost answer: keep the pending record; the next sync decides.
        Err(error) => return Err(error),
    }
    let link = loaded.book.issued(&id).ok_or(ErrorCode::Unavailable)?;
    Ok((info(link, 0, 0, started), vec![]))
}

pub(super) async fn links(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Links, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let mut loaded = load(door, &origin).await?;
    let links = sync(door, &origin, &mut loaded).await?;
    Ok((Links { links }, vec![]))
}

pub(super) async fn link_revoke(
    door: &mut Door,
    key: &[u8; 32],
    request: LinkRef,
) -> Result<(LinkRevoked, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let mut loaded = load(door, &origin).await?;
    // The community first: a link that is revoked here but live there is worse
    // than the reverse.
    let body = manage_body(&loaded.book, &request.id)?;
    let released: WireRevoked = owner(door, &origin, "voucher_link_revoke", body).await?;
    let started = now()?;
    let view_body = manage_body(&loaded.book, &request.id)?;
    let view: WireView = owner(door, &origin, "voucher_link_view", view_body).await?;
    settle_admitted(door, &origin, &mut loaded.book, &request.id, &view.admitted).await?;
    let link = loaded
        .book
        .issued_mut(&request.id)
        .ok_or(ErrorCode::Refused)?;
    link.pending = false;
    link.revoked = true;
    link.done = true;
    let (admitted, _) = counts(&view);
    let link = loaded.book.issued(&request.id).ok_or(ErrorCode::Refused)?;
    let shown = info(link, admitted, 0, started);
    loaded.save(door, &origin).await?;
    Ok((
        LinkRevoked {
            link: shown,
            released: u32::try_from(released.released.len()).unwrap_or(u32::MAX),
        },
        vec![],
    ))
}

async fn waiting_all(door: &mut Door, origin: &str, loaded: &Loaded) -> Result<Vec<Applicant>> {
    let now = now()?;
    let candidates: Vec<String> = loaded
        .book
        .issued
        .iter()
        .filter(|link| link.signoff && !link.pending && !link.revoked && now < link.expires_at)
        .map(|link| link.id.clone())
        .collect();
    let mut out = Vec::new();
    for id in candidates {
        let body = manage_body(&loaded.book, &id)?;
        let waiting: WireWaiting = owner(door, origin, "voucher_signoff_list", body).await?;
        let issued = loaded.book.issued(&id).ok_or(ErrorCode::Unavailable)?;
        let secret = from_hex(&issued.key)
            .and_then(|bytes| IssuerSecret::from_bytes(&bytes).ok())
            .ok_or(ErrorCode::Unavailable)?;
        let link_id = LinkId::parse(&id).map_err(|_| ErrorCode::Unavailable)?;
        for entry in waiting.waiting {
            let handle = from_hex(&entry.notice)
                .and_then(|sealed| Notice::open(&sealed, &secret, &link_id).ok())
                .filter(|notice| notice.member == entry.member)
                .and_then(|notice| notice.handle);
            out.push(Applicant {
                id: applicant_id(&id, &entry.member),
                link: id.clone(),
                member: entry.member,
                handle,
            });
        }
    }
    Ok(out)
}

pub(super) async fn signoff_list(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Applicants, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let loaded = load(door, &origin).await?;
    let requests = waiting_all(door, &origin, &loaded).await?;
    Ok((Applicants { requests }, vec![]))
}

pub(super) async fn signoff_decide(
    door: &mut Door,
    key: &[u8; 32],
    request: Decide,
) -> Result<(Decided, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let (link, member) = split_applicant(&request.id)?;
    let (link, member) = (link.to_owned(), member.to_owned());
    let mut loaded = load(door, &origin).await?;
    // The notice comes from the waiting list: read it before the decision moves
    // the person out of it.
    let body = manage_body(&loaded.book, &link)?;
    let waiting: WireWaiting = owner(door, &origin, "voucher_signoff_list", body).await?;
    let entry = waiting
        .waiting
        .into_iter()
        .find(|entry| entry.member == member)
        .ok_or(ErrorCode::Refused)?;
    let manage = manage_body(&loaded.book, &link)?;
    let body = serde_json::json!({
        "id": link,
        "secret": manage["secret"],
        "member": member,
        "confirm": request.confirm,
    });
    let decision: WireDecision = owner(door, &origin, "voucher_signoff_decide", body).await?;
    if decision.admitted {
        settle_admitted(door, &origin, &mut loaded.book, &link, &[entry]).await?;
        loaded.save(door, &origin).await?;
    }
    let requests = waiting_all(door, &origin, &loaded).await?;
    Ok((
        Decided {
            admitted: decision.admitted,
            requests,
        },
        vec![],
    ))
}

#[cfg(test)]
#[path = "../../tests/support/vouching.rs"]
mod tests;
