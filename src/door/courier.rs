//! The courier: the one task per member origin that carries bytes between this
//! Door and the Mesh, so that no client ever has to.
//!
//! Outbound it drains the wave outbox, chat wires, receipts and the group texts
//! (invitations, answers, Welcomes travel in the existing 1:1 conversation) to
//! `Mesh::app_message`. Inbound it parses a VERSIONED [`Frame`] and hands the
//! payload to the same handlers the diagnostic actions use. It also runs the
//! timed duties of a bound member: forum presence (attend, heartbeat), the trust
//! feed refresh, proof-job recovery at start and room serving.
//!
//! Delivery is at-least-once on the wire and exactly-once in effect:
//! - waves stay in the durable wave outbox until the recipient's `wave_ack`
//!   frame (sent only after its owner accepted or finally refused the message);
//! - chat wires stay `Pending` in Delivery until the signed receipt arrives, and
//!   a periodic scan re-sends them, also after a restart;
//! - every receiver is idempotent (wave sequence admission, Delivery duplicates).
//!
//! Peers are found from their reachability descriptor: first contact through a
//! [`Directory`] (the forum entry), afterwards every frame carries the sender's
//! current addresses and the book keeps the latest. A descriptor is routing
//! data only; it grants no authority and lineage stays authoritative for device
//! keys. Nothing in a frame is secret beyond what the Mesh channel protects.
use super::{
    board::{GroupAnswer, GroupPropose, GroupWelcome, RoomRef},
    inbox_conversation::{ConversationRetry, ConversationSend, Retried, Sent},
    inbox_waves::{engine::kind_of, Envelope},
    Door, ErrorCode, Event, Grant, Result,
};
use cmsh::{Address, Scheme};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
};

/// Wire version of the courier frame. A frame of any other version is dropped.
pub const FRAME_VERSION: u8 = 1;
const MAX_ADDRESSES: usize = 8;
const MAX_PEERS: usize = 4096;
const MAX_QUEUE: usize = 1024;
const MAX_SCAN_MESSAGES: usize = 64;

/// One frame between two devices. `reach` is the sender's current reachability
/// descriptor (an address update); the body names what the frame asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub version: u8,
    #[serde(default)]
    pub reach: Vec<u8>,
    pub body: Body,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Body {
    /// A wave message; the recipient answers with `WaveAck`.
    Wave { envelope: Envelope },
    /// The recipient's owner took the wave message of this kind.
    WaveAck { nonce: [u8; 32], kind: String },
    /// A Delivery wire of a conversation message; answered by `Receipt`.
    Chat { conversation: [u8; 32], wire: Vec<u8> },
    /// The signed receipt for a chat wire.
    Receipt { conversation: [u8; 32], wire: Vec<u8> },
}

/// Routing descriptor of this Door: every listener address, JSON, bounded.
pub fn encode_reachability(addresses: &[Address]) -> Vec<u8> {
    let items: Vec<Value> = addresses
        .iter()
        .take(MAX_ADDRESSES)
        .map(|a| json!({"scheme": a.scheme().as_str(), "address": BASE64URL_NOPAD.encode(a.bytes())}))
        .collect();
    serde_json::to_vec(&items).unwrap_or_default()
}

/// Parse a descriptor; anything malformed is dropped, never an error.
pub fn decode_reachability(bytes: &[u8]) -> Vec<Address> {
    #[derive(Deserialize)]
    struct Item {
        scheme: String,
        address: String,
    }
    let Ok(items) = serde_json::from_slice::<Vec<Item>>(bytes) else {
        return vec![];
    };
    items
        .into_iter()
        .take(MAX_ADDRESSES)
        .filter_map(|item| {
            let scheme = Scheme::new(&item.scheme).ok()?;
            let bytes = BASE64URL_NOPAD.decode(item.address.as_bytes()).ok()?;
            Address::new(scheme, bytes).ok()
        })
        .collect()
}

/// First contact: where to reach a member never heard from. The embedder
/// implements it from the forum entry (the profile's `reachability`).
pub trait Directory {
    fn reachability(&self, peer: &str) -> Option<Vec<u8>>;
}

/// Latest known addresses per peer. Memory only: after a restart the Directory
/// answers first contact and the next frame from the peer refreshes it.
#[derive(Default)]
pub(super) struct Book(BTreeMap<String, Vec<Address>>);
impl Book {
    pub(super) fn learn(&mut self, peer: &str, reach: &[u8]) {
        let addresses = decode_reachability(reach);
        if addresses.is_empty() || (self.0.len() >= MAX_PEERS && !self.0.contains_key(peer)) {
            return;
        }
        self.0.insert(peer.to_owned(), addresses);
    }
    pub(super) fn get(&self, peer: &str) -> Option<&Vec<Address>> {
        self.0.get(peer)
    }
}

/// One item the courier still has to deliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Outgoing {
    pub peer: String,
    pub body: Body,
}

/// Everything about one bound Mesh that the courier shares with the Door:
/// the Mesh and its listener, the address book, the send queue and the stop
/// signal. Held by `BoundMesh` and cloned by the running courier.
pub(super) struct Shared {
    pub mesh: cmsh::Mesh,
    pub listener: cmsh::Listening,
    pub own: RefCell<Vec<Address>>,
    pub book: RefCell<Book>,
    pub queue: RefCell<VecDeque<Outgoing>>,
    pub directory: RefCell<Option<Box<dyn Directory>>>,
    pub closed: Cell<bool>,
    #[cfg(not(target_arch = "wasm32"))]
    pub stop: tokio::sync::Notify,
}
impl Shared {
    pub(super) fn new(mesh: cmsh::Mesh, listener: cmsh::Listening) -> Self {
        Self {
            own: RefCell::new(listener.addresses().to_vec()),
            mesh,
            listener,
            book: RefCell::default(),
            queue: RefCell::default(),
            directory: RefCell::new(None),
            closed: Cell::new(false),
            #[cfg(not(target_arch = "wasm32"))]
            stop: tokio::sync::Notify::new(),
        }
    }
    pub(super) fn close(&self) {
        self.closed.set(true);
        #[cfg(not(target_arch = "wasm32"))]
        self.stop.notify_one();
    }
    pub(super) fn push(&self, peer: &str, body: Body) {
        let mut queue = self.queue.borrow_mut();
        if queue.len() < MAX_QUEUE {
            queue.push_back(Outgoing {
                peer: peer.to_owned(),
                body,
            });
        }
        // A full queue loses nothing durable: waves stay in the wave outbox and
        // chat wires stay Pending in Delivery, both found again by the next scan.
    }
    pub(super) fn reachability(&self) -> Vec<u8> {
        encode_reachability(&self.own.borrow())
    }
    /// Where to send to `peer`: the latest book entry, else the Directory.
    fn route(&self, peer: &str) -> Vec<Address> {
        if let Some(found) = self.book.borrow().get(peer) {
            return found.clone();
        }
        let first = self
            .directory
            .borrow()
            .as_ref()
            .and_then(|directory| directory.reachability(peer));
        if let Some(descriptor) = first {
            self.book.borrow_mut().learn(peer, &descriptor);
        }
        self.book.borrow().get(peer).cloned().unwrap_or_default()
    }
}

impl Door {
    /// Trusted embedding control: how to find a member the Door has never heard
    /// from (the forum entry). Absent from every callable projection.
    pub fn bind_directory(&mut self, origin: &str, directory: Box<dyn Directory>) -> Result<()> {
        let mesh = self.meshes.get(origin).ok_or(ErrorCode::Unavailable)?;
        *mesh.shared.directory.borrow_mut() = Some(directory);
        Ok(())
    }

    /// The reachability descriptor for the profile: this Door's own listener
    /// addresses, never a caller-supplied value. Empty while no Mesh is bound.
    pub fn reachability(&self, origin: &str) -> Vec<u8> {
        self.meshes
            .get(origin)
            .map(|mesh| mesh.shared.reachability())
            .unwrap_or_default()
    }

    pub(super) fn courier_shared(&self, origin: &str) -> Option<Rc<Shared>> {
        self.meshes.get(origin).map(|mesh| mesh.shared.clone())
    }
}

// ---- internal calls ------------------------------------------------------------

/// The actions the courier uses; the lease grants nothing else.
const ACTIONS: &[&str] = &[
    "inbox.waves",
    "inbox.wave_outbox",
    "inbox.wave_delivered",
    "inbox.wave_receive",
    "inbox.wave_jobs_recover",
    "inbox.snapshot",
    "inbox.delivery_status",
    "inbox.send",
    "inbox.receive",
    "inbox.ack",
    "inbox.retry",
    "board.attend",
    "board.heartbeat",
    "board.group_message",
    "board.room_serve",
    "foyer.refresh",
];

/// A short-lived internal grant of this origin. It is never handed out; the
/// handlers read the origin and expiry from it exactly as for a paired client.
pub(super) struct Lease {
    key: [u8; 32],
}
impl Lease {
    pub(super) fn open(door: &mut Door, origin: &str, now: u64, seconds: u64) -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| ErrorCode::Unavailable)?;
        door.grants.insert(
            key,
            Grant {
                origin: origin.to_owned(),
                actions: ACTIONS.iter().map(|a| (*a).to_owned()).collect(),
                expires: now.saturating_add(seconds),
            },
        );
        Ok(Self { key })
    }
    pub(super) fn close(self, door: &mut Door) {
        door.grants.remove(&self.key);
    }
    pub(super) async fn call(&self, door: &mut Door, action: &str, body: Value) -> Result<Value> {
        debug_assert!(ACTIONS.contains(&action));
        let action = super::registry::action(action).ok_or(ErrorCode::UnsupportedAction)?;
        let (value, _) = (action.handler)(door, &self.key, &body.to_string()).await?;
        Ok(value)
    }
}

fn typed<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| ErrorCode::Unavailable)
}

/// (peer, conversation) of every wave that has opened a conversation.
async fn conversations(lease: &Lease, door: &mut Door) -> Result<Vec<(String, [u8; 32])>> {
    let list: super::inbox_waves::WaveList = typed(lease.call(door, "inbox.waves", json!({})).await?)?;
    Ok(list
        .waves
        .into_iter()
        .filter_map(|w| w.conversation.map(|c| (w.peer, c)))
        .collect())
}

// ---- inbound -------------------------------------------------------------------

/// Counters of one courier, for diagnostics and tests; no content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub received: u64,
    pub dropped: u64,
    pub sent: u64,
    pub failed: u64,
    pub heartbeats: u64,
    pub refreshes: u64,
}

/// Handle one received payload for `origin`. Returns without error for anything
/// malformed or refused: a receiver never answers an unauthenticated frame with
/// detail. Acks are queued only after the owner took (or finally refused) it.
pub(super) async fn receive(
    door: &mut Door,
    origin: &str,
    shared: &Shared,
    payload: &[u8],
    now: u64,
    report: &mut Report,
) {
    let frame = match serde_json::from_slice::<Frame>(payload) {
        Ok(frame) if frame.version == FRAME_VERSION => frame,
        _ => {
            report.dropped += 1;
            return;
        }
    };
    report.received += 1;
    let Ok(lease) = Lease::open(door, origin, now, 120) else {
        report.dropped += 1;
        return;
    };
    let reach = frame.reach;
    match frame.body {
        Body::Wave { envelope } => {
            let peer = envelope.sender.clone();
            let (nonce, kind) = (*envelope.message.nonce(), kind_of(&envelope.message));
            let result = lease
                .call(
                    door,
                    "inbox.wave_receive",
                    json!({"peer": peer, "envelope": envelope}),
                )
                .await;
            match result {
                Ok(_) => {
                    shared.book.borrow_mut().learn(&peer, &reach);
                    shared.push(&peer, Body::WaveAck { nonce, kind });
                }
                // Final refusal (a repeat, a blocked peer, a foreign sender): the
                // sender must stop; it would be refused again.
                Err(ErrorCode::Refused) => {
                    shared.push(&peer, Body::WaveAck { nonce, kind });
                }
                Err(_) => report.dropped += 1,
            }
        }
        Body::WaveAck { nonce, kind } => {
            let _ = lease
                .call(
                    door,
                    "inbox.wave_delivered",
                    json!({"nonce": nonce, "kind": kind}),
                )
                .await;
        }
        Body::Chat { conversation, wire } => {
            let peer = conversations(&lease, door)
                .await
                .ok()
                .and_then(|all| all.into_iter().find(|(_, c)| *c == conversation))
                .map(|(peer, _)| peer);
            if let Some(peer) = peer {
                let received = lease
                    .call(
                        door,
                        "inbox.receive",
                        json!({"peer": peer, "conversation": conversation, "wire": wire}),
                    )
                    .await;
                if let Ok(value) = received {
                    shared.book.borrow_mut().learn(&peer, &reach);
                    if let Some(receipt) = value.get("receipt").and_then(|r| {
                        serde_json::from_value::<Vec<u8>>(r.clone()).ok()
                    }) {
                        shared.push(
                            &peer,
                            Body::Receipt {
                                conversation,
                                wire: receipt,
                            },
                        );
                    }
                    if let Some(message) = value.get("message").filter(|m| !m.is_null()) {
                        let from = message.get("sender").and_then(Value::as_str);
                        let text = message
                            .get("bytes")
                            .and_then(|b| serde_json::from_value::<Vec<u8>>(b.clone()).ok())
                            .and_then(|b| String::from_utf8(b).ok());
                        if let (Some(from), Some(text)) = (from, text) {
                            // Not every text is a group message; a refusal is normal.
                            let _ = group_inbound(door, &lease, shared, from, &text).await;
                        }
                    }
                }
            }
        }
        Body::Receipt { conversation, wire } => {
            let peer = conversations(&lease, door)
                .await
                .ok()
                .and_then(|all| all.into_iter().find(|(_, c)| *c == conversation))
                .map(|(peer, _)| peer);
            if let Some(peer) = peer {
                let acked = lease
                    .call(
                        door,
                        "inbox.ack",
                        json!({"peer": peer, "conversation": conversation, "wire": wire}),
                    )
                    .await;
                if acked.is_ok() {
                    shared.book.borrow_mut().learn(&peer, &reach);
                }
            }
        }
    }
    lease.close(door);
}

/// A text received in the 1:1 conversation with `from`: feed the group desk and
/// carry on the Welcomes a committed proposal now owes to the other members.
async fn group_inbound(
    door: &mut Door,
    lease: &Lease,
    shared: &Shared,
    from: &str,
    text: &str,
) -> Result<Value> {
    let inbound = lease
        .call(
            door,
            "board.group_message",
            json!({"from": from, "text": text}),
        )
        .await?;
    queue_texts(door, lease, shared, inbound.get("welcomes")).await;
    Ok(inbound)
}

/// Send each `{member, text}` in that member's 1:1 conversation.
async fn queue_texts(door: &mut Door, lease: &Lease, shared: &Shared, invites: Option<&Value>) {
    let Some(items) = invites.and_then(Value::as_array) else {
        return;
    };
    for item in items {
        if let (Some(member), Some(text)) = (
            item.get("member").and_then(Value::as_str),
            item.get("text").and_then(Value::as_str),
        ) {
            let _ = send_text(door, lease, shared, member, text).await;
        }
    }
}

/// Put `text` into the existing 1:1 conversation with `peer` (durable in
/// Delivery as soon as this returns) and queue its wire for the courier.
async fn send_text(
    door: &mut Door,
    lease: &Lease,
    shared: &Shared,
    peer: &str,
    text: &str,
) -> Result<()> {
    let conversation = conversations(lease, door)
        .await?
        .into_iter()
        .find(|(p, _)| p == peer)
        .map(|(_, c)| c)
        .ok_or(ErrorCode::Unavailable)?;
    let (sent, _) = super::inbox_conversation::send(
        door,
        &lease.key,
        ConversationSend {
            peer: peer.to_owned(),
            conversation,
            text: text.to_owned(),
        },
    )
    .await?;
    shared.push(
        peer,
        Body::Chat {
            conversation,
            wire: sent.wire,
        },
    );
    Ok(())
}

// ---- action wrappers: the Door itself hands what it produced to the courier ------

fn origin_of(door: &Door, key: &[u8; 32]) -> Result<String> {
    Ok(door
        .grants
        .get(key)
        .ok_or(ErrorCode::Unauthorized)?
        .origin
        .clone())
}

/// `inbox.send`: the durable wire goes to the courier instead of the client.
pub(super) async fn chat_send(
    door: &mut Door,
    key: &[u8; 32],
    request: ConversationSend,
) -> Result<(Sent, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let (peer, conversation) = (request.peer.clone(), request.conversation);
    let (sent, events) = super::inbox_conversation::send(door, key, request).await?;
    if let Some(shared) = door.courier_shared(&origin) {
        shared.push(
            &peer,
            Body::Chat {
                conversation,
                wire: sent.wire.clone(),
            },
        );
    }
    Ok((sent, events))
}

/// Hand wires that were made without a client call (a joined vouching thread
/// that flushed its waiting messages) to the courier.
pub(super) fn push_wires(
    door: &Door,
    origin: &str,
    peer: &str,
    conversation: [u8; 32],
    wires: Vec<Vec<u8>>,
) {
    if let Some(shared) = door.courier_shared(origin) {
        for wire in wires {
            shared.push(peer, Body::Chat { conversation, wire });
        }
    }
}

/// `inbox.retry`: same, for a wire the client asks to send again.
pub(super) async fn chat_retry(
    door: &mut Door,
    key: &[u8; 32],
    request: ConversationRetry,
) -> Result<(Retried, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let (peer, conversation) = (request.peer.clone(), request.conversation);
    let (retried, events) = super::inbox_conversation::retry(door, key, request).await?;
    if let Some(shared) = door.courier_shared(&origin) {
        shared.push(
            &peer,
            Body::Chat {
                conversation,
                wire: retried.wire.clone(),
            },
        );
    }
    Ok((retried, events))
}

/// Run `f` with an internal lease of the caller's origin and the Mesh's shared
/// state; with no Mesh bound the text cannot travel and the caller is told.
async fn with_courier<T>(
    door: &mut Door,
    key: &[u8; 32],
    f: impl for<'a> FnOnce(
        &'a mut Door,
        &'a Lease,
        &'a Shared,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>,
) -> Result<T> {
    let origin = origin_of(door, key)?;
    let shared = door.courier_shared(&origin).ok_or(ErrorCode::Unavailable)?;
    let lease = Lease { key: *key };
    Ok(f(door, &lease, &shared).await)
}

/// `board.group_propose`: the invitations go to each member's conversation.
pub(super) async fn group_propose(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupPropose,
) -> Result<(super::board::GroupProposed, Vec<Event>)> {
    let (proposed, events) = super::board::group_propose(door, key, request).await?;
    let invites = serde_json::to_value(&proposed.invitations).unwrap_or(Value::Null);
    let _ = with_courier(door, key, |door, lease, shared| {
        Box::pin(async move { queue_texts(door, lease, shared, Some(&invites)).await })
    })
    .await;
    Ok((proposed, events))
}

/// `board.group_answer`: the decision goes back to the actor's conversation.
pub(super) async fn group_answer(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupAnswer,
) -> Result<(super::board::GroupAnswered, Vec<Event>)> {
    let (answered, events) = super::board::group_answer(door, key, request).await?;
    let (actor, text) = (answered.actor.clone(), answered.text.clone());
    let _ = with_courier(door, key, |door, lease, shared| {
        Box::pin(async move { send_text(door, lease, shared, &actor, &text).await })
    })
    .await;
    Ok((answered, events))
}

/// `board.group_message`: a text from a member's conversation; Welcomes that a
/// committed proposal owes follow in the other members' conversations.
pub(super) async fn group_message(
    door: &mut Door,
    key: &[u8; 32],
    request: super::board::GroupMessageIn,
) -> Result<(super::board::GroupInbound, Vec<Event>)> {
    let (inbound, events) = super::board::group_message(door, key, request).await?;
    if let super::board::GroupInbound::Committed { welcomes, .. } = &inbound {
        let invites = serde_json::to_value(welcomes).unwrap_or(Value::Null);
        let _ = with_courier(door, key, |door, lease, shared| {
            Box::pin(async move { queue_texts(door, lease, shared, Some(&invites)).await })
        })
        .await;
    }
    Ok((inbound, events))
}

/// `board.group_welcome`: every owed Welcome is put into its member's
/// conversation, then reported delivered (it is durable in Delivery by then).
pub(super) async fn group_welcome(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupWelcome,
) -> Result<(super::board::GroupWelcomes, Vec<Event>)> {
    let operation = request.operation;
    let (welcomes, events) = super::board::group_welcome(door, key, request).await?;
    let pending = welcomes.pending.clone();
    let delivered = with_courier(door, key, |door, lease, shared| {
        Box::pin(async move {
            let mut done = Vec::new();
            for invite in pending {
                if send_text(door, lease, shared, &invite.member, &invite.text)
                    .await
                    .is_ok()
                {
                    done.push(invite.member);
                }
            }
            done
        })
    })
    .await
    .unwrap_or_default();
    if delivered.is_empty() {
        return Ok((welcomes, events));
    }
    super::board::group_welcome(
        door,
        key,
        GroupWelcome {
            operation,
            delivered,
        },
    )
    .await
}

// ---- the runtime loop ------------------------------------------------------------

/// Timing and room list of one courier.
#[derive(Clone)]
pub struct Config {
    /// How often the loop wakes to drain the outboxes.
    pub tick: u64,
    /// Seconds between forum heartbeats; keep below the forum's lease.
    pub heartbeat: u64,
    /// Seconds between trust-feed refreshes.
    pub refresh: u64,
    /// Seconds before an unacknowledged wave message is sent again.
    pub resend: u64,
    /// Seconds between scans for chat messages still Pending.
    pub scan: u64,
    /// Seconds between room-serving rounds.
    pub serve: u64,
    /// Rooms this member serves while online.
    pub rooms: Vec<RoomRef>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            tick: 1,
            heartbeat: 30,
            refresh: 300,
            resend: 20,
            scan: 30,
            serve: 10,
            rooms: vec![],
        }
    }
}

/// State of one running courier; none of it is authority and all of it can be
/// rebuilt after a restart from the durable outboxes.
#[derive(Default)]
struct State {
    sent: BTreeMap<Vec<u8>, u64>,
    next_heartbeat: u64,
    next_refresh: u64,
    next_scan: u64,
    next_serve: u64,
    attended: bool,
    started: bool,
    report: Report,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One pass of the Door-side work: start-up recovery, due duties, and the list
/// of frames that should leave now. Holds the Door only for this call.
async fn gather(
    door: &mut Door,
    origin: &str,
    shared: &Shared,
    config: &Config,
    state: &mut State,
    now: u64,
) -> Vec<Outgoing> {
    let Ok(lease) = Lease::open(door, origin, now, 120) else {
        return vec![];
    };
    if !state.started {
        state.started = true;
        // The proof worker died with the old process: its jobs go back to the queue.
        let _ = lease.call(door, "inbox.wave_jobs_recover", json!({})).await;
    }
    // Presence: attend once, then heartbeat; a failed heartbeat attends again.
    if now >= state.next_heartbeat {
        state.next_heartbeat = now + config.heartbeat;
        if !state.attended {
            state.attended = lease.call(door, "board.attend", json!({})).await.is_ok();
        }
        if state.attended {
            match lease.call(door, "board.heartbeat", json!({})).await {
                Ok(_) => state.report.heartbeats += 1,
                Err(_) => state.attended = false,
            }
        }
    }
    if now >= state.next_refresh {
        state.next_refresh = now + config.refresh;
        if lease.call(door, "foyer.refresh", json!({})).await.is_ok() {
            state.report.refreshes += 1;
        }
    }
    if now >= state.next_serve && !config.rooms.is_empty() {
        state.next_serve = now + config.serve;
        for room in &config.rooms {
            let _ = lease
                .call(
                    door,
                    "board.room_serve",
                    json!({"room": room.room, "group": room.group}),
                )
                .await;
        }
    }
    let mut out: Vec<Outgoing> = shared.queue.borrow_mut().drain(..).collect();
    // The durable wave outbox: resend until the recipient's ack removed it.
    if let Ok(value) = lease.call(door, "inbox.wave_outbox", json!({})).await {
        if let Ok(outbox) = serde_json::from_value::<super::inbox_waves::Outbox>(value) {
            for queued in outbox.messages {
                let id = [
                    b"w".as_slice(),
                    queued.envelope.message.nonce(),
                    kind_of(&queued.envelope.message).as_bytes(),
                ]
                .concat();
                if state.sent.get(&id).is_none_or(|at| now >= at + config.resend) {
                    out.push(Outgoing {
                        peer: queued.peer,
                        body: Body::Wave {
                            envelope: queued.envelope,
                        },
                    });
                }
            }
        }
    }
    // Chat messages still Pending (also after a restart): send their wire again.
    if now >= state.next_scan {
        state.next_scan = now + config.scan;
        scan_pending(door, &lease, &mut out).await;
    }
    lease.close(door);
    out
}

async fn scan_pending(door: &mut Door, lease: &Lease, out: &mut Vec<Outgoing>) {
    let Ok(all) = conversations(lease, door).await else {
        return;
    };
    for (peer, conversation) in all {
        let Ok(view) = lease
            .call(
                door,
                "inbox.snapshot",
                json!({"peer": peer, "conversation": conversation}),
            )
            .await
        else {
            continue;
        };
        let ids: Vec<[u8; 32]> = view
            .get("history")
            .and_then(Value::as_array)
            .map(|h| {
                h.iter()
                    .rev()
                    .take(MAX_SCAN_MESSAGES)
                    .filter_map(|m| serde_json::from_value(m.get("id")?.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        for id in ids {
            let pending = lease
                .call(
                    door,
                    "inbox.delivery_status",
                    json!({"conversation": conversation, "message": id}),
                )
                .await
                .is_ok_and(|status| status == json!("Pending"));
            if !pending {
                continue;
            }
            if let Ok((retried, _)) = super::inbox_conversation::retry(
                door,
                &lease.key,
                ConversationRetry {
                    peer: peer.clone(),
                    conversation,
                    message: id,
                },
            )
            .await
            {
                out.push(Outgoing {
                    peer: peer.clone(),
                    body: Body::Chat {
                        conversation,
                        wire: retried.wire,
                    },
                });
            }
        }
    }
}

/// Send one frame; a missing route or a refused send is a failure to retry.
async fn transmit(shared: &Shared, item: &Outgoing) -> bool {
    let addresses = shared.route(&item.peer);
    if addresses.is_empty() {
        return false;
    }
    let frame = Frame {
        version: FRAME_VERSION,
        reach: shared.reachability(),
        body: item.body.clone(),
    };
    let Ok(bytes) = serde_json::to_vec(&frame) else {
        return false;
    };
    shared.mesh.app_message(&addresses, &bytes).await.is_ok()
}

#[cfg(not(target_arch = "wasm32"))]
pub use run::{spawn, Courier, SharedDoor};

#[cfg(not(target_arch = "wasm32"))]
mod run {
    use super::*;
    use tokio::sync::Mutex;

    /// The Door shared between the embedder's dispatcher and the courier. Each
    /// side locks it per call; the courier never holds it across a network send.
    pub type SharedDoor = Rc<Mutex<Door>>;

    /// A running courier. Dropping it does not stop the task; closing the Mesh
    /// (`mesh.disconnect`, vault lock, Door close) does.
    pub struct Courier {
        task: tokio::task::JoinHandle<Report>,
    }
    impl Courier {
        /// Wait for the courier to end and read its counters.
        pub async fn finished(self) -> Option<Report> {
            self.task.await.ok()
        }
    }

    /// Start the courier of `origin` on the current `LocalSet`. The Mesh must
    /// be bound (`Door::bind_mesh`); otherwise the courier ends at once.
    pub fn spawn(door: SharedDoor, origin: &str, config: Config) -> Courier {
        let origin = origin.to_owned();
        Courier {
            task: tokio::task::spawn_local(run(door, origin, config)),
        }
    }

    async fn run(door: SharedDoor, origin: String, config: Config) -> Report {
        let Some(shared) = door.lock().await.courier_shared(&origin) else {
            return Report::default();
        };
        let mut state = State::default();
        let tick = std::time::Duration::from_secs(config.tick.max(1));
        loop {
            if shared.closed.get() {
                break;
            }
            tokio::select! {
                biased;
                _ = shared.stop.notified() => break,
                incoming = shared.listener.next() => {
                    match incoming {
                        Some(cmsh::Incoming::Message { payload, .. }) => {
                            let mut guard = door.lock().await;
                            receive(&mut guard, &origin, &shared, &payload, now(), &mut state.report).await;
                        }
                        Some(cmsh::Incoming::Call { .. }) => state.report.dropped += 1,
                        Some(cmsh::Incoming::ListenerClosed(scheme, _)) => {
                            shared.own.borrow_mut().retain(|a| *a.scheme() != scheme);
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(tick) => {}
            }
            cycle(&door, &origin, &shared, &config, &mut state).await;
        }
        state.report
    }

    /// Gather under the lock, then send without it, then record what left.
    async fn cycle(
        door: &SharedDoor,
        origin: &str,
        shared: &Shared,
        config: &Config,
        state: &mut State,
    ) {
        let now = now();
        let batch = {
            let mut guard = door.lock().await;
            gather(&mut guard, origin, shared, config, state, now).await
        };
        for item in batch {
            if transmit(shared, &item).await {
                state.report.sent += 1;
                if let Body::Wave { envelope } = &item.body {
                    let id = [
                        b"w".as_slice(),
                        envelope.message.nonce(),
                        kind_of(&envelope.message).as_bytes(),
                    ]
                    .concat();
                    state.sent.insert(id, now);
                }
            } else {
                state.report.failed += 1;
            }
        }
        if state.sent.len() > 4096 {
            let keep: BTreeSet<Vec<u8>> = state.sent.keys().rev().take(1024).cloned().collect();
            state.sent.retain(|key, _| keep.contains(key));
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/support/courier.rs"]
mod tests;
