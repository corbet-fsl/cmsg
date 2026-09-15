//! Browser bindings for the same MLS core and wire format used by native peers.
//! JavaScript owns the UI, durable ciphertext storage and Tor transport. These
//! bindings never call browser fetch, render messages or choose a gateway.
use crate::inbox::ReopeningInvitation;
use crate::{
    Acceptance, AdmissionGrant, AdmissionTrust, Clock, ContactResolution, DeviceAuthorization,
    Error, FirstContactPolicy, FirstContactRole, FrameCodec, Inbox, Invitation, Member,
    MemberIdentity, OnionEndpoint, Participant, Received, Redemption, MAX_DATA_BYTES,
    MAX_WIRE_BYTES,
};
use js_sys::{Array, Function, Promise, Uint8Array};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

#[path = "browser_accounting.rs"]
mod accounting_bindings;
#[path = "browser_live.rs"]
mod live_bindings;
#[path = "browser_reservation.rs"]
mod reservation_bindings;

fn js_error(error: Error) -> JsValue {
    JsValue::from_str(&format!("cmsg:{error:?}"))
}

struct BrowserClock;
impl Clock for BrowserClock {
    fn now(&self) -> Result<u64, Error> {
        let seconds = js_sys::Date::now() / 1000.0;
        if !seconds.is_finite() || !(1.0..=9_007_199_254_740_991.0).contains(&seconds) {
            return Err(Error::Admission);
        }
        Ok(seconds as u64)
    }
}

fn wrapping_key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, JsValue> {
    Ok(Zeroizing::new(
        bytes
            .try_into()
            .map_err(|_| js_error(Error::InvalidStore))?,
    ))
}

fn timestamp(seconds: f64) -> Result<u64, JsValue> {
    if !seconds.is_finite()
        || seconds.fract() != 0.0
        || !(1.0..=9_007_199_254_740_991.0).contains(&seconds)
    {
        return Err(js_error(Error::Admission));
    }
    Ok(seconds as u64)
}

fn contact_policy(
    response_deadline: f64,
    max_intro_bytes: f64,
) -> Result<FirstContactPolicy, JsValue> {
    if !max_intro_bytes.is_finite()
        || max_intro_bytes.fract() != 0.0
        || !(1.0..=MAX_DATA_BYTES as f64).contains(&max_intro_bytes)
    {
        return Err(js_error(Error::Admission));
    }
    Ok(FirstContactPolicy {
        response_deadline: timestamp(response_deadline)?,
        max_intro_bytes: max_intro_bytes as usize,
    })
}

/// Member-controlled community identity. The private root key is never exported;
/// recovery returns only an authenticated encrypted envelope.
#[wasm_bindgen]
pub struct BrowserIdentity {
    identity: MemberIdentity,
}

#[wasm_bindgen]
impl BrowserIdentity {
    #[wasm_bindgen(constructor)]
    pub fn new(community_id: &str) -> Result<BrowserIdentity, JsValue> {
        Ok(Self {
            identity: MemberIdentity::new(community_id).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = memberId)]
    pub fn member_id(&self) -> String {
        self.identity.member_id().to_owned()
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.identity.public_key().to_vec()
    }

    #[wasm_bindgen(js_name = authorizeDevice)]
    pub fn authorize_device(
        &self,
        device_public_key: &[u8],
        issued_at: f64,
        expires_at: f64,
    ) -> Result<String, JsValue> {
        let authorization = self
            .identity
            .authorize_device(
                device_public_key,
                timestamp(issued_at)?,
                timestamp(expires_at)?,
            )
            .map_err(js_error)?;
        serde_json::to_string(&authorization).map_err(|_| js_error(Error::Admission))
    }

    pub fn seal(&self, key: &[u8], context: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.identity
            .seal(&*wrapping_key(key)?, context)
            .map_err(js_error)
    }

    pub fn restore(
        sealed: &[u8],
        key: &[u8],
        community_id: &str,
        expected_member_id: &str,
        context: &[u8],
    ) -> Result<BrowserIdentity, JsValue> {
        Ok(Self {
            identity: MemberIdentity::restore(
                sealed,
                &*wrapping_key(key)?,
                community_id,
                expected_member_id,
                context,
            )
            .map_err(js_error)?,
        })
    }
}

/// One MLS participant. JavaScript must call `free()` when finished, and erase
/// its own plaintext/key copies. Wasm memory is not isolated from same-origin JS.
#[wasm_bindgen]
pub struct BrowserMember {
    member: Member,
}

#[wasm_bindgen]
impl BrowserMember {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BrowserMember, JsValue> {
        Ok(Self {
            member: Member::new_with_clock(Arc::new(BrowserClock)).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = chatPublicKey)]
    pub fn chat_public_key(&self) -> Vec<u8> {
        self.member.chat_public_key()
    }

    /// Trust is application configuration. Do not take issuer trust from peers.
    #[wasm_bindgen(js_name = bindDeviceAdmission)]
    pub fn bind_device_admission(
        &mut self,
        grant_json: &str,
        trust_json: &str,
        device_authorization_json: &str,
    ) -> Result<(), JsValue> {
        if grant_json.len() > MAX_WIRE_BYTES
            || trust_json.len() > MAX_WIRE_BYTES
            || device_authorization_json.len() > MAX_WIRE_BYTES
        {
            return Err(js_error(Error::Admission));
        }
        let grant: AdmissionGrant =
            serde_json::from_str(grant_json).map_err(|_| js_error(Error::Admission))?;
        let trust: AdmissionTrust =
            serde_json::from_str(trust_json).map_err(|_| js_error(Error::Admission))?;
        let device_authorization: DeviceAuthorization =
            serde_json::from_str(device_authorization_json)
                .map_err(|_| js_error(Error::Admission))?;
        self.member
            .bind_device_admission(
                grant,
                trust,
                device_authorization,
                BrowserClock.now().map_err(js_error)?,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = memberId)]
    pub fn member_id(&self) -> Result<String, JsValue> {
        self.member.member_id().map_err(js_error)
    }

    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&mut self) -> Result<(), JsValue> {
        self.member.create_group().map_err(js_error)
    }

    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&self) -> Result<Vec<u8>, JsValue> {
        self.member.key_package().map_err(js_error)
    }

    pub fn add(&mut self, key_package: &[u8]) -> Result<BrowserInvitation, JsValue> {
        Ok(BrowserInvitation {
            invitation: self.member.add(key_package).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = addMany)]
    pub fn add_many(&mut self, key_packages: Array) -> Result<BrowserInvitation, JsValue> {
        if key_packages.length() == 0 || key_packages.length() > 255 {
            return Err(js_error(Error::InvalidMessage));
        }
        let mut packages = Vec::with_capacity(key_packages.length() as usize);
        let mut total = 0usize;
        for package in key_packages.iter() {
            let package: Uint8Array = package
                .dyn_into()
                .map_err(|_| js_error(Error::InvalidMessage))?;
            total += package.length() as usize;
            if total > MAX_WIRE_BYTES {
                return Err(js_error(Error::InvalidMessage));
            }
            packages.push(package.to_vec());
        }
        Ok(BrowserInvitation {
            invitation: self.member.add_many(&packages).map_err(js_error)?,
        })
    }

    pub fn join(&mut self, welcome: &[u8]) -> Result<(), JsValue> {
        self.member.join(welcome).map_err(js_error)
    }

    #[wasm_bindgen(js_name = sendBytes)]
    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.member.send_bytes(bytes).map_err(js_error)
    }

    #[wasm_bindgen(js_name = sendText)]
    pub fn send_text(&mut self, text: &str) -> Result<Vec<u8>, JsValue> {
        self.member.send(text.as_bytes()).map_err(js_error)
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<BrowserReceived, JsValue> {
        Ok(BrowserReceived {
            received: self.member.receive(wire).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = receiveControl)]
    pub fn receive_control(&mut self, wire: &[u8]) -> Result<(), JsValue> {
        self.member.receive_control(wire).map_err(js_error)
    }

    pub fn participants(&self) -> Result<Array, JsValue> {
        let participants = Array::new();
        for participant in self.member.participants().map_err(js_error)? {
            participants.push(&JsValue::from(BrowserParticipant { participant }));
        }
        Ok(participants)
    }

    #[wasm_bindgen(js_name = removeParticipant)]
    pub fn remove_participant(
        &mut self,
        participant: &BrowserParticipant,
    ) -> Result<Vec<u8>, JsValue> {
        self.member
            .remove_participant(&participant.participant.handle)
            .map_err(js_error)
    }

    pub fn snapshot(&self, key: &[u8], context: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.member
            .snapshot(&*wrapping_key(key)?, context)
            .map_err(js_error)
    }

    pub fn restore(sealed: &[u8], key: &[u8], context: &[u8]) -> Result<BrowserMember, JsValue> {
        Ok(Self {
            member: Member::restore_with_clock(
                sealed,
                &*wrapping_key(key)?,
                context,
                Arc::new(BrowserClock),
            )
            .map_err(js_error)?,
        })
    }
}

/// Policy-enforcing browser session. Construction consumes the low-level member.
/// Mutations publish only after the host's async durable checkpoint/outbox write.
#[wasm_bindgen]
pub struct BrowserInbox {
    inbox: Inbox,
    member: Member,
}

// Requiring Promise<true> prevents a forgotten `return` or an unawaited write
// from accidentally being interpreted as a durable acknowledgement. The host
// remains trusted to implement atomic durable storage and prevent rollback.
async fn persist_browser_metadata(
    persist: &Function,
    checkpoint: &[u8],
    outbound: &[Vec<u8>],
    metadata: &JsValue,
) -> Result<(), JsValue> {
    let wires = Array::new();
    for wire in outbound {
        wires.push(&Uint8Array::from(wire.as_slice()));
    }
    let promise: Promise = persist
        .call3(
            &JsValue::UNDEFINED,
            &Uint8Array::from(checkpoint),
            &wires,
            metadata,
        )
        .map_err(|_| js_error(Error::InvalidStore))?
        .dyn_into()
        .map_err(|_| js_error(Error::InvalidStore))?;
    if JsFuture::from(promise)
        .await
        .map_err(|_| js_error(Error::InvalidStore))?
        .as_bool()
        != Some(true)
    {
        return Err(js_error(Error::InvalidStore));
    }
    Ok(())
}

impl BrowserInbox {
    fn duplicate(&self, key: &[u8; 32], context: &[u8]) -> Result<Self, JsValue> {
        self.duplicate_with_member(&self.member, key, context)
    }

    fn duplicate_with_member(
        &self,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
    ) -> Result<Self, JsValue> {
        let sealed = self
            .inbox
            .snapshot(member, key, context)
            .map_err(js_error)?;
        let (mut inbox, member) =
            Inbox::restore_with_clock(&sealed, key, context, Arc::new(BrowserClock))
                .map_err(js_error)?;
        inbox.copy_live_runtime(&self.inbox);
        Ok(Self { inbox, member })
    }

    async fn persist_candidate(
        &self,
        candidate: &mut Self,
        key: &[u8; 32],
        context: &[u8],
        persist: &Function,
        outbound: &[Vec<u8>],
    ) -> Result<(), JsValue> {
        let expected = self.inbox.publication_version();
        let next = candidate
            .inbox
            .advance_publication(expected)
            .map_err(js_error)?;
        let checkpoint = candidate
            .inbox
            .snapshot(&candidate.member, key, context)
            .map_err(js_error)?;
        let mut metadata = candidate.inbox.live_outbox_metadata(outbound);
        metadata["expectedVersion"] = expected.into();
        metadata["nextVersion"] = next.into();
        metadata["devicePublicKey"] = serde_json::json!(candidate.member.chat_public_key());
        let metadata = js_sys::JSON::parse(&metadata.to_string())
            .map_err(|_| js_error(Error::InvalidStore))?;
        persist_browser_metadata(persist, &checkpoint, outbound, &metadata).await
    }

    async fn update<T>(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: &Function,
        operation: impl FnOnce(&mut Inbox, &mut Member) -> Result<(T, Vec<Vec<u8>>), Error>,
    ) -> Result<T, JsValue> {
        let key = wrapping_key(key)?;
        let mut candidate = self.duplicate(&key, context)?;
        let (output, outbound) =
            operation(&mut candidate.inbox, &mut candidate.member).map_err(js_error)?;
        self.persist_candidate(&mut candidate, &key, context, persist, &outbound)
            .await?;
        *self = candidate;
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_replacement_candidate(
        &mut self,
        replacement: Option<&mut BrowserMember>,
        welcome: &[u8],
        control: &[u8],
        recipient_redemption: Option<Vec<u8>>,
        key: &[u8],
        context: &[u8],
        persist: &Function,
        redeem: &Function,
    ) -> Result<String, JsValue> {
        let key = wrapping_key(key)?;
        let retirement = if replacement.is_some() {
            Some(Member::new_with_clock(Arc::new(BrowserClock)).map_err(js_error)?)
        } else {
            None
        };
        let mut candidate = match replacement.as_deref() {
            Some(member) => self.duplicate_with_member(&member.member, &key, context)?,
            None => self.duplicate(&key, context)?,
        };
        let recipient_redemption = recipient_redemption.map(Zeroizing::new);
        let mut checkpoint = None;
        let mut request = None;
        let result = candidate
            .inbox
            .accept_replacement(
                &mut candidate.member,
                welcome,
                control,
                recipient_redemption.as_ref().map(|bytes| bytes.as_slice()),
                &key,
                context,
                |bytes| {
                    checkpoint = Some(bytes.to_vec());
                    Ok(())
                },
                |bytes| {
                    request = Some(Zeroizing::new(bytes.to_vec()));
                    Redemption::Indeterminate
                },
            )
            .map_err(js_error)?;
        if checkpoint.is_some() {
            self.persist_candidate(&mut candidate, &key, context, persist, &[])
                .await?;
            // A pending replacement already owns its KeyPackage private state.
            // Retire the external handle only after this first durable write.
            if let (Some(replacement), Some(retirement)) = (replacement, retirement) {
                replacement.member = retirement;
            }
            *self = candidate;
        }
        let Some(request) = request else {
            return Ok(acceptance_name(result));
        };
        let outcome = match redeem.call1(&JsValue::UNDEFINED, &Uint8Array::from(request.as_slice()))
        {
            Ok(value) => match value.dyn_into::<Promise>() {
                Ok(promise) => JsFuture::from(promise)
                    .await
                    .ok()
                    .and_then(|value| value.as_string()),
                Err(_) => None,
            },
            Err(_) => None,
        };
        let outcome = match outcome.as_deref() {
            Some("accepted") => Redemption::Accepted,
            Some("rejected") => Redemption::Rejected,
            _ => return Ok("pending".into()),
        };
        let mut candidate = self.duplicate(&key, context)?;
        let mut checkpoint = None;
        let result = candidate
            .inbox
            .accept_replacement(
                &mut candidate.member,
                welcome,
                control,
                None,
                &key,
                context,
                |bytes| {
                    checkpoint = Some(bytes.to_vec());
                    Ok(())
                },
                |_| match outcome {
                    Redemption::Accepted => Redemption::Accepted,
                    _ => Redemption::Rejected,
                },
            )
            .map_err(js_error)?;
        if checkpoint.is_some() {
            self.persist_candidate(&mut candidate, &key, context, persist, &[])
                .await?;
            *self = candidate;
        }
        Ok(acceptance_name(result))
    }
}

fn acceptance_name(acceptance: Acceptance) -> String {
    match acceptance {
        Acceptance::Joined => "joined",
        Acceptance::Rejected => "rejected",
        Acceptance::Pending => "pending",
        Acceptance::NeedsPermit => "needsPermit",
        Acceptance::Busy => "busy",
        Acceptance::Blocked => "blocked",
    }
    .into()
}

#[wasm_bindgen]
impl BrowserInbox {
    #[wasm_bindgen(constructor)]
    pub fn new(member: BrowserMember) -> Result<BrowserInbox, JsValue> {
        Ok(Self {
            inbox: Inbox::new_live(&member.member).map_err(js_error)?,
            member: member.member,
        })
    }

    pub fn restore(sealed: &[u8], key: &[u8], context: &[u8]) -> Result<BrowserInbox, JsValue> {
        let (mut inbox, member) = Inbox::restore_with_clock(
            sealed,
            &*wrapping_key(key)?,
            context,
            Arc::new(BrowserClock),
        )
        .map_err(js_error)?;
        inbox.require_live_delivery();
        Ok(Self { inbox, member })
    }

    pub fn snapshot(&self, key: &[u8], context: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inbox
            .snapshot(&self.member, &*wrapping_key(key)?, context)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = memberId)]
    pub fn member_id(&self) -> Result<String, JsValue> {
        self.member.member_id().map_err(js_error)
    }

    #[wasm_bindgen(js_name = chatPublicKey)]
    pub fn chat_public_key(&self) -> Vec<u8> {
        self.member.chat_public_key()
    }

    #[wasm_bindgen(js_name = invitationSender)]
    pub fn invitation_sender(&self, welcome: &[u8]) -> Result<String, JsValue> {
        self.member.invitation_sender(welcome).map_err(js_error)
    }

    #[wasm_bindgen(js_name = signPresence)]
    pub fn sign_presence(
        &self,
        endpoint: &BrowserOnionEndpoint,
        sequence: f64,
        expires_at: f64,
    ) -> Result<String, JsValue> {
        let update = self
            .member
            .sign_presence(
                Some(&endpoint.endpoint),
                timestamp(sequence)?,
                timestamp(expires_at)?,
            )
            .map_err(js_error)?;
        serde_json::to_string(&update).map_err(|_| js_error(Error::Admission))
    }

    #[wasm_bindgen(js_name = signDisconnect)]
    pub fn sign_disconnect(&self, sequence: f64, expires_at: f64) -> Result<String, JsValue> {
        let update = self
            .member
            .sign_presence(None, timestamp(sequence)?, timestamp(expires_at)?)
            .map_err(js_error)?;
        serde_json::to_string(&update).map_err(|_| js_error(Error::Admission))
    }

    #[wasm_bindgen(js_name = authorizeAllocation)]
    pub fn authorize_allocation(
        &self,
        policy_digest: &str,
        nonce: &[u8],
        blinded_request: &[u8],
        expires_at: f64,
    ) -> Result<String, JsValue> {
        let nonce: &[u8; 32] = nonce.try_into().map_err(|_| js_error(Error::Admission))?;
        let request = self
            .member
            .authorize_allocation(
                policy_digest,
                nonce,
                blinded_request,
                timestamp(expires_at)?,
            )
            .map_err(js_error)?;
        serde_json::to_string(&request).map_err(|_| js_error(Error::Admission))
    }

    #[wasm_bindgen(js_name = isKnown)]
    pub fn is_known(&self, peer: &str) -> bool {
        self.inbox.is_known(peer)
    }

    #[wasm_bindgen(js_name = isClosed)]
    pub fn is_closed(&self, peer: &str) -> bool {
        self.inbox.is_closed(peer)
    }

    #[wasm_bindgen(js_name = isBlocked)]
    pub fn is_blocked(&self, peer: &str) -> bool {
        self.inbox.is_blocked(peer)
    }

    #[wasm_bindgen(js_name = pendingWelcome)]
    pub fn pending_welcome(&self) -> Option<Vec<u8>> {
        self.inbox.pending_welcome().map(<[u8]>::to_vec)
    }

    #[wasm_bindgen(js_name = pendingReplacementControl)]
    pub fn pending_replacement_control(&self) -> Option<Vec<u8>> {
        self.inbox.pending_replacement_control().map(<[u8]>::to_vec)
    }

    #[wasm_bindgen(js_name = needsResolution)]
    pub fn needs_resolution(&self, peer: &str) -> bool {
        self.inbox.needs_resolution(peer)
    }

    #[wasm_bindgen(js_name = awaitingPeerResolution)]
    pub fn awaiting_peer_resolution(&self, peer: &str) -> bool {
        self.inbox.awaiting_peer_resolution(peer)
    }

    /// Private peer decision; never send its named contact data to telemetry or
    /// a public board. This is not an anonymous proof or an encrypted wire frame.
    #[wasm_bindgen(js_name = inboundResolutionReceipt)]
    pub fn inbound_resolution_receipt(&self, peer: &str) -> Option<Vec<u8>> {
        self.inbox
            .inbound_resolution_receipt(peer)
            .map(<[u8]>::to_vec)
    }

    #[wasm_bindgen(js_name = outboundResolutionReceipt)]
    pub fn outbound_resolution_receipt(&self, peer: &str) -> Option<Vec<u8>> {
        self.inbox
            .outbound_resolution_receipt(peer)
            .map(<[u8]>::to_vec)
    }

    /// Apply a private peer receipt and save the resulting encrypted checkpoint.
    /// Receipt identities never enter the message transport outbox.
    #[wasm_bindgen(js_name = applyResolution)]
    pub async fn apply_resolution(
        &mut self,
        receipt_json: &str,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<bool, JsValue> {
        if receipt_json.len() > MAX_WIRE_BYTES {
            return Err(js_error(Error::InvalidMessage));
        }
        let receipt: ContactResolution =
            serde_json::from_str(receipt_json).map_err(|_| js_error(Error::InvalidMessage))?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let first_resolution =
                inbox.apply_resolution(&receipt, member, &wrapping, context, |_| Ok(()))?;
            Ok((first_resolution, Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = refreshOutboundResolution)]
    pub async fn refresh_outbound_resolution(
        &mut self,
        peer: &str,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let receipt =
                inbox.refresh_outbound_resolution(peer, member, &wrapping, context, |_| Ok(()))?;
            // The receipt is retained inside the encrypted checkpoint. It is
            // not an MLS wire frame and must not enter the transport outbox.
            Ok((receipt, Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = beginFirstContact)]
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_first_contact(
        &mut self,
        peer: &str,
        introduction_id: &[u8],
        role: &str,
        response_deadline: f64,
        max_intro_bytes: f64,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let introduction_id: &[u8; 32] = introduction_id
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        let role = match role {
            "initiator" => FirstContactRole::Initiator,
            "recipient" => FirstContactRole::Recipient,
            _ => return Err(js_error(Error::Admission)),
        };
        let policy = contact_policy(response_deadline, max_intro_bytes)?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.begin_first_contact(
                peer,
                introduction_id,
                role,
                policy,
                member,
                &wrapping,
                context,
                |_| Ok(()),
            )?;
            Ok(((), Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = applyDeadlines)]
    pub async fn apply_deadlines(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<usize, JsValue> {
        let key = wrapping_key(key)?;
        let mut candidate = self.duplicate(&key, context)?;
        let mut checkpoint = None;
        let count = candidate
            .inbox
            .apply_deadlines(&candidate.member, &key, context, |bytes| {
                checkpoint = Some(bytes.to_vec());
                Ok(())
            })
            .map_err(js_error)?;
        if checkpoint.is_some() {
            self.persist_candidate(&mut candidate, &key, context, &persist, &[])
                .await?;
            *self = candidate;
        }
        Ok(count)
    }

    #[wasm_bindgen(js_name = createGroup)]
    pub async fn create_group(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        self.update(key, context, &persist, |_, member| {
            member.create_group()?;
            Ok(((), Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = keyPackage)]
    pub async fn key_package(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        self.update(key, context, &persist, |_, member| {
            let package = member.key_package()?;
            Ok((package.clone(), vec![package]))
        })
        .await
    }

    pub async fn add(
        &mut self,
        package: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<BrowserInvitation, JsValue> {
        self.update(key, context, &persist, |inbox, member| {
            let invitation = member.add(package)?;
            inbox.check_group(member)?;
            let outbound = vec![invitation.commit.clone(), invitation.welcome.clone()];
            Ok((BrowserInvitation { invitation }, outbound))
        })
        .await
    }

    #[wasm_bindgen(js_name = sendBytes)]
    pub async fn send_bytes(
        &mut self,
        bytes: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        self.apply_deadlines(key, context, persist.clone()).await?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let mut deadline_changed = false;
            match inbox.send_contact_bytes(member, bytes, &wrapping, context, |_, wire| {
                deadline_changed |= wire.is_empty();
                Ok(())
            }) {
                Ok(wire) => Ok((Ok(wire.clone()), vec![wire])),
                Err(error) if deadline_changed => Ok((Err(error), Vec::new())),
                Err(error) => Err(error),
            }
        })
        .await?
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = sendText)]
    pub async fn send_text(
        &mut self,
        text: &str,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        self.apply_deadlines(key, context, persist.clone()).await?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let mut deadline_changed = false;
            match inbox.send_contact(member, text.as_bytes(), &wrapping, context, |_, wire| {
                deadline_changed |= wire.is_empty();
                Ok(())
            }) {
                Ok(wire) => Ok((Ok(wire.clone()), vec![wire])),
                Err(error) if deadline_changed => Ok((Err(error), Vec::new())),
                Err(error) => Err(error),
            }
        })
        .await?
        .map_err(js_error)
    }

    pub async fn receive(
        &mut self,
        wire: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<BrowserReceived, JsValue> {
        self.apply_deadlines(key, context, persist.clone()).await?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let mut changed = false;
            match inbox.receive_contact(member, wire, &wrapping, context, |_| {
                changed = true;
                Ok(())
            }) {
                Ok(received) => Ok((
                    Ok(BrowserReceived { received }),
                    inbox.pending_live_controls(),
                )),
                Err(error) if changed => Ok((Err(error), Vec::new())),
                Err(error) => Err(error),
            }
        })
        .await?
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = closeContact)]
    pub async fn close_contact(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        self.close_contact_until(None, key, context, persist).await
    }

    /// Close until the blocking member explicitly starts again. An optional
    /// expiry permits a later fresh initiative; it never revives old traffic.
    #[wasm_bindgen(js_name = closeContactUntil)]
    pub async fn close_contact_until(
        &mut self,
        until: Option<f64>,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let until = until.map(timestamp).transpose()?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let wire =
                inbox.close_contact_until(member, until, &wrapping, context, |_, _| Ok(()))?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }

    #[wasm_bindgen(js_name = initiateContact)]
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_contact(
        &mut self,
        introduction_id: &[u8],
        response_deadline: f64,
        max_intro_bytes: f64,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let introduction_id: &[u8; 32] = introduction_id
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        let policy = contact_policy(response_deadline, max_intro_bytes)?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let wire = inbox.initiate_contact(
                member,
                introduction_id,
                policy,
                &wrapping,
                context,
                |_, _| Ok(()),
            )?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }

    /// Start a new group while preserving the member-owned contact journal.
    /// A successful durable write moves the replacement into this Inbox and
    /// resets its external handle to a fresh, unbound low-level member.
    #[wasm_bindgen(js_name = initiateReplacement)]
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_replacement(
        &mut self,
        replacement: &mut BrowserMember,
        peer_key_package: &[u8],
        introduction_id: &[u8],
        response_deadline: f64,
        max_intro_bytes: f64,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<BrowserReopeningInvitation, JsValue> {
        let introduction_id: &[u8; 32] = introduction_id
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        let policy = contact_policy(response_deadline, max_intro_bytes)?;
        let key = wrapping_key(key)?;
        let retirement = Member::new_with_clock(Arc::new(BrowserClock)).map_err(js_error)?;
        let mut candidate = self.duplicate_with_member(&replacement.member, &key, context)?;
        let mut checkpoint = None;
        let invitation = candidate
            .inbox
            .initiate_replacement(
                &mut candidate.member,
                peer_key_package,
                introduction_id,
                policy,
                &key,
                context,
                |bytes, _| {
                    checkpoint = Some(bytes.to_vec());
                    Ok(())
                },
            )
            .map_err(js_error)?;
        checkpoint.ok_or_else(|| js_error(Error::InvalidStore))?;
        self.persist_candidate(
            &mut candidate,
            &key,
            context,
            &persist,
            &[invitation.welcome.clone(), invitation.control.clone()],
        )
        .await?;
        replacement.member = retirement;
        *self = candidate;
        Ok(BrowserReopeningInvitation { invitation })
    }

    /// Authenticate the complete replacement before preparing a private
    /// recipient admission claim. This consumes neither state nor KeyPackage.
    #[wasm_bindgen(js_name = previewReplacement)]
    pub fn preview_replacement(
        &self,
        replacement: &BrowserMember,
        welcome: &[u8],
        control: &[u8],
    ) -> Result<String, JsValue> {
        let preview = self
            .inbox
            .preview_replacement(&replacement.member, welcome, control)
            .map_err(js_error)?;
        serde_json::to_string(&preview).map_err(|_| js_error(Error::InvalidMessage))
    }

    #[wasm_bindgen(js_name = acceptReplacement)]
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_replacement(
        &mut self,
        replacement: &mut BrowserMember,
        welcome: &[u8],
        control: &[u8],
        recipient_redemption: Option<Vec<u8>>,
        key: &[u8],
        context: &[u8],
        persist: Function,
        redeem: Function,
    ) -> Result<String, JsValue> {
        self.accept_replacement_candidate(
            Some(replacement),
            welcome,
            control,
            recipient_redemption,
            key,
            context,
            &persist,
            &redeem,
        )
        .await
    }

    /// Retry the exact durable pending replacement with its internal member and
    /// original opaque claim, including after encrypted checkpoint recovery.
    #[wasm_bindgen(js_name = retryPendingReplacement)]
    pub async fn retry_pending_replacement(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
        redeem: Function,
    ) -> Result<String, JsValue> {
        let welcome = self
            .inbox
            .pending_welcome()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| js_error(Error::InvalidState))?;
        let control = self
            .inbox
            .pending_replacement_control()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| js_error(Error::InvalidState))?;
        self.accept_replacement_candidate(
            None, &welcome, &control, None, key, context, &persist, &redeem,
        )
        .await
    }

    #[wasm_bindgen(js_name = consentContact)]
    pub async fn consent_contact(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let wire = inbox.consent_contact(member, &wrapping, context, |_, _| Ok(()))?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }

    /// persist(checkpoint, outboundFrames) must atomically commit both and resolve
    /// true. redeem receives only trusted recipient-prepared opaque bytes, after
    /// the pending checkpoint is durable; it resolves accepted/rejected/pending.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept(
        &mut self,
        welcome: &[u8],
        recipient_redemption: Option<Vec<u8>>,
        key: &[u8],
        context: &[u8],
        persist: Function,
        redeem: Function,
    ) -> Result<String, JsValue> {
        let key = wrapping_key(key)?;
        let recipient_redemption = recipient_redemption.map(Zeroizing::new);
        let mut candidate = self.duplicate(&key, context)?;
        let mut checkpoint = None;
        let mut request = None;
        let result = candidate
            .inbox
            .accept(
                &mut candidate.member,
                welcome,
                recipient_redemption.as_ref().map(|bytes| bytes.as_slice()),
                &key,
                context,
                |bytes| {
                    checkpoint = Some(bytes.to_vec());
                    Ok(())
                },
                |bytes| {
                    request = Some(Zeroizing::new(bytes.to_vec()));
                    Redemption::Indeterminate
                },
            )
            .map_err(js_error)?;
        if checkpoint.is_some() {
            self.persist_candidate(&mut candidate, &key, context, &persist, &[])
                .await?;
            *self = candidate;
        }
        let Some(request) = request else {
            return Ok(acceptance_name(result));
        };
        // Failed/ambiguous redemption keeps the exact durable pending attempt.
        let outcome = match redeem.call1(&JsValue::UNDEFINED, &Uint8Array::from(request.as_slice()))
        {
            Ok(value) => match value.dyn_into::<Promise>() {
                Ok(promise) => JsFuture::from(promise)
                    .await
                    .ok()
                    .and_then(|v| v.as_string()),
                Err(_) => None,
            },
            Err(_) => None,
        };
        let outcome = match outcome.as_deref() {
            Some("accepted") => Redemption::Accepted,
            Some("rejected") => Redemption::Rejected,
            _ => return Ok("pending".into()),
        };
        let mut candidate = self.duplicate(&key, context)?;
        let mut checkpoint = None;
        // The first phase already durably stored this intent. This callback is
        // only the observed result; it performs no second external redemption.
        let result = candidate
            .inbox
            .accept(
                &mut candidate.member,
                welcome,
                None,
                &key,
                context,
                |bytes| {
                    checkpoint = Some(bytes.to_vec());
                    Ok(())
                },
                |_| match outcome {
                    Redemption::Accepted => Redemption::Accepted,
                    _ => Redemption::Rejected,
                },
            )
            .map_err(js_error)?;
        if checkpoint.is_some() {
            self.persist_candidate(&mut candidate, &key, context, &persist, &[])
                .await?;
            *self = candidate;
        }
        Ok(acceptance_name(result))
    }

    #[wasm_bindgen(js_name = blockMemberUntil)]
    pub async fn block_member_until(
        &mut self,
        peer: &str,
        until: Option<f64>,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let until = until.map(timestamp).transpose()?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.block_member_until(peer, until, member, &wrapping, context, |_| Ok(()))?;
            Ok(((), Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = setBlocked)]
    pub async fn set_blocked(
        &mut self,
        peer: &str,
        blocked: bool,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.set_blocked(peer, blocked, member, &wrapping, context, |_| Ok(()))?;
            Ok(((), Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = cancelPending)]
    pub async fn cancel_pending(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.cancel_pending(member, &wrapping, context, |_| Ok(()))?;
            Ok(((), Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = exportContactSync)]
    pub fn export_contact_sync(&self) -> Result<Vec<u8>, JsValue> {
        self.inbox
            .export_contact_sync(&self.member)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = mergeContactSync)]
    pub async fn merge_contact_sync(
        &mut self,
        payload: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.merge_contact_sync(payload, member, &wrapping, context, |_| Ok(()))?;
            Ok(((), Vec::new()))
        })
        .await
    }

    #[wasm_bindgen(js_name = renewDeviceAdmission)]
    pub async fn renew_device_admission(
        &mut self,
        grant: &str,
        authorization: &str,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        if grant.len() > MAX_WIRE_BYTES || authorization.len() > MAX_WIRE_BYTES {
            return Err(js_error(Error::Admission));
        }
        let grant: AdmissionGrant =
            serde_json::from_str(grant).map_err(|_| js_error(Error::Admission))?;
        let authorization: DeviceAuthorization =
            serde_json::from_str(authorization).map_err(|_| js_error(Error::Admission))?;
        self.update(key, context, &persist, |_, member| {
            let wire = member.renew_device_admission(grant, authorization, |_, _| Ok(()))?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }
}

#[wasm_bindgen]
pub struct BrowserInvitation {
    invitation: Invitation,
}

#[wasm_bindgen]
impl BrowserInvitation {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.invitation.commit.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.invitation.welcome.clone()
    }
}

#[wasm_bindgen]
pub struct BrowserReopeningInvitation {
    invitation: ReopeningInvitation,
}

#[wasm_bindgen]
impl BrowserReopeningInvitation {
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.invitation.welcome.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn control(&self) -> Vec<u8> {
        self.invitation.control.clone()
    }
}

#[wasm_bindgen]
pub struct BrowserReceived {
    received: Received,
}

#[wasm_bindgen]
impl BrowserReceived {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        match &self.received {
            Received::Text(_) => "text",
            Received::Bytes(_) => "bytes",
            Received::MembershipChanged => "membershipChanged",
            Received::ContactClosed => "contactClosed",
            Received::ContactPolicyChanged => "contactPolicyChanged",
            Received::LiveControl => "liveControl",
        }
        .into()
    }

    #[wasm_bindgen(getter, js_name = memberId)]
    pub fn member_id(&self) -> Option<String> {
        match &self.received {
            Received::Text(message) => Some(message.member_id.clone()),
            Received::Bytes(message) => Some(message.member_id.clone()),
            Received::MembershipChanged
            | Received::ContactClosed
            | Received::ContactPolicyChanged
            | Received::LiveControl => None,
        }
    }

    /// Opaque payloads are returned byte-for-byte. Text is returned as UTF-8.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        match &self.received {
            Received::Text(message) => message.text.as_bytes().to_vec(),
            Received::Bytes(message) => message.bytes.clone(),
            Received::MembershipChanged
            | Received::ContactClosed
            | Received::ContactPolicyChanged
            | Received::LiveControl => Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn text(&self) -> Option<String> {
        match &self.received {
            Received::Text(message) => Some(message.text.clone()),
            _ => None,
        }
    }
}

#[wasm_bindgen]
pub struct BrowserParticipant {
    participant: Participant,
}

#[wasm_bindgen]
impl BrowserParticipant {
    #[wasm_bindgen(getter, js_name = memberId)]
    pub fn member_id(&self) -> String {
        self.participant.member_id.clone()
    }

    #[wasm_bindgen(getter, js_name = chatPublicKey)]
    pub fn chat_public_key(&self) -> Vec<u8> {
        self.participant.chat_public_key.clone()
    }
}

/// Validated onion destinations can be passed to a separately configured Tor
/// adapter. Validation authenticates the address format, not the adapter.
#[wasm_bindgen]
pub struct BrowserOnionEndpoint {
    endpoint: OnionEndpoint,
}

#[wasm_bindgen]
impl BrowserOnionEndpoint {
    #[wasm_bindgen(constructor)]
    pub fn new(host: &str, port: f64) -> Result<BrowserOnionEndpoint, JsValue> {
        if !port.is_finite() || port.fract() != 0.0 || !(1.0..=65535.0).contains(&port) {
            return Err(js_error(Error::InvalidRoute));
        }
        Ok(Self {
            endpoint: OnionEndpoint::parse(host, port as u16).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn host(&self) -> String {
        self.endpoint.host().to_owned()
    }

    #[wasm_bindgen(getter)]
    pub fn port(&self) -> u16 {
        self.endpoint.port()
    }
}

#[wasm_bindgen]
pub struct BrowserFrameCodec {
    codec: FrameCodec,
}

#[wasm_bindgen]
impl BrowserFrameCodec {
    #[wasm_bindgen(constructor)]
    pub fn new(max_frame_bytes: f64) -> Result<BrowserFrameCodec, JsValue> {
        if !max_frame_bytes.is_finite()
            || max_frame_bytes.fract() != 0.0
            || !(1.0..=MAX_WIRE_BYTES as f64).contains(&max_frame_bytes)
        {
            return Err(js_error(Error::InvalidState));
        }
        Ok(Self {
            codec: FrameCodec::new(max_frame_bytes as usize).map_err(js_error)?,
        })
    }

    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.codec.encode(payload).map_err(js_error)
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Array, JsValue> {
        let frames = Array::new();
        for frame in self.codec.push(chunk).map_err(js_error)? {
            frames.push(&Uint8Array::from(frame.as_slice()));
        }
        Ok(frames)
    }

    pub fn finish(&mut self) -> Result<(), JsValue> {
        self.codec.finish().map_err(js_error)
    }

    pub fn close(&mut self) {
        self.codec.close();
    }
}
