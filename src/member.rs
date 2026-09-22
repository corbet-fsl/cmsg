use crate::{
    validate_text, verify_admission, AdmissionGrant, AdmissionTrust, Clock, DeviceAuthorization,
    Error, Participant, ParticipantHandle, MAX_DATA_BYTES, MAX_WIRE_BYTES,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use tls_codec::{Deserialize as _, Serialize as _};
use zeroize::{Zeroize, Zeroizing};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const PAYLOAD_HEADER: &[u8] = b"cmsg-payload-v1\0";

/// The caller must send these over authenticated, anonymous member channels.
/// Welcome data includes the group roster; it must not go to a central log.
pub struct Invitation {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Authenticated sender identity is visible only to conversation participants.
#[derive(Serialize, Deserialize)]
pub struct TextMessage {
    pub member_id: String,
    pub text: String,
}
impl Drop for TextMessage {
    fn drop(&mut self) {
        self.text.zeroize();
        self.member_id.zeroize();
    }
}

/// Opaque authenticated application data. Retention belongs to the embedding
/// application; binary data is not added to the text-history convenience store.
pub struct DataMessage {
    pub member_id: String,
    pub bytes: Vec<u8>,
}
impl fmt::Debug for DataMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataMessage([redacted])")
    }
}
impl Drop for DataMessage {
    fn drop(&mut self) {
        self.member_id.zeroize();
        self.bytes.zeroize();
    }
}

pub enum Received {
    Text(TextMessage),
    Bytes(DataMessage),
    MembershipChanged,
    /// Emitted by the guarded Inbox first-contact protocol after verifying and
    /// durably applying a peer's encrypted permanent-close receipt.
    ContactClosed,
    /// A signed owner block or fresh-initiative transition was durably applied.
    ContactPolicyChanged,
    /// Session or delivery evidence changed; this contains no application data.
    LiveControl,
}
impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => f.write_str("Text([redacted])"),
            Self::Bytes(_) => f.write_str("Bytes([redacted])"),
            Self::MembershipChanged => f.write_str("MembershipChanged"),
            Self::ContactClosed => f.write_str("ContactClosed"),
            Self::ContactPolicyChanged => f.write_str("ContactPolicyChanged"),
            Self::LiveControl => f.write_str("LiveControl"),
        }
    }
}

/// One independently generated MLS device in one conversation. Several devices
/// can carry the same issuer-certified community member identity. Each device
/// must generate its own signer and ratchet state; restoring a snapshot is not
/// device enrollment. Never reuse account identifiers across communities.
/// Memory storage is client-local; persistence is available only as ciphertext.
pub struct Member {
    provider: OpenMlsRustCrypto,
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential: CredentialWithKey,
    group: Option<MlsGroup>,
    pub(crate) trust: Option<AdmissionTrust>,
    history: Vec<TextMessage>,
    clock: Arc<dyn Clock>,
}

fn config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(256)
        .build()
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| Error::Randomness)?;
    Ok(value)
}
fn parse(wire: &[u8]) -> Result<MlsMessageIn, Error> {
    if wire.is_empty() || wire.len() > MAX_WIRE_BYTES {
        return Err(Error::InvalidMessage);
    }
    MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| Error::InvalidMessage)
}

fn participant_device_keys(
    group: &MlsGroup,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<BTreeSet<(String, Vec<u8>)>, Error> {
    let mut participants = BTreeSet::new();
    for participant in group.members() {
        let member_id = verify_historical_credential(
            &participant.credential,
            &participant.signature_key,
            trust,
            now,
        )?;
        if !participants.insert((member_id, participant.signature_key.to_vec())) {
            return Err(Error::Admission);
        }
    }
    Ok(participants)
}

impl Member {
    pub fn new() -> Result<Self, Error> {
        Self::new_with_clock(Arc::new(crate::lifecycle::SystemClock))
    }

    pub fn new_with_clock(clock: Arc<dyn Clock>) -> Result<Self, Error> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            SignatureKeyPair::new(SUITE.signature_algorithm()).map_err(|_| Error::InvalidState)?;
        signer
            .store(provider.storage())
            .map_err(|_| Error::InvalidState)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(random::<32>()?.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            group: None,
            trust: None,
            history: Vec::new(),
            clock,
        })
    }

    /// Supply this device public key to the integrating admission authority.
    pub fn chat_public_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Legacy issuer-owned identity binding. An issuer can substitute another
    /// device under this identity. Use bind_device_admission when the admission
    /// authority is outside the identity trust boundary.
    pub fn bind_admission(
        &mut self,
        grant: AdmissionGrant,
        trust: AdmissionTrust,
        now: u64,
    ) -> Result<(), Error> {
        if self.group.is_some() || self.trust.is_some() {
            return Err(Error::InvalidState);
        }
        verify_admission(&grant, &trust, &self.chat_public_key(), now)?;
        self.credential.credential =
            BasicCredential::new(serde_json::to_vec(&grant).map_err(|_| Error::Admission)?).into();
        self.trust = Some(trust);
        Ok(())
    }

    /// Bind an eligibility grant to a member-controlled identity root. The
    /// eligibility issuer cannot authorize a replacement device by itself.
    /// Every participant in a group using this API must carry a root signature.
    pub fn bind_device_admission(
        &mut self,
        grant: AdmissionGrant,
        trust: AdmissionTrust,
        device_authorization: DeviceAuthorization,
        now: u64,
    ) -> Result<(), Error> {
        if self.group.is_some() || self.trust.is_some() {
            return Err(Error::InvalidState);
        }
        verify_admission(&grant, &trust, &self.chat_public_key(), now)?;
        crate::verify_device_authorization(
            &device_authorization,
            &trust.community_id,
            &grant.member_id,
            &self.chat_public_key(),
            now,
        )?;
        self.credential.credential = BasicCredential::new(
            serde_json::to_vec(&DeviceCredential {
                admission: grant,
                device_authorization,
            })
            .map_err(|_| Error::Admission)?,
        )
        .into();
        self.trust = Some(trust);
        Ok(())
    }

    /// Refresh the issuer and root-authorized certificates on an ungrouped
    /// restored device. The stable member root and device signing key remain
    /// unchanged; grouped members must use `renew_device_admission`, which
    /// emits and durably persists an MLS update commit.
    pub fn refresh_device_admission(
        &mut self,
        grant: AdmissionGrant,
        device_authorization: DeviceAuthorization,
        now: u64,
    ) -> Result<(), Error> {
        if self.group.is_some() {
            return Err(Error::InvalidState);
        }
        let trust = self.trust.as_ref().ok_or(Error::Admission)?.clone();
        let old_id = self.stored_member_id()?;
        if verify_admission(&grant, &trust, &self.chat_public_key(), now)? != old_id {
            return Err(Error::Admission);
        }
        crate::verify_device_authorization(
            &device_authorization,
            &trust.community_id,
            &old_id,
            &self.chat_public_key(),
            now,
        )?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                serde_json::to_vec(&DeviceCredential {
                    admission: grant,
                    device_authorization,
                })
                .map_err(|_| Error::Admission)?,
            )
            .into(),
            signature_key: self.chat_public_key().into(),
        };
        if credential_parts(&self.credential.credential)?.1.is_none() {
            return Err(Error::Admission);
        }
        // Re-login can replay the exact still-valid certificate before the
        // issuer has advanced either timestamp. The existing key, member and
        // root checks above already authenticate it; retain the current
        // credential instead of treating an identical retry as a downgrade.
        if credential.credential == self.credential.credential {
            self.member_id()?;
            return Ok(());
        }
        verify_renewal_advance(&self.credential.credential, &credential.credential)?;
        self.credential = credential;
        Ok(())
    }

    pub(crate) fn admission_grant(&self) -> Result<AdmissionGrant, Error> {
        credential_grant(&self.credential.credential)
    }

    pub(crate) fn device_authorization(&self) -> Result<Option<DeviceAuthorization>, Error> {
        Ok(credential_parts(&self.credential.credential)?.1)
    }

    pub(crate) fn private_identity_credential(&self) -> Result<Vec<u8>, Error> {
        let basic = BasicCredential::try_from(self.credential.credential.clone())
            .map_err(|_| Error::Admission)?;
        Ok(basic.identity().to_vec())
    }

    pub(crate) fn verify_private_identity_credential(
        &self,
        credential: &[u8],
        key: &[u8],
        at: u64,
    ) -> Result<String, Error> {
        let credential: Credential = BasicCredential::new(credential.to_vec()).into();
        if credential_parts(&credential)?.1.is_none() {
            return Err(Error::Admission);
        }
        verify_credential(
            &credential,
            key,
            self.trust.as_ref().ok_or(Error::Admission)?,
            at,
        )
    }

    pub fn member_id(&self) -> Result<String, Error> {
        verify_credential(
            &self.credential.credential,
            &self.chat_public_key(),
            self.trust.as_ref().ok_or(Error::Admission)?,
            self.clock.now()?,
        )
    }

    pub(crate) fn authorization_time(&self) -> Result<u64, Error> {
        self.clock.now()
    }

    // Local encrypted history and recovery remain accessible after grant expiry.
    pub(crate) fn stored_member_id(&self) -> Result<String, Error> {
        verify_historical_credential(
            &self.credential.credential,
            &self.chat_public_key(),
            self.trust.as_ref().ok_or(Error::Admission)?,
            self.clock.now()?,
        )
    }

    /// The history is local to this client and is included in encrypted snapshots.
    pub fn history(&self) -> &[TextMessage] {
        &self.history
    }

    pub fn create_group(&mut self) -> Result<(), Error> {
        self.member_id()?;
        if self.group.is_some() {
            return Err(Error::InvalidState);
        }
        self.group = Some(
            MlsGroup::new(
                &self.provider,
                &self.signer,
                &config(),
                self.credential.clone(),
            )
            .map_err(|_| Error::InvalidState)?,
        );
        Ok(())
    }

    /// A fresh, single-use KeyPackage. Its credential binding must be authenticated
    /// by the integrating application's admission/introduction protocol.
    pub fn key_package(&self) -> Result<Vec<u8>, Error> {
        self.member_id()?;
        KeyPackage::builder()
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(|_| Error::InvalidState)?
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| Error::InvalidMessage)
    }

    /// Add several issuer-authenticated members in one MLS epoch transition.
    /// cfrm first-contact spending is an additional application-level gate.
    pub fn add_many(&mut self, packages: &[Vec<u8>]) -> Result<Invitation, Error> {
        self.member_id()?;
        if packages.is_empty() || packages.len() > 255 {
            return Err(Error::InvalidMessage);
        }
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let now = self.clock.now()?;
        let root_bound = self.device_authorization()?.is_some();
        let mut devices =
            group_devices(self.group.as_ref().ok_or(Error::InvalidState)?, trust, now)?;
        let mut validated = Vec::with_capacity(packages.len());
        for wire in packages {
            if wire.len() > MAX_WIRE_BYTES {
                return Err(Error::InvalidMessage);
            }
            let package = KeyPackageIn::tls_deserialize_exact(wire)
                .map_err(|_| Error::InvalidMessage)?
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| Error::InvalidMessage)?;
            verify_credential(
                package.leaf_node().credential(),
                package.leaf_node().signature_key().as_slice(),
                trust,
                now,
            )?;
            if credential_parts(package.leaf_node().credential())?
                .1
                .is_some()
                != root_bound
            {
                return Err(Error::Admission);
            }
            if !devices.insert(package.leaf_node().signature_key().as_slice().to_vec()) {
                return Err(Error::Admission);
            }
            validated.push(package);
        }
        let group = self.group.as_mut().ok_or(Error::InvalidState)?;
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &validated)
            .map_err(|_| Error::InvalidMessage)?;
        let invitation = Invitation {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| Error::InvalidMessage)?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|_| Error::InvalidMessage)?,
        };
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::InvalidState)?;
        Ok(invitation)
    }

    pub fn add(&mut self, key_package: &[u8]) -> Result<Invitation, Error> {
        self.add_many(&[key_package.to_vec()])
    }

    pub fn join(&mut self, welcome: &[u8]) -> Result<(), Error> {
        let prepared = self.prepare_join(welcome)?;
        self.commit_join(prepared, |_| Ok(()))
    }

    /// Authenticate the actual MLS Welcome signer without consuming a key
    /// package or joining. Recipient policy adapters use this stable ID when
    /// constructing their private, invitation-bound redemption claim.
    pub fn invitation_sender(&self, welcome: &[u8]) -> Result<String, Error> {
        Ok(self.prepare_join(welcome)?.inviter.clone())
    }

    pub(crate) fn prepare_join(&self, welcome: &[u8]) -> Result<PreparedJoin, Error> {
        self.prepare_join_at_current_time(welcome, false)
    }

    pub(crate) fn prepare_stored_join(&self, welcome: &[u8]) -> Result<PreparedJoin, Error> {
        self.prepare_join_at_current_time(welcome, true)
    }

    fn prepare_join_at_current_time(
        &self,
        welcome: &[u8],
        historical: bool,
    ) -> Result<PreparedJoin, Error> {
        if historical {
            self.stored_member_id()?;
        } else {
            self.member_id()?;
        }
        if self.group.is_some() {
            return Err(Error::InvalidState);
        }
        let welcome = match parse(welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::InvalidMessage),
        };
        let working = WorkingProvider(OpenMlsRustCrypto::default());
        *working
            .0
            .storage()
            .values
            .write()
            .map_err(|_| Error::InvalidState)? = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::InvalidState)?
            .clone();
        let staged =
            StagedWelcome::new_from_welcome(&working.0, config().join_config(), welcome, None)
                .map_err(|_| Error::InvalidMessage)?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let sender = staged.welcome_sender().map_err(|_| Error::InvalidMessage)?;
        let verify = if historical {
            verify_historical_credential
        } else {
            verify_credential
        };
        let inviter = verify(
            sender.credential(),
            sender.signature_key().as_slice(),
            trust,
            self.clock.now()?,
        )?;
        let group = staged
            .into_group(&working.0)
            .map_err(|_| Error::InvalidState)?;
        verify_group_history(&group, trust, self.clock.now()?)?;
        Ok(PreparedJoin {
            working,
            group,
            inviter,
        })
    }

    pub(crate) fn commit_join(
        &mut self,
        mut prepared: PreparedJoin,
        persist: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.group.is_some() {
            return Err(Error::InvalidState);
        }
        std::mem::swap(&mut self.provider, &mut prepared.working.0);
        self.group = Some(prepared.group);
        let mut guard = JoinGuard {
            member: self,
            original: prepared.working,
            committed: false,
        };
        let outcome = persist(guard.member);
        guard.committed = outcome.is_ok();
        outcome
    }

    /// Low-level MLS primitive: leaf indices are meaningful only in their epoch.
    /// User-facing clients should use remove_participant with a current roster handle.
    pub fn remove(&mut self, leaf: u32) -> Result<Vec<u8>, Error> {
        self.member_id()?;
        let group = self.group.as_mut().ok_or(Error::InvalidState)?;
        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[LeafNodeIndex::new(leaf)])
            .map_err(|_| Error::InvalidMessage)?;
        let wire = commit
            .tls_serialize_detached()
            .map_err(|_| Error::InvalidMessage)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::InvalidState)?;
        Ok(wire)
    }

    /// Display authenticated local participants, including expired stored members.
    /// Each entry is one independently certified device. Member IDs can repeat;
    /// device signing keys cannot. Target a device through its epoch-bound handle.
    pub fn participants(&self) -> Result<Vec<Participant>, Error> {
        self.stored_member_id()?;
        let group = self.group.as_ref().ok_or(Error::InvalidState)?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let now = self.clock.now()?;
        verify_group_history(group, trust, now)?;
        group
            .members()
            .map(|member| {
                let member_id = verify_historical_credential(
                    &member.credential,
                    &member.signature_key,
                    trust,
                    now,
                )?;
                Ok(Participant {
                    handle: ParticipantHandle {
                        group_id: group.group_id().as_slice().to_vec(),
                        epoch: group.epoch().as_u64(),
                        leaf: member.index.u32(),
                        member_id: member_id.clone(),
                        chat_public_key: member.signature_key.clone(),
                    },
                    member_id,
                    chat_public_key: member.signature_key,
                })
            })
            .collect()
    }

    /// Remove exactly the participant represented by a current local roster handle.
    /// Handles fail after every epoch transition, including removal and leaf reuse.
    pub fn remove_participant(&mut self, handle: &ParticipantHandle) -> Result<Vec<u8>, Error> {
        self.member_id()?;
        let group = self.group.as_ref().ok_or(Error::InvalidState)?;
        if group.group_id().as_slice() != handle.group_id || group.epoch().as_u64() != handle.epoch
        {
            return Err(Error::InvalidState);
        }
        let member = group
            .member_at(LeafNodeIndex::new(handle.leaf))
            .ok_or(Error::InvalidState)?;
        let id = verify_historical_credential(
            &member.credential,
            &member.signature_key,
            self.trust.as_ref().ok_or(Error::Admission)?,
            self.clock.now()?,
        )?;
        if id != handle.member_id || member.signature_key != handle.chat_public_key {
            return Err(Error::Admission);
        }
        self.remove(handle.leaf)
    }

    pub fn send(&mut self, text: &[u8]) -> Result<Vec<u8>, Error> {
        validate_text(text)?;
        let member_id = self.member_id()?;
        let wire = self.send_payload(0, text)?;
        self.history.push(TextMessage {
            member_id,
            text: validate_text(text)?.to_owned(),
        });
        Ok(wire)
    }

    /// Encrypt bounded opaque bytes. cmsg never parses or fetches their contents.
    /// Text-only products should expose `send` instead of this lower-level API.
    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if bytes.len() > MAX_DATA_BYTES {
            return Err(Error::InvalidMessage);
        }
        self.send_payload(1, bytes)
    }

    pub(crate) fn policy_group_id(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .group
            .as_ref()
            .ok_or(Error::InvalidState)?
            .group_id()
            .as_slice()
            .to_vec())
    }

    pub(crate) fn send_policy_record(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if bytes.len() > MAX_WIRE_BYTES / 2 {
            return Err(Error::InvalidMessage);
        }
        self.send_payload(2, bytes)
    }

    pub(crate) fn remember_policy_text(
        &mut self,
        member_id: &str,
        text: &[u8],
    ) -> Result<(), Error> {
        self.history.push(TextMessage {
            member_id: member_id.to_owned(),
            text: validate_text(text)?.to_owned(),
        });
        Ok(())
    }

    fn send_payload(&mut self, kind: u8, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        self.member_id()?;
        let mut payload =
            Zeroizing::new(Vec::with_capacity(PAYLOAD_HEADER.len() + 1 + bytes.len()));
        payload.extend_from_slice(PAYLOAD_HEADER);
        payload.push(kind);
        payload.extend_from_slice(bytes);
        let wire = self
            .group
            .as_mut()
            .ok_or(Error::InvalidState)?
            .create_message(&self.provider, &self.signer, &payload)
            .map_err(|_| Error::InvalidMessage)?
            .tls_serialize_detached()
            .map_err(|_| Error::InvalidMessage)?;
        Ok(wire)
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Received, Error> {
        self.process_incoming(wire, false, false, false, &BTreeSet::new())
    }

    pub(crate) fn receive_excluding(
        &mut self,
        wire: &[u8],
        excluded: &BTreeSet<String>,
    ) -> Result<Received, Error> {
        self.process_incoming(wire, false, false, false, excluded)
    }

    /// Decode the bounded internal contact envelope only inside the guarded
    /// inbox. Generic receive must retain its public text/data size contract.
    pub(crate) fn receive_policy_excluding(
        &mut self,
        wire: &[u8],
        excluded: &BTreeSet<String>,
    ) -> Result<Received, Error> {
        self.process_incoming(wire, false, true, false, excluded)
    }

    /// Process only authenticated control while a local certificate is expired.
    /// Application messages are rejected without changing ratchets or history.
    pub fn receive_control(&mut self, wire: &[u8]) -> Result<(), Error> {
        match self.process_incoming(wire, true, false, false, &BTreeSet::new())? {
            Received::MembershipChanged => Ok(()),
            Received::Text(_)
            | Received::Bytes(_)
            | Received::ContactClosed
            | Received::ContactPolicyChanged
            | Received::LiveControl => Err(Error::InvalidMessage),
        }
    }

    /// Receive only a same-device credential renewal, including while our
    /// own certificate is expired. Generic control processing stays separate.
    pub fn receive_admission_renewal(&mut self, wire: &[u8]) -> Result<(), Error> {
        match self.process_incoming(wire, true, false, true, &BTreeSet::new())? {
            Received::MembershipChanged => Ok(()),
            _ => Err(Error::InvalidMessage),
        }
    }

    fn process_incoming(
        &mut self,
        wire: &[u8],
        control_only: bool,
        allow_policy: bool,
        renewal_only: bool,
        excluded: &BTreeSet<String>,
    ) -> Result<Received, Error> {
        if control_only {
            self.stored_member_id()?;
        } else {
            self.member_id()?;
        }
        let now = self.clock.now()?;
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(|_| Error::InvalidMessage)?;
        let current = self.group.as_ref().ok_or(Error::InvalidState)?;
        // OpenMLS may consume receive keys before it returns an authentication
        // error. Process in isolated storage; publish state only after validation.
        let mut working = WorkingProvider(OpenMlsRustCrypto::default());
        *working
            .0
            .storage()
            .values
            .write()
            .map_err(|_| Error::InvalidState)? = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::InvalidState)?
            .clone();
        let mut group = MlsGroup::load(working.0.storage(), current.group_id())
            .map_err(|_| Error::InvalidState)?
            .ok_or(Error::InvalidState)?;
        let processed = group
            .process_message(&working.0, message)
            .map_err(|_| Error::InvalidMessage)?;
        let sender = match processed.sender() {
            Sender::Member(index) => group.member_at(*index).ok_or(Error::Admission)?,
            _ => return Err(Error::Admission),
        };
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let before_participants = if renewal_only {
            participant_device_keys(current, trust, now)?
        } else {
            BTreeSet::new()
        };
        let sender_credential = processed.credential().clone();
        let sender_id =
            verify_historical_credential(&sender_credential, &sender.signature_key, trust, now)?;
        if excluded.contains(&sender_id) {
            return Err(Error::Admission);
        }
        let received = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = Zeroizing::new(application.into_bytes());
                if control_only {
                    return Err(Error::InvalidMessage);
                }
                let member_id =
                    verify_credential(&sender_credential, &sender.signature_key, trust, now)?;
                let payload = bytes
                    .strip_prefix(PAYLOAD_HEADER)
                    .ok_or(Error::InvalidMessage)?;
                let (&kind, body) = payload.split_first().ok_or(Error::InvalidMessage)?;
                match kind {
                    0 => Received::Text(TextMessage {
                        member_id,
                        text: validate_text(body)?.to_owned(),
                    }),
                    1 if body.len() <= MAX_DATA_BYTES => Received::Bytes(DataMessage {
                        member_id,
                        bytes: body.to_vec(),
                    }),
                    2 if allow_policy && body.len() <= MAX_WIRE_BYTES / 2 => {
                        Received::Bytes(DataMessage {
                            member_id,
                            bytes: body.to_vec(),
                        })
                    }
                    _ => return Err(Error::InvalidMessage),
                }
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                if renewal_only {
                    let update = commit
                        .update_path_leaf_node()
                        .ok_or(Error::InvalidMessage)?;
                    if commit.queued_proposals().next().is_some()
                        || update.credential() == &sender_credential
                    {
                        return Err(Error::InvalidMessage);
                    }
                }
                let currently_authorized =
                    verify_credential(&sender_credential, &sender.signature_key, trust, now)
                        .is_ok();
                if let Some(leaf) = commit.update_path_leaf_node() {
                    verify_leaf_change(
                        &sender_credential,
                        &sender.signature_key,
                        leaf,
                        trust,
                        now,
                    )?;
                }
                // An expired sender may recover only through a current same-key
                // own-leaf renewal, never through proposals or ordinary control.
                if !currently_authorized
                    && (commit.update_path_leaf_node().is_none()
                        || commit.queued_proposals().next().is_some())
                {
                    return Err(Error::Admission);
                }
                for queued in commit.queued_proposals() {
                    match queued.proposal() {
                        Proposal::Add(add) => {
                            let leaf = add.key_package().leaf_node();
                            verify_credential(
                                leaf.credential(),
                                leaf.signature_key().as_slice(),
                                trust,
                                now,
                            )?;
                        }
                        Proposal::Update(update) => {
                            let previous = match queued.sender() {
                                Sender::Member(index) => {
                                    group.member_at(*index).ok_or(Error::Admission)?
                                }
                                _ => return Err(Error::Admission),
                            };
                            verify_leaf_change(
                                &previous.credential,
                                &previous.signature_key,
                                update.leaf_node(),
                                trust,
                                now,
                            )?;
                        }
                        Proposal::Remove(_) => (),
                        // Unsupported extensions/PSKs/external proposals are not
                        // an implicit authorization or recovery mechanism.
                        _ => return Err(Error::InvalidMessage),
                    }
                }
                group
                    .merge_staged_commit(&working.0, *commit)
                    .map_err(|_| Error::InvalidMessage)?;
                verify_group_history(&group, trust, now)?;
                if renewal_only
                    && participant_device_keys(&group, trust, now)? != before_participants
                {
                    return Err(Error::Admission);
                }
                for participant in group.members() {
                    let identity = verify_historical_credential(
                        &participant.credential,
                        &participant.signature_key,
                        trust,
                        now,
                    )?;
                    if excluded.contains(&identity) {
                        return Err(Error::Admission);
                    }
                }
                Received::MembershipChanged
            }
            _ => return Err(Error::InvalidMessage),
        };
        std::mem::swap(&mut self.provider, &mut working.0);
        self.group = Some(group);
        if let Received::Text(text) = &received {
            self.history.push(TextMessage {
                member_id: text.member_id.clone(),
                text: text.text.clone(),
            });
        }
        Ok(received)
    }

    /// Renew an existing group's certificate with the same stable ID and signer.
    /// The trusted persistence callback receives the candidate member and exact
    /// outbound control bytes. It must atomically encrypt and durably save both
    /// snapshot and outbox entry before returning success. Failed writes and panics
    /// roll back local certificate and ratchet state. Returning the bytes does not
    /// guarantee network delivery or storage freshness after a device restart.
    pub fn renew_admission(
        &mut self,
        grant: AdmissionGrant,
        persist: impl FnOnce(&Member, &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.renew_admission_inner(grant, None, persist)
    }

    /// Renew this same device's root authorization and eligibility together,
    /// including after the old certificates expire. Recovery never changes the
    /// root-derived member identity, MLS signing key, or credential mode.
    pub fn renew_device_admission(
        &mut self,
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        persist: impl FnOnce(&Member, &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.renew_admission_inner(grant, Some(authorization), persist)
    }

    fn renew_admission_inner(
        &mut self,
        grant: AdmissionGrant,
        replacement_device: Option<DeviceAuthorization>,
        persist: impl FnOnce(&Member, &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let now = self.clock.now()?;
        let old_id = self.stored_member_id()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        if verify_admission(&grant, trust, &self.chat_public_key(), now)? != old_id {
            return Err(Error::Admission);
        }
        let current = self.group.as_ref().ok_or(Error::InvalidState)?;
        let own_leaf = current.own_leaf().ok_or(Error::InvalidState)?;
        if own_leaf.credential() != &self.credential.credential
            || own_leaf.signature_key().as_slice() != self.chat_public_key()
        {
            return Err(Error::InvalidState);
        }
        let mut working = WorkingProvider(OpenMlsRustCrypto::default());
        *working
            .0
            .storage()
            .values
            .write()
            .map_err(|_| Error::InvalidState)? = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::InvalidState)?
            .clone();
        let mut group = MlsGroup::load(working.0.storage(), current.group_id())
            .map_err(|_| Error::InvalidState)?
            .ok_or(Error::InvalidState)?;
        let old_device = self.device_authorization()?;
        if replacement_device.is_some() && old_device.is_none() {
            return Err(Error::Admission);
        }
        let encoded = if let Some(device_authorization) = replacement_device.or(old_device) {
            crate::verify_device_authorization(
                &device_authorization,
                &trust.community_id,
                &old_id,
                &self.chat_public_key(),
                now,
            )?;
            serde_json::to_vec(&DeviceCredential {
                admission: grant,
                device_authorization,
            })
        } else {
            serde_json::to_vec(&grant)
        }
        .map_err(|_| Error::Admission)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(encoded).into(),
            signature_key: self.chat_public_key().into(),
        };
        verify_renewal_advance(&self.credential.credential, &credential.credential)?;
        let parameters = LeafNodeParameters::builder()
            .with_credential_with_key(credential.clone())
            .build();
        let bundle = group
            .commit_builder()
            .consume_proposal_store(false)
            .leaf_node_parameters(parameters)
            .load_psks(working.0.storage())
            .map_err(|_| Error::InvalidState)?
            .build(working.0.rand(), working.0.crypto(), &self.signer, |_| {
                false
            })
            .map_err(|_| Error::InvalidState)?
            .stage_commit(&working.0)
            .map_err(|_| Error::InvalidState)?;
        let wire = bundle
            .into_commit()
            .tls_serialize_detached()
            .map_err(|_| Error::InvalidMessage)?;
        group
            .merge_pending_commit(&working.0)
            .map_err(|_| Error::InvalidState)?;
        verify_group_history(&group, trust, now)?;
        std::mem::swap(&mut self.provider, &mut working.0);
        let old_group = self.group.replace(group);
        let old_credential = std::mem::replace(&mut self.credential, credential);
        let mut guard = RenewalGuard {
            member: self,
            original_provider: working,
            original_group: old_group,
            original_credential: old_credential,
            committed: false,
        };
        persist(guard.member, &wire)?;
        guard.committed = true;
        Ok(wire)
    }

    /// Encrypt all ratchet state using a fresh data key, then wrap that key with
    /// the host's 32-byte wrapping material. The caller holds wrapping material only
    /// locally. `context` binds this envelope to the intended wallet/community.
    /// No password derivation, server escrow or plaintext persistence is provided.
    pub fn snapshot(&self, wrapping_key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        let storage = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::InvalidStore)?;
        let snapshot = SnapshotRef {
            storage: storage.iter().collect(),
            signer: &self.signer,
            credential: &self.credential,
            group_id: self.group.as_ref().map(|g| g.group_id()),
            trust: &self.trust,
            history: &self.history,
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&snapshot).map_err(|_| Error::InvalidStore)?);
        crate::vault::seal(&plaintext, wrapping_key, context)
    }

    pub(crate) fn staged_copy(&self, key: &[u8; 32], context: &[u8]) -> Result<Self, Error> {
        Self::restore_with_clock(
            &self.snapshot(key, context)?,
            key,
            context,
            self.clock.clone(),
        )
    }

    /// Revalidate private sealed pending state at its locally recorded time.
    /// The returned candidate always resumes the caller's live clock. Network
    /// callers must supply the current time, never a peer-claimed timestamp.
    pub(crate) fn inspect_at<T>(
        &self,
        at: u64,
        inspect: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        struct InspectionClock(u64);
        impl Clock for InspectionClock {
            fn now(&self) -> Result<u64, Error> {
                Ok(self.0)
            }
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *key).map_err(|_| Error::Randomness)?;
        let context = b"cmsg.private-replacement-inspection.v1";
        let mut candidate = Self::restore_with_clock(
            &self.snapshot(&key, context)?,
            &key,
            context,
            Arc::new(InspectionClock(at)),
        )?;
        let result = inspect(&mut candidate)?;
        candidate.clock = self.clock.clone();
        Ok((candidate, result))
    }

    /// A replacement invitation starts with exactly two current root-authorized
    /// device leaves. Additional devices require normal authenticated enrollment.
    pub(crate) fn replacement_peer(&self) -> Result<String, Error> {
        let own = self.member_id()?;
        if self.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let group = self.group.as_ref().ok_or(Error::InvalidState)?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let now = self.clock.now()?;
        let members: Vec<_> = group.members().collect();
        if members.len() != 2 {
            return Err(Error::Admission);
        }
        let mut peer = None;
        let mut self_found = false;
        for leaf in members {
            let id = verify_credential(&leaf.credential, &leaf.signature_key, trust, now)?;
            if credential_parts(&leaf.credential)?.1.is_none() {
                return Err(Error::Admission);
            }
            if id == own {
                if self_found || leaf.signature_key != self.chat_public_key() {
                    return Err(Error::Admission);
                }
                self_found = true;
            } else if peer.replace(id).is_some() {
                return Err(Error::Admission);
            }
        }
        if !self_found {
            return Err(Error::Admission);
        }
        peer.ok_or(Error::Admission)
    }

    /// Restores the exact saved ratchet state. Authenticating an old valid snapshot
    /// cannot detect rollback: monotonic local persistence is an integration need.
    pub fn restore(sealed: &[u8], wrapping_key: &[u8; 32], context: &[u8]) -> Result<Self, Error> {
        Self::restore_with_clock(
            sealed,
            wrapping_key,
            context,
            Arc::new(crate::lifecycle::SystemClock),
        )
    }

    /// Restore private state and reconnect its trusted local time source.
    pub fn restore_with_clock(
        sealed: &[u8],
        wrapping_key: &[u8; 32],
        context: &[u8],
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        let plaintext = crate::vault::open(sealed, wrapping_key, context)?;
        let mut snapshot: Snapshot =
            serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidStore)?;
        let mut working = WorkingProvider(OpenMlsRustCrypto::default());
        {
            let mut storage = working
                .0
                .storage()
                .values
                .write()
                .map_err(|_| Error::InvalidStore)?;
            for (key, value) in snapshot.storage.drain(..) {
                if storage.insert(key, value).is_some() {
                    return Err(Error::InvalidStore);
                }
            }
        }
        let group = snapshot
            .group_id
            .as_ref()
            .map(|id| {
                MlsGroup::load(working.0.storage(), id)
                    .map_err(|_| Error::InvalidStore)?
                    .ok_or(Error::InvalidStore)
            })
            .transpose()?;
        let restored = Self {
            provider: std::mem::take(&mut working.0),
            signer: snapshot.signer.take().ok_or(Error::InvalidStore)?,
            credential: snapshot.credential.clone(),
            group,
            trust: snapshot.trust.take(),
            history: std::mem::take(&mut snapshot.history),
            clock,
        };
        restored.validate_restored_state()?;
        Ok(restored)
    }

    fn validate_restored_state(&self) -> Result<(), Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use openmls_traits::signatures::Signer;
        let key = self.chat_public_key();
        if self.credential.signature_key.as_slice() != key {
            return Err(Error::InvalidStore);
        }
        // Check the stored public/private signing-key pair, not just two public
        // fields that an inconsistent serializer could copy together.
        let proof = self
            .signer
            .sign(b"cmsg.restore-key-consistency.v1")
            .map_err(|_| Error::InvalidStore)?;
        let public: [u8; 32] = key.as_slice().try_into().map_err(|_| Error::InvalidStore)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| Error::InvalidStore)?
            .verify_strict(
                b"cmsg.restore-key-consistency.v1",
                &Signature::from_slice(&proof).map_err(|_| Error::InvalidStore)?,
            )
            .map_err(|_| Error::InvalidStore)?;
        if self.trust.is_some() {
            self.stored_member_id().map_err(|_| Error::InvalidStore)?;
        } else if self.group.is_some() || !self.history.is_empty() {
            return Err(Error::InvalidStore);
        }
        if let Some(group) = &self.group {
            verify_group_history(
                group,
                self.trust.as_ref().ok_or(Error::InvalidStore)?,
                self.clock.now()?,
            )
            .map_err(|_| Error::InvalidStore)?;
            let own = group.own_leaf().ok_or(Error::InvalidStore)?;
            if own.credential() != &self.credential.credential
                || own.signature_key().as_slice() != key
            {
                return Err(Error::InvalidStore);
            }
        }
        for message in &self.history {
            if !crate::admission::valid_member_id(&message.member_id)
                || validate_text(message.text.as_bytes()).is_err()
            {
                return Err(Error::InvalidStore);
            }
        }
        Ok(())
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        if let Ok(mut storage) = self.provider.storage().values.write() {
            for value in storage.values_mut() {
                value.zeroize();
            }
            storage.clear();
        }
    }
}
#[derive(Serialize)]
struct SnapshotRef<'a> {
    storage: Vec<(&'a Vec<u8>, &'a Vec<u8>)>,
    signer: &'a SignatureKeyPair,
    credential: &'a CredentialWithKey,
    group_id: Option<&'a GroupId>,
    trust: &'a Option<AdmissionTrust>,
    history: &'a [TextMessage],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    storage: Vec<(Vec<u8>, Vec<u8>)>,
    signer: Option<SignatureKeyPair>,
    credential: CredentialWithKey,
    group_id: Option<GroupId>,
    trust: Option<AdmissionTrust>,
    history: Vec<TextMessage>,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        for (_, value) in &mut self.storage {
            value.zeroize();
        }
    }
}

struct WorkingProvider(OpenMlsRustCrypto);
impl Drop for WorkingProvider {
    fn drop(&mut self) {
        if let Ok(mut storage) = self.0.storage().values.write() {
            for value in storage.values_mut() {
                value.zeroize();
            }
            storage.clear();
        }
    }
}
fn verify_credential(
    credential: &Credential,
    key: &[u8],
    trust: &AdmissionTrust,
    now: u64,
) -> Result<String, Error> {
    let (grant, device) = credential_parts(credential)?;
    let identity = verify_admission(&grant, trust, key, now)?;
    if let Some(device) = device {
        crate::verify_device_authorization(&device, &trust.community_id, &identity, key, now)?;
    }
    Ok(identity)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceCredential {
    admission: AdmissionGrant,
    device_authorization: DeviceAuthorization,
}

fn credential_grant(credential: &Credential) -> Result<AdmissionGrant, Error> {
    Ok(credential_parts(credential)?.0)
}

pub(crate) fn verify_bound_identity_bytes(
    bytes: &[u8],
    key: &[u8],
    trust: &AdmissionTrust,
    at: u64,
) -> Result<String, Error> {
    if bytes.len() > 8192 {
        return Err(Error::Admission);
    }
    let credential: Credential = BasicCredential::new(bytes.to_vec()).into();
    if credential_parts(&credential)?.1.is_none() {
        return Err(Error::Admission);
    }
    verify_credential(&credential, key, trust, at)
}

fn credential_parts(
    credential: &Credential,
) -> Result<(AdmissionGrant, Option<DeviceAuthorization>), Error> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| Error::Admission)?;
    if basic.identity().len() > 8192 {
        return Err(Error::Admission);
    }
    if let Ok(bound) = serde_json::from_slice::<DeviceCredential>(basic.identity()) {
        return Ok((bound.admission, Some(bound.device_authorization)));
    }
    serde_json::from_slice(basic.identity())
        .map(|grant| (grant, None))
        .map_err(|_| Error::Admission)
}
fn verify_historical_credential(
    credential: &Credential,
    key: &[u8],
    trust: &AdmissionTrust,
    now: u64,
) -> Result<String, Error> {
    let (grant, device) = credential_parts(credential)?;
    if grant.issued_at > now {
        return Err(Error::Admission);
    }
    let identity = verify_admission(&grant, trust, key, grant.issued_at)?;
    if let Some(device) = device {
        if device.issued_at > now
            || device.expires_at <= grant.issued_at
            || grant.expires_at <= device.issued_at
        {
            return Err(Error::Admission);
        }
        crate::verify_device_authorization(
            &device,
            &trust.community_id,
            &identity,
            key,
            device.issued_at,
        )?;
    }
    Ok(identity)
}
fn verify_group_history(group: &MlsGroup, trust: &AdmissionTrust, now: u64) -> Result<(), Error> {
    group_devices(group, trust, now).map(|_| ())
}
fn group_devices(
    group: &MlsGroup,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<BTreeSet<Vec<u8>>, Error> {
    let mut devices = BTreeSet::new();
    let mut root_bound = None;
    for member in group.members() {
        verify_historical_credential(&member.credential, &member.signature_key, trust, now)?;
        let bound = credential_parts(&member.credential)?.1.is_some();
        if root_bound.is_some_and(|expected| bound != expected) {
            return Err(Error::Admission);
        }
        root_bound = Some(bound);
        if !devices.insert(member.signature_key) {
            return Err(Error::Admission);
        }
    }
    Ok(devices)
}

fn verify_leaf_change(
    old: &Credential,
    old_key: &[u8],
    leaf: &LeafNode,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<(), Error> {
    let old_id = verify_historical_credential(old, old_key, trust, now)?;
    let new_id = verify_credential(
        leaf.credential(),
        leaf.signature_key().as_slice(),
        trust,
        now,
    )?;
    if old_key != leaf.signature_key().as_slice()
        || old_id != new_id
        || credential_parts(old)?.1.is_some() != credential_parts(leaf.credential())?.1.is_some()
    {
        return Err(Error::Admission);
    }
    if old != leaf.credential() {
        verify_renewal_advance(old, leaf.credential())?;
    }
    Ok(())
}

fn verify_renewal_advance(old: &Credential, new: &Credential) -> Result<(), Error> {
    let (old_grant, old_device) = credential_parts(old)?;
    let (new_grant, new_device) = credential_parts(new)?;
    if new_grant.issued_at < old_grant.issued_at || new_grant.expires_at < old_grant.expires_at {
        return Err(Error::Admission);
    }
    let mut extended = new_grant.expires_at > old_grant.expires_at;
    match (old_device, new_device) {
        (Some(old), Some(new)) => {
            if new.root_public_key != old.root_public_key
                || new.device_public_key != old.device_public_key
                || new.member_id != old.member_id
                || new.community_id != old.community_id
                || new.issued_at < old.issued_at
                || new.expires_at < old.expires_at
            {
                return Err(Error::Admission);
            }
            extended |= new.expires_at > old.expires_at;
        }
        (None, None) => (),
        _ => return Err(Error::Admission),
    }
    if !extended {
        return Err(Error::Admission);
    }
    Ok(())
}

pub(crate) struct PreparedJoin {
    working: WorkingProvider,
    group: MlsGroup,
    pub(crate) inviter: String,
}

impl PreparedJoin {
    pub(crate) fn contains_any(
        &self,
        identities: &BTreeSet<String>,
        trust: &AdmissionTrust,
        now: u64,
    ) -> Result<bool, Error> {
        for member in self.group.members() {
            if identities.contains(&verify_historical_credential(
                &member.credential,
                &member.signature_key,
                trust,
                now,
            )?) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct JoinGuard<'a> {
    member: &'a mut Member,
    original: WorkingProvider,
    committed: bool,
}
impl Drop for JoinGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.member.group = None;
            std::mem::swap(&mut self.member.provider, &mut self.original.0);
        }
    }
}

struct RenewalGuard<'a> {
    member: &'a mut Member,
    original_provider: WorkingProvider,
    original_group: Option<MlsGroup>,
    original_credential: CredentialWithKey,
    committed: bool,
}
impl Drop for RenewalGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            std::mem::swap(&mut self.member.provider, &mut self.original_provider.0);
            std::mem::swap(&mut self.member.group, &mut self.original_group);
            std::mem::swap(&mut self.member.credential, &mut self.original_credential);
        }
    }
}

#[cfg(test)]
mod snapshot_validation_tests {
    use super::*;

    const KEY: [u8; 32] = [47; 32];
    const CONTEXT: &[u8] = b"synthetic-malformed-state";

    fn encoded_snapshot(member: &Member) -> serde_json::Value {
        let sealed = member.snapshot(&KEY, CONTEXT).unwrap();
        serde_json::from_slice(&crate::vault::open(&sealed, &KEY, CONTEXT).unwrap()).unwrap()
    }

    fn restore_value(value: &serde_json::Value) -> Result<Member, Error> {
        let plaintext = Zeroizing::new(serde_json::to_vec(value).unwrap());
        let sealed = crate::vault::seal(&plaintext, &KEY, CONTEXT).unwrap();
        Member::restore(&sealed, &KEY, CONTEXT)
    }

    #[test]
    fn authenticated_but_inconsistent_snapshots_are_rejected() {
        let member = Member::new().unwrap();
        let valid = encoded_snapshot(&member);
        assert!(restore_value(&valid).is_ok());
        let other = encoded_snapshot(&Member::new().unwrap());
        let mut wrong_signer = valid.clone();
        wrong_signer["signer"] = other["signer"].clone();
        assert!(restore_value(&wrong_signer).is_err());
        let mut duplicate_storage = valid.clone();
        let first = duplicate_storage["storage"][0].clone();
        assert!(!first.is_null());
        duplicate_storage["storage"]
            .as_array_mut()
            .unwrap()
            .push(first);
        assert!(restore_value(&duplicate_storage).is_err());
        let mut unknown_field = valid.clone();
        unknown_field["unknown_security_override"] = true.into();
        assert!(restore_value(&unknown_field).is_err());
        let mut injected_history = valid;
        injected_history["history"] =
            serde_json::json!([{"member_id":"forged", "text":"injected"}]);
        assert!(restore_value(&injected_history).is_err());
    }
}
