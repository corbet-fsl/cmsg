use crate::{
    validate_text, verify_admission, AdmissionGrant, AdmissionTrust, Clock, Error, Participant,
    ParticipantHandle, MAX_WIRE_BYTES,
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

pub enum Received {
    Text(TextMessage),
    MembershipChanged,
}
impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => f.write_str("Text([redacted])"),
            Self::MembershipChanged => f.write_str("MembershipChanged"),
        }
    }
}

/// One independently generated, conversation-scoped MLS identity.
/// Never reuse it as a global account identifier across communities.
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

    /// Supply this public key to cvld during passkey-authorized admission.
    pub fn chat_public_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Bind the issuer-certified stable community identity to this MLS signing key.
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
        let mut identities =
            group_identities(self.group.as_ref().ok_or(Error::InvalidState)?, trust, now)?;
        let mut validated = Vec::with_capacity(packages.len());
        for wire in packages {
            if wire.len() > MAX_WIRE_BYTES {
                return Err(Error::InvalidMessage);
            }
            let package = KeyPackageIn::tls_deserialize_exact(wire)
                .map_err(|_| Error::InvalidMessage)?
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| Error::InvalidMessage)?;
            let identity = verify_credential(
                package.leaf_node().credential(),
                package.leaf_node().signature_key().as_slice(),
                trust,
                now,
            )?;
            if !identities.insert(identity) {
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

    pub(crate) fn prepare_join(&self, welcome: &[u8]) -> Result<PreparedJoin, Error> {
        self.member_id()?;
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
        let inviter = verify_credential(
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
    /// Duplicate stable IDs are rejected until a multi-device protocol is defined.
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
        let wire = self
            .group
            .as_mut()
            .ok_or(Error::InvalidState)?
            .create_message(&self.provider, &self.signer, text)
            .map_err(|_| Error::InvalidMessage)?
            .tls_serialize_detached()
            .map_err(|_| Error::InvalidMessage)?;
        self.history.push(TextMessage {
            member_id,
            text: validate_text(text)?.to_owned(),
        });
        Ok(wire)
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Received, Error> {
        self.process_incoming(wire, false)
    }

    /// Process only authenticated control while a local certificate is expired.
    /// Application messages are rejected without changing ratchets or history.
    pub fn receive_control(&mut self, wire: &[u8]) -> Result<(), Error> {
        match self.process_incoming(wire, true)? {
            Received::MembershipChanged => Ok(()),
            Received::Text(_) => Err(Error::InvalidMessage),
        }
    }

    fn process_incoming(&mut self, wire: &[u8], control_only: bool) -> Result<Received, Error> {
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
        let sender_credential = processed.credential().clone();
        verify_historical_credential(&sender_credential, &sender.signature_key, trust, now)?;
        let received = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = Zeroizing::new(application.into_bytes());
                if control_only {
                    return Err(Error::InvalidMessage);
                }
                let member_id =
                    verify_credential(&sender_credential, &sender.signature_key, trust, now)?;
                Received::Text(TextMessage {
                    member_id,
                    text: validate_text(&bytes)?.to_owned(),
                })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
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
        let now = self.clock.now()?;
        let old_id = self.stored_member_id()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        if verify_admission(&grant, trust, &self.chat_public_key(), now)? != old_id {
            return Err(Error::Admission);
        }
        let old_grant = credential_grant(&self.credential.credential)?;
        if grant.issued_at < old_grant.issued_at || grant.expires_at <= old_grant.expires_at {
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
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                serde_json::to_vec(&grant).map_err(|_| Error::Admission)?,
            )
            .into(),
            signature_key: self.chat_public_key().into(),
        };
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
    /// cvld's 32-byte PRF-derived material. The caller holds wrapping material only
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
        let provider = OpenMlsRustCrypto::default();
        {
            let mut storage = provider
                .storage()
                .values
                .write()
                .map_err(|_| Error::InvalidStore)?;
            storage.extend(snapshot.storage.drain(..));
        }
        let group = snapshot
            .group_id
            .as_ref()
            .map(|id| {
                MlsGroup::load(provider.storage(), id)
                    .map_err(|_| Error::InvalidStore)?
                    .ok_or(Error::InvalidStore)
            })
            .transpose()?;
        Ok(Self {
            provider,
            signer: snapshot.signer.take().ok_or(Error::InvalidStore)?,
            credential: snapshot.credential.clone(),
            group,
            trust: snapshot.trust.take(),
            history: std::mem::take(&mut snapshot.history),
            clock,
        })
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
    let grant = credential_grant(credential)?;
    verify_admission(&grant, trust, key, now)
}
fn credential_grant(credential: &Credential) -> Result<AdmissionGrant, Error> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| Error::Admission)?;
    if basic.identity().len() > 4096 {
        return Err(Error::Admission);
    }
    serde_json::from_slice(basic.identity()).map_err(|_| Error::Admission)
}
fn verify_historical_credential(
    credential: &Credential,
    key: &[u8],
    trust: &AdmissionTrust,
    now: u64,
) -> Result<String, Error> {
    let grant = credential_grant(credential)?;
    if grant.issued_at > now {
        return Err(Error::Admission);
    }
    verify_admission(&grant, trust, key, grant.issued_at)
}
fn verify_group_history(group: &MlsGroup, trust: &AdmissionTrust, now: u64) -> Result<(), Error> {
    group_identities(group, trust, now).map(|_| ())
}
fn group_identities(
    group: &MlsGroup,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<BTreeSet<String>, Error> {
    let mut identities = BTreeSet::new();
    for member in group.members() {
        let id =
            verify_historical_credential(&member.credential, &member.signature_key, trust, now)?;
        if !identities.insert(id) {
            return Err(Error::Admission);
        }
    }
    Ok(identities)
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
    if old_key != leaf.signature_key().as_slice() || old_id != new_id {
        return Err(Error::Admission);
    }
    if old != leaf.credential() {
        let old_grant = credential_grant(old)?;
        let new_grant = credential_grant(leaf.credential())?;
        if new_grant.issued_at < old_grant.issued_at || new_grant.expires_at <= old_grant.expires_at
        {
            return Err(Error::Admission);
        }
    }
    Ok(())
}

pub(crate) struct PreparedJoin {
    working: WorkingProvider,
    group: MlsGroup,
    pub(crate) inviter: String,
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
