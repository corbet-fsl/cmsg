//! Original account admission and delegation from retained device-local owners.
use super::{custody::SystemClock, foyer::Transport, ErrorCode, Result};
use cblc::{admission, enrollment};
use ckmg::{Authority, Clock, Entropy};
use cvlt::{CommunityAccountCustody, Records, Vault};
use cwlt::passport::{self, AuthenticatedCommunity, CommunityId};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use sha2::{Digest, Sha256};
mod activation;
mod checkpoint;
mod custody;
mod genesis;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
mod lifecycle;
mod pending;
mod request;
pub use activation::{Activation, ActivationPoll, ActivationProver};
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use activation::{prove as prove_activation, NativeActivationProver};
pub use checkpoint::{CheckpointAcquisition, CurrentEnrollment, SubmittedEnrollment};
pub use custody::CommunityAccount;
pub use genesis::PreparedAccount;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use genesis::{ProvenAccount, StagedRequest};
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use lifecycle::{existing_active, has_pending, Activated};
pub use pending::PendingBinding;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use request::response_trust;
pub use request::{AcceptedResponse, ProvenGenesis, SignedApplyExtended};

/// Distinct local intentions reserved by the trusted recovery composer. No
/// caller can admit arbitrary transcript bytes through this opaque owner.
pub struct AccountingIntents {
    pub(super) root: ckmg::IntentAdmission,
    pub(super) device: ckmg::IntentAdmission,
    pub(super) expires: u64,
}

struct Cohort {
    scope: String,
    member: String,
    device: [u8; 32],
    signed: Vec<u8>,
    epoch: u64,
    digest: String,
}

/// Actual account response joined to the same durable global passport proof.
/// The issuer grant remains subject to original current-policy verification.
pub struct AccountAdmission<'p> {
    lease: cfyr::membership::AccountGrantLease<'p, Transport>,
    cohort: Cohort,
}

/// Signed original delegation while the same HTTPS owner and separate local
/// intent guards remain held. This is not an enrolled account or a frontier.
pub struct PreparedEnrollment<'p> {
    admission: AccountAdmission<'p>,
    delegation: enrollment::AccountingDelegation,
    _root: ckmg::IntentGuard,
    _device: ckmg::IntentGuard,
}

struct CurrentAdmission {
    material: cblc::publication::PublicVerifierMaterial,
    /// The standing and voucher parameters of the same verified rulebook; the engine
    /// refuses a genesis unless their digest is the material's published one.
    standing: czkp::standing::Params,
    material_digest: [u8; 32],
    trust: admission::AdmissionTrust,
    grant: admission::AdmissionGrant,
    origin: String,
    now: u64,
    expires: u64,
}

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

/// Present the existing durable global holder to the exact origin-authenticated
/// community challenge. Neither caller passport bytes nor a supplied grant can
/// construct AccountAdmission. The community device must be currently listed by
/// the real HTTPS owner, and later match actual community Keys during signing.
/// Use an independently authenticated Foyer for this challenge when community
/// Keys retain a session lease: the original pending owner refuses a second
/// lease on that same Foyer before waiting on its session mutex.
pub async fn issue_account_admission<'p, B, C, E, A, R, G>(
    mut challenge: cfyr::membership::AccountChallenge<'p, Transport>,
    global: &mut super::passport::GlobalPassport<B, C, E, A, R>,
    device: [u8; 32],
    rng: &mut G,
    creation: Option<&str>,
) -> Result<AccountAdmission<'p>>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    G: passport::rand::RngCore + passport::rand::CryptoRng,
{
    // The creator of a community presents the creation id of the claim it made, so
    // this one admission seats it as first admin; everyone else sends nothing.
    if let Some(id) = creation {
        challenge = challenge.with_creation(id.to_owned());
    }
    let (proof, cohort) = global
        .with_global_passport(|holder| {
            challenge
                .with_current(now, |current, member, _, signed, checked| {
                    if current.community() == "wallet" || !member.device_keys.contains(&device) {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let scope = CommunityId::new(current.community().as_bytes())
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    if HEX.encode(&holder.pseudonym(&scope).to_bytes()) != member.member {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let expected = AuthenticatedCommunity::from_authenticated_origin(
                        scope,
                        current.key_ring().clone(),
                    );
                    let request = expected
                        .authenticate(signed, checked)
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    if request.policy_epoch() != current.policy_epoch() {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let expiry = request.epoch_expiry().ok_or(ErrorCode::Unauthorized)?;
                    let gates = request
                        .required_gates()
                        .iter()
                        .map(|gate| gate.as_str().to_owned())
                        .collect();
                    let digest = B64.encode(&admission::passport_cohort_digest(
                        request.policy_epoch(),
                        expiry,
                        &gates,
                    ));
                    let proof = holder
                        .present(rng, &expected, signed, checked)
                        .map_err(|_| ErrorCode::Unauthorized)?
                        .to_bytes();
                    Ok((
                        proof,
                        Cohort {
                            scope: current.community().into(),
                            member: member.member.clone(),
                            device,
                            signed: signed.to_vec(),
                            epoch: request.policy_epoch(),
                            digest,
                        },
                    ))
                })
                .map_err(|_| ErrorCode::Unauthorized)?
        })
        .await
        .map_err(|_| ErrorCode::Unauthorized)??;
    // Proof generation and the global owner's fresh post-check may have waited.
    // Re-authenticate the original still-live challenge before issuing anything.
    challenge
        .with_current(now, |current, member, _, signed, checked| {
            cohort.check(current, member, signed, device)?;
            let expected = AuthenticatedCommunity::from_authenticated_origin(
                CommunityId::new(current.community().as_bytes())
                    .map_err(|_| ErrorCode::Unauthorized)?,
                current.key_ring().clone(),
            );
            expected
                .authenticate(signed, checked)
                .map_err(|_| ErrorCode::Unauthorized)?;
            Ok(())
        })
        .map_err(|_| ErrorCode::Unauthorized)??;
    let lease = challenge
        .finish(proof, device, now)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    let mut result = AccountAdmission { lease, cohort };
    result.current().map_err(|_| ErrorCode::Reconcile)?;
    Ok(result)
}

impl Cohort {
    fn check(
        &self,
        current: &cchr::VerifiedCharter,
        member: &cfyr::membership::Observation,
        signed: &[u8],
        device: [u8; 32],
    ) -> Result<()> {
        if current.community() != self.scope
            || current.policy_epoch() != self.epoch
            || member.member != self.member
            || signed != self.signed
            || device != self.device
            || !member.device_keys.contains(&device)
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }
}

impl AccountAdmission<'_> {
    /// The signed community credential the server issued with this admission,
    /// exactly as returned. Public data; the caller stores it in the Vault.
    pub fn community_credential(&self) -> &[u8] {
        self.lease.community_credential()
    }

    fn current(&mut self) -> Result<CurrentAdmission> {
        let cohort = &self.cohort;
        self.lease
            .with_current(
                now,
                |current, member, origin, signed, wire, device, checked| {
                    cohort.check(current, member, signed, device)?;
                    let balance = current.balance().ok_or(ErrorCode::Unavailable)?;
                    if checked >= balance.valid_until() {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let material: cblc::publication::PublicVerifierMaterial =
                        serde_json::from_slice(balance.payload())
                            .map_err(|_| ErrorCode::Unauthorized)?;
                    material
                        .validate_at(current.community(), checked)
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    if material.policy_epoch != current.policy_epoch()
                        || material.revision != balance.revision()
                    {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let trust = admission::AdmissionTrust {
                        community_id: current.community().into(),
                        policy_digest: B64.encode(&material.admission_policy_digest),
                        policy_keys: current.key_ring().clone(),
                    };
                    let grant: admission::AdmissionGrant = serde_json::from_value(wire.clone())
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    admission::verify_admission(&grant, &trust, checked)
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    if grant.policy_epoch != cohort.epoch
                        || grant.passport_policy_digest != cohort.digest
                        || grant.pseudonym != cohort.member
                        || grant.chat_public_key != B64.encode(&device)
                    {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let expires = grant
                        .expires_at
                        .min(member.expires)
                        .min(current.valid_until())
                        .min(balance.valid_until());
                    if checked >= expires {
                        return Err(ErrorCode::Unauthorized);
                    }
                    let standing = current
                        .settings(checked)
                        .map_err(|_| ErrorCode::Unauthorized)?
                        .standing_params()
                        .map_err(|_| ErrorCode::Unauthorized)?;
                    Ok(CurrentAdmission {
                        standing,
                        material_digest: Sha256::digest(balance.payload()).into(),
                        material,
                        trust,
                        grant,
                        origin: origin.into(),
                        now: checked,
                        expires,
                    })
                },
            )
            .map_err(|_| ErrorCode::Unauthorized)?
    }
}

impl<'p> AccountAdmission<'p> {
    /// Bind only this existing durable account coordinate to the original root
    /// and device authorization transcripts. All awaits are followed by current
    /// issuer/Charter and actual Keys checks; each signer consumes separate intent.
    pub async fn delegate<B, C, E, A, R>(
        mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        intents: &mut AccountingIntents,
    ) -> Result<PreparedEnrollment<'p>>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let admitted_origin = self.current()?.origin;
        account.check(&admitted_origin).await?;
        let coordinate = account
            .vault
            .account_projection()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let current = self.current()?;
        let expires = current.expires.min(intents.expires);
        let plan = account
            .vault
            .keys()
            .prepare_account_device(expires)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let current = self.current()?;
        if plan.binding().community() != self.cohort.scope
            || plan.binding().member() != self.cohort.member
            || plan.device().value() != &self.cohort.device
            || expires > current.expires
            || current.now >= expires
        {
            return Err(ErrorCode::Unauthorized);
        }
        let command = ckmg::AdmittedCommand {
            binding: plan.binding().clone(),
            origin: current.origin.clone(),
            action: ckmg::Action::AuthorizeAccountDevice,
            device: plan.device(),
            root: Some(plan.root()),
            epoch: plan.epoch(),
            target: None,
            statement: None,
            transcript: Some(plan.signing_bytes().to_vec()),
            expires,
        };
        let root = intents
            .root
            .admit(command, current.now)
            .map_err(|_| ErrorCode::Unauthorized)?;
        let authorization = account
            .vault
            .keys()
            .authorize_account_device(plan)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let current = self.current()?;
        if expires > current.expires {
            return Err(ErrorCode::Unauthorized);
        }
        let authorization: admission::DeviceAuthorization = serde_json::from_slice(
            &authorization
                .to_bytes()
                .map_err(|_| ErrorCode::Unauthorized)?,
        )
        .map_err(|_| ErrorCode::Unauthorized)?;
        admission::verify_device_authorization(&authorization, &current.grant, current.now)
            .map_err(|_| ErrorCode::Unauthorized)?;
        let mut delegation = enrollment::AccountingDelegation {
            version: 1,
            hash_scheme: enrollment::ACCOUNT_HASH_SCHEME.into(),
            admission: current.grant,
            authorization,
            account_public_key: HEX.encode(&coordinate.public_key),
            state_secret_commitment: HEX.encode(&coordinate.registered_secret),
            issued_at: current.now,
            expires_at: expires,
            signature: String::new(),
        };
        let transcript = delegation
            .signing_bytes()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let lineage = account
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = account
            .vault
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let current = self.current()?;
        if lineage.binding.community() != self.cohort.scope
            || lineage.binding.member() != self.cohort.member
            || device.value() != &self.cohort.device
            || B64.encode(lineage.root.value()) != delegation.authorization.root_public_key
            || current.grant != delegation.admission
            || current.now >= expires
            || expires > current.expires
        {
            return Err(ErrorCode::Unauthorized);
        }
        let admitted = intents
            .device
            .admit(
                ckmg::AdmittedCommand {
                    binding: lineage.binding,
                    origin: current.origin,
                    action: ckmg::Action::SignDeviceEd25519,
                    device,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: None,
                    statement: None,
                    transcript: Some(transcript.clone()),
                    expires,
                },
                current.now,
            )
            .map_err(|_| ErrorCode::Unauthorized)?;
        let signature = account
            .vault
            .keys()
            .sign_device_ed25519_current(&transcript, expires)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        delegation.signature = B64.encode(&signature);
        account.check(&admitted_origin).await?;
        let mut prepared = PreparedEnrollment {
            admission: self,
            delegation,
            _root: root,
            _device: admitted,
        };
        prepared.with_current(|_| ())?;
        Ok(prepared)
    }
}

impl<'p> PreparedEnrollment<'p> {
    /// Submit this exact signed delegation to the original current member host.
    /// The response is only the matching registry entry. Common checkpoint
    /// publication and initialized-account proof acceptance remain separate.
    pub async fn submit(self) -> Result<enrollment::EnrollmentEntry> {
        Ok(self.submit_for_initialization().await?.entry)
    }

    /// Retain the same actual admission owner for current checkpoint acquisition.
    /// The returned registry receipt still proves no common-root installation.
    pub async fn submit_for_initialization(mut self) -> Result<SubmittedEnrollment<'p>> {
        let expected = self.expected_entry()?;
        let wire = serde_json::to_value(&self.delegation).map_err(|_| ErrorCode::InvalidRequest)?;
        let response = self
            .admission
            .lease
            .submit_enrollment(wire, now)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        let response: enrollment::EnrollmentEntry =
            serde_json::from_value(response).map_err(|_| ErrorCode::Reconcile)?;
        let current = self.expected_entry().map_err(|_| ErrorCode::Reconcile)?;
        if response != expected || current != expected {
            return Err(ErrorCode::Reconcile);
        }
        Ok(SubmittedEnrollment {
            prepared: self,
            entry: response,
        })
    }

    fn expected_entry(&mut self) -> Result<enrollment::EnrollmentEntry> {
        let current = self.admission.current()?;
        let verified = enrollment::verify_delegation(
            &self.delegation,
            enrollment::ExpectedAdmission {
                trust: &current.trust,
                policy_epoch: self.admission.cohort.epoch,
                passport_policy_digest: &self.admission.cohort.digest,
            },
            current.now,
        )
        .map_err(|_| ErrorCode::Unauthorized)?;
        Ok(enrollment::EnrollmentEntry::from_verified(&verified))
    }
    /// Reborrow the exact public original request only while the retained owner
    /// still verifies it. The recipient must independently perform original
    /// enrollment verification; these public bytes never install an account.
    pub fn with_current<T>(
        &mut self,
        use_delegation: impl FnOnce(&enrollment::AccountingDelegation) -> T,
    ) -> Result<T> {
        let current = self.admission.current()?;
        enrollment::verify_delegation(
            &self.delegation,
            enrollment::ExpectedAdmission {
                trust: &current.trust,
                policy_epoch: self.admission.cohort.epoch,
                passport_policy_digest: &self.admission.cohort.digest,
            },
            current.now,
        )
        .map_err(|_| ErrorCode::Unauthorized)?;
        let output = use_delegation(&self.delegation);
        let completed = self.admission.current()?;
        if completed.now >= self.delegation.expires_at {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(output)
    }
}
