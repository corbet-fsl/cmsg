//! The creating device's proof of a new community's accounting genesis. The hub
//! names the policies in its terms; the device proves one throwaway genesis under
//! them for exactly that community and uploads the statement with the proof.
use super::genesis::{engine_account_policy, engine_extension_policy};
use super::*;
use serde_json::Value;

/// A finished activation: the statement as cvld's `AccountStatement` JSON and the proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Activation {
    pub statement: Value,
    pub proof: Vec<u8>,
}

/// Where a background activation proof stands.
#[derive(Debug)]
pub enum ActivationPoll {
    /// Still being proved; ask again later. Nothing for the person to do.
    Pending,
    Ready(Activation),
    /// The proof failed (prover or terms); a new poll starts it again.
    Failed,
}

/// The device's prover for activation proofs, lent by the trusted embedder. A poll
/// starts the proof in the background the first time and never blocks the Door.
pub trait ActivationProver: Send + Sync {
    /// `owner` is the one-time value the proof must bind (`czkp::activation_owner`).
    fn poll(&self, address: &str, owner: [u8; 32], terms: &Value) -> ActivationPoll;
}

/// Prove synchronously (the caller runs this off the Door's executor).
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub fn prove(
    prover: &ckmg::wallet_engine::native_prover::NativeProver,
    address: &str,
    owner: [u8; 32],
    terms: &Value,
) -> Result<Activation> {
    use ckmg::wallet_engine::account as engine;
    let account: cblc::accounting::AccountPolicy = serde_json::from_value(
        terms
            .get("ledger_policy")
            .and_then(|ledger| ledger.get("account"))
            .cloned()
            .ok_or(ErrorCode::InvalidRequest)?,
    )
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let extension: cblc::extensions::ExtensionPolicy = serde_json::from_value(
        terms
            .get("extension_policy")
            .cloned()
            .ok_or(ErrorCode::InvalidRequest)?,
    )
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    // The values of the community's rulebook as the hub resolved them; the engine
    // refuses the proof unless their digest is the extension policy's.
    let values: std::collections::BTreeMap<String, Value> = serde_json::from_value(
        terms
            .get("standing")
            .cloned()
            .ok_or(ErrorCode::InvalidRequest)?,
    )
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let standing = crbk::standing_params(&values).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let observed = terms
        .get("observed_at")
        .and_then(Value::as_u64)
        .ok_or(ErrorCode::InvalidRequest)?;
    let proven = engine::prove_activation(
        prover,
        engine::ActivationRequest {
            community_id: address.to_owned(),
            policy: engine_account_policy(&account),
            extension: engine_extension_policy(&extension),
            standing,
            checked_at: observed,
            owner,
        },
    )
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    let public = &proven.public;
    let statement = cblc::accounting::AccountStatement {
        protocol_version: public.protocol_version,
        community: public.community,
        owner: public.owner,
        policy_digest: public.policy_digest,
        enrollment_root: public.enrollment_root,
        now: public.now,
        valid_until: public.valid_until,
        genesis: public.genesis,
        previous_version: public.previous_version,
        next_version: public.next_version,
        previous_state: public.previous_state,
        next_state: public.next_state,
        settlement_marker: public.settlement_marker,
        policy: account.clone(),
    };
    cblc::accounting::statement_bytes(&statement).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unauthorized",
            ErrorCode::Unauthorized,
            &__cause,
        )
    })?;
    // The ledger verifies an activation as an extension update bundle.
    Ok(Activation {
        statement: serde_json::to_value(&statement).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?,
        proof: super::request::genesis_bundle(&statement.next_state, &proven.proof)?,
    })
}

/// Runs each address's proof once on its own thread; a poll reads the outcome.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub struct NativeActivationProver {
    artifacts: super::super::composer::ProverArtifacts,
    jobs: std::sync::Mutex<
        std::collections::HashMap<
            String,
            std::sync::Arc<std::sync::Mutex<Option<Result<Activation>>>>,
        >,
    >,
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
impl NativeActivationProver {
    pub fn new(artifacts: super::super::composer::ProverArtifacts) -> Self {
        Self {
            artifacts,
            jobs: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
impl ActivationProver for NativeActivationProver {
    fn poll(&self, address: &str, owner: [u8; 32], terms: &Value) -> ActivationPoll {
        let Ok(mut jobs) = self.jobs.lock() else {
            return ActivationPoll::Failed;
        };
        // One job per creation: the same address with another token is another proof.
        let key = format!(
            "{address}/{}",
            owner.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        if let Some(job) = jobs.get(&key) {
            let Ok(mut slot) = job.lock() else {
                return ActivationPoll::Failed;
            };
            return match slot.take() {
                None => ActivationPoll::Pending,
                Some(Ok(activation)) => {
                    drop(slot);
                    jobs.remove(&key);
                    ActivationPoll::Ready(activation)
                }
                Some(Err(__cause)) => {
                    crate::door::cause::print(file!(), line!(), "ActivationPoll::Failed", &__cause);
                    drop(slot);
                    jobs.remove(&key);
                    ActivationPoll::Failed
                }
            };
        }
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        jobs.insert(key, slot.clone());
        let (artifacts, address, terms) =
            (self.artifacts.clone(), address.to_owned(), terms.clone());
        std::thread::spawn(move || {
            let result = artifacts
                .prover()
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })
                .and_then(|prover| prove(&prover, &address, owner, &terms));
            if let Ok(mut slot) = slot.lock() {
                *slot = Some(result);
            }
        });
        ActivationPoll::Pending
    }
}
