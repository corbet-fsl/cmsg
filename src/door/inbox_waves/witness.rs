//! The account witness shared between the wave ports and the proof worker, and the update
//! sink that carries a proven update to the community accounting through the D2 update
//! actor (`Door::account_update`).
//!
//! | Piece | Role |
//! |---|---|
//! | [`WitnessCell`] | the newest accepted witness, read by the ports ([`AccountView`]) and kept by the wallet ([`WalletState`]) |
//! | [`WitnessStore`] | durable save of a new witness (the embedding seals it with `Account::seal` into the Vault `witness_state` record) |
//! | [`UpdateTransport`] | the D2 actor: store-before-send, resend unchanged, settle |
//! | [`DoorUpdateSink`] | candidate and proof in, issuer certificate out |
use super::account_ports::AccountView;
use super::wallet::{UpdateSink, WalletState};
use super::super::{
    accounting::ProvenUpdate,
    account::{Applied, Shared},
    facades::OwnedFuture,
    ErrorCode, Result,
};
use cblc::accounting::AccountProofScope;
use ckmg::wallet_engine::account::{Account, Candidate, Certificate};
use std::sync::{Arc, Mutex};

/// The newest accepted account witness of this device. Clones share one state.
#[derive(Clone)]
pub struct WitnessCell(Arc<Mutex<Account>>);

impl WitnessCell {
    pub fn new(account: Account) -> Self {
        Self(Arc::new(Mutex::new(account)))
    }

    pub fn snapshot(&self) -> Result<Account> {
        self.0
            .lock()
            .map(|account| account.clone())
            .map_err(|_| ErrorCode::Unavailable)
    }

    fn replace(&self, account: &Account) -> Result<()> {
        *self.0.lock().map_err(|_| ErrorCode::Unavailable)? = account.clone();
        Ok(())
    }
}

impl AccountView for WitnessCell {
    fn current<'a>(&'a self) -> OwnedFuture<'a, Account> {
        Box::pin(async move { self.snapshot() })
    }
}

/// Makes a new witness state durable.
#[allow(async_fn_in_trait)]
pub trait WitnessStore {
    async fn save(&mut self, account: &Account) -> Result<()>;
}

/// The wallet state: the shared cell, saved durably before the next step starts.
pub struct DurableWitness<P> {
    pub cell: WitnessCell,
    pub store: P,
}

impl<P: WitnessStore> WalletState for DurableWitness<P> {
    async fn load(&mut self) -> Result<Account> {
        self.cell.snapshot()
    }
    async fn store(&mut self, account: &Account) -> Result<()> {
        self.store.save(account).await?;
        self.cell.replace(account)
    }
}

/// The trusted embedding's door to the D2 update actor.
#[allow(async_fn_in_trait)]
pub trait UpdateTransport {
    async fn update(&mut self, proven: ProvenUpdate) -> Result<Shared<Applied>>;
    async fn settle(&mut self, request_id: [u8; 32]) -> Result<()>;
}

/// The update sink over the update actor.
pub struct DoorUpdateSink<T> {
    pub transport: T,
    pub scope: AccountProofScope,
    owed: Option<[u8; 32]>,
}

impl<T: UpdateTransport> DoorUpdateSink<T> {
    pub fn new(transport: T, scope: AccountProofScope) -> Self {
        Self {
            transport,
            scope,
            owed: None,
        }
    }
}

/// The public statement and effect, spelled by the witness crate, read as the accounting
/// owner spells them (same camelCase wire; unknown fields are refused).
fn bridge<S: serde::Serialize, D: serde::de::DeserializeOwned>(value: &S) -> Result<D> {
    serde_json::from_value(serde_json::to_value(value).map_err(|_| ErrorCode::Refused)?)
        .map_err(|_| ErrorCode::Refused)
}

impl<T: UpdateTransport> UpdateSink for DoorUpdateSink<T> {
    async fn apply(&mut self, candidate: &Candidate, proof: Vec<u8>) -> Result<Certificate> {
        let proven = ProvenUpdate {
            statement: bridge(&candidate.statement)?,
            scope: self.scope.clone(),
            proof,
            update: bridge(&candidate.update)?,
        };
        let applied = self.transport.update(proven).await?;
        let certificate = applied.response().certificate();
        let signature: [u8; 64] = certificate
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ErrorCode::Refused)?;
        self.owed = Some(applied.request_id());
        Ok(Certificate {
            accepted_at: certificate.accepted_at,
            signature,
        })
    }

    async fn settled(&mut self) -> Result<()> {
        match self.owed.take() {
            Some(request_id) => self.transport.settle(request_id).await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::bridge;

    /// A statement the witness crate produced (golden vector, same bytes the TypeScript
    /// builders emit) is read by the accounting owner's wire type; an unknown field would
    /// be refused, so a drift between the two spellings fails here.
    #[test]
    fn the_witness_statement_is_the_accounting_wire() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixture/witness-statement.json"))
                .unwrap();
        let parsed: cblc::accounting::AccountStatement =
            bridge(&fixture["statement"]).expect("the accounting wire");
        assert_eq!(parsed.protocol_version, 2);
        let mut extra = fixture["statement"].clone();
        extra["unexpected"] = serde_json::json!(1);
        assert!(bridge::<_, cblc::accounting::AccountStatement>(&extra).is_err());
    }

    #[test]
    fn the_effect_spellings_agree() {
        let update = serde_json::json!({
            "previousInbox": {"root": vec![1u8; 32]},
            "inbox": {"root": vec![2u8; 32]},
            "effect": {"kind": "consume", "obligation": vec![3u8; 32]},
        });
        let parsed: cblc::extensions::ExtendedUpdate = bridge(&update).unwrap();
        assert_eq!(parsed.inbox.root, [2; 32]);
    }
}
