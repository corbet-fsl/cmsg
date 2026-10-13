//! Inbox actions over the member's own Contacts. Thin: every fact and mutation
//! is the Inbox owner's, and the Vault supplies the only authority.
use super::*;

/// Block, close or reopen one peer under this member's own authority.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactAct {
    pub peer: String,
    pub action: cnbx::OwnAction,
}

pub(super) async fn blocking_rules(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Vec<String>, Vec<Event>)> {
    registry::inbox_read(door, key, |vault| vault.blocking_rules()).await
}

pub(super) async fn contact_act(
    door: &mut Door,
    key: &[u8; 32],
    request: ContactAct,
) -> Result<(cnbx::Relation, Vec<Event>)> {
    registry::inbox_read(door, key, |vault| vault.contact_act(request)).await
}
