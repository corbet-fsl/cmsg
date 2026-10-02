//! Local login lifecycle wire types, owned by the same Rust action registry.
//! The launch fragment, assertion, PRF and service session are never wire fields.
use super::*;

pub type Start = Empty;
pub type Poll = Empty;
pub type Cancel = Empty;

/// One operation per paired local capability. Complete is reserved for verified
/// server authentication AND accepted durable device custody; Mesh readiness
/// remains an independent runtime status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Status {
    Idle,
    Pending { expires_at: u64 },
    Complete,
    Cancelled,
    Expired,
}
