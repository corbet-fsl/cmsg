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
    Pending {
        expires_at: u64,
    },
    Complete,
    Cancelled,
    Expired,
    /// The server accepted the passkey; compound device custody is still needed.
    AuthenticatedPendingCustody,
}

/// Public deployment inputs for the original native or browser popup ceremony. These are
/// trusted constructor inputs, never fields in a local action body.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub page: String,
    pub origin: String,
    pub relying_party: String,
}

/// Browser handover status, never a server authentication or vault-ready claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallbackStatus {
    Ready,
    Running,
    HandedBack,
    Cancelled,
    Failed,
    Reconcile,
}

#[cfg(target_arch = "wasm32")]
mod callback;
#[cfg(target_arch = "wasm32")]
pub use callback::CliLogin;

impl Configuration {
    pub(crate) fn context(&self) -> Result<cfyr::passkeys::Context> {
        let page = url::Url::parse(&self.page).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        if page.scheme() != "https"
            || page.origin().ascii_serialization() != self.origin
            || !page.username().is_empty()
            || page.password().is_some()
            || page.query().is_some()
            || page.fragment().is_some()
            || !page
                .host_str()
                .is_some_and(|host| host.starts_with("vault."))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        cfyr::passkeys::Context::new(&self.origin, &self.relying_party).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) mod browser;
#[cfg(not(target_arch = "wasm32"))]
pub(super) mod native;
#[cfg(target_arch = "wasm32")]
mod popup;
pub(super) mod session;
#[cfg(target_arch = "wasm32")]
pub use popup::PopupLogin;

pub(super) async fn start(
    door: &mut Door,
    key: &[u8; 32],
    _: Start,
) -> Result<(Status, Vec<Event>)> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        native::start(door, key)
            .await
            .map(|status| (status, vec![]))
    }
    #[cfg(target_arch = "wasm32")]
    {
        browser::start(door, key)
            .await
            .map(|status| (status, vec![]))
    }
}
pub(super) async fn poll(door: &mut Door, key: &[u8; 32], _: Poll) -> Result<(Status, Vec<Event>)> {
    session::poll(door, key).map(|status| (status, vec![]))
}
pub(super) async fn cancel(
    door: &mut Door,
    key: &[u8; 32],
    _: Cancel,
) -> Result<(Status, Vec<Event>)> {
    session::cancel(door, key).map(|status| (status, vec![]))
}
