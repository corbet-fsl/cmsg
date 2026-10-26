//! `foyer.communities`: the member's own list of communities.
//!
//! A device holds no list of communities in one place: each community has its own
//! Vault (own records, own device key). The list is therefore assembled from what this
//! Vault itself knows: the community it is bound to (with the owner's newest lobby state),
//! the communities it created (kept in the custody record once their creation is finished,
//! the unfinished creation counts too). Nothing is asked of a service for communities the
//! device cannot reach; the list never leaves the device.
use super::*;

/// Most communities one list keeps.
pub(super) const MAXIMUM: usize = 256;

/// One community of the member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The community's id (the name the platform gave it; the configured name for the
    /// community this Door is bound to).
    pub id: String,
    /// Name shown to members; the id when none was chosen.
    pub name: String,
    /// The community's host name (no scheme).
    pub host: String,
    /// `member`, `admin` or `root`.
    pub role: String,
    /// The newest known lobby state of the member in that community (`active`, ...), or
    /// `created` for a community this device created, or `unavailable` when the owner
    /// did not answer.
    pub state: String,
}

/// Result of `foyer.communities`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Communities {
    pub communities: Vec<Entry>,
}

fn origin_of(door: &Door, key: &[u8; 32]) -> Result<String> {
    door.grants
        .get(key)
        .map(|grant| grant.origin.clone())
        .ok_or(ErrorCode::Unauthorized)
}

fn host_of(origin: &str) -> String {
    origin
        .split_once("://")
        .map_or(origin, |(_, rest)| rest)
        .trim_end_matches('/')
        .to_owned()
}

/// The entry a finished or running creation stands for.
pub(super) fn created_entry(created: &creating::Created) -> Entry {
    Entry {
        id: created.id.clone(),
        name: if created.display_name.is_empty() {
            created.address.clone()
        } else {
            created.display_name.clone()
        },
        host: created.community_host.clone(),
        role: "admin".into(),
        state: "created".into(),
    }
}

/// Keep `entry` once (by id); the newest information replaces the old.
pub(super) fn remember(list: &mut Vec<Entry>, entry: Entry) {
    if let Some(known) = list.iter_mut().find(|known| known.id == entry.id) {
        *known = entry;
    } else if list.len() < MAXIMUM {
        list.push(entry);
    }
}

pub(super) async fn communities(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Communities, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    let book = vouching::load(door, &origin).await?.book;
    let mut list = book.communities.clone();
    if let Some(created) = book
        .creation
        .as_ref()
        .and_then(|record| record.created.as_ref())
    {
        remember(&mut list, created_entry(created));
    }
    let bound = door
        .foyers
        .get(&origin)
        .filter(|binding| binding.sessions.primary == foyer::Scope::Community)
        .map(|binding| binding.role);
    if let Some(role) = bound {
        let state = match owner::<Value>(door, &origin, "lobby", serde_json::json!({})).await {
            Ok(lobby) => lobby
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("unavailable")
                .to_owned(),
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "unavailable into", &__cause);
                "unavailable".into()
            }
        };
        let id = door.config.community.clone();
        let entry = Entry {
            name: id.clone(),
            id,
            host: host_of(&origin),
            role: serde_json::to_value(role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(ErrorCode::Unavailable)?,
            state,
        };
        remember(&mut list, entry);
    }
    Ok((Communities { communities: list }, vec![]))
}

async fn owner<T: serde::de::DeserializeOwned>(
    door: &mut Door,
    origin: &str,
    name: &str,
    body: Value,
) -> Result<T> {
    let operation = foyer::owner_operation(name).ok_or(ErrorCode::Unavailable)?;
    let binding = door.foyers.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
    let answer = binding.call(operation, body).await?;
    serde_json::from_value(answer).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}
