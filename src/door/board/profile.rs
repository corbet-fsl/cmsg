//! Publish the member's own profile and rules as one signed bundle. The caller
//! names answers and rules only: the reachability descriptor is the device's own Mesh addresses, and the next
//! revision, the profile key, every signature and the admission decision come
//! from the retained owner and the original Profile, Envelope and Guard owners.
//! Profile keys go only to members the rules allow, and only person to person
//! (Exchange); publishing here releases no key to anybody.
use super::handlers::{board_error, with_context, OwnedBoard};
use super::*;

/// Owner-lent inputs for one preparation, valid only inside the callback that
/// receives them: the actual device signer and Envelope custody come from
/// `Keys::with_profile_custody`, the Store read from the committed checkpoint.
pub struct ProfileParts<'p, B: cwst::backend::Backend> {
    pub read: CommittedRead<'p, B>,
    pub signer: ckmg::ProfileSigner<'p>,
    pub custody: cbrd::cnvl::Custodian<'p>,
    /// A freshly issued community credential, when admission just produced one.
    /// `None` re-uses the credential inside the committed publication.
    pub credential: Option<Vec<u8>>,
    /// Members Contacts currently blocks; they become never-match rules.
    pub blocked: Vec<String>,
}

/// The member's answers and rules. Block rules are not accepted here: they come
/// from Contacts only.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfilePublish {
    /// All answers for the current schema: `{community, schema_version, public, private}`.
    pub profile: serde_json::Value,
    /// Personal rules (`{"op":"number_range",...}` and the other Guard rules).
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct ProfilePublished {
    /// Vault checkpoint version after the atomic commit.
    pub version: u64,
}

impl ProfilePublish {
    fn edit(self, reachability: Vec<u8>) -> Result<cbrd::Edit> {
        if self.rules.len() > cbrd::cgrd::MAX_ITEMS {
            return Err(ErrorCode::InvalidRequest);
        }
        let profile =
            serde_json::from_value(self.profile).map_err(|_| ErrorCode::InvalidRequest)?;
        let rules = self
            .rules
            .into_iter()
            .map(|rule| serde_json::from_value(rule).map_err(|_| ErrorCode::InvalidRequest))
            .collect::<Result<Vec<_>>>()?;
        Ok(cbrd::Edit {
            profile,
            rules,
            reachability,
            // A system field: never taken from the request, only from custody.
            vouched_by: None,
            vouched_snapshot: None,
        })
    }
}

impl<T: clnk::Transport, R, O: CommittedOwner> OwnedBoard<T, R, O> {
    /// Prepare, authorize against the CURRENT Charter inside one synchronous
    /// callback, then commit atomically in a later await. The Forum still holds
    /// the previous publication, so the stale presence ends and the member
    /// attends again with the committed one.
    pub(super) async fn publish_profile(&mut self, edit: cbrd::Edit, expires: u64) -> Result<u64> {
        self.idle()?;
        let community = self.inner.board.community().to_owned();
        let board = &self.inner.board;
        let current = &mut self.current;
        let policy = &self.policy;
        let authorized = self
            .owner
            .with_profile(|parts| {
                let ProfileParts {
                    read,
                    mut signer,
                    custody,
                    credential,
                    blocked,
                } = parts;
                with_context(current, policy, &community, expires, read, |context, _| {
                    let candidate = board
                        .prepare_profile(
                            &cbrd::PublishContext {
                                read: context,
                                custody: &custody,
                                credential: credential.as_deref(),
                            },
                            &mut signer,
                            edit,
                            &blocked,
                        )
                        .map_err(board_error)?;
                    board
                        .authorize_profile(context, candidate)
                        .map_err(board_error)
                })
            })
            .await?;
        let version = self.owner.commit_profile(authorized).await?;
        self.inner.board.disconnect();
        Ok(version)
    }
}

pub(in crate::door) async fn profile_publish(
    door: &mut Door,
    key: &[u8; 32],
    request: ProfilePublish,
) -> Result<(ProfilePublished, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    // A system field: the device's own live Mesh addresses, never request data.
    let reachability = door.reachability(&origin);
    let mut edit = request.edit(reachability)?;
    if let Some((wire, snapshot)) = super::super::vouching::endorsement_wire(door, &origin).await {
        edit.vouched_by = Some(wire);
        edit.vouched_snapshot = snapshot;
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    let version = board.profile_publish(edit, expires).await?;
    Ok((ProfilePublished { version }, vec![]))
}
