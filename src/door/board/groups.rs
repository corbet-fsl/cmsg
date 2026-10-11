//! Local group views for the member. Groups decide membership on the device;
//! this action only reads the committed checkpoint under the current policy.
use super::*;

pub(in crate::door) async fn groups(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Vec<cbrd::GroupView>, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    Ok((board.groups(expires).await?, vec![]))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use cbrd::{cgrp, crbk};
    use cgrp::{Band, DAY, Notification, Policy, PolicySource, SeatFormats};
    use serde_json::{Value, json};

    const COMMUNITY: &str = "alpha";
    const VALID_UNTIL: u64 = 1_000 * DAY;

    fn curve() -> Vec<Band> {
        let edges = [3, 6, 9, 13, 20, 30, 43, 60, 80];
        let posts = [120, 90, 60, 40, 30, 24, 18, 12, 8];
        let bursts = [20, 15, 12, 10, 8, 6, 5, 4, 3];
        let notifications = [
            Notification::EveryMessage,
            Notification::QuietHours,
            Notification::SilentReactions,
            Notification::MentionsReplies,
            Notification::MentionsRepliesDigest,
            Notification::MentionsDigest,
            Notification::MentionsDaily,
            Notification::MentionsDaily,
            Notification::ContactsWeekly,
        ];
        (0..9)
            .map(|i| Band {
                lower: edges[i],
                enter_up: edges[i],
                leave_down: edges[i] - 2,
                notification: notifications[i],
                posts_per_hour: posts[i],
                burst: bursts[i],
                vouches: match i {
                    5 => 2,
                    3..5 => 1,
                    _ => 0,
                },
                history_seconds: [0, 0, 0, 14 * DAY, 7 * DAY, 3 * DAY, DAY, DAY / 2, DAY / 4][i],
                history_messages: [0, 0, 0, 200, 200, 200, 100, 50, 50][i],
                joins_per_hour: if i >= 7 { Some(6) } else { None },
            })
            .collect()
    }

    fn expected() -> Policy {
        Policy {
            epoch: 4,
            valid_until: VALID_UNTIL,
            cap: 100,
            circle_max: 12,
            ingroup_max: 42,
            shrink_public: 36,
            shrink_ingroup: 10,
            open_seconds: 21 * DAY,
            fork_cooldown: 14 * DAY,
            retarget_cooldown: 28 * DAY,
            listing_wait: 72 * 3_600,
            split_public_min: 43,
            bands: curve().try_into().unwrap(),
            seats: SeatFormats {
                enabled: false,
                refill_per_day: 1.0,
                capacity: 10.0,
                initial: 5.0,
                minimum: 0.25,
                small: 1.5,
                large: 3.0,
                low: 7,
                high: 60,
                tau: 1.0,
                epoch_days: 7,
                quantum: 0.5,
                warning_days: 2,
            },
            suggest_at: 66,
            pressure_at: 85,
            modularity: 0.3,
            overlap: 0.4,
            suggestion_cooldown: 7 * DAY,
            decline_cooldown: 14 * DAY,
            reciprocity_enabled: true,
            welcome_quarters: 1,
            introduction_quarters: 4,
            week_cap_quarters: 6,
        }
    }

    /// Decided defaults plus the keys the Rulebook catalogue does not yet carry.
    fn snapshot() -> crbk::Snapshot {
        let mut content = crbk::group_defaults().unwrap();
        content.insert(
            "groups.curve".into(),
            serde_json::to_value(curve()).unwrap(),
        );
        for (key, value) in [
            ("groups.split_public_min", json!(43)),
            ("groups.suggest.threshold", json!(66)),
            ("groups.suggest.hard", json!(85)),
            ("groups.suggest.modularity", json!(0.3)),
            ("groups.suggest.jaccard", json!(0.4)),
            ("groups.suggest.cooldown_days", json!(7)),
            ("groups.suggest.decline_cooldown_days", json!(14)),
        ] {
            content.insert(key.into(), value);
        }
        crbk::Snapshot {
            community: COMMUNITY.into(),
            kind: crbk::SnapshotKind::Settings,
            revision: 8,
            policy_epoch: 4,
            issued: 1,
            content,
        }
    }

    #[test]
    fn signed_settings_project_to_the_decided_group_policy() {
        let policy = cbrd::project_group_policy(&snapshot(), VALID_UNTIL).unwrap();
        assert_eq!(policy, expected());
        let binding = snapshot();
        let source = cbrd::SettingsPolicy::new(&binding, VALID_UNTIL);
        assert_eq!(source.current(COMMUNITY, 10).unwrap(), expected());
    }

    #[test]
    fn projection_refuses_missing_mistyped_and_foreign_inputs() {
        for key in snapshot().content.keys() {
            // Hysteresis and join pace travel inside the signed curve rows.
            let unused = ["groups.band_hysteresis", "groups.join_rate_per_hour"];
            let owned = ["groups.", "seats.", "waves."];
            if unused.contains(&key.as_str()) || !owned.iter().any(|p| key.starts_with(p)) {
                continue;
            }
            let mut missing = snapshot();
            missing.content.remove(key);
            assert_eq!(
                cbrd::project_group_policy(&missing, VALID_UNTIL),
                Err(cgrp::Error::Policy),
                "{key}"
            );
            let mut mistyped = snapshot();
            mistyped
                .content
                .insert(key.clone(), Value::String("x".into()));
            assert_eq!(
                cbrd::project_group_policy(&mistyped, VALID_UNTIL),
                Err(cgrp::Error::Policy),
                "{key}"
            );
        }
        let mut overflow = snapshot();
        overflow.content.insert("groups.cap".into(), json!(70_000));
        assert!(cbrd::project_group_policy(&overflow, VALID_UNTIL).is_err());
        let mut huge = snapshot();
        huge.content
            .insert("groups.open_days".into(), json!(u64::MAX));
        assert!(cbrd::project_group_policy(&huge, VALID_UNTIL).is_err());
        let mut hours = snapshot();
        hours
            .content
            .insert("groups.fork_listing_wait_h".into(), json!(u64::MAX));
        assert!(cbrd::project_group_policy(&hours, VALID_UNTIL).is_err());
        for credit in [json!(0.1), json!(-0.25), json!(1.0e9)] {
            let mut waves = snapshot();
            waves.content.insert("waves.welcome_credit".into(), credit);
            assert!(cbrd::project_group_policy(&waves, VALID_UNTIL).is_err());
        }
        let mut short = snapshot();
        short.content.insert(
            "groups.curve".into(),
            serde_json::to_value(&curve()[..8]).unwrap(),
        );
        assert!(cbrd::project_group_policy(&short, VALID_UNTIL).is_err());
    }

    #[test]
    fn source_refuses_foreign_community_expiry_and_invalid_policy() {
        let binding = snapshot();
        let source = cbrd::SettingsPolicy::new(&binding, VALID_UNTIL);
        assert_eq!(source.current("beta", 10), Err(cgrp::Error::Authority));
        assert_eq!(
            source.current(COMMUNITY, VALID_UNTIL),
            Err(cgrp::Error::Policy)
        );
        let mut seats = snapshot();
        seats.content.insert("seats.enabled".into(), json!(true));
        assert_eq!(
            cbrd::SettingsPolicy::new(&seats, VALID_UNTIL).current(COMMUNITY, 10),
            Err(cgrp::Error::Policy)
        );
    }
}
