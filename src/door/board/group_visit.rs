//! Client open-group entry: record "was here" without saying what was read.
//!
//! The embedding client calls [`note_group_opened`] when the member actually
//! opens a group. At most one [`WasHere`] per member, group and 6-hour bucket
//! is ever recorded; the fact waits out its jitter and then rides the next
//! ordinary group exchange the device builds anyway ([`due_for_exchange`] peeks
//! at what is due, [`mark_exchanged`] consumes what an exchange really
//! carried). Nothing is transmitted standalone, and closing the group or going
//! offline drops undelivered facts instead of delivering them later.
//!
//! The sender of the piggybacked fact is whoever the group's MLS already
//! authenticated, exactly like any other group exchange; this module adds no
//! signature, no custody and no key handling, and changes nothing the server
//! accepts. MLS removal of a due free seat is out of scope.
use super::*;
use cbrd::cgrp::{self, WasHere};

/// The client opened this group. `jitter_ticks` is the caller's own 0..=4
/// draw (0..60 s at 15 s ticks); production draws one fresh entropy byte mod
/// 5 per opening, tests pass fixed values.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupOpened {
    pub group: [u8; 32],
    pub jitter_ticks: u64,
}

/// Whether the opening recorded a new pending visit.
#[derive(Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupOpenedAck {
    pub recorded: bool,
}

/// Record the opening of `group` by `member` at `now_ticks`. Returns
/// `recorded = true` for the first opening of the member/group/bucket and
/// `recorded = false` for repeats in the same bucket.
pub fn note_group_opened(
    ledger: &mut cgrp::VisitLedger,
    member: &str,
    request: &GroupOpened,
    now_ticks: u64,
) -> Result<GroupOpenedAck> {
    let outcome = ledger
        .record_open(member, &request.group, now_ticks, request.jitter_ticks)
        .map_err(super::handlers::group_error)?;
    Ok(GroupOpenedAck {
        recorded: matches!(outcome, cgrp::RecordOutcome::Recorded { .. }),
    })
}

/// Facts due for the next ordinary group exchange. Peeking changes nothing:
/// only [`mark_exchanged`] consumes facts, and only the caller builds the
/// exchange they ride on.
pub fn due_for_exchange(ledger: &cgrp::VisitLedger, now_ticks: u64) -> Vec<WasHere> {
    ledger.due_for_exchange(now_ticks)
}

/// Consume the facts an actually built group exchange carried. Facts never
/// offered to an exchange stay pending for a later one while live.
pub fn mark_exchanged(ledger: &mut cgrp::VisitLedger, facts: &[WasHere]) -> Result<()> {
    ledger
        .mark_exchanged(facts)
        .map_err(super::handlers::group_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn opened(group: u8, jitter: u64) -> GroupOpened {
        GroupOpened {
            group: [group; 32],
            jitter_ticks: jitter,
        }
    }

    #[test]
    fn opening_a_group_records_one_visit() {
        let mut ledger = cgrp::VisitLedger::new();
        let ack = note_group_opened(&mut ledger, "a", &opened(1, 2), 100).unwrap();
        assert!(ack.recorded);
        let again = note_group_opened(&mut ledger, "a", &opened(1, 0), 150).unwrap();
        assert!(!again.recorded);
        assert_eq!(ledger.pending_count(), 1);
    }

    #[test]
    fn jitter_delays_release_until_due() {
        let mut ledger = cgrp::VisitLedger::new();
        note_group_opened(&mut ledger, "a", &opened(1, 3), 100).unwrap();
        assert!(due_for_exchange(&ledger, 102).is_empty());
        let due = due_for_exchange(&ledger, 103);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].member, "a");
        assert_eq!(due[0].group, [1; 32]);
    }

    #[test]
    fn exchange_consumes_and_blocks_bucket_resend() {
        let mut ledger = cgrp::VisitLedger::new();
        note_group_opened(&mut ledger, "a", &opened(1, 0), 100).unwrap();
        let due = due_for_exchange(&ledger, 100);
        mark_exchanged(&mut ledger, &due).unwrap();
        assert!(ledger.is_sent("a", &[1; 32], 0));
        let again = note_group_opened(&mut ledger, "a", &opened(1, 0), 150).unwrap();
        assert!(!again.recorded);
    }

    #[test]
    fn closing_without_exchange_supplies_nothing() {
        let mut ledger = cgrp::VisitLedger::new();
        note_group_opened(&mut ledger, "a", &opened(1, 0), 100).unwrap();
        ledger.drop_undelivered();
        assert!(due_for_exchange(&ledger, 10_000).is_empty());
        let again = note_group_opened(&mut ledger, "a", &opened(1, 0), 150).unwrap();
        assert!(again.recorded);
    }

    #[test]
    fn open_group_carries_no_read_state() {
        let mut ledger = cgrp::VisitLedger::new();
        note_group_opened(&mut ledger, "a", &opened(1, 0), 100).unwrap();
        let due = due_for_exchange(&ledger, 100);
        assert_eq!(due.len(), 1);
        let value = serde_json::to_value(&due[0]).unwrap();
        let keys: BTreeSet<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, BTreeSet::from(["bucket_start", "group", "member"]));
    }
}
