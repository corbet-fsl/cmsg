//! The daily delegation refresh against a scripted device: a Vault record with
//! compare-and-swap, a policy that hands out the grant day, and a registry that
//! behaves like cblc's (one row per member; identical bytes accepted again; a
//! different delegation needs a strictly later `issued_at`, else Replay, which
//! the host reports as Reconcile).
use super::*;

const DAY: u64 = 86_400;
/// A UTC midnight: the start of grant day D1.
const D1: u64 = 1_793_836_800;
const D2: u64 = D1 + DAY;

fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    futures_executor::block_on(future)
}

fn day(issued_at: u64) -> GrantDay {
    GrantDay {
        issued_at,
        policy_epoch: 7,
    }
}

/// A well-formed delegation signed at `signed_at` under the grant of `grant`.
fn delegation(grant: GrantDay, signed_at: u64) -> Vec<u8> {
    let text = |s: &str| s.to_owned();
    serde_json::to_vec(&enrollment::AccountingDelegation {
        version: 1,
        hash_scheme: text("scheme"),
        admission: admission::AdmissionGrant {
            version: 3,
            issuer_key_id: text("issuer"),
            community_id: text("community"),
            member_id: text("member"),
            pseudonym: text("pseudonym"),
            chat_public_key: text("device"),
            policy_digest: text("policy"),
            policy_epoch: grant.policy_epoch,
            passport_policy_digest: text("passport"),
            issued_at: grant.issued_at,
            expires_at: grant.issued_at + DAY,
            signature: text("grant-signature"),
        },
        authorization: admission::DeviceAuthorization {
            version: 1,
            community_id: text("community"),
            member_id: text("member"),
            root_public_key: text("root"),
            device_public_key: text("device"),
            issued_at: signed_at,
            expires_at: grant.issued_at + DAY,
            signature: text("root-signature"),
        },
        account_public_key: text("account"),
        state_secret_commitment: text("secret"),
        issued_at: signed_at,
        expires_at: grant.issued_at + DAY,
        signature: text("device-signature"),
    })
    .unwrap()
}

fn parsed(bytes: &[u8]) -> enrollment::AccountingDelegation {
    serde_json::from_slice(bytes).unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    /// Signed, but the `Sent` record was never written.
    BeforePersist,
    /// `Sent` written, the device died before the request left.
    BeforeSend,
    /// The registry accepted, the answer was lost.
    LostAnswer,
    /// Accepted and answered, the device died before writing `Registered`.
    BeforeAck,
}

struct Device {
    /// The Vault record (survives a restart).
    record: Option<Vec<u8>>,
    /// The registry row of this member (shared with the member's other devices).
    row: Option<Vec<u8>>,
    /// Distinct delegations the registry stored.
    rows: usize,
    /// The fresh admission's grant day; `None` when the admission is refused
    /// (revoked device, ended membership).
    fresh: Option<GrantDay>,
    /// The device clock.
    now: u64,
    signs: usize,
    sends: Vec<Vec<u8>>,
    crash: Option<Crash>,
    /// Another writer changes the record between this device's read and write.
    interfere: bool,
}

impl Device {
    fn new(fresh: u64, now: u64) -> Self {
        Self {
            record: None,
            row: None,
            rows: 0,
            fresh: Some(day(fresh)),
            now,
            signs: 0,
            sends: Vec::new(),
            crash: None,
            interfere: false,
        }
    }

    /// The same device after a restart: only the Vault record and the registry remain.
    fn restarted(&self, fresh: u64, now: u64) -> Self {
        Self {
            record: self.record.clone(),
            row: self.row.clone(),
            rows: self.rows,
            ..Self::new(fresh, now)
        }
    }

    fn crashes(&mut self, at: Crash) -> bool {
        if self.crash == Some(at) {
            self.crash = None;
            return true;
        }
        false
    }

    fn stored(&self) -> Stored {
        Stored::parse(self.record.as_deref().unwrap()).unwrap()
    }
}

impl Delegations for Device {
    async fn record(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.record.clone())
    }
    async fn replace(&mut self, expected: Option<&[u8]>, record: &[u8]) -> Result<()> {
        if std::mem::take(&mut self.interfere) {
            self.record = Some(registered(&delegation(day(0), 0)));
        }
        if self.record.as_deref() != expected {
            return Err(ErrorCode::Reconcile);
        }
        let crash = if record.first() == Some(&SENT) {
            Crash::BeforePersist
        } else {
            Crash::BeforeAck
        };
        if self.crashes(crash) {
            return Err(ErrorCode::Unavailable);
        }
        self.record = Some(record.to_vec());
        Ok(())
    }
    fn grant(&mut self) -> Result<GrantDay> {
        self.fresh.ok_or(ErrorCode::Unauthorized)
    }
    fn resendable(&mut self, bytes: &[u8]) -> bool {
        let d = parsed(bytes);
        self.fresh
            .is_some_and(|fresh| GrantDay::of(&d.admission) == fresh && self.now < d.expires_at)
    }
    async fn sign(&mut self) -> Result<Vec<u8>> {
        self.signs += 1;
        Ok(delegation(self.grant()?, self.now))
    }
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if self.crashes(Crash::BeforeSend) {
            return Err(ErrorCode::Unavailable);
        }
        self.sends.push(bytes.to_vec());
        match &self.row {
            Some(row) if row == bytes => {}
            Some(row) if parsed(row).issued_at >= parsed(bytes).issued_at => {
                return Err(ErrorCode::Reconcile);
            }
            _ => {
                self.row = Some(bytes.to_vec());
                self.rows += 1;
            }
        }
        if self.crashes(Crash::LostAnswer) {
            return Err(ErrorCode::Reconcile);
        }
        Ok(())
    }
}

#[test]
fn a_device_re_issues_at_most_once_per_grant_day() {
    let mut device = Device::new(D1, D1 + 600);
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Issued));
    device.now = D1 + 7_200;
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Current));
    device.now = D2 - 60;
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Current));
    assert_eq!((device.signs, device.sends.len(), device.rows), (1, 1, 1));
    assert!(device.stored().registered);
}

#[test]
fn a_new_grant_day_re_issues_exactly_one_later_delegation() {
    let mut device = Device::new(D1, D1 + 600);
    block(refresh(&mut device)).unwrap();
    // The policy hands out the next day's grant only after its midnight.
    device.fresh = Some(day(D2));
    device.now = D2 + 120;
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Issued));
    device.now = D2 + 900;
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Current));
    assert_eq!((device.signs, device.rows), (2, 2));
    let row = parsed(device.row.as_deref().unwrap());
    assert_eq!(row.admission.issued_at, D2);
    assert_eq!(row.expires_at, D2 + DAY);
}

#[test]
fn a_restart_on_the_same_grant_day_signs_nothing() {
    let mut device = Device::new(D1, D1 + 600);
    block(refresh(&mut device)).unwrap();
    let mut restarted = device.restarted(D1, D1 + 3_600);
    assert_eq!(block(refresh(&mut restarted)), Ok(Refreshed::Current));
    assert_eq!((restarted.signs, restarted.sends.len()), (0, 0));
}

#[test]
fn every_crash_window_ends_with_one_registered_delegation_per_day() {
    for crash in [
        Crash::BeforePersist,
        Crash::BeforeSend,
        Crash::LostAnswer,
        Crash::BeforeAck,
    ] {
        let mut device = Device::new(D1, D1 + 600);
        device.crash = Some(crash);
        assert!(block(refresh(&mut device)).is_err(), "{crash:?}");
        let mut restarted = device.restarted(D1, D1 + 1_200);
        let expected = if crash == Crash::BeforePersist {
            // Nothing left the device: the next login signs once.
            Refreshed::Issued
        } else {
            // Persist-before-send: the identical bytes go out again.
            Refreshed::Resent
        };
        assert_eq!(block(refresh(&mut restarted)), Ok(expected), "{crash:?}");
        assert_eq!(restarted.rows, 1, "{crash:?}: one distinct registry record");
        assert_eq!(
            restarted.row.as_deref(),
            Some(&restarted.stored().delegation[..]),
            "{crash:?}"
        );
        assert!(restarted.stored().registered, "{crash:?}");
        if crash != Crash::BeforePersist {
            assert_eq!(restarted.signs, 0, "{crash:?}: a resend never signs");
            assert_eq!(
                restarted.sends,
                vec![device.stored().delegation],
                "{crash:?}: the resend carries the exact stored bytes"
            );
        }
        assert_eq!(
            block(refresh(&mut restarted)),
            Ok(Refreshed::Current),
            "{crash:?}"
        );
    }
}

#[test]
fn a_device_whose_admission_is_refused_signs_and_resends_nothing() {
    let mut device = Device::new(D1, D1 + 600);
    device.crash = Some(Crash::BeforeSend);
    block(refresh(&mut device)).unwrap_err();
    let pending = device.record.clone();
    // Revoked: the policy no longer grants this device an admission.
    let mut revoked = device.restarted(D1, D1 + 1_200);
    revoked.fresh = None;
    assert_eq!(block(refresh(&mut revoked)), Err(ErrorCode::Unauthorized));
    assert_eq!(
        (revoked.signs, revoked.sends.len(), revoked.rows),
        (0, 0, 0)
    );
    assert_eq!(revoked.record, pending);
}

#[test]
fn a_stale_pending_delegation_is_replaced_never_resent() {
    // Sent on D1, the device comes back on D2: the D1 bytes no longer cover the day.
    let mut device = Device::new(D1, D1 + 600);
    device.crash = Some(Crash::BeforeSend);
    block(refresh(&mut device)).unwrap_err();
    let mut later = device.restarted(D2, D2 + 60);
    assert_eq!(block(refresh(&mut later)), Ok(Refreshed::Issued));
    assert_eq!(later.signs, 1);
    assert_eq!(parsed(&later.sends[0]).admission.issued_at, D2);
    // A policy epoch change on the same day also re-signs once.
    later.fresh = Some(GrantDay {
        issued_at: D2,
        policy_epoch: 8,
    });
    later.now = D2 + 600;
    assert_eq!(block(refresh(&mut later)), Ok(Refreshed::Issued));
    later.now = D2 + 1_200;
    assert_eq!(block(refresh(&mut later)), Ok(Refreshed::Current));
    assert_eq!(later.signs, 2);
}

#[test]
fn the_device_clock_never_decides_the_day() {
    let mut device = Device::new(D1, D1 + 600);
    block(refresh(&mut device)).unwrap();
    // The device clock runs two hours ahead past midnight; the policy still grants D1.
    device.now = D2 + 7_200;
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Current));
    assert_eq!(device.signs, 1);
}

#[test]
fn a_newer_row_from_another_device_is_not_overwritten_and_the_next_day_recovers() {
    let mut device = Device::new(D1, D1 + 600);
    device.crash = Some(Crash::BeforeSend);
    block(refresh(&mut device)).unwrap_err();
    // Another device of the member registered a later delegation meanwhile.
    let newer = delegation(day(D1), D1 + 900);
    device.row = Some(newer.clone());
    device.rows = 1;
    let mut restarted = device.restarted(D1, D1 + 1_200);
    assert_eq!(block(refresh(&mut restarted)), Err(ErrorCode::Reconcile));
    assert_eq!(restarted.row.as_deref(), Some(&newer[..]));
    assert_eq!((restarted.signs, restarted.sends.len()), (0, 1));
    // One request per login at most; the next grant day signs a later delegation.
    let mut next = restarted.restarted(D2, D2 + 60);
    assert_eq!(block(refresh(&mut next)), Ok(Refreshed::Issued));
    assert_eq!(parsed(next.row.as_deref().unwrap()).admission.issued_at, D2);
}

#[test]
fn a_lost_compare_and_swap_sends_nothing() {
    let mut device = Device::new(D1, D1 + 600);
    device.interfere = true;
    assert_eq!(block(refresh(&mut device)), Err(ErrorCode::Reconcile));
    assert_eq!((device.sends.len(), device.rows), (0, 0));
}

#[test]
fn an_unreadable_record_is_replaced_by_one_signed_delegation() {
    let mut device = Device::new(D1, D1 + 600);
    device.record = Some(b"\x09garbage".to_vec());
    assert_eq!(block(refresh(&mut device)), Ok(Refreshed::Issued));
    assert_eq!(device.signs, 1);
    assert!(device.stored().registered);
}
