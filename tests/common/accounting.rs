//! Synthetic admission/clock fixture; the MLS decisions and signatures are real.
#![allow(dead_code)]
use cmsg::{
    AccountingDelegation, AccountingKey, Clock, Error, FirstContactPolicy, FirstContactRole, Inbox,
    Member, MemberIdentity,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
pub const KEY: [u8; 32] = [83; 32];
pub const CONTEXT: &[u8] = b"synthetic-accounting-extension";
pub const SCHEME: &str = "poseidon2-bn254-fixed-128-v1";
pub struct Time(pub AtomicU64);
impl Clock for Time {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::Relaxed))
    }
}
pub fn device(root: &MemberIdentity, time: &Arc<Time>, expires: u64) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = super::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    grant.expires_at = expires;
    super::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            super::trust(),
            root.authorize_device(&key, 1, expires).unwrap(),
            100,
        )
        .unwrap();
    member
}
pub struct Pair {
    pub a: Member,
    pub b: Member,
    pub ai: Inbox,
    pub bi: Inbox,
    pub ar: MemberIdentity,
    pub br: MemberIdentity,
    pub time: Arc<Time>,
    pub ak: AccountingKey,
    pub bk: AccountingKey,
    pub ad: AccountingDelegation,
    pub bd: AccountingDelegation,
}
impl Pair {
    pub fn configured(sender_expires: u64) -> Self {
        let time = Arc::new(Time(AtomicU64::new(100)));
        let ar = MemberIdentity::new("synthetic-community").unwrap();
        let br = MemberIdentity::new("synthetic-community").unwrap();
        let mut a = device(&ar, &time, sender_expires);
        let mut b = device(&br, &time, 10_000);
        a.create_group().unwrap();
        b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
            .unwrap();
        let mut ai = Inbox::new(&a).unwrap();
        let mut bi = Inbox::new(&b).unwrap();
        let policy = FirstContactPolicy {
            response_deadline: 5000,
            max_intro_bytes: 128,
        };
        ai.begin_first_contact(
            br.member_id(),
            &[84; 32],
            FirstContactRole::Initiator,
            policy,
            &a,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
        bi.begin_first_contact(
            ar.member_id(),
            &[84; 32],
            FirstContactRole::Recipient,
            policy,
            &b,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
        let ak = AccountingKey::new(&a).unwrap();
        let bk = AccountingKey::new(&b).unwrap();
        let ad = a
            .delegate_accounting(&ak, SCHEME, &[1; 32], sender_expires)
            .unwrap();
        let bd = b
            .delegate_accounting(&bk, SCHEME, &[2; 32], 10_000)
            .unwrap();
        Self {
            a,
            b,
            ai,
            bi,
            ar,
            br,
            time,
            ak,
            bk,
            ad,
            bd,
        }
    }
    pub fn pending() -> Self {
        let mut p = Self::configured(10_000);
        p.send_intro();
        p
    }
    pub fn send_intro(&mut self) {
        let intro = self
            .ai
            .send_contact(&mut self.a, b"introduction", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
        self.bi
            .receive_contact(&mut self.b, &intro, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    }
    pub fn send_answer(&mut self) -> Vec<u8> {
        self.bi
            .send_contact(&mut self.b, b"answer", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap()
    }
    pub fn established() -> Self {
        let mut p = Self::pending();
        let reply = p.send_answer();
        p.ai.receive_contact(&mut p.a, &reply, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        p
    }
}
