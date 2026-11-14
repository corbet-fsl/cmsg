//! Board signing and Profile custody for a Vault opened under its initial recovery authority.
//!
//! The open path (a registered device starting) opens the community Vault under
//! [`InitialRecoveryAuthority`], which admits Board device signing and Profile custody never. Once the
//! start restore has proven this device is in the community's current lineage, it binds
//! the very same [`MemberAuthority`] the restore path binds (one shared function,
//! `Door::bind_member_authority`) and installs it here. Until then both stay refused by
//! the inner authority; every other action is the inner authority's, always.
use super::*;
use std::{cell::RefCell, future::Future, pin::Pin};

type Check<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>>;

/// The Board-signing face of a member authority (object safe, so the Vault's authority
/// type does not name the network type of the later binding).
trait BoardSigning {
    fn board_check<'a>(&'a mut self, request: Authorization<'a>) -> Check<'a>;
    fn board_signing<'a>(&'a mut self, request: Authorization<'a>) -> Check<'a>;
    fn board_current(&mut self, request: Authorization<'_>) -> Result<u64, Error>;
    fn board_discard(&mut self);
}

impl<A: ckmg::Authority> BoardSigning for A {
    fn board_check<'a>(&'a mut self, request: Authorization<'a>) -> Check<'a> {
        Box::pin(ckmg::Authority::check(self, request))
    }
    fn board_signing<'a>(&'a mut self, request: Authorization<'a>) -> Check<'a> {
        Box::pin(ckmg::Authority::check_device_signing(self, request))
    }
    fn board_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        ckmg::Authority::check_device_signing_current(self, request)
    }
    fn board_discard(&mut self) {
        ckmg::Authority::discard_current_attempt(self);
    }
}

/// The trusted start restore's handle to install the member authority, once.
#[derive(Clone, Default)]
pub struct MemberSlot {
    slot: Rc<RefCell<Option<(Binding, Box<dyn BoardSigning>)>>>,
    used: Rc<Cell<bool>>,
    bound: SigningBound,
}

impl MemberSlot {
    /// The signing bound the installed member authority reports into.
    pub fn signing_bound(&self) -> SigningBound {
        self.bound.clone()
    }
    /// Install the member authority of exactly this community member's `binding`.
    /// Refused a second time.
    pub fn install<A: ckmg::Authority + 'static>(
        &self,
        binding: Binding,
        authority: A,
    ) -> super::super::Result<()> {
        if self.used.replace(true) {
            crate::door::cause::print(
                file!(),
                line!(),
                "member slot: already installed once",
                &ErrorCode::Unauthorized,
            );
            return Err(ErrorCode::Unauthorized);
        }
        *self.slot.borrow_mut() = Some((binding, Box::new(authority)));
        Ok(())
    }
}

/// What the start restore knows when it binds the member authority of an eager Vault.
pub struct BindInputs {
    pub origin: String,
    pub prepared: cvlt::PreparedOpen,
    pub binding: Binding,
    pub stamps: Option<cvlt::StampTrust>,
    pub member: MemberAuthorityBuilder,
    pub now: u64,
}

type BindFuture<'a> =
    Pin<Box<dyn Future<Output = super::super::Result<ckmg::IntentAdmission>> + 'a>>;

/// The one late bind of an eager Vault, made when the Vault is composed: it reads the
/// member's lineage through the very records network the Vault was recovered from (the
/// embedder's, which holds the registration's checkpoints), not the start restore's own.
pub struct MemberBinder(Box<dyn for<'a> FnOnce(&'a Door, BindInputs) -> BindFuture<'a>>);

impl MemberBinder {
    pub fn new<N: cdht::Network + Clone + 'static>(slot: MemberSlot, network: N) -> Self {
        Self(Box::new(move |door, inputs| {
            Box::pin(async move {
                door.bind_member_authority(
                    &inputs.origin,
                    inputs.prepared,
                    &inputs.binding,
                    inputs.stamps,
                    inputs.member,
                    network,
                    &slot,
                    inputs.now,
                )
                .await
            })
        }))
    }

    /// A binder that binds nothing (a Door whose Vault was never composed).
    #[cfg(test)]
    pub fn unbound() -> Self {
        Self(Box::new(|_, _| {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }))
    }

    /// Bind the member authority: see `Door::bind_member_authority`.
    pub async fn bind(
        self,
        door: &Door,
        inputs: BindInputs,
    ) -> super::super::Result<ckmg::IntentAdmission> {
        (self.0)(door, inputs).await
    }
}

/// `initial` for everything, except Board device signing once a member authority is
/// installed (and while the account actor does not hold the arm).
pub struct LateMemberAuthority<A> {
    initial: A,
    slot: MemberSlot,
    member: Option<(Binding, Box<dyn BoardSigning>)>,
    arm: Rc<ArmState>,
}

impl<A> LateMemberAuthority<A> {
    /// `arm` is the account port's arm: while it is held the account's device
    /// signatures belong to `initial`, never to the Board's member authority.
    pub fn new(initial: A, arm: Rc<ArmState>) -> (Self, MemberSlot) {
        let slot = MemberSlot::default();
        (
            Self {
                initial,
                slot: slot.clone(),
                member: None,
                arm,
            },
            slot,
        )
    }

    /// The member authority, for the actions of the Board's one signing admission: its
    /// device signature (unless the account actor holds the arm) and its Profile custody.
    /// The initial authority admits neither. Exact: only this member's own binding, and
    /// Profile custody only in its plain shape (no target, statement or signing); the
    /// member authority itself then admits it solely against the Board's single-use
    /// admitted command for exactly that action.
    fn board(&mut self, request: &Authorization<'_>) -> Option<&mut Box<dyn BoardSigning>> {
        let board = match request.action {
            Action::SignDeviceEd25519 => !self.arm.is_armed(),
            Action::LendProfileCustody => {
                request.target.is_none() && request.statement.is_none() && request.signing.is_none()
            }
            _ => false,
        };
        if !board {
            return None;
        }
        if self.member.is_none() {
            self.member = self.slot.slot.borrow_mut().take();
        }
        match self.member.as_mut() {
            Some((own, member)) if own == request.binding => Some(member),
            // A Board action falls through to the initial authority, which refuses it.
            Some(_) => {
                crate::door::cause::print(
                    file!(),
                    line!(),
                    "board action: member authority of another binding",
                    &request.action,
                );
                None
            }
            None => {
                crate::door::cause::print(
                    file!(),
                    line!(),
                    "board action: no member authority installed",
                    &request.action,
                );
                None
            }
        }
    }
}

impl<A> LateMemberAuthority<A> {
    /// Defence in depth for the two account signatures this router hands to `initial`
    /// while the arm carries the account actor's verified grant (L20261114b): never past
    /// min(grant end, now + 24 h). `initial` still applies its own lease and grant check;
    /// every other signature's bound is `initial`'s alone.
    fn account_cap(&self, request: &Authorization<'_>) -> Result<(), Error> {
        let (Some(grant), Some(signing)) = (self.arm.grant_end(), request.signing) else {
            return Ok(());
        };
        if super::is_account_signature(request)
            && signing.expires > super::signature_bound(request, Some(grant), 0, request.now)
        {
            crate::door::cause::print(
                file!(),
                line!(),
                "account signature past the grant end or the one-day cap",
                &Error::Expired,
            );
            return Err(Error::Expired);
        }
        Ok(())
    }
}

impl<A: ckmg::Authority> ckmg::Authority for LateMemberAuthority<A> {
    async fn check_initial_activation(
        &mut self,
        request: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.initial.check_initial_activation(request).await
    }
    fn check_initial_activation_current(
        &mut self,
        request: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.initial.check_initial_activation_current(request)
    }
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        match self.board(&request) {
            Some(member) => member.board_check(request).await,
            None => {
                self.account_cap(&request)?;
                self.initial.check(request).await
            }
        }
    }
    fn check_checkpoint_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.initial.check_checkpoint_current(request)
    }
    fn check_account_device_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.account_cap(&request)?;
        self.initial.check_account_device_current(request)
    }
    async fn check_account_signing(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.initial.check_account_signing(request).await
    }
    fn check_account_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.initial.check_account_signing_current(request)
    }
    async fn check_device_signing(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        match self.board(&request) {
            Some(member) => member.board_signing(request).await,
            None => {
                self.account_cap(&request)?;
                self.initial.check_device_signing(request).await
            }
        }
    }
    async fn check_record_recipient(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.initial.check_record_recipient(request).await
    }
    fn discard_current_attempt(&mut self) {
        if let Some((_, member)) = self.member.as_mut() {
            member.board_discard();
        }
        self.initial.discard_current_attempt();
    }
    fn check_device_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        match self.board(&request) {
            Some(member) => member.board_current(request),
            None => {
                self.account_cap(&request)?;
                self.initial.check_device_signing_current(request)
            }
        }
    }
    fn check_record_recipient_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.initial.check_record_recipient_current(request)
    }
    async fn check_genesis(
        &mut self,
        request: ckmg::GenesisAuthorization<'_>,
    ) -> Result<(), Error> {
        self.initial.check_genesis(request).await
    }
    fn check_genesis_current(
        &mut self,
        request: ckmg::GenesisAuthorization<'_>,
    ) -> Result<(), Error> {
        self.initial.check_genesis_current(request)
    }
    async fn check_completion(
        &mut self,
        request: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.initial.check_completion(request).await
    }
    fn check_completion_current(
        &mut self,
        request: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.initial.check_completion_current(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckmg::Authority;

    /// Stands for the initial recovery authority: no Board device signing (it is allowed
    /// only for the account Delegation channel), everything else accepted.
    struct Initial;
    impl Authority for Initial {
        async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
            if matches!(
                request.action,
                Action::SignDeviceEd25519 | Action::LendProfileCustody
            ) {
                return Err(Error::Unauthorized);
            }
            Ok(())
        }
        fn check_device_signing_current(&mut self, _: Authorization<'_>) -> Result<u64, Error> {
            Err(Error::Unauthorized)
        }
    }

    /// Stands for the member authority: admits Board device signing only.
    struct Member;
    impl Authority for Member {
        async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
            if matches!(
                request.action,
                Action::SignDeviceEd25519 | Action::LendProfileCustody
            ) {
                Ok(())
            } else {
                Err(Error::Unauthorized)
            }
        }
        fn check_device_signing_current(&mut self, _: Authorization<'_>) -> Result<u64, Error> {
            Ok(42)
        }
    }

    fn request<'a>(binding: &'a Binding, action: Action) -> Authorization<'a> {
        Authorization {
            binding,
            root: None,
            device: PublicKey::new(ckmg::VLD0, [1; 32]),
            epoch: 1,
            action,
            target: None,
            statement: None,
            signing: None,
            now: 1,
            evidence: &[],
        }
    }

    fn late() -> (LateMemberAuthority<Initial>, MemberSlot, AccountArm) {
        let arm = AccountArm::default();
        let (authority, slot) = LateMemberAuthority::new(Initial, arm.state());
        (authority, slot, arm)
    }

    /// Before the start restore proves the device is in the current lineage, Board
    /// signing is refused by the initial authority, in both the async and the final check.
    #[tokio::test]
    async fn board_signing_is_refused_until_the_member_authority_is_installed() {
        let binding = Binding::new("c", "m").unwrap();
        let (mut authority, _slot, _) = late();
        let sign = request(&binding, Action::SignDeviceEd25519);
        assert_eq!(
            authority.check_device_signing(sign).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority
                .check(request(&binding, Action::LendProfileCustody))
                .await,
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority.check_device_signing_current(request(&binding, Action::SignDeviceEd25519)),
            Err(Error::Unauthorized)
        );
    }

    /// After the install, Board signing is the member authority's, and every other
    /// action stays the initial authority's.
    #[tokio::test]
    async fn board_signing_succeeds_through_the_installed_member_authority() {
        let binding = Binding::new("c", "m").unwrap();
        let (mut authority, slot, _) = late();
        slot.install(binding.clone(), Member).unwrap();
        assert_eq!(
            authority
                .check_device_signing(request(&binding, Action::SignDeviceEd25519))
                .await,
            Ok(())
        );
        assert_eq!(
            authority.check_device_signing_current(request(&binding, Action::SignDeviceEd25519)),
            Ok(42)
        );
        // Profile custody is the same admission's; the initial authority refuses it.
        assert_eq!(
            authority
                .check(request(&binding, Action::LendProfileCustody))
                .await,
            Ok(())
        );
        // The member authority never decides a non-signing action.
        assert_eq!(
            authority.check(request(&binding, Action::Use)).await,
            Ok(())
        );
    }

    /// While the account actor holds the arm, device signatures are the account's: the
    /// initial authority's, never the Board's member authority.
    #[tokio::test]
    async fn account_signing_stays_with_the_initial_authority() {
        let binding = Binding::new("c", "m").unwrap();
        let (mut authority, slot, arm) = late();
        slot.install(binding.clone(), Member).unwrap();
        let _armed = arm.arm();
        assert_eq!(
            authority
                .check(request(&binding, Action::SignDeviceEd25519))
                .await,
            Err(Error::Unauthorized)
        );
    }

    /// The member authority is installed once.
    #[test]
    fn the_member_authority_installs_only_once() {
        let (_authority, slot, _) = late();
        let binding = Binding::new("c", "m").unwrap();
        assert_eq!(slot.install(binding.clone(), Member), Ok(()));
        assert_eq!(slot.install(binding, Member), Err(ErrorCode::Unauthorized));
    }

    /// Stands for the member authority's Profile custody rule: only against the single-use
    /// admitted command (consumed exactly as `MemberAuthority::check` does).
    struct Admitted(ckmg::IntentVerifier);
    impl Authority for Admitted {
        async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
            match request.action {
                Action::LendProfileCustody => self.0.consume(&request, "o"),
                _ => Err(Error::Unauthorized),
            }
        }
    }

    fn command(binding: &Binding) -> ckmg::AdmittedCommand {
        ckmg::AdmittedCommand {
            binding: binding.clone(),
            origin: "o".into(),
            action: Action::LendProfileCustody,
            device: PublicKey::new(ckmg::VLD0, [1; 32]),
            root: None,
            epoch: 1,
            target: None,
            statement: None,
            transcript: None,
            format: None,
            expires: 100,
        }
    }

    /// Profile custody is lent for this member's own profile only: another member's
    /// binding is refused even when an admission for that binding is pending.
    #[tokio::test]
    async fn profile_custody_is_refused_for_another_members_profile() {
        let own = Binding::new("c", "m").unwrap();
        let other = Binding::new("c", "other").unwrap();
        let (mut authority, slot, _) = late();
        let (mut admission, verifier) = ckmg::intent_channel();
        slot.install(own.clone(), Admitted(verifier)).unwrap();
        let _guard = admission.admit(command(&other), 1).unwrap();
        assert_eq!(
            authority
                .check(request(&other, Action::LendProfileCustody))
                .await,
            Err(Error::Unauthorized)
        );
        // The refusal did not consume the pending admission: it is still spent on the owner.
        let _guard = ();
        assert!(admission.admit(command(&own), 1).is_err());
    }

    /// Profile custody is lent only inside the Board's admission, once: with no admitted
    /// command, after it was spent, and for a request that names a target it is refused.
    #[tokio::test]
    async fn profile_custody_is_refused_outside_a_board_admission() {
        let own = Binding::new("c", "m").unwrap();
        let (mut authority, slot, _) = late();
        let (mut admission, verifier) = ckmg::intent_channel();
        slot.install(own.clone(), Admitted(verifier)).unwrap();
        // No admission at all.
        assert_eq!(
            authority
                .check(request(&own, Action::LendProfileCustody))
                .await,
            Err(Error::Unauthorized)
        );
        // A shaped request (target) never reaches the member authority.
        let guard = admission.admit(command(&own), 1).unwrap();
        let mut shaped = request(&own, Action::LendProfileCustody);
        shaped.target = Some(PublicKey::new(ckmg::VLD0, [2; 32]));
        assert_eq!(authority.check(shaped).await, Err(Error::Unauthorized));
        // Inside the admission: once.
        assert_eq!(
            authority
                .check(request(&own, Action::LendProfileCustody))
                .await,
            Ok(())
        );
        assert_eq!(
            authority
                .check(request(&own, Action::LendProfileCustody))
                .await,
            Err(Error::Unauthorized)
        );
        drop(guard);
    }

    /// Stands for the initial recovery authority's expiry rule (L20261114b): a signature
    /// needs a live lease and an expiry within `signature_bound` of the arm it shares.
    struct Leased(Rc<ArmState>);
    const NOW: u64 = 1_000;
    const LEASE: u64 = NOW + 900;
    const GRANT: u64 = NOW + 20 * 3_600;
    impl Leased {
        fn rule(&self, request: &Authorization<'_>) -> Result<u64, Error> {
            let signing = request.signing.ok_or(Error::Unauthorized)?;
            if request.now >= LEASE
                || signing.expires
                    > super::super::signature_bound(request, self.0.grant_end(), LEASE, request.now)
            {
                return Err(Error::Expired);
            }
            Ok(request.now)
        }
    }
    impl Authority for Leased {
        async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
            self.rule(&request).map(|_| ())
        }
        fn check_account_device_current(
            &mut self,
            request: Authorization<'_>,
        ) -> Result<u64, Error> {
            self.rule(&request)
        }
        fn check_device_signing_current(
            &mut self,
            request: Authorization<'_>,
        ) -> Result<u64, Error> {
            self.rule(&request)
        }
    }

    /// Accepts every signature, so only the router's own cap can refuse.
    struct Permissive;
    impl Authority for Permissive {
        async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
            Ok(())
        }
        fn check_account_device_current(&mut self, _: Authorization<'_>) -> Result<u64, Error> {
            Ok(NOW)
        }
        fn check_device_signing_current(&mut self, _: Authorization<'_>) -> Result<u64, Error> {
            Ok(NOW)
        }
    }

    fn signing(
        binding: &Binding,
        format: Option<ckmg::DeviceFormat>,
        expires: u64,
        now: u64,
    ) -> Authorization<'_> {
        let action = match format {
            None => Action::AuthorizeAccountDevice,
            Some(_) => Action::SignDeviceEd25519,
        };
        super::super::signing_request(binding, action, format, expires, now)
    }

    const DELEGATION: Option<ckmg::DeviceFormat> = Some(ckmg::DeviceFormat::AccountingDelegation);

    /// Both account signatures reach the initial authority and are accepted up to the
    /// grant end the arm carries, in the async and the final check.
    async fn both_through<A: Authority>(
        authority: &mut LateMemberAuthority<A>,
        binding: &Binding,
        expires: u64,
    ) -> [Result<u64, Error>; 4] {
        [
            authority
                .check(signing(binding, None, expires, NOW))
                .await
                .map(|_| NOW),
            authority.check_account_device_current(signing(binding, None, expires, NOW)),
            authority
                .check_device_signing(signing(binding, DELEGATION, expires, NOW))
                .await
                .map(|_| NOW),
            authority.check_device_signing_current(signing(binding, DELEGATION, expires, NOW)),
        ]
    }

    #[tokio::test]
    async fn both_account_signatures_are_accepted_up_to_the_grant_end() {
        let binding = Binding::new("c", "m").unwrap();
        let arm = AccountArm::default();
        let (mut authority, slot) = LateMemberAuthority::new(Leased(arm.state()), arm.state());
        slot.install(binding.clone(), Member).unwrap();
        let _armed = arm.arm_carrying(Some(crate::door::accounting::VerifiedGrantEnd::for_test(
            GRANT,
        )));
        assert_eq!(
            both_through(&mut authority, &binding, GRANT).await,
            [Ok(NOW); 4]
        );
    }

    /// Every other signature keeps the initial authority's lease bound while armed.
    #[tokio::test]
    async fn any_other_signature_past_the_lease_is_refused() {
        let binding = Binding::new("c", "m").unwrap();
        let arm = AccountArm::default();
        let (mut authority, _slot) = LateMemberAuthority::new(Leased(arm.state()), arm.state());
        let _armed = arm.arm_carrying(Some(crate::door::accounting::VerifiedGrantEnd::for_test(
            GRANT,
        )));
        let request = Some(ckmg::DeviceFormat::AccountRequest);
        assert_eq!(
            authority
                .check_device_signing(signing(&binding, request, LEASE + 1, NOW))
                .await,
            Err(Error::Expired)
        );
        assert_eq!(
            authority.check_device_signing_current(signing(&binding, request, LEASE + 1, NOW)),
            Err(Error::Expired)
        );
        assert_eq!(
            authority.check_device_signing_current(signing(&binding, request, LEASE, NOW)),
            Ok(NOW)
        );
    }

    /// The router itself refuses an account signature past the carried grant end, even in
    /// front of an inner authority that would accept it.
    #[tokio::test]
    async fn an_account_signature_past_the_grant_end_is_refused() {
        let binding = Binding::new("c", "m").unwrap();
        let arm = AccountArm::default();
        let (mut authority, _slot) = LateMemberAuthority::new(Permissive, arm.state());
        let _armed = arm.arm_carrying(Some(crate::door::accounting::VerifiedGrantEnd::for_test(
            GRANT,
        )));
        assert_eq!(
            both_through(&mut authority, &binding, GRANT + 1).await,
            [Err(Error::Expired); 4]
        );
        assert_eq!(
            both_through(&mut authority, &binding, GRANT).await,
            [Ok(NOW); 4]
        );
    }

    /// The router's one-day cap holds even when the carried grant claims a longer end.
    #[tokio::test]
    async fn an_account_signature_past_one_day_is_refused_even_under_a_longer_grant() {
        let binding = Binding::new("c", "m").unwrap();
        let cap = NOW + super::super::ACCOUNT_SIGNATURE_MAX_SECONDS;
        let arm = AccountArm::default();
        let (mut authority, _slot) = LateMemberAuthority::new(Permissive, arm.state());
        let _armed = arm.arm_carrying(Some(crate::door::accounting::VerifiedGrantEnd::for_test(
            NOW + 3 * super::super::ACCOUNT_SIGNATURE_MAX_SECONDS,
        )));
        assert_eq!(
            both_through(&mut authority, &binding, cap + 1).await,
            [Err(Error::Expired); 4]
        );
        assert_eq!(
            both_through(&mut authority, &binding, cap).await,
            [Ok(NOW); 4]
        );
    }

    /// No live lease, no signature; and with the arm dropped the grant is gone, so neither
    /// account signature outlives the lease (the delegation format then is the Board's).
    #[tokio::test]
    async fn no_lease_or_a_disarmed_arm_gives_no_signature() {
        let binding = Binding::new("c", "m").unwrap();
        let arm = AccountArm::default();
        let (mut authority, _slot) = LateMemberAuthority::new(Leased(arm.state()), arm.state());
        let armed = arm.arm_carrying(Some(crate::door::accounting::VerifiedGrantEnd::for_test(
            GRANT,
        )));
        assert_eq!(
            authority.check_account_device_current(signing(&binding, None, GRANT, LEASE)),
            Err(Error::Expired)
        );
        assert_eq!(
            authority.check_device_signing_current(signing(&binding, DELEGATION, GRANT, LEASE)),
            Err(Error::Expired)
        );
        drop(armed);
        assert_eq!(
            both_through(&mut authority, &binding, GRANT).await,
            [Err(Error::Expired); 4]
        );
    }
}
