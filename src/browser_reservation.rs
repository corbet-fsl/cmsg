//! Host proof-verifier bindings; a peer-supplied success boolean is never parsed.
use super::*;
use crate::{ReservationContext, ReservationPolicy, ReservationVerifier, VerifiedReservation};
struct CheckedValue {
    context: ReservationContext,
    own: bool,
    evidence: [u8; 32],
    value: VerifiedReservation,
}
struct Checked(Vec<CheckedValue>);
impl Checked {
    fn matching(
        &self,
        evidence: &[u8],
        context: &ReservationContext,
        own: bool,
    ) -> Result<VerifiedReservation, Error> {
        self.0
            .iter()
            .find(|v| {
                v.own == own
                    && v.evidence == crate::live::hash(evidence)
                    && v.context.expected == context.expected
                    && v.context.device_public_key == context.device_public_key
                    && context.now >= v.context.now
                    && context.now < v.value.valid_until
            })
            .map(|v| v.value.clone())
            .ok_or(Error::Admission)
    }
}
impl ReservationVerifier for Checked {
    fn verify_remote(
        &mut self,
        e: &[u8],
        c: &ReservationContext,
    ) -> Result<VerifiedReservation, Error> {
        self.matching(e, c, false)
    }
    fn verify_current_local(
        &mut self,
        e: &[u8],
        c: &ReservationContext,
    ) -> Result<VerifiedReservation, Error> {
        self.matching(e, c, true)
    }
}
async fn verify_host(
    callback: &Function,
    evidence: &[u8],
    context: &ReservationContext,
    own: bool,
) -> Result<CheckedValue, JsValue> {
    if evidence.is_empty() || evidence.len() > MAX_WIRE_BYTES {
        return Err(js_error(Error::Admission));
    }
    let expected = serde_json::to_string(context).map_err(|_| js_error(Error::Admission))?;
    let value = callback
        .call3(
            &JsValue::UNDEFINED,
            &Uint8Array::from(evidence).into(),
            &JsValue::from_str(&expected),
            &JsValue::from_bool(own),
        )
        .map_err(|_| js_error(Error::Admission))?;
    if !value.is_instance_of::<Promise>() {
        return Err(js_error(Error::Admission));
    }
    let value = JsFuture::from(Promise::from(value))
        .await
        .map_err(|_| js_error(Error::Admission))?;
    let text = value
        .as_string()
        .filter(|s| s.len() <= 16 * 1024)
        .ok_or_else(|| js_error(Error::Admission))?;
    let value = serde_json::from_str(&text).map_err(|_| js_error(Error::Admission))?;
    Ok(CheckedValue {
        context: context.clone(),
        own,
        evidence: crate::live::hash(evidence),
        value,
    })
}
#[wasm_bindgen]
impl BrowserInbox {
    #[wasm_bindgen(js_name=newAccounted)]
    pub fn new_accounted(member: BrowserMember) -> Result<BrowserInbox, JsValue> {
        Ok(Self {
            inbox: Inbox::new_accounted(&member.member).map_err(js_error)?,
            member: member.member,
        })
    }
    #[wasm_bindgen(js_name=requireActiveReservations)]
    pub async fn require_active_reservations(
        &mut self,
        policy_json: &str,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<String, JsValue> {
        if policy_json.len() > 4096 {
            return Err(js_error(Error::Admission));
        }
        let policy: ReservationPolicy =
            serde_json::from_str(policy_json).map_err(|_| js_error(Error::Admission))?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            let expected = inbox.require_active_reservations(
                member,
                policy,
                &wrapping,
                context,
                |_| Ok(()),
            )?;
            Ok((
                serde_json::to_string(&expected).map_err(|_| Error::InvalidState)?,
                vec![],
            ))
        })
        .await
    }
    #[wasm_bindgen(js_name=reservationContexts)]
    pub fn reservation_contexts(&self) -> Result<String, JsValue> {
        serde_json::to_string(
            &self
                .inbox
                .reservation_contexts(&self.member)
                .map_err(js_error)?,
        )
        .map_err(|_| js_error(Error::Admission))
    }
    #[wasm_bindgen(js_name=setOwnReservationChallenge)]
    pub async fn set_own_reservation_challenge(
        &mut self,
        challenge: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let challenge: &[u8; 32] = challenge
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox
                .set_own_reservation_challenge(member, challenge, &wrapping, context, |_| Ok(()))?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=authorizeIncomingReservation)]
    pub async fn authorize_incoming_reservation(
        &mut self,
        outgoing: &[u8],
        verifier: Function,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let expected = self
            .inbox
            .reservation_contexts(&self.member)
            .map_err(js_error)?;
        let checked = verify_host(&verifier, outgoing, &expected.outgoing, false).await?;
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.authorize_incoming_reservation(
                member,
                outgoing,
                &mut Checked(vec![checked]),
                &wrapping,
                context,
                |_| Ok(()),
            )?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=bindActiveReservations)]
    pub async fn bind_active_reservations(
        &mut self,
        outgoing: &[u8],
        incoming: &[u8],
        verifier: Function,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let expected = self
            .inbox
            .reservation_contexts(&self.member)
            .map_err(js_error)?;
        let own = data_encoding::BASE64URL_NOPAD
            .decode(self.member.member_id().map_err(js_error)?.as_bytes())
            .map_err(|_| js_error(Error::Admission))?;
        let local_outgoing = own == expected.outgoing.expected.owner;
        let remote = if local_outgoing {
            verify_host(&verifier, incoming, &expected.incoming, false).await?
        } else {
            verify_host(&verifier, outgoing, &expected.outgoing, false).await?
        };
        let refreshed = self
            .inbox
            .reservation_contexts(&self.member)
            .map_err(js_error)?;
        let local = if local_outgoing {
            verify_host(&verifier, outgoing, &refreshed.outgoing, true).await?
        } else {
            verify_host(&verifier, incoming, &refreshed.incoming, true).await?
        };
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.bind_active_reservations(
                member,
                outgoing,
                incoming,
                &mut Checked(vec![remote, local]),
                &wrapping,
                context,
                |_| Ok(()),
            )?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=invalidateReservation)]
    pub async fn invalidate_reservation(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.invalidate_reservation(member, &wrapping, context, |_| Ok(()))?;
            Ok(((), vec![]))
        })
        .await
    }
}
