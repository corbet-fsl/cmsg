//! Browser lifetime and durable cancellation bindings for the actual Inbox.
use super::*;
fn fixed(bytes: &[u8]) -> Result<&[u8; 32], JsValue> {
    bytes
        .try_into()
        .map_err(|_| js_error(Error::InvalidMessage))
}
fn wires(values: Vec<Vec<u8>>) -> Array {
    values
        .iter()
        .map(|v| JsValue::from(Uint8Array::from(v.as_slice())))
        .collect()
}
#[wasm_bindgen]
impl BrowserInbox {
    #[wasm_bindgen(js_name=sendLiveBytes)]
    pub async fn send_live_bytes(
        &mut self,
        session: &[u8],
        bytes: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping = wrapping_key(key)?;
        let session = fixed(session)?;
        self.apply_deadlines(key, context, persist.clone()).await?;
        let result = self
            .update(key, context, &persist, |inbox, member| {
                let mut changed = false;
                let outcome =
                    inbox.send_live_bytes(member, session, bytes, &wrapping, context, |_, _| {
                        changed = true;
                        Ok(())
                    });
                match outcome {
                    Ok(wire) => Ok((Ok(wire.clone()), vec![wire])),
                    Err(error) if changed => Ok((Err(error), vec![])),
                    Err(error) => Err(error),
                }
            })
            .await?;
        result.map_err(js_error)
    }
    #[wasm_bindgen(js_name=liveSessionForOpening)]
    pub fn live_session_for_opening(&self, nonce: &[u8]) -> Result<Option<Vec<u8>>, JsValue> {
        Ok(self
            .inbox
            .live_session_for_opening(fixed(nonce)?)
            .map(|s| s.to_vec()))
    }

    #[wasm_bindgen(js_name=beginLiveSession)]
    pub async fn begin_live_session(
        &mut self,
        peer_device: &[u8],
        until: f64,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping = wrapping_key(key)?;
        let until = timestamp(until)?;
        self.update(key, context, &persist, |inbox, member| {
            let wire = inbox.begin_live_session(
                member,
                peer_device,
                until,
                &wrapping,
                context,
                |_, _| Ok(()),
            )?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }
    #[wasm_bindgen(js_name=pendingLiveControlsFor)]
    pub fn pending_live_controls_for(&self, nonce: &[u8]) -> Result<Array, JsValue> {
        Ok(wires(self.inbox.pending_live_controls_for(fixed(nonce)?)))
    }
    #[wasm_bindgen(js_name=clearLiveControlsFor)]
    pub async fn clear_live_controls_for(
        &mut self,
        nonce: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        let nonce = fixed(nonce)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.clear_live_controls_for(member, nonce, &wrapping, context, |_| Ok(()))?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=liveSessions)]
    pub fn live_sessions(&self) -> Array {
        wires(
            self.inbox
                .live_sessions()
                .iter()
                .map(|s| s.to_vec())
                .collect(),
        )
    }
    #[wasm_bindgen(js_name=liveOpeningNonce)]
    pub fn live_opening_nonce(&self, peer_device: &[u8]) -> Option<Vec<u8>> {
        self.inbox
            .live_opening_nonce(peer_device)
            .map(|n| n.to_vec())
    }
    #[wasm_bindgen(js_name=cancelLiveOpening)]
    pub async fn cancel_live_opening(
        &mut self,
        nonce: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        let nonce = fixed(nonce)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.cancel_live_opening(member, nonce, &wrapping, context, |_| Ok(()))?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=liveDeliveries)]
    pub fn live_deliveries(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inbox.live_deliveries())
            .map_err(|_| js_error(Error::InvalidStore))
    }
    #[wasm_bindgen(js_name=pendingLiveControls)]
    pub fn pending_live_controls(&self) -> Array {
        wires(self.inbox.pending_live_controls())
    }
    #[wasm_bindgen(js_name=clearLiveControls)]
    pub async fn clear_live_controls(
        &mut self,
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.clear_live_controls(member, &wrapping, context, |_| Ok(()))?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=loseLiveSession)]
    pub async fn lose_live_session(
        &mut self,
        session: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<(), JsValue> {
        let wrapping = wrapping_key(key)?;
        let session = fixed(session)?;
        self.update(key, context, &persist, |inbox, member| {
            inbox.lose_live_session(member, session, &wrapping, context, |_| Ok(()))?;
            Ok(((), vec![]))
        })
        .await
    }
    #[wasm_bindgen(js_name=endLiveSession)]
    pub async fn end_live_session(
        &mut self,
        session: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping = wrapping_key(key)?;
        let session = fixed(session)?;
        self.update(key, context, &persist, |inbox, member| {
            let wire =
                inbox.end_live_session(member, session, &wrapping, context, |_, _| Ok(()))?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }
    #[wasm_bindgen(js_name=retransmitLiveAck)]
    pub async fn retransmit_live_ack(
        &mut self,
        message: &[u8],
        key: &[u8],
        context: &[u8],
        persist: Function,
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping = wrapping_key(key)?;
        let message = fixed(message)?;
        self.update(key, context, &persist, |inbox, member| {
            let wire =
                inbox.retransmit_live_ack(member, message, &wrapping, context, |_, _| Ok(()))?;
            Ok((wire.clone(), vec![wire]))
        })
        .await
    }
    #[wasm_bindgen(js_name=canTransmitLiveWire)]
    pub fn can_transmit_live_wire(&self, wire: &[u8]) -> Result<bool, JsValue> {
        self.inbox
            .can_transmit_live_wire(wire, &self.member)
            .map_err(js_error)
    }
    #[wasm_bindgen(js_name=acceptedLiveHistory)]
    pub fn accepted_live_history(&self) -> Array {
        self.inbox
            .accepted_live_history()
            .into_iter()
            .map(|message| {
                JsValue::from(BrowserReceived {
                    received: Received::Bytes(message),
                })
            })
            .collect()
    }
}
