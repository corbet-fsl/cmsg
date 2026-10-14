//! The ephemeral listener of one pairing offer and the new device's channel to it.
//!
//! The existing device opens a SECOND mesh listener for exactly one offer (the member's
//! own listener keeps serving the profile), shows the `cvpr1.` link that names its
//! address, serves the sealed rounds of [`Host`], and drops the listener when the offer is
//! finished or expired, which withdraws the address. The new device reaches it with
//! [`MeshChannel`] over its own mesh. Nothing here knows what a round carries.
use super::pairing::Offer;
use super::pairing_roles::{Channel, Host, HostSteps};
use super::*;

/// What one served message did to the offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    /// A message was answered or refused; the offer is still open.
    Open,
    /// All rounds are answered.
    Finished,
    /// The window ended; nothing more is served.
    Expired,
    /// The listener lost its network; the person starts a new link.
    Closed,
}

/// One open offer: its listener, its link and the host that serves the rounds.
pub struct PairingListener<S: HostSteps> {
    listening: cmsh::Listening,
    host: Host<S>,
    link: String,
}

impl<S: HostSteps> PairingListener<S> {
    /// Open a listener on `mesh` and an offer of `window` seconds (the rulebook's pairing
    /// window) for it. The window is bounded by the hard limit of a pairing request.
    pub async fn open(mesh: &cmsh::Mesh, steps: S, now: u64, window: u64) -> Result<Self> {
        let listening = mesh.listen().await.map_err(|_| ErrorCode::Unavailable)?;
        let address = listening
            .addresses()
            .first()
            .ok_or(ErrorCode::Unavailable)?
            .clone();
        let (offer, link) = Offer::with_window(&address, now, window)?;
        Ok(Self {
            listening,
            host: Host::new(offer, steps),
            link,
        })
    }

    /// The link to show as QR code or text.
    pub fn link(&self) -> &str {
        &self.link
    }

    /// Unix seconds the offer stays open.
    pub fn expires(&self) -> u64 {
        self.host.expires()
    }

    /// Serve the next incoming message. A refused or malformed message gets no reply and
    /// no detail; only the holder of the link can ever receive an answer.
    pub async fn serve_next(&mut self, now: impl Fn() -> u64) -> Served {
        if self.host.finished() {
            return Served::Finished;
        }
        if now() >= self.host.expires() {
            return Served::Expired;
        }
        match self.listening.next().await {
            Some(cmsh::Incoming::Call { payload, reply, .. }) => {
                if let Ok(answer) = self.host.serve(&payload, now()).await {
                    let _ = reply.send(&answer).await;
                }
            }
            Some(cmsh::Incoming::Message { .. }) => {}
            Some(cmsh::Incoming::ListenerClosed(..)) | None => return Served::Closed,
        }
        if self.host.finished() {
            Served::Finished
        } else {
            Served::Open
        }
    }

    /// Close the listener and give the steps back.
    pub fn close(mut self) -> S {
        self.listening.close();
        self.host.into_steps()
    }
}

/// The new device's channel: one sealed call over its own mesh.
pub struct MeshChannel<'a>(pub &'a cmsh::Mesh);

impl Channel for MeshChannel<'_> {
    async fn call(&mut self, address: &cmsh::Address, message: &[u8]) -> Result<Vec<u8>> {
        self.0
            .app_call(std::slice::from_ref(address), message)
            .await
            .map_err(|_| ErrorCode::Unavailable)
    }
}

impl Door {
    /// The mesh of a bound origin, for an ephemeral pairing listener or channel.
    pub fn pairing_mesh(&self, origin: &str) -> Result<&cmsh::Mesh> {
        self.meshes
            .get(origin)
            .map(|bound| &bound.shared.mesh)
            .ok_or(ErrorCode::Unavailable)
    }
}
