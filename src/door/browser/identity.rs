//! Original node-purpose signing for the one browser transport custody session.
use super::records::{Identity, Verifier};
use crate::door::{custody, network_browser, Door, ErrorCode};
use cdht::{
    rpc::{
        envelope::{
            AuthenticatedOperation, Envelope, EnvelopeCipher, TimeWindow, MAX_ENVELOPE_BYTES,
        },
        peers::{Advertisement, FindAnswer},
        Answer, Question, SignedOperation, Statement, UnverifiedPeerInfoBytes,
    },
    Error, NodeId,
};
use cmsh::tor_discovery::{TorEnvelopeTime, TorNodeIdentity};
use std::{rc::Rc, sync::Arc};

type Transport = network_browser::BrowserTor<
    custody::SystemClock,
    custody::TransportAuthority<custody::SystemClock>,
>;

/// Typed original protocol operations only. Secret custody remains in BrowserTor
/// and every signing/DH callback performs fresh original transport authorization.
#[derive(Clone)]
pub struct TransportClient {
    transport: Rc<Transport>,
    lifetime: custody::CustodyLifetime,
    window: TimeWindow,
}

/// Retain with the accepted Vault. Losing this owner closes every client clone,
/// the original Tor engine and the same negative member/transport lifetime.
#[must_use = "retain through restore and member use"]
pub struct TransportOwner {
    transport: Rc<Transport>,
    lifetime: custody::CustodyLifetime,
    member: Option<custody::MemberAuthorityBuilder>,
}
impl TransportOwner {
    pub fn take_member_authority(
        &mut self,
    ) -> crate::door::Result<custody::MemberAuthorityBuilder> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        self.member.take().ok_or(ErrorCode::Unavailable)
    }
    pub fn lifetime(&self) -> custody::CustodyLifetime {
        self.lifetime.clone()
    }
    pub fn close(&self) {
        self.lifetime.close();
        self.transport.close();
    }
    pub async fn shutdown(self) -> crate::door::Result<()> {
        self.close();
        self.transport.shutdown().await
    }
}
impl Drop for TransportOwner {
    fn drop(&mut self) {
        self.close();
    }
}
struct Starting(Option<custody::CustodyLifetime>);
impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(lifetime) = &self.0 {
            lifetime.close();
        }
    }
}
impl Door {
    /// Trusted construction after original passkey handover. Binding comes from
    /// the authenticated Foyer; configuration never marks a member ready.
    pub async fn prepare_browser_transport(
        &self,
        origin: &str,
        prepared: &cvlt::PreparedOpen,
        binding: ckmg::Binding,
        scope: ctrn::Scope,
        config: network_browser::Configuration,
        window: TimeWindow,
    ) -> crate::door::Result<(TransportClient, TransportOwner)> {
        let device = prepared.device().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let (authority, lifetime) =
            self.transport_authority(origin, binding.clone(), device, custody::SystemClock)?;
        let mut starting = Starting(Some(lifetime.clone()));
        let member = self.member_authority_builder(origin, &authority)?;
        let session = prepared
            .transport(binding, custody::SystemClock, authority)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let transport = Rc::new(Transport::start(session, scope, config).await?);
        starting.0.take();
        Ok((
            TransportClient {
                transport: transport.clone(),
                lifetime: lifetime.clone(),
                window,
            },
            TransportOwner {
                transport,
                lifetime,
                member: Some(member),
            },
        ))
    }
}

struct Time;
impl TorEnvelopeTime for Time {
    fn now_us(&self) -> Result<u64, Error> {
        let now = js_sys::Date::now() * 1000.0;
        if !now.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&now) {
            return Err(Error::Unavailable);
        }
        Ok(now as u64)
    }
}
struct Signer<'a>(ckmg::Vld0Signer<'a>);
impl cdht::Signer for Signer<'_> {
    fn public_key(&self) -> NodeId {
        *self.0.public_key()
    }
    fn sign(&self, data: &[u8]) -> Result<[u8; 64], Error> {
        self.0.sign(data).map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "Error::Signer", Error::Signer, &__cause)
        })
    }
}
struct Cipher<'a>(ckmg::Vld0NodeCipher<'a>);
impl EnvelopeCipher for Cipher<'_> {
    fn node_id(&self) -> NodeId {
        *self.0.public_key()
    }
    fn crypt(
        &self,
        peer: &NodeId,
        nonce: &[u8; 24],
        bytes: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        self.0.crypt(peer, nonce, bytes).map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })
    }
}
fn bounded(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        Err(Error::ValueTooLarge)
    } else {
        Ok(())
    }
}
impl Identity for TransportClient {
    type Clock = custody::SystemClock;
    type Authority = custody::TransportAuthority<custody::SystemClock>;
    fn transport(&self) -> &Rc<Transport> {
        &self.transport
    }
    fn lifetime(&self) -> custody::CustodyLifetime {
        self.lifetime.clone()
    }
    fn envelope_time(&self) -> Arc<dyn TorEnvelopeTime> {
        Arc::new(Time)
    }
    fn envelope_window(&self) -> TimeWindow {
        self.window
    }
    fn advertise(
        &self,
        advertisement: Advertisement,
    ) -> futures_util::future::LocalBoxFuture<'_, Result<UnverifiedPeerInfoBytes, Error>> {
        Box::pin(async move {
            self.transport
                .with_node(|signer, _| {
                    UnverifiedPeerInfoBytes::sign_extension(advertisement, &Signer(signer))
                })
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "Error::Unavailable",
                        Error::Unavailable,
                        &__cause,
                    )
                })?
        })
    }
}
/// The original node operations of a client over its retained `transport` and `window`:
/// the vault session (`TransportClient`) and a registration's ephemeral one
/// (`BootstrapClient`) sign, seal and open the same way.
macro_rules! node_identity {
    ($client:ty) => {
        impl $client {
            async fn sign(
                &self,
                bytes: &[u8],
                destination: &NodeId,
            ) -> Result<SignedOperation, Error> {
                bounded(bytes)?;
                self.transport
                    .with_node(|signer, _| {
                        SignedOperation::sign(bytes.to_vec(), destination, &Signer(signer))
                    })
                    .await
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "Error::Unavailable",
                            Error::Unavailable,
                            &__cause,
                        )
                    })?
            }
        }
        impl TorNodeIdentity for $client {
            fn node_id(&self) -> NodeId {
                *self.transport.public_key().value()
            }
            fn question<'a>(
                &'a self,
                value: &'a Question,
                destination: &'a NodeId,
            ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
                Box::pin(self.sign(value.as_bytes(), destination))
            }
            fn answer<'a>(
                &'a self,
                value: &'a FindAnswer,
                destination: &'a NodeId,
            ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
                Box::pin(self.sign(value.as_bytes(), destination))
            }
            fn record_answer<'a>(
                &'a self,
                value: &'a Answer,
                destination: &'a NodeId,
            ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
                Box::pin(self.sign(value.as_bytes(), destination))
            }
            fn statement<'a>(
                &'a self,
                value: &'a Statement,
                destination: &'a NodeId,
            ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
                Box::pin(self.sign(value.as_bytes(), destination))
            }
            fn seal<'a>(
                &'a self,
                operation: &'a SignedOperation,
                destination: &'a NodeId,
                timestamp_us: u64,
            ) -> cmsh::BoxFuture<'a, Result<Vec<u8>, Error>> {
                Box::pin(async move {
                    bounded(operation.as_bytes())?;
                    self.transport
                        .with_node(|signer, cipher| {
                            let checked = SignedOperation::verify_sender(
                                operation.as_bytes().to_vec(),
                                destination,
                                &Verifier,
                            )?;
                            Envelope::seal(
                                checked.as_bytes(),
                                destination,
                                timestamp_us,
                                &Signer(signer),
                                &Cipher(cipher),
                            )
                        })
                        .await
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "Error::Unavailable",
                                Error::Unavailable,
                                &__cause,
                            )
                        })?
                })
            }
            fn open<'a>(
                &'a self,
                envelope: &'a Envelope,
            ) -> cmsh::BoxFuture<'a, Result<AuthenticatedOperation, Error>> {
                Box::pin(async move {
                    bounded(envelope.as_bytes())?;
                    self.transport
                        .with_node(|_, cipher| {
                            // The original timestamp is checked AFTER the HTTPS await, so
                            // queue/authorization time cannot extend ENV0 acceptance.
                            let envelope = Envelope::verify(
                                envelope.as_bytes().to_vec(),
                                cipher.public_key(),
                                Time.now_us()?,
                                self.window,
                                &Verifier,
                            )?;
                            envelope.open_operation(&Cipher(cipher), &Verifier)
                        })
                        .await
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "Error::Unavailable",
                                Error::Unavailable,
                                &__cause,
                            )
                        })?
                })
            }
        }
    };
}
node_identity!(TransportClient);
node_identity!(BootstrapClient);

/// The dial-only records identity of one registration scope: a fresh
/// `ckmg::EphemeralTransport` (CSPRNG keys, memory only) in its own client-only browser Tor
/// engine. It takes no CustodyLifetime from any Door and advertises nothing; dropping the
/// last clone stops the engine and wipes the keys.
#[derive(Clone)]
pub struct BootstrapClient {
    transport: Rc<Transport>,
    window: TimeWindow,
}
impl BootstrapClient {
    /// Start the client-only engine of one scope on that scope's own fresh transport
    /// (`registration::network::bootstrap_identity`), so scopes never share an identity.
    pub async fn start(
        transport: ckmg::EphemeralTransport,
        scope: ctrn::Scope,
        config: network_browser::Configuration,
        window: TimeWindow,
    ) -> crate::door::Result<Self> {
        Ok(Self {
            transport: Rc::new(Transport::start(transport, scope, config).await?),
            window,
        })
    }
}
impl super::records::ClientIdentity for BootstrapClient {
    type Clock = custody::SystemClock;
    type Authority = custody::TransportAuthority<custody::SystemClock>;
    fn transport(&self) -> &Rc<Transport> {
        &self.transport
    }
    fn envelope_time(&self) -> Arc<dyn TorEnvelopeTime> {
        Arc::new(Time)
    }
    fn envelope_window(&self) -> TimeWindow {
        self.window
    }
}
