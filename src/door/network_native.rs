//! Actual native Tor construction for the same Door used by the browser.
//! Trusted engine inputs only: no network/key override enters the action API.
use super::{facades::MeshLifetime, Door, ErrorCode, Result};
use std::sync::Arc;

/// Trusted native process configuration. No identity seed, session, endpoint,
/// ready flag or direct peer socket can be supplied by a public Door request.
pub struct Configuration {
    pub tor: arti_client::config::TorClientConfigBuilder,
    pub directories: ctrn::arti::Directories,
    pub limits: ctrn::Limits,
    pub messages: ctrn::MessageLimits,
}

impl Door {
    /// Consume an original Keys onion initializer and bind the original live
    /// Node -> Ferry messages -> Mesh listener. All owners remain inside Door;
    /// shutdown/cancellation closes the Node even if a background pump retains it.
    ///
    /// This establishes only the actual message transport. It is not a Records
    /// backend, Inbox receiver, domain authorization or full runtime-ready claim.
    /// Native and browser consumers still invoke the same registry/dispatcher.
    pub async fn bind_native_tor(
        &mut self,
        origin: &str,
        initializer: ckmg::NativeTorInitializer,
        configuration: Configuration,
    ) -> Result<()> {
        self.member_origin(origin)?;
        if initializer.community() != self.config.community {
            return Err(ErrorCode::Unauthorized);
        }
        if self.meshes.contains_key(origin) {
            return Err(ErrorCode::InvalidRequest);
        }
        let runtime = tor_rtcompat::tokio::TokioRustlsRuntime::current()
            .map_err(|_| ErrorCode::Unavailable)?;
        let clock = Arc::new(ctrn::arti::TokioClock::default());
        let node = initializer
            .initialize(
                runtime,
                configuration.tor,
                configuration.directories,
                clock.clone(),
                configuration.limits,
            )
            .map_err(|_| ErrorCode::Unavailable)?;
        let stopped = node.clone();
        let lifetime = MeshLifetime::new(move || stopped.stop());
        let messages = ctrn::messages::Messages::new(
            node.clone(),
            Arc::new(|future: ctrn::BoxFuture<'static, ()>| {
                tokio::spawn(future);
            }),
            clock,
            configuration.messages,
        )
        .map_err(|_| ErrorCode::InvalidRequest)?;
        let mesh = cmsh::Mesh::builder(Arc::new(|future: cmsh::BoxFuture<'static, ()>| {
            tokio::spawn(future);
        }))
        .backend(Arc::new(cmsh::Tor(messages)))
        .build()
        .map_err(|_| ErrorCode::InvalidRequest)?;
        node.start().await.map_err(|_| ErrorCode::Unavailable)?;
        // bind_mesh_owned waits for actual onion publication and retains the
        // actual bounded receiver. A failed/dropped await drops the stop guard.
        self.bind_mesh_owned(origin, mesh, Some(lifetime)).await
    }
}
