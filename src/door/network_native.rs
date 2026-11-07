//! Actual native Tor construction for the same Door used by the browser.
//! Trusted engine inputs only: no network/key override enters the action API.
use super::{facades::MeshLifetime, Door, ErrorCode, Result};
use std::sync::Arc;

fn native_runtime() -> Result<tor_rtcompat::tokio::TokioRustlsRuntime> {
    // Arti requires a process TLS provider before runtime construction.
    super::ensure_tls_provider();
    tor_rtcompat::tokio::TokioRustlsRuntime::current().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}

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
        let runtime = native_runtime()?;
        let clock = Arc::new(ctrn::arti::TokioClock::default());
        let node = initializer
            .initialize(
                runtime,
                configuration.tor,
                configuration.directories,
                clock.clone(),
                configuration.limits,
            )
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
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
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let mesh = cmsh::Mesh::builder(Arc::new(|future: cmsh::BoxFuture<'static, ()>| {
            tokio::spawn(future);
        }))
        .backend(Arc::new(cmsh::Tor(messages)))
        .build()
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        node.start().await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        // bind_mesh_owned waits for actual onion publication and retains the
        // actual bounded receiver. A failed/dropped await drops the stop guard.
        let bound = self.bind_mesh_owned(origin, mesh, Some(lifetime)).await;
        self.network_bound(bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tls_provider_is_initialized_once_in_an_isolated_process() {
        const CASE: &str = "CMSG_NATIVE_TLS_PROVIDER_FIXTURE";
        let Ok(case) = std::env::var(CASE) else {
            // The rustls default is process-global. Each case must start without
            // another test's HTTP client or Tor fixture choosing it first.
            let module = module_path!().split_once("::").unwrap().1;
            let filter =
                format!("{module}::native_tls_provider_is_initialized_once_in_an_isolated_process");
            for case in ["empty", "installed"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &filter, "--nocapture"])
                    .env(CASE, case)
                    .output()
                    .unwrap();
                assert!(output.status.success(), "isolated TLS provider case failed");
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            }
            return;
        };
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let installed = match case.as_str() {
            "empty" => None,
            "installed" => {
                rustls::crypto::ring::default_provider()
                    .install_default()
                    .unwrap();
                Some(
                    rustls::crypto::CryptoProvider::get_default()
                        .unwrap()
                        .clone(),
                )
            }
            _ => panic!("unknown TLS provider fixture"),
        };
        // Provider installation does not manufacture a Tokio execution context.
        assert!(matches!(native_runtime(), Err(ErrorCode::Unavailable)));
        let selected = rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .clone();
        if let Some(installed) = installed {
            assert!(Arc::ptr_eq(&installed, &selected));
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _entered = runtime.enter();
        let first = native_runtime().unwrap();
        let second = native_runtime().unwrap();
        assert!(Arc::ptr_eq(
            &selected,
            rustls::crypto::CryptoProvider::get_default().unwrap()
        ));
        drop((first, second));
    }
}
