//! Loopback TLS transport for an original router and its retained fixture owner.
//! This module creates no grants, changes no headers and installs no client trust.

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use std::{io, path::Path, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        crypto::ring,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(5);
const CONNECTION_LIMIT: Duration = Duration::from_secs(60);
const DRAIN_LIMIT: Duration = Duration::from_secs(5);

/// Retain until `shutdown().await` completes. Drop requests the same bounded drain;
/// callers must await shutdown before tearing down the Tokio runtime.
pub struct HttpsFixture {
    base: String,
    stop: watch::Sender<bool>,
    task: JoinHandle<io::Result<()>>,
}

impl HttpsFixture {
    /// `lifetime` owns the original database directory, clock and other fixtures.
    /// It is released by the supervisor only after all TLS connections are joined.
    pub async fn start<L: Send + 'static>(
        router: Router,
        lifetime: L,
        certificate_chain: &Path,
        private_key: &Path,
    ) -> io::Result<Self> {
        // Parse using Rustls' maintained PEM reader. Never include parser/key
        // material in errors or diagnostics, including on key/cert mismatch.
        let certificates = CertificateDer::pem_file_iter(certificate_chain)
            .map_err(|_| invalid_tls())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid_tls())?;
        let key = PrivateKeyDer::from_pem_file(private_key).map_err(|_| invalid_tls())?;
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid_tls())?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|_| invalid_tls())?;
        // HTTP/1 keeps every connection in our JoinSet, with no detached HTTP/2
        // stream tasks. The original router still owns every protocol decision.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let base = format!("https://{}", listener.local_addr()?);
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            let result = serve(listener, router, acceptor, stopped).await;
            drop(lifetime);
            result
        });
        Ok(Self { base, stop, task })
    }

    /// Public transport address only; the certificate must cover 127.0.0.1.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        // Borrow the handle so cancellation of this method still runs Drop.
        (&mut self.task)
            .await
            .map_err(|_| io::Error::other("HTTPS fixture supervisor failed"))?
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        // Do not abort the supervisor: it must drain and join its children before
        // releasing the original owner, even on cancellation of shutdown().
    }
}

fn invalid_tls() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid fixture TLS identity")
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    if !*stop.borrow_and_update() {
        let _ = stop.changed().await;
    }
}

async fn serve(
    listener: TcpListener,
    router: Router,
    acceptor: TlsAcceptor,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = stopped(&mut stop) => break Ok(()),
            completed = connections.join_next(), if !connections.is_empty() => {
                if matches!(completed, Some(Err(_))) {
                    break Err(io::Error::other("HTTPS fixture connection task failed"));
                }
            }
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => break Err(error),
                };
                connections.spawn(connection(stream, router.clone(), acceptor.clone(), stop.clone()));
            }
        }
    };
    drop(listener);
    // Normal shutdown signals graceful HTTP completion. Accept/task failures
    // still have this deadline, followed by cancellation and an awaited join.
    let mut task_failed = false;
    if timeout(DRAIN_LIMIT, async {
        while let Some(joined) = connections.join_next().await {
            task_failed |= joined.is_err();
        }
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while let Some(joined) = connections.join_next().await {
            task_failed |= joined.is_err_and(|error| !error.is_cancelled());
        }
    }
    result.and(if task_failed {
        Err(io::Error::other("HTTPS fixture connection task failed"))
    } else {
        Ok(())
    })
}

async fn connection(
    stream: TcpStream,
    router: Router,
    acceptor: TlsAcceptor,
    mut stop: watch::Receiver<bool>,
) {
    let stream = tokio::select! {
        biased;
        _ = stopped(&mut stop) => return,
        handshake = timeout(HANDSHAKE_LIMIT, acceptor.accept(stream)) => {
            match handshake {
                Ok(Ok(stream)) => stream,
                // Peer errors close only this connection; log no request data.
                _ => return,
            }
        }
    };
    let builder = http1::Builder::new();
    let connection =
        builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router));
    tokio::pin!(connection);
    tokio::select! {
        biased;
        _ = stopped(&mut stop) => {
            connection.as_mut().graceful_shutdown();
            let _ = timeout(DRAIN_LIMIT, &mut connection).await;
        }
        _ = timeout(CONNECTION_LIMIT, &mut connection) => {}
    }
}
