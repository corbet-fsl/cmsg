//! App-owned integration experiment. No onion anonymity is established by its unit tests.
use std::{
    future::Future,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{watch, Semaphore},
    time::{sleep_until, timeout, Instant},
};
use tor_proto::stream::IncomingStreamRequest;

#[path = "../../../tests/common/mod.rs"]
mod synthetic;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Configuration,
    Route,
    Deadline,
    Closed,
    Capacity,
    Protocol,
    Network,
}
pub type Result<T> = std::result::Result<T, Failure>;

/// Configure the process TLS provider before constructing an Arti client.
/// This standalone experiment owns initialization; an unrelated prior provider is refused.
pub fn initialize_tls_provider() -> Result<()> {
    static INITIALIZED: OnceLock<Result<()>> = OnceLock::new();
    *INITIALIZED.get_or_init(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| Failure::Configuration)
    })
}

pub struct OwnedState {
    root: tempfile::TempDir,
}
impl OwnedState {
    pub fn create(parent: &Path) -> Result<Self> {
        if !parent.is_absolute()
            || parent.parent().is_none()
            || parent
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(Failure::Configuration);
        }
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| Failure::Configuration)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Failure::Configuration);
        }
        // An app-controlled parent is still required; no untrusted party may swap its ancestors.
        let parent = parent.canonicalize().map_err(|_| Failure::Configuration)?;
        let root = tempfile::Builder::new()
            .prefix("cmsg-onion-")
            .tempdir_in(parent)
            .map_err(|_| Failure::Configuration)?;
        for name in [
            "client-a-state",
            "client-a-cache",
            "client-b-state",
            "client-b-cache",
        ] {
            let mut directory = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directory.mode(0o700);
            }
            directory
                .create(root.path().join(name))
                .map_err(|_| Failure::Configuration)?;
        }
        Ok(Self { root })
    }
    pub fn root(&self) -> &Path {
        self.root.path()
    }
    pub fn client_directories(&self, index: usize) -> Result<(PathBuf, PathBuf)> {
        let label = match index {
            0 => "a",
            1 => "b",
            _ => return Err(Failure::Configuration),
        };
        Ok((
            self.root.path().join(format!("client-{label}-state")),
            self.root.path().join(format!("client-{label}-cache")),
        ))
    }
}

pub struct CheckedOnion {
    host: String,
    port: u16,
}
impl CheckedOnion {
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}
pub async fn dial_checked<T, F, Fut>(
    host: &str,
    port: u16,
    deadline: Duration,
    dial: F,
) -> Result<T>
where
    F: FnOnce(CheckedOnion) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    if deadline.is_zero() || deadline > Duration::from_secs(60) {
        return Err(Failure::Configuration);
    }
    cmsg::OnionEndpoint::parse(host, port).map_err(|_| Failure::Route)?;
    // The closure is the only route acquisition operation. It receives no alternative address.
    timeout(
        deadline,
        dial(CheckedOnion {
            host: host.to_owned(),
            port,
        }),
    )
    .await
    .map_err(|_| Failure::Deadline)?
}
pub fn allowed_request(request: &IncomingStreamRequest, port: u16) -> bool {
    // Tor recommends ordinary BEGIN/port checks; do not fingerprint clients by its address field.
    port != 0 && matches!(request, IncomingStreamRequest::Begin(begin) if begin.port() == port)
}

struct ScopeInner {
    expires: Instant,
    closed: watch::Sender<bool>,
    capacity: Arc<Semaphore>,
}
#[derive(Clone)]
pub struct SessionScope {
    inner: Arc<ScopeInner>,
}
impl SessionScope {
    pub fn new(lifetime: Duration, capacity: usize) -> Result<Self> {
        if lifetime.is_zero()
            || lifetime > Duration::from_secs(600)
            || capacity == 0
            || capacity > 1024
        {
            return Err(Failure::Configuration);
        }
        let (closed, _) = watch::channel(false);
        Ok(Self {
            inner: Arc::new(ScopeInner {
                expires: Instant::now() + lifetime,
                closed,
                capacity: Arc::new(Semaphore::new(capacity)),
            }),
        })
    }
    pub fn close(&self) {
        self.inner.closed.send_replace(true);
    }
    pub async fn run<T, F>(&self, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let mut closed = self.inner.closed.subscribe();
        if *closed.borrow() {
            return Err(Failure::Closed);
        }
        if Instant::now() >= self.inner.expires {
            return Err(Failure::Deadline);
        }
        let _permit = self
            .inner
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Capacity)?;
        // The supplied future must own the service/request streams/tasks it starts. Cancelling
        // this scope drops that future; it never resumes a partially cancelled framing operation.
        tokio::select! {
            biased;
            _ = closed.changed() => Err(Failure::Closed),
            _ = sleep_until(self.inner.expires) => Err(Failure::Deadline),
            result = future => {
                if *closed.borrow() { Err(Failure::Closed) }
                else if Instant::now() >= self.inner.expires { Err(Failure::Deadline) }
                else { result }
            }
        }
    }
}

pub async fn mls_round_trip<C, S>(client: C, service: S, frame_timeout: Duration) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    use cmsg::{FramedStream, Member, Received};
    use data_encoding::BASE64URL_NOPAD;
    let mut sender = Member::new().map_err(|_| Failure::Protocol)?;
    let mut recipient = Member::new().map_err(|_| Failure::Protocol)?;
    sender
        .bind_admission(
            synthetic::grant(&sender.chat_public_key(), 101),
            synthetic::trust(),
            100,
        )
        .map_err(|_| Failure::Protocol)?;
    recipient
        .bind_admission(
            synthetic::grant(&recipient.chat_public_key(), 102),
            synthetic::trust(),
            100,
        )
        .map_err(|_| Failure::Protocol)?;
    sender.create_group().map_err(|_| Failure::Protocol)?;
    let package = recipient.key_package().map_err(|_| Failure::Protocol)?;
    let welcome = sender.add(&package).map_err(|_| Failure::Protocol)?.welcome;
    recipient.join(&welcome).map_err(|_| Failure::Protocol)?;
    let request = sender
        .send(b"synthetic embedded onion request")
        .map_err(|_| Failure::Protocol)?;
    let mut client =
        FramedStream::new(client, 100000, frame_timeout).map_err(|_| Failure::Configuration)?;
    let mut service =
        FramedStream::new(service, 100000, frame_timeout).map_err(|_| Failure::Configuration)?;
    let client_task = async move {
        client
            .send_frame(&request)
            .await
            .map_err(|_| Failure::Network)?;
        let reply = client.receive_frame().await.map_err(|_| Failure::Network)?;
        match sender.receive(&reply).map_err(|_| Failure::Protocol)? {
            Received::Text(value)
                if value.text == "synthetic embedded onion reply"
                    && value.member_id == BASE64URL_NOPAD.encode(&[102; 32]) =>
            {
                Ok(())
            }
            _ => Err(Failure::Protocol),
        }
    };
    let service_task = async move {
        let request = service
            .receive_frame()
            .await
            .map_err(|_| Failure::Network)?;
        match recipient.receive(&request).map_err(|_| Failure::Protocol)? {
            Received::Text(value)
                if value.text == "synthetic embedded onion request"
                    && value.member_id == BASE64URL_NOPAD.encode(&[101; 32]) =>
            {
                ()
            }
            _ => return Err(Failure::Protocol),
        }
        let reply = recipient
            .send(b"synthetic embedded onion reply")
            .map_err(|_| Failure::Protocol)?;
        service
            .send_frame(&reply)
            .await
            .map_err(|_| Failure::Network)
    };
    tokio::try_join!(client_task, service_task)?;
    Ok(())
}
