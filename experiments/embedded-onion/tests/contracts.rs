use cmsg_embedded_onion_experiment::{
    allowed_request, dial_checked, initialize_tls_provider, mls_round_trip, Failure, OwnedState,
    SessionScope,
};
use std::{
    future::pending,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tor_cell::relaycell::msg::{Begin, Resolve};
use tor_proto::stream::IncomingStreamRequest;

const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn tls_startup_installs_one_provider_and_constructs_a_real_client_without_network() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let starters: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(initialize_tls_provider))
        .collect();
    for starter in starters {
        assert_eq!(starter.join().unwrap(), Ok(()));
    }
    let first = rustls::crypto::CryptoProvider::get_default()
        .expect("startup must select a provider before any TLS builder")
        .clone();
    let configuration = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let _client = rustls::ClientConnection::new(
        Arc::new(configuration),
        "synthetic.invalid".try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(initialize_tls_provider(), Ok(()));
    assert!(Arc::ptr_eq(
        &first,
        rustls::crypto::CryptoProvider::get_default().unwrap()
    ));
}

#[test]
fn state_is_private_unique_isolated_and_removes_only_its_own_tree() {
    let parent = tempfile::tempdir().unwrap();
    let canary = parent.path().join("keep.txt");
    std::fs::write(&canary, b"keep").unwrap();
    let first = OwnedState::create(parent.path()).unwrap();
    let second = OwnedState::create(parent.path()).unwrap();
    let root = first.root().to_owned();
    assert_ne!(root, second.root());
    assert!(root.starts_with(parent.path()));
    assert_ne!(root, parent.path());
    let (state_a, cache_a) = first.client_directories(0).unwrap();
    let (state_b, cache_b) = first.client_directories(1).unwrap();
    let paths = [state_a, cache_a, state_b, cache_b];
    for (index, path) in paths.iter().enumerate() {
        assert!(path.is_dir());
        assert!(path.starts_with(&root));
        for other in paths.iter().skip(index + 1) {
            assert_ne!(path, other);
            assert!(!path.starts_with(other));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
    assert!(first.client_directories(2).is_err());
    drop(first);
    assert!(!root.exists());
    assert!(canary.exists());
    assert!(second.root().exists());
}

#[test]
fn unsafe_or_implicit_state_parents_are_refused_without_overwriting_files() {
    let parent = tempfile::tempdir().unwrap();
    let file = parent.path().join("file");
    std::fs::write(&file, b"keep").unwrap();
    for path in [
        Path::new(""),
        Path::new("."),
        Path::new("/"),
        file.as_path(),
        &parent.path().join("missing"),
    ] {
        assert!(OwnedState::create(path).is_err());
    }
    assert_eq!(std::fs::read(file).unwrap(), b"keep");
    #[cfg(unix)]
    {
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(parent.path(), &link).unwrap();
        assert!(OwnedState::create(&link).is_err());
    }
}

#[test]
fn actual_tor_request_types_allow_only_begin_with_the_explicit_virtual_port() {
    for address in ["", "example.com", "127.0.0.1"] {
        let begin: IncomingStreamRequest = Begin::new(address, 443, 0_u32).unwrap().into();
        assert!(allowed_request(&begin, 443));
        assert!(!allowed_request(&begin, 80));
        assert!(!allowed_request(&begin, 0));
    }
    let resolve: IncomingStreamRequest = Resolve::new("example.com").into();
    assert!(!allowed_request(&resolve, 443));
}

#[tokio::test]
async fn validated_onion_is_the_only_dial_input_and_failed_dial_is_not_retried() {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let output = dial_checked(
        ONION,
        443,
        Duration::from_secs(1),
        move |route| async move {
            seen.fetch_add(1, Ordering::SeqCst);
            assert_eq!(route.host(), ONION);
            assert_eq!(route.port(), 443);
            Ok(17)
        },
    )
    .await
    .unwrap();
    assert_eq!(output, 17);
    for host in [
        "127.0.0.1",
        "example.com",
        "https://example.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
    ] {
        let seen = count.clone();
        assert!(
            dial_checked(host, 443, Duration::from_secs(1), move |_| async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err()
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let seen = count.clone();
    assert_eq!(
        dial_checked::<(), _, _>(ONION, 443, Duration::from_secs(1), move |_| async move {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(Failure::Network)
        })
        .await,
        Err(Failure::Network)
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn dial_deadline_drops_pending_owned_work_and_has_no_late_success() {
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let result =
        dial_checked::<(), _, _>(ONION, 443, Duration::from_millis(10), move |_| async move {
            let _owned_stream = guard;
            pending::<()>().await;
            Ok(())
        })
        .await;
    assert_eq!(result, Err(Failure::Deadline));
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn scope_allows_live_work_and_rejects_invalid_or_expired_lifetimes() {
    for duration in [Duration::ZERO, Duration::from_secs(601)] {
        assert!(SessionScope::new(duration, 1).is_err());
    }
    assert!(SessionScope::new(Duration::from_secs(1), 0).is_err());
    let scope = SessionScope::new(Duration::from_millis(20), 1).unwrap();
    assert_eq!(scope.run(async { Ok(42) }).await, Ok(42));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(scope.run(async { Ok(42) }).await, Err(Failure::Deadline));
}

#[tokio::test]
async fn scope_capacity_counts_pending_work_and_close_cancels_owned_resources() {
    let scope = SessionScope::new(Duration::from_secs(2), 1).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let (started, entered) = tokio::sync::oneshot::channel();
    let worker_scope = scope.clone();
    let worker = tokio::spawn(async move {
        worker_scope
            .run(async move {
                let _owned_service_and_stream = guard;
                let _ = started.send(());
                pending::<()>().await;
                Ok(())
            })
            .await
    });
    entered.await.unwrap();
    assert_eq!(scope.run(async { Ok(()) }).await, Err(Failure::Capacity));
    scope.close();
    assert_eq!(worker.await.unwrap(), Err(Failure::Closed));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(scope.run(async { Ok(()) }).await, Err(Failure::Closed));
}

#[tokio::test]
async fn scope_expiry_drops_an_active_stream_without_another_request() {
    let scope = SessionScope::new(Duration::from_millis(10), 1).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    assert_eq!(
        scope
            .run(async move {
                let _owned_stream = guard;
                pending::<()>().await;
                Ok(())
            })
            .await,
        Err(Failure::Deadline)
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancellation_of_the_whole_session_drops_owned_resources() {
    let scope = SessionScope::new(Duration::from_secs(2), 1).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let result = tokio::time::timeout(
        Duration::from_millis(10),
        scope.run(async move {
            let _owned_service_and_stream = guard;
            pending::<()>().await;
            Ok::<(), Failure>(())
        }),
    )
    .await;
    assert!(result.is_err());
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(scope.run(async { Ok(()) }).await, Ok(()));
}

#[tokio::test]
async fn actual_mls_ciphertext_and_authenticated_reply_cross_owned_framed_streams() {
    let (client, service) = tokio::io::duplex(1024);
    mls_round_trip(client, service, Duration::from_secs(5))
        .await
        .unwrap();
}
