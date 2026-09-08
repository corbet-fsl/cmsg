//! Explicitly triggered synthetic public-network experiment, never a host daemon.
use arti_client::{config::TorClientConfigBuilder, TorClient};
use cmsg_embedded_onion_experiment::{
    allowed_request, dial_checked, initialize_tls_provider, mls_round_trip, Failure, OwnedState,
    Result, SessionScope,
};
use futures::StreamExt;
use safelog::DisplayRedacted;
use std::{path::Path, time::Duration};
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{config::OnionServiceConfigBuilder, HsNickname};

const PORT: u16 = 443;
const TOTAL_SECONDS: u64 = 600;
const BOOTSTRAP_SECONDS: u64 = 180;
const PUBLICATION_SECONDS: u64 = 180;
const CONNECT_SECONDS: u64 = 60;
const ACCEPT_SECONDS: u64 = 60;
const FRAME_SECONDS: u64 = 30;
const MAX_RENDEZVOUS: usize = 4;
const MAX_STREAM_REQUESTS: usize = 4;

fn emit(phase: &'static str, state: &'static str) {
    println!("{}", serde_json::json!({ "phase": phase, "state": state }));
}

fn install_coarse_panic_hook() {
    // A panic payload can contain upstream state; the standalone binary emits no payload.
    std::panic::set_hook(Box::new(|_| emit("panic", "failed")));
}

async fn phase<T, F>(name: &'static str, seconds: u64, future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    emit(name, "started");
    let result = match tokio::time::timeout(Duration::from_secs(seconds), future).await {
        Ok(result) => result,
        Err(_) => Err(Failure::Deadline),
    };
    emit(name, if result.is_ok() { "passed" } else { "failed" });
    result
}

async fn network(state: &OwnedState) -> Result<()> {
    let (state_a, cache_a) = state.client_directories(0)?;
    let (state_b, cache_b) = state.client_directories(1)?;
    let config_a = TorClientConfigBuilder::from_directories(state_a, cache_a)
        .build()
        .map_err(|_| Failure::Configuration)?;
    let config_b = TorClientConfigBuilder::from_directories(state_b, cache_b)
        .build()
        .map_err(|_| Failure::Configuration)?;
    let (service_client, reader_client) = phase("bootstrap", BOOTSTRAP_SECONDS, async {
        let a = async {
            TorClient::create_bootstrapped(config_a)
                .await
                .map_err(|_| Failure::Network)
        };
        let b = async {
            TorClient::create_bootstrapped(config_b)
                .await
                .map_err(|_| Failure::Network)
        };
        tokio::try_join!(a, b)
    })
    .await?;
    // Separate app state already separates the two clients; this handle also gives
    // this single connection its own isolation token, without selecting another route.
    let reader_client = reader_client.isolated_client();
    let nickname = HsNickname::try_from("synthetic-roundtrip".to_owned())
        .map_err(|_| Failure::Configuration)?;
    let configuration = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .max_concurrent_streams_per_circuit(1)
        .build()
        .map_err(|_| Failure::Configuration)?;
    let (service, requests) = service_client
        .launch_onion_service(configuration)
        .map_err(|_| Failure::Network)?
        .ok_or(Failure::Configuration)?;
    // Upstream makes exposure explicit; this value is used only for the in-memory
    // connection target and is never included in phase output.
    let host = service
        .onion_address()
        .ok_or(Failure::Network)?
        .display_unredacted()
        .to_string();
    cmsg::OnionEndpoint::parse(&host, PORT).map_err(|_| Failure::Route)?;
    emit("owned_endpoint", "passed");
    let mut publication_events = Box::pin(service.status_events());
    phase("publication", PUBLICATION_SECONDS, async {
        while !service.status().state().is_fully_reachable() {
            publication_events.next().await.ok_or(Failure::Closed)?;
        }
        Ok(())
    })
    .await?;

    let scope = SessionScope::new(Duration::from_secs(120), 1)?;
    let monitor_service = service.clone();
    let monitor = async move {
        loop {
            if !monitor_service.status().state().is_fully_reachable() {
                return Err::<(), Failure>(Failure::Closed);
            }
            publication_events.next().await.ok_or(Failure::Closed)?;
        }
    };
    let exchange = async move {
        let accepting = async move {
            let mut requests = Box::pin(requests);
            // Sequential acceptance puts a hard bound on app-owned in-flight handshakes.
            // Never use handle_rend_requests(), whose concurrency is unbounded upstream.
            for _ in 0..MAX_RENDEZVOUS {
                let request = requests.next().await.ok_or(Failure::Closed)?;
                let accepted =
                    tokio::time::timeout(Duration::from_secs(ACCEPT_SECONDS), request.accept())
                        .await
                        .map_err(|_| Failure::Deadline)?
                        .map_err(|_| Failure::Network)?;
                let mut stream_requests = Box::pin(accepted);
                for _ in 0..MAX_STREAM_REQUESTS {
                    let request = stream_requests.next().await.ok_or(Failure::Closed)?;
                    if !allowed_request(request.request(), PORT) {
                        request
                            .reject(End::new_with_reason(EndReason::DONE))
                            .await
                            .map_err(|_| Failure::Network)?;
                        continue;
                    }
                    let stream = request
                        .accept(Connected::new_empty())
                        .await
                        .map_err(|_| Failure::Network)?;
                    // The returned request iterator holds the rendezvous tunnel alive.
                    // Keep it and the service's request receiver until the full exchange ends.
                    return Ok((stream, stream_requests, requests));
                }
            }
            Err(Failure::Capacity)
        };
        let connecting = dial_checked(
            &host,
            PORT,
            Duration::from_secs(CONNECT_SECONDS),
            move |route| async move {
                reader_client
                    .connect((route.host(), route.port()))
                    .await
                    .map_err(|_| Failure::Network)
            },
        );
        let ((incoming, _stream_requests, _rendezvous_requests), outgoing) =
            phase("connect_accept", ACCEPT_SECONDS, async {
                tokio::try_join!(accepting, connecting)
            })
            .await?;
        // Both data streams implement Tokio IO directly via the pinned `tokio` feature.
        // Framing is sequential request/response and flushes every complete frame.
        phase(
            "mls_round_trip",
            FRAME_SECONDS * 2,
            mls_round_trip(outgoing, incoming, Duration::from_secs(FRAME_SECONDS)),
        )
        .await
    };
    let result = tokio::select! {
        biased;
        result = monitor => result,
        result = scope.run(exchange) => result,
    };
    scope.close();
    // The select's losing future, request iterators, data streams and service handle
    // are dropped. No detached task can keep accepting or send a late frame.
    drop(service);
    result
}

fn main() {
    install_coarse_panic_hook();
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 4
        || arguments[1] != "--run-public-network"
        || arguments[2] != "--state-parent"
    {
        emit("configuration", "failed");
        std::process::exit(1);
    }
    if initialize_tls_provider().is_err() {
        emit("tls_provider", "failed");
        std::process::exit(1);
    }
    emit("tls_provider", "passed");
    let state = match OwnedState::create(Path::new(&arguments[3])) {
        Ok(state) => state,
        Err(_) => {
            emit("configuration", "failed");
            std::process::exit(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            drop(state);
            emit("runtime", "failed");
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(async {
        let scope = SessionScope::new(Duration::from_secs(TOTAL_SECONDS), 1)?;
        scope.run(network(&state)).await
    });
    // Request bounded runtime shutdown before best-effort synthetic-state cleanup.
    // Tokio may leave blocking tasks alive beyond this wait; the hosted runner must
    // also clean its disposable parent after this process exits. No complete upstream
    // shutdown, encrypted at-rest storage or forensic erasure is inferred here.
    runtime.shutdown_timeout(Duration::from_secs(5));
    drop(state);
    emit("complete", if result.is_ok() { "passed" } else { "failed" });
    if result.is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::install_coarse_panic_hook;
    use std::process::Command;

    const PANIC_MARKER: &str = "synthetic-private-panic-payload-47";
    const CHILD_ENV: &str = "CMSG_SYNTHETIC_PANIC_CHILD";

    #[test]
    fn panic_payload_child() {
        if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
            install_coarse_panic_hook();
            panic!("{}", PANIC_MARKER);
        }
    }

    #[test]
    fn panic_payload_is_hidden_in_subprocess_output() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::panic_payload_child", "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains(PANIC_MARKER));
        assert!(!stderr.contains(PANIC_MARKER));
        assert!(stdout.contains("{\"phase\":\"panic\",\"state\":\"failed\"}"));
    }
}
