//! Reuse the exact owner's real database, passkey, passport and policy fixtures.
mod gardens;
mod https;
#[path = "owner/mod.rs"]
mod owner;
mod wallet;
use owner::*;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Fault {
    session: String,
    count: AtomicUsize,
    release: tokio::sync::Notify,
}

// The exact production root-board constructor, with a fictional public issuer.
async fn root_board(public: &cvld::api::GlobalPublic, source: &Running) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), "root", public, 1000);
    let issuer = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("fixture-root-board").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let descriptor = cpsd::RootBoardPublicKey::from_authenticated_beacon(
        issuer.public_key().clone(),
        cpsd::CommunityId::new("root").unwrap(),
        1,
        NOW / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    let path = dir.path().join("root-public");
    std::fs::write(&path, descriptor.to_bytes()).unwrap();
    let config =
        cvld::config::RootCommunityConfig::new(config, path.to_str().unwrap().into()).unwrap();
    let clock = Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)));
    let door = cvld::service::Door::root_board(config, clock.clone())
        .await
        .unwrap();
    let purpose = door.root_board_purpose(issuer).await.unwrap();
    source
        .door
        .attach_root_board_purpose(purpose)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}

// Original owner login request preparation, without completing the assertion
// until the fault transport forwards it. The selected main owner keeps this
// helper in client_contract.rs rather than exporting it from support/mod.rs.
async fn login_request(
    service: &Running,
    host: &str,
    authenticator: &mut webauthn_authenticator_rs::softtoken::SoftToken,
    user: &str,
    credential: &[u8],
) -> serde_json::Value {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    let client = client(service, host, None);
    let start: cvld::api::Ceremony = serde_json::from_value(
        client
            .call("login_begin", json!({"user":user,"credential":credential}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    json!({"ceremony":start.ceremony,"credential":credential})
}

// Fault only the transport after the original owner accepts a real assertion.
async fn login_faults(
    service: &Running,
    member: &mut Member,
) -> (serde_json::Value, tokio::task::JoinHandle<()>) {
    let mut requests = Vec::new();
    for _ in 0..2 {
        requests.push(
            login_request(
                service,
                WALLET,
                &mut member.authenticator,
                &member.user,
                &member.credential,
            )
            .await,
        );
    }
    let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let release = Arc::new(tokio::sync::Notify::new());
    let observed = counts.clone();
    let released = release.clone();
    let challenges = requests
        .iter()
        .map(|body| body["ceremony"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let upstream = service.base.clone();
    let app = axum::Router::new()
        .route(
            "/__stats",
            axum::routing::get(move || {
                let counts = observed.clone();
                async move {
                    axum::Json(
                        counts
                            .iter()
                            .map(|n| n.load(Ordering::SeqCst))
                            .collect::<Vec<_>>(),
                    )
                }
            }),
        )
        .route(
            "/__release",
            axum::routing::post(move || {
                let release = released.clone();
                async move {
                    release.notify_one();
                }
            }),
        )
        .route(
            "/v1/login_finish",
            axum::routing::post(move |body: axum::body::Bytes| {
                let challenges = challenges.clone();
                let counts = counts.clone();
                let release = release.clone();
                let upstream = upstream.clone();
                async move {
                    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let index = challenges
                        .iter()
                        .position(|id| Some(id.as_str()) == value["ceremony"].as_str())
                        .unwrap();
                    let response = reqwest::Client::new()
                        .post(format!("{upstream}/v1/login_finish"))
                        .header("host", WALLET)
                        .header("content-type", "application/json")
                        .body(body)
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), reqwest::StatusCode::OK);
                    let bytes = response.bytes().await.unwrap();
                    counts[index].fetch_add(1, Ordering::SeqCst);
                    if index == 1 {
                        release.notified().await;
                    }
                    axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(if index == 0 {
                            b"lost-after-real-session-write".to_vec()
                        } else {
                            bytes.to_vec()
                        }))
                        .unwrap()
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (json!({"base":base,"host":WALLET,"requests":requests}), task)
}

// The unoptimized original owner futures are deep; give every runtime thread real
// room instead of the 2 MiB default worker stack.
const STACK: usize = 64 * 1024 * 1024;

fn main() {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(STACK)
                .enable_all()
                .build()
                .expect("fixture runtime")
                .block_on(entry())
        })
        .expect("fixture thread")
        .join()
        .expect("fixture thread panicked");
}

async fn entry() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("private fixture output path");
    let tls_paths = match args.next().as_deref() {
        None => None,
        Some("--https") => Some((
            args.next().expect("ephemeral certificate-chain PEM path"),
            args.next().expect("ephemeral private-key PEM path"),
        )),
        Some(_) => panic!("expected --https CERTIFICATE_CHAIN_PEM PRIVATE_KEY_PEM"),
    };
    assert!(args.next().is_none(), "unexpected fixture argument");
    let certified_wallet = if let Some((chain, key)) = &tls_paths {
        Some(
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                wallet::Fixture::start(chain.as_ref(), key.as_ref()),
            )
            .await
            .expect("current Wallet startup deadline")
            .expect("original current Wallet fixture"),
        )
    } else {
        None
    };
    let wallet = global(1000).await;
    let (mut global_member, passport, public) = wallet_passport(&wallet).await;
    let service = community_with_burst("alpha", &public, 1000).await;
    let member_host = "api.alpha.example.test";
    // Public challenge for a real browser fixture credential. Membership still
    // requires the original passport and Keyhole finish; no session is seeded.
    let (_, browser_passport, _) = wallet_passport(&wallet).await;
    let proof = presentation(&service, member_host, None, &browser_passport).await;
    let browser_registration = client(&service, member_host, None)
        .call("register_begin", json!({"passport":proof}))
        .await
        .unwrap();
    // Independent real public registrations for the shared native/Wasm custody
    // source fixture. Only original passport presentation and registration begin
    // produce these challenges; the test's actual authenticator must finish them.
    let mut custody_registrations = serde_json::Map::new();
    for target in ["native", "browser"] {
        let (_, passport, _) = wallet_passport(&wallet).await;
        let proof = presentation(&service, member_host, None, &passport).await;
        let registration = client(&service, member_host, None)
            .call("register_begin", json!({"passport":proof}))
            .await
            .unwrap();
        custody_registrations.insert(target.into(), registration);
    }
    // Actual holder proof for each independent initial-custody journey. The
    // client chooses its private seed before submitting the original proof.
    let mut initial_enrollments = serde_json::Map::new();
    for target in ["durable", "before-finish", "wrong-key"] {
        let (_, passport, _) = wallet_passport(&wallet).await;
        let member = passport
            .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
            .to_hex();
        let proof = presentation(&service, member_host, None, &passport).await;
        initial_enrollments.insert(target.into(), json!({"member":member,"passport":proof}));
    }
    let trust_feed = client(&service, member_host, None)
        .call("trust_feed", json!({}))
        .await
        .unwrap();
    let admin_host = "api.admin.alpha.example.test";
    let mut member = enrol_community(&service, member_host, &passport).await;
    let vault_session = login(
        &service,
        member_host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let global_root = enrol(
        &wallet,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let board = root_board(&public, &service).await;
    // Real founding: the community and the root board start Uninitialized and each
    // first Root is created through the Global Root operator's public actions.
    let (root, board_root) = gardens::roots(&wallet, &global_root, &service, &board).await;
    let admin = gardens::admin(&wallet, &service, &root).await;
    service.clock.set(NOW + 1);
    board.clock.set(NOW + 1);
    let mut faults = Vec::new();
    for _ in 0..3 {
        let session = login(
            &wallet,
            WALLET,
            &mut global_member.authenticator,
            &global_member.user,
            &global_member.credential,
        )
        .await;
        faults.push(Fault {
            session,
            count: AtomicUsize::new(0),
            release: tokio::sync::Notify::new(),
        });
    }
    let (login_faults, login_fault_task) = login_faults(&wallet, &mut global_member).await;
    let faults = Arc::new(faults);
    let observed = faults.clone();
    let released = faults.clone();
    let forwarded = faults.clone();
    let upstream = wallet.base.clone();
    let proxy = axum::Router::new()
        .route(
            "/__stats",
            axum::routing::get(move || {
                let observed = observed.clone();
                async move {
                    axum::Json(
                        observed
                            .iter()
                            .map(|fault| fault.count.load(Ordering::SeqCst))
                            .collect::<Vec<_>>(),
                    )
                }
            }),
        )
        .route(
            "/__release",
            axum::routing::post(move || {
                let released = released.clone();
                async move {
                    for fault in released.iter() {
                        fault.release.notify_one();
                    }
                }
            }),
        )
        .route(
            "/v1/{action}",
            axum::routing::post(
                move |axum::extract::Path(action): axum::extract::Path<String>,
                      headers: axum::http::HeaderMap,
                      body: axum::body::Bytes| {
                    let forwarded = forwarded.clone();
                    let upstream = upstream.clone();
                    async move {
                        let bearer = headers.get("authorization").and_then(|v| v.to_str().ok());
                        let selected =
                            bearer
                                .and_then(|v| v.strip_prefix("Bearer "))
                                .and_then(|token| {
                                    forwarded.iter().position(|fault| fault.session == token)
                                });
                        let mut request = reqwest::Client::new()
                            .post(format!("{upstream}/v1/{action}"))
                            .header("host", WALLET)
                            .header("content-type", "application/json")
                            .body(body);
                        if let Some(bearer) = bearer {
                            request = request.header("authorization", bearer);
                        }
                        // Keep the actual browser Origin at the owner's gate;
                        // the output-fault proxy must not turn browser traffic
                        // into an origin-free native request.
                        for origin in headers.get_all("origin") {
                            request = request.header("origin", origin);
                        }
                        let response = request.send().await.unwrap();
                        let status = response.status();
                        let bytes = response.bytes().await.unwrap();
                        let mut output = bytes.to_vec();
                        if let Some(index) = selected {
                            assert_eq!(status, reqwest::StatusCode::OK);
                            forwarded[index].count.fetch_add(1, Ordering::SeqCst);
                            match index {
                                0 => output = b"broken-after-real-owner-effect".to_vec(),
                                1 => {
                                    let mut value: serde_json::Value =
                                        serde_json::from_slice(&output).unwrap();
                                    value["issuer"] = json!(vec![0u8; 600_000]);
                                    output = serde_json::to_vec(&value).unwrap();
                                }
                                _ => forwarded[index].release.notified().await,
                            }
                        }
                        axum::http::Response::builder()
                            .status(status.as_u16())
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(output))
                            .unwrap()
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_base = format!("http://{}", listener.local_addr().unwrap());
    let proxy_task = tokio::spawn(async move { axum::serve(listener, proxy).await.unwrap() });
    let mut data = json!({
        "now": NOW + 1,
        "browser_registration": browser_registration,
        "custody_registrations": custody_registrations,
        "initial_enrollments": initial_enrollments,
        "trust_key_ring": trust_feed["key_ring"],
        "login_faults": login_faults,
        "global": {"base": wallet.base, "host": WALLET, "session": global_member.session},
        "member": {"base": service.base, "host": member_host, "session": member.session},
        "vault": {"base": service.base, "host": member_host, "session": vault_session},
        "admin": {"base": service.base, "host": admin_host, "session": admin.session},
        "root": {"base": service.base, "host": admin_host, "session": root.session},
        "root_board": {"base": board.base, "host": ROOT, "session": board_root.session},
        "global_root": {"base": wallet.base, "host": ROOT, "session": global_root.session},
        "faults": faults.iter().map(|fault| json!({"base":proxy_base,"host":WALLET,"session":fault.session})).collect::<Vec<_>>(),
    });
    if let Some(wallet) = &certified_wallet {
        data["certified_wallet"] = wallet.data.clone();
    }
    // Retain the exact owner's HTTP lifecycle behind the optional TLS listener.
    // Existing component URLs and their private fixture data remain explicit HTTP.
    let https = if let Some((cert, key)) = tls_paths {
        // This fixed loopback ingress selects the original fixture community;
        // bearer, body and original server checks remain unchanged.
        let router = cvld::api::router(service.door.clone()).layer(axum::middleware::from_fn(
            |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                request.headers_mut().insert(
                    axum::http::header::HOST,
                    axum::http::HeaderValue::from_static("api.alpha.example.test"),
                );
                next.run(request).await
            },
        ));
        let https = https::HttpsFixture::start(router, service, cert.as_ref(), key.as_ref())
            .await
            .expect("start HTTPS fixture");
        data["https"] = json!({"base": https.base_url()});
        Some(https)
    } else {
        None
    };
    let temporary = format!("{path}.pending");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&temporary).unwrap();
    serde_json::to_writer(file, &data).unwrap();
    std::fs::rename(temporary, path).unwrap();
    tokio::signal::ctrl_c().await.unwrap();
    if let Some(https) = https {
        https.shutdown().await.expect("drain HTTPS fixture");
    }
    if let Some(wallet) = certified_wallet {
        wallet
            .shutdown()
            .await
            .expect("drain current Wallet fixture");
    }
    proxy_task.abort();
    login_fault_task.abort();
}
