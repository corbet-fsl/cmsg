//! Reuse the exact owner's real database, passkey, passport and policy fixtures.
#[path = "owner/mod.rs"]
mod owner;
use owner::*;
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Fault {
    session: String,
    count: AtomicUsize,
    release: tokio::sync::Notify,
}

#[tokio::main]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("private fixture output path");
    let wallet = global(1000).await;
    let (mut global_member, passport, public) = wallet_passport(&wallet).await;
    let service = community_with_burst("alpha", &public, 1000).await;
    let member_host = "api.alpha.example.test";
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
    let admin = enrol(
        &service,
        admin_host,
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let root = enrol(&service, ROOT, Some("synthetic-root-enrolment-capability")).await;
    let global_root = enrol(
        &wallet,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    service.clock.set(NOW + 1);
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
    let data = json!({
        "now": NOW + 1,
        "global": {"base": wallet.base, "host": WALLET, "session": global_member.session},
        "member": {"base": service.base, "host": member_host, "session": member.session},
        "vault": {"base": service.base, "host": member_host, "session": vault_session},
        "admin": {"base": service.base, "host": admin_host, "session": admin.session},
        "root": {"base": service.base, "host": ROOT, "session": root.session},
        "global_root": {"base": wallet.base, "host": ROOT, "session": global_root.session},
        "faults": faults.iter().map(|fault| json!({"base":proxy_base,"host":WALLET,"session":fault.session})).collect::<Vec<_>>(),
    });
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
    proxy_task.abort();
}
