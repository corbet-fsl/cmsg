//! Test-only actual Door host for the generated client conformance check.
//! Pairing material is written only to the child process's inherited private pipe.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    use cmsg::door::{catalog, native, Configuration, Door, Role};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    struct Clock;
    impl native::Clock for Clock {
        fn now(&self) -> u64 {
            11
        }
    }
    let origin = "https://client.example";
    let config = Configuration::new(
        "conformance".into(),
        BTreeMap::from([(Role::Member, BTreeSet::from([origin.into()]))]),
    )
    .unwrap();
    let mut door = Door::new(config);
    let token = door
        .pair_client(
            origin,
            Role::Member,
            catalog().into_iter().map(|a| a.action).collect(),
            10,
            100,
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = native::router(door, BTreeSet::from([address.to_string()]), Arc::new(Clock)).unwrap();
    // The parent consumes this private pipe; it never forwards the token to logs.
    println!(
        "{}",
        serde_json::json!({
            "base": format!("http://{address}"), "origin": origin,
            "capability": token.expose_for_transport()
        })
    );
    axum::serve(listener, app).await.unwrap();
}

#[cfg(target_arch = "wasm32")]
fn main() {}
