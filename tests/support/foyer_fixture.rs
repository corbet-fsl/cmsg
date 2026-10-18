//! The live Foyer owner fixture, found or built by the tests themselves.
//!
//! `fixture_path()` returns the path of the fixture JSON, in this order:
//! 1. `CMSG_FOYER_FIXTURE` when set (CI, `ci/test-env/cmsg.sh`, `.ci/with-foyer-fixture.py`);
//! 2. a fixture service this test process started, one per process even when several modules
//!    include this file: the process directory `<target>/foyer-fixture/run-<pid>` is created by
//!    exactly one includer, which starts the service; the others wait for its JSON.
//!
//! The service binary is `CMSG_FOYER_FIXTURE_BIN`, else the cached build
//! `<target>/foyer-fixture/build/debug/cmsg-foyer-fixture`, else it is built once with
//! `.ci/prepare-foyer-fixture.sh` into that cache (a nix shell with the pinned openssl; the same
//! build CI and `ci/test-env/cmsg.sh` run). The service stops when the test process ends: a
//! watcher shell kills it as soon as its parent is gone. Ceremony state expires 300 s after start.
#![allow(dead_code)]
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn fixture_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CMSG_FOYER_FIXTURE") {
        return path.into();
    }
    let root = target_cache().join("foyer-fixture");
    std::fs::create_dir_all(&root).unwrap();
    let run = root.join(format!("run-{}", std::process::id()));
    let json = run.join("fixture.json");
    if std::fs::create_dir(&run).is_ok() {
        let binary = fixture_binary(&root);
        start(&binary, &run);
    }
    wait_for(&json, Duration::from_secs(1200));
    json
}

/// `<target>/debug`, two levels above the running test executable (`debug/deps/<name>`).
fn target_cache() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors().nth(2).expect("test executable in target/debug/deps").to_path_buf()
}

fn wait_for(path: &Path, limit: Duration) {
    let start = Instant::now();
    while !path.is_file() || std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) == 0 {
        assert!(start.elapsed() < limit, "Foyer fixture not ready: {}", path.display());
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn fixture_binary(root: &Path) -> PathBuf {
    if let Some(binary) = std::env::var_os("CMSG_FOYER_FIXTURE_BIN") {
        return binary.into();
    }
    let build = root.join("build");
    let binary = build.join("debug/cmsg-foyer-fixture");
    if binary.is_file() {
        return binary;
    }
    // One builder; later callers wait for the finished binary.
    let lock = root.join("build.lock");
    if std::fs::create_dir(&lock).is_ok() {
        let status = Command::new("bash")
            .arg(".ci/prepare-foyer-fixture.sh")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("CARGO_TARGET_DIR", &build)
            .stdout(Stdio::null())
            .status()
            .expect("bash runs the fixture build");
        assert!(status.success(), "Foyer fixture build failed (set CMSG_FOYER_FIXTURE or CMSG_FOYER_FIXTURE_BIN)");
    } else {
        wait_for(&binary, Duration::from_secs(3600));
    }
    binary
}

fn start(binary: &Path, run: &Path) {
    let tls = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/current-tls");
    let script = r#"fixture="$1"; shift
"$@" >/dev/null 2>&1 &
child=$!
while kill -0 "$fixture" 2>/dev/null && kill -0 "$child" 2>/dev/null; do sleep 1; done
kill "$child" 2>/dev/null
"#;
    Command::new("sh")
        .args(["-c", script, "foyer-fixture-watch"])
        .arg(std::process::id().to_string())
        .arg(binary)
        .arg(run.join("fixture.json"))
        .arg("--https")
        .arg(tls.join("certificate.pem"))
        .arg(tls.join("key.pem"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sh starts the Foyer fixture");
}
