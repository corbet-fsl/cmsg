//! The live Foyer owner fixture, found or built by the tests themselves.
//!
//! `fixture_path()` returns the path of the fixture JSON, in this order:
//! 1. `CMSG_FOYER_FIXTURE` when set (CI, `ci/test-env/cmsg.sh`, `.ci/with-foyer-fixture.py`);
//! 2. a fixture service this test process started, one per process even when several modules
//!    include this file: the process directory `<target>/foyer-fixture/run-<pid>` is created by
//!    exactly one includer, which starts the service; the others wait for its JSON.
//!
//! The service is a built fixture directory with `fixture.bin` and `tests/fixture/owner/check-shell.nix`:
//! `CMSG_FOYER_FIXTURE_DIR`, else the newest `~/agents/scratch/ws-fixture/cmsg-*` that has one (the
//! directories `ci/test-env/cmsg.sh` builds), else the repository itself, built once with
//! `.ci/prepare-foyer-fixture.sh` into `<target>/foyer-fixture/build` (works where the resolved door
//! owner is a git source, as in CI; a lane workspace patches it by path and needs the first two).
//! The binary links openssl, so it runs inside the pinned nix shell. The service stops when the test process ends: a
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
        let started = std::panic::catch_unwind(|| { let (binary, shell) = fixture_binary(&root); start(&binary, &shell, &run) });
        let mut child = started.unwrap_or_else(|e| {
            std::fs::write(run.join("failed"), b"").unwrap();
            std::panic::resume_unwind(e)
        });
        let begin = Instant::now();
        while !json.is_file() || std::fs::metadata(&json).map(|m| m.len()).unwrap_or(0) == 0 {
            if child.try_wait().unwrap().is_some() || begin.elapsed() > Duration::from_secs(300) {
                std::fs::write(run.join("failed"), b"").unwrap();
                panic!("Foyer fixture did not start (see {})", run.join("fixture.log").display());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let begin = Instant::now();
    while !json.is_file() || std::fs::metadata(&json).map(|m| m.len()).unwrap_or(0) == 0 {
        assert!(!run.join("failed").exists(), "Foyer fixture failed to start in this process");
        assert!(begin.elapsed() < Duration::from_secs(300), "Foyer fixture not ready");
        std::thread::sleep(Duration::from_millis(100));
    }
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

/// (binary, nix shell file).
fn fixture_binary(root: &Path) -> (PathBuf, PathBuf) {
    let shell_of = |dir: &Path| dir.join("tests/fixture/owner/check-shell.nix");
    if let Some(dir) = std::env::var_os("CMSG_FOYER_FIXTURE_DIR").map(PathBuf::from) {
        return (dir.join("fixture.bin"), shell_of(&dir));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let mut found: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(Path::new(&home).join("agents/scratch/ws-fixture"))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("fixture.bin").is_file() && shell_of(&e.path()).is_file())
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        found.sort();
        if let Some((_, dir)) = found.pop() {
            return (dir.join("fixture.bin"), shell_of(&dir));
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let build = root.join("build");
    let binary = build.join("debug/cmsg-foyer-fixture");
    // One builder; later callers wait for the finished binary.
    let lock = root.join("build.lock");
    if binary.is_file() {
    } else if std::fs::create_dir(&lock).is_ok() {
        let status = Command::new("bash")
            .arg(".ci/prepare-foyer-fixture.sh")
            .current_dir(manifest)
            .env("CARGO_TARGET_DIR", &build)
            .stdout(Stdio::null())
            .status()
            .expect("bash runs the fixture build");
        assert!(status.success(), "Foyer fixture build failed (set CMSG_FOYER_FIXTURE or CMSG_FOYER_FIXTURE_DIR)");
    } else {
        wait_for(&binary, Duration::from_secs(3600));
    }
    (binary, shell_of(manifest))
}

fn start(binary: &Path, shell: &Path, run: &Path) -> std::process::Child {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tls = manifest.join("tests/support/current-tls");
    let script = r#"fixture="$1"; shift
nix-shell "$1" --run "$2" &
child=$!
while kill -0 "$fixture" 2>/dev/null && kill -0 "$child" 2>/dev/null; do sleep 1; done
pkill -P "$child" 2>/dev/null; kill "$child" 2>/dev/null
"#;
    let inner = format!(
        "exec '{}' '{}' --https '{}' '{}'",
        binary.display(),
        run.join("fixture.json").display(),
        tls.join("certificate.pem").display(),
        tls.join("key.pem").display()
    );
    let log = std::fs::File::create(run.join("fixture.log")).unwrap();
    Command::new("sh")
        .args(["-c", script, "foyer-fixture-watch"])
        .arg(std::process::id().to_string())
        .arg(shell)
        .arg(inner)
        .env("NIX_BUILD_SHELL", "bash")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("sh starts the Foyer fixture")
}
