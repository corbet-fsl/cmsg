//! Launch an original owner from trusted, CI-supplied ephemeral configuration.
#![forbid(unsafe_code)]

#[path = "acceptance/current.rs"]
mod current;
mod https;

use cvld::{
    config::{CommunityConfig, Config},
    service::{Door, SystemClock},
};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::signal::unix::{SignalKind, signal};

type Result<T> = std::result::Result<T, &'static str>;
const FILE_LIMIT: u64 = 1024 * 1024;
const LIFETIME: Duration = Duration::from_secs(900);
const STARTUP_LIMIT: Duration = Duration::from_secs(30);

struct Inputs {
    mode: String,
    directory: PathBuf,
    config: PathBuf,
    chain: PathBuf,
    key: PathBuf,
    output: PathBuf,
}

impl Inputs {
    fn read() -> Result<Self> {
        let args: Vec<_> = std::env::args_os().skip(1).take(7).collect();
        if args.len() != 6 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
            return Err("usage: cmsg-acceptance-fixture MODE FIXTURE_DIR CONFIG CHAIN KEY OUTPUT");
        }
        let mode = args[0].to_str().ok_or("invalid mode")?;
        if !matches!(mode, "global" | "community") {
            return Err("invalid mode");
        }
        let directory = Path::new(&args[1]);
        if !directory.is_absolute() || !directory.is_dir() {
            return Err("invalid fixture directory");
        }
        let directory = directory
            .canonicalize()
            .map_err(|_| "invalid fixture directory")?;
        let config = input_file(&directory, Path::new(&args[2]))?;
        let chain = input_file(&directory, Path::new(&args[3]))?;
        let key = input_file(&directory, Path::new(&args[4]))?;
        let output = local_destination(&directory, Path::new(&args[5]))?;
        match fs::symlink_metadata(&output) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("output must be absent"),
        }
        Ok(Self {
            mode: mode.into(),
            directory,
            config,
            chain,
            key,
            output,
        })
    }

    async fn owner(&self) -> Result<Door> {
        let config_path = self.config.to_str().ok_or("invalid configuration path")?;
        let clock = Arc::new(SystemClock);
        match self.mode.as_str() {
            "global" => {
                let config =
                    Config::read(config_path).map_err(|_| "invalid global configuration")?;
                self.database(&config.database_url, config.database_token_file.as_deref())?;
                self.files(&[
                    Some(&config.signing_seed_file),
                    Some(&config.issuer_key_file),
                    Some(&config.uniqueness_key_file),
                    Some(&config.policy_file),
                    Some(&config.policy_authority_file),
                    config.root_bootstrap_file.as_deref(),
                ])?;
                Door::global(config, clock)
                    .await
                    .map_err(|_| "global owner unavailable")
            }
            "community" => {
                let config = CommunityConfig::read(config_path)
                    .map_err(|_| "invalid community configuration")?;
                self.database(&config.database_url, config.database_token_file.as_deref())?;
                self.files(&[
                    Some(&config.signing_seed_file),
                    Some(&config.rulebook_file),
                    Some(&config.schema_file),
                    Some(&config.global_key_ring_file),
                    Some(&config.global_status_file),
                    Some(&config.voucher_public_key_file),
                    config.root.bootstrap_file.as_deref(),
                    config.admin.bootstrap_file.as_deref(),
                ])?;
                Door::community(config, clock)
                    .await
                    .map_err(|_| "community owner unavailable")
            }
            _ => Err("invalid mode"),
        }
    }

    fn files(&self, paths: &[Option<&str>]) -> Result<()> {
        for path in paths.iter().flatten() {
            input_file(&self.directory, Path::new(path))?;
        }
        Ok(())
    }

    fn database(&self, address: &str, token: Option<&str>) -> Result<()> {
        let url = reqwest::Url::parse(address).map_err(|_| "invalid fixture database")?;
        if token.is_some()
            || url.scheme() != "file"
            || url.host_str().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("database must be a local file without a token");
        }
        let path = url.to_file_path().map_err(|_| "invalid fixture database")?;
        let path = local_destination(&self.directory, &path)?;
        if path == self.output {
            return Err("database and output must differ");
        }
        // SQLite may open these siblings as well. CI exclusively owns this tree.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut sibling = path.as_os_str().to_os_string();
            sibling.push(suffix);
            match fs::symlink_metadata(Path::new(&sibling)) {
                Ok(metadata) if metadata.is_file() => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("invalid fixture database file"),
            }
        }
        Ok(())
    }
}

fn input_file(directory: &Path, path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > 4096 {
        return Err("invalid fixture input");
    }
    let path = path.canonicalize().map_err(|_| "invalid fixture input")?;
    let metadata = fs::metadata(&path).map_err(|_| "invalid fixture input")?;
    if !path.starts_with(directory) || !metadata.is_file() || metadata.len() > FILE_LIMIT {
        return Err("invalid fixture input");
    }
    Ok(path)
}

fn local_destination(directory: &Path, path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > 4096 {
        return Err("invalid fixture destination");
    }
    let parent = path
        .parent()
        .ok_or("invalid fixture destination")?
        .canonicalize()
        .map_err(|_| "invalid fixture destination")?;
    if !parent.is_dir() || !parent.starts_with(directory) {
        return Err("invalid fixture destination");
    }
    Ok(parent.join(path.file_name().ok_or("invalid fixture destination")?))
}

async fn run() -> Result<()> {
    let inputs = Inputs::read()?;
    // Install handlers before construction: no listener follows a startup error.
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal setup failed")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal setup failed")?;
    let owner = tokio::select! {
        result = tokio::time::timeout(STARTUP_LIMIT, inputs.owner()) =>
            result.map_err(|_| "owner startup timed out")??,
        _ = interrupt.recv() => return Ok(()),
        _ = terminate.recv() => return Ok(()),
    };
    let mut output =
        tempfile::NamedTempFile::new_in(inputs.output.parent().ok_or("invalid output")?)
            .map_err(|_| "output preparation failed")?;
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "output preparation failed")?;
    let fixture = https::HttpsFixture::start(
        cvld::api::router(owner.clone()),
        owner.clone(),
        &inputs.chain,
        &inputs.key,
    )
    .await
    .map_err(|_| "HTTPS startup failed")?;
    // Every fallible operation after listener startup funnels through shutdown.
    let result = async {
        let manifest = serde_json::json!({ "base": fixture.base_url(), "mode": inputs.mode });
        serde_json::to_writer(&mut output, &manifest).map_err(|_| "output write failed")?;
        output.write_all(b"\n").map_err(|_| "output write failed")?;
        output.as_file().sync_all().map_err(|_| "output write failed")?;
        output.persist_noclobber(&inputs.output).map_err(|_| "output publication failed")?;
        let deadline = tokio::time::sleep(LIFETIME);
        tokio::pin!(deadline);
        let mut maintenance = tokio::time::interval(Duration::from_secs(30));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interrupt.recv() => return Ok(()),
                _ = terminate.recv() => return Ok(()),
                _ = &mut deadline => return Ok(()),
                _ = maintenance.tick() => {
                    tokio::select! {
                        _ = interrupt.recv() => return Ok(()),
                        _ = terminate.recv() => return Ok(()),
                        _ = &mut deadline => return Ok(()),
                        result = tokio::time::timeout(Duration::from_secs(10), owner.maintain()) => {
                            result.map_err(|_| "owner maintenance timed out")?
                                .map_err(|_| "owner maintenance failed")?;
                        }
                    }
                }
            }
        }
    }.await;
    let shutdown = fixture
        .shutdown()
        .await
        .map_err(|_| "HTTPS shutdown failed");
    result.and(shutdown)
}

// Original ckyh storage requires a multithread runtime for its blocking bridge.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let result = match std::env::args().nth(1).as_deref() {
        Some("--current-owner") => current::run().await,
        Some("--wallet-owner") => current::run_wallet().await,
        _ => run().await,
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}
