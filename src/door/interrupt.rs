//! Test only (feature `interrupt-points`; production builds never enable it): named points
//! after every durable step of the composer, so a harness can kill the composing device at
//! each one and prove that every step resumes without a second confirmation.
//!
//! `CMSG_INTERRUPT_LOG=<file>` records each point the first time it is passed (`point
//! <name>`) and each wallet stamp confirmation the person is asked for (`confirmation`).
//! With `CMSG_INTERRUPT_NEW` also set, the process ends at the first point not yet in the log,
//! as a kill would (no unwinding, nothing flushed): restarting the device on the same storage
//! until it serves visits every point exactly once. Without the feature both are no-ops.

#[cfg(feature = "interrupt-points")]
fn append(path: &std::ffi::OsStr, line: &str) {
    use std::io::Write;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path);
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{line}");
        let _ = file.sync_all();
    }
}

/// A durable step named `name` just completed.
pub(crate) fn point(name: &str) {
    #[cfg(feature = "interrupt-points")]
    if let Some(path) = std::env::var_os("CMSG_INTERRUPT_LOG") {
        let line = format!("point {name}");
        let seen = std::fs::read_to_string(&path)
            .map(|log| log.lines().any(|l| l == line))
            .unwrap_or(false);
        if !seen {
            append(&path, &line);
            if std::env::var_os("CMSG_INTERRUPT_NEW").is_some() {
                eprintln!("interrupt-point reached: {name}");
                std::process::exit(86);
            }
        }
    }
    #[cfg(not(feature = "interrupt-points"))]
    let _ = name;
}

/// The person is asked for one wallet stamp confirmation now.
pub(crate) fn confirmation() {
    #[cfg(feature = "interrupt-points")]
    if let Some(path) = std::env::var_os("CMSG_INTERRUPT_LOG") {
        append(&path, "confirmation");
    }
}
