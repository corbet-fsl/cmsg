"""Real Tor experiment with synthetic local keys, on a disposable CI runner only."""
import pathlib
import subprocess
import tempfile
import time

with tempfile.TemporaryDirectory(prefix="cmsg-tor-") as tmp:
    root = pathlib.Path(tmp)
    processes = []
    logs = []
    try:
        for name, socks_port in [("client", 19050), ("service", 19051)]:
            data = root / name
            data.mkdir(mode=0o700)
            lines = [f"DataDirectory {data}", f"SocksPort 127.0.0.1:{socks_port} IsolateSOCKSAuth", "Log notice stdout"]
            if name == "service":
                lines += [f"HiddenServiceDir {data / 'onion'}", "HiddenServicePort 80 127.0.0.1:18999"]
            config = data / "torrc"
            config.write_text("\n".join(lines) + "\n")
            log = (data / "notice.log").open("w")
            logs.append(log)
            processes.append(subprocess.Popen(["tor", "-f", str(config)], stdout=log, stderr=log))
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("isolated Tor process exited before bootstrap")
            if all("Bootstrapped 100%" in (root / name / "notice.log").read_text() for name in ("client", "service")):
                break
            time.sleep(2)
        else:
            raise RuntimeError("Tor bootstrap unavailable on this hosted runner")
        onion = (root / "service" / "onion" / "hostname").read_text().strip()
        # Descriptor publication follows bootstrap. Each failed probe exits; retry
        # still uses only Tor. No direct fallback exists in the probe or library.
        for attempt in range(4):
            result = subprocess.run(["target/debug/examples/tor_roundtrip", "127.0.0.1:19050", onion, "127.0.0.1:18999"], timeout=65, capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout.strip())
                break
            time.sleep(15)
        else:
            raise RuntimeError("onion probe could not establish a circuit")
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in logs:
            log.close()
