#!/usr/bin/env python3
"""Bounded public-Tor browser/native contract using disposable CI processes.

No custom authorities, consensus fabrication, relay/exits, persistent services,
or system configuration. Application participants and payloads are synthetic.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import zipfile

from runtime_process import poll_child, stop_child

BOOTSTRAP_SECONDS = 1200
DRIVER_SECONDS = 2000
CONSENSUS_LIMIT = 32 * 1024 * 1024


def stop_signal(signum, _frame):
    raise KeyboardInterrupt(f"public fixture interrupted by signal {signum}")


def read_bounded(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("public fixture artifact exceeds bound")
    return data


def log_tail(path, limit=65536):
    if not path.is_file():
        return b""
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - limit))
        return stream.read(limit)


def consensus_evidence(data):
    # Cryptographic authority validation belongs to the owning C Tor client or
    # gateway sync. These checks bind retained public evidence and our run bound.
    lines = data.decode("ascii").splitlines()
    if not lines or lines[0] != "network-status-version 3 microdesc":
        raise RuntimeError("expected accepted public microdescriptor consensus")
    dates = {}
    for name in ["valid-after", "fresh-until", "valid-until"]:
        values = [line[len(name) + 1:] for line in lines if line.startswith(name + " ")]
        if len(values) != 1:
            raise RuntimeError("invalid public consensus lifetime")
        dates[name] = int(datetime.strptime(values[0], "%Y-%m-%d %H:%M:%S")
                          .replace(tzinfo=timezone.utc).timestamp())
    if not dates["valid-after"] < dates["fresh-until"] < dates["valid-until"]:
        raise RuntimeError("invalid public consensus lifetime order")
    for name in ["shared-rand-current-value", "shared-rand-previous-value"]:
        values = [line.split() for line in lines if line.startswith(name + " ")]
        if len(values) != 1 or len(values[0]) != 3 or not values[0][1].isdigit():
            raise RuntimeError("public consensus shared randomness missing")
        value = base64.b64decode(values[0][2], validate=True)
        if len(value) != 32 or base64.b64encode(value).decode("ascii") != values[0][2]:
            raise RuntimeError("invalid public shared-random encoding")
    return {"sha256": hashlib.sha256(data).hexdigest(), **dates,
            "relayCount": sum(line.startswith("r ") for line in lines),
            "hsdirRelayCount": sum(line.startswith("s ") and "HSDir" in line.split() for line in lines),
            "directorySignatures": sum(line.startswith("directory-signature ") for line in lines)}


signal.signal(signal.SIGTERM, stop_signal)
signal.signal(signal.SIGINT, stop_signal)
if os.environ.get("TOR_NETWORK") != "public":
    raise RuntimeError("explicit TOR_NETWORK=public required")
root = Path(__file__).resolve().parents[2]
artifact = Path(os.environ["TOR_RUNTIME_ARTIFACT"]).resolve()
artifact.mkdir(parents=True, exist_ok=True)
for name in ["TOR_BIN", "TOR_GATEWAY_BIN", "TOR_NATIVE_PEER_BIN"]:
    if not Path(os.environ[name]).is_file():
        raise RuntimeError("missing public fixture executable")

started = time.monotonic()
receipt = {"network": "public", "syntheticParticipants": True,
           "customAuthorities": False, "testNetworkFeature": False,
           "gatewaySync": "public authority signature and lifetime verification",
           "gatewayLocalTargetsAllowed": False, "gatewayBindIp": "127.0.0.1",
           "vanguards": "full", "stage": "startup", "complete": False,
           "bootstrapLimitSeconds": BOOTSTRAP_SECONDS, "driverLimitSeconds": DRIVER_SECONDS}


def save_receipt():
    receipt["elapsedSeconds"] = round(time.monotonic() - started, 3)
    (artifact / "public-network-provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")


# Arti checks the entire ancestor chain. The worker's shared /tmp is writable
# by other users, so retain the normal permission checks under the owned CI
# artifact parent, outside the recursively collected runtime outputs. Even a
# forced termination must not sweep leftover test keys into runtime artifacts.
with tempfile.TemporaryDirectory(prefix=".public-tor-", dir=artifact.parent) as temporary:
    temporary = Path(temporary)
    native = gateway = driver = None
    native_log = temporary / "native-tor.log"
    gateway_log = temporary / "gateway.log"
    native_handle = gateway_handle = None
    try:
        native_data = temporary / "native"
        gateway_data = temporary / "gateway"
        native_data.mkdir(mode=0o700)
        gateway_data.mkdir(mode=0o700)
        # A failed port claim aborts the fixture; it never adopts another proxy.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            socks_port = listener.getsockname()[1]
        torrc = temporary / "torrc"
        torrc.write_text("\n".join([
            f"DataDirectory {native_data}", "ClientOnly 1", "RunAsDaemon 0",
            f"SocksPort 127.0.0.1:{socks_port} IsolateSOCKSAuth",
            "SocksPolicy accept 127.0.0.1", "SocksPolicy reject *",
            "ControlPort 0", "DNSPort 0", "ORPort 0", "DirPort 0",
            "UseMicrodescriptors 1", "SafeLogging 1", "AvoidDiskWrites 1",
            f"__OwningControllerProcess {os.getpid()}", "Log notice stdout", "",
        ]))
        native_handle = native_log.open("wb")
        native = subprocess.Popen([os.environ["TOR_BIN"], "-f", str(torrc)],
                                  stdout=native_handle, stderr=subprocess.STDOUT,
                                  start_new_session=True)
        gateway_config = {"data_dir": str(gateway_data), "kps_port": 0,
                          "kps_bind_ip": "127.0.0.1",
                          "kps_key_file": str(temporary / "ephemeral-kps.key"), "keccak_dir": "",
                          "advertised_addresses": ["127.0.0.1"], "tunnel_max": 128,
                          "tunnel_per_ip": 128, "tunnel_idle_timeout": 300,
                          "tunnel_max_lifetime": 2300}
        config_path = temporary / "gateway.json"
        config_path.write_text(json.dumps(gateway_config))
        environment = {**os.environ, "XDG_DATA_HOME": str(temporary / "xdg-data"),
                       "XDG_CACHE_HOME": str(temporary / "xdg-cache"),
                       "XDG_CONFIG_HOME": str(temporary / "xdg-config"),
                       "RUST_LOG": "info", "NO_COLOR": "1"}
        environment.pop("TOR_JS_GATEWAY_ALLOW_LOCAL_TARGETS", None)
        gateway_handle = gateway_log.open("wb")
        # Empty data_dir prevents upstream's unverified cached-text preload.
        # Normal sync verifies authority signatures and time before allowlisting.
        gateway = subprocess.Popen([os.environ["TOR_GATEWAY_BIN"], "--config", str(config_path), "run"],
                                   env=environment, stdout=gateway_handle,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        receipt["stage"] = "public-directory-bootstrap"
        save_receipt()
        last_report = -60
        gateway_address = None
        while time.monotonic() - started < BOOTSTRAP_SECONDS:
            if poll_child(native) is not None or poll_child(gateway) is not None:
                raise RuntimeError("public Tor client or gateway exited during bootstrap")
            native_ready = b"Bootstrapped 100%" in log_tail(native_log)
            text = log_tail(gateway_log).decode("utf-8", errors="replace")
            match = re.search(r"127\.0\.0\.1:[1-9][0-9]{0,4}:[A-Za-z0-9_=-]+", text)
            if match:
                gateway_address = match[0]
            native_cache = native_data / "cached-microdesc-consensus"
            gateway_cache = gateway_data / "consensus-microdesc.txt"
            archive_ready = (gateway_data / "bootstrap.zip.zst").is_file()
            if native_ready and gateway_address and archive_ready and native_cache.is_file() and gateway_cache.is_file():
                native_bytes = read_bounded(native_cache, CONSENSUS_LIMIT)
                gateway_bytes = read_bounded(gateway_cache, CONSENSUS_LIMIT)
                native_consensus = consensus_evidence(native_bytes)
                gateway_consensus = consensus_evidence(gateway_bytes)
                now = time.time()
                # The gateway's ACL has no expiry field. End the fixture before
                # the accepted directory can expire; never silently broaden it.
                enough_time = all(c["valid-after"] <= now and
                    c["valid-until"] > now + DRIVER_SECONDS + 30 and c["hsdirRelayCount"] > 0
                    for c in [native_consensus, gateway_consensus])
                with zipfile.ZipFile(gateway_data / "bootstrap.zip") as archive:
                    entry = archive.getinfo("bootstrap/consensus-microdesc.txt")
                    if entry.file_size > CONSENSUS_LIMIT:
                        raise RuntimeError("public bootstrap consensus exceeds bound")
                    same_archive = archive.read(entry) == gateway_bytes
                if enough_time and same_archive:
                    (artifact / "public-native-consensus.txt").write_bytes(native_bytes)
                    (artifact / "public-gateway-consensus.txt").write_bytes(gateway_bytes)
                    receipt["nativeConsensus"] = native_consensus
                    receipt["gatewayConsensus"] = gateway_consensus
                    receipt["torVersion"] = subprocess.check_output(
                        [os.environ["TOR_BIN"], "--version"], text=True).strip()
                    receipt["bootstrapElapsedSeconds"] = round(time.monotonic() - started, 3)
                    break
            elapsed = time.monotonic() - started
            if elapsed - last_report >= 60:
                print(f"Public Tor bootstrap: {elapsed:.0f}s; native={native_ready}, gatewayArchive={archive_ready}", flush=True)
                last_report = elapsed
            time.sleep(1)
        else:
            raise RuntimeError("public Tor bootstrap deadline exceeded")

        fixture = {"testOnly": True, "network": "public", "gateway": gateway_address,
                   "vanguards": "full", "testNetworkFeature": False,
                   "publicNonRelay": "192.0.2.1:1"}
        fixture_path = temporary / "fixture.json"
        fixture_path.write_text(json.dumps(fixture))
        environment.update({"TOR_FIXTURE_JSON": str(fixture_path),
                            "TOR_NATIVE_SOCKS": f"127.0.0.1:{socks_port}",
                            "BROWSER_EVIDENCE": str(artifact / "browser-tor-runtime.json")})
        receipt["stage"] = "browser-public-tor-contract"
        save_receipt()
        driver = subprocess.Popen(["node", str(root / "browser/upstream/runtime-driver.mjs")],
                                  cwd=root, env=environment, start_new_session=True)
        driver_started = time.monotonic()
        while poll_child(driver) is None:
            if poll_child(native) is not None or poll_child(gateway) is not None:
                raise RuntimeError("public Tor dependency exited during browser contract")
            if time.monotonic() - driver_started >= DRIVER_SECONDS:
                raise RuntimeError("public browser contract supervisor deadline exceeded")
            if time.time() >= min(native_consensus["valid-until"], gateway_consensus["valid-until"]):
                raise RuntimeError("retained public consensus expired during browser contract")
            time.sleep(1)
        if poll_child(driver) != 0:
            raise RuntimeError("actual public browser Tor contract failed")
        receipt["stage"] = "complete"
        receipt["complete"] = True
    finally:
        cleanup_failed = False
        for child in [driver, gateway, native]:
            try:
                stop_child(child)
            except (OSError, RuntimeError):
                cleanup_failed = True
        if gateway_handle is not None:
            gateway_handle.close()
        if native_handle is not None:
            native_handle.close()
        (artifact / "public-gateway.log").write_bytes(log_tail(gateway_log))
        (artifact / "public-native-tor.log").write_bytes(log_tail(native_log))
        receipt["cleanupFailed"] = cleanup_failed
        save_receipt()
        if cleanup_failed:
            raise RuntimeError("public fixture process cleanup failed")
