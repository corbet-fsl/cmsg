#!/usr/bin/env python3
"""Disposable real Tor/KPS network for the browser/native runtime contract.

Run only on a CI worker with the pinned Chutney source and isolated tool deps.
No host service or public directory authority participates in this fixture.
"""
import dataclasses
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

CHUTNEY_REVISION = "6cc158868d722e652975cb4efd5b278d95ff2fbb"
source = Path(os.environ["CHUTNEY_SOURCE"]).resolve()
sys.path.insert(0, str(source / "lib"))
from chutney import TorNet
from chutney.TorNet import NodeConfig, NetworkConfig


def stop_child(child):
    if child is not None and child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def stop_signal(signum, _frame):
    raise KeyboardInterrupt(f"fixture interrupted by signal {signum}")


signal.signal(signal.SIGTERM, stop_signal)
signal.signal(signal.SIGINT, stop_signal)
root = Path(__file__).resolve().parents[2]
artifact = Path(os.environ["TOR_RUNTIME_ARTIFACT"]).resolve()
artifact.mkdir(parents=True, exist_ok=True)
os.environ["CHUTNEY_TOR"] = os.environ["TOR_BIN"]
os.environ["CHUTNEY_TOR_GENCERT"] = os.environ["TOR_GENCERT_BIN"]
for executable in [os.environ["TOR_BIN"], os.environ["TOR_GENCERT_BIN"],
                   os.environ["TOR_GATEWAY_BIN"], os.environ["TOR_NATIVE_PEER_BIN"]]:
    if not Path(executable).is_file():
        raise RuntimeError("missing isolated fixture executable")

with tempfile.TemporaryDirectory(prefix="cmsg-browser-tor-fixture-") as temporary:
    temporary = Path(temporary)
    # Exits are needed for a representative consensus, but this fixture never
    # requests an exit stream. Keep any resolver probing on loopback too.
    resolver = temporary / "resolv.conf"
    resolver.write_text("nameserver 127.0.0.1\n")
    network = TorNet.Network(NetworkConfig(tor_bin=os.environ["TOR_BIN"]))
    base = NodeConfig(controlling_pid=os.getpid(), connlimit=256, disableipv6=True,
                      sandbox=False, dns_conf=str(resolver), enable_dnsport=False,
                      extra_raw_torrc="ServerDNSDetectHijacking 0\n")
    authority = dataclasses.replace(base, tag="a", authority=True, relay=True)
    relay = dataclasses.replace(base, tag="r", relay=True)
    exit_relay = dataclasses.replace(base, tag="e", relay=True, exit=True)
    client = dataclasses.replace(base, tag="c", client=True)
    network.addNodes(authority.getN(4) + relay.getN(20) + exit_relay.getN(2) + client.getN(1))
    # Reserve all TCP port ranges together before configuring. The runner must
    # serialize this fixture; Chutney releases reservations when Tor starts.
    reservations = []
    for field in ["orport_base", "dirport_base", "controlport_base", "socksport_base",
                  "extorport_base", "ptport_base", "dnsport_base"]:
        for attempt in range(100):
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            first = probe.getsockname()[1]
            probe.close()
            if first > 65000:
                continue
            group = []
            try:
                for port in range(first, first + 32):
                    reserved = socket.socket()
                    reserved.bind(("127.0.0.1", port))
                    group.append(reserved)
            except OSError:
                reserved.close()
                for reserved in group:
                    reserved.close()
                continue
            reservations.extend(group)
            setattr(network, field, first)
            break
        else:
            raise RuntimeError("cannot reserve isolated Tor ports")
    gateway = None
    driver = None
    gateway_log = temporary / "gateway.log"
    log_handle = None
    try:
        network.init(data_dir=temporary / "tor")
        network.configure(config_phase=1)
        for reserved in reservations:
            reserved.close()
        network.start(launch_phase=1)
        network.wait_for_bootstrap(launch_phase=1, limit_secs=360)
        nodes = list(network.nodes)
        authorities = []
        for node in nodes[:4]:
            certificate = (node.dir / "keys/authority_certificate").read_text()
            match = re.search(r"(?m)^fingerprint ([A-Fa-f0-9]{40})$", certificate)
            if not match:
                raise RuntimeError("fixture authority certificate missing identity")
            authorities.append(match[1])
        fallbacks = [{"rsa_identity": node.fingerprint.unwrap(),
                      "ed_identity": node.fingerprint_ed25519.unwrap(),
                      "orports": [f"127.0.0.1:{node.orport}"]} for node in nodes[:4]]
        consensus = nodes[-1].dir / "cached-microdesc-consensus"
        if not consensus.is_file():
            raise RuntimeError("fixture has no signed microdescriptor consensus")
        gateway_data = temporary / "gateway"
        gateway_data.mkdir()
        shutil.copyfile(consensus, gateway_data / "consensus-microdesc.txt")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            gateway_port = udp.getsockname()[1]
        config = {"data_dir": str(gateway_data), "kps_port": gateway_port,
                  "kps_key_file": str(temporary / "synthetic-kps.key"), "keccak_dir": "",
                  "advertised_addresses": ["127.0.0.1"], "tunnel_max": 128,
                  "tunnel_per_ip": 128, "tunnel_idle_timeout": 300, "tunnel_max_lifetime": 1200}
        config_path = temporary / "gateway.json"
        config_path.write_text(json.dumps(config))
        log_handle = gateway_log.open("w")
        gateway = subprocess.Popen([os.environ["TOR_GATEWAY_BIN"], "--config", str(config_path), "run", "--no-sync"],
            env={**os.environ, "TOR_JS_GATEWAY_ALLOW_LOCAL_TARGETS": "1", "RUST_LOG": "info", "NO_COLOR": "1"},
            stdout=log_handle, stderr=subprocess.STDOUT, start_new_session=True)
        gateway_address = None
        for _ in range(300):
            if gateway.poll() is not None:
                raise RuntimeError("fixture gateway exited")
            match = re.search(r"127\.0\.0\.1:" + str(gateway_port) + r":[A-Za-z0-9_=-]+", gateway_log.read_text())
            if match:
                gateway_address = match[0]
                break
            time.sleep(0.1)
        if gateway_address is None:
            raise RuntimeError("fixture gateway address not available")
        fixture = {"testOnly": True, "gateway": gateway_address, "arti": {
            "tor_network": {"authorities": {"v3idents": authorities, "uploads": [], "downloads": [], "votes": []},
                            "fallback_caches": fallbacks},
            "path_rules": {"ipv4_subnet_family_prefix": 33, "ipv6_subnet_family_prefix": 129},
            "override_net_params": {}, "vanguards": {"mode": "full"}}}
        fixture_path = temporary / "fixture.json"
        fixture_path.write_text(json.dumps(fixture))
        socks_ip, socks_port = next(iter(nodes[-1].socksport_endpoints()))
        environment = {**os.environ, "TOR_FIXTURE_JSON": str(fixture_path),
                       "TOR_NATIVE_SOCKS": f"{socks_ip}:{socks_port}",
                       "BROWSER_EVIDENCE": str(artifact / "browser-tor-runtime.json")}
        driver = subprocess.Popen(["node", str(root / "browser/upstream/runtime-driver.mjs")],
            cwd=root, env=environment, start_new_session=True)
        result = driver.wait(timeout=1000)
        if result != 0:
            raise RuntimeError("real browser Tor contract failed")
        (artifact / "fixture-provenance.json").write_text(json.dumps({
            "chutneyRevision": CHUTNEY_REVISION, "authorities": 4, "guardRelays": 20,
            "exitRelays": 2, "nativeClients": 1, "vanguards": "full", "synthetic": True,
            "torVersion": subprocess.check_output([os.environ["TOR_BIN"], "--version"], text=True).strip(),
        }, indent=2) + "\n")
    finally:
        stop_child(driver)
        stop_child(gateway)
        if log_handle is not None:
            log_handle.close()
        # Keep bounded synthetic diagnostics, never generated secret key files.
        if gateway_log.exists():
            (artifact / "gateway-synthetic.log").write_text(gateway_log.read_text()[-65536:])
        for node in network.nodes:
            for name in ["notice.log", "info.log"]:
                log = node.dir / name
                if log.is_file():
                    (artifact / f"{node.nick}-{name}").write_text(log.read_text()[-4096:])
        for reserved in reservations:
            reserved.close()
        network.stop()
