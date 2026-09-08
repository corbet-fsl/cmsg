"""Use upstream Chutney to exercise real Tor without public-network bootstrap.

Run only on a disposable runner. This is functional routing evidence, not an
anonymity benchmark or protection against an observer controlling every relay.
"""
import dataclasses
import os
import pathlib
import subprocess
import tempfile
import time
from chutney import TorNet
from chutney.TorNet import NodeConfig

with tempfile.TemporaryDirectory(prefix="cmsg-isolated-tor-") as tmp:
    network = TorNet.Network()
    base = NodeConfig(controlling_pid=os.getpid())
    authorities = dataclasses.replace(base, tag="a", authority=True, relay=True)
    relays = dataclasses.replace(base, tag="r", relay=True)
    client = dataclasses.replace(base, tag="c", client=True)
    service = dataclasses.replace(base, tag="h", hs=True)
    network.addNodes(authorities.getN(4) + relays.getN(3) + client.getN(1) + service.getN(1))
    network.init(data_dir=pathlib.Path(tmp))
    try:
        network.configure(config_phase=1)
        network.start(launch_phase=1)
        network.wait_for_bootstrap(launch_phase=1, limit_secs=300)
        nodes = list(network.nodes)
        client_node, service_node = nodes[-2:]
        client_address, client_port = next(iter(client_node.socksport_endpoints()))
        onion = service_node.hs_hostname.unwrap()
        target = f"{service_node.hs_target_address.unwrap()}:{service_node.hs_targetport.unwrap()}"
        for _ in range(4):
            result = subprocess.run([
                "target/debug/examples/tor_roundtrip",
                f"{client_address}:{client_port}", onion, target,
                str(service_node.hs_virtport.unwrap()),
            ], timeout=65, capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout.strip())
                break
            time.sleep(10)
        else:
            raise RuntimeError("isolated Tor onion probe failed")
    finally:
        network.stop()
