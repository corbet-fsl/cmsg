"""Invoke only the exact resolved CTRN fixture and genuine built Tor journey.

This product test adapter installs nothing and creates no authority or transport.
The original fixture owns the disposable private Tor network and its cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

SCRIPT_SHA256 = "050e6bdb3248a14b2ca5bff51c19d8eb5472b79e5dd4ef8565ef37938039d932"


def inputs(root, metadata, artifacts):
    owners = [p for p in metadata["packages"] if p["name"] == "ctrn"]
    consumers = [p for p in metadata["packages"] if p["name"] == "cmsg"]
    if len(owners) != 1 or len(consumers) != 1:
        raise ValueError("expected exact original transport and consumer identities")
    owner, consumer = owners[0], consumers[0]
    if not re.fullmatch(r"git\+https://git\.corbet\.ch/corbet-foss/ctrn\.git\?branch=v01#[0-9a-f]{40}", owner["source"]):
        raise ValueError("unexpected original transport source")
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    locked = [p for p in lock["package"] if p["name"] == "ctrn"]
    if len(locked) != 1 or locked[0]["source"] != owner["source"] or locked[0]["version"] != owner["version"]:
        raise ValueError("transport source differs from actual retained lock")
    if Path(consumer["manifest_path"]).resolve() != root / "Cargo.toml":
        raise ValueError("consumer metadata does not describe this checkout")
    source = Path(owner["manifest_path"]).resolve().parent
    script = (source / ".ci/private-network.py").resolve()
    if not script.is_relative_to(source) or hashlib.sha256(script.read_bytes()).hexdigest() != SCRIPT_SHA256:
        raise ValueError("original private-network source changed or escaped")
    built = [a for a in artifacts if a.get("reason") == "compiler-artifact"
             and a.get("package_id") == consumer["id"]
             and a.get("target", {}).get("name") == "initial_tor"
             and a.get("target", {}).get("kind") == ["test"]
             and a.get("executable") and a.get("profile", {}).get("test") is True]
    if len(built) != 1:
        raise ValueError("expected one actual integration-test executable receipt")
    target = Path(metadata["target_directory"]).resolve()
    executable = Path(built[0]["executable"]).resolve()
    if not executable.is_relative_to(target) or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("compiled journey executable is absent or outside actual target")
    return owner["source"], script, target, executable


def run():
    root = Path.cwd().resolve()
    evidence = root / "evidence/native"
    metadata = json.loads((evidence / "tor-metadata.json").read_text())
    artifacts = [json.loads(line) for line in (evidence / "tor-build.jsonl").read_text().splitlines() if line]
    source, script, _, executable = inputs(root, metadata, artifacts)
    fixture_metadata = json.loads((root / "fixture-metadata.json").read_text())
    fixtures = [p for p in fixture_metadata["packages"] if p["name"] == "cmsg-foyer-fixture"]
    if len(fixtures) != 1 or Path(fixtures[0]["manifest_path"]).resolve() != root / "tests/fixture/Cargo.toml":
        raise ValueError("acceptance metadata does not describe the built original fixture")
    acceptance = Path(fixture_metadata["target_directory"]).resolve() / "debug/cmsg-acceptance-fixture"
    # These are the unchanged original CTRN native fixture paths. Their absence
    # is a prerequisite failure, never permission to bootstrap/install tools.
    tools = Path.home() / ".cache/ctrn-tools"
    python = tools / "venv/bin/python"
    tor = tools / "bin/tor"
    gencert = tools / "bin/tor-gencert"
    chutney = tools / "chutney"
    for path in (acceptance, python, tor, gencert):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f"required provisioned original fixture executable {path.name} is absent")
    if not (chutney / "lib/chutney").is_dir():
        raise ValueError("required provisioned original Chutney source is absent")
    environment = dict(os.environ, CHUTNEY_SOURCE=str(chutney), TOR_BIN=str(tor),
                       TOR_GENCERT_BIN=str(gencert), TOR_PROBE_BIN=str(executable),
                       TOR_ARTIFACT=str(evidence / "private-tor"), CMSG_ACCEPTANCE_FIXTURE=str(acceptance))
    receipt = {"transport_source": source, "private_network_sha256": SCRIPT_SHA256,
               "test_executable": str(executable), "test_executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
               "acceptance_executable_sha256": hashlib.sha256(acceptance.read_bytes()).hexdigest(),
               "qualification": "private Tor; original development passport fixture; normal root custody only"}
    (evidence / "tor-invocation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    # Original fixture has its own bounded network/probe deadlines and always
    # stops its disposable nodes. No wrapper timeout can bypass that cleanup.
    return subprocess.run([str(python), str(script)], env=environment, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (KeyError, OSError, ValueError) as error:
        raise SystemExit(f"Original Tor journey prerequisite refused: {error}") from None
