#!/usr/bin/env python3
"""Self-test of copy-foyer-fixture.py's door-source guarantee: the fixture's door owner and the production
client's door packages (`cvld-client`, or `cvld` in older graphs, or both) must come from exactly one source.
Runs the real script in a scratch directory against synthetic metadata. Usage: python3 -B .ci/test-copy-foyer-fixture.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "copy-foyer-fixture.py"
REV = "a" * 40
SOURCE = f"git+https://git.corbet.ch/corbet-fsl/cvld.git?branch=main#{REV}"
OTHER = f"git+https://git.corbet.ch/corbet-fsl/cvld.git?branch=main#{'b' * 40}"
REFUSAL = "Fixture and production client must use exactly the same door source"


def run(client_packages):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        owner = root / "owner"
        (owner / "tests/support").mkdir(parents=True)
        (owner / "tools").mkdir()
        (owner / ".ci").mkdir()
        for name in ["mod.rs", "resident.rs", "client_faults.rs", "active.rs", "self_ban.rs"]:
            (owner / "tests/support" / name).write_text("// fixture\n")
        (owner / "tools/g5-account-config.py").write_text("# tool\n")
        (owner / ".ci/check-shell.nix").write_text("{}\n")
        (owner / "Cargo.toml").write_text('[package]\nname = "cvld"\n')
        door = {"name": "cvld", "source": SOURCE, "manifest_path": str(owner / "Cargo.toml")}
        work = root / "work"
        work.mkdir()
        (work / "fixture-metadata.json").write_text(json.dumps({"packages": [door]}))
        runtime = [{"name": "cmsg", "source": None}] + [{"name": n, "source": s} for n, s in client_packages]
        (work / "runtime-metadata.json").write_text(json.dumps({"packages": runtime}))
        env = {k: v for k, v in os.environ.items() if k != "CHECKS"}
        result = subprocess.run([sys.executable, "-B", str(SCRIPT)], cwd=work, env=env, capture_output=True, text=True)
        return result.returncode, result.stderr


def main():
    cases = [
        ("the client half as cvld-client", [("cvld-client", SOURCE)], True),
        ("the client half as cvld (older graphs)", [("cvld", SOURCE)], True),
        ("both names from the door source", [("cvld", SOURCE), ("cvld-client", SOURCE)], True),
        ("no door client at all", [], False),
        ("cvld-client from another door revision", [("cvld-client", OTHER)], False),
        ("cvld from another door revision", [("cvld", OTHER)], False),
        ("both names, one from another revision", [("cvld", SOURCE), ("cvld-client", OTHER)], False),
        ("one name twice", [("cvld-client", SOURCE), ("cvld-client", SOURCE)], False),
    ]
    failed = 0
    for label, packages, accepted in cases:
        code, stderr = run(packages)
        ok = code == 0 if accepted else (code != 0 and REFUSAL in stderr)
        print(f"{'ok' if ok else 'FAIL'}: {label}")
        if not ok:
            failed += 1
            print(stderr, file=sys.stderr)
    if failed:
        sys.exit(f"test-copy-foyer-fixture: {failed} of {len(cases)} cases failed")
    print(f"test-copy-foyer-fixture: {len(cases)} cases passed")


if __name__ == "__main__":
    main()
