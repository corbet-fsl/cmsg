"""Run one check with a bounded real owner service; retain no bearer artifacts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

if len(sys.argv) < 3:
    raise SystemExit("Usage: with-foyer-fixture.py fixture-binary command [args...]")
with tempfile.TemporaryDirectory(prefix="cmsg-foyer-") as directory:
    fixture_path = Path(directory) / "fixture.json"
    process = subprocess.Popen([sys.argv[1], str(fixture_path)], stdout=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 120
        while not fixture_path.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Real Foyer fixture did not become ready")
            time.sleep(0.1)
        fixture = json.loads(fixture_path.read_text())
        if not fixture.get("member") or not fixture.get("admin") or not fixture.get("root"):
            raise RuntimeError("Incomplete real Foyer fixture")
        environment = dict(os.environ, CMSG_FOYER_FIXTURE=str(fixture_path))
        result = subprocess.run(sys.argv[2:], env=environment, check=False)
        raise SystemExit(result.returncode)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
