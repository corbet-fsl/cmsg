"""Run only synthetic clients; reap the process before deleting its state parent."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    target = Path(os.environ["CARGO_TARGET_DIR"])
    binary = target / "debug" / "cmsg-embedded-onion-experiment"
    # The verified CI source workspace is disk-backed and already task-owned.
    # The library's bounded runtime shutdown cannot prove every blocking task
    # stopped. Process reaping below precedes parent cleanup even on timeout.
    with tempfile.TemporaryDirectory(prefix="synthetic-onion-", dir=Path.cwd()) as parent:
        try:
            result = subprocess.run(
                [str(binary), "--run-public-network", "--state-parent", parent],
                timeout=630,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # subprocess.run kills and waits for the process before raising.
            print(json.dumps({"phase": "outer_deadline", "state": "failed"}), flush=True)
            return 1
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
