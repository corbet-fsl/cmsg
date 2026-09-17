"""Run on CI only: python3 browser/upstream/runtime-process.test.py."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from runtime_process import stop_child, wait_child


def runnable(pid):
    try:
        # A terminated orphan can remain a zombie until the runner's init reaps
        # it; the regression requires it cannot execute or retain live sockets.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


class ProcessCleanup(unittest.TestCase):
    def test_descendant_stops_after_its_group_leader_exits(self):
        source = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready',flush=True); time.sleep(60)"
        leader_source = (
            "import subprocess,sys; "
            f"p=subprocess.Popen([sys.executable,'-c',{source!r}],stdout=subprocess.PIPE,text=True); "
            "assert p.stdout.readline().strip()=='ready'; print(p.pid,flush=True)"
        )
        leader = subprocess.Popen([sys.executable, "-c", leader_source],
                                  stdout=subprocess.PIPE, text=True, start_new_session=True)
        descendant = None
        try:
            descendant = int(leader.stdout.readline().strip())
            self.assertEqual(wait_child(leader, timeout=5), 0)
            self.assertTrue(runnable(descendant))
            stop_child(leader)
            deadline = time.monotonic() + 2
            while runnable(descendant) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(runnable(descendant))
            # Idempotence also covers ESRCH after a normal process exit.
            stop_child(leader)
        finally:
            if descendant is not None and runnable(descendant):
                os.kill(descendant, signal.SIGKILL)
            stop_child(leader)
            leader.stdout.close()

    def test_reaped_leader_never_authorizes_signaling_a_reused_group_id(self):
        leader = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
        self.assertEqual(leader.wait(timeout=5), 0)
        with patch("runtime_process.os.killpg") as kill_group:
            stop_child(leader)
            kill_group.assert_not_called()


if __name__ == "__main__":
    unittest.main()
