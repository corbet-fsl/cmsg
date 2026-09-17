"""Bounded cleanup for the disposable sessions created by CI Tor fixtures."""
import os
import signal
import subprocess
import time


def poll_child(child):
    """Observe exit without releasing the owned process-group leader's PID."""
    if child.returncode is not None:
        raise RuntimeError("fixture group leader was already reaped")
    state = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if state is None:
        return None
    return state.si_status if state.si_code == os.CLD_EXITED else -state.si_status


def wait_child(child, timeout):
    deadline = time.monotonic() + timeout
    while True:
        result = poll_child(child)
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(child.args, timeout)
        time.sleep(0.05)


def stop_child(child):
    if child is None:
        return
    # start_new_session=True makes the owned child's PID its process group.
    # Its descendants may survive even if the group leader already exited.
    # All callers retain that leader unreaped through poll_child/wait_child.
    # Never signal a stale numeric PGID after ownership has been released.
    if child.returncode is not None:
        return
    try:
        poll_child(child)
    except ChildProcessError:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        child.wait()
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            child.wait()
            return
        time.sleep(0.05)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise RuntimeError("owned fixture process did not stop") from None
