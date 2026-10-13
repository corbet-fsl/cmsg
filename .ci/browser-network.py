"""Run the unchanged HTTPS fixture on isolated loopback, or refuse before building."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys


def main():
    # The parent masks termination only across process creation so cleanup owns
    # the child before a pending signal is handled. Restore normal child masks.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    if (os.environ.get('CI') != 'crow' or
            os.environ.get('CHECKS') != 'browser-package-candidates'):
        raise RuntimeError('exact candidate CI selector required')
    if len(sys.argv) < 7 or sys.argv[1] not in {'preflight', 'browser'}:
        raise RuntimeError('expected phase, parent namespaces, source hash, ip tool, optional command')
    phase, parent_user, parent_net, parent_pid, expected_source, ip, *command = sys.argv[1:]
    if bool(command) != (phase == 'browser'):
        raise RuntimeError('unexpected namespace command')
    report = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    receipt = {'phase': phase, 'status': 'failed', 'parent_user_namespace': parent_user,
               'parent_network_namespace': parent_net, 'parent_pid_namespace': parent_pid,
               'uid': os.geteuid(), 'pid': os.getpid()}
    try:
        source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        receipt['wrapper_sha256'] = source
        if source != expected_source:
            raise RuntimeError('namespace wrapper source changed')
        current_user = os.readlink('/proc/self/ns/user')
        current_net = os.readlink('/proc/self/ns/net')
        current_pid = os.readlink('/proc/self/ns/pid')
        receipt.update(user_namespace=current_user, network_namespace=current_net,
                       pid_namespace=current_pid)
        if (os.geteuid() != 0 or os.getpid() != 1 or current_user == parent_user or
                current_net == parent_net or current_pid == parent_pid):
            raise RuntimeError('fresh mapped user/network namespaces and PID namespace init required')
        # This acts only after verifying isolation from the worker namespaces.
        subprocess.run([ip, 'link', 'set', 'lo', 'up'], check=True, timeout=10)
        links = json.loads(subprocess.check_output([ip, '-json', 'link', 'show'], timeout=10))
        if len(links) != 1 or links[0]['ifname'] != 'lo' or 'UP' not in links[0]['flags']:
            raise RuntimeError('isolated loopback-only network required')
        receipt['links'] = links
        with ExitStack() as sockets:
            for port in [443, 4443]:
                listener = sockets.enter_context(socket.socket())
                listener.bind(('127.0.0.1', port))
        receipt['ports'] = [443, 4443]
        receipt['status'] = 'ready'
    except Exception as error:
        receipt['error'] = str(error)
        raise
    finally:
        (report / f'network-{phase}.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if command:
        os.execvp(command[0], command)


if __name__ == '__main__':
    main()
