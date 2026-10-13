"""Bounded hosted Caddy TLS admission only; original owner tests remain unchanged."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time


def main():
    if os.environ.get('CI') != 'github-actions' or os.environ.get('CHECKS') != 'browser-package-candidates':
        raise RuntimeError('explicit hosted candidate selector required')
    with tempfile.TemporaryDirectory(prefix='cmsg-caddy-admission-') as directory:
        root = Path(directory)
        certificate, key = root / 'certificate.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=hosted-admission.invalid',
                        '-addext', 'subjectAltName=DNS:hosted-admission.invalid',
                        '-keyout', str(key), '-out', str(certificate)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        config = root / 'Caddyfile'
        config.write_text('{\n admin off\n auto_https off\n}\n' + '\n'.join(
            f'https://hosted-admission.invalid:{port} {{\n bind 127.0.0.1\n'
            f' tls {certificate} {key}\n respond "hosted-admission"\n}}' for port in [443, 4443]))
        process = subprocess.Popen(['caddy', 'run', '--config', str(config), '--adapter', 'caddyfile'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            context = ssl.create_default_context(cafile=str(certificate))
            deadline = time.monotonic() + 10
            for port in [443, 4443]:
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=1) as raw:
                            with context.wrap_socket(raw, server_hostname='hosted-admission.invalid') as tls:
                                tls.sendall(b'GET / HTTP/1.1\r\nHost: hosted-admission.invalid\r\nConnection: close\r\n\r\n')
                                data = b''
                                while len(data) < 4096:
                                    chunk = tls.recv(4096 - len(data))
                                    if not chunk:
                                        break
                                    data += chunk
                                if not data.startswith(b'HTTP/1.1 200 ') or b'hosted-admission' not in data:
                                    raise RuntimeError('Caddy admission response differs')
                        break
                    except (OSError, ssl.SSLError):
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('actual hosted TLS low-port admission refused')
                        time.sleep(0.1)
            print('Actual hosted Caddy TLS admission passed on443 and4443.')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    main()
