"""Ephemeral HTTPS routing to real owner services; never alter authority or CORS."""
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time

PORTALS = ["alpha.example.test", "vault.alpha.example.test", "wallet.example.test",
           "admin.alpha.example.test", "admin.root.example.test"]
APIS = ["api.alpha.example.test", "api.admin.alpha.example.test", "api.admin.root.example.test"]


def loopback(value):
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", value):
        raise ValueError("fixture backend must be real literal loopback")
    return value


@contextmanager
def proxy(fixture_path, runner, origin):
    if origin not in ["https://" + host for host in PORTALS]:
        raise ValueError("unexpected browser portal")
    fixture = json.loads(Path(fixture_path).read_text())
    wallet = loopback(fixture["global"]["base"])
    community = loopback(fixture["member"]["base"])
    faults = loopback(fixture["faults"][0]["base"])
    loopback(runner)
    with tempfile.TemporaryDirectory(prefix="cmsg-browser-") as directory:
        root = Path(directory)
        certificate, key = root / "certificate.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=wallet.example.test",
                        "-addext", "subjectAltName=" + ",".join("DNS:" + host for host in PORTALS + APIS),
                        "-keyout", str(key), "-out", str(certificate)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in ["global", "member", "vault", "admin", "root", "global_root"]:
            fixture[name]["base"] = "https://" + fixture[name]["host"]
        fixture["global_root"]["base"] += ":4443"
        for row in fixture["faults"]:
            row["base"] = "https://wallet.example.test"
        private_fixture = root / "fixture.json"
        private_fixture.write_text(json.dumps(fixture))
        private_fixture.chmod(0o600)
        blocks = ["{\n admin off\n auto_https off\n}"]
        for host in PORTALS:
            routes = ""
            if host == "wallet.example.test":
                routes = f"""handle /v1/* {{
 reverse_proxy {faults}
}}
handle /__stats {{
 reverse_proxy {faults}
}}
handle /__release {{
 reverse_proxy {faults}
}}
"""
            blocks.append(f"""https://{host} {{
 bind 127.0.0.1
 tls {certificate} {key}
 {routes}
 handle /__fixture {{
  root * {root}
  rewrite * /fixture.json
  file_server
 }}
 handle {{
  reverse_proxy {runner}
 }}
}}""")
        for host, port, upstream in [(host, "", community) for host in APIS] + [
                ("api.admin.root.example.test", ":4443", wallet)]:
            blocks.append(f"""https://{host}{port} {{
 bind 127.0.0.1
 tls {certificate} {key}
 reverse_proxy {upstream} {{
  header_up Host {host}
 }}
}}""")
        config = root / "Caddyfile"
        config.write_text("\n".join(blocks))
        process = subprocess.Popen(["caddy", "run", "--config", str(config), "--adapter", "caddyfile"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            context = ssl.create_default_context(cafile=str(certificate))
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", 443), timeout=1) as sock:
                        with context.wrap_socket(sock, server_hostname="wallet.example.test"):
                            break
                except (OSError, ssl.SSLError):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("ephemeral fixture TLS did not start")
                    time.sleep(0.1)
            pem = subprocess.check_output(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"])
            der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                                 input=pem, stdout=subprocess.PIPE, check=True).stdout
            spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
            yield ["--no-proxy-server", "--host-resolver-rules=" + ", ".join(
                "MAP " + host + " 127.0.0.1" for host in PORTALS + APIS),
                "--ignore-certificate-errors-spki-list=" + spki]
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
