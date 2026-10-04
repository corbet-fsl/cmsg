#!/usr/bin/env python3
"""Execute the generated module and actual Wasm owner in the HTTPS member page."""
from contextlib import ExitStack
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import os
import shutil
from pathlib import Path
import threading

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait


class Static(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        paths = {
            "/__vault-frame-fixture.html": ("text/html", "vault-frame-fixture.html"),
            "/__vault-close-mismatch.html": ("text/html", "vault-frame-fixture.html"),
            "/__vault-close-pending.html": ("text/html", "vault-frame-fixture.html"),
            "/__bridge-vectors.js": ("text/javascript", "bridge-browser.mjs"),
        }
        if self.path == "/__redirect-foreign":
            self.send_response(302)
            self.send_header("Location", "https://wallet.example.test/__member-fixture.html")
            self.end_headers()
        elif self.path == "/__member-fixture.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<!doctype html><title>Member UI transport fixture</title><body>')
        elif self.path in paths:
            kind, name = paths[self.path]
            data = Path(__file__).with_name(name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        else:
            super().do_GET()


def main():
    spec = importlib.util.spec_from_file_location(
        "fixture_browser", Path(__file__).with_name("fixture-browser.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    with ExitStack() as cleanup:
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(
            Static, directory=str(Path("generated/runtime").resolve())))
        cleanup.callback(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cleanup.callback(server.shutdown)
        origin = "https://alpha.example.test"
        options = webdriver.ChromeOptions()
        for argument in ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage"]:
            options.add_argument(argument)
        for argument in cleanup.enter_context(fixture.proxy(
                os.environ["CMSG_FOYER_FIXTURE"],
                f"http://127.0.0.1:{server.server_port}", origin)):
            options.add_argument(argument)
        chromedriver = shutil.which("chromedriver")
        if chromedriver is None:
            raise RuntimeError("qualified browser environment lacks chromedriver")
        driver = webdriver.Chrome(service=Service(chromedriver), options=options)
        cleanup.callback(driver.quit)
        driver.set_page_load_timeout(60)
        driver.set_script_timeout(60)
        driver.get(origin)
        result = driver.execute_async_script("""
            const done = arguments[0];
            (async () => {
                const {createBrowserClient} = await import('/browser.js');
                const fixture = await (await fetch('/__fixture')).json();
                const client = await createBrowserClient({
                    community: 'alpha', origin: window.location.origin, role: 'member',
                    primary: 'community', services: [{scope: 'community',
                        base: fixture.member.base, host: fixture.member.host}],
                });
                const status = await client.call('runtime.status', {});
                if (status.preload !== 'unavailable') throw new Error('readiness');
                const login = await client.invoke('login.start', {});
                if (login.status !== 'error' || login.error !== 'unavailable') throw new Error('custody');
                const events = [];
                const stop = client.subscribe(event => events.push(event.event));
                client.subscribe(() => { throw new Error('synthetic observer'); });
                const revoked = await client.call('client.revoke', {});
                if (!revoked.revoked || events.join(',') !== 'client_revoked') throw new Error('event');
                stop();
                await client.dispose();
                await client.dispose();
                const closed = await client.invoke('runtime.status', {});
                if (closed.status !== 'error' || closed.error !== 'unavailable') throw new Error('disposal');
                done(true);
            })().catch(() => done(false));
        """)
        if result is not True:
            raise RuntimeError("generated browser runtime conformance failed")
        for entry in ["member", "raw", "foreign", "wrong_source", "redirect", "top_rejected", "unread", "forged_ack", "stalled", "close_mismatch", "close_pending"]:
            origin = "https://wallet.example.test" if entry == "foreign" else "https://alpha.example.test"
            page = origin + "/__member-fixture.html"
            if entry == "top_rejected":
                page = "https://vault.alpha.example.test/__vault-frame-fixture.html"
            driver.get(page)
            if entry == "top_rejected":
                WebDriverWait(driver, 15).until(lambda browser: browser.execute_script("return !!document.body.dataset.owner"))
            result = driver.execute_async_script("""
                const [entry, done] = arguments;
                import('/__bridge-vectors.js').then(module => module[entry]())
                    .then(() => done(true)).catch(() => done(false));
            """, entry)
            if result is not True:
                raise RuntimeError("actual isolated Vault bridge conformance failed")
        print("Generated browser module passed actual HTTPS/Wasm lifecycle conformance.")


if __name__ == "__main__":
    main()
