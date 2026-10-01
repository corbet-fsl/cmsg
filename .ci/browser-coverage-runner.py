"""Run upstream browser tests and wait for its actual coverage upload before exit."""
import os
import queue
import re
import subprocess
import sys
import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service


def main():
    env = dict(os.environ, NO_HEADLESS="1", WASM_BINDGEN_TEST_ADDRESS="127.0.0.1:0")
    process = subprocess.Popen(
        ["wasm-bindgen-test-runner", *sys.argv[1:]], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    output = queue.Queue()

    def collect():
        for line in process.stdout:
            output.put(line)

    threading.Thread(target=collect, daemon=True).start()
    driver = None
    try:
        deadline = time.monotonic() + 120
        address = None
        while time.monotonic() < deadline and address is None:
            if process.poll() is not None and output.empty():
                raise RuntimeError("upstream test server exited before browser startup")
            try:
                line = output.get(timeout=0.2)
            except queue.Empty:
                continue
            print(line, end="", flush=True)
            match = re.search(r"http://127\.0\.0\.1:\d+", line)
            if match:
                address = match.group()
        if address is None:
            raise RuntimeError("upstream test server startup timed out")
        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
        driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)
        driver.set_page_load_timeout(120)
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": """
            window.__coverageLog = [];
            for (const name of ['log', 'error']) {
                const original = console[name].bind(console);
                console[name] = (...args) => {
                    window.__coverageLog.push(args.map(String).join(' '));
                    original(...args);
                };
            }
            window.addEventListener('unhandledrejection', event => {
                window.__coverageError = String(event.reason);
            });
            const fetchOriginal = window.fetch.bind(window);
            window.fetch = async (...args) => {
                const response = await fetchOriginal(...args);
                if (String(args[0]).endsWith('/__wasm_bindgen/coverage')) {
                    if (!response.ok || !args[1]?.body?.byteLength) {
                        window.__coverageError = 'Coverage upload failed or was empty';
                    } else {
                        window.__coverageSaved = true;
                    }
                }
                return response;
            };
        """})
        driver.get(address)
        deadline = time.monotonic() + 120
        state = {}
        while time.monotonic() < deadline:
            state = driver.execute_script("""
                const text = (document.getElementById('output')?.textContent || '')
                    + '\\n' + window.__coverageLog.join('\\n');
                return {text, saved: window.__coverageSaved === true,
                        error: window.__coverageError || null};
            """)
            if state["error"] or "test result: FAILED" in state["text"]:
                raise RuntimeError(state["error"] or "upstream browser tests failed")
            if re.search(r"test result: ok\. [1-9][0-9]* passed", state["text"]):
                driver.set_script_timeout(30)
                captured = driver.execute_async_script("""
                    const done = arguments[0];
                    (async () => {
                        // Reuse the exact module URL loaded by upstream run.js; do not initialize a second instance.
                        const runtime = await import('./wasm-bindgen-test');
                        const bytes = runtime.__owned_test_cov_dump();
                        if (!bytes.byteLength) throw new Error('Empty actual profiling data');
                        const result = await fetch('/__wasm_bindgen/coverage', {
                            method: 'POST',
                            headers: {'Module-Signature': runtime.__owned_test_module_signature().toString()},
                            body: bytes
                        });
                        if (!result.ok) throw new Error('Upstream profile-file handler refused data');
                        done({bytes: bytes.byteLength});
                    })().catch(error => done({error: String(error.stack || error)}));
                """)
                if captured.get("error") or not captured.get("bytes"):
                    raise RuntimeError(captured.get("error", "profiling capture failed"))
                print(state["text"], flush=True)
                print("Saved actual profiling bytes:", captured["bytes"], flush=True)
                return
            time.sleep(0.1)
        print(state.get("text", ""), flush=True)
        raise RuntimeError("browser tests did not complete and upload coverage within 120 seconds")
    finally:
        if driver is not None:
            for entry in driver.get_log("browser"):
                if entry["level"] == "SEVERE":
                    print(entry["message"], file=sys.stderr)
            driver.quit()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()
