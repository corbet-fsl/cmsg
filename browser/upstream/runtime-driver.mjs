// Run the real browser Arti/onion fixture using generated, pinned artifacts.
// No npm packages, browser downloads, persistent browser profiles or services.
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { resolve, join, extname, sep } from 'node:path';

const root = resolve(process.cwd());
const artifact = process.env.BROWSER_EVIDENCE;
const binary = process.env.BROWSER_BIN;
const torDist = resolve(process.env.TORJS_DIST ?? '');
const fixturePath = process.env.TOR_FIXTURE_JSON;
const nativeBinary = process.env.TOR_NATIVE_PEER_BIN;
const nativeSocks = process.env.TOR_NATIVE_SOCKS;
if (!process.env.TORJS_DIST || !fixturePath || !nativeBinary || !nativeSocks) throw new Error('runtime fixture paths required');
let nativeStarted = false;
let nativeChild;
async function startNative(request, response) {
  if (nativeStarted) { response.writeHead(409).end(); return; }
  nativeStarted = true;
  let body = '';
  for await (const chunk of request) {
    body += chunk.toString();
    if (body.length > 1024) { response.writeHead(413).end(); return; }
  }
  const input = JSON.parse(body);
  if (!/^[a-z2-7]{56}\.onion$/.test(input.host) || input.port !== 80) {
    response.writeHead(400).end(); return;
  }
  nativeChild = spawn(nativeBinary, [nativeSocks, input.host, String(input.port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  let nativeError = '';
  nativeChild.stdout.on('data', bytes => { output = (output + bytes.toString()).slice(-4096); });
  nativeChild.stderr.on('data', bytes => { nativeError = (nativeError + bytes.toString()).slice(-4096); });
  const timer = setTimeout(() => nativeChild.kill('SIGKILL'), 120_000);
  try {
    const [code] = await once(nativeChild, 'exit');
    if (code !== 0) {
      await writeFile(artifact + '.native-error.txt', nativeError);
      response.writeHead(500).end('native fixture failed'); return;
    }
    const result = JSON.parse(output.trim());
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify(result));
  } finally { clearTimeout(timer); }
}
if (!binary || !artifact) throw new Error('BROWSER_BIN and BROWSER_EVIDENCE are required');
const mime = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/fixture.json') {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      response.end(await readFile(fixturePath)); return;
    }
    if (pathname === '/__native-peer' && request.method === 'POST') {
      await startNative(request, response); return;
    }
    if (pathname.startsWith('/torjs/')) {
      const file = resolve(torDist, '.' + decodeURIComponent(pathname.slice('/torjs'.length)));
      if (!file.startsWith(torDist + sep) || !mime[extname(file)]) { response.writeHead(404).end(); return; }
      response.writeHead(200, { 'content-type': mime[extname(file)], 'cache-control': 'no-store' });
      response.end(await readFile(file)); return;
    }
    if (pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      response.end('<!doctype html><meta charset="utf-8"><title>cmsg browser contract</title>');
      return;
    }
    const file = resolve(root, '.' + decodeURIComponent(pathname));
    if (!file.startsWith(join(root, 'browser') + sep) || !mime[extname(file)]) {
      response.writeHead(404).end(); return;
    }
    const bytes = await readFile(file);
    response.writeHead(200, { 'Content-Type': mime[extname(file)], 'Cache-Control': 'no-store' });
    response.end(bytes);
  } catch { response.writeHead(404).end(); }
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = `http://127.0.0.1:${server.address().port}`;
const profile = await mkdtemp(join(tmpdir(), 'cmsg-browser-test-'));
let browser;
let socket;
let stderr = '';
let nextId = 1;
const pending = new Map();
const forbiddenRequests = [];
const loaded = new Set();
let deadline;

async function command(method, params = {}) {
  const id = nextId++;
  const result = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  socket.send(JSON.stringify({ id, method, params }));
  return result;
}

try {
  browser = spawn(binary, [
    '--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--disable-background-networking', '--disable-component-update', '--no-first-run',
    '--no-default-browser-check', '--disable-extensions', '--remote-debugging-address=127.0.0.1',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, `--disk-cache-dir=${join(profile, 'cache')}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let launchError;
  browser.on('error', error => { launchError = error; });
  browser.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-8000); });
  let port;
  for (let attempt = 0; attempt < 300; attempt++) {
    if (launchError) throw launchError;
    if (browser.exitCode !== null) throw new Error(`Chromium exited: ${stderr}`);
    try { port = Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!port) throw new Error(`Chromium did not expose its test interface: ${stderr}`);
  const metadata = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const page = targets.find(target => target.type === 'page');
  if (!page) throw new Error('Chromium has no test page');
  socket = new WebSocket(page.webSocketDebuggerUrl);
  await once(socket, 'open');
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const waiting = pending.get(message.id);
      if (waiting) {
        pending.delete(message.id);
        if (message.error) waiting.reject(new Error(JSON.stringify(message.error)));
        else waiting.resolve(message.result);
      }
    } else if (message.method === 'Page.lifecycleEvent' && message.params.name === 'load') {
      loaded.add(message.params.loaderId);
    } else if (message.method === 'Fetch.requestPaused') {
      const { requestId, request } = message.params;
      if (request.url.startsWith(origin + '/')) {
        command('Fetch.continueRequest', { requestId }).catch(() => {});
      } else {
        forbiddenRequests.push(request.url);
        command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }).catch(() => {});
      }
    }
  });
  await command('Page.enable');
  await command('Page.setLifecycleEventsEnabled', { enabled: true });
  await command('Runtime.enable');
  await command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const navigation = await command('Page.navigate', { url: origin });
  if (navigation.errorText || !navigation.loaderId) throw new Error('Browser navigation failed');
  for (let attempt = 0; attempt < 300 && !loaded.has(navigation.loaderId); attempt++) {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!loaded.has(navigation.loaderId)) throw new Error('Browser navigation deadline exceeded');
  // Evaluation waits for the current page's document before importing fixtures.
  const running = command('Runtime.evaluate', {
    expression: "(async () => { while (document.readyState === 'loading') await new Promise(r => setTimeout(r, 10)); return await (await import('/browser/upstream/runtime-contract.mjs')).runTorRuntimeContract(); })()",
    awaitPromise: true, returnByValue: true,
  });
  const result = await Promise.race([running, new Promise((_, reject) => {
    deadline = setTimeout(() => reject(new Error('Browser contract deadline exceeded')), 900_000);
  })]);
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  if (!result.result || !('value' in result.result)) throw new Error('Browser contract returned no evidence');
  if (forbiddenRequests.length) throw new Error(`Unexpected external requests: ${JSON.stringify(forbiddenRequests)}`);
  const evidence = { source: process.env.CI_COMMIT_SHA, browser: metadata.Browser,
    runtime: process.version, contract: result.result.value, unexpectedExternalRequests: forbiddenRequests };
  await writeFile(artifact, JSON.stringify(evidence, null, 2) + '\n');
  process.stdout.write(JSON.stringify(evidence) + '\n');
} finally {
  clearTimeout(deadline);
  if (nativeChild?.pid && nativeChild.exitCode === null) {
    const reaped = once(nativeChild, 'exit');
    nativeChild.kill('SIGKILL');
    await reaped;
  }
  socket?.close();
  if (browser?.pid && browser.exitCode === null) {
    const exited = once(browser, 'exit');
    browser.kill('SIGTERM');
    const force = setTimeout(() => browser.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(force);
  }
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
