// Run the real browser Arti/onion fixture using generated, pinned artifacts.
// No npm packages, browser downloads, persistent browser profiles or services.
import { createServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
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
let nativeClosed;
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
  nativeClosed = new Promise(resolve => nativeChild.once('close', resolve));
  let output = '';
  let nativeError = '';
  nativeChild.stdout.on('data', bytes => { output = (output + bytes.toString()).slice(-4096); });
  nativeChild.stderr.on('data', bytes => { nativeError = (nativeError + bytes.toString()).slice(-4096); });
  const timer = setTimeout(() => nativeChild.kill('SIGKILL'), 120_000);
  try {
    const [code] = await once(nativeChild, 'close');
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
let canaryConnections = 0;
const canary = createTcpServer(socket => {
  canaryConnections += 1;
  socket.destroy();
});
canary.listen(0, '127.0.0.1');
await once(canary, 'listening');
const canaryTarget = `127.0.0.1:${canary.address().port}`;
const mime = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/fixture.json') {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
      response.end(JSON.stringify({ ...fixture, nonRelayCanary: canaryTarget })); return;
    }
    if (pathname === '/__canary') {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      response.end(JSON.stringify({ connections: canaryConnections })); return;
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
let browserClosed;
let socket;
let stderr = '';
let browserMetadata;
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
  browserClosed = new Promise(resolve => browser.once('close', resolve));
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
  browserMetadata = metadata;
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
  if (canaryConnections !== 0) throw new Error('Non-relay canary received a TCP connection');
  const evidence = { source: process.env.CI_COMMIT_SHA, browser: metadata.Browser,
    runtime: process.version, contract: result.result.value, nonRelayCanaryConnections: canaryConnections,
    unexpectedExternalRequests: forbiddenRequests };
  await writeFile(artifact, JSON.stringify(evidence, null, 2) + '\n');
  process.stdout.write(JSON.stringify(evidence) + '\n');
} catch (error) {
  let progress = null;
  let traceTimer;
  try {
    if (socket?.readyState === WebSocket.OPEN) {
      const result = await Promise.race([
        command('Runtime.evaluate', { expression: 'globalThis.__cmsgTorRuntime ?? null', returnByValue: true }),
        new Promise((_, reject) => { traceTimer = setTimeout(() => reject(new Error('diagnostic deadline')), 2000); }),
      ]);
      progress = result.result?.value ?? null;
    }
  } catch {} finally { clearTimeout(traceTimer); }
  await writeFile(artifact + '.failure.json', JSON.stringify({
    source: process.env.CI_COMMIT_SHA, testNetworkOnly: true,
    browser: browserMetadata?.Browser, runtime: process.version, progress,
    nonRelayCanaryConnections: canaryConnections,
    failure: String(error).slice(0, 8192), chromiumStderr: stderr.slice(-8000),
    unexpectedExternalRequests: forbiddenRequests.slice(0, 16).map(url => url.slice(0, 512)),
  }, null, 2) + '\n');
  throw error;
} finally {
  clearTimeout(deadline);
  if (nativeChild?.pid && nativeChild.exitCode === null && nativeChild.signalCode === null) {
    nativeChild.kill('SIGKILL');
  }
  await nativeClosed;
  socket?.close();
  if (browser?.pid && browser.exitCode === null && browser.signalCode === null) {
    browser.kill('SIGTERM');
    const force = setTimeout(() => browser.kill('SIGKILL'), 5000);
    await browserClosed;
    clearTimeout(force);
  }
  await browserClosed;
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  await new Promise(resolve => canary.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
