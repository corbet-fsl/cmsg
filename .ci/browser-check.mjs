// Execute only synthetic project fixtures in a preinstalled headless Chromium.
// No npm packages, browser downloads, persistent browser profiles or services.
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { resolve, join, extname, sep } from 'node:path';

const root = resolve(process.cwd());
const artifact = process.env.BROWSER_EVIDENCE;
const binary = process.env.BROWSER_BIN;
if (!binary || !artifact) throw new Error('BROWSER_BIN and BROWSER_EVIDENCE are required');
const profileModules = new Map();
let profileSource;
if (process.env.CFRM_SOURCE_ARCHIVE || process.env.CFRM_SOURCE_COMMIT || process.env.CFRM_SOURCE_SHA256) {
  const { CFRM_SOURCE_ARCHIVE: archivePath, CFRM_SOURCE_COMMIT: commit, CFRM_SOURCE_SHA256: expectedHash } = process.env;
  if (!archivePath || !/^[0-9a-f]{40}$/.test(commit ?? '') || !/^[0-9a-f]{64}$/.test(expectedHash ?? '')) {
    throw new Error('Profile composition requires an explicit cfrm archive, commit and checksum');
  }
  const archive = await readFile(archivePath);
  if (createHash('sha256').update(archive).digest('hex') !== expectedHash) throw new Error('cfrm archive checksum mismatch');
  const identified = spawnSync('git', ['get-tar-commit-id'], { input: archive, encoding: 'utf8' });
  if (identified.error || identified.status !== 0 || identified.stdout.trim() !== commit) throw new Error('cfrm archive commit mismatch');
  // Serve only these verified source modules. No repository directory, test
  // secrets, package installation, or external endpoint is exposed to the page.
  for (const name of ['index.js', 'publisher.js', 'access.js', 'envelope.js', 'keys.js', 'eligibility.js', 'crypto.js', 'discovery.js', 'tickets.js']) {
    const extracted = spawnSync('tar', ['--extract', '--to-stdout', '--file', '-', `browser/profiles/${name}`],
      { input: archive, maxBuffer: 2 * 1024 * 1024 });
    if (extracted.error || extracted.status !== 0 || !extracted.stdout.length) throw new Error('Missing pinned cfrm profile module');
    profileModules.set(`/cfrm-profiles/${name}`, extracted.stdout);
  }
  profileSource = { commit, archiveSha256: expectedHash };
}
const mime = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      response.end('<!doctype html><meta charset="utf-8"><title>cmsg browser contract</title><script type="importmap">{"imports":{"tor-js/wasm-file":"/browser/fixtures/tor-js.mjs"}}</script>');
      return;
    }
    if (profileModules.has(pathname)) {
      response.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' });
      response.end(profileModules.get(pathname)); return;
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
    expression: `(async () => { while (document.readyState === 'loading') await new Promise(r => setTimeout(r, 10)); return await (await import('/browser/contract.mjs')).runBrowserContract(${profileSource ? "{ profileApi: await import('/cfrm-profiles/index.js') }" : ''}); })()`,
    awaitPromise: true, returnByValue: true,
  });
  const result = await Promise.race([running, new Promise((_, reject) => {
    deadline = setTimeout(() => reject(new Error('Browser contract deadline exceeded')), 180_000);
  })]);
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  if (!result.result || !('value' in result.result)) throw new Error('Browser contract returned no evidence');
  if (forbiddenRequests.length) throw new Error(`Unexpected external requests: ${JSON.stringify(forbiddenRequests)}`);
  const evidence = { source: process.env.CI_COMMIT_SHA, browser: metadata.Browser,
    runtime: process.version, profileSource, contract: result.result.value, unexpectedExternalRequests: forbiddenRequests };
  await writeFile(artifact, JSON.stringify(evidence, null, 2) + '\n');
  process.stdout.write(JSON.stringify(evidence) + '\n');
} finally {
  clearTimeout(deadline);
  socket?.close();
  if (browser && browser.exitCode === null) {
    const exited = once(browser, 'close');
    browser.kill('SIGTERM');
    const force = setTimeout(() => browser.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(force);
  }
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  // Chromium's profile writers may finish just after the main process exits.
  // Retry only this owned temporary profile; persistent failure remains fatal.
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
