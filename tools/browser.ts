// Generated with the original Rust registry. Do not edit the emitted module.
import {
  createCmsgClient, CmsgError, type BrowserConfiguration, type Output,
  type VaultBridgeConfiguration, type VaultHostConfiguration,
  type VaultBridgeRequest, type VaultBridgeReply,
} from './client.js';
export type {BrowserConfiguration, VaultBridgeConfiguration, VaultHostConfiguration} from './client.js';
export const bridgeProtocol = __BRIDGE_PROTOCOL__ as const;
type Code = Extract<Output, {status: 'error'}>['error'];
const failure = (error: Code): Output => ({status: 'error', error});

/** Partial non-custody page runtime; the member PWA uses createVaultClient. */
export async function createBrowserClient(configuration: BrowserConfiguration) {
  const {default: init, BrowserRuntime} = await import('./wasm/cmsg.js');
  await init();
  const runtime = new BrowserRuntime(JSON.stringify(configuration));
  return createCmsgClient(
    async request => JSON.parse(await runtime.invoke(JSON.stringify(request))) as Output,
    {async dispose() { try { await runtime.dispose(); } finally { runtime.free(); } }},
  );
}

/** Only the isolated vault frame instantiates custody Wasm. */
export async function startVaultHost(configuration: VaultHostConfiguration) {
  const {default: init, VaultHost} = await import('./wasm/cmsg.js');
  await init();
  const host = new VaultHost(JSON.stringify(configuration));
  let disposal: Promise<void> | undefined;
  return {dispose(): Promise<void> {
    disposal ??= host.dispose().finally(() => host.free());
    return disposal;
  }};
}

/** UI-only transport: no Wasm, authenticator, bearer or custody is instantiated here. */
export async function createVaultClient(configuration: VaultBridgeConfiguration) {
  const {member_origin: member, vault_origin: vault, vault_url: page, timeout_millis: timeout} = configuration;
  if (window.parent !== window || location.origin !== member || !Number.isInteger(timeout) || timeout <= 0 || timeout > 0xffffffff) {
    throw new CmsgError('unauthorized');
  }
  let memberURL: URL, vaultURL: URL, pageURL: URL;
  try { memberURL = new URL(member); vaultURL = new URL(vault); pageURL = new URL(page); }
  catch { throw new CmsgError('invalid_request'); }
  if (memberURL.origin !== member || vaultURL.origin !== vault || memberURL.protocol !== 'https:'
      || vaultURL.protocol !== 'https:' || vaultURL.hostname !== `vault.${memberURL.hostname}`
      || memberURL.port !== vaultURL.port || pageURL.origin !== vault || pageURL.username
      || pageURL.password || pageURL.search || pageURL.hash) throw new CmsgError('unauthorized');
  if (!document.body) throw new CmsgError('unavailable');
  const frame = document.createElement('iframe');
  frame.title = 'Account security';
  frame.setAttribute('data-cmsg-vault', '');
  frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox');
  frame.allow = "publickey-credentials-get 'none'; publickey-credentials-create 'none'";
  frame.referrerPolicy = 'no-referrer';
  const encoder = new TextEncoder();
  let port: MessagePort | undefined;
  let sequence = 0, connected = false, closing = false;
  let closeId: number | undefined;
  const pending = new Map<number, {resolve(value: Output): void; timer: ReturnType<typeof setTimeout>}>();
  let readyResolve!: () => void, readyReject!: (reason: CmsgError) => void;
  const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  let closeResolve!: () => void, closeReject!: (reason: CmsgError) => void;
  const done = new Promise<void>((resolve, reject) => { closeResolve = resolve; closeReject = reject; });
  // An owner can close independently before the shell explicitly disposes.
  void done.catch(() => {});
  let closeTimer: ReturnType<typeof setTimeout> | undefined;
  const next = () => { if (sequence === 0xffffffff) throw new CmsgError('capacity'); return ++sequence; };
  function post(request: VaultBridgeRequest) { port!.postMessage(JSON.stringify(request)); }
  function cleanup() {
    removeEventListener('message', hello);
    removeEventListener('pagehide', leaving);
    frame.removeEventListener('load', loaded);
    clearTimeout(readyTimer); clearTimeout(closeTimer);
    if (port) { port.onmessage = null; port.onmessageerror = null; port.close(); }
  }
  function beginClose() {
    closing = true;
    if (closeId !== undefined) return;
    if (!port) { readyReject(new CmsgError('unavailable')); closeResolve(); cleanup(); return; }
    try { closeId = next(); post({kind: 'close', id: closeId}); }
    catch { closeReject(new CmsgError('reconcile')); }
    closeTimer = setTimeout(() => { closeReject(new CmsgError('reconcile')); cleanup(); }, timeout);
  }
  function fail(code: Code) {
    closing = true;
    clearTimeout(readyTimer);
    readyReject(new CmsgError(code));
    for (const {resolve, timer} of pending.values()) { clearTimeout(timer); resolve(failure('reconcile')); }
    pending.clear();
    // Never remove the custody frame or retry an unknown operation.
    beginClose();
  }
  function receive(event: MessageEvent) {
    if (!event.isTrusted || event.ports.length || typeof event.data !== 'string'
        || encoder.encode(event.data).byteLength > bridgeProtocol.maximum_reply_bytes) { fail('reconcile'); return; }
    let reply: VaultBridgeReply;
    try { reply = JSON.parse(event.data) as VaultBridgeReply; } catch { fail('reconcile'); return; }
    if (reply.kind === 'ready' && !connected && !closing) {
      connected = true; clearTimeout(readyTimer); readyResolve();
    } else if (reply.kind === 'output' && connected) {
      const waiter = pending.get(reply.id);
      if (!waiter) { if (!closing) fail('reconcile'); return; }
      if (!reply.output || (reply.output.status !== 'ok' && reply.output.status !== 'error')) { fail('reconcile'); return; }
      if (typeof reply.challenge !== 'string' || !/^[0-9a-f]{32}$/.test(reply.challenge)) { fail('reconcile'); return; }
      try { post({kind: 'ack', id: reply.id, challenge: reply.challenge}); } catch { fail('reconcile'); return; }
      pending.delete(reply.id); clearTimeout(waiter.timer); waiter.resolve(reply.output);
    } else if (reply.kind === 'closed') {
      const valid = closeId !== undefined && reply.id === closeId && pending.size === 0;
      if (!valid) fail('reconcile');
      if (valid && reply.error == null) closeResolve(); else closeReject(new CmsgError('reconcile'));
      closing = true; connected = false; cleanup();
      // Only the actual owner acknowledgement proves its admitted work drained.
      if (valid && reply.error == null) frame.remove();
    } else fail('reconcile');
  }
  function hello(event: MessageEvent) {
    if (event.data !== bridgeProtocol.connect) return;
    if (!event.isTrusted || event.origin !== vault || event.source !== frame.contentWindow || event.ports.length !== 1 || port || closing) {
      for (const unwanted of event.ports) unwanted.close(); return;
    }
    [port] = event.ports;
    port.onmessage = receive; port.onmessageerror = () => fail('reconcile'); port.start();
  }
  let initialLoad = false;
  function loaded() {
    if (initialLoad) { fail('reconcile'); return; }
    initialLoad = true;
    if (!closing) frame.contentWindow?.postMessage(bridgeProtocol.ready, vault);
  }
  function leaving() { fail('reconcile'); }
  const readyTimer = setTimeout(() => { fail('unavailable'); }, timeout);
  addEventListener('message', hello);
  addEventListener('pagehide', leaving, {once: true});
  frame.addEventListener('load', loaded);
  frame.src = page;
  try { document.body.append(frame); }
  catch { fail('unavailable'); }
  await ready;
  return createCmsgClient(request => {
    if (!connected || closing) return Promise.resolve(failure('unavailable'));
    const bytes = JSON.stringify(request);
    if (encoder.encode(bytes).byteLength > bridgeProtocol.maximum_body_bytes || pending.size >= bridgeProtocol.maximum_pending) {
      return Promise.resolve(failure('capacity'));
    }
    return new Promise<Output>(resolve => {
      let id: number;
      try { id = next(); } catch { resolve(failure('capacity')); return; }
      const timer = setTimeout(() => fail('reconcile'), timeout);
      pending.set(id, {resolve, timer});
      try { post({kind: 'invoke', id, request: bytes}); } catch { fail('reconcile'); }
    });
  }, {dispose() { beginClose(); return done; }});
}
