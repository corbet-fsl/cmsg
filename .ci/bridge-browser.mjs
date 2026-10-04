import {createVaultClient, bridgeProtocol} from '/browser.js';
const MEMBER = 'https://alpha.example.test';
const VAULT = 'https://vault.alpha.example.test';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function check(value, label) { if (!value) throw new Error(label); }
function next(port) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('missing owner response')), 10000);
    port.onmessage = event => { clearTimeout(timeout); resolve(JSON.parse(event.data)); };
    port.start();
  });
}
const PAGE = VAULT + '/__vault-frame-fixture.html';
async function boundPort(beforeReady) {
  const frame = document.createElement('iframe');
  frame.setAttribute('data-raw-vault', '');
  frame.src = PAGE;
  let received = 0;
  const connected = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('missing original channel')), 10000);
    function receive(event) {
      if (event.origin === VAULT && event.source === frame.contentWindow && event.data === bridgeProtocol.connect && event.ports.length === 1) {
        received++; removeEventListener('message', receive); clearTimeout(timeout); resolve(event.ports[0]);
      }
    }
    addEventListener('message', receive);
  });
  const loaded = new Promise(resolve => frame.addEventListener('load', resolve, {once: true}));
  document.body.append(frame); await loaded;
  if (beforeReady) { await beforeReady(frame); check(received === 0, 'wrong source Window accepted'); }
  frame.contentWindow.postMessage(bridgeProtocol.ready, VAULT);
  const port = await connected;
  check((await next(port)).kind === 'ready', 'missing owner acknowledgement');
  return port;
}
export async function member() {
  check(parent === window && location.origin === MEMBER, 'UI is not top-level');
  const config = {member_origin: MEMBER, vault_origin: VAULT, vault_url: PAGE, timeout_millis: 10000};
  for (const bad of [
    {...config, member_origin: 'https://wallet.example.test'},
    {...config, vault_origin: 'https://vault.other.example.test'},
    {...config, vault_origin: VAULT + '#capability'},
    {...config, timeout_millis: 0},
  ]) {
    let refused = false; try { await createVaultClient(bad); } catch { refused = true; }
    check(refused, 'wrong configured origin accepted');
  }
  const client = await createVaultClient(config);
  const status = await client.call('runtime.status', {});
  check(status.preload === 'unavailable', 'fabricated readiness');
  check((await client.invoke('login.start', {})).error === 'unavailable', 'fabricated login');
  const calls = Array.from({length: bridgeProtocol.maximum_pending}, () => client.invoke('runtime.status', {}));
  check((await client.invoke('runtime.status', {})).error === 'capacity', 'unbounded channel queue');
  check((await Promise.all(calls)).every(value => value.status === 'ok'), 'lost actual owner results');
  const events = []; client.subscribe(event => events.push(event.event));
  client.subscribe(() => { throw new Error('observer'); });
  const revoke = client.call('client.revoke', {});
  const disposed = client.dispose();
  check((await revoke).revoked && events.join(',') === 'client_revoked', 'lost admitted effect');
  await disposed; await client.dispose();
  check(!document.querySelector('[data-cmsg-vault]'), 'acknowledged drained frame retained');
  check((await client.invoke('runtime.status', {})).error === 'unavailable', 'closed client reused');
  check(!performance.getEntriesByType('resource').some(entry => entry.name.endsWith('.wasm')), 'UI instantiated custody Wasm');
}
async function invalid_close_retains_custody(page, withPending) {
  const client = await createVaultClient({member_origin: MEMBER, vault_origin: VAULT,
    vault_url: VAULT + page, timeout_millis: 10000});
  const frame = document.querySelector('[data-cmsg-vault]');
  check(frame?.isConnected, 'missing live custody frame');
  // The actual owner receives an invocation followed by close. Its response is
  // altered only at the wire boundary, never replaced by domain fixture logic.
  const pending = withPending ? client.invoke('runtime.status', {}) : null;
  const disposed = client.dispose().then(() => false, error => error.code === 'reconcile');
  if (pending) check((await pending).error === 'reconcile', 'pending effect lost its uncertainty');
  check(await disposed, 'unproven close was accepted');
  check(frame.isConnected, 'unproven close destroyed custody');
  check((await client.invoke('runtime.status', {})).error === 'unavailable', 'uncertain client reused');
}
export async function close_mismatch() {
  await invalid_close_retains_custody('/__vault-close-mismatch.html', false);
}
export async function close_pending() {
  await invalid_close_retains_custody('/__vault-close-pending.html', true);
}
export async function raw() {
  const port = await boundPort();
  let response = next(port);
  port.postMessage(JSON.stringify({kind: 'invoke', id: 1,
    request: '{"action":"runtime.status","version":1,"version":1,"body":{}}'}));
  check((await response).output.error === 'invalid_request', 'duplicate fields normalized');
  response = next(port);
  port.postMessage(JSON.stringify({kind: 'invoke', id: 1,
    request: '{"action":"client.revoke","version":1,"body":{}}'}));
  const closed = await response;
  check(closed.kind === 'closed' && closed.id === null, 'sequence replay accepted');
  port.close();
}
export async function foreign() {
  check(location.origin === 'https://wallet.example.test' && parent === window, 'missing foreign top-level document');
  const frame = document.createElement('iframe'); frame.src = PAGE;
  const loaded = new Promise(resolve => frame.addEventListener('load', resolve, {once: true}));
  document.body.append(frame); await loaded;
  let replies = 0;
  addEventListener('message', event => { if (event.data === bridgeProtocol.connect) replies++; });
  frame.contentWindow.postMessage(bridgeProtocol.ready, VAULT);
  await delay(250);
  check(replies === 0, 'wrong actual parent origin accepted');
  frame.remove();
}
export async function wrong_source() {
  const port = await boundPort(async () => {
    const sibling = document.createElement('iframe'); document.body.append(sibling);
    sibling.contentWindow.eval(`parent.document.querySelector('[data-raw-vault]').contentWindow.postMessage(${JSON.stringify(bridgeProtocol.ready)}, ${JSON.stringify(VAULT)})`);
    await delay(250); sibling.remove();
  });
  const response = next(port); port.postMessage(JSON.stringify({kind: 'close', id: 1}));
  check((await response).kind === 'closed', 'wrong-source probe damaged real owner');
  port.close();
}
export async function redirect() {
  let refused = false;
  try {
    await createVaultClient({member_origin: MEMBER, vault_origin: VAULT,
      vault_url: VAULT + '/__redirect-foreign', timeout_millis: 500});
  } catch { refused = true; }
  check(refused, 'redirected foreign frame acquired a client');
}
export async function top_rejected() {
  check(parent === window && location.origin === VAULT, 'missing top-level Vault negative');
  check(document.body.dataset.owner === 'refused', 'inverted embedding remained accepted');
}

export async function unread() {
  const port = await boundPort();
  port.onmessage = null;
  const request = JSON.stringify({action: 'runtime.status', version: 1, body: {}});
  for (let id = 1; id <= bridgeProtocol.maximum_pending; id++) {
    port.postMessage(JSON.stringify({kind: 'invoke', id, request}));
  }
  // Give the actual owner time to finish and enqueue replies without consuming
  // them. A request counter that drops at postMessage would incorrectly reopen.
  await delay(250);
  port.postMessage(JSON.stringify({kind: 'invoke', id: bridgeProtocol.maximum_pending + 1, request}));
  const values = await new Promise((resolve, reject) => {
    const values = [], timer = setTimeout(() => reject(new Error('unbounded unread channel')), 10000);
    port.onmessage = event => {
      const value = JSON.parse(event.data); values.push(value);
      if (value.kind === 'closed') { clearTimeout(timer); resolve(values); }
    };
  });
  check(values.filter(value => value.kind === 'output').length <= bridgeProtocol.maximum_pending, 'unbounded unread replies');
  check(values.at(-1).id === null, 'unread overflow did not fence owner');
  port.close();
}
export async function forged_ack() {
  const port = await boundPort();
  let response = next(port);
  port.postMessage(JSON.stringify({kind: 'invoke', id: 1,
    request: JSON.stringify({action: 'runtime.status', version: 1, body: {}})}));
  const value = await response;
  check(value.kind === 'output' && typeof value.challenge === 'string', 'missing consumption challenge');
  response = next(port);
  // An ID alone, or guessed receipt, cannot release the outgoing window.
  port.postMessage(JSON.stringify({kind: 'ack', id: 1, challenge: (value.challenge[0] === '0' ? '1' : '0') + value.challenge.slice(1)}));
  check((await response).kind === 'closed', 'forged acknowledgement accepted');
  port.close();
}
export async function stalled() {
  const port = await boundPort();
  let response = next(port);
  port.postMessage(JSON.stringify({kind: 'invoke', id: 1,
    request: JSON.stringify({action: 'runtime.status', version: 1, body: {}})}));
  check((await response).kind === 'output', 'missing actual reply');
  const closed = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('stalled owner not fenced')), bridgeProtocol.acknowledgement_millis + 5000);
    port.onmessage = event => { clearTimeout(timer); resolve(JSON.parse(event.data)); };
  });
  check((await closed).kind === 'closed', 'stalled owner accepted new lifetime');
  port.close();
}
