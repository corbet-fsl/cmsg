import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { createCmsgClient, CmsgError } from '../generated/runtime/client.js';

const child = spawn(process.argv[2], [], { stdio: ['ignore', 'pipe', 'pipe'] });
// A private inherited pipe carries this trusted test pairing. Nothing is logged.
const lines = createInterface({ input: child.stdout });
let stderrBytes = 0;
child.stderr.on('data', bytes => {
  stderrBytes += bytes.length;
  if (stderrBytes > 64 * 1024) child.kill();
});
let timer;
try {
  const startup = await Promise.race([
    once(lines, 'line').then(([line]) => {
      assert.ok(line.length <= 8192, 'bounded private bootstrap');
      return JSON.parse(line);
    }),
    once(child, 'exit').then(() => { throw new Error('Door exited before bootstrap'); }),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Door startup timed out')), 10000); }),
  ]);
  clearTimeout(timer);
  const post = async (body, origin = startup.origin) => {
    const response = await fetch(`${startup.base}/invoke`, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json', Origin: origin,
        Authorization: `Bearer ${startup.capability}` }, body,
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return response.json();
  };
  const client = createCmsgClient(request => post(JSON.stringify(request)));
  const status = await client.call('runtime.status', {});
  assert.equal(status.community, 'conformance');
  assert.equal(status.preload, 'unavailable');
  const descriptions = await client.call('runtime.describe', {});
  assert.ok(descriptions.some(action => action.action === 'board.status'));
  assert.deepEqual(await client.invoke('board.status', {}), { status: 'error', error: 'unavailable' });
  assert.deepEqual(await post('{"action":"runtime.status","version":1,"body":{},"body":{}}'),
    { status: 'error', error: 'invalid_request' });
  assert.deepEqual(await post('{"action":"runtime.status","version":1,"body":{}}', 'https://foreign.example'),
    { status: 'error', error: 'unauthorized' });
  assert.deepEqual(await client.invoke('client.revoke', {}),
    { status: 'ok', result: { revoked: true }, events: [{ event: 'client_revoked' }] });
  await assert.rejects(client.call('runtime.status', {}),
    error => error instanceof CmsgError && error.code === 'unauthorized');
  console.log('Generated TypeScript client passed actual local Door HTTP conformance.');
} finally {
  clearTimeout(timer);
  lines.close();
  if (child.exitCode === null && child.signalCode === null) {
    child.kill();
    await once(child, 'exit');
  }
}
