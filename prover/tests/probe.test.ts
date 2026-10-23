// Headless Chromium against the wallet-origin double, driving the REAL cmsg wasm (feature
// `browser-prover-probe`): the Rust prover path the wallet frame lends, not only its glue.
//   - a genesis proves in the worker through the Rust BrowserProver; the engine derived the public
//     inputs itself; the proof verifies natively and its public inputs equal the native engine's;
//   - calibration keeps one measurement in this origin and announces a device class, and nothing
//     about it leaves the origin (request recorder, both sides);
//   - a predicted overrun is announced and no proof starts without the member's one-shot permission;
//   - a tampered circuit, a tampered setup and a tampered G2 are refused (and refetched once).
//
// Inputs: CMSG_PROVER_ARTIFACTS = the deployment's prover directory (circuit.json, keys.json,
// calibration.json, srs/g1-<points>.dat, srs/g2.dat; what cmeet's web build ships under /prover/);
// CMSG_PROVER_FIXTURE = input.json + expected.json of the native engine (CWLT_BROWSER_FIXTURE_OUT of
// its test `real::a_genesis_proves_through_the_browser_path...`); CWLT_NATIVE_PROVER_FIXTURE = the
// extension artifact (setup/g1.dat, g2.dat); CMSG_PROVER_VERIFY = the native verifier (cwlt-engine
// example `verify-reply`); CMSG_PROVER_PROBE_DIST = the directory `node build-probe.mjs` wrote.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import type { Browser, BrowserContext, Page } from 'playwright-core';
import { launch, record, type Contact } from './harness/browser.ts';
import { startHarness, type Harness } from './harness/server.ts';

const need = (name: string): string => {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  return value;
};
const ARTIFACTS = need('CMSG_PROVER_ARTIFACTS');
const FIXTURE = need('CMSG_PROVER_FIXTURE');
const NATIVE = need('CWLT_NATIVE_PROVER_FIXTURE');
const DIST = need('CMSG_PROVER_PROBE_DIST');
const MINUTES = 60_000;

const sha256 = (name: string) => createHash('sha256').update(readFileSync(join(ARTIFACTS, name))).digest('hex');
const POINTS = Number(/^g1-(\d+)\.dat$/.exec(readdirSync(join(ARTIFACTS, 'srs')).find((name) => name.startsWith('g1-')) ?? '')?.[1]);
assert.ok(POINTS > 0, 'the artifacts directory holds srs/g1-<points>.dat');
const G1 = `/prover/srs/g1-${POINTS}.dat`;
// What the deployment's vault.json pins (registration.prover).
const DEPLOYMENT = JSON.stringify({
  circuit_sha256: sha256('circuit.json'),
  keys_sha256: sha256('keys.json'),
  calibration_sha256: sha256('calibration.json'),
  points: POINTS,
});
const input = readFileSync(join(FIXTURE, 'input.json'), 'utf8');
const expected = JSON.parse(readFileSync(join(FIXTURE, 'expected.json'), 'utf8')) as string[];
// The public statement: the public parameters of the update circuit's ABI, taken from the input.
// The engine derives the expected public inputs from exactly this and nothing else.
const PUBLIC = (() => {
  const abi = (JSON.parse(readFileSync(join(ARTIFACTS, 'circuit.json'), 'utf8')) as { update: { abi: { parameters: { name: string; visibility: string }[] } } }).update.abi;
  const all = JSON.parse(input) as Record<string, unknown>;
  return JSON.stringify(Object.fromEntries(abi.parameters.filter((p) => p.visibility === 'public').map((p) => [p.name, all[p.name]])));
})();

type Outcome<T> = { ok: true; value: T } | { ok: false; error: string };
type Event = { stage: string; code?: string; threads?: number; cached?: boolean; class?: string; fits?: boolean; predicted_millis?: number; window_seconds?: number };

let browser: Browser;
before(async () => {
  browser = await launch();
});
after(async () => {
  await browser.close();
});

async function open(harness: Harness): Promise<{ context: BrowserContext; page: Page; contacts: Contact[]; pageErrors: string[] }> {
  const context = await browser.newContext();
  const contacts = record(context);
  const page = await context.newPage();
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto(`${harness.origin}/`);
  await page.waitForFunction(() => 'probe' in window, null, { timeout: MINUTES });
  return { context, page, contacts, pageErrors };
}
type Probe = {
  events: Event[];
  isolated: boolean;
  cancel(): void;
  setup(deployment: string): Promise<Outcome<string>>;
  prove(deployment: string, publicJson: string, input: string): Promise<Outcome<string>>;
  calibrate(deployment: string): Promise<Outcome<string>>;
  stored(circuitId: string): Promise<number | null>;
  store(circuitId: string, millis: number): Promise<void>;
  allowSlow(): void;
};
const probe = <T>(page: Page, run: (p: Probe, ...rest: string[]) => Promise<T> | T, ...rest: string[]): Promise<T> =>
  page.evaluate(`(${run.toString()})(window.probe, ...${JSON.stringify(rest)})`) as Promise<T>;
const prove = (page: Page) => probe(page, (p, d, pub, inp) => p.prove(d!, pub!, inp!), DEPLOYMENT, PUBLIC, input);
const events = (page: Page): Promise<Event[]> => probe(page, (p) => p.events.slice());
const circuitIdOf = async (page: Page): Promise<string> => {
  const setup = await probe(page, (p, d) => p.setup(d!), DEPLOYMENT);
  assert.ok(setup.ok, JSON.stringify(setup));
  return (JSON.parse(setup.value) as { circuit_id: string }).circuit_id;
};
const waitFor = (page: Page, stage: string, count = 1) =>
  page.waitForFunction(([s, n]) => (window as unknown as { probe: Probe }).probe.events.filter((e) => e.stage === s).length >= (n as number), [stage, count], { timeout: 15 * MINUTES });
const classOf = (millis: number, windowSeconds: number) => {
  const share = (millis * 100) / (windowSeconds * 1000);
  return share <= 30 ? 'fast' : share <= 55 ? 'ok' : share <= 80 ? 'slow' : 'too_slow';
};
const idbNames = (page: Page) => page.evaluate(async () => (await indexedDB.databases()).map((db) => db.name).sort());
const idbKeys = (page: Page, database: string, store: string) =>
  page.evaluate(
    ([name, storeName]) =>
      new Promise<{ keys: unknown[]; values: unknown[] }>((resolve, reject) => {
        const open = indexedDB.open(name!);
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const objects = open.result.transaction(storeName!).objectStore(storeName!);
          const keys = objects.getAllKeys();
          const values = objects.getAll();
          values.onsuccess = () => {
            open.result.close();
            resolve({ keys: keys.result, values: values.result });
          };
        };
      }),
    [database, store],
  );

describe('the Rust prover path in headless Chromium (wasm probe)', () => {
  let harness: Harness;
  before(async () => {
    harness = await startHarness({ dist: DIST, artifacts: ARTIFACTS, setupDir: join(NATIVE, 'setup'), page: 'probe-page.js' });
  });
  after(async () => {
    await harness.close();
  });

  test('a genesis proves in the worker through the Rust BrowserProver, verifies natively, and carries the native public inputs', { timeout: 20 * MINUTES }, async () => {
    const { context, page, contacts, pageErrors } = await open(harness);
    try {
      assert.equal(await probe(page, (p) => p.isolated), false, 'no COOP/COEP is added');
      const result = await prove(page);
      assert.deepEqual(pageErrors, []);
      assert.ok(result.ok, JSON.stringify(result));
      // The engine (wasm32) derived the public inputs from the public statement and accepted the reply
      // only because it carried exactly those; the reply is handed to the NATIVE verifier unchanged.
      const { setup: setupText, reply } = JSON.parse(result.value) as { setup: string; reply: { verified: boolean; public_inputs: string[]; proof: string } };
      assert.equal(reply.verified, true);
      assert.deepEqual(reply.public_inputs, expected, 'public inputs equal the native engine\'s');
      assert.ok(reply.proof.length > 0 && reply.proof.length % 64 === 0);
      const directory = mkdtempSync(join(tmpdir(), 'cmsg-probe-'));
      writeFileSync(join(directory, 'setup.json'), setupText);
      const setup = JSON.parse(setupText) as { circuit_id: string };
      writeFileSync(join(directory, 'reply.json'), JSON.stringify(reply));
      const verdict = execFileSync(need('CMSG_PROVER_VERIFY'), [join(directory, 'setup.json'), join(directory, 'reply.json'), join(FIXTURE, 'expected.json'), join(NATIVE, 'setup')], { encoding: 'utf8' });
      assert.match(verdict, /native verification: verified/);
      // The setup the Rust side built names the circuit version (the calibration key) and the pinned size.
      assert.match(setup.circuit_id, /^[0-9a-f]{64}$/);
      // Progress reached the frame host in order, without any value; threads = 1 without isolation.
      const seen = await events(page);
      const order = seen.map((e) => e.stage);
      for (const [a, b] of [['start', 'srs-load'], ['srs-load', 'witness'], ['witness', 'prove'], ['prove', 'verify'], ['verify', 'done']]) {
        assert.ok(order.indexOf(a!) !== -1 && order.indexOf(a!) < order.lastIndexOf(b!), `${a} before ${b}`);
      }
      assert.ok(!order.includes('forecast'), 'a device without a stored measurement is not forecast');
      assert.equal(seen.find((e) => e.stage === 'prove')?.threads, 1);
      // The deployed files came from the wallet origin only, each once, and the worker fetched the setup there.
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
      for (const path of ['/prover/circuit.json', '/prover/keys.json', G1, '/prover/srs/g2.dat']) assert.ok(contacts.some((c) => c.url.endsWith(path)), path);
      assert.ok(contacts.every((c) => c.method === 'GET' && !c.body));
    } finally {
      await context.close();
    }
  });

  test('calibration keeps one measurement and a device class on this origin, and nothing about it leaves', { timeout: 20 * MINUTES }, async () => {
    const mark = harness.seen.length;
    const { context, page, contacts, pageErrors } = await open(harness);
    try {
      const id = await circuitIdOf(page);
      assert.equal(await probe(page, (p, i) => p.stored(i!), id), null, 'a new device has no measurement');
      const result = await probe(page, (p, d) => p.calibrate(d!), DEPLOYMENT);
      assert.deepEqual(pageErrors, []);
      assert.ok(result.ok, JSON.stringify(result));
      const forecast = JSON.parse(result.value) as { class: string; predicted_millis: number; window_seconds: number; fits: boolean };
      // The measurement is whole milliseconds under the circuit version, and the class follows it.
      const stored = await probe(page, (p, i) => p.stored(i!), id);
      assert.equal(stored, forecast.predicted_millis);
      assert.ok(Number.isInteger(stored) && stored! >= 1);
      assert.equal(forecast.class, classOf(forecast.predicted_millis, forecast.window_seconds));
      assert.equal(forecast.fits, forecast.class !== 'too_slow');
      const announced = (await events(page)).find((e) => e.stage === 'calibrated');
      assert.equal(announced?.class, forecast.class);
      // The store holds exactly that one integer: the page keeps nothing else about the device.
      assert.deepEqual(await idbKeys(page, 'cmsg-prover-calibration', 'millis'), { keys: [id], values: [stored] });
      assert.deepEqual((await idbNames(page)).filter((name) => name !== 'cmeet-prover-srs'), ['cmsg-prover-calibration']);
      // Once per circuit version: the next idle time reads the stored value and starts no worker.
      const workers = harness.hits.get('/prover.worker.js') ?? 0;
      const again = await probe(page, (p, d) => p.calibrate(d!), DEPLOYMENT);
      assert.ok(again.ok && (JSON.parse(again.value) as { predicted_millis: number }).predicted_millis === stored);
      assert.equal(harness.hits.get('/prover.worker.js') ?? 0, workers, 'no second calibration proof');
      // Nothing left: every request of the page and its workers went to the wallet origin as a plain
      // GET without body or query, and none of them mentions the measurement or the class.
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
      assert.ok(contacts.every((c) => c.method === 'GET' && !c.body && !c.url.includes('?') && c.kind !== 'websocket' && c.kind !== 'ping'));
      const mine = harness.seen.slice(mark);
      assert.ok(mine.every((r) => r.method === 'GET' && !r.body && r.search === ''));
      const text = [...contacts.map((c) => c.url.slice(c.origin.length)), ...mine.map((r) => r.path + r.search)].join('\n');
      assert.ok(!new RegExp(`(^|[^0-9])${stored}([^0-9]|$)`).test(text), 'no request carries the measured time');
      assert.ok(!/fast|slow|too_slow|class/.test(text.replace(/chunk|barretenberg|prover|srs/g, '')), 'no request names a class');
    } finally {
      await context.close();
    }
  });

  test('a predicted overrun is announced and no proof starts without the member\'s one-shot permission', { timeout: 10 * MINUTES }, async () => {
    const { context, page, contacts } = await open(harness);
    try {
      const id = await circuitIdOf(page);
      // A device that measured 95 s against the 100 s window.
      await probe(page, (p, i, m) => p.store(i!, Number(m)), id, '95000');
      const g1Before = harness.hits.get(G1) ?? 0;
      const refused = await prove(page);
      assert.deepEqual(refused, { ok: false, error: 'refused' });
      let seen = await events(page);
      const forecast = seen.find((e) => e.stage === 'forecast');
      assert.equal(forecast?.class, 'too_slow');
      assert.equal(forecast?.fits, false);
      assert.equal(forecast?.predicted_millis, 95000);
      assert.equal(forecast?.window_seconds, 100);
      assert.ok(!seen.some((e) => e.stage === 'start' || e.stage === 'srs-load'), 'no worker was started');
      assert.equal(harness.hits.get(G1) ?? 0, g1Before, 'no setup was fetched for it');
      // The member chooses to try: the next proof starts, once.
      await probe(page, (p) => p.allowSlow());
      const trying = prove(page);
      await waitFor(page, 'witness');
      await probe(page, (p) => p.cancel());
      assert.equal((await trying).ok, false);
      // The permission was spent by that one attempt.
      const spent = await prove(page);
      assert.deepEqual(spent, { ok: false, error: 'refused' });
      seen = await events(page);
      assert.equal(seen.filter((e) => e.stage === 'start').length, 1);
      assert.equal(seen.filter((e) => e.stage === 'forecast').length, 3);
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
    } finally {
      await context.close();
    }
  });

  test('a tampered circuit file is refused before any worker starts', { timeout: 2 * MINUTES }, async () => {
    const { context, page } = await open(harness);
    try {
      harness.control.tamperCircuit = true;
      const workers = harness.hits.get('/prover.worker.js') ?? 0;
      assert.deepEqual(await prove(page), { ok: false, error: 'configure' });
      assert.equal(harness.hits.get('/prover.worker.js') ?? 0, workers);
    } finally {
      harness.control.tamperCircuit = false;
      await context.close();
    }
  });

  test('a tampered setup is refused after one refetch, through the Rust path too', { timeout: 5 * MINUTES }, async () => {
    const { context, page, contacts } = await open(harness);
    try {
      harness.control.tamperG1 = true;
      const before = harness.hits.get(G1) ?? 0;
      assert.deepEqual(await prove(page), { ok: false, error: 'refused' });
      assert.equal((harness.hits.get(G1) ?? 0) - before, 2, 'fetched, then fetched again past the HTTP cache');
      const last = (await events(page)).at(-1);
      assert.equal(last?.stage, 'failed');
      assert.equal(last?.code, 'srs_digest');
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
      // Served right again, the next proof starts from a clean fetch (nothing tampered was cached).
      harness.control.tamperG1 = false;
      const retry = prove(page);
      await waitFor(page, 'witness');
      await probe(page, (p) => p.cancel());
      assert.equal((await retry).ok, false);
      assert.equal((harness.hits.get(G1) ?? 0) - before, 3);
    } finally {
      harness.control.tamperG1 = false;
      harness.control.tamperG2 = false;
      await context.close();
    }
  });
});
