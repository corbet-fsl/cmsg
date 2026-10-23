// Headless Chromium against the wallet-origin double: one real account update is proven in the
// worker, verified by the native backend, and its public inputs equal the native ones; a tampered
// setup is refused and refetched; no request leaves the wallet origin.
//
// Inputs (made by the engine's test `real::a_genesis_proves_through_the_browser_path...` with
// CWLT_BROWSER_FIXTURE_OUT): CMSG_PROVER_FIXTURE = a directory with setup.json, input.json and
// expected.json. CWLT_NATIVE_PROVER_FIXTURE = the retained extension artifact (setup/g1.dat, g2.dat).
// CMSG_PROVER_VERIFY = the native verifier (cwlt-engine example `verify-reply`).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright-core';
import { startHarness, type Harness } from './harness/server.ts';

const need = (name: string): string => {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  return value;
};
const FIXTURE = need('CMSG_PROVER_FIXTURE');
const ARTIFACT = need('CWLT_NATIVE_PROVER_FIXTURE');
const DIST = new URL('../dist', import.meta.url).pathname;
const setup = readFileSync(join(FIXTURE, 'setup.json'), 'utf8');
const input = readFileSync(join(FIXTURE, 'input.json'), 'utf8');
const expected = JSON.parse(readFileSync(join(FIXTURE, 'expected.json'), 'utf8')) as string[];
const POINTS = (JSON.parse(setup) as { srs: { points: number } }).srs.points;
const G1 = `/prover/srs/g1-${POINTS}.dat`;
const MINUTES = 60_000;

type Reply = { ok: true; reply: string } | { ok: false; error: string };
type Contact = { origin: string; url: string; kind: string };

let browser: Browser;
before(async () => {
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM ?? '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
});
after(async () => {
  await browser.close();
});

// Records every request of every page of the context, workers and web sockets included (the
// pattern of the member page's network spec), as origin + url.
function record(context: BrowserContext): Contact[] {
  const contacts: Contact[] = [];
  const origin = (url: string) => {
    const parsed = new URL(url);
    if (['data:', 'blob:', 'about:'].includes(parsed.protocol)) return null;
    return `${parsed.protocol.replace('ws', 'http')}//${parsed.host}`;
  };
  context.on('request', (request) => {
    const o = origin(request.url());
    if (o !== null) contacts.push({ origin: o, url: request.url(), kind: request.resourceType() });
  });
  const sockets = (page: Page) =>
    page.on('websocket', (socket) => {
      const o = origin(socket.url());
      if (o !== null) contacts.push({ origin: o, url: socket.url(), kind: 'websocket' });
    });
  context.pages().forEach(sockets);
  context.on('page', sockets);
  return contacts;
}

async function open(harness: Harness): Promise<{ context: BrowserContext; page: Page; contacts: Contact[]; pageErrors: string[] }> {
  const context = await browser.newContext();
  const contacts = record(context);
  const page = await context.newPage();
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto(`${harness.origin}/`);
  await page.waitForFunction(() => 'prover' in window);
  return { context, page, contacts, pageErrors };
}
const prove = (page: Page): Promise<Reply> =>
  page.evaluate(([s, i]) => (window as unknown as { prover: { prove(s: string, i: string): Promise<Reply> } }).prover.prove(s, i), [setup, input]);
const events = (page: Page): Promise<{ stage: string; code?: string; threads?: number; cached?: boolean }[]> =>
  page.evaluate(() => (window as unknown as { prover: { events: never[] } }).prover.events.slice());
const stages = async (page: Page) => (await events(page)).map((e) => e.stage);

describe('the browser prover on the wallet origin', () => {
  let harness: Harness;
  before(async () => {
    harness = await startHarness({ dist: DIST, setupDir: join(ARTIFACT, 'setup') });
  });
  after(async () => {
    await harness.close();
  });

  test('one real account update proves in the worker, verifies natively, and carries the native public inputs', { timeout: 15 * MINUTES }, async () => {
    const { context, page, contacts, pageErrors } = await open(harness);
    try {
      assert.equal(await page.evaluate(() => (window as unknown as { prover: { isolated: boolean } }).prover.isolated), false, 'no COOP/COEP is added');
      const result = await prove(page);
      assert.deepEqual(pageErrors, []);
      assert.ok(result.ok, JSON.stringify(result));
      const reply = JSON.parse(result.reply) as { verified: boolean; public_inputs: string[]; proof: string };
      assert.equal(reply.verified, true);
      assert.deepEqual(reply.public_inputs, expected, 'public inputs equal the native engine\'s');
      assert.ok(reply.proof.length > 0 && reply.proof.length % 64 === 0);
      // Verified by the native backend (barretenberg through the same crate the native prover uses).
      const directory = mkdtempSync(join(tmpdir(), 'cmsg-prover-'));
      writeFileSync(join(directory, 'reply.json'), result.reply);
      const verdict = execFileSync(need('CMSG_PROVER_VERIFY'), [join(FIXTURE, 'setup.json'), join(directory, 'reply.json'), join(FIXTURE, 'expected.json')], { encoding: 'utf8' });
      assert.match(verdict, /native verification: verified/);
      // Progress reached the frame host as events, in order, without any value.
      const seen = await events(page);
      const order = seen.map((e) => e.stage);
      for (const [a, b] of [['start', 'srs-load'], ['srs-load', 'witness'], ['witness', 'prove'], ['prove', 'verify'], ['verify', 'done']]) {
        assert.ok(order.indexOf(a!) !== -1 && order.indexOf(a!) < order.lastIndexOf(b!), `${a} before ${b}`);
      }
      assert.equal(seen.find((e) => e.stage === 'prove')?.threads, 1, 'single thread without cross-origin isolation');
      assert.deepEqual(Object.keys(seen.find((e) => e.stage === 'prove') ?? {}).sort(), ['stage', 'threads']);
      // Nothing left the wallet origin, workers included; the worker's own setup fetch is among the records.
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
      assert.ok(contacts.some((c) => c.url.endsWith(G1)), 'the recorder sees the worker\'s requests');
      assert.ok(contacts.every((c) => !/aztec|crs\./.test(c.url)));
    } finally {
      await context.close();
    }
  });

  test('a cached setup is verified again on every load; a tampered cache is discarded and fetched again', { timeout: 15 * MINUTES }, async () => {
    // The first test left no cache in this fresh context; run until the setup is cached, then stop.
    const { context, page } = await open(harness);
    try {
      const before = harness.hits.get(G1) ?? 0;
      const first = prove(page);
      await page.waitForFunction(() => (window as unknown as { prover: { events: { stage: string }[] } }).prover.events.some((e) => e.stage === 'witness'), null, { timeout: 10 * MINUTES });
      await page.evaluate(() => (window as unknown as { prover: { cancel(): void } }).prover.cancel());
      assert.equal((await first).ok, false);
      assert.equal((harness.hits.get(G1) ?? 0) - before, 1, 'fetched once to fill the cache');
      // A second start loads from the cache: no setup download.
      const warm = prove(page);
      await page.waitForFunction(() => (window as unknown as { prover: { events: { stage: string }[] } }).prover.events.filter((e) => e.stage === 'witness').length >= 2, null, { timeout: 10 * MINUTES });
      await page.evaluate(() => (window as unknown as { prover: { cancel(): void } }).prover.cancel());
      await warm;
      assert.equal((harness.hits.get(G1) ?? 0) - before, 1, 'the verified cache is used');
      assert.equal((await events(page)).filter((e) => e.stage === 'srs-load').at(-1)?.cached, true);
      // Corrupt one byte of the cached copy: the next load discards it and fetches again.
      await page.evaluate(
        () =>
          new Promise<void>((resolve, reject) => {
            const open = indexedDB.open('cmeet-prover-srs', 1);
            open.onsuccess = () => {
              const db = open.result;
              const store = db.transaction('srs', 'readwrite');
              const get = store.objectStore('srs').openCursor();
              get.onsuccess = () => {
                const cursor = get.result!;
                const bytes = cursor.value as Uint8Array;
                bytes[1000] ^= 1;
                cursor.update(bytes);
              };
              store.oncomplete = () => { db.close(); resolve(); };
              store.onerror = () => reject(store.error);
            };
          }),
      );
      const third = prove(page);
      await page.waitForFunction(() => (window as unknown as { prover: { events: { stage: string }[] } }).prover.events.filter((e) => e.stage === 'witness').length >= 3, null, { timeout: 10 * MINUTES });
      await page.evaluate(() => (window as unknown as { prover: { cancel(): void } }).prover.cancel());
      await third;
      assert.equal((harness.hits.get(G1) ?? 0) - before, 2, 'the tampered cache was refetched');
      assert.equal((await events(page)).filter((e) => e.stage === 'srs-load').at(-1)?.cached, false);
    } finally {
      await context.close();
    }
  });

  test('a tampered setup from the network is refused after one more fetch that bypasses the HTTP cache', { timeout: 5 * MINUTES }, async () => {
    const { context, page, contacts } = await open(harness);
    try {
      harness.control.tamperG1 = true;
      const before = harness.hits.get(G1) ?? 0;
      const result = await prove(page);
      assert.equal(result.ok, false);
      assert.equal((harness.hits.get(G1) ?? 0) - before, 2, 'fetched, then fetched again');
      const seen = await events(page);
      assert.equal(seen.at(-1)?.stage, 'failed');
      assert.equal(seen.at(-1)?.code, 'srs_digest');
      assert.ok(!seen.some((e) => e.stage === 'srs-load' || e.stage === 'witness'), 'the proof system never saw it');
      // Nothing was cached from it.
      const cached = await page.evaluate(
        () => new Promise<number>((resolve) => {
          const open = indexedDB.open('cmeet-prover-srs', 1);
          open.onsuccess = () => {
            const count = open.result.transaction('srs').objectStore('srs').count();
            count.onsuccess = () => resolve(count.result);
          };
        }),
      );
      assert.equal(cached, 0);
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
    } finally {
      harness.control.tamperG1 = false;
      await context.close();
    }
  });

  test('a tampered G2 setup is refused', { timeout: 5 * MINUTES }, async () => {
    const { context, page } = await open(harness);
    try {
      harness.control.tamperG2 = true;
      assert.equal((await prove(page)).ok, false);
      const last = (await events(page)).at(-1);
      assert.equal(last?.stage, 'failed');
      assert.equal(last?.code, 'srs_digest');
    } finally {
      harness.control.tamperG2 = false;
      await context.close();
    }
  });

  test('the worker policy blocks every other origin: fetch, import and web socket', { timeout: 2 * MINUTES }, async () => {
    const other = await startHarness({ dist: DIST, setupDir: join(ARTIFACT, 'setup') });
    const { context, page } = await open(harness);
    try {
      const outcome = await page.evaluate(
        (otherOrigin) =>
          new Promise((resolve) => {
            const worker = new Worker(`/probe.worker.js?other=${encodeURIComponent(otherOrigin)}`, { type: 'module' });
            worker.onmessage = (event) => resolve(event.data);
          }),
        other.origin,
      );
      assert.deepEqual(outcome, { fetch: 'blocked', import: 'blocked', socket: 'blocked' });
      assert.deepEqual([...other.hits.keys()], [], 'the other origin saw nothing');
    } finally {
      await context.close();
      await other.close();
    }
  });
});
