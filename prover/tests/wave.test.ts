// The browser wave stack in headless Chromium, driving the REAL cmsg wasm (feature
// `browser-prover-probe`) on the deployment's pinned material:
//   - a `wave` and an `outcome` proof are produced in the prover worker through the Rust
//     BrowserProver of the pinned peer-release group, and the counterpart check (bb.js in the
//     worker under the pinned key) accepts each and refuses a tampered proof, changed public
//     fields and a proof judged under another verification key;
//   - the whole counterpart verifier (cwlt WaveVerifier over the worker checks) accepts the
//     retained real reservation and Answer of the wave release and refuses a tampered proof,
//     another context, another outcome, another account group and another issuer key ring;
//   - a served key group that differs from the pinned digest is refused before any worker starts;
//   - the compose warm-up (speculative reservation option (b)) loads the pinned setup into the
//     verified cache, proves nothing and talks to no other origin.
//
// Inputs: CMSG_PROVER_ARTIFACTS = the deployment's prover directory (circuit.json, keys.json,
// calibration.json, srs/g1-<points>.dat, srs/g2.dat, wave/{circuit,keys,manifest}.json: what cmeet's
// web build ships under /prover/); CMSG_WAVE_FIXTURE = the retained wave release fixture
// (CBLC_WAVE_FIXTURE of cblc's proof-fixtures job: wave-roundtrip.json under its own digest);
// CMSG_WAVE_INPUTS = cwlt's blessed witness vectors (tests/vectors/witness/golden.json);
// CMSG_PROVER_PROBE_DIST = the directory `node build-probe.mjs` wrote.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
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
const FIXTURE = need('CMSG_WAVE_FIXTURE');
const INPUTS = need('CMSG_WAVE_INPUTS');
const DIST = need('CMSG_PROVER_PROBE_DIST');
const MINUTES = 60_000;

const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const POINTS = Number(/^g1-(\d+)\.dat$/.exec(readdirSync(join(ARTIFACTS, 'srs')).find((name) => name.startsWith('g1-')) ?? '')?.[1]);
assert.ok(POINTS > 0, 'the artifacts directory holds srs/g1-<points>.dat');
// What the deployment's vault.json pins (registration.prover, its wave group included).
const deploymentOf = (directory: string) =>
  JSON.stringify({
    circuit_sha256: sha256(readFileSync(join(directory, 'circuit.json'))),
    keys_sha256: sha256(readFileSync(join(directory, 'keys.json'))),
    calibration_sha256: sha256(readFileSync(join(directory, 'calibration.json'))),
    points: POINTS,
    wave: {
      circuit_sha256: sha256(readFileSync(join(directory, 'wave', 'circuit.json'))),
      keys_sha256: sha256(readFileSync(join(directory, 'wave', 'keys.json'))),
      manifest_sha256: sha256(readFileSync(join(directory, 'wave', 'manifest.json'))),
    },
  });
const DEPLOYMENT = deploymentOf(ARTIFACTS);

// The retained release, consumed by its content address (never regenerated here).
const fixtureText = readFileSync(join(FIXTURE, 'wave-roundtrip.json'));
assert.equal(basename(FIXTURE.replace(/\/$/, '')), sha256(fixtureText), 'the fixture is its content address');
type Case = { kind: 'wave' | 'outcome'; statement: Record<string, any>; proof: string };
const fixture = JSON.parse(fixtureText.toString()) as { cases: Case[]; material: { waveVerifier: Record<string, any> } };
const byKind = Object.fromEntries(fixture.cases.map((c) => [c.kind, c])) as Record<'wave' | 'outcome', Case>;
const reservation = byKind.wave.statement.wave;
const settled = byKind.outcome.statement.outcome;
const policy = fixture.material.waveVerifier;
// The served wave group is the release's own group (its manifest names exactly the served files).
const hexOf = (bytes: number[]) => Buffer.from(bytes).toString('hex');
const waveScope = (fixture as unknown as { waveScope: { circuitDigest: number[]; verifyingKeyDigest: number[] } }).waveScope;
assert.equal(sha256(readFileSync(join(ARTIFACTS, 'wave', 'circuit.json'))), hexOf(waveScope.circuitDigest));
assert.equal(sha256(readFileSync(join(ARTIFACTS, 'wave', 'keys.json'))), hexOf(waveScope.verifyingKeyDigest));
// The community's policy pins the account (extension) group, never the peer-release group: the
// wave keys are trusted by the deployment's pins alone.
assert.notEqual(hexOf(policy.proofScope.verifyingKeyDigest), hexOf(waveScope.verifyingKeyDigest));

// The member's own witness of a synthetic account: cwlt's blessed vectors (the `wave` step of an
// accepted active reservation and the `outcome` step of a Silence). The vectors carry a stub
// issuer certificate whose acceptance time predates the slot; the circuits bind that time only
// through the window checks, so it is set inside the window (wave: at the slot's admission;
// Silence: at the lease end). Public test data, never a member's value.
const golden = JSON.parse(readFileSync(INPUTS, 'utf8')) as { steps: { op: string; ok: boolean; input?: Record<string, any> }[] };
const witnessOf = (kind: 'wave' | 'outcome'): string => {
  const step = golden.steps.find((s) => s.ok && s.op === kind && s.input && (kind === 'wave' || s.input.outcome === 3));
  assert.ok(step?.input, `a ${kind} vector`);
  const input = structuredClone(step.input);
  input.accepted_at = kind === 'wave' ? input.opened_at : input.expires_at;
  return JSON.stringify(input);
};
const WITNESS = { wave: witnessOf('wave'), outcome: witnessOf('outcome') };
const PUBLICS = { wave: 618, outcome: 651 };

type Outcome<T> = { ok: true; value: T } | { ok: false; error: string };
type Event = { stage: string; threads?: number; cached?: boolean };
type Reply = { verified: boolean; public_inputs: string[]; proof: string };
type Probe = {
  events: Event[];
  waveProve(deployment: string, program: string, input: string): Promise<Outcome<string>>;
  waveCheck(deployment: string, program: string, fields: string, proof: string): Promise<Outcome<boolean>>;
  waveVerify(...args: string[]): Promise<Outcome<string>>;
  wavePrewarm(deployment: string): Promise<Outcome<boolean>>;
};
const probe = <T>(page: Page, run: (p: Probe, ...rest: string[]) => Promise<T> | T, ...rest: string[]): Promise<T> =>
  page.evaluate(`(${run.toString()})(window.probe, ...${JSON.stringify(rest)})`) as Promise<T>;

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

const flip = (hex: string, at: number) => hex.slice(0, at * 2) + ((parseInt(hex.slice(at * 2, at * 2 + 2), 16) ^ 1).toString(16).padStart(2, '0')) + hex.slice(at * 2 + 2);
const proofHex = (c: Case) => c.proof;
const receipt = Buffer.from(settled.receiptDigest as number[]).toString('hex');
const now = String(Math.max(reservation.acceptedAt, settled.evidence.acceptedAt) + 1);
const until = String(reservation.context.expiresAt + 1000);
const verify = (page: Page, deployment: string, pinned: object, kind: 'wave' | 'outcome', statement: object, proof: string, expected: object, outcome = '', digest = '') =>
  probe(page, (p, ...a) => p.waveVerify(...a), deployment, JSON.stringify(pinned), now, until, kind, JSON.stringify(statement), proof, JSON.stringify(expected), outcome, digest);

describe('the browser wave stack in headless Chromium (wasm probe)', () => {
  let harness: Harness;
  before(async () => {
    harness = await startHarness({ dist: DIST, artifacts: ARTIFACTS, page: 'probe-page.js', isolated: process.env.ISOLATED === '1' });
  });
  after(async () => {
    await harness.close();
  });

  test('a wave and an outcome proof are produced in the worker, the pinned-key check accepts them and refuses tampering and another key', { timeout: 30 * MINUTES }, async () => {
    const { context, page, contacts, pageErrors } = await open(harness);
    // A key group whose `wave` and `outcome` keys are swapped, with a manifest naming it: pinned by
    // a deployment of its own, so only the key (its digest) differs from the release.
    const swapped = mkdtempSync(join(tmpdir(), 'cmsg-wave-swapped-'));
    cpSync(ARTIFACTS, swapped, { recursive: true });
    const keys = JSON.parse(readFileSync(join(ARTIFACTS, 'wave', 'keys.json'), 'utf8')) as Record<string, string>;
    const swappedKeys = JSON.stringify({ wave: keys.outcome, outcome: keys.wave });
    writeFileSync(join(swapped, 'wave', 'keys.json'), swappedKeys);
    const manifest = JSON.parse(readFileSync(join(ARTIFACTS, 'wave', 'manifest.json'), 'utf8')) as Record<string, unknown>;
    writeFileSync(join(swapped, 'wave', 'manifest.json'), JSON.stringify({ ...manifest, vkSha256: sha256(swappedKeys) }));
    const other = await startHarness({ dist: DIST, artifacts: swapped, page: 'probe-page.js' });
    const otherSite = await open(other);
    try {
      for (const kind of ['wave', 'outcome'] as const) {
        const proved = await probe(page, (p, d, k, i) => p.waveProve(d!, k!, i!), DEPLOYMENT, kind, WITNESS[kind]);
        assert.deepEqual(pageErrors, []);
        assert.ok(proved.ok, `${kind}: ${JSON.stringify(proved)}`);
        const { setup, reply } = JSON.parse(proved.value) as { setup: string; reply: Reply };
        assert.equal(reply.verified, true);
        assert.equal(reply.public_inputs.length, PUBLICS[kind], 'the engine derived every public field of the member');
        assert.equal((JSON.parse(setup) as { program: string }).program, kind);
        assert.ok(!setup.includes(JSON.stringify((JSON.parse(WITNESS[kind]) as { secret: number[] }).secret)), "the public setup carries no witness");
        const fields = JSON.stringify(reply.public_inputs);
        const check = (site: Page, deployment: string, program: string, f: string, proof: string) =>
          probe(site, (p, d, k, x, y) => p.waveCheck(d!, k!, x!, y!), deployment, program, f, proof);
        assert.deepEqual(await check(page, DEPLOYMENT, kind, fields, reply.proof), { ok: true, value: true }, `${kind} accepted`);
        assert.deepEqual(await check(page, DEPLOYMENT, kind, fields, flip(reply.proof, 40)), { ok: true, value: false }, `${kind} tampered proof`);
        const changed = [...reply.public_inputs];
        changed[changed.length - 1] = flip(changed[changed.length - 1]!, 31);
        assert.deepEqual(await check(page, DEPLOYMENT, kind, JSON.stringify(changed), reply.proof), { ok: true, value: false }, `${kind} changed fields`);
        // The same member under another verification key (another pinned key digest): refused.
        assert.deepEqual(await check(otherSite.page, deploymentOf(swapped), kind, fields, reply.proof), { ok: true, value: false }, `${kind} under another key`);
      }
      // Every request of both pages and their workers went to their own origin only.
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
      assert.deepEqual([...new Set(otherSite.contacts.map((c) => c.origin))], [other.origin]);
      for (const path of ['/prover/wave/circuit.json', '/prover/wave/keys.json', '/prover/wave/manifest.json']) assert.ok(contacts.some((c) => c.url.endsWith(path)), path);
    } finally {
      await otherSite.context.close();
      await other.close();
      await context.close();
    }
  });

  test('the counterpart verifier accepts the retained real reservation and Answer and refuses every change', { timeout: 15 * MINUTES }, async () => {
    const { context, page, pageErrors } = await open(harness);
    try {
      const accepted = { ok: true, value: 'accepted' };
      const refusedWith = (error: string) => ({ ok: false, error });
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'wave', reservation, proofHex(byKind.wave), reservation.context), accepted);
      assert.deepEqual(pageErrors, []);
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'wave', reservation, flip(proofHex(byKind.wave), 40), reservation.context), refusedWith('Refused'));
      const otherContext = { ...reservation.context, nonce: (reservation.context.nonce as number[]).map((b, i) => (i ? b : b ^ 1)) };
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'wave', reservation, proofHex(byKind.wave), otherContext), refusedWith('Refused'));
      const context0 = settled.evidence.context;
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'outcome', settled, proofHex(byKind.outcome), context0, 'answer', receipt), accepted);
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'outcome', settled, proofHex(byKind.wave), context0, 'answer', receipt), refusedWith('Refused'));
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'outcome', settled, proofHex(byKind.outcome), context0, 'close', receipt), refusedWith('Refused'));
      // A policy of another account group (its certificate scope) or another issuer key ring refuses.
      const scope = policy.proofScope as { circuitDigest: number[]; verifyingKeyDigest: number[] };
      const otherGroup = { ...policy, proofScope: { ...scope, circuitDigest: scope.circuitDigest.map((b, i) => (i ? b : b ^ 1)) } };
      assert.deepEqual(await verify(page, DEPLOYMENT, otherGroup, 'wave', reservation, proofHex(byKind.wave), reservation.context), refusedWith('Refused'));
      const keys = policy.certificateKeys as { publicKey: number[] }[];
      const otherIssuer = { ...policy, certificateKeys: keys.map((k) => ({ ...k, publicKey: [...k.publicKey].reverse() })) };
      assert.deepEqual(await verify(page, DEPLOYMENT, otherIssuer, 'outcome', settled, proofHex(byKind.outcome), context0, 'answer', receipt), refusedWith('Refused'));
    } finally {
      await context.close();
    }
  });

  test('a member proof queues behind a running counterpart verification instead of being refused', { timeout: 10 * MINUTES }, async () => {
    const { context, page, pageErrors } = await open(harness);
    try {
      const args = [DEPLOYMENT, JSON.stringify(policy), now, until, 'wave', JSON.stringify(reservation), proofHex(byKind.wave), JSON.stringify(reservation.context), '', ''];
      const [verdict, proved] = await probe(
        page,
        async (p, d, input, ...a) => {
          // Both start in the same turn: the verification takes the device first, the proof must wait for it.
          const checked = p.waveVerify(d!, ...a);
          const proving = p.waveProve(d!, 'wave', input!);
          return [await checked, await proving];
        },
        DEPLOYMENT,
        WITNESS.wave,
        ...args.slice(1),
      );
      assert.deepEqual(pageErrors, []);
      assert.deepEqual(verdict, { ok: true, value: 'accepted' });
      assert.ok((proved as { ok: boolean }).ok, JSON.stringify(proved));
    } finally {
      await context.close();
    }
  });

  test('a served key group that differs from the pinned digest is refused before any worker starts', { timeout: 2 * MINUTES }, async () => {
    const { context, page } = await open(harness);
    try {
      harness.control.tamperWaveKeys = true;
      const workers = harness.hits.get('/prover.worker.js') ?? 0;
      assert.deepEqual(await verify(page, DEPLOYMENT, policy, 'wave', reservation, proofHex(byKind.wave), reservation.context), { ok: false, error: 'configure' });
      assert.deepEqual(await probe(page, (p, d, k, i) => p.waveProve(d!, k!, i!), DEPLOYMENT, 'wave', WITNESS.wave), { ok: false, error: 'configure' });
      assert.equal(harness.hits.get('/prover.worker.js') ?? 0, workers);
    } finally {
      harness.control.tamperWaveKeys = false;
      await context.close();
    }
  });

  test('the compose warm-up caches the pinned setup, proves nothing and reaches no other origin', { timeout: 10 * MINUTES }, async () => {
    const { context, page, contacts } = await open(harness);
    try {
      const mark = harness.seen.length;
      const workers = harness.hits.get('/prover.worker.js') ?? 0;
      assert.deepEqual(await probe(page, (p, d) => p.wavePrewarm(d!), DEPLOYMENT), { ok: true, value: true });
      assert.equal((harness.hits.get('/prover.worker.js') ?? 0) - workers, 1, 'one worker, ended again');
      const quiet = await probe(page, (p) => p.events.slice());
      assert.ok(!quiet.some((e) => ['witness', 'prove'].includes(e.stage)), 'nothing was proven');
      // Only this origin's public material, as plain GETs without body or query.
      assert.deepEqual([...new Set(contacts.map((c) => c.origin))], [harness.origin]);
      assert.ok(harness.seen.slice(mark).every((r) => r.method === 'GET' && !r.body && r.search === ''));
      // The next proof finds the setup warm in the verified cache.
      const proved = await probe(page, (p, d, k, i) => p.waveProve(d!, k!, i!), DEPLOYMENT, 'wave', WITNESS.wave);
      assert.ok(proved.ok, JSON.stringify(proved));
      const seen = await probe(page, (p) => p.events.slice());
      assert.equal(seen.find((e) => e.stage === 'srs-load')?.cached, true, 'the setup came from the warm cache');
    } finally {
      await context.close();
    }
  });
});
