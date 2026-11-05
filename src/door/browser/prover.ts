// Frame-host glue of the browser prover (imported by prover.rs). It owns the life of ONE
// proving Web Worker per proof: it starts it from this origin, hands it the public setup and the
// private input once (the input's buffer is transferred, so this thread keeps no copy), ends it
// when the proof is done, fails or times out, and forwards progress to the frame host as events
// on the frame's window. No value of the witness appears in an event; a failure is one fixed
// code. The worker file is built by cmsg/prover/build.mjs and sits next to this bundle.
//
// It also keeps the device's calibration (decided 2026-10-23): one calibration proof of the real
// circuit with a shipped dummy input, run when the page is idle, once per circuit version. The
// measured time is kept in this origin's IndexedDB only; no request carries it. What it means
// (the device class, the forecast against the proof window) is decided by the Rust engine.

type Progress = {
  stage: string;
  loaded?: number;
  total?: number;
  code?: string;
  cached?: boolean;
  threads?: number;
  [key: string]: unknown;
};
type FromWorker =
  | { type: 'progress'; progress: Progress }
  | { type: 'done'; reply: string }
  | { type: 'error'; code: string };

export const PROGRESS_EVENT = 'cmsg:prover';
/** Dispatched by the frame's own UI when the member chooses to prove although a forecast said no. */
export const ALLOW_SLOW_EVENT = 'cmsg:prover-allow-slow';

const unavailable = () => new Error('cmsg:Unavailable');

function emit(progress: Progress): void {
  if (typeof globalThis.dispatchEvent === 'function' && typeof CustomEvent === 'function') {
    globalThis.dispatchEvent(new CustomEvent(PROGRESS_EVENT, { detail: progress }));
  }
}

/** The Rust side announces a decision (forecast, window-elapsed, calibrated) as one event. */
export function announce(stage: string, detail: string): void {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(detail) as Record<string, unknown>;
  } catch {
    return;
  }
  emit({ ...parsed, stage });
}

// --- the member's one-shot permission to prove although the forecast said the window will not hold

let allowSlow = false;
if (typeof globalThis.addEventListener === 'function') {
  globalThis.addEventListener(ALLOW_SLOW_EVENT, () => {
    allowSlow = true;
  });
}
/** True once for each permission the member gave; the permission is spent by asking. */
export function takeSlowPermission(): boolean {
  const given = allowSlow;
  allowSlow = false;
  return given;
}

// --- bounded same-origin reads of the deployment's public prover material

/** Read one file of the wallet origin (absolute path), at most `maxBytes`, no redirect, no credentials. */
export async function fetchMaterial(path: string, maxBytes: number): Promise<Uint8Array> {
  if (!path.startsWith('/') || path.startsWith('//') || !Number.isInteger(maxBytes) || maxBytes < 1) {
    throw unavailable();
  }
  let response: Response;
  try {
    response = await fetch(path, { credentials: 'omit', redirect: 'error', cache: 'no-cache' });
  } catch {
    throw unavailable();
  }
  if (!response.ok || response.body === null) throw unavailable();
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > maxBytes) throw unavailable();
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maxBytes) {
      void reader.cancel();
      throw unavailable();
    }
    parts.push(value);
  }
  const bytes = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    bytes.set(part, at);
    at += part.byteLength;
  }
  return bytes;
}

// --- the device's measurement: seconds-as-milliseconds per circuit version, in this origin's IndexedDB only

const CALIBRATION_DATABASE = 'cmsg-prover-calibration';
const CALIBRATION_STORE = 'millis';
const MAX_MILLIS = 3_600_000;
const CIRCUIT_ID = /^[0-9a-f]{64}$/;

function openCalibration(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CALIBRATION_DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(CALIBRATION_STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** The stored measurement of this circuit version, or null (nothing stored, or the store unusable). */
export async function storedMillis(circuitId: string): Promise<number | null> {
  if (!CIRCUIT_ID.test(circuitId)) return null;
  try {
    const db = await openCalibration();
    try {
      const value = await new Promise<unknown>((resolve, reject) => {
        const request = db.transaction(CALIBRATION_STORE, 'readonly').objectStore(CALIBRATION_STORE).get(circuitId);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      return Number.isInteger(value) && (value as number) >= 1 && (value as number) <= MAX_MILLIS ? (value as number) : null;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

/** Keep a measurement; a store that cannot be written only means the device measures again later. */
export async function storeMillis(circuitId: string, millis: number): Promise<void> {
  if (!CIRCUIT_ID.test(circuitId) || !Number.isInteger(millis) || millis < 1 || millis > MAX_MILLIS) return;
  try {
    const db = await openCalibration();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(CALIBRATION_STORE, 'readwrite');
        tx.objectStore(CALIBRATION_STORE).put(millis, circuitId);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  } catch {
    // Not stored: the next idle time calibrates again.
  }
}

// --- the one worker of a proof (or of a calibration, a counterpart verification or a warm-up)

/** `preemptible`: a real proof ends it (calibration, warm-up); `quiet`: no progress reaches the frame. */
type Running = { cancel: () => void; preemptible: boolean };
let running: Running | null = null;
/** Verifications waiting for the device: a counterpart's proof is never refused for a busy device. */
const waiting: (() => void)[] = [];

function release(): void {
  running = null;
  waiting.shift()?.();
}

function timeoutOf(setup: string): number | null {
  try {
    const timeoutMs = (JSON.parse(setup) as { timeout_ms: number }).timeout_ms;
    return Number.isInteger(timeoutMs) && timeoutMs >= 1 ? timeoutMs : null;
  } catch {
    return null;
  }
}

/** The transferred buffer must be exactly the input bytes. */
function transferable(input: Uint8Array): ArrayBuffer {
  return input.byteOffset === 0 && input.byteLength === input.buffer.byteLength
    ? (input.buffer as ArrayBuffer)
    : (input.slice().buffer as ArrayBuffer);
}

type Job = { input: ArrayBuffer } | { verify: { fields: ArrayBuffer; proof: ArrayBuffer } } | { warm: true };

/** Run one worker; resolves to the reply and the milliseconds from "setup ready" to "done". */
function runWorker(
  setup: string,
  job: Job,
  transfer: ArrayBuffer[],
  timeoutMs: number,
  mode: { quiet: boolean; preemptible: boolean },
): Promise<{ reply: string; millis: number }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./prover.worker.js', import.meta.url), { type: 'module', name: 'cmsg-prover' });
    let settled = false;
    let computeStart = performance.now();
    const finish = (error: Error | null, reply?: string, code?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate(); // frees every byte the worker held, including the witness
      release();
      if (error === null) {
        if (!mode.quiet) emit({ stage: 'done' });
        resolve({ reply: reply as string, millis: Math.max(1, Math.round(performance.now() - computeStart)) });
      } else {
        if (!mode.quiet) emit({ stage: 'failed', code: code ?? 'internal' });
        reject(error);
      }
    };
    const timer = setTimeout(() => finish(unavailable(), undefined, 'timeout'), timeoutMs);
    running = { cancel: () => finish(unavailable(), undefined, 'cancelled'), preemptible: mode.preemptible };
    worker.onmessage = (event: MessageEvent<FromWorker>) => {
      const message = event.data;
      if (message.type === 'progress') {
        // The measurement starts when the setup is in the worker's hands: the network is not the device's speed.
        if (message.progress.stage === 'srs-load') computeStart = performance.now();
        if (!mode.quiet) emit(message.progress);
      } else if (message.type === 'done') finish(null, message.reply);
      else finish(unavailable(), undefined, message.code);
    };
    worker.onerror = () => finish(unavailable(), undefined, 'internal');
    worker.onmessageerror = () => finish(unavailable(), undefined, 'internal');
    worker.postMessage({ setup, ...job }, transfer);
  });
}

/** Prove one input in a fresh worker. Resolves to the worker's reply JSON; rejects with a fixed error. */
export function proveInWorker(setup: string, input: Uint8Array): Promise<string> {
  return provedMillis(setup, input).then((done) => done.reply);
}

/** Milliseconds a real proof took, from the setup being in the worker's hands to its reply. */
export function provedMillis(setup: string, input: Uint8Array): Promise<{ reply: string; millis: number }> {
  if (running?.preemptible) running.cancel();
  if (running !== null) return Promise.reject(unavailable());
  const timeoutMs = timeoutOf(setup);
  if (timeoutMs === null) return Promise.reject(unavailable());
  const buffer = transferable(input);
  return runWorker(setup, { input: buffer }, [buffer], timeoutMs, { quiet: false, preemptible: false });
}

/**
 * The counterpart verifier's proof check (cwlt `ProofCheck`): bb.js verifies `proof` for exactly the
 * concatenated 32-byte public `fields` under the verification key of `setup` (the engine took it from
 * the pinned key group). Waits for a running proof instead of refusing; resolves to the verdict.
 */
export async function verifyInWorker(setup: string, fields: Uint8Array, proof: Uint8Array): Promise<boolean> {
  const timeoutMs = timeoutOf(setup);
  if (timeoutMs === null || fields.byteLength % 32 !== 0) return false;
  if (running?.preemptible) running.cancel();
  while (running !== null) await new Promise<void>((resolve) => waiting.push(resolve));
  const fieldBuffer = fields.slice().buffer as ArrayBuffer;
  const proofBuffer = proof.slice().buffer as ArrayBuffer;
  try {
    const { reply } = await runWorker(setup, { verify: { fields: fieldBuffer, proof: proofBuffer } }, [fieldBuffer, proofBuffer], timeoutMs, { quiet: true, preemptible: false });
    return (JSON.parse(reply) as { verified?: unknown }).verified === true;
  } catch {
    return false;
  }
}

/**
 * Warm the device for a coming proof (speculative reservation option (b)): the pinned setup of `setup`
 * is loaded from this origin's verified cache (or fetched from this origin once and cached) and the
 * proof system started, then the worker ends. No witness, no proof, no request beyond this origin.
 * A real proof ends a warm-up at once. False when the device is busy or the warm-up failed.
 */
export async function warmInWorker(setup: string): Promise<boolean> {
  const timeoutMs = timeoutOf(setup);
  if (timeoutMs === null || running !== null) return false;
  try {
    const { reply } = await runWorker(setup, { warm: true }, [], timeoutMs, { quiet: true, preemptible: true });
    return (JSON.parse(reply) as { warm?: unknown }).warm === true;
  } catch {
    return false;
  }
}

/** Withdraw: end the running worker at once. */
export function cancelProof(): void {
  running?.cancel();
}

function idle(): Promise<void> {
  return new Promise((resolve) => {
    const ric = (globalThis as { requestIdleCallback?: (callback: () => void, options: { timeout: number }) => void }).requestIdleCallback;
    // No idle callback (or a page that is never idle): a quiet moment after the first paint.
    if (typeof ric === 'function') ric(() => resolve(), { timeout: 15_000 });
    else setTimeout(resolve, 3_000);
  });
}

let calibrating: Promise<number | null> | null = null;

/**
 * The device's measurement for this circuit version: the stored one, or one calibration proof of the
 * shipped dummy input when the page is idle. Null when a real proof took the device first or the
 * calibration could not finish; the next idle time tries again. Never runs beside another proof.
 */
export function calibrateInWorker(setup: string, circuitId: string, input: Uint8Array): Promise<number | null> {
  calibrating ??= (async () => {
    try {
      const stored = await storedMillis(circuitId);
      if (stored !== null) return stored;
      await idle();
      const timeoutMs = timeoutOf(setup);
      if (running !== null || timeoutMs === null) return null;
      const buffer = transferable(input);
      const { reply, millis } = await runWorker(setup, { input: buffer }, [buffer], timeoutMs, { quiet: true, preemptible: true });
      // A calibration whose proof does not verify measures nothing.
      if ((JSON.parse(reply) as { verified?: boolean }).verified !== true) return null;
      await storeMillis(circuitId, millis);
      return millis;
    } catch {
      return null;
    } finally {
      calibrating = null;
    }
  })();
  return calibrating;
}
