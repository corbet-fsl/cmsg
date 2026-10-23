// Frame-host glue of the browser prover (imported by prover.rs). It owns the life of ONE
// proving Web Worker per proof: it starts it from this origin, hands it the public setup and the
// private input once (the input's buffer is transferred, so this thread keeps no copy), ends it
// when the proof is done, fails or times out, and forwards progress to the frame host as events
// on the frame's window. No value of the witness appears in an event; a failure is one fixed
// code. The worker file is built by cmsg/prover/build.mjs and sits next to this bundle.

type Progress = { stage: string; loaded?: number; total?: number; code?: string; cached?: boolean; threads?: number };
type FromWorker =
  | { type: 'progress'; progress: Progress }
  | { type: 'done'; reply: string }
  | { type: 'error'; code: string };

export const PROGRESS_EVENT = 'cmsg:prover';

const unavailable = () => new Error('cmsg:Unavailable');

function emit(progress: Progress): void {
  if (typeof globalThis.dispatchEvent === 'function' && typeof CustomEvent === 'function') {
    globalThis.dispatchEvent(new CustomEvent(PROGRESS_EVENT, { detail: progress }));
  }
}

let running: { cancel: () => void } | null = null;

/** Prove one input in a fresh worker. Resolves to the worker's reply JSON; rejects with a fixed error. */
export function proveInWorker(setup: string, input: Uint8Array): Promise<string> {
  if (running !== null) return Promise.reject(unavailable());
  let timeoutMs: number;
  try {
    timeoutMs = (JSON.parse(setup) as { timeout_ms: number }).timeout_ms;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new Error();
  } catch {
    return Promise.reject(unavailable());
  }
  // The transferred buffer must be exactly the input bytes.
  const buffer =
    input.byteOffset === 0 && input.byteLength === input.buffer.byteLength
      ? (input.buffer as ArrayBuffer)
      : (input.slice().buffer as ArrayBuffer);
  return new Promise<string>((resolve, reject) => {
    const worker = new Worker(new URL('./prover.worker.js', import.meta.url), { type: 'module', name: 'cmsg-prover' });
    let settled = false;
    const finish = (error: Error | null, reply?: string, code?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate(); // frees every byte the worker held, including the witness
      running = null;
      if (error === null) {
        emit({ stage: 'done' });
        resolve(reply as string);
      } else {
        emit({ stage: 'failed', code: code ?? 'internal' });
        reject(error);
      }
    };
    const timer = setTimeout(() => finish(unavailable(), undefined, 'timeout'), timeoutMs);
    running = { cancel: () => finish(unavailable(), undefined, 'cancelled') };
    worker.onmessage = (event: MessageEvent<FromWorker>) => {
      const message = event.data;
      if (message.type === 'progress') emit(message.progress);
      else if (message.type === 'done') finish(null, message.reply);
      else finish(unavailable(), undefined, message.code);
    };
    worker.onerror = () => finish(unavailable(), undefined, 'internal');
    worker.onmessageerror = () => finish(unavailable(), undefined, 'internal');
    worker.postMessage({ setup, input: buffer }, [buffer]);
  });
}

/** Withdraw: end the running worker at once. */
export function cancelProof(): void {
  running?.cancel();
}
