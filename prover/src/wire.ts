// The messages between the frame host and the proving Web Worker, and the fixed vocabulary of
// stages and failure codes. Nothing here carries a value of the witness: a progress event names
// a stage and byte counts, a failure names one code from the closed list below.

/** Stages a proof passes through, in order. */
export type Stage =
  | 'start'
  | 'srs-fetch'
  | 'srs-verify'
  | 'srs-cache'
  | 'srs-load'
  | 'witness'
  | 'prove'
  | 'verify'
  | 'done'
  | 'failed';

/** Closed list of failure codes. No message text ever leaves the worker. */
export type FailureCode =
  | 'setup'
  | 'srs_fetch'
  | 'srs_digest'
  | 'witness'
  | 'prove'
  | 'verify'
  | 'timeout'
  | 'cancelled'
  | 'busy'
  | 'internal';

export interface Progress {
  stage: Stage;
  /** Bytes received so far (srs-fetch only). */
  loaded?: number;
  /** Bytes expected (srs-fetch only). */
  total?: number;
  /** The failure code (stage `failed` only). */
  code?: FailureCode;
  /** Whether the setup came from the verified IndexedDB cache (stage `srs-load` only). */
  cached?: boolean;
  /** Threads the proof system runs with (stage `prove` only). */
  threads?: number;
}

/** The public setup the engine hands over (`BrowserProver::setup_json`). */
export interface Setup {
  version: 1;
  program: string;
  circuit: { bytecode: string; abi: unknown };
  /** Hex of the program's verification key. */
  verification_key: string;
  srs: {
    g1_path: string;
    g2_path: string;
    points: number;
    g1_sha256: string;
    g1_expanded_sha256: string;
    g2_sha256: string;
  };
  timeout_ms: number;
  max_threads: number;
}

export type ToWorker = { setup: string; input: ArrayBuffer };
export type FromWorker =
  | { type: 'progress'; progress: Progress }
  | { type: 'done'; reply: string }
  | { type: 'error'; code: FailureCode };

/** The event the host dispatches on the frame's window for every progress step. */
export const PROGRESS_EVENT = 'cmsg:prover';

export class Failure extends Error {
  constructor(readonly code: FailureCode) {
    super(code);
  }
}
