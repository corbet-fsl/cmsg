// The proving Web Worker, started by the frame host for ONE proof and ended right after it.
// It receives the public setup and the private witness input, runs the witness execution
// (noir_js) and the proof system (bb.js) with the pinned setup, verifies the proof and answers
// with the proof and its public inputs. It reads nothing from any origin but its own, it keeps
// nothing but the verified setup cache, and every failure is one code from a closed list.
// The logic (what is trusted, what must match) lives in the Rust engine; this is thin glue.
import { Barretenberg } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import initACVM from '@noir-lang/acvm_js';
import initABI from '@noir-lang/noirc_abi';
import { cacheExpanded, hex, loadSrs } from './srs.js';
import { Failure, type FailureCode, type FromWorker, type Progress, type Setup, type ToWorker } from './wire.js';

// The proof settings of the native worker: poseidon2 oracle hash, zero knowledge on, no IPA.
const SETTINGS = { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false };

// Set only by the test build (build.mjs --page): shows why a proof failed in the console of the test browser.
declare const __PROVER_DEBUG__: boolean;

const post = (message: FromWorker) => (self as unknown as Worker).postMessage(message);
const report = (progress: Progress) => post({ type: 'progress', progress });

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
const unhex = (text: string): Uint8Array => {
  if (text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) throw new Failure('setup');
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
};

function parseSetup(text: string): Setup {
  let setup: Setup;
  try {
    setup = JSON.parse(text) as Setup;
  } catch {
    throw new Failure('setup');
  }
  const srs = setup?.srs;
  if (
    setup?.version !== 1 ||
    typeof setup.circuit?.bytecode !== 'string' ||
    typeof setup.verification_key !== 'string' ||
    !srs ||
    !Number.isInteger(srs.points) ||
    srs.points < 1 ||
    typeof srs.g1_path !== 'string' ||
    typeof srs.g2_path !== 'string' ||
    !Number.isInteger(setup.max_threads) ||
    setup.max_threads < 1
  ) {
    throw new Failure('setup');
  }
  return setup;
}

async function run(setupText: string, buffer: ArrayBuffer): Promise<string> {
  const setup = parseSetup(setupText);
  report({ stage: 'start' });
  const view = new Uint8Array(buffer);
  let input: unknown;
  try {
    input = JSON.parse(new TextDecoder().decode(view));
  } catch {
    throw new Failure('witness');
  } finally {
    view.fill(0); // the received private bytes; the parsed copy dies with this worker
  }

  const srs = await loadSrs(setup.srs, report);
  report({ stage: 'srs-load', cached: srs.expanded });
  await Promise.all([
    initACVM({ module_or_path: new URL('./acvm_js_bg.wasm', import.meta.url) }),
    initABI({ module_or_path: new URL('./noirc_abi_wasm_bg.wasm', import.meta.url) }),
  ]);
  // Threads only on a cross-origin isolated page; otherwise one thread (no headers are added).
  const threads = self.crossOriginIsolated ? Math.max(1, Math.min(setup.max_threads, navigator.hardwareConcurrency || 1)) : 1;
  // skipSrsInit: bb.js would otherwise download its own setup from a third-party CDN.
  // The wasm is a plain file next to this worker (bb.js would otherwise fetch an inline data: URL).
  const wasmPath = new URL('./barretenberg.wasm.gz', import.meta.url).href;
  const api = await Barretenberg.new({ threads, skipSrsInit: true, wasmPath, logger: () => {} });
  try {
    const initialised = await api.srsInitSrs({ pointsBuf: srs.g1, numPoints: setup.srs.points, g2Point: srs.g2 });
    if (!srs.expanded) await cacheExpanded(setup.srs, initialised.pointsBuf);

    report({ stage: 'witness' });
    let witness: Uint8Array;
    try {
      const noir = new Noir(setup.circuit as ConstructorParameters<typeof Noir>[0]);
      witness = (await noir.execute(input as Parameters<Noir['execute']>[0])).witness;
    } catch {
      throw new Failure('witness');
    }
    const bytecode = await gunzip(Uint8Array.from(atob(setup.circuit.bytecode), (c) => c.charCodeAt(0)));
    const verificationKey = unhex(setup.verification_key);
    report({ stage: 'prove', threads });
    let proved: Awaited<ReturnType<typeof api.circuitProve>>;
    try {
      proved = await api.circuitProve({
        circuit: { name: setup.program, bytecode, verificationKey },
        witness: await gunzip(witness),
        settings: SETTINGS,
      });
    } catch {
      throw new Failure('prove');
    }
    report({ stage: 'verify' });
    let verified: boolean;
    try {
      verified = (
        await api.circuitVerify({ verificationKey, publicInputs: proved.publicInputs, proof: proved.proof, settings: SETTINGS })
      ).verified;
    } catch {
      throw new Failure('verify');
    }
    const proof = new Uint8Array(proved.proof.length * 32);
    proved.proof.forEach((field, index) => proof.set(field, index * 32));
    return JSON.stringify({ verified, public_inputs: proved.publicInputs.map(hex), proof: hex(proof) });
  } finally {
    await api.destroy().catch(() => {});
  }
}

self.onmessage = (event: MessageEvent<ToWorker>) => {
  const { setup, input } = event.data;
  run(setup, input).then(
    (reply) => post({ type: 'done', reply }),
    (error: unknown) => {
      if (__PROVER_DEBUG__) console.error('prover worker failed:', error);
      const code: FailureCode = error instanceof Failure ? error.code : 'internal';
      post({ type: 'error', code });
    },
  );
};
