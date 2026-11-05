// The wallet-origin test page of the wasm probe: it loads the REAL cmsg wasm (built with the
// `browser-prover-probe` feature) and drives the same Rust prover path the wallet frame lends:
// deployed material fetched and checked against pinned digests, public inputs derived by the
// engine, the Web Worker, and the engine's check of the reply. It knows no key and no vault.
// The two aliases are filled in by build-probe.mjs: the generated glue and its copy of the
// frame-host glue (the snippet the Rust side imports, so the page shares its state: the running
// worker and the member's one-shot permission).
import init, { probe_prove, probe_calibrate, probe_setup, probe_wave_prove, probe_wave_check, probe_wave_verify, probe_wave_prewarm } from 'cmsg-glue';
import { ALLOW_SLOW_EVENT, PROGRESS_EVENT, cancelProof, storeMillis, storedMillis } from 'cmsg-prover-snippet';

const events: unknown[] = [];
// Each event keeps when the page saw it (milliseconds of this page), for the timing runs.
addEventListener(PROGRESS_EVENT, (event) => events.push({ ...(event as CustomEvent).detail, at: performance.now() }));

const outcome = async <T>(run: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> => {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
};

await init({ module_or_path: new URL('./cmsg_bg.wasm', import.meta.url) });
Object.assign(window, {
  probe: {
    events,
    isolated: self.crossOriginIsolated,
    cancel: cancelProof,
    setup: (deployment: string) => outcome(() => probe_setup(deployment)),
    prove: (deployment: string, publicJson: string, input: string) => outcome(() => probe_prove(deployment, publicJson, input)),
    calibrate: (deployment: string) => outcome(() => probe_calibrate(deployment)),
    // The browser wave stack: wave/outcome proofs, the counterpart check and verifier, the compose warm-up.
    waveProve: (deployment: string, program: string, input: string) => outcome(() => probe_wave_prove(deployment, program, input)),
    waveCheck: (deployment: string, program: string, fields: string, proof: string) => outcome(() => probe_wave_check(deployment, program, fields, proof)),
    waveVerify: (deployment: string, policy: string, now: string, until: string, kind: string, statement: string, proof: string, expected: string, expectedOutcome: string, receipt: string) =>
      outcome(() => probe_wave_verify(deployment, policy, BigInt(now), BigInt(until), kind, statement, proof, expected, expectedOutcome, receipt)),
    wavePrewarm: (deployment: string) => outcome(() => probe_wave_prewarm(deployment)),
    stored: storedMillis,
    store: storeMillis,
    /** What the wallet frame's own "Try anyway" button does. */
    allowSlow: () => dispatchEvent(new CustomEvent(ALLOW_SLOW_EVENT)),
  },
});
