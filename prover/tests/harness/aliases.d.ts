// The two module names build-probe.mjs aliases when it bundles the probe page.
declare module 'cmsg-glue' {
  export default function init(options: { module_or_path: URL | string }): Promise<unknown>;
  export function probe_prove(deployment: string, publicJson: string, input: string): Promise<string>;
  export function probe_calibrate(deployment: string): Promise<string>;
  export function probe_setup(deployment: string): Promise<string>;
  export function probe_wave_prove(deployment: string, program: string, input: string): Promise<string>;
  export function probe_wave_check(deployment: string, program: string, fields: string, proof: string): Promise<boolean>;
  export function probe_wave_verify(
    deployment: string, policy: string, now: bigint, authorityUntil: bigint, kind: string, statement: string,
    proof: string, expected: string, expectedOutcome: string, receiptDigest: string,
  ): Promise<string>;
  export function probe_wave_prewarm(deployment: string): Promise<boolean>;
}
