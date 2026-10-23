// The two module names build-probe.mjs aliases when it bundles the probe page.
declare module 'cmsg-glue' {
  export default function init(options: { module_or_path: URL | string }): Promise<unknown>;
  export function probe_prove(deployment: string, publicJson: string, input: string): Promise<string>;
  export function probe_calibrate(deployment: string): Promise<string>;
  export function probe_setup(deployment: string): Promise<string>;
}
