import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { compile } from 'json-schema-to-typescript';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('Usage: generate.mjs registry.json output-directory');
const registry = JSON.parse(await readFile(input, 'utf8'));
await mkdir(output, { recursive: true });
const types = [];
const names = [];
const versions = {};
for (const action of registry.actions) {
  const name = action.action.split('.').map(part => part[0].toUpperCase() + part.slice(1)).join('');
  const body = await compile({ ...action.body, title: 'Body' }, 'Body', { bannerComment: '' });
  const result = await compile({ ...action.result, title: 'Result' }, 'Result', { bannerComment: '' });
  types.push(`export namespace ${name} {\n${body}\n${result}\n}`);
  names.push(`  ${JSON.stringify(action.action)}: { body: ${name}.Body; result: ${name}.Result };`);
  versions[action.action] = action.version;
}
for (const [name, schema] of Object.entries(registry.types ?? {})) {
  types.push(await compile({ ...schema, title: name }, name, { bannerComment: '' }));
}
const outputType = await compile(registry.output, 'Output', { bannerComment: '' });
const invocation = await compile(registry.invocation, 'Invocation', { bannerComment: '' });
const source = `// Generated from cmsg's Rust registry. Do not edit.\n${types.join('\n')}\n${outputType}\n${invocation}
export interface Actions {\n${names.join('\n')}\n}
export const actionVersions = ${JSON.stringify(versions, null, 2)} as const;
export type Transport = (request: Invocation) => Promise<Output>;
export type ActionOutput<K extends keyof Actions> =
  | (Omit<Extract<Output, { status: 'ok' }>, 'result'> & { result: Actions[K]['result'] })
  | Extract<Output, { status: 'error' }>;
export class CmsgError extends Error {
  constructor(public readonly code: Extract<Output, { status: 'error' }>['error']) {
    super(code);
    this.name = 'CmsgError';
  }
}
export type ClientEvent = Extract<Output, { status: 'ok' }>['events'][number];
export function createCmsgClient(transport: Transport, lifecycle?: { dispose(): Promise<void> }) {
  const listeners = new Set<(event: ClientEvent) => void>();
  let closed = false;
  let disposal: Promise<void> | undefined;
  async function invoke<K extends keyof Actions>(action: K, body: Actions[K]['body']): Promise<ActionOutput<K>> {
    if (closed) return { status: 'error', error: 'unavailable' } as ActionOutput<K>;
    const response = await transport({ action, version: actionVersions[action], body }) as ActionOutput<K>;
    if (response.status === 'ok') {
      for (const event of response.events) for (const listener of [...listeners]) {
        // Observers cannot turn an accepted child effect into an action failure.
        try { listener(event); } catch { /* The observer owns its own failure. */ }
      }
    }
    return response;
  }
  return {
    invoke,
    subscribe(listener: (event: ClientEvent) => void): () => void {
      if (!closed) listeners.add(listener);
      return () => { listeners.delete(listener); };
    },
    dispose(): Promise<void> {
      closed = true;
      disposal ??= Promise.resolve().then(() => lifecycle?.dispose()).finally(() => listeners.clear());
      return disposal;
    },
    async call<K extends keyof Actions>(action: K, body: Actions[K]['body']): Promise<Actions[K]['result']> {
      const response = await invoke(action, body);
      if (response.status === 'error') throw new CmsgError(response.error);
      return response.result as Actions[K]['result'];
    }
  };
}
`;
await writeFile(`${output}/client.ts`, source);
await writeFile(`${output}/package.json`, `${JSON.stringify({ type: 'module' })}\n`);
const browserTemplate = await readFile(new URL('./browser.ts', import.meta.url), 'utf8');
await writeFile(`${output}/browser.ts`, browserTemplate.replace('__BRIDGE_PROTOCOL__', JSON.stringify(registry.bridge)));
for (const key of ['openapi', 'mcp', 'cli']) {
  await writeFile(`${output}/${key}.json`, `${JSON.stringify(registry[key], null, 2)}\n`);
}
await writeFile(`${output}/registry.json`, `${JSON.stringify(registry, null, 2)}\n`);
