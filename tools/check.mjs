import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';

const registry = JSON.parse(await readFile(process.argv[2], 'utf8'));
const ajv = new Ajv2020({ strict: false });
for (const schema of Object.values(registry.types ?? {})) ajv.compile(schema);
for (const action of registry.actions) {
  for (const name of ['body', 'result', 'event', 'error']) ajv.compile(action[name]);
  const route = `/v${action.version}/${action.action}`;
  const operation = registry.openapi.paths[route].post;
  const tool = registry.mcp.tools.find(tool => tool.name === action.action);
  assert.deepEqual(tool.inputSchema, action.body);
  const response = operation.responses['200'].content['application/json'].schema;
  assert.deepEqual(tool.outputSchema, response);
  const validate = ajv.compile(response);
  assert.equal(validate({ status: 'error', error: 'unauthorized' }), true);
  assert.equal(validate({ status: 'error', error: 'made_up_error' }), false);
  assert.equal(validate({ status: 'ok', result: null, events: [] }), false);
  assert.equal(validate({ status: 'ok', result: null }), false);
}
const output = ajv.compile(registry.output);
assert.equal(output({ status: 'error', error: 'unavailable' }), true);
assert.equal(output({ status: 'error', error: 'fixture_success' }), false);
console.log(`Validated ${registry.actions.length} generated action schemas and their refusal envelopes.`);
