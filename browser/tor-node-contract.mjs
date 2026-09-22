// Exercises the production factory with an explicitly scripted TorJS module.
import { createTorJsOnionNode } from './tor-streams.mjs';
import { configure } from './fixtures/tor-js.mjs';

const ONION = 'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion';
const options = { gateway: ['fixture-gateway'], bootstrapDeadlineMs: 1000, operationDeadlineMs: 30 };
const check = (value, label) => { if (!value) throw new Error('Tor factory contract: ' + label); };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
async function failure(operation, expected = 'cmsg:Transport') {
  try { await operation(); } catch (error) { check(error.message === expected, 'coarse error: ' + error.message); return; }
  throw new Error('Tor factory contract: expected rejection');
}
function raw() {
  return { closed: 0, freed: 0, read: async () => new Uint8Array(), write: async () => {},
    close() { this.closed++; }, free() { this.freed++; } };
}
function service(overrides = {}) {
  return { host: ONION, port: 80, readiness: 'running', closed: 0, freed: 0, accept: async () => raw(),
    close() { this.closed++; }, free() { this.freed++; }, ...overrides };
}
async function tick() { await new Promise(resolve => setTimeout(resolve, 0)); }
// Models an upstream operation blocking the event loop past its own deadline.
// The adapter cannot preempt it but must reject its eventual success.
function blockPastDeadline() {
  const end = performance.now() + 35;
  while (performance.now() < end) { /* bounded synthetic event-loop stall */ }
}

export async function runTorNodeContract() {
  const passed = [];
  let fixture = configure();
  for (const gateway of [undefined, [], [undefined], new Array(1), '', [1]]) {
    await failure(() => createTorJsOnionNode({ ...options, gateway }), 'cmsg:InvalidState');
  }
  for (const operationDeadlineMs of [60_001, 420_000, 600_000]) {
    await failure(() => createTorJsOnionNode({ ...options, operationDeadlineMs }), 'cmsg:InvalidState');
  }
  check(fixture.constructed === 0, 'invalid configuration does not construct a client');
  for (const [behavior, expected] of [
    [() => false, 'cmsg:TorOnionSupportRequired'],
    [() => { throw new Error('private support context'); }, 'cmsg:Transport'],
    [() => new Promise(() => {}), 'cmsg:Transport'],
  ]) {
    fixture = configure({ support: behavior });
    await failure(() => createTorJsOnionNode({ ...options, bootstrapDeadlineMs: 20 }), expected);
    check(fixture.constructed === 0, 'failed capabilities do not construct a client');
  }
  passed.push('scripted Tor factory: configuration and capability failures occur before client creation');

  for (const ready of [() => { throw new Error('private readiness'); }, () => new Promise(() => {})]) {
    fixture = configure({ ready, close: () => { throw new Error('private close'); } });
    await failure(() => createTorJsOnionNode({ ...options, bootstrapDeadlineMs: 20 }));
    check(fixture.closed === 1, 'failed readiness closes exactly once');
  }
  fixture = configure({ construct: blockPastDeadline });
  await failure(() => createTorJsOnionNode({ ...options, bootstrapDeadlineMs: 20 }));
  check(fixture.closed === 1 && fixture.readyCalls === 0, 'construction consumes the same bootstrap deadline');
  passed.push('scripted Tor factory: bootstrap deadline and synchronous errors close with coarse errors');

  const gateways = ['fixture-gateway'];
  const capabilities = deferred();
  fixture = configure({ connect: () => raw(), support: () => capabilities.promise });
  const creating = createTorJsOnionNode({ ...options, gateway: gateways, socketProvider: 'untrusted override' });
  gateways[0] = 'changed-during-bootstrap'; capabilities.resolve(true);
  let node = await creating;
  check(fixture.options.gateway[0] === 'fixture-gateway' && !('socketProvider' in fixture.options), 'entry configuration is copied and scoped');
  for (const host of ['127.0.0.1', '[::1]', 'example.com', 'https://' + ONION, ONION + '/path',
    ONION + '.example.com', 'user@' + ONION, 'a' + ONION.slice(1), ONION + String.fromCharCode(0)]) {
    try { await node.connect(host, 80); throw new Error('accepted invalid host'); }
    catch (error) { check(error.message !== 'accepted invalid host', 'reject invalid peer route'); }
  }
  for (const port of [0, -1, 65536, 1.5, NaN, Infinity]) {
    try { await node.connect(ONION, port); throw new Error('accepted invalid port'); }
    catch (error) { check(error.message !== 'accepted invalid port', 'reject invalid peer port'); }
  }
  check(fixture.calls.length === 0, 'invalid peers never reach TorJS');
  const stream = await node.connect(ONION, 80);
  check(JSON.stringify(fixture.calls) === JSON.stringify([['connect', ONION, 80, 30]]), 'only validated onion and bounded port/deadline reach TorJS');
  stream.close(); node.close(); node.close();
  check(fixture.closed === 1, 'node shutdown idempotent');
  passed.push('scripted Tor factory: contact input cannot select a clearnet route or change entry configuration');

  fixture = configure({ connect: () => { throw new Error('private destination'); } });
  node = await createTorJsOnionNode(options);
  await failure(() => node.connect(ONION, 80));
  await failure(() => node.connect(ONION, 80));
  check(fixture.closed === 1 && fixture.calls.length === 1, 'synchronous connect failure is terminal');
  const blockedRaw = raw();
  fixture = configure({ connect: () => { blockPastDeadline(); return blockedRaw; } });
  node = await createTorJsOnionNode({ ...options, operationDeadlineMs: 20 });
  await failure(() => node.connect(ONION, 80));
  check(fixture.closed === 1 && blockedRaw.closed === 1 && blockedRaw.freed === 1, 'late success rejected even before timer callback runs');
  const delayed = deferred(); const lateRaw = raw();
  lateRaw.close = function () { this.closed++; throw new Error('private late-close context'); };
  fixture = configure({ connect: () => delayed.promise });
  node = await createTorJsOnionNode(options);
  await failure(() => node.connect(ONION, 80));
  delayed.resolve(lateRaw); await tick();
  check(fixture.closed === 1 && lateRaw.closed === 1 && lateRaw.freed === 1, 'late dial result is disposed');
  passed.push('scripted Tor factory: dial failure or deadline cannot retry and late streams are disposed');

  for (const publicationDeadline of [420_000, 600_000]) {
    let acceptDeadline;
    const published = service({ accept: async deadline => { acceptDeadline = deadline; return raw(); } });
    fixture = configure({ listen: () => published });
    node = await createTorJsOnionNode(options);
    for (const deadlineMs of [0, -1, 1.5, NaN, Infinity, 600_001]) {
      await failure(() => node.listen({ port: 80, maximumStreams: 4, deadlineMs }), 'cmsg:InvalidState');
    }
    check(fixture.calls.length === 0, 'invalid publication budgets never reach TorJS or consume the launch');
    const listener = await node.listen({ port: 80, maximumStreams: 4, deadlineMs: publicationDeadline });
    check(JSON.stringify(fixture.calls) === JSON.stringify([['listen', 80, 4, publicationDeadline]]),
      'explicit publication budget reaches TorJS without a stream-deadline clamp');
    const accepted = await listener.accept();
    check(acceptDeadline === Math.floor(options.operationDeadlineMs / 2), 'idle poll stays within the outer stream watchdog');
    accepted.close(); listener.close(); node.close();
  }
  passed.push('scripted Tor factory: publication supports its separate bounded retry budget while stream limits remain short');

  let idlePolls = 0;
  const idleService = service({ accept: async () => { await tick(); return ++idlePolls <= 2 ? null : raw(); } });
  fixture = configure({ listen: () => idleService }); node = await createTorJsOnionNode(options);
  const idleListener = await node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 });
  const afterIdle = await idleListener.accept();
  check(idlePolls === 3 && fixture.closed === 0 && idleService.closed === 0, 'ordinary idle polls retain the live service');
  afterIdle.close(); idleListener.close(); node.close();
  passed.push('scripted Tor factory: idle service can accept a later conversation');

  for (const readiness of ['running', 'degraded-reachable']) {
    const published = service({ readiness });
    fixture = configure({ listen: () => published });
    node = await createTorJsOnionNode(options);
    const listener = await node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 });
    check(listener.readiness === readiness, 'startup degradation is exposed without relabeling');
    published.readiness = 'broken';
    check(listener.readiness === readiness, 'readiness is a captured startup snapshot, not a live health claim');
    listener.close(); node.close();
  }
  for (const readiness of [undefined, 'bootstrapping', 'degraded-unreachable', 'recovering', 'broken', 'shutdown', 'unknown']) {
    const unavailable = service({ readiness });
    fixture = configure({ listen: () => unavailable });
    node = await createTorJsOnionNode(options);
    await failure(() => node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 }));
    check(fixture.closed === 1 && unavailable.closed === 1 && unavailable.freed === 1,
      'unavailable or unknown service status closes and frees its handle');
  }
  const throwingStatus = service();
  Object.defineProperty(throwingStatus, 'readiness', { get() { throw new Error('private service status'); } });
  fixture = configure({ listen: () => throwingStatus });
  node = await createTorJsOnionNode(options);
  await failure(() => node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 }));
  check(fixture.closed === 1 && throwingStatus.closed === 1 && throwingStatus.freed === 1,
    'status getter errors remain coarse and dispose the service');
  passed.push('scripted Tor factory: fully reachable readiness snapshots preserve degradation and reject all unavailable states');

  for (const invalid of [{ host: '127.0.0.1' }, { port: 81 }]) {
    const bad = service(invalid); fixture = configure({ listen: () => bad });
    node = await createTorJsOnionNode(options);
    await failure(() => node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 }));
    check(fixture.closed === 1 && bad.closed === 1 && bad.freed === 1, 'invalid published endpoint disposed');
  }
  const publication = deferred(); const lateService = service();
  fixture = configure({ listen: () => publication.promise }); node = await createTorJsOnionNode(options);
  const pending = node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 });
  await failure(() => node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 }), 'cmsg:InvalidState');
  await failure(() => pending); publication.resolve(lateService); await tick();
  check(fixture.calls.length === 1 && lateService.closed === 1 && lateService.freed === 1, 'one launch and late service cleanup');
  passed.push('scripted Tor factory: onion publication validates the endpoint and reserves one bounded launch');

  const acceptance = deferred(); const lateAccepted = raw(); const listenerService = service({ accept: () => acceptance.promise });
  fixture = configure({ listen: () => listenerService }); node = await createTorJsOnionNode(options);
  const listener = await node.listen({ port: 80, maximumStreams: 4, deadlineMs: 30 });
  await failure(() => listener.accept()); acceptance.resolve(lateAccepted); await tick();
  check(fixture.closed === 1 && listenerService.closed === 1 && lateAccepted.closed === 1 && lateAccepted.freed === 1, 'accept watchdog closes and disposes late stream');
  passed.push('scripted Tor factory: accept has an independent deadline and late-result cleanup');
  return passed;
}
