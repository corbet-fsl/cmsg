// Genuine Tor/Arti network fixture. Every identity and payload is synthetic.
import { init, BrowserIdentity, BrowserMember, BrowserOnionEndpoint } from '../index.mjs';
import { OnionFramedStream } from '../internal/streams.mjs';
import { TorClient, Log, storage, KpsGateway } from '/torjs/entryPoints/wasm-file/index.js';

const encode = value => new TextEncoder().encode(value);
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const same = (a, b) => a.length === b.length && a.every((n, i) => n === b[i]);
function check(ok, label) { if (!ok) throw new Error(`Tor runtime fixture: ${label}`); }
async function bounded(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Tor runtime fixture deadline')), ms);
  })]); } finally { clearTimeout(timer); }
}

async function syntheticMember() {
  const seed = new Uint8Array(32).fill(17);
  const pkcs8 = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, ...seed]);
  const signer = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', signer);
  const publicKey = Uint8Array.from(atob(jwk.x.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  const trust = { community_id: 'synthetic-community', policy_digest: b64(new Uint8Array(32).fill(42)), issuer_public_key: [...publicKey] };
  const identity = new BrowserIdentity(trust.community_id);
  const member = new BrowserMember();
  const key = member.chatPublicKey();
  const grant = { version: 1, issuerKeyId: b64(new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey))),
    communityId: trust.community_id, memberId: identity.memberId(), chatPublicKey: b64(key),
    policyDigest: trust.policy_digest, issuedAt: 1, expiresAt: 9_000_000_000 };
  const canonical = ['cvld.admission.v1', grant.issuerKeyId, grant.communityId, grant.memberId,
    grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt];
  grant.signature = b64(new Uint8Array(await crypto.subtle.sign('Ed25519', signer, encode(JSON.stringify(canonical)))));
  member.bindDeviceAdmission(JSON.stringify(grant), JSON.stringify(trust), identity.authorizeDevice(key, 1, 9_000_000_000));
  seed.fill(0); pkcs8.fill(0); identity.free();
  return member;
}

export async function runTorRuntimeContract() {
  const progress = { network: 'unselected', testNetworkOnly: null, stage: 'initialization',
    phaseDurationsMs: {}, passed: [], failed: [] };
  let phaseStarted = performance.now();
  function stage(value) {
    progress.phaseDurationsMs[progress.stage] = Math.round(performance.now() - phaseStarted);
    progress.stage = value;
    phaseStarted = performance.now();
  }
  globalThis.__cmsgTorRuntime = progress;
  await init({ module_or_path: new URL('../pkg/cmsg_bg.wasm', import.meta.url) });
  const fixture = await (await fetch('/fixture.json', { cache: 'no-store' })).json();
  const publicNetwork = fixture.network === 'public';
  const renewal = fixture.renewal !== undefined;
  check(!renewal || (!publicNetwork && fixture.renewal.waitMs === 900_000
    && fixture.renewal.heartbeatMs === 15_000), 'bounded private-only renewal configuration');
  check(fixture.testOnly === true, 'disposable test participants');
  if (publicNetwork) {
    check(!Object.hasOwn(fixture, 'arti') && fixture.testNetworkFeature === false
      && fixture.vanguards === 'full', 'public service build without injected Tor configuration');
  } else {
    check(fixture.network === undefined && fixture.arti.vanguards.mode === 'full',
      'isolated full-vanguard configuration');
  }
  progress.network = publicNetwork ? 'public' : 'private';
  progress.testNetworkOnly = !publicNetwork;
  check(await TorClient.onionClientSupported() && await TorClient.onionStreamSupported()
    && await TorClient.onionServiceSupported(), 'actual Wasm capabilities');
  const clients = [];
  const services = [];
  const framed = [];
  const passed = progress.passed;
  const members = [];
  try {
    stage('gateway-non-relay-rejection');
    check(/^127\.0\.0\.1:\d+$/.test(fixture.nonRelayCanary), 'owned loopback canary');
    const gateway = new KpsGateway(fixture.gateway);
    let forbidden = false;
    progress.gatewayCanary = 'pending';
    try {
      const socket = await bounded(gateway.connect(fixture.nonRelayCanary, {
        signal: AbortSignal.timeout(15_000),
      }), 20_000);
      socket.close();
      progress.gatewayCanary = 'unexpected-tunnel';
    } catch (error) {
      const detail = String(error);
      const refusal = publicNetwork ? 'connections to local addresses are forbidden'
        : 'target is not an advertised Tor relay';
      forbidden = detail === `Error: CONNECT ${fixture.nonRelayCanary}: 403 ${refusal}`;
      progress.gatewayCanary = forbidden ? 'expected-403'
        : /timed out|deadline/i.test(detail) ? 'deadline'
        : /framing|body|response head/i.test(detail) ? 'response-framing'
        : 'other-error';
    } finally { gateway.close(); }
    const canaryUntouched = (await (await fetch('/__canary', { cache: 'no-store' })).json()).connections === 0;
    if (forbidden && canaryUntouched) {
      passed.push(publicNetwork
        ? 'actual browser WebRTC/KPS local-address CONNECT rejected with 403 and zero owned canary connections'
        : 'actual browser WebRTC/KPS non-relay CONNECT rejected with 403 and zero owned canary connections');
    } else {
      // Retain failure and continue independent service diagnostics. The final
      // result still fails unless exact 403 AND zero connections were observed.
      progress.failed.push('real KPS non-relay 403 with zero canary connections was not verified');
    }
    if (publicNetwork) {
      stage('gateway-public-non-relay-rejection');
      check(fixture.publicNonRelay === '192.0.2.1:1', 'fixed documentation-range non-relay target');
      const publicGateway = new KpsGateway(fixture.gateway);
      let rejected = false;
      try {
        const socket = await bounded(publicGateway.connect(fixture.publicNonRelay, {
          signal: AbortSignal.timeout(15_000),
        }), 20_000);
        socket.close();
      } catch (error) {
        rejected = String(error) === `Error: CONNECT ${fixture.publicNonRelay}: 403 target is not an advertised Tor relay`;
      } finally { publicGateway.close(); }
      check(rejected, 'public gateway requires advertised relay even for a nonlocal address');
      passed.push('actual browser KPS nonlocal non-relay CONNECT rejected with exact 403');
    }
    function newClient() {
      const client = new TorClient({ gateway: fixture.gateway,
        ...(publicNetwork ? {} : { testNetwork: JSON.stringify(fixture.arti) }),
        storage: new storage.MemoryStorage(),
        log: new Log({ rawLog: () => {} }), logLevel: 'error' });
      clients.push(client);
      return client;
    }
    stage('client-bootstrap');
    for (let i = 0; i < 2; i++) newClient();
    await bounded(Promise.all(clients.map(c => c.ready())), 360_000);
    passed.push(publicNetwork ? 'two browser Arti clients bootstrapped on public signed Tor network'
      : 'two browser Arti clients bootstrapped on isolated signed Tor network');
    stage('wasm-onion-route-validation');
    for (const host of [fixture.nonRelayCanary, '127.0.0.1', '[::1]', 'https://example.invalid/',
      'a'.repeat(56) + '.onion', 'example.invalid\r\nHost: 127.0.0.1']) {
      let rejected = false;
      try {
        const stream = await bounded(clients[0].connectOnion(host, 80, 1_000), 2_000);
        stream.close(); stream.free();
      } catch (error) { rejected = String(error) === 'tor-js:OnionTransport'; }
      check(rejected, 'actual Wasm rejects invalid route with coarse error');
    }
    check((await (await fetch('/__canary', { cache: 'no-store' })).json()).connections === 0,
      'invalid contact routes did not reach the canary');
    passed.push('actual Wasm rejects IP, URL, malformed onion and injected route inputs before connection');
    stage('wasm-publication-deadline-validation');
    for (const deadline of [0, -1, 0.5, NaN, Infinity, 600_001]) {
      let rejected = false;
      try {
        const service = await bounded(clients[0].hostOnion(80, 4, deadline), 2_000);
        service.close(); service.free();
      } catch (error) { rejected = String(error) === 'tor-js:OnionService'; }
      check(rejected, 'actual Wasm rejects invalid publication deadline before launch');
    }
    const publicationDeadlineMs = publicNetwork ? 420_000 : 60_000;
    progress.publicationDeadlineMs = publicationDeadlineMs;
    progress.serviceReadiness = [];
    async function publish(index) {
      stage(`service-publication-${index}`);
      try {
        const service = await bounded(clients[index].hostOnion(80, 4, publicationDeadlineMs), publicationDeadlineMs + 5_000);
        services.push(service);
        const readiness = service.readiness;
        check(readiness === 'running' || readiness === 'degraded-reachable', 'actual Wasm reports its accepted readiness snapshot');
        progress.serviceReadiness.push({ service: index, readiness });
        new BrowserOnionEndpoint(service.host, service.port).free();
      } catch (error) {
        const label = String(error);
        // Diagnostic builds return static categories only. Never retain an
        // arbitrary upstream exception as service diagnostic metadata.
        if (/^tor-js:OnionService:[a-z0-9=:/-]{1,512}$/.test(label)) {
          progress.serviceDiagnostic = label;
        }
        throw error;
      }
    }
    await publish(0);
    passed.push('actual Wasm rejects invalid publication budgets and preserves the valid one-service launch');
    async function nativeExchange(label) {
      stage(`${label}-connection`);
      const incoming = services[0].accept(60_000);
      const native = fetch('/__native-peer', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ host: services[0].host, port: 80 }) }).then(async r => {
          if (!r.ok) throw new Error('native fixture failed');
          return r.json();
        });
      // Attach immediately; the native task remains independently bounded by CI.
      native.catch(() => {});
      const peer = new OnionFramedStream(await bounded(incoming, 65_000), 60_000);
      framed.push(peer);
      stage(`${label}-mls`);
      const member = await syntheticMember();
      members.push(member);
      member.createGroup();
      const invitation = member.add(await peer.receive());
      try { await peer.send(invitation.welcome); } finally { invitation.free(); }
      const ciphertext = await peer.receive();
      const received = member.receive(ciphertext);
      try {
        check(received.kind === 'bytes' && same(received.bytes, [0, 255, 128, 7, 0, 9]), 'native MLS ciphertext authenticated');
      } finally { received.free(); }
      let replay = false;
      try { member.receive(ciphertext).free(); } catch { replay = true; }
      check(replay, 'native ciphertext replay rejected');
      await peer.send(member.sendBytes(new Uint8Array([254, 0, 129, 4, 0, 3])));
      check(same(await peer.receive(), encode('cmsg-native-verified')), 'native peer verified browser ciphertext');
      const evidence = await bounded(native, 125_000);
      check(evidence.nativeFramedStream && evidence.rootAuthorizedMlsBinaryBothDirections, 'native process evidence');
      peer.close();
      return evidence;
    }
    const nativeEvidence = await nativeExchange('native-peer');
    progress.nativePeer = nativeEvidence;
    passed.push('browser/native Tor FramedStream and root-authorized MLS binary both directions, replay rejected');
    await publish(1);
    check(services[0].host !== services[1].host, 'distinct ephemeral onion identities');
    passed.push('two browser-owned onion services published with full vanguards');
    stage('browser-onion-stream');
    const [dialled, accepted] = await bounded(Promise.all([
      clients[0].connectOnion(services[1].host, 80, 60_000), services[1].accept(60_000),
    ]), 65_000);
    const left = new OnionFramedStream(dialled, 60_000);
    const right = new OnionFramedStream(accepted, 60_000);
    framed.push(left, right);
    await left.send(new Uint8Array([0, 128, 255, 0, 9]));
    check(same(await right.receive(), [0, 128, 255, 0, 9]), 'browser outgoing onion bytes');
    await right.send(new Uint8Array([253, 129, 0, 1]));
    check(same(await left.receive(), [253, 129, 0, 1]), 'browser return onion bytes');
    if (!renewal) { left.close(); right.close(); }
    passed.push('actual browser onion dial/accept and bidirectional cmsg framing');

    if (renewal) {
      function snapshot(service) {
        check(typeof service.publicationSnapshot === 'function', 'per-service publication diagnostics are present');
        const value = JSON.parse(service.publicationSnapshot());
        check(value && Object.keys(value).sort().join(',') === 'currentPeriod,latestSuccessfulPeriod,successfulBatches'
          && Number.isSafeInteger(value.successfulBatches) && value.successfulBatches > 0
          && value.successfulBatches <= 0xffff_ffff
          && Number.isSafeInteger(value.currentPeriod) && value.currentPeriod >= 0
          && Number.isSafeInteger(value.latestSuccessfulPeriod) && value.latestSuccessfulPeriod >= 0,
        'exact bounded per-service publication evidence');
        return value;
      }
      async function authenticatedChannel(outgoing, incoming) {
        const sender = await syntheticMember();
        members.push(sender);
        const receiver = await syntheticMember();
        members.push(receiver);
        sender.createGroup();
        await incoming.send(receiver.keyPackage());
        const invitation = sender.add(await outgoing.receive());
        try { await outgoing.send(invitation.welcome); } finally { invitation.free(); }
        receiver.join(await incoming.receive());
        let sequence = 0;
        return async function exchange() {
          const current = ++sequence;
          check(current < 65536, 'bounded authenticated heartbeat count');
          const request = new Uint8Array([0, current >>> 8, current & 255, 255]);
          await outgoing.send(sender.sendBytes(request));
          const received = receiver.receive(await incoming.receive());
          try { check(received.kind === 'bytes' && same(received.bytes, request), 'authenticated stream request'); }
          finally { received.free(); }
          const reply = new Uint8Array([254, current >>> 8, current & 255, 0]);
          await incoming.send(receiver.sendBytes(reply));
          const answer = sender.receive(await outgoing.receive());
          try { check(answer.kind === 'bytes' && same(answer.bytes, reply), 'authenticated stream reply'); }
          finally { answer.free(); }
          return current;
        };
      }
      stage('descriptor-period-transition');
      const hosts = services.map(service => service.host);
      const heartbeat = await bounded(authenticatedChannel(left, right), 65_000);
      const initialHeartbeat = await bounded(heartbeat(), 60_000);
      // Capture the baseline after authenticated traffic, so a boundary crossed
      // during channel setup cannot stand in for continuity from before renewal.
      const baseline = services.map(snapshot);
      const renewalEvidence = { scope: 'accelerated signed private-network period transition',
        waitLimitMs: fixture.renewal.waitMs, baseline, final: null, elapsedMs: 0,
        authenticatedHeartbeats: initialHeartbeat, addressUnchanged: false };
      progress.renewal = renewalEvidence;
      const started = performance.now();
      const expires = started + fixture.renewal.waitMs;
      let nextHeartbeat = started + fixture.renewal.heartbeatMs;
      let nextReport = started;
      while (true) {
        const now = performance.now();
        check(now < expires, 'descriptor period transition deadline');
        if (now >= nextHeartbeat) {
          renewalEvidence.authenticatedHeartbeats = await bounded(heartbeat(), Math.min(60_000, expires - now));
          nextHeartbeat = performance.now() + fixture.renewal.heartbeatMs;
        }
        const observed = services.map(snapshot);
        const elapsed = Math.round(performance.now() - started);
        renewalEvidence.final = observed;
        renewalEvidence.elapsedMs = elapsed;
        // A future-period upload alone, a late initial batch, or another
        // service's success cannot satisfy all three per-service advances.
        const advanced = renewalEvidence.authenticatedHeartbeats > initialHeartbeat
          && observed.every((value, index) =>
          value.successfulBatches > baseline[index].successfulBatches
          && value.latestSuccessfulPeriod > baseline[index].latestSuccessfulPeriod
          && value.currentPeriod > baseline[index].currentPeriod);
        if (performance.now() >= nextReport || advanced) {
          const response = await bounded(fetch('/__renewal-progress', { method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ elapsedMs: elapsed,
              authenticatedHeartbeats: renewalEvidence.authenticatedHeartbeats,
              services: observed }),
          }), 2_000);
          check(response.ok, 'renewal progress receipt');
          nextReport = performance.now() + 60_000;
        }
        check(performance.now() < expires, 'renewal evidence arrived within its bound');
        if (advanced) break;
        await new Promise(resolve => setTimeout(resolve, Math.min(1_000, expires - performance.now())));
      }
      check(services.every((service, index) => service.host === hosts[index]), 'onion addresses stable after publication transition');
      renewalEvidence.addressUnchanged = true;
      passed.push('both services accepted later-period publication batches and observed a signed directory-period transition without changing onion address');
      stage('established-stream-after-renewal');
      renewalEvidence.authenticatedHeartbeats = await bounded(heartbeat(), 60_000);
      left.close(); right.close();
      passed.push('established browser onion stream carried authenticated MLS binary before, during and after renewal');

      stage('fresh-browser-after-renewal');
      // A fresh Arti client has no cached old descriptor or established circuit.
      const freshClient = newClient();
      await bounded(freshClient.ready(), 360_000);
      const [newDialled, newAccepted] = await bounded(Promise.all([
        freshClient.connectOnion(services[1].host, 80, 60_000), services[1].accept(60_000),
      ]), 65_000);
      const freshLeft = new OnionFramedStream(newDialled, 60_000);
      const freshRight = new OnionFramedStream(newAccepted, 60_000);
      framed.push(freshLeft, freshRight);
      const freshExchange = await bounded(authenticatedChannel(freshLeft, freshRight), 65_000);
      await bounded(freshExchange(), 60_000);
      freshLeft.close(); freshRight.close();
      passed.push('fresh browser Arti client fetched the renewed service and exchanged root-authorized MLS binary both directions');
      renewalEvidence.nativePeer = await nativeExchange('native-peer-after-renewal');
      passed.push('fresh native onion connection exchanged root-authorized MLS binary both directions after renewal, replay rejected');
    }

    stage('service-cancellation');
    const pending = services[0].accept(60_000);
    services[0].close();
    const cancelled = await bounded(pending.then(() => false, () => true), 5_000);
    check(cancelled, 'service close cancels accept');
    passed.push('browser onion service close cancels pending accept');
    check(progress.failed.length === 0, 'gateway boundary assertions failed');
    stage('complete');
    return { network: progress.network, testNetworkOnly: !publicNetwork,
      phaseDurationsMs: progress.phaseDurationsMs,
      serviceReadiness: progress.serviceReadiness,
      topology: 'native C Tor client connects to browser-owned onion; MLS binary both directions',
      nativePeer: nativeEvidence, ...(renewal ? { renewal: progress.renewal } : {}), passed };
  } finally {
    if (progress.stage !== 'complete') {
      progress.phaseDurationsMs[progress.stage] = Math.round(performance.now() - phaseStarted);
    }
    for (const member of members) member.free();
    for (const stream of framed) stream.close();
    for (const service of services) { service.close(); service.free(); }
    for (const client of clients) { try { await bounded(client.close(), 2_000); } catch {} }
  }
}
