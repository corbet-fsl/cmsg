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
  const progress = { testNetworkOnly: true, stage: 'initialization', passed: [], failed: [] };
  globalThis.__cmsgTorRuntime = progress;
  await init({ module_or_path: new URL('../pkg/cmsg_bg.wasm', import.meta.url) });
  const fixture = await (await fetch('/fixture.json', { cache: 'no-store' })).json();
  check(fixture.testOnly === true && fixture.arti.vanguards.mode === 'full', 'isolated full-vanguard configuration');
  check(await TorClient.onionClientSupported() && await TorClient.onionStreamSupported()
    && await TorClient.onionServiceSupported(), 'actual Wasm capabilities');
  const clients = [];
  const services = [];
  const framed = [];
  const passed = progress.passed;
  let member;
  try {
    progress.stage = 'gateway-non-relay-rejection';
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
      forbidden = detail === `Error: CONNECT ${fixture.nonRelayCanary}: 403 target is not an advertised Tor relay`;
      progress.gatewayCanary = forbidden ? 'expected-403'
        : /timed out|deadline/i.test(detail) ? 'deadline'
        : /framing|body|response head/i.test(detail) ? 'response-framing'
        : 'other-error';
    } finally { gateway.close(); }
    const canaryUntouched = (await (await fetch('/__canary', { cache: 'no-store' })).json()).connections === 0;
    if (forbidden && canaryUntouched) {
      passed.push('actual browser WebRTC/KPS non-relay CONNECT rejected with 403 and zero owned canary connections');
    } else {
      // Retain failure and continue independent service diagnostics. The final
      // result still fails unless exact 403 AND zero connections were observed.
      progress.failed.push('real KPS non-relay 403 with zero canary connections was not verified');
    }
    progress.stage = 'client-bootstrap';
    for (let i = 0; i < 2; i++) clients.push(new TorClient({ gateway: fixture.gateway,
      testNetwork: JSON.stringify(fixture.arti), storage: new storage.MemoryStorage(),
      log: new Log({ rawLog: () => {} }), logLevel: 'error' }));
    await bounded(Promise.all(clients.map(c => c.ready())), 360_000);
    passed.push('two browser Arti clients bootstrapped on isolated signed Tor network');
    progress.stage = 'wasm-onion-route-validation';
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
    for (let index = 0; index < clients.length; index++) {
      progress.stage = `service-publication-${index}`;
      services.push(await bounded(clients[index].hostOnion(80, 4, 60_000), 65_000));
    }
    check(services[0].host !== services[1].host, 'distinct ephemeral onion identities');
    for (const service of services) new BrowserOnionEndpoint(service.host, service.port).free();
    passed.push('two browser-owned onion services published with full vanguards');
    progress.stage = 'browser-onion-stream';
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
    left.close(); right.close();
    passed.push('actual browser onion dial/accept and bidirectional cmsg framing');

    progress.stage = 'native-peer-connection';
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
    progress.stage = 'native-peer-mls';
    member = await syntheticMember();
    member.createGroup();
    const invitation = member.add(await peer.receive());
    await peer.send(invitation.welcome); invitation.free();
    const ciphertext = await peer.receive();
    const received = member.receive(ciphertext);
    check(received.kind === 'bytes' && same(received.bytes, [0, 255, 128, 7, 0, 9]), 'native MLS ciphertext authenticated');
    received.free();
    let replay = false;
    try { member.receive(ciphertext); } catch { replay = true; }
    check(replay, 'native ciphertext replay rejected');
    await peer.send(member.sendBytes(new Uint8Array([254, 0, 129, 4, 0, 3])));
    check(same(await peer.receive(), encode('cmsg-native-verified')), 'native peer verified browser ciphertext');
    const nativeEvidence = await bounded(native, 125_000);
    check(nativeEvidence.nativeFramedStream && nativeEvidence.rootAuthorizedMlsBinaryBothDirections, 'native process evidence');
    peer.close();
    passed.push('browser/native Tor FramedStream and root-authorized MLS binary both directions, replay rejected');
    progress.stage = 'service-cancellation';
    const pending = services[0].accept(60_000);
    services[0].close();
    const cancelled = await bounded(pending.then(() => false, () => true), 5_000);
    check(cancelled, 'service close cancels accept');
    passed.push('browser onion service close cancels pending accept');
    check(progress.failed.length === 0, 'gateway boundary assertions failed');
    progress.stage = 'complete';
    return { testNetworkOnly: true, nativePeer: nativeEvidence, passed };
  } finally {
    member?.free();
    for (const stream of framed) stream.close();
    for (const service of services) { service.close(); service.free(); }
    for (const client of clients) { try { await bounded(client.close(), 2_000); } catch {} }
  }
}
