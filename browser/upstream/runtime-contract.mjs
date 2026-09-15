// Genuine Tor/Arti network fixture. Every identity and payload is synthetic.
import { init, BrowserIdentity, BrowserMember, BrowserOnionEndpoint } from '../index.mjs';
import { OnionFramedStream } from '../internal/streams.mjs';
import { TorClient, Log, storage } from '/torjs/entryPoints/wasm-file/index.js';

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
  await init({ module_or_path: new URL('../pkg/cmsg_bg.wasm', import.meta.url) });
  const fixture = await (await fetch('/fixture.json', { cache: 'no-store' })).json();
  check(fixture.testOnly === true && fixture.arti.vanguards.mode === 'full', 'isolated full-vanguard configuration');
  check(await TorClient.onionClientSupported() && await TorClient.onionStreamSupported()
    && await TorClient.onionServiceSupported(), 'actual Wasm capabilities');
  const clients = [];
  const services = [];
  const framed = [];
  const passed = [];
  let member;
  try {
    for (let i = 0; i < 2; i++) clients.push(new TorClient({ gateway: fixture.gateway,
      testNetwork: JSON.stringify(fixture.arti), storage: new storage.MemoryStorage(),
      log: new Log({ rawLog: () => {} }), logLevel: 'error' }));
    await bounded(Promise.all(clients.map(c => c.ready())), 360_000);
    passed.push('two browser Arti clients bootstrapped on isolated signed Tor network');
    for (const client of clients) services.push(await bounded(client.hostOnion(80, 4, 60_000), 65_000));
    check(services[0].host !== services[1].host, 'distinct ephemeral onion identities');
    for (const service of services) new BrowserOnionEndpoint(service.host, service.port).free();
    passed.push('two browser-owned onion services published with full vanguards');
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
    const pending = services[0].accept(60_000);
    services[0].close();
    const cancelled = await bounded(pending.then(() => false, () => true), 5_000);
    check(cancelled, 'service close cancels accept');
    passed.push('browser onion service close cancels pending accept');
    return { testNetworkOnly: true, nativePeer: nativeEvidence, passed };
  } finally {
    member?.free();
    for (const stream of framed) stream.close();
    for (const service of services) { service.close(); service.free(); }
    for (const client of clients) { try { await bounded(client.close(), 2_000); } catch {} }
  }
}
