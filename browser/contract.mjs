// Browser-only behavioral checks against the generated Wasm JavaScript API.
// Scripted transport cases exercise adapter failure boundaries, not Tor.
import {
  init, BrowserFrameCodec, BrowserIdentity, BrowserMember, BrowserInbox, BrowserOnionEndpoint,
} from './index.mjs';
import { OnionHttpTransport } from './internal/http.mjs';
import { OnionFramedStream } from './internal/streams.mjs';

function assert(condition, label) {
  if (!condition) throw new Error(`browser contract: ${label}`);
}

function throws(operation, label) {
  let rejected = false;
  try { operation(); } catch { rejected = true; }
  assert(rejected, label);
}

async function rejects(operation, label) {
  let rejected = false;
  try { await operation(); } catch { rejected = true; }
  assert(rejected, label);
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

const encode = (text) => new TextEncoder().encode(text);
const b64 = (bytes) => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

async function authority() {
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
  const keyId = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey)));
  const trust = {
    community_id: 'browser-fixture',
    policy_digest: b64(new Uint8Array(32).fill(42)),
    issuer_public_key: [...publicKey],
  };
  async function grant(memberId, chatPublicKey) {
    const now = Math.floor(Date.now() / 1000);
    const grant = {
      version: 1,
      issuerKeyId: keyId,
      communityId: trust.community_id,
      memberId,
      chatPublicKey: b64(chatPublicKey),
      policyDigest: trust.policy_digest,
      issuedAt: now - 1,
      expiresAt: now + 3600,
    };
    const signed = [
      'cvld.admission.v1', grant.issuerKeyId, grant.communityId, grant.memberId,
      grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt,
    ];
    grant.signature = b64(new Uint8Array(await crypto.subtle.sign(
      'Ed25519', keys.privateKey, encode(JSON.stringify(signed)),
    )));
    return grant;
  }
  return { trust, grant };
}

async function member(issuer) {
  const identity = new BrowserIdentity(issuer.trust.community_id);
  const member = new BrowserMember();
  const key = member.chatPublicKey();
  const now = Math.floor(Date.now() / 1000);
  const certificate = identity.authorizeDevice(key, now - 1, now + 3600);
  const grant = await issuer.grant(identity.memberId(), key);
  member.bindDeviceAdmission(JSON.stringify(grant), JSON.stringify(issuer.trust), certificate);
  return { member, identity, certificate, grant };
}

// Published Tor documentation example, used only for address validation in
// scripted adapter tests. No test below contacts this service.
const ONION = 'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion';
const CONTENT_TYPE = 'application/vnd.cmsg.frame';

function frame(bytes) {
  const codec = new BrowserFrameCodec(1024 * 1024);
  try { return codec.encode(bytes); } finally { codec.free(); }
}

function response(bytes) {
  return new Response(bytes, {
    status: 200,
    headers: { 'content-type': CONTENT_TYPE, 'content-length': String(bytes.length) },
  });
}

async function checkpointStore() {
  const name = `cmsg-contract-${crypto.randomUUID()}`;
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('sessions');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('fixture database open'));
  });
  return {
    persist: (id) => (checkpoint, outbound) => new Promise((resolve, reject) => {
      const transaction = db.transaction('sessions', 'readwrite', { durability: 'strict' });
      transaction.objectStore('sessions').put({ checkpoint, outbound }, id);
      transaction.oncomplete = () => resolve(true);
      transaction.onabort = transaction.onerror = () => reject(new Error('fixture database write'));
    }),
    read: (id) => new Promise((resolve, reject) => {
      const request = db.transaction('sessions').objectStore('sessions').get(id);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('fixture database read'));
    }),
    close: () => { db.close(); indexedDB.deleteDatabase(name); },
  };
}

export async function runBrowserContract() {
  await init({ module_or_path: new URL('./pkg/cmsg_bg.wasm', import.meta.url) });
  const passed = [];
  const issuer = await authority();
  const alice = await member(issuer);
  const bob = await member(issuer);
  alice.member.createGroup();
  const invitation = alice.member.add(bob.member.keyPackage());
  bob.member.join(invitation.welcome);
  invitation.free();

  const binary = new Uint8Array([0, 255, 128, 10, 0]);
  const wire = alice.member.sendBytes(binary);
  const received = bob.member.receive(wire);
  assert(received.kind === 'bytes' && sameBytes(received.bytes, binary), 'binary ABI roundtrip');
  assert(received.memberId === alice.identity.memberId() && received.text === undefined, 'authenticated byte kind');
  received.free();
  throws(() => bob.member.receive(wire), 'replay rejection');
  const text = alice.member.receive(bob.member.sendText('literal <tag> 🦀'));
  assert(text.kind === 'text' && text.text === 'literal <tag> 🦀', 'text ABI roundtrip');
  text.free();
  passed.push('generated JS API: root-authorized MLS binary/text roundtrip and replay rejection');

  const valid = alice.member.sendBytes(new Uint8Array([254, 0, 1]));
  const corrupt = valid.slice();
  corrupt[corrupt.length - 1] ^= 1;
  throws(() => bob.member.receive(corrupt), 'tamper rejection');
  const recovered = bob.member.receive(valid);
  assert(sameBytes(recovered.bytes, [254, 0, 1]), 'rejected tamper preserves receive state');
  recovered.free();
  passed.push('generated JS API: tampering rejection preserves valid receive state');

  const key = crypto.getRandomValues(new Uint8Array(32));
  const context = encode('browser-fixture');
  const sealed = alice.identity.seal(key, context);
  const restored = BrowserIdentity.restore(sealed, key, issuer.trust.community_id, alice.identity.memberId(), context);
  assert(restored.memberId() === alice.identity.memberId(), 'root identity restore');
  throws(() => BrowserIdentity.restore(sealed, key, issuer.trust.community_id, bob.identity.memberId(), context), 'identity pin');
  restored.free();
  const checkpoint = alice.member.snapshot(key, context);
  throws(() => BrowserMember.restore(checkpoint, key, encode('other-context')), 'context binding');
  alice.member.free();
  const resumed = BrowserMember.restore(checkpoint, key, context);
  const afterRestore = bob.member.receive(resumed.sendBytes(new Uint8Array([1, 0, 255])));
  assert(sameBytes(afterRestore.bytes, [1, 0, 255]), 'conversation state restored');
  afterRestore.free();
  resumed.free();
  key.fill(0);
  passed.push('generated JS API: identity and conversation encrypted recovery with context/member pins');

  const forged = new BrowserMember();
  const substitutedGrant = await issuer.grant(alice.identity.memberId(), forged.chatPublicKey());
  throws(() => forged.bindDeviceAdmission(
    JSON.stringify(substitutedGrant), JSON.stringify(issuer.trust), alice.certificate,
  ), 'issuer alone cannot replace a device');
  forged.free();
  passed.push('generated JS API: issuer-only device substitution rejected');

  const sender = await member(issuer);
  const recipient = await member(issuer);
  const senderId = sender.identity.memberId();
  const recipientId = recipient.identity.memberId();
  const senderInbox = new BrowserInbox(sender.member);
  const recipientInbox = new BrowserInbox(recipient.member);
  const store = await checkpointStore();
  const sessionKey = crypto.getRandomValues(new Uint8Array(32));
  const sessionContext = encode('guarded-browser-session');
  const saveSender = store.persist('sender');
  const saveRecipient = store.persist('recipient');
  await senderInbox.createGroup(sessionKey, sessionContext, saveSender);
  const recipientPackage = await recipientInbox.keyPackage(sessionKey, sessionContext, saveRecipient);
  const guardedInvitation = await senderInbox.add(recipientPackage, sessionKey, sessionContext, saveSender);
  const welcome = guardedInvitation.welcome;
  guardedInvitation.free();
  assert(recipientInbox.invitationSender(welcome) === senderId, 'authenticated invitation sender');
  let redemptions = 0;
  const redeem = async (opaque) => {
    redemptions += 1;
    assert(sameBytes(opaque, [7, 2, 9]), 'recipient opaque claim');
    const pending = await store.read('recipient');
    const saved = BrowserInbox.restore(pending.checkpoint, sessionKey, sessionContext);
    assert(sameBytes(saved.pendingWelcome(), welcome), 'pending durable before external redemption');
    saved.free();
    return 'accepted';
  };
  assert(await recipientInbox.accept(welcome, undefined, sessionKey, sessionContext, saveRecipient, redeem) === 'needsPermit', 'unknown contact requires permit');
  assert(redemptions === 0, 'no premature redemption');
  await rejects(() => recipientInbox.accept(welcome, new Uint8Array([7, 2, 9]), sessionKey, sessionContext,
    async () => { throw new Error('synthetic write failure'); }, redeem), 'failed pending checkpoint');
  assert(redemptions === 0 && recipientInbox.pendingWelcome() === undefined, 'failed persistence cannot spend or publish');
  assert(await recipientInbox.accept(welcome, new Uint8Array([7, 2, 9]), sessionKey, sessionContext, saveRecipient, redeem) === 'joined', 'guarded acceptance');
  assert(redemptions === 1 && recipientInbox.isKnown(senderId), 'exactly one redeemed initial acceptance');
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'first-contact policy is mandatory');
  const introductionId = crypto.getRandomValues(new Uint8Array(32));
  const responseDeadline = Math.floor(Date.now() / 1000) + 300;
  await senderInbox.beginFirstContact(recipientId, introductionId, 'initiator', responseDeadline, 64,
    sessionKey, sessionContext, saveSender);
  await recipientInbox.beginFirstContact(senderId, introductionId, 'recipient', responseDeadline, 64,
    sessionKey, sessionContext, saveRecipient);
  await rejects(() => recipientInbox.sendBytes(binary, sessionKey, sessionContext, saveRecipient), 'recipient cannot reply before intro');
  await rejects(() => senderInbox.sendBytes(new Uint8Array(65), sessionKey, sessionContext, saveSender), 'caller intro byte bound');
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, async () => undefined), 'missing durable acknowledgement');
  const guardedWire = await senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender);
  assert(senderInbox.awaitingPeerResolution(recipientId), 'sent intro retains peer obligation');
  assert(sameBytes((await store.read('sender')).outbound[0], guardedWire), 'outbox committed with checkpoint');
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'one introduction until authentic reply');
  await rejects(() => recipientInbox.receive(guardedWire, sessionKey, sessionContext,
    async () => { throw new Error('synthetic receive write failure'); }), 'receive requires persistence before plaintext');
  const guardedReceived = await recipientInbox.receive(guardedWire, sessionKey, sessionContext, saveRecipient);
  assert(sameBytes(guardedReceived.bytes, binary), 'failed receive write preserves retry');
  guardedReceived.free();
  const answer = await recipientInbox.sendText('answer', sessionKey, sessionContext, saveRecipient);
  const answerReceived = await senderInbox.receive(answer, sessionKey, sessionContext, saveSender);
  assert(answerReceived.text === 'answer' && !senderInbox.needsResolution(recipientId), 'authenticated answer resolves intro');
  answerReceived.free();
  const queuedBeforeClose = await senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender);
  await rejects(() => recipientInbox.blockMemberUntil(senderId, undefined, sessionKey, sessionContext,
    async () => false), 'closure requires acknowledgement');
  assert(!recipientInbox.isClosed(senderId), 'failed closure write preserves policy');
  await recipientInbox.blockMemberUntil(senderId, undefined, sessionKey, sessionContext, saveRecipient);
  await recipientInbox.setBlocked(senderId, false, sessionKey, sessionContext, saveRecipient);
  assert(recipientInbox.isClosed(senderId), 'temporary flag cannot clear owned block');
  await rejects(() => recipientInbox.sendBytes(binary, sessionKey, sessionContext, saveRecipient), 'closed contact cannot send');
  const closeWire = await recipientInbox.closeContact(sessionKey, sessionContext, saveRecipient);
  const closeReceived = await senderInbox.receive(closeWire, sessionKey, sessionContext, saveSender);
  assert(closeReceived.kind === 'contactClosed' && senderInbox.isClosed(recipientId), 'authenticated encrypted closure reaches peer');
  assert(senderInbox.inboundResolutionReceipt(recipientId).length > 0
    && recipientInbox.outboundResolutionReceipt(senderId).length > 0, 'private resolution retained for recovery');
  await rejects(() => recipientInbox.refreshOutboundResolution(senderId, sessionKey, sessionContext, saveRecipient), 'unexpired receipt cannot be refreshed');
  closeReceived.free();
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'peer closure stops further messages');
  const restoredInbox = BrowserInbox.restore((await store.read('recipient')).checkpoint, sessionKey, sessionContext);
  assert(restoredInbox.isClosed(senderId) && restoredInbox.memberId() === recipientId, 'closed policy survives IndexedDB restore');
  restoredInbox.free();
  const freshId = crypto.getRandomValues(new Uint8Array(32));
  const freshDeadline = Math.floor(Date.now() / 1000) + 300;
  await rejects(() => senderInbox.initiateContact(freshId, freshDeadline, 64,
    sessionKey, sessionContext, saveSender), 'blocked member cannot reopen');
  await rejects(() => recipientInbox.initiateContact(freshId, freshDeadline, 64,
    sessionKey, sessionContext, async () => false), 'fresh initiative requires durability');
  assert(recipientInbox.isClosed(senderId), 'failed initiative keeps owned block');
  const initiative = await recipientInbox.initiateContact(freshId, freshDeadline, 64,
    sessionKey, sessionContext, saveRecipient);
  assert(sameBytes((await store.read('recipient')).outbound[0], initiative), 'fresh initiative checkpoint includes encrypted outbox');
  await rejects(() => recipientInbox.receive(queuedBeforeClose, sessionKey, sessionContext, saveRecipient), 'queued old data cannot answer new initiative');
  const initiativeReceived = await senderInbox.receive(initiative, sessionKey, sessionContext, saveSender);
  assert(initiativeReceived.kind === 'contactPolicyChanged', 'only blocker authenticated fresh initiative reopens');
  initiativeReceived.free();
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'new recipient must await actual intro');
  const freshIntro = await recipientInbox.sendText('fresh introduction', sessionKey, sessionContext, saveRecipient);
  await rejects(() => recipientInbox.sendBytes(binary, sessionKey, sessionContext, saveRecipient), 'fresh initiative still permits only one intro');
  const freshIntroReceived = await senderInbox.receive(freshIntro, sessionKey, sessionContext, saveSender);
  assert(freshIntroReceived.text === 'fresh introduction', 'new introduction received');
  freshIntroReceived.free();
  const freshAnswer = await senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender);
  const freshAnswerReceived = await recipientInbox.receive(freshAnswer, sessionKey, sessionContext, saveRecipient);
  assert(sameBytes(freshAnswerReceived.bytes, binary), 'authenticated answer resolves fresh initiative');
  freshAnswerReceived.free();
  const leaseEndpoint = new BrowserOnionEndpoint(ONION, 80);
  const lease = JSON.parse(senderInbox.signPresence(leaseEndpoint, 1, Math.floor(Date.now() / 1000) + 60));
  assert(lease.memberId === senderId && lease.endpoint.host === ONION, 'typed presence binds owner and onion');
  leaseEndpoint.free();
  const disconnect = JSON.parse(senderInbox.signDisconnect(2, Math.floor(Date.now() / 1000) + 60));
  assert(disconnect.endpoint === null && disconnect.sequence === 2, 'typed disconnect');
  senderInbox.free(); recipientInbox.free(); sender.identity.free(); recipient.identity.free();
  sessionKey.fill(0); store.close();
  passed.push('generated JS API + IndexedDB: bounded intro/reply, owner-only fresh restart, stale traffic rejection and durable checkpoint/outbox');

  for (const port of [0, -1, 65536, 65537, 1.5, NaN, Infinity]) {
    throws(() => new BrowserOnionEndpoint(ONION, port), 'port bounds before JS integer coercion');
  }
  for (const limit of [0, -1, 1048577, 4294967297, 1.5, NaN, Infinity]) {
    throws(() => new BrowserFrameCodec(limit), 'frame bound before JS integer coercion');
  }
  const endpoint = new BrowserOnionEndpoint(ONION, 80);
  assert(endpoint.host === ONION && endpoint.port === 80, 'onion getters');
  endpoint.free();
  passed.push('generated JS API: onion checksum and numeric bounds');

  const requests = [];
  let closes = 0;
  const transport = new OnionHttpTransport({
    ready: async () => {},
    fetch: async (url, init) => {
      requests.push({ url, init });
      return response(frame(new Uint8Array([255, 0])));
    },
    close: () => { closes += 1; },
  }, 1000);
  const reply = await transport.exchange(ONION, 80, new Uint8Array([1, 2]));
  assert(sameBytes(reply, [255, 0]) && requests.length === 1, 'HTTP framed exchange');
  assert(requests[0].url === `http://${ONION}:80/cmsg/v1/exchange`, 'fixed peer path');
  assert(requests[0].init.method === 'POST' && requests[0].init.headers['User-Agent'] === 'cmsg/1', 'private request defaults');
  for (const host of ['127.0.0.1', 'example.com', `${ONION}/other`, `${ONION}.example.com`]) {
    await rejects(() => transport.exchange(host, 80, new Uint8Array([1])), 'reject non-onion route');
  }
  assert(requests.length === 1, 'invalid routes never reach adapter');
  transport.close();
  assert(closes === 1, 'transport closes exactly once');
  passed.push('scripted adapter boundary: onion-only framing, fixed path, no invalid-route I/O');

  const invalidResponses = [
    () => new Response(null, { status: 302, headers: { location: 'https://tracking.invalid/' } }),
    () => new Response('bad', { status: 200, headers: { 'content-type': CONTENT_TYPE, 'content-length': '1048581' } }),
    () => new Response(frame(new Uint8Array([1])), { status: 200, headers: { 'content-type': CONTENT_TYPE, 'content-length': '6' } }),
    () => response(new Uint8Array([...frame(new Uint8Array([1])), ...frame(new Uint8Array([2]))])),
    () => new Response('bad', { status: 200, headers: { 'content-type': CONTENT_TYPE, 'transfer-encoding': 'chunked', 'content-length': '3' } }),
  ];
  for (const badResponse of invalidResponses) {
    let calls = 0;
    let closed = false;
    const failing = new OnionHttpTransport({
      ready: async () => {},
      fetch: async () => { calls += 1; return badResponse(); },
      close: () => { closed = true; },
    }, 1000);
    await rejects(() => failing.exchange(ONION, 80, new Uint8Array([1])), 'bad response rejected');
    await rejects(() => failing.exchange(ONION, 80, new Uint8Array([1])), 'failed transport cannot retry');
    assert(calls === 1 && closed, 'response failure closes without a retry/redirect');
  }
  passed.push('scripted adapter boundary: redirects, oversize, truncation, multiple frames and chunking rejected');

  let timedOut = false;
  const stalled = new OnionHttpTransport({
    ready: () => new Promise(() => {}),
    fetch: () => { throw new Error('must not reach fetch'); },
    close: () => { timedOut = true; },
  }, 20);
  await rejects(() => stalled.exchange(ONION, 80, new Uint8Array([1])), 'whole exchange timeout');
  assert(timedOut, 'timeout closes Tor client');
  passed.push('scripted adapter boundary: readiness is inside whole-exchange deadline');

  const throwingClose = new OnionHttpTransport({
    ready: async () => {}, fetch: async () => { throw new Error('secret destination'); },
    close: () => { throw new Error('secret close details'); },
  }, 1000);
  let sanitized;
  try { await throwingClose.exchange(ONION, 80, new Uint8Array([1])); } catch (error) { sanitized = error.message; }
  assert(sanitized === 'cmsg:Transport', 'upstream close errors scrubbed');
  throwingClose.close();
  passed.push('scripted adapter boundary: transport and shutdown errors cannot disclose upstream details');

  const incomingFrames = new Uint8Array([...frame(new Uint8Array([1, 255])), ...frame(new Uint8Array([2]))]);
  const chunks = [incomingFrames.slice(0, 3), incomingFrames.slice(3)];
  const outgoing = [];
  let rawClosed = 0;
  const framed = new OnionFramedStream({
    read: async (maximum, deadline) => {
      assert(maximum === 65536 && deadline > 0 && deadline <= 1000, 'bounded raw read');
      return chunks.shift() ?? new Uint8Array();
    },
    write: async (bytes) => { outgoing.push(bytes.slice()); },
    close: () => { rawClosed += 1; }, free: () => {},
  }, 1000);
  await framed.send(new Uint8Array([0, 255]));
  assert(sameBytes(outgoing[0], [0, 0, 0, 2, 0, 255]), 'native interoperable uint32 framing');
  assert(sameBytes(await framed.receive(), [1, 255]), 'fragmented raw receive');
  assert(sameBytes(await framed.receive(), [2]) && chunks.length === 0, 'coalesced second frame');
  await rejects(() => framed.receive(), 'EOF is terminal');
  assert(framed.closed && rawClosed === 1, 'raw EOF closes once');
  const invalidRaw = new OnionFramedStream({
    read: async () => new Uint8Array([0, 0, 0, 0]), write: async () => {},
    close: () => {}, free: () => {},
  }, 1000);
  await rejects(() => invalidRaw.receive(), 'invalid raw frame');
  assert(invalidRaw.closed, 'invalid raw frame poisons stream');
  passed.push('scripted raw-stream boundary: native framing, fragmentation, coalescing, EOF and invalid-frame closure');

  bob.member.free();
  alice.identity.free();
  bob.identity.free();
  return { evidence: 'browser crypto and scripted adapter boundaries; no live Tor claim', passed };
}
