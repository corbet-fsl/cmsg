// Browser-only behavioral checks against the generated Wasm JavaScript API.
// Scripted transport cases exercise adapter failure boundaries, not Tor.
import {
  init, BrowserFrameCodec, BrowserIdentity, BrowserMember, BrowserInbox, BrowserOnionEndpoint, openIndexedDbInboxStore,
} from './index.mjs';
import { OnionHttpTransport } from './internal/http.mjs';
import { OnionFramedStream } from './internal/streams.mjs';
import { runTorNodeContract } from './tor-node-contract.mjs';
import { runLiveStreamContract } from './live-contract.mjs';
import { runAccountingContract, runAccountingMemberContract } from './accounting-contract.mjs';

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
  return { identity, ...await device(issuer, identity) };
}

async function device(issuer, identity) {
  const member = new BrowserMember();
  const key = member.chatPublicKey();
  const now = Math.floor(Date.now() / 1000);
  const certificate = identity.authorizeDevice(key, now - 1, now + 3600);
  const grant = await issuer.grant(identity.memberId(), key);
  member.bindDeviceAdmission(JSON.stringify(grant), JSON.stringify(issuer.trust), certificate);
  return { member, certificate, grant };
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
  const name=`cmsg-contract-${crypto.randomUUID()}`;
  const first=await openIndexedDbInboxStore(name),second=await openIndexedDbInboxStore(name);
  return {persist:first.persist,read:first.read,secondPersist:second.persist,
    close(){first.close();second.close();indexedDB.deleteDatabase(name);}};
}

async function liveControls(from,to,key,context,saveFrom,saveTo) {
  const controls=from.pendingLiveControls();
  for (const wire of controls) {const result=await to.receive(wire,key,context,saveTo);assert(result.kind==='liveControl','authenticated live control');result.free();}
  await from.clearLiveControls(key,context,saveFrom);
}
async function liveHandshake(a,b,key,context,saveA,saveB) {
  const until=Math.floor(Date.now()/1000)+120;
  const ah=await a.beginLiveSession(b.chatPublicKey(),until,key,context,saveA);
  const bh=await b.beginLiveSession(a.chatPublicKey(),until,key,context,saveB);
  (await a.receive(bh,key,context,saveA)).free();(await b.receive(ah,key,context,saveB)).free();
  await liveControls(a,b,key,context,saveA,saveB);await liveControls(b,a,key,context,saveB,saveA);
  assert(a.liveSessions().length>0 && b.liveSessions().length>0,'mutual fresh live session');
}

export async function runBrowserContract() {
  await init({ module_or_path: new URL('./pkg/cmsg_bg.wasm', import.meta.url) });
  const passed = [];
  const issuer = await authority();
  const alice = await member(issuer);
  const bob = await member(issuer);
  await runAccountingMemberContract(alice.member, alice.identity.memberId(), issuer.trust);
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
  let senderInbox = new BrowserInbox(sender.member);
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
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'live session required before payload');
  await liveHandshake(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
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
  await runAccountingContract({ sender: senderInbox, recipient: recipientInbox, senderId, recipientId, trust: issuer.trust,
    receiveAnswer: async () => {
      const answerReceived = await senderInbox.receive(answer, sessionKey, sessionContext, saveSender);
      assert(answerReceived.text === 'answer' && !senderInbox.needsResolution(recipientId), 'authenticated answer resolves intro');
      answerReceived.free();
      await liveControls(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
    } });
  passed.push('generated Wasm + WebCrypto: actual Inbox Ed25519/P256 receipt, original sender acknowledgment, external delegated key and sealed recovery');
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
  const privateCloseReceipt = new TextDecoder().decode(recipientInbox.outboundResolutionReceipt(senderId));
  await rejects(() => senderInbox.applyResolution(privateCloseReceipt, sessionKey, sessionContext,
    async () => false), 'private receipt application requires durability');
  assert(await senderInbox.applyResolution(privateCloseReceipt, sessionKey, sessionContext, saveSender) === false,
    'duplicate private receipt creates no new resolution');
  assert((await store.read('sender')).outbound.length === 0, 'private receipt is excluded from transport outbox');
  const forgedReceipt = JSON.parse(privateCloseReceipt);
  forgedReceipt.signature[0] ^= 1;
  let forgedReceiptWrites = 0;
  await rejects(() => senderInbox.applyResolution(JSON.stringify(forgedReceipt), sessionKey, sessionContext,
    async () => { forgedReceiptWrites += 1; return true; }), 'forged receipt rejects before persistence');
  assert(forgedReceiptWrites === 0, 'forged receipt cannot publish a checkpoint');
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
  assert(await senderInbox.applyResolution(privateCloseReceipt, sessionKey, sessionContext, saveSender) === false,
    'archived receipt creates no current resolution');
  assert(!senderInbox.isClosed(recipientId), 'archived close cannot close the fresh contact');
  assert((await store.read('sender')).outbound.length === 0, 'archived receipt remains private');
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'new recipient must await actual intro');
  await liveHandshake(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
  const freshIntro = await recipientInbox.sendText('fresh introduction', sessionKey, sessionContext, saveRecipient);
  await rejects(() => recipientInbox.sendBytes(binary, sessionKey, sessionContext, saveRecipient), 'fresh initiative still permits only one intro');
  const freshIntroReceived = await senderInbox.receive(freshIntro, sessionKey, sessionContext, saveSender);
  assert(freshIntroReceived.text === 'fresh introduction', 'new introduction received');
  freshIntroReceived.free();
  const freshAnswer = await senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender);
  const freshAnswerReceived = await recipientInbox.receive(freshAnswer, sessionKey, sessionContext, saveRecipient);
  assert(sameBytes(freshAnswerReceived.bytes, binary), 'authenticated answer resolves fresh initiative');
  freshAnswerReceived.free();
  await liveControls(recipientInbox,senderInbox,sessionKey,sessionContext,saveRecipient,saveSender);
  const leaseEndpoint = new BrowserOnionEndpoint(ONION, 80);
  const lease = JSON.parse(senderInbox.signPresence(leaseEndpoint, 1, Math.floor(Date.now() / 1000) + 60));
  assert(lease.memberId === senderId && lease.endpoint.host === ONION, 'typed presence binds owner and onion');
  leaseEndpoint.free();
  const disconnect = JSON.parse(senderInbox.signDisconnect(2, Math.floor(Date.now() / 1000) + 60));
  assert(disconnect.endpoint === null && disconnect.sequence === 2, 'typed disconnect');

  const queuedBeforeReplacement = await senderInbox.sendText('old group queued data', sessionKey, sessionContext, saveSender);
  const replacementClose = await recipientInbox.closeContact(sessionKey, sessionContext, saveRecipient);
  const replacementClosed = await senderInbox.receive(replacementClose, sessionKey, sessionContext, saveSender);
  assert(replacementClosed.kind === 'contactClosed', 'replacement starts from owned closure');
  replacementClosed.free();
  const senderReplacement = await device(issuer, sender.identity);
  const recipientReplacement = await device(issuer, recipient.identity);
  const senderReplacementKey = senderReplacement.member.chatPublicKey();
  const recipientReplacementKey = recipientReplacement.member.chatPublicKey();
  const replacementPackage = senderReplacement.member.keyPackage();
  await store.persist('replacement-member')(
    senderReplacement.member.snapshot(sessionKey, sessionContext), [replacementPackage],
    {expectedVersion:0,nextVersion:1,devicePublicKey:[...senderReplacementKey]});
  const replacementNonce = crypto.getRandomValues(new Uint8Array(32));
  const replacementDeadline = Math.floor(Date.now() / 1000) + 300;
  await rejects(() => recipientInbox.initiateReplacement(recipientReplacement.member,
    replacementPackage, replacementNonce, replacementDeadline, 64, sessionKey, sessionContext,
    async () => false), 'replacement initiation requires durability');
  assert(sameBytes(recipientReplacement.member.chatPublicKey(), recipientReplacementKey)
    && recipientInbox.isClosed(senderId), 'failed replacement preserves handle and owned block');
  const replacementInvitation = await recipientInbox.initiateReplacement(recipientReplacement.member,
    replacementPackage, replacementNonce, replacementDeadline, 64, sessionKey, sessionContext, saveRecipient);
  const replacementWelcome = replacementInvitation.welcome;
  const replacementControl = replacementInvitation.control;
  replacementInvitation.free();
  const replacementOutbox = (await store.read('recipient')).outbound;
  assert(sameBytes(replacementOutbox[0], replacementWelcome) && sameBytes(replacementOutbox[1], replacementControl),
    'replacement bundle committed atomically with checkpoint');
  assert(!sameBytes(recipientReplacement.member.chatPublicKey(), recipientReplacementKey), 'initiator replacement handle retired after commit');
  throws(() => recipientReplacement.member.sendBytes(binary), 'retired external handle has no joined group');
  const replacementPreview = JSON.parse(senderInbox.previewReplacement(senderReplacement.member,
    replacementWelcome, replacementControl));
  assert(replacementPreview.inviter === recipientId
    && sameBytes(replacementPreview.introductionId, replacementNonce)
    && replacementPreview.groupId.length > 0
    && replacementPreview.policy.response_deadline === replacementDeadline
    && replacementPreview.policy.max_intro_bytes === 64,
    'recipient preview authenticates inviter, nonce, group and bounded policy');
  const tamperedReplacementControl = replacementControl.slice();
  tamperedReplacementControl[tamperedReplacementControl.length - 1] ^= 1;
  throws(() => senderInbox.previewReplacement(senderReplacement.member,
    replacementWelcome, tamperedReplacementControl), 'recipient preview rejects tampered control');
  assert(sameBytes(senderReplacement.member.chatPublicKey(), senderReplacementKey)
    && senderInbox.isClosed(recipientId), 'preview preserves replacement handle and local contact state');
  let replacementRedemptions = 0;
  const pendingReplacement = async opaque => {
    replacementRedemptions += 1;
    assert(sameBytes(opaque, [9, 4, 1]), 'replacement uses fresh opaque claim');
    const saved = BrowserInbox.restore((await store.read('sender')).checkpoint, sessionKey, sessionContext);
    assert(sameBytes(saved.pendingWelcome(), replacementWelcome)
      && sameBytes(saved.pendingReplacementControl(), replacementControl), 'exact replacement bundle durable before spend');
    saved.free();
    return 'pending';
  };
  assert(await senderInbox.acceptReplacement(senderReplacement.member, replacementWelcome, replacementControl,
    undefined, sessionKey, sessionContext, saveSender, pendingReplacement) === 'needsPermit', 'known contact replacement still needs fresh admission');
  assert(replacementRedemptions === 0 && sameBytes(senderReplacement.member.chatPublicKey(), senderReplacementKey),
    'missing replacement permit preserves external handle');
  await rejects(() => senderInbox.acceptReplacement(senderReplacement.member, replacementWelcome, replacementControl,
    new Uint8Array([9, 4, 1]), sessionKey, sessionContext, async () => false, pendingReplacement),
    'failed replacement checkpoint cannot spend');
  assert(replacementRedemptions === 0 && sameBytes(senderReplacement.member.chatPublicKey(), senderReplacementKey),
    'failed pending checkpoint preserves retry handle');
  assert(await senderInbox.acceptReplacement(senderReplacement.member, replacementWelcome, replacementControl,
    new Uint8Array([9, 4, 1]), sessionKey, sessionContext, saveSender, pendingReplacement) === 'pending',
    'ambiguous replacement keeps durable pending intent');
  assert(!sameBytes(senderReplacement.member.chatPublicKey(), senderReplacementKey), 'pending checkpoint retires external recipient handle');
  senderInbox.free();
  senderInbox = BrowserInbox.restore((await store.read('sender')).checkpoint, sessionKey, sessionContext);
  assert(await senderInbox.retryPendingReplacement(sessionKey, sessionContext, saveSender, async opaque => {
    replacementRedemptions += 1;
    assert(sameBytes(opaque, [9, 4, 1]), 'restored retry retains exact original claim');
    return 'accepted';
  }) === 'joined', 'restored replacement retry joins after fresh admission');
  assert(replacementRedemptions === 2 && senderInbox.pendingReplacementControl() === undefined,
    'successful retry clears pending control');
  await rejects(() => senderInbox.receive(queuedBeforeReplacement, sessionKey, sessionContext, saveSender), 'old group ciphertext cannot enter replacement');
  await rejects(() => senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender), 'replacement recipient waits for actual intro');
  await liveHandshake(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
  const replacementIntro = await recipientInbox.sendText('replacement introduction', sessionKey, sessionContext, saveRecipient);
  await rejects(() => recipientInbox.sendText('second intro', sessionKey, sessionContext, saveRecipient), 'replacement gets only one introduction');
  const replacementReceived = await senderInbox.receive(replacementIntro, sessionKey, sessionContext, saveSender);
  assert(replacementReceived.text === 'replacement introduction', 'replacement group receives authentic introduction');
  replacementReceived.free();
  const replacementAnswer = await senderInbox.sendBytes(binary, sessionKey, sessionContext, saveSender);
  const replacementAnswered = await recipientInbox.receive(replacementAnswer, sessionKey, sessionContext, saveRecipient);
  assert(sameBytes(replacementAnswered.bytes, binary), 'replacement group exchanges authentic answer');
  replacementAnswered.free();
  await liveControls(recipientInbox,senderInbox,sessionKey,sessionContext,saveRecipient,saveSender);
  const staleWriter=BrowserInbox.restore((await store.read('sender')).checkpoint,sessionKey,sessionContext);
  const competing=await Promise.allSettled([
    senderInbox.clearLiveControls(sessionKey,sessionContext,saveSender),
    staleWriter.beginLiveSession(recipientInbox.chatPublicKey(),Math.floor(Date.now()/1000)+60,sessionKey,sessionContext,store.secondPersist('sender')),
  ]);
  assert(competing.filter(r=>r.status==='fulfilled').length===1,'two IndexedDB connections accept only one device writer');
  if(competing[0].status==='rejected'){senderInbox.free();senderInbox=staleWriter;}else{staleWriter.free();}
  const currentRecord=await store.read('sender');
  await rejects(()=>store.secondPersist('absent-row')(currentRecord.checkpoint,[],{...currentRecord.metadata,expectedVersion:currentRecord.version,nextVersion:currentRecord.version+1}),'missing row cannot import a later publication chain');
  await liveHandshake(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
  const pendingLive=await senderInbox.sendBytes(binary,sessionKey,sessionContext,saveSender);
  const savedLive=await store.read('sender');
  assert(savedLive.metadata.entries[0].kind==='application','atomic outbox identifies live application');
  const acceptedLive=await recipientInbox.receive(pendingLive,sessionKey,sessionContext,saveRecipient);acceptedLive.free();
  const originalSid=senderInbox.liveSessions()[0];
  await senderInbox.loseLiveSession(originalSid,sessionKey,sessionContext,saveSender);
  assert(!senderInbox.isClosed(recipientId) && !senderInbox.canTransmitLiveWire(pendingLive),'abrupt loss cancels transmit without block');
  assert((await store.read('sender')).metadata.cancelApplicationIds.length>0,'atomic cancellation metadata');
  assert(JSON.parse(senderInbox.liveDeliveries()).some(d=>d.status==='canceledUnconfirmed'),'lost ACK is explicitly ambiguous');
  await liveControls(recipientInbox,senderInbox,sessionKey,sessionContext,saveRecipient,saveSender);
  assert(JSON.parse(senderInbox.liveDeliveries()).some(d=>d.outgoing && d.status==='accepted'),'late ACK retains committed acceptance');
  const restoredLive=BrowserInbox.restore((await store.read('sender')).checkpoint,sessionKey,sessionContext);
  assert(restoredLive.liveSessions().length===0 && !restoredLive.canTransmitLiveWire(pendingLive),'restore cannot replay application outbox');
  restoredLive.free();
  await liveHandshake(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
  await rejects(()=>recipientInbox.receive(pendingLive,sessionKey,sessionContext,saveRecipient),'old session frame rejected after fresh handshake');
  passed.push('generated Wasm + IndexedDB: fresh live sessions, atomic cancellation, lost ACK recovery and no restored application replay');
  await runLiveStreamContract(senderInbox,recipientInbox,sessionKey,sessionContext,saveSender,saveRecipient);
  passed.push('actual Wasm with scripted framed I/O: live adapter acceptance, close during pending write, cancellation and member independence');
  senderReplacement.member.free(); recipientReplacement.member.free();
  passed.push('generated JS API + IndexedDB: fresh-admission replacement group, durable handle transfer, exact restored pending retry and one-introduction gate');
  senderInbox.free(); recipientInbox.free(); sender.identity.free(); recipient.identity.free();
  sessionKey.fill(0); store.close();
  passed.push('generated JS API + IndexedDB: bounded intro/reply, owner-only fresh restart, private archived receipts, stale traffic rejection and durable checkpoint/outbox');

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
  passed.push(...await runTorNodeContract());

  bob.member.free();
  alice.identity.free();
  bob.identity.free();
  return { evidence: 'browser crypto and scripted adapter boundaries; no live Tor claim', passed };
}
