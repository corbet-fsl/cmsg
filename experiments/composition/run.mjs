// Synthetic local integration harness, never a service or production identity source.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const root = fileURLToPath(new URL('../../', import.meta.url));
const sibling = (repo, path) => pathToFileURL(resolve(root, '..', repo, path)).href;

export async function runComposition() {
  const [cvld, fixtures, client, admission, forum, permits] = await Promise.all([
    import(sibling('cvld', 'src/index.js')),
    import(sibling('cvld', 'test/fixtures.js')),
    import(sibling('cvld', 'src/client.js')),
    import(sibling('cvld', 'src/admission.js')),
    import(sibling('cfrm', 'src/rendezvous.js')),
    import(sibling('cfrm', 'experiments/anonymous-permits/permits.js')),
  ]);
  const dir = mkdtempSync(join(tmpdir(), 'component-composition-'));
  const ledger = permits.openLedger(join(dir, 'allowances.sqlite'));
  const child = spawn(resolve(root, 'target/debug/examples/composition'), [], { stdio: ['pipe', 'pipe', 'pipe'] });
  let childError;
  let errorOutput = '';
  child.on('error', error => { childError = error; });
  child.stderr.on('data', data => { errorOutput = (errorOutput + data.toString()).slice(-2048); });
  const completion = new Promise(resolveExit => child.on('close', code => resolveExit(code)));
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const read = async () => {
    const line = await lines.next();
    if (line.done) throw new Error(`Synthetic participant ended: ${childError?.message ?? errorOutput}`);
    return JSON.parse(line.value);
  };
  const write = value => child.stdin.write(`${JSON.stringify(value)}\n`);
  let registry;
  try {
    const { chatPublicKeys } = await read();
    assert.equal(chatPublicKeys.length, 2);
    let now = Math.floor(Date.now() / 1000);
    const communityId = 'community.example';
    const policy = { version: 'composition', mode: 'any', factors: ['phone'] };
    const gate = fixtures.makeGate('phone');
    const receiptStore = cvld.createMemoryReceiptStore({ maxEntries: 100 });
    const credentialStore = cvld.createMemoryCredentialStore({ maxCredentials: 100 });
    const issuer = cvld.createIssuer({
      issuerId: 'https://issuer.example/cvld', communityId, policy,
      attesters: { phone: gate.public }, receiptStore,
      maxCredentialLifetimeSeconds: 900, clock: () => now,
    });
    const passkeys = cvld.createPasskeyService({
      credentialStore, communityId, origin: fixtures.ORIGIN, rpID: fixtures.RP_ID,
      rpName: 'Synthetic community', clock: () => now, challengeLifetimeSeconds: 120,
      maxPendingChallenges: 100, requireUserVerification: true, maxPasskeysPerMember: 4,
    });
    const signingKeys = generateKeyPairSync('ed25519');
    const trustedPublicKey = Buffer.from(signingKeys.publicKey.export({ format: 'jwk' }).x, 'base64url');
    const verifier = cvld.createVerifier({
      publicIssuer: issuer.public, policy, communityId, credentialStore,
      origin: fixtures.ORIGIN, rpID: fixtures.RP_ID, clock: () => now,
      challengeLifetimeSeconds: 120, grantLifetimeSeconds: 120,
      maxPendingChallenges: 100, maxPresentationBytes: 100_000, requireUserVerification: true,
      grantSigningKey: signingKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }),
    });
    const grants = [];
    for (const chatPublicKey of chatPublicKeys) {
      const auth = fixtures.makeAuthenticator();
      const registration = await passkeys.beginRegistration();
      const account = await passkeys.finishRegistration({ id: registration.id, response: auth.register(registration.options.challenge) });
      const holder = cvld.createHolder();
      const offer = issuer.offer();
      const pending = holder.request(issuer.public, offer, account.memberId);
      pending.accept(await issuer.issue({ offer, request: pending.request,
        attestations: [gate.attest(offer, pending.request, policy, { validUntil: now + 600 })] }));
      const challenge = verifier.begin(account.credentialId, fixtures.ORIGIN, chatPublicKey);
      const result = await verifier.authenticate({ id: challenge.id, audience: fixtures.ORIGIN,
        presentation: holder.present(issuer.public, challenge), authentication: auth.assert(challenge.authentication.challenge) });
      assert.equal(result.eligible, true);
      assert.equal(result.memberId, account.memberId);
      grants.push(result.admission);
    }
    const policyDigest = cvld.policyDigest(policy);
    assert.ok(grants.every(grant => admission.verifyAdmission({ grant, trustedPublicKey, communityId, policyDigest, now })));
    // The native participant uses wall time; refresh after expensive issuance
    // before creating short-lived live-discovery challenges.
    now = Math.floor(Date.now() / 1000);
    let nextTimer = 0;
    const timers = new Map();
    registry = forum.createRendezvous({
      communityId, policyDigest, trustedPublicKey, verifyAdmission: admission.verifyAdmission,
      clock: () => now, leaseSeconds: 10, challengeSeconds: 5, maxMembers: 100, maxReplayEntries: 200,
      setTimer: (callback, milliseconds) => { const id = ++nextTimer; timers.set(id, { callback, at: now + milliseconds / 1000 }); return id; },
      clearTimer: id => timers.delete(id),
    });
    const host = 'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion';
    const envelopes = await Promise.all(grants.map((grant, index) => registry.begin(grant, { host, port: 4000 + index })));
    const copied = await registry.register({ grant: grants[0], ...envelopes[0], signature: '' });
    assert.equal(copied, null);
    write({ grants, trust: { community_id: communityId, policy_digest: policyDigest, issuer_public_key: [...trustedPublicKey] },
      deferExchange: true, rendezvousChallenges: envelopes.map(({ challenge }) => ({
        communityId: challenge.communityId, memberId: challenge.memberId, chatPublicKey: challenge.chatPublicKey,
        endpoint: challenge.endpoint, challengeId: challenge.challengeId, issuedAt: challenge.issuedAt, expiresAt: challenge.expiresAt,
      })) });
    const accepted = await read();
    assert.equal(accepted.admitted, true);
    const sessions = await Promise.all(grants.map((grant, index) => registry.register({
      grant, ...envelopes[index], signature: accepted.rendezvousSignatures[index],
    })));
    assert.ok(sessions.every(Boolean));
    assert.deepEqual(registry.list(sessions[0].token).map(member => member.memberId).sort(), grants.map(grant => grant.memberId).sort());

    // A trusted initial policy assigns one first-contact permit per admitted ID.
    // No sender/recipient pair is passed to the permit issuer or redeemer.
    const epoch = await permits.createEpoch({ scope: communityId, epoch: 'synthetic-1', notBefore: now, expiresAt: now + 60 });
    const allowanceIssuer = permits.createIssuer(epoch, ledger, () => now);
    allowanceIssuer.allocate(grants[0].memberId, 1);
    const request = await permits.preparePermit(epoch.public);
    const permit = await request.finish(await allowanceIssuer.issue(grants[0].memberId, request.request));
    const redemption = permits.prepareRedemption(permit);
    registry.disconnect(sessions[0].token);
    allowanceIssuer.allocate(grants[0].memberId, 1);
    const extra = await permits.preparePermit(epoch.public);
    await assert.rejects(allowanceIssuer.issue(grants[0].memberId, extra.request));

    // PRF output is synthetic here; cvld's browser experiment tests actual PRF.
    const prfOutput = Uint8Array.from(randomBytes(32));
    const wallet = await client.createWallet({ prfOutput, scope: communityId });
    const restoredWallet = await client.unlockWallet({ prfOutput, scope: communityId, envelope: wallet.envelope });
    const wrappingKey = await restoredWallet.storageKey('cmsg');
    assert.deepEqual(wrappingKey, await wallet.storageKey('cmsg'));
    write({ wrappingKey: [...wrappingKey], recipientRedemption: [...Buffer.from(JSON.stringify(redemption))] });
    // The real receiving client validates its Welcome and durably stores the
    // encrypted pending attempt before asking the anonymous rules adapter.
    const action = await read();
    assert.deepEqual(Object.keys(action), ['redeemRequest']);
    const callbackRequest = JSON.parse(Buffer.from(action.redeemRequest).toString('utf8'));
    assert.deepEqual(callbackRequest, redemption);
    assert.deepEqual(await permits.redeemIntroduction(epoch.public, ledger, callbackRequest, () => now), { accepted: true });
    // A lost first response must be recoverable with the exact persisted claim.
    assert.deepEqual(await permits.redeemIntroduction(epoch.public, ledger, callbackRequest, () => now), { accepted: true });
    assert.deepEqual(await permits.redeemIntroduction(epoch.public, ledger, permits.prepareRedemption(permit), () => now), { accepted: false });
    assert.equal(await permits.redeemPermit(epoch.public, ledger, permit, () => now), false);
    write({ outcome: 'accepted' });
    const messaging = await read();
    child.stdin.end();
    assert.equal(await completion, 0, errorOutput);
    now += 120;
    for (;;) {
      const due = [...timers].find(([, timer]) => timer.at <= now);
      if (!due) break;
      timers.delete(due[0]); due[1].callback();
    }
    assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
    return { realAdmission: true, copiedCertificateRejected: true, certifiedDiscovery: true,
      firstContactPermitSpent: true, permitReplayRejected: true, reconnectCannotRefillAllowance: true,
      interruptedSpendRetrySafe: true,
      ...messaging, offlinePresenceForgotten: true };
  } finally {
    registry?.close();
    child.stdin.end();
    if (child.exitCode === null) child.kill('SIGTERM');
    ledger.close();
    rmSync(dir, { recursive: true, force: true });
  }
}
