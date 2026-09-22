// Actual generated cmsg Wasm signing. Full composition below imports the
// independently pinned cfrm source; synthetic gates are not eligibility proofs.
const utf8 = new TextEncoder();
const decodeText = new TextDecoder('utf-8', { fatal: true });
const json = value => utf8.encode(JSON.stringify(value));
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const random = size => crypto.getRandomValues(new Uint8Array(size));
const hash = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const unb64 = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const check = (value, label) => { if (!value) throw new Error(`profile signing contract: ${label}`); };
function refuses(run, label) { let rejected = false; try { run(); } catch { rejected = true; } check(rejected, label); }

export async function runProfileSigningContract(signer, authority) {
  const now = Math.floor(Date.now() / 1000), { admission } = authority;
  const fields = ['cfrm.cached-profile.v1', admission.communityId, admission.memberId, admission.chatPublicKey,
    b64(random(32)), 1, now, now + 60, b64(random(12)), b64(random(32)), [['region', 2]]];
  const signature = signer.signProfileStatement(json(fields));
  const publicKey = await crypto.subtle.importKey('raw', signer.chatPublicKey(), 'Ed25519', false, ['verify']);
  check(await crypto.subtle.verify('Ed25519', publicKey, unb64(signature), json(fields)), 'Wasm signature verifies in WebCrypto');
  for (const index of [0, 1, 2, 3]) {
    const bad = structuredClone(fields); bad[index] = 'unrelated';
    refuses(() => signer.signProfileStatement(json(bad)), 'domain and certified owner substitution');
  }
  refuses(() => signer.signProfileStatement(utf8.encode('MLS 1.0 FramedContentTBS')), 'no MLS signing oracle');
  const expired = structuredClone(fields); expired[7] = now;
  refuses(() => signer.signProfileStatement(json(expired)), 'actual browser clock rejects expired statement');
}

export async function runProfileComposition(api, ownerSigner, ownerAuthority, holderSigner, holderAuthority, trust, report = () => {}) {
  const domains = new Set(), clock = () => Math.floor(Date.now() / 1000), now = clock();
  const identity = (signer, authority) => ({ authority, sign(bytes) {
    domains.add(JSON.parse(decodeText.decode(bytes))[0]);
    return signer.signProfileStatement(bytes);
  } });
  const owner = identity(ownerSigner, ownerAuthority), holder = identity(holderSigner, holderAuthority);
  const config = { trust, clock, publicIssuer: { schemaId: 'synthetic-schema', credentialDefinitionId: 'synthetic-definition' },
    limits: { maxProfileBytes: 2048, maxEnvelopeBytes: 8192, maxProfileSeconds: 300, maxFrameBytes: 16384,
      maxProofBytes: 2048, maxChallengeSeconds: 30, maxKeySeconds: 60, maxReplayEntries: 64,
      maxConcurrentProofs: 4, maxRequestsPerWindow: 100, requestWindowSeconds: 60 } };
  let cached, sequence = 0, keyService, seededHolder;
  const cache = { publish: async value => { cached = structuredClone(value); }, fetch: async () => structuredClone(cached) };
  report('profile composition: create publisher');
  const publisher = await api.createProfilePublisher({ ...config, identity: owner, cache,
    reserveSequence: async () => ++sequence, saveCheckpoint: async () => {} });
  // Explicit fixture gates only. This contract establishes device signatures
  // and profile cryptographic composition, not real eligibility or issuance.
  const access = { verifyEligibilityProof: async () => true, verifyTicket: async () => true, authorizeAccess: async () => true };
  const encoded = async value => BigInt(`0x${[...await hash(utf8.encode(value))].map(byte => byte.toString(16).padStart(2, '0')).join('')}`).toString(10);
  async function read(service, holderMemberId) {
    const reader = api.createProfileReader({ ...config, cache, acceptPublication: async () => true,
      memberTransport: { open: async () => ({ exchange: bytes => service.handle(bytes), close: async () => {} }) },
      proveAccess: async () => ({ synthetic: true }), acquireTicket: async () => ({ synthetic: true }),
      async proveEligibility() {
        return { proof: { synthetic: true }, requested_proof: {
          revealed_attrs: Object.fromEntries(await Promise.all([['community_id', trust.communityId], ['policy', trust.policyDigest]]
            .map(async ([name, value]) => [name, { sub_proof_index: 0, raw: value, encoded: await encoded(value) }]))),
          self_attested_attrs: {}, unrevealed_attrs: {}, predicates: { eligible: { sub_proof_index: 0 }, valid_until: { sub_proof_index: 0 } },
        }, identifiers: [{ schema_id: config.publicIssuer.schemaId, cred_def_id: config.publicIssuer.credentialDefinitionId,
          rev_reg_id: null, timestamp: null }] };
      },
    });
    const received = await reader.read({ memberId: ownerAuthority.admission.memberId, holderMemberId });
    check(received.text === 'Private profile 🦀', 'actual cfrm publisher/reader decrypts authenticated profile');
  }
  try {
    report('profile composition: publish encrypted profile');
    const publication = await publisher.publish({ text: 'Private profile 🦀', discriminators: { region: 2 }, expiresAt: now + 120 });
    const discovery = api.createDiscoveryClient({ ...config, identity: owner, sessionId: b64(random(32)),
      requestSeconds: 30, maxResponseBytes: 16384, savePending: async () => {},
      lease: async () => ({ leaseId: b64(random(32)), sequence: 1, expiresAt: now + 30 }),
      send: async request => {
        const key = await crypto.subtle.importKey('raw', ownerSigner.chatPublicKey(), 'Ed25519', false, ['verify']);
        check(await crypto.subtle.verify('Ed25519', key, unb64(request.signature), api.discoveryRequestBytes(request)), 'real nested discovery transcript');
        return { kind: 'updated' };
      } });
    report('profile composition: publish discovery request');
    await discovery.publish(publication); await discovery.confirmPublication(publication);
    keyService = publisher.createKeyService(access);
    report('profile composition: owner key release and decryption');
    await read(keyService, ownerAuthority.admission.memberId);
    report('profile composition: holder offer and seed');
    const wrappingKeys = await api.wrappingKeyPair();
    const holderOffer = await api.createHolderKeyOffer({ identity: holder, wrappingKeys, expiresAt: now + 50 }, config);
    const seed = await publisher.seedHolder({ holderOffer, expiresAt: now + 45 });
    seededHolder = await api.createSeededProfileHolder({ ...config, ...access, identity: holder, seed, wrappingKeys });
    report('profile composition: holder key release and decryption');
    await read(seededHolder, holderAuthority.admission.memberId);
    // The real signing helper constructs its transcript. The blinded request
    // below is synthetic; no RSA permit issuance or redemption is claimed.
    const epoch = { communityId: trust.communityId, epochId: 'cfrm.key-access.v1/signing-contract', validFrom: now - 1,
      issueUntil: now + 60, expiresAt: now + 120, publicKeyDer: b64(random(400)), redemptionPublicKey: holderAuthority.admission.chatPublicKey };
    const contextId = await hash(json(['cfrm.permit.epoch.v1', epoch.communityId, epoch.epochId, epoch.validFrom,
      epoch.issueUntil, epoch.expiresAt, epoch.publicKeyDer, epoch.redemptionPublicKey]));
    const blindedRequest = random(416); blindedRequest.set(contextId);
    report('profile composition: ticket issue signature');
    await api.signProfileTicketIssue({ ...config, identity: owner, epoch, blindedRequest,
      requestId: b64(random(32)), expiresAt: now + 30 });
    const expected = ['cfrm.cached-profile.v1', 'cfrm.discovery-request.v1', 'cfrm.key-access.issue.v1',
      'cfrm.profile-holder-key.v1', 'cfrm.profile-holder.v1', 'cfrm.profile-holder-seed.v1',
      'cfrm.profile-key-challenge.v1', 'cfrm.profile-key-grant.v1'];
    check(expected.length === domains.size && expected.every(domain => domains.has(domain)), 'all eight actual cfrm signing domains covered');
    return { domains: [...domains].sort(), eligibility: 'synthetic callbacks', tickets: 'synthetic request; no issuance', transport: 'in-memory; not Tor' };
  } finally { seededHolder?.close(); keyService?.close(); publisher.close(); }
}
