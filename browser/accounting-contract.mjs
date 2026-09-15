// Real Wasm <-> WebCrypto P-256 interoperability over actual Inbox decisions.
import {
  BrowserAccountingKey, verifyAccountingDelegation, verifyAccountingReceipt,
  verifyAccountingAcknowledgment, accountingReceiptSigningBytes,
  accountingAcknowledgmentSigningBytes,
} from './index.mjs';

const scheme = 'poseidon2-bn254-fixed-128-v1';
function check(value, label) { if (!value) throw new Error(`accounting contract: ${label}`); }
function fails(operation, label) {
  let rejected = false;
  try { operation(); } catch { rejected = true; }
  check(rejected, label);
}
const hex = (bytes) => [...bytes].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = (value) => Uint8Array.from(value.match(/../g), x => Number.parseInt(x, 16));
async function publicKey(bytes) {
  return crypto.subtle.importKey('raw', new Uint8Array([4, ...bytes]), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}
async function verify(publicBytes, signature, transcript) {
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await publicKey(publicBytes), new Uint8Array(signature), transcript);
}
async function sign(key, transcript) {
  const bytes = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, transcript));
  check(bytes.length === 64, 'WebCrypto P1363 signature');
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const s = BigInt(`0x${hex(bytes.subarray(32))}`);
  if (s > order / 2n) bytes.set(unhex((order - s).toString(16).padStart(64, '0')), 32);
  return [...bytes];
}
export async function runAccountingMemberContract(member, memberId, trust) {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey)).subarray(1);
  const now = Math.floor(Date.now() / 1000), expires = now + 120;
  const delegation = member.delegateAccountingPublicKey(publicBytes, scheme, new Uint8Array(32).fill(2), expires);
  verifyAccountingDelegation(delegation, JSON.stringify(trust), Math.floor(Date.now() / 1000));
  check(JSON.parse(delegation).admission.memberId === memberId, 'ungrouped Member delegation binds owner');
  const fields = [1, 2, 3, 4, 5].map(value => new Uint8Array(32).fill(value));
  const request = JSON.parse(member.authorizeAccountRequest(...fields, now, expires));
  const integer = value => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(value)); return bytes; };
  const transcript = new Uint8Array([
    ...new TextEncoder().encode('cfrm.account.request.v1\0'), ...fields[0], ...fields[1], ...fields[2],
    ...member.chatPublicKey(), ...integer(now), ...integer(expires), ...fields[3], ...fields[4],
  ]);
  const signature = Uint8Array.from(atob(request.signature.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  const device = await crypto.subtle.importKey('raw', member.chatPublicKey(), 'Ed25519', false, ['verify']);
  check(await crypto.subtle.verify('Ed25519', device, signature, transcript), 'ungrouped Member request verifies independently in WebCrypto');
  fails(() => member.authorizeAccountRequest(new Uint8Array(31), ...fields.slice(1), now, expires), 'Member request bounds');
}
export async function runAccountingContract({ sender, recipient, senderId, recipientId, trust, receiveAnswer }) {
  const now = Math.floor(Date.now() / 1000), trustJson = JSON.stringify(trust);
  const at = () => Math.floor(Date.now() / 1000);
  const senderKey = new BrowserAccountingKey(sender), recipientKey = new BrowserAccountingKey(recipient);
  try {
    const ad = sender.delegateAccounting(senderKey, scheme, new Uint8Array(32).fill(1), now + 120);
    const bd = recipient.delegateAccounting(recipientKey, scheme, new Uint8Array(32).fill(2), now + 120);
    check(verifyAccountingDelegation(bd, trustJson, at()).length === 32, 'root/device verified delegation digest');
    fails(() => recipient.accountingReceipt(senderId, recipientKey, bd), 'queued Answer has no accepted receipt');
    await receiveAnswer();
    const receiptJson = recipient.accountingReceipt(senderId, recipientKey, bd);
    const receipt = JSON.parse(receiptJson);
    const transcript = verifyAccountingReceipt(receiptJson, trustJson, at());
    check(transcript.length === 357, 'fixed receipt transcript');
    check(await verify(recipientKey.publicKey(), receipt.signature, transcript), 'Rust receipt verifies in WebCrypto');
    fails(() => recipient.accountingAcknowledgment(senderId, recipientKey, bd, receiptJson), 'recipient self acknowledgment rejected');
    const ackJson = sender.accountingAcknowledgment(recipientId, senderKey, ad, receiptJson);
    const ack = JSON.parse(ackJson), ackBytes = verifyAccountingAcknowledgment(ackJson, trustJson, at());
    check(ackBytes.length === 255 && await verify(senderKey.publicKey(), ack.signature, ackBytes), 'Rust original sender acknowledgment verifies in WebCrypto');
    const bad = JSON.parse(receiptJson); bad.contact.groupId[0] ^= 1;
    fails(() => verifyAccountingReceipt(JSON.stringify(bad), trustJson, at()), 'group substitution rejected');
    const context = JSON.parse(recipient.prepareAccountingContact(senderId));
    check(context.responderId === recipientId && context.contact.initiatorId === senderId, 'reservation context has exact roles');
    const external = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicBytes = new Uint8Array(await crypto.subtle.exportKey('raw', external.publicKey)).subarray(1);
    const delegated = recipient.delegateAccountingPublicKey(publicBytes, scheme, new Uint8Array(32).fill(2), now + 120);
    const prepared = JSON.parse(recipient.prepareAccountingReceipt(senderId, delegated));
    fails(() => verifyAccountingReceipt(JSON.stringify(prepared), trustJson, at()), 'unsigned witness is not accepted');
    prepared.signature = await sign(external.privateKey, accountingReceiptSigningBytes(JSON.stringify(prepared)));
    verifyAccountingReceipt(JSON.stringify(prepared), trustJson, at());
    const externalSender = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const senderPublicBytes = new Uint8Array(await crypto.subtle.exportKey('raw', externalSender.publicKey)).subarray(1);
    const delegatedSender = sender.delegateAccountingPublicKey(senderPublicBytes, scheme, new Uint8Array(32).fill(1), now + 120);
    const preparedAck = JSON.parse(sender.prepareAccountingAcknowledgment(recipientId, delegatedSender, JSON.stringify(prepared)));
    preparedAck.signature = await sign(externalSender.privateKey, accountingAcknowledgmentSigningBytes(JSON.stringify(preparedAck)));
    verifyAccountingAcknowledgment(JSON.stringify(preparedAck), trustJson, at());
    const wrapping = crypto.getRandomValues(new Uint8Array(32)), storageContext = new TextEncoder().encode('accounting-key-contract');
    const sealed = recipientKey.seal(wrapping, storageContext);
    const restored = BrowserAccountingKey.restore(sealed, wrapping, trust.community_id, recipientId, recipientKey.publicKey(), storageContext);
    check(hex(restored.publicKey()) === hex(recipientKey.publicKey()), 'encrypted P256 recovery'); restored.free();
    fails(() => BrowserAccountingKey.restore(sealed, wrapping, trust.community_id, senderId, recipientKey.publicKey(), storageContext), 'wrong root recovery rejected');
  } finally { senderKey.free(); recipientKey.free(); }
}
