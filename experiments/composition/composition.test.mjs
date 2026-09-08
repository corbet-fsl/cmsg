import test from 'node:test';
import assert from 'node:assert/strict';
import { runComposition } from './run.mjs';

test('real admission, live discovery, anonymous allowance and private text compose', { timeout: 120_000 }, async () => {
  const result = await runComposition();
  assert.equal(result.realAdmission, true);
  assert.equal(result.copiedCertificateRejected, true);
  assert.equal(result.certifiedDiscovery, true);
  assert.equal(result.firstContactPermitSpent, true);
  assert.equal(result.recipientGateEnforced, true);
  assert.equal(result.recipientCheckpointRestored, true);
  assert.equal(result.interruptedSpendRetrySafe, true);
  assert.equal(result.permitReplayRejected, true);
  assert.equal(result.reconnectCannotRefillAllowance, true);
  assert.equal(result.delivered, true);
  assert.equal(result.stableIdentityBound, true);
  assert.equal(result.encryptedSnapshotRestored, true);
  assert.equal(result.replayRejected, true);
  assert.equal(result.offlinePresenceForgotten, true);
  assert.equal(Object.values(result).every(value => typeof value === 'boolean'), true);
});
