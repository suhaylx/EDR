import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeScan, scanEngineEvidence } from '../dist/scan-state.js';
const job = (status, verdict, other = {}) => ({ id: 'job1', agent_id: 'lab1', status, verdict, ...other });
test('job delivery never becomes successful protection', () => {
  for (const status of ['queued','leased','expired','failed','unknown']) {
    const value = describeScan(job(status));
    assert.equal(value.attested, false);
    assert.doesNotMatch(value.explanation, /protected|safe endpoint/i);
  }
});
test('failed unscanned is distinct from scanner error', () => {
  assert.equal(describeScan(job('failed','unscanned')).heading, 'Unscanned');
  assert.equal(describeScan(job('failed','error')).heading, 'Scanner error');
});
test('reported clean never implies safety', () => {
  const value = describeScan(job('completed','clean_by_signature'));
  assert.match(value.explanation, /not proof/i);
  assert.equal(value.attested, false);
});
test('malicious and malformed completion remain non-attested', () => {
  assert.equal(describeScan(job('completed','malicious', { threat_name: 'Test-Signature' })).tone, 'danger');
  assert.match(describeScan(job('completed','malicious')).explanation, /without a signature/i);
  assert.equal(describeScan(job('completed','unscanned')).heading, 'Result not verified');
});
test('missing engine and DB versions cannot imply freshness', () => {
  assert.match(scanEngineEvidence(job('completed','clean_by_signature')), /freshness NOT VERIFIED/);
  assert.match(scanEngineEvidence(job('completed','clean_by_signature')), /signature DB version: not reported/);
});
