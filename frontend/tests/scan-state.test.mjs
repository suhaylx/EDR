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
  assert.equal(describeScan(job('completed')).heading, 'Result not verified');
});
test('missing engine and DB versions cannot imply freshness', () => {
  assert.match(scanEngineEvidence(job('completed','clean_by_signature')), /freshness NOT VERIFIED/);
  assert.match(scanEngineEvidence(job('completed','clean_by_signature')), /signature DB version: not reported/);
});

test('completed delivery with scanner error stays danger and unattested', () => {
  const result = describeScan(job('completed', 'error'));
  assert.equal(result.heading, 'Scanner error');
  assert.equal(result.tone, 'danger');
  assert.equal(result.attested, false);
  assert.match(result.explanation, /No successful scan/i);
});
test('completed but unsupported scan explicitly remains unscanned', () => {
  const result = describeScan(job('completed', 'unscanned'));
  assert.equal(result.heading, 'Unscanned');
  assert.equal(result.attested, false);
  assert.match(result.explanation, /not performed/i);
});

test('unsupported quick/full success reports cannot become signature evidence', () => {
  for (const mode of ['quick', 'full']) {
    for (const verdict of ['clean_by_signature', 'malicious', 'suspicious']) {
      const result = describeScan(job('completed', verdict, {scan_type: mode, threat_name: 'Test-Signature'}));
      assert.equal(result.heading, 'Unsupported scan claim');
      assert.equal(result.tone, 'danger');
      assert.equal(result.attested, false);
      assert.match(result.explanation, /does not implement/);
    }
    // Failure and honest unscanned claims are still displayed normally.
    assert.equal(describeScan(job('completed', 'error', {scan_type: mode})).heading, 'Scanner error');
    assert.equal(describeScan(job('failed', 'unscanned', {scan_type: mode})).heading, 'Unscanned');
  }
  assert.equal(describeScan(job('completed', 'clean_by_signature', {scan_type: 'path'})).heading,
    'Clean by signature (reported)');
});
