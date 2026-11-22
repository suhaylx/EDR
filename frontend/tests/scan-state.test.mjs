import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeScan, scanEngineEvidence } from '../.test-dist/scan-state.js';
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
  const value = describeScan(job('completed','clean_by_signature',{scan_type:'path'}));
  assert.match(value.explanation, /not proof/i);
  assert.equal(value.attested, false);
});
test('malicious and malformed completion remain non-attested', () => {
  assert.equal(describeScan(job('completed','malicious', {scan_type:'path',threat_name:'Test-Signature'})).tone, 'danger');
  assert.match(describeScan(job('completed','malicious',{scan_type:'path'})).explanation, /without a signature/i);
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

test('completed positive-looking verdicts without supported path mode remain unverified', () => {
  for(const verdict of ['malicious','suspicious','clean_by_signature']) {
    for(const scan_type of [undefined,'', 'unknown', 'PATH']) {
      const result=describeScan(job('completed',verdict,{scan_type,signature_reported:true}));
      assert.equal(result.heading,'Result not verified');
      assert.equal(result.attested,false);
      assert.equal(result.tone,'danger');
      assert.match(result.explanation,/without a supported path scan mode/);
      assert.doesNotMatch(result.heading,/Signature match|Clean by signature|Suspicious \(reported\)/);
    }
  }
});
test('quick/full positive-looking completions remain unsupported rather than signature evidence', () => {
  for(const scan_type of ['quick','full']){
    for(const verdict of ['clean_by_signature','malicious','suspicious']){
      const result=describeScan(job('completed',verdict,{scan_type,signature_reported:true}));
      assert.equal(result.heading,'Unsupported scan claim');
      assert.equal(result.attested,false);
    }
  }
});
test('path-mode malicious claim without a signature indicator is not described as a signature match', () => {
  const result=describeScan(job('completed','malicious',{scan_type:'path',signature_reported:false}));
  assert.equal(result.heading,'Malicious verdict lacks signature evidence');
  assert.match(result.explanation,/without a signature indicator/);
  assert.equal(result.attested,false);
});
test('path-mode reported signature indicator does not expose a signature name',()=>{
  const result=describeScan(job('completed','malicious',{
    scan_type:'path',signature_reported:true,threat_name:'PRIVATE_SIGNATURE',
  }));
  assert.equal(result.heading,'Signature match reported');
  assert.match(result.explanation,/name withheld/);
  assert.doesNotMatch(result.explanation,/PRIVATE_SIGNATURE/);
  assert.equal(result.attested,false);
});
test('a completed scanner error or unscanned result remains distinct regardless of mode',()=>{
  for(const mode of [undefined,'quick','full']){
    assert.equal(describeScan(job('completed','error',{scan_type:mode})).heading,'Scanner error');
    assert.equal(describeScan(job('completed','unscanned',{scan_type:mode})).heading,'Unscanned');
  }
});
