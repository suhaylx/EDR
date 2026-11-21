import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizePolicyEvidence, policyEvidenceState } from '../.test-dist/policy-evidence.js';
const ep = (id, status='online', policy='', error='') => ({
  id,status,platform:'windows',group:'lab',last_seen:'2026-11-21T10:00:00Z',
  events:0,alerts:0,inactive_seconds:0,reported_health:'ok',
  applied_policy_id:policy,applied_revision:1,last_policy_error:error,
});
const overview = (endpoints, policy_coverage=[], policy_errors=0) => ({endpoints,policy_coverage,policy_errors});
test('empty inventory never reads as verified policy coverage', () => {
  const summary = summarizePolicyEvidence(overview([]));
  assert.equal(summary.total, 0);
  assert.equal(summary.reportedPolicyIds, 0);
  assert.equal(summary.missingPolicyIds, 0);
  assert.deepEqual(summary.discrepancies, []);
});
test('counts policy acknowledgements separately from absence, errors and stale status', () => {
  const summary = summarizePolicyEvidence(overview([
    ep('a','online','p1'), ep('b','offline','p1','collector disconnected'),
    ep('c','unknown',''), ep('d','online',''),
  ],[{policy_id:'p1',policy_name:'Windows lab',endpoints:2}],1));
  assert.equal(summary.reportedPolicyIds,2);
  assert.equal(summary.missingPolicyIds,2);
  assert.equal(summary.endpointsWithErrors,1);
  assert.equal(summary.staleOrUnknownAcknowledgements,1);
  assert.equal(summary.serverReportedErrors,1);
  assert.equal(summary.aggregates[0].consistent,true);
  assert.deepEqual(summary.discrepancies,[]);
});
test('mismatched/duplicate aggregate records are flagged rather than shown healthy', () => {
  const summary = summarizePolicyEvidence(overview([ep('a','online','p1'),ep('b','online','p2')],
    [{policy_id:'p1',policy_name:'A',endpoints:2},{policy_id:'p1',policy_name:'B',endpoints:1}]));
  assert.equal(summary.aggregates[0].consistent,false);
  assert.equal(summary.aggregates[1].consistent,false);
  assert.ok(summary.discrepancies.some(x=>x.includes('disagree')));
  assert.ok(summary.discrepancies.some(x=>x.includes('duplicate')));
  assert.ok(summary.discrepancies.some(x=>x.includes('p2')));
});
test('policy evidence descriptions never claim protection even when online', () => {
  assert.match(policyEvidenceState(ep('a','online','p1')), /NOT VERIFIED/);
  assert.match(policyEvidenceState(ep('b','unknown','p1')), /stale\/unknown/);
  assert.match(policyEvidenceState(ep('c','online','')), /UNKNOWN/);
  assert.match(policyEvidenceState(ep('d','online','p1','error')), /error reported/i);
});
