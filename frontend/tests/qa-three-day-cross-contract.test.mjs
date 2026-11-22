import test from 'node:test';
import assert from 'node:assert/strict';
import {backendUTCWindow,withinBackendUTCWindow} from '../.test-dist/backend-utc-window.js';
import {decodePolicyMetadata,decodePolicyAssignments,reviewPolicyEvidence} from '../.test-dist/policy-readonly.js';
import {reviewScanLifecycle,lifecycleTotals} from '../.test-dist/scan-lifecycle.js';

const digest='a'.repeat(64), at='2026-11-21T12:00:00Z';
const policy=(id,patch={})=>({id,name:'Original Lab Policy',platform:'windows',
  revision:2,sha256:digest,created_at:at,...patch});
const assignment=(type,target,id,patch={})=>({target_type:type,target_id:target,
  platform:'windows',policy_id:id,...patch});
const agent=(id,patch={})=>({id,group:'soc',platform:'windows',status:'online',
  applied_policy_id:'',applied_revision:0,last_policy_error:'',...patch});
const job=(id,patch={})=>({id,agent_id:'WIN-A',status:'leased',scan_type:'path',
  created_at:'2026-11-21T10:00:00Z',expires_at:'2026-11-21T10:30:00Z',
  lease_until:'2026-11-21T10:20:00Z',completed_at:undefined,
  verdict:undefined,...patch});

test('QA day3: Go calendar cutoff includes UTC midnight, excludes prior 23:59:59',()=>{
  const w=backendUTCWindow(at,7);
  assert.equal(w.startDay,'2026-11-15');
  assert.equal(withinBackendUTCWindow(Date.parse('2026-11-15T00:00:00Z'),w),true);
  assert.equal(withinBackendUTCWindow(Date.parse('2026-11-14T23:59:59Z'),w),false);
});
test('QA day3: timezone offset near midnight uses the resulting UTC day',()=>{
  const w=backendUTCWindow('2026-11-21T02:00:00+05:00',1);
  assert.equal(w.startDay,'2026-11-20');
  assert.equal(withinBackendUTCWindow(Date.parse('2026-11-20T23:00:00Z'),w),false);
});
test('QA day3: no unsupported rolling-day or unknown timestamp is accepted',()=>{
  assert.throws(()=>backendUTCWindow(at,14),/Unsupported/);
  assert.throws(()=>backendUTCWindow('bad',7),/Invalid/);
  assert.equal(withinBackendUTCWindow(null,backendUTCWindow(at,7)),false);
});
test('QA day3: platform-matched agent assignment overrides group and default',()=>{
  const policies=decodePolicyMetadata([policy('p-agent'),policy('p-group'),policy('p-default')]);
  const assignments=decodePolicyAssignments([
    assignment('default','*','p-default'),assignment('group','soc','p-group'),
    assignment('agent','WIN-A','p-agent'),
  ]);
  const rows=reviewPolicyEvidence({endpoints:[agent('WIN-A'),agent('WIN-B')]},
    policies,assignments);
  assert.deepEqual(rows.map(r=>r.desiredID),['p-agent','p-group']);
  assert.deepEqual(rows.map(r=>r.assignmentLevel),['agent','group']);
});
test('QA day3: a bare acknowledgment is reported only and revision mismatch is not enforcement',()=>{
  const policies=decodePolicyMetadata([policy('p1')]);
  const assign=decodePolicyAssignments([assignment('default','*','p1')]);
  const rows=reviewPolicyEvidence({endpoints:[
    agent('WIN-A',{applied_policy_id:'p1',applied_revision:2}),
    agent('WIN-B',{applied_policy_id:'p1',applied_revision:1}),
  ]},policies,assign);
  assert.equal(rows[0].status,'applied_reported');
  assert.equal(rows[1].status,'ack_mismatch');
});
test('QA day3: raw policy error and policy XML cannot reach derived review rows',()=>{
  const malicious='<img src=x onerror=steal()> SECRET_CREDENTIAL';
  const policies=decodePolicyMetadata([policy('p1')]);
  const assignments=decodePolicyAssignments([assignment('agent','WIN-A','p1')]);
  const rows=reviewPolicyEvidence({endpoints:[
    agent('WIN-A',{last_policy_error:malicious}),
  ]},policies,assignments);
  assert.equal(rows[0].status,'error_reported');
  assert.equal(rows[0].errorReported,true);
  assert.doesNotMatch(JSON.stringify(rows),/SECRET_CREDENTIAL|onerror|<img/);
  assert.throws(()=>decodePolicyMetadata([policy('p1',{xml:'<Sysmon/>'})]),/Unexpected Sysmon XML/);
});
test('QA day3: scoped platform prevents cross-OS policy assignment',()=>{
  const policies=decodePolicyMetadata([policy('p1')]);
  const assign=decodePolicyAssignments([assignment('default','*','p1')]);
  const rows=reviewPolicyEvidence({endpoints:[agent('LINUX-1',{platform:'linux'})]},policies,assign);
  assert.equal(rows[0].status,'unassigned');
});
test('QA day3: overdue leased scan is a queue inconsistency, not execution evidence',()=>{
  const rows=reviewScanLifecycle([job('leased')],at);
  assert.ok(rows[0].warnings.includes('pending_after_expiry'));
  assert.equal(lifecycleTotals(rows).pendingAfterExpiry,1);
});
test('QA day3: inverted timestamps, future clocks and terminal leases are identified',()=>{
  const rows=reviewScanLifecycle([job('completed',{
    status:'completed',expires_at:'2026-11-21T09:00:00Z',
    created_at:'2026-11-21T13:00:00Z',completed_at:'2026-11-21T13:01:00Z',
    lease_until:'2026-11-21T13:02:00Z',
  })],at);
  for(const key of ['expiry_before_creation','created_after_overview','completion_after_overview',
    'terminal_with_lease','lease_after_expiry'])assert.ok(rows[0].warnings.includes(key));
});
test('QA day3: source scan path and lease capability never enter lifecycle review',()=>{
  const rows=reviewScanLifecycle([job('private',{
    path:'C:\\SECRET_USER\\secret.exe',request_id:'PRIVATE_REQUEST',lease_id:'PRIVATE_LEASE',
  })],at);
  assert.doesNotMatch(JSON.stringify(rows),/SECRET_USER|PRIVATE_REQUEST|PRIVATE_LEASE/);
});
test('QA day3: invalid or missing server clock fails closed',()=>{
  assert.throws(()=>reviewScanLifecycle([job('j')],'not-a-timestamp'),/Invalid/);
});
