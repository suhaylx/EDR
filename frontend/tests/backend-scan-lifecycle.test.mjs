import test from 'node:test';
import assert from 'node:assert/strict';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
import {reviewScanLifecycle,lifecycleTotals} from '../.test-dist/scan-lifecycle.js';
const clock='2026-11-21T12:00:00Z';
const job=(id,patch={})=>({id,agent_id:'WIN-A',status:'completed',scan_type:'path',
  created_at:'2026-11-21T10:00:00Z',expires_at:'2026-11-21T10:30:00Z',
  completed_at:'2026-11-21T10:05:00Z',lease_until:null,lease_id:'SECRET_LEASE',
  request_id:'REQ-SECRET',path:'C:\\Sensitive\\secret.txt',
  verdict:'clean_by_signature',engine:'clamav',engine_version:'1.5',
  database_version:'lab',detail:'reported',threat_name:'',...patch});
const review=(raw,at=clock)=>reviewScanLifecycle(decodeScanJobs(raw),at);
test('Day3 parse Go time.Time lifecycle fields without persisting raw path or lease id',()=>{
 const decoded=decodeScanJobs([job('one')])[0];
 assert.equal(decoded.created_at,'2026-11-21T10:00:00Z');
 assert.equal(decoded.expires_at,'2026-11-21T10:30:00Z');
 assert.equal(decoded.completed_at,'2026-11-21T10:05:00Z');
 assert.equal('lease_id' in decoded,false);
 assert.equal('path' in decoded,false);
 assert.equal('request_id' in decoded,false);
});
test('Day3 completed reported lifecycle can be consistent but never attested',()=>{
 const rows=review([job('one')]);assert.deepEqual(rows[0].warnings,[]);
 assert.equal(lifecycleTotals(rows).withWarnings,0);
});
test('Day3 queued or leased after expiry is a stale state, not a confirmed scan',()=>{
 for(const status of ['queued','leased']){
 const rows=review([job('one',{status,completed_at:null,verdict:undefined,threat_name:''})]);
 assert.ok(rows[0].warnings.includes('pending_after_expiry'));
 }
});
test('Day3 expiry earlier than creation is not a valid job timeline',()=>{
 const rows=review([job('one',{expires_at:'2026-11-21T09:00:00Z'})]);
 assert.ok(rows[0].warnings.includes('expiry_before_creation'));
});
test('Day3 completion before creation and after expiry are separately flagged',()=>{
 assert.ok(review([job('one',{completed_at:'2026-11-21T09:59:59Z'})])[0].warnings.includes('complete_before_creation'));
 assert.ok(review([job('one',{completed_at:'2026-11-21T10:30:01Z'})])[0].warnings.includes('complete_after_expiry'));
});
test('Day3 completed or failed jobs without completion time are gaps, not proof of failure to scan',()=>{
 for(const status of ['completed','failed'])assert.ok(review([
   job('one',{status,completed_at:null,verdict:'error',threat_name:''})
 ])[0].warnings.includes('completed_without_timestamp'));
 assert.equal(review([job('one',{status:'expired',completed_at:null})])[0].warnings.includes('completed_without_timestamp'),false);
});
test('Day3 pending job with completion time is inconsistent',()=>{
 const r=review([job('one',{status:'queued',verdict:undefined})])[0];
 assert.ok(r.warnings.includes('pending_with_completion'));
});
test('Day3 terminal job must not disclose a live lease deadline',()=>{
 const r=review([job('one',{lease_until:'2026-11-21T10:02:00Z'})])[0];
 assert.ok(r.warnings.includes('terminal_with_lease'));
});
test('Day3 lease deadline later than job expiry is independently flagged',()=>{
 const r=review([job('one',{status:'leased',completed_at:null,
    lease_until:'2026-11-21T10:31:00Z',verdict:undefined})])[0];
 assert.ok(r.warnings.includes('lease_after_expiry'));
});
test('Day3 future created/completed times are measured against Go overview clock',()=>{
 const r=review([job('one',{created_at:'2026-11-21T12:10:00Z',
  expires_at:'2026-11-21T12:50:00Z',completed_at:'2026-11-21T12:15:00Z'})])[0];
 assert.ok(r.warnings.includes('created_after_overview'));
 assert.ok(r.warnings.includes('completion_after_overview'));
 assert.equal(lifecycleTotals([r]).futureClock,1);
});
test('Day3 malformed optional timestamps fail closed before rendering',()=>{
 for(const key of ['created_at','expires_at','lease_until','completed_at']){
  assert.throws(()=>decodeScanJobs([job('one',{[key]:'not-an-ISO-date'})]),/timestamp/);
 }
});
test('Day3 invalid overview time does not silently infer past-due jobs',()=>{
 assert.throws(()=>review([job('one')],'invalid'),/Invalid Go server overview time/);
});
test('Day3 privacy protects request, path and lease capability across lifecycle summaries',()=>{
 const r=review([job('one')])[0];
 const serialized=JSON.stringify(r);
 assert.equal(serialized.includes('REQ-SECRET'),false);
 assert.equal(serialized.includes('SECRET_LEASE'),false);
 assert.equal(serialized.includes('Sensitive'),false);
});
