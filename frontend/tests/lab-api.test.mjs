import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeScanJobs, fetchLabScanJobs } from '../.test-dist/lab-api.js';

const job = {id:'j1',agent_id:'win-lab',status:'completed',verdict:'clean_by_signature'};
test('decodes exact lab scan fields without deriving protection', () => {
  const value = decodeScanJobs([job])[0];
  assert.deepEqual({...value}, {id:'j1', agent_id:'win-lab', status:'completed', verdict:'clean_by_signature',
    scan_type:undefined,created_at:undefined,engine:undefined,engine_version:undefined,database_version:undefined,threat_name:undefined,detail:undefined});
});
test('invalid outer payload, oversized list and bad records fail closed', () => {
  assert.throws(() => decodeScanJobs({data: [job]}), /expected a list/);
  assert.throws(() => decodeScanJobs(new Array(5001).fill(job)), /exceeds/);
  assert.throws(() => decodeScanJobs([{id:'j1',agent_id:'a',status:42}]), /record 1/);
  assert.throws(() => decodeScanJobs([{...job, engine: {name:'ClamAV'}}]), /record 1/);
});
test('unknown states remain strings; no invalid completion is silently normalized', () => {
  assert.equal(decodeScanJobs([{...job,status:'mystery'}])[0].status, 'mystery');
});
test('uses an explicit bearer token in a no-store read-only request', async () => {
  let captured;
  const fetcher = async (path, options) => {
    captured = {path,options};
    return {ok:true,json:async () => [job]};
  };
  const data = await fetchLabScanJobs('a'.repeat(16), undefined, fetcher);
  assert.equal(data.length, 1);
  assert.equal(captured.path, '/api/scan-jobs');
  assert.equal(captured.options.method, 'GET');
  assert.equal(captured.options.credentials, 'omit');
  assert.equal(captured.options.cache, 'no-store');
  assert.equal(captured.options.headers.Authorization, 'Bearer ' + 'a'.repeat(16));
});
test('rejects short credentials and untrusted HTTP responses', async () => {
  const denied = async () => ({ok:false,status:401});
  await assert.rejects(fetchLabScanJobs('too-short', undefined, denied), /16 characters/);
  await assert.rejects(fetchLabScanJobs('a'.repeat(16), undefined, denied), /401/);
});
