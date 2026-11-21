import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decodeLabDetections, detectionsInWindow, seedForDetection, fetchLabDetections} from '../.test-dist/detections.js';
const row=(change={})=>({
  id:'d1',rule_id:'TURAN-WIN-DLL-LOAD-001',category:'suspicious_dll_load',severity:'medium',confidence:'low',
  device_id:'win-1',process_guid:'{ABC}',process_image:'cmd.exe',module_path:'C:\\Users\\test.dll',
  load_event_id:'source-1',observed_at:'2026-11-21T10:00:00Z',explanation:'Observed DLL load; review evidence.',...change
});
test('decodes and retains source IDs without classifying infection',()=>{
 const v=decodeLabDetections([row()]);
 assert.equal(v.length,1);assert.equal(v[0].severity,'medium');assert.equal(v[0].file_create_event_id,'');
 assert.deepEqual(seedForDetection(v[0]),{deviceID:'win-1',kind:'detection',detectionID:'d1'});
});
test('fails closed on missing ids, duplicate ids and malformed source',()=>{
 assert.throws(()=>decodeLabDetections(null),/Invalid lab detection response/);
 assert.throws(()=>decodeLabDetections([row({device_id:''})]),/missing bounded/);
 assert.throws(()=>decodeLabDetections([row({load_event_id:''})]),/missing bounded/);
 assert.throws(()=>decodeLabDetections([row({observed_at:'not a timestamp'})]),/timestamp/);
 assert.throws(()=>decodeLabDetections([row(),row()]),/Duplicate/);
 assert.throws(()=>decodeLabDetections(new Array(5001).fill(row())),/5,000/);
});
test('retained window uses supplied server timestamp and excludes future events',()=>{
 const v=decodeLabDetections([row({id:'a',observed_at:'2026-11-21T10:00:00Z'}),
  row({id:'b',observed_at:'2026-11-10T10:00:00Z'}),
  row({id:'c',observed_at:'2026-11-22T10:00:00Z'})]);
 assert.deepEqual(detectionsInWindow(v,'2026-11-21T12:00:00Z',7).map(x=>x.id),['a']);
 assert.deepEqual(detectionsInWindow(v,'2026-11-21T12:00:00Z',30).map(x=>x.id),['a','b']);
});
test('read-only authenticated fetch omits ambient cookies and caches',async()=>{
 let request;
 const mock=async (url,options)=>{request={url,options};return {ok:true,json:async()=>[row()]};};
 const v=await fetchLabDetections('z'.repeat(16),undefined,mock);
 assert.equal(v.length,1);assert.equal(request.url,'/api/detections');
 assert.equal(request.options.method,'GET');assert.equal(request.options.credentials,'omit');
 assert.equal(request.options.cache,'no-store');assert.equal(request.options.headers.Authorization,'Bearer '+'z'.repeat(16));
});
test('invalid authorization and request failures have distinct errors',async()=>{
 const deny=async()=>({ok:false,status:401});
 await assert.rejects(fetchLabDetections('short',undefined,deny),/16 characters/);
 await assert.rejects(fetchLabDetections('z'.repeat(16),undefined,deny),/HTTP 401/);
 await assert.rejects(fetchLabDetections('z'.repeat(16),undefined,async()=>({ok:false,status:503})),/HTTP 503/);
});
