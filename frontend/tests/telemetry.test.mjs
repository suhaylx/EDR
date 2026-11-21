import test from 'node:test';
import assert from 'node:assert/strict';
import {decodeLabTelemetry,observedSysmonCounts,SYSMON_EVENT_NAMES,fetchLabTelemetry,reportedReceiptGap} from '../.test-dist/telemetry.js';

const event=(changes={})=>({
  id:'ev1',device_id:'win-lab-01',platform:'windows',source:'sysmon',
  source_event_id:7,source_record_id:'124',type:'module_load',
  time:'2026-11-21T13:00:00Z',received_at:'2026-11-21T13:00:01Z',
  image:'C:\\Windows\\explorer.exe',file_path:'C:\\Temp\\demo.dll',
  process_guid:'{123}',source_fields:{image_loaded:'C:\\Temp\\demo.dll'},
  ...changes
});

test('supports all Sysmon 1-29 and 255 without claiming installed coverage',()=>{
  assert.equal(Object.keys(SYSMON_EVENT_NAMES).length,30);
  for(const id of [...Array(29)].map((_,i)=>i+1).concat([255])) {
    const v=decodeLabTelemetry([event({source_event_id:id,id:'event'+id,
      source_fields:id===24?{}:{rule_name:'lab'},image:id===24?'':'app.exe',
      file_path:id===24?'':'C:\\Lab\\file',process_guid:id===24?'':'{123}'})]);
    assert.equal(v[0].source_event_id,id);
  }
  const events=decodeLabTelemetry([
    event(),event({id:'e2',source_event_id:3,source_record_id:'125',source_fields:{destination_ip:'10.0.0.1'}}),
    event({id:'e3',source:'procfs',platform:'linux',source_event_id:0,source_fields:{},image:'/usr/bin/true',file_path:''}),
  ]);
  const counts=observedSysmonCounts(events);
  assert.equal(counts.get(7),1);
  assert.equal(counts.get(3),1);
  assert.equal(counts.has(1),false);
  assert.equal(counts.size,2);
});
test('requires explicit source evidence and rejects private payloads',()=>{
  assert.throws(()=>decodeLabTelemetry([event({source_fields:{command_line:'secret'}})]),/Private/);
  assert.throws(()=>decodeLabTelemetry([event({source_fields:{user:'administrator'}})]),/Private/);
  assert.throws(()=>decodeLabTelemetry([event({source_event_id:24})]),/(Clipboard|Private)/);
  const process=decodeLabTelemetry([event({source_event_id:1,image:'a.exe',parent_process_guid:'{parent}',source_fields:{}})]);
  assert.equal(process[0].parent_process_guid,'{parent}');
  assert.throws(()=>decodeLabTelemetry([event({source_event_id:3,parent_process_guid:'{parent}'})]),/Only Sysmon/);
  assert.throws(()=>decodeLabTelemetry([event({source:'procfs',platform:'linux',source_event_id:3})]),/Inconsistent/);
  assert.throws(()=>decodeLabTelemetry([event({source_event_id:30})]),/Inconsistent/);
  assert.throws(()=>decodeLabTelemetry([event({source_fields:{query_name:'line\nbreak'}})]),/Invalid/);
  assert.throws(()=>decodeLabTelemetry([event({id:'ev1'}),event({id:'ev1'})]),/duplicated/);
});
test('legacy missing numerical ID remains an unclassified source event',()=>{
  const legacy=decodeLabTelemetry([event({source_event_id:undefined,source_fields:{}})]);
  assert.equal(legacy[0].source_event_id,0);
  assert.equal(observedSysmonCounts(legacy).size,0);
});
test('authorized API request is no-store and has no cookies',async()=>{
  let request;
  const fake=async(path,opt)=>{
    request={path,opt};
    return {ok:true,json:async()=>[event()]};
  };
  const values=await fetchLabTelemetry('0123456789abcdef',undefined,fake);
  assert.equal(values.length,1);
  assert.equal(request.path,'/api/events');
  assert.equal(request.opt.cache,'no-store');
  assert.equal(request.opt.credentials,'omit');
  assert.equal(request.opt.headers.Authorization,'Bearer 0123456789abcdef');
  await assert.rejects(fetchLabTelemetry('0123456789abcdef',undefined,async()=>({ok:false,status:401})),/401/);
});

test('SEC-076: Sysmon provider and channel remain explicitly sender-reported',()=>{
  const valid=decodeLabTelemetry([event({
    source_provider:'Microsoft-Windows-Sysmon',
    source_channel:'Microsoft-Windows-Sysmon/Operational'
  })]);
  assert.equal(valid[0].source_provider,'Microsoft-Windows-Sysmon');
  assert.equal(valid[0].source_channel,'Microsoft-Windows-Sysmon/Operational');
  // Legacy records remain explicitly unknown; no provider attribution is invented.
  const legacy=decodeLabTelemetry([event()]);
  assert.equal(legacy[0].source_provider,'');
  assert.equal(legacy[0].source_channel,'');
  for(const candidate of [
    {source_provider:'Microsoft-Windows-Security-Auditing',source_channel:'Security'},
    {source_provider:'Microsoft-Windows-Sysmon',source_channel:'Security'},
    {source_provider:'Microsoft-Windows-PowerShell',source_channel:'Microsoft-Windows-PowerShell/Operational'},
    {source_provider:'Service Control Manager',source_channel:'System'},
    {source_provider:'Microsoft-Windows-Sysmon',source_channel:''},
    {source_provider:'',source_channel:'Microsoft-Windows-Sysmon/Operational'},
  ]) {
    assert.throws(()=>decodeLabTelemetry([event(candidate)]),/provider\/channel mismatch/);
  }
  assert.throws(()=>decodeLabTelemetry([event({
    source:'procfs',platform:'linux',source_event_id:0,source_fields:{},
    source_provider:'Microsoft-Windows-Sysmon',source_channel:'Microsoft-Windows-Sysmon/Operational'
  })]),/provider\/channel mismatch/);
});

test('Day 5 timing hint preserves uncertainty about queue delay versus clock drift',()=>{
  const e=decodeLabTelemetry([event({
    time:'2026-11-21T12:00:00Z',
    received_at:'2026-11-21T12:06:00Z',
    time_origin:'sender_reported_unverified'
  })])[0];
  assert.match(reportedReceiptGap(e),/6 minute/);
  assert.match(reportedReceiptGap(e),/queue delay, clock drift, or sender error/);
  assert.equal(reportedReceiptGap({...e,received_at:'2026-11-21T12:02:00Z'}),'');
  assert.equal(reportedReceiptGap({...e,time_origin:'server_received'}),'');
  assert.equal(reportedReceiptGap({...e,time:''}),'');
  assert.equal(reportedReceiptGap({...e,received_at:''}),'');
  assert.equal(reportedReceiptGap({...e,received_at:'2026-11-19T12:00:00Z'}).includes('day(s)'),true);
  assert.equal(reportedReceiptGap({...e,time:'2026-11-21T12:06:00Z',received_at:'2026-11-21T12:00:00Z'}).includes('6 minute(s)'),true);
});
