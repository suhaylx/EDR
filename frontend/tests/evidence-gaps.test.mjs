import test from 'node:test';
import assert from 'node:assert/strict';
import {decodeLabDetections} from '../.test-dist/detections.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';
import {summarizeReturnedEvidenceGaps,otherReportedProcessEvents} from '../.test-dist/evidence-gaps.js';
import {linkedFileCreateSource} from '../.test-dist/multisignal-alert-triage.js';

const detection=(id,patch={})=>({
  id,device_id:'hostA',rule_id:'LAB-RULE',category:'signal',severity:'low',confidence:'low',
  process_guid:'{P}',process_image:'',module_path:'',load_event_id:'',
  evidence_event_id:'go-'+id,evidence_source_event_id:7,
  file_create_event_id:'file-'+id,target_object:'file.exe',
  observed_at:'2026-11-21T12:00:00Z',explanation:'Reported',...patch,
});
const event=(id,patch={})=>({
  id,device_id:'hostA',platform:'windows',source:'sysmon',
  source_event_id:7,source_record_id:'11',type:'image_load',
  time:'2026-11-21T12:00:00Z',received_at:'2026-11-21T12:01:00Z',
  time_origin:'reported',process_guid:'{P}',parent_process_guid:'',
  image:'process.exe',file_path:'mod.dll',detail:'report',
  source_fields:{},...patch,
});
test('M21 response-scoped gap summary distinguishes absent fields from sample absence',()=>{
  const rows=decodeLabDetections([detection('a'),detection('b',{
    process_guid:'',evidence_source_event_id:0,file_create_event_id:'',
    target_object:'',module_path:'',
  })]);
  const ev=decodeLabTelemetry([event('go-a')]);
  assert.deepEqual(summarizeReturnedEvidenceGaps(rows,ev),{
    returnedDetections:2,missingProcessGuid:1,unknownNumericEventType:1,
    noLinkedFileCreate:1,noTargetObject:1,
    primaryNotInEventSample:1,primaryInEventSample:1,withReportedSourceTime:1,
  });
});
test('M22 separate FileCreate reference never duplicates primary source',()=>{
  const rows=decodeLabDetections([detection('a'),detection('b',{
    file_create_event_id:'go-b',
  })]);
  assert.deepEqual(linkedFileCreateSource(rows[0]),
    {deviceID:'hostA',eventID:'file-a',expectedSysmonID:11});
  assert.equal(linkedFileCreateSource(rows[1]),null);
});
test('M23 same-process context requires same endpoint AND process GUID',()=>{
  const first=event('primary');
  const events=decodeLabTelemetry([first,event('same'),event('other-process',{process_guid:'{OTHER}'}),
    event('other-host',{device_id:'hostB'})]);
  const result=otherReportedProcessEvents(events[0],events);
  assert.deepEqual(result.events.map(x=>x.id),['same']);
  assert.equal(result.total,1);
});
test('M24 related-event limit is bounded and cannot imply complete history',()=>{
  const events=decodeLabTelemetry([
    event('primary'),...Array.from({length:14},(_,i)=>event('x'+i)),
  ]);
  const result=otherReportedProcessEvents(events[0],events,10);
  assert.equal(result.total,14);
  assert.equal(result.events.length,10);
  assert.deepEqual(otherReportedProcessEvents({...events[0],process_guid:''},events).events,[]);
  assert.deepEqual(otherReportedProcessEvents(events[0],events,0).events,[]);
});
test('M25 gap summary never counts a cross-host event ID as authenticated evidence',()=>{
  const rows=decodeLabDetections([detection('a')]);
  const ev=decodeLabTelemetry([event('go-a',{device_id:'hostB'})]);
  const summary=summarizeReturnedEvidenceGaps(rows,ev);
  assert.equal(summary.primaryInEventSample,0);
  assert.equal(summary.primaryNotInEventSample,1);
});
