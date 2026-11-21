import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeLabDetections, detectionsInWindow } from '../.test-dist/detections.js';
import {
  retainedAlertCounts, severityBucket, filteredRetainedAlerts, primaryDetectionSource,
} from '../.test-dist/multisignal-alert-triage.js';
import { locateRetainedSource } from '../.test-dist/retained-source.js';
import { decodeLabTelemetry } from '../.test-dist/telemetry.js';

const detection = (id, patch = {}) => ({
  id, device_id: 'host-A', rule_id:'LAB-MULTI-1',category:'behavioral',
  severity:'medium',confidence:'low',process_guid:'',process_image:'',
  module_path:'',load_event_id:'', evidence_event_id:'go-evt-7',
  target_object:'registry\\key', evidence_source_event_id:13,
  file_create_event_id:'',observed_at:'2026-11-21T10:00:00Z',
  explanation:'Observed retained signal only',...patch,
});
const telemetry = (id,patch={})=>({
  id,device_id:'host-A',platform:'windows',source:'sysmon',
  type:'registry_update',source_event_id:13,source_record_id:'win-rec-17',
  time:'2026-11-21T10:00:00Z',received_at:'2026-11-21T10:00:01Z',
  time_origin:'sender', process_guid:'', parent_process_guid:'',
  image:'',file_path:'',detail:'reported',source_fields:{},...patch,
});

test('severity counts preserve unknown and case-folded labels',()=>{
  const records=decodeLabDetections([
    detection('a',{severity:'CRITICAL'}),detection('b',{severity:'High'}),
    detection('c',{severity:'medium'}),detection('d',{severity:'low'}),
    detection('e',{severity:'informational'}),
  ]);
  assert.equal(severityBucket(' HIGH '),'high');
  assert.deepEqual(retainedAlertCounts(records),
    {critical:1,high:1,medium:1,low:1,other:1});
  assert.deepEqual(filteredRetainedAlerts(records,'critical_high','all','').map(d=>d.id),['a','b']);
  assert.deepEqual(filteredRetainedAlerts(records,'other','all','').map(d=>d.id),['e']);
});
test('source-class filter and local search preserve records including no process GUID',()=>{
  const records=decodeLabDetections([
    detection('unknown',{evidence_source_event_id:0,rule_id:'RULE-NO-ID'}),
    detection('network',{severity:'high',evidence_source_event_id:3,
      evidence_event_id:'go-net-1',target_object:'example.com',device_id:'host-B'}),
  ]);
  assert.deepEqual(filteredRetainedAlerts(records,'all','unknown_event_type','').map(d=>d.id),['unknown']);
  assert.deepEqual(filteredRetainedAlerts(records,'all','with_event_type','').map(d=>d.id),['network']);
  assert.deepEqual(filteredRetainedAlerts(records,'all','all','HOST-b').map(d=>d.id),['network']);
  assert.deepEqual(filteredRetainedAlerts(records,'all','all','example.com').map(d=>d.id),['network']);
  assert.deepEqual(records.map(d=>d.id),['unknown','network']);
});
test('source identity uses general event ID; legacy load ID is only a fallback',()=>{
  const modern=decodeLabDetections([detection('modern',{
    evidence_event_id:'go-registry-1',load_event_id:'legacy-dll-2',
  })])[0];
  assert.deepEqual(primaryDetectionSource(modern),{deviceID:'host-A',eventID:'go-registry-1'});
  const legacy=decodeLabDetections([detection('legacy',{
    evidence_event_id:'',load_event_id:'go-dll-1',evidence_source_event_id:7,
  })])[0];
  assert.deepEqual(primaryDetectionSource(legacy),{deviceID:'host-A',eventID:'go-dll-1'});
});
test('UTC server window is applied before local severity counts',()=>{
  const records=decodeLabDetections([
    detection('recent',{severity:'low'}),
    detection('old',{severity:'critical',observed_at:'2026-11-10T10:00:00Z'}),
    detection('future',{severity:'critical',observed_at:'2026-11-22T10:00:00Z'}),
  ]);
  const visible=detectionsInWindow(records,'2026-11-21T12:00:00Z',7);
  assert.deepEqual(visible.map(d=>d.id),['recent']);
  assert.equal(retainedAlertCounts(visible).critical,0);
});
test('source inspection never matches a RecordID collision or another endpoint',()=>{
  const events=decodeLabTelemetry([
    telemetry('other-go-event',{device_id:'host-A',source_record_id:'go-evt-7'}),
    telemetry('go-evt-7',{device_id:'host-B',source_record_id:'win-rec-17'}),
  ]);
  assert.equal(locateRetainedSource(events,{deviceID:'host-A',eventID:'go-evt-7'}),null);
  const correct=decodeLabTelemetry([...events,telemetry('go-evt-7',{device_id:'host-A'})]);
  assert.equal(locateRetainedSource(correct,{deviceID:'host-A',eventID:'go-evt-7'})?.device_id,'host-A');
  assert.equal(locateRetainedSource(correct,{deviceID:'host-X',eventID:'go-evt-7'}),null);
});
test('empty retained events do not imply absent endpoint activity',()=>{
  assert.equal(locateRetainedSource([],{deviceID:'host-A',eventID:'go-evt-7'}),null);
  assert.deepEqual(filteredRetainedAlerts([],'all','all',''),[]);
});
