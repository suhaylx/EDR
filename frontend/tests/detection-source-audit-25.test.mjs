import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeLabDetections } from '../.test-dist/detections.js';
import { decodeLabTelemetry } from '../.test-dist/telemetry.js';
import {
  auditDetectionSources,indexRetainedEventSample,filterAuditRows,
  summarizeAudit,pageAudit,DEFAULT_AUDIT_QUERY,PRIMARY_LABELS,FILE_LABELS,
} from '../.test-dist/detection-source-audit.js';

const generatedAt='2026-11-21T14:00:00Z';
const detection=(id,patch={})=>({
  id,device_id:'host-A',rule_id:'R-A',category:'behavior',severity:'high',
  confidence:'low',process_guid:'{P}',process_image:'p.exe',
  module_path:'',load_event_id:'',evidence_event_id:'go-'+id,
  target_object:'HKLM\\Run',evidence_source_event_id:13,
  file_create_event_id:'',observed_at:'2026-11-21T12:00:00Z',
  explanation:'unverified signal',...patch,
});
const source=(id,patch={})=>({
  id,device_id:'host-A',platform:'windows',source:'sysmon',
  type:'registry',source_event_id:13,source_record_id:'win-record-7',
  time:'2026-11-21T12:00:00Z',received_at:'2026-11-21T12:01:00Z',
  time_origin:'sender',process_guid:'{P}',parent_process_guid:'',
  image:'p.exe',file_path:'HKLM\\Run',detail:'unverified',
  source_fields:{},...patch,
});
const audit=(ds,es)=>auditDetectionSources(decodeLabDetections(ds),decodeLabTelemetry(es),generatedAt);
const one=(d=detection('a'),e=source('go-a'))=>audit([d],[e])[0];
const query=(rs,patch={})=>filterAuditRows(rs,{...DEFAULT_AUDIT_QUERY,...patch});

test('M101 one claimed Go source ID is linked only by exact opaque host identity',()=>{
 const r=one();
 assert.equal(r.primaryID,'go-a');assert.equal(r.deviceID,'host-A');
 assert.equal(r.primaryState,'reported_type_agrees');
});
test('M102 same Go event ID on a different host is not considered retained evidence',()=>{
 const r=one(detection('a'),source('go-a',{device_id:'host-B'}));
 assert.equal(r.primaryState,'not_in_sample');assert.equal(r.sourceAvailable,false);
});
test('M103 source IDs are case-sensitive even when a sender varies capitalization',()=>{
 const r=one(detection('a',{evidence_event_id:'GO-A'}),source('go-a'));
 assert.equal(r.primaryState,'not_in_sample');
});
test('M104 legacy load-event ID is only a fallback when general primary ID absent',()=>{
 const rows=auditDetectionSources([detection('a',{evidence_event_id:'',load_event_id:'legacy'})],
   decodeLabTelemetry([source('legacy')]),generatedAt);
 assert.equal(rows[0].primaryID,'legacy');assert.equal(rows[0].sourceAvailable,true);
});
test('M105 missing primary ID is unknown rather than a fabricated DLL source',()=>{
 const r=auditDetectionSources([detection('a',{evidence_event_id:'',load_event_id:''})],[],generatedAt)[0];
 assert.equal(r.primaryState,'missing_reference');
 assert.ok(r.flags.includes('primary_reference_missing'));
});
test('M106 missing from a bounded API sample is not a verified loss event',()=>{
 const r=one(detection('a'),source('other'));
 assert.equal(r.primaryState,'not_in_sample');
 assert.match(PRIMARY_LABELS.not_in_sample,/not in returned sample/);
});
test('M107 matching reported Sysmon numeric ID yields only reported agreement',()=>{
 const r=one();
 assert.equal(r.primaryState,'reported_type_agrees');
 assert.equal(r.flags.length,0);
 assert.match(PRIMARY_LABELS.reported_type_agrees,/not attested/);
});
test('M108 claimed event type disagreeing with returned type is surfaced',()=>{
 const r=one(detection('a',{evidence_source_event_id:7}));
 assert.equal(r.primaryState,'type_conflict');
 assert.ok(r.flags.includes('source_type_conflict'));
});
test('M109 numeric Sysmon type zero on detection remains explicitly unreported',()=>{
 const r=one(detection('a',{evidence_source_event_id:0}));
 assert.equal(r.primaryState,'type_unreported');
 assert.ok(r.flags.includes('primary_type_unreported'));
});
test('M110 source with numeric event type zero is never reported Sysmon agreement',()=>{
 const r=one(detection('a'),source('go-a',{source_event_id:0,source:'legacy'}));
 assert.equal(r.primaryState,'untyped_source');
});
test('M111 Linux source can never satisfy a Windows Sysmon type claim',()=>{
 const r=one(detection('a'),source('go-a',{
   source:'procfs',platform:'linux',source_event_id:0,process_guid:'{P}',
 }));
 assert.equal(r.primaryState,'untyped_source');
});
test('M112 conflicting nonempty process GUIDs yield a distinct discrepancy',()=>{
 const r=one(detection('a'),source('go-a',{process_guid:'{OTHER}'}));
 assert.ok(r.flags.includes('process_guid_conflict'));
});
test('M113 missing detection process GUID remains unknown, never inferred ancestry',()=>{
 const r=one(detection('a',{process_guid:''}));
 assert.ok(r.flags.includes('no_process_guid'));
 assert.ok(!r.flags.includes('process_guid_conflict'));
});
test('M114 absent source GUID cannot be interpreted as a GUID mismatch',()=>{
 const r=one(detection('a'),source('go-a',{process_guid:''}));
 assert.ok(!r.flags.includes('process_guid_conflict'));
});
test('M115 distinct linked FileCreate with returned Windows Sysmon ID 11 is reported only',()=>{
 const r=audit([detection('a',{file_create_event_id:'go-create'})],
  [source('go-a'),source('go-create',{source_event_id:11})])[0];
 assert.equal(r.fileState,'reported_filecreate_11');
 assert.equal(r.fileSourceAvailable,true);
 assert.match(FILE_LABELS.reported_filecreate_11,/not attested/);
});
test('M116 linked FileCreate outside retained sample is explicitly unavailable',()=>{
 const r=one(detection('a',{file_create_event_id:'lost-create'}));
 assert.equal(r.fileState,'not_in_sample');
 assert.ok(r.flags.includes('filecreate_not_retained'));
});
test('M117 wrong Event 7 cannot be labeled FileCreate Event 11',()=>{
 const r=audit([detection('a',{file_create_event_id:'go-loaded'})],
  [source('go-a'),source('go-loaded',{source_event_id:7})])[0];
 assert.equal(r.fileState,'not_sysmon_11');
 assert.ok(r.flags.includes('filecreate_type_conflict'));
});
test('M118 linked FileCreate equal to primary Go ID is not independent evidence',()=>{
 const r=one(detection('a',{file_create_event_id:'go-a'}));
 assert.equal(r.fileState,'same_primary_reference');
 assert.equal(r.fileSourceAvailable,false);
 assert.ok(r.flags.includes('filecreate_is_primary'));
});
test('M119 cross-host FileCreate ID collision never produces positive linkage',()=>{
 const r=audit([detection('a',{file_create_event_id:'go-create'})],
  [source('go-a'),source('go-create',{device_id:'host-B',source_event_id:11})])[0];
 assert.equal(r.fileState,'not_in_sample');
});
test('M120 missing server receipt time prevents a freshness assertion',()=>{
 const r=one(detection('a'),source('go-a',{received_at:''}));
 assert.ok(r.flags.includes('source_receipt_unknown'));
});
test('M121 future reported server receipt time triggers a clock warning',()=>{
 const r=one(detection('a'),source('go-a',{received_at:'2026-11-21T16:00:00Z'}));
 assert.ok(r.flags.includes('future_source_receipt'));
});
test('M122 source free text and clipboard content are never copied into audit searchable rows',()=>{
 const clipboard=source('go-a',{source_event_id:24,detail:'DO_NOT_COPY_SECRET',
  process_guid:'',image:'',file_path:'',source_fields:{}});
 const r=audit([detection('a',{evidence_source_event_id:24,process_guid:''})],
  [clipboard])[0];
 assert.equal(r.primaryState,'reported_type_agrees');
 assert.ok(!JSON.stringify(r).includes('DO_NOT_COPY_SECRET'));
 assert.equal(query([r],{state:'all',query:'DO_NOT_COPY_SECRET'}).length,0);
});
test('M123 local exact host and other/unclassified severity filters are robust',()=>{
 const rs=audit([detection('a'),detection('b',{id:'b',device_id:'host-B',severity:'INFO',
  evidence_event_id:'go-b'})],[source('go-a')]);
 assert.equal(query(rs,{state:'all',endpoint:'HOST-b'}).length,1);
 assert.equal(query(rs,{state:'all',endpoint:'host'}).length,0);
 assert.deepEqual(query(rs,{state:'all',severity:'other'}).map(x=>x.detectionID),['b']);
});
test('M124 deterministic warning-first, severity and rule sorting preserve source records',()=>{
 const rs=audit([detection('a',{severity:'low',rule_id:'Z'}),
  detection('b',{severity:'critical',rule_id:'A',evidence_source_event_id:7})],[source('go-a'),source('go-b')]);
 assert.deepEqual(query(rs,{state:'all',sort:'issues'}).map(x=>x.detectionID),['b','a']);
 assert.deepEqual(query(rs,{state:'all',sort:'severity'}).map(x=>x.detectionID),['b','a']);
 assert.deepEqual(query(rs,{state:'all',sort:'rule'}).map(x=>x.detectionID),['b','a']);
 assert.deepEqual(rs.map(x=>x.detectionID),['a','b']);
});
test('M125 25/50/100 pages, response counts and duplicate source collision fail closed',()=>{
 const rs=auditDetectionSources(Array.from({length:61},(_,i)=>
   detection('d'+i,{evidence_event_id:'go-'+i})),[],generatedAt);
 const pages=[0,1,2].map(i=>pageAudit(rs,i,25));
 assert.deepEqual(pages.map(p=>[p.start,p.end]),[[1,25],[26,50],[51,61]]);
 assert.equal(new Set(pages.flatMap(p=>p.rows.map(x=>x.detectionID))).size,61);
 assert.equal(pageAudit([],0,25).pages,1);
 assert.equal(pageAudit(rs,999,25).page,2);
 assert.throws(()=>pageAudit(rs,1,2));
 assert.throws(()=>pageAudit(rs,Number.NaN,25));
 assert.equal(summarizeAudit(rs).primaryUnavailable,61);
 const s=source('collision');
 const idx=indexRetainedEventSample([s,s,s]);
 assert.equal(idx.get('host-A')?.has('collision'),false);
});
