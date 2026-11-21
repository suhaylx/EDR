import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {decodeLabDetections} from '../.test-dist/detections.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';
import {DetectionSourceAudit} from '../.test-dist/DetectionSourceAudit.js';
import {MultisignalAlertTriage} from '../.test-dist/MultisignalAlertTriage.js';

const d=(id,patch={})=>({
  id,device_id:'host-A',rule_id:'LAB-RULE',category:'behavior',
  severity:'medium',confidence:'low',process_guid:'{P}',
  process_image:'process.exe',module_path:'',load_event_id:'',
  evidence_event_id:'go-'+id,target_object:'HKLM\\Run',
  evidence_source_event_id:13,file_create_event_id:'',
  observed_at:'2026-11-21T11:00:00Z',explanation:'reported',...patch,
});
const e=(id,patch={})=>({
  id,device_id:'host-A',platform:'windows',source:'sysmon',
  source_event_id:13,type:'registry',source_record_id:'17',
  time:'2026-11-21T11:00:00Z',received_at:'2026-11-21T11:01:00Z',
  time_origin:'sender',process_guid:'{P}',parent_process_guid:'',
  image:'process.exe',file_path:'HKLM\\Run',detail:'reported',
  source_fields:{},...patch,
});
const audit=(ds,es)=>renderToStaticMarkup(createElement(DetectionSourceAudit,{
  detections:decodeLabDetections(ds),events:decodeLabTelemetry(es),
  generatedAt:'2026-11-21T12:00:00Z',
  onInspectSource:()=>{},onInvestigate:()=>{},
}));
test('audit controls are labeled, table described and result count announced',()=>{
  const html=audit([d('a',{evidence_source_event_id:7})],[e('go-a')]);
  for(const field of ['audit-state','audit-severity','audit-host','audit-query','audit-sort','audit-page-size'])
    assert.match(html,new RegExp('for="'+field+'"'));
  assert.match(html,/<caption>/);
  assert.match(html,/aria-live="polite"/);
  assert.match(html,/Detection-source integrity audit/);
  assert.match(html,/reported values/);
});
test('audit with no detections does not claim a protected or clean fleet',()=>{
  const html=audit([],[]);
  assert.match(html,/No detections returned/);
  assert.match(html,/does not establish clean endpoints/);
  assert.doesNotMatch(html,/<tbody>/);
});
test('record matching source type is reported agreement not authenticated trust',()=>{
  const html=audit([d('a')],[e('go-a')]);
  assert.match(html,/Reported type agreement \(not attested\)/);
  assert.doesNotMatch(html,/Verified Sysmon enforcement|protected fleet/);
});
test('misleading FileCreate source and GUID conflicts remain visible to analyst',()=>{
  const html=audit([d('a',{file_create_event_id:'go-file'})],
    [e('go-a',{process_guid:'{DIFFERENT}'}),e('go-file',{source_event_id:7})]);
  assert.match(html,/Reported GUID disagreement/);
  assert.match(html,/Separate FileCreate reference issues/);
  assert.match(html,/warning\(s\)/);
});
test('audited source uses React text escaping, not arbitrary HTML insertion',()=>{
  const html=audit([d('a',{rule_id:'<script>alert(1)</script>',evidence_source_event_id:7})],
    [e('go-a')]);
  assert.match(html,/&lt;script/);
  assert.doesNotMatch(html,/<script\b/i);
});
test('clipboard details are omitted even when underlying telemetry decoder allows metadata',()=>{
  const html=audit([d('a',{process_guid:'',evidence_source_event_id:24})],
    [e('go-a',{source_event_id:24,process_guid:'',image:'',file_path:'',
      detail:'SECRET_CLIPBOARD_STRING',source_fields:{}})]);
  assert.doesNotMatch(html,/SECRET_CLIPBOARD_STRING/);
  assert.match(html,/Sysmon type/);
});
test('default audit worklist renders 25 of 61 rows with bounded pagination',()=>{
  const ds=Array.from({length:61},(_,i)=>d('n'+i));
  const html=audit(ds,[]);
  assert.match(html,/61 of 61 returned detection reference\(s\) match/);
  assert.match(html,/Page 1 of 3/);
  assert.match(html,/rows 1–25/);
  const body=html.split('<tbody>')[1]?.split('</tbody>')[0]||'';
  assert.equal((body.match(/<tr>/g)||[]).length,25);
});
test('audit is embedded in current alert UX without backend or response controls',()=>{
  const detections=decodeLabDetections([d('a')]);
  const events=decodeLabTelemetry([e('go-a')]);
  const html=renderToStaticMarkup(createElement(MultisignalAlertTriage,{
    detections,events,days:7,generatedAt:'2026-11-21T12:00:00Z',
    onInvestigate:()=>{},onInspectSource:()=>{},
  }));
  assert.match(html,/Review detection-to-source integrity for all returned records/);
  assert.match(html,/Detection-source integrity audit/);
  assert.doesNotMatch(html,/<button[^>]*>(Quarantine|Isolate|Delete|Run scan)<\/button>/);
});
