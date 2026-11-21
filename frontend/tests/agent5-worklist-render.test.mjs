import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {decodeLabDetections} from '../.test-dist/detections.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';
import {MultisignalAlertTriage} from '../.test-dist/MultisignalAlertTriage.js';
import {RetainedSourceInspection} from '../.test-dist/RetainedSourceInspection.js';
import {SysmonCoverage} from '../.test-dist/SysmonCoverage.js';

const detection=(id,patch={})=>({
  id,device_id:'host-A',rule_id:'RULE-13',category:'registry',
  severity:'medium',confidence:'low',process_guid:'{abc}',process_image:'cmd.exe',
  module_path:'',load_event_id:'',evidence_event_id:'go-'+id,
  target_object:'HKLM\\Run',evidence_source_event_id:13,file_create_event_id:'go-file-'+id,
  observed_at:'2026-11-21T12:00:00Z',explanation:'Lab observation',...patch,
});
const event=(id,patch={})=>({
  id,device_id:'host-A',platform:'windows',source:'sysmon',
  type:'registry',source_event_id:13,source_record_id:'99',
  time:'2026-11-21T12:00:00Z',received_at:'2026-11-21T12:01:00Z',
  time_origin:'sender',process_guid:'{abc}',parent_process_guid:'',
  image:'a.exe',file_path:'HKLM\\Run',detail:'untrusted',
  source_fields:{},...patch,
});
const alerts=(rows,events=[])=>renderToStaticMarkup(createElement(MultisignalAlertTriage,{
  detections:decodeLabDetections(rows),events:decodeLabTelemetry(events),
  days:7,generatedAt:'2026-11-21T16:00:00Z',
  onInvestigate:()=>{},onInspectSource:()=>{},
}));
const inspect=(selection,events)=>renderToStaticMarkup(createElement(RetainedSourceInspection,{
  events:decodeLabTelemetry(events),selection,onBack:()=>{},
  onInvestigate:()=>{},onInspectSource:()=>{},
}));
test('accessible analyst fields, reset, ordered pages and evidence gap summaries render',()=>{
  const html=alerts([detection('a')],[event('go-a')]);
  for(const id of ['analyst-host','analyst-rule','analyst-category','analyst-confidence',
    'analyst-process','analyst-filecreate','analyst-target','analyst-sample',
    'analyst-sort','analyst-page-size']) assert.match(html,new RegExp('for="'+id+'"'));
  assert.match(html,/Additional analyst filters/);
  assert.match(html,/Previous page/);
  assert.match(html,/Next page/);
  assert.match(html,/Page 1 of 1/);
  assert.match(html,/Returned-record evidence gaps/);
  assert.match(html,/role="status"/);
  assert.match(html,/aria-live="polite"/);
  assert.match(html,/Inspect linked FileCreate reference/);
});
test('default worklist renders 25 rows, not all 60 returned records',()=>{
  const rows=Array.from({length:60},(_,i)=>detection('n'+i));
  const html=alerts(rows);
  assert.match(html,/25 of 60/);
  assert.match(html,/Page 1 of 3/);
  assert.match(html,/rows 1–25/);
  const table=html.split('<tbody>')[1]?.split('</tbody>')[0]||'';
  assert.equal((table.match(/<tr>/g)||[]).length,25);
});
test('claimed FileCreate source with returned non-11 event is marked inconsistent',()=>{
  const html=inspect({deviceID:'host-A',eventID:'go-a',expectedSysmonID:11},[event('go-a')]);
  assert.match(html,/does not match a returned Windows Sysmon Event 11/);
  assert.match(html,/not treat it as file-creation evidence/);
  assert.match(html,/tabindex="-1"/i);
});
test('matching reported FileCreate event still does not attest real DLL execution',()=>{
  const html=inspect({deviceID:'host-A',eventID:'go-a',expectedSysmonID:11},[
    event('go-a',{source_event_id:11,source_fields:{}}),
  ]);
  assert.match(html,/Matching Event 11 classification does not attest/);
});
test('same-process context is bounded and does not claim causality or history',()=>{
  const html=inspect({deviceID:'host-A',eventID:'go-a'},[
    event('go-a'),event('go-b'),event('go-c',{process_guid:'{other}'}),
  ]);
  assert.match(html,/Other co-observed events in this response/);
  assert.match(html,/do not prove causality/);
  assert.match(html,/Inspect co-observed event/);
  assert.doesNotMatch(html,/go-c/);
});
test('telemetry table has direct exact Go event inspection, with no response action',()=>{
  const html=renderToStaticMarkup(createElement(SysmonCoverage,{
    events:decodeLabTelemetry([event('go-a')]),onInvestigate:()=>{},
    onInspectSource:()=>{},
  }));
  assert.match(html,/Inspect retained Go event go-a on host-A/);
  assert.match(html,/role="status"/);
  assert.doesNotMatch(html, /<button[^>]*>Quarantine<\/button>/);
});
test('untrusted source and target strings remain escaped in both screens',()=>{
  const alertHtml=alerts([detection('a',{target_object:'<img src=x onerror=alert(1)>'})]);
  const sourceHtml=inspect({deviceID:'host-A',eventID:'go-a'},[
    event('go-a',{detail:'<svg onload=alert(1)>'}),
  ]);
  assert.match(alertHtml,/&lt;img/);
  assert.match(sourceHtml,/&lt;svg/);
  assert.doesNotMatch(alertHtml,/<img\b/i);
  assert.doesNotMatch(sourceHtml,/<svg\b/i);
});
