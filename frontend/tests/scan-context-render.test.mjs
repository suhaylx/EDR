import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {decodeLabDetections} from '../.test-dist/detections.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
import {ScanEvidenceContext} from '../.test-dist/ScanEvidenceContext.js';
import {ScanEvidenceWorkbench} from '../.test-dist/ScanEvidenceWorkbench.js';

const scan=(id,patch={})=>({
  id,agent_id:'WIN-A',status:'completed',scan_type:'path',
  verdict:'unscanned',created_at:'2026-11-21T12:00:00Z',
  engine:'clamav',engine_version:'1.5',database_version:'lab',
  threat_name:'',detail:'reported',...patch,
});
const detection=(id,patch={})=>({
  id,device_id:'WIN-A',rule_id:'RULE-13',category:'registry',
  severity:'high',confidence:'low',process_guid:'{abc}',
  process_image:'p.exe',module_path:'',load_event_id:'',
  evidence_event_id:'go-'+id,target_object:'HKLM\\Run',
  evidence_source_event_id:13,file_create_event_id:'',
  observed_at:'2026-11-21T12:01:00Z',explanation:'reported',...patch,
});
const event=(id,patch={})=>({
  id,device_id:'WIN-A',platform:'windows',source:'sysmon',
  source_event_id:13,type:'registry',source_record_id:'123',
  time:'2026-11-21T12:01:00Z',received_at:'2026-11-21T12:04:00Z',
  time_origin:'sender',process_guid:'{abc}',parent_process_guid:'',
  image:'a.exe',file_path:'HKLM\\Run',detail:'reported',
  source_fields:{},...patch,
});
const render=(patch={})=>{
  const rawJobs=patch.jobs||[scan('selected'),scan('other')];
  const jobs=decodeScanJobs(rawJobs);
  return renderToStaticMarkup(createElement(ScanEvidenceContext,{
    selected:patch.selected||jobs[0],jobs,
    detections:decodeLabDetections(patch.detections||[detection('one')]),
    events:decodeLabTelemetry(patch.events||[event('go-one')]),
    generatedAt:patch.generatedAt||'2026-11-21T14:00:00Z',
    onBack:()=>{},onInspectSource:()=>{},onInvestigate:()=>{},onSelectScan:()=>{},
  }));
};
test('read-only scan history exposes a labeled same-endpoint pivot, never scan triggers',()=>{
  const html=renderToStaticMarkup(createElement(ScanEvidenceWorkbench,{
    jobs:decodeScanJobs([scan('selected')]),onInspectContext:()=>{},
  }));
  assert.match(html,/Inspect same-endpoint evidence/);
  assert.match(html,/same-endpoint retained context for scan job selected/);
  assert.doesNotMatch(html,/<button[^>]*>(Run scan|Quarantine|Isolate)<\/button>/i);
});
test('context has semantic heading/focus target, native labels, and evidence-only actions',()=>{
  const html=render();
  assert.match(html,/aria-labelledby="scan-context-title"/);
  assert.match(html,/tabindex="-1"/i);
  for (const id of ['scan-context-window','scan-context-kind','scan-context-search',
    'scan-context-sort','scan-context-size']) assert.match(html,new RegExp('for="'+id+'"'));
  assert.match(html,/aria-live="polite"/);
  assert.match(html,/<caption>/);
  assert.match(html,/Inspect exact Go event go-one on WIN-A/);
  assert.match(html,/Inspect detection one on WIN-A/);
  assert.match(html,/Inspect other reported scan job/);
  assert.match(html,/Back to scan evidence worklist/);
});
test('context evidence labels state noncausality, retention limits and scan unverified',()=>{
  const html=render();
  assert.match(html,/do not prove that this scan ran/);
  assert.match(html,/at most 100/);
  assert.match(html,/not installed coverage/);
  assert.match(html,/not attested by lab API/i);
  assert.doesNotMatch(html,/protection verified|confirmed infection/i);
});
test('empty context does not claim endpoint is idle or protected',()=>{
  const html=render({jobs:[scan('selected')],detections:[],events:[]});
  assert.match(html,/No other records for this exact endpoint/);
  assert.match(html,/not proof the endpoint had no activity/);
  assert.doesNotMatch(html,/<tbody>/);
});
test('rendered rows are bounded to 25 and show time-source labels',()=>{
  const html=render({jobs:[scan('selected'),
    ...Array.from({length:66},(_,i)=>scan('j'+i))],detections:[],events:[]});
  assert.match(html,/66 of 66 same-endpoint record\(s\) match/);
  assert.match(html,/Page 1 of 3/);
  assert.match(html,/rows 1–25/);
  const body=html.split('<tbody>')[1]?.split('</tbody>')[0]||'';
  assert.equal((body.match(/<tr>/g)||[]).length,25);
  assert.match(html,/Go server-recorded job creation time/);
});
test('future timestamps receive visible warning, not asserted causality',()=>{
  const html=render({generatedAt:'2026-11-21T11:00:00Z'});
  assert.match(html,/Some reported timestamps are later/);
  assert.match(html,/Clock alignment and provenance/);
});
test('malicious HTML in returned event class and detection rule stays escaped',()=>{
  const html=render({events:[event('go-one',{type:'<img src=x onerror=alert(1)>',
    source_event_id:0,source:'legacy'})],
    detections:[detection('one',{rule_id:'<script>alert(1)</script>'})]});
  assert.match(html,/&lt;script/);
  assert.match(html,/&lt;img/);
  assert.doesNotMatch(html,/<script\b|<img\b/i);
});
test('clipboard content is not printed, even if source decoder retained detail',()=>{
  const html=render({events:[event('go-clip',{
    source_event_id:24,process_guid:'',image:'',file_path:'',
    detail:'SECRET_CLIPBOARD_CONTENT',source_fields:{},
  })]});
  assert.match(html,/Clipboard-change metadata only/);
  assert.doesNotMatch(html,/SECRET_CLIPBOARD_CONTENT/);
});
