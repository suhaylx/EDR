import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {decodeLabOverview} from '../.test-dist/overview.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';
import {decodeLabDetections} from '../.test-dist/detections.js';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
import {EvidenceSnapshotReview} from '../.test-dist/EvidenceSnapshotReview.js';

const time='2026-11-21T12:00:00Z';
const ep=(id,status='online')=>({
  id,platform:'windows',status,last_seen:time,events:0,alerts:0,
  inactive_seconds:0,group:'lab',reported_health:'',
  applied_policy_id:'',applied_revision:0,last_policy_error:'',
});
const overview=(patch={})=>{
  const endpoints=patch.endpoints||[ep('WIN-A')];
  return decodeLabOverview({
    generated_at:time,window_days:7,data_source:'development_in_memory_retained_telemetry',
    heartbeat_ttl_seconds:300,
    agents:endpoints.length,
    online:endpoints.filter(e=>e.status==='online').length,
    offline:endpoints.filter(e=>e.status==='offline').length,
    unknown:endpoints.filter(e=>e.status==='unknown').length,
    events:5,alerts:3,high_risk_alerts:0,policy_errors:0,
    scans:{queued:0,leased:0,completed:0,failed:0},
    severity:[],alert_trend:[],top_rules:[],policy_coverage:[],
    most_active:[],inactive_machines:[],endpoints,unavailable:[],
  },7);
};
const ev=(id,patch={})=>({
  id,device_id:'WIN-A',platform:'windows',source:'sysmon',type:'image_load',
  source_event_id:7,source_record_id:'9',time:'2026-11-21T11:00:00Z',
  received_at:'2026-11-21T11:01:00Z',time_origin:'sender',
  process_guid:'{p}',parent_process_guid:'',image:'a.exe',file_path:'a.dll',
  detail:'reported',source_fields:{},...patch,
});
const display=(patch={})=>renderToStaticMarkup(createElement(EvidenceSnapshotReview,{
  overview:overview(patch),events:decodeLabTelemetry(patch.events||[]),
  detections:decodeLabDetections(patch.detections||[]),jobs:decodeScanJobs(patch.jobs||[]),
}));

test('snapshot review renders native labels, live count, semantic tables and no response controls',()=>{
  const html=display({events:[ev('e1')]});
  for(const id of ['snapshot-search','snapshot-heartbeat','snapshot-sort','snapshot-page-size'])
    assert.match(html,new RegExp('for="'+id+'"'));
  assert.match(html,/aria-live="polite"/);
  assert.match(html,/<caption>/);
  assert.match(html,/Evidence snapshot review/);
  assert.match(html,/Previous snapshot page/);
  assert.match(html,/Next snapshot page/);
  assert.doesNotMatch(html,/<button[^>]*>(Quarantine|Isolate|Scan now|Disable protection)<\/button>/i);
});
test('source count differences do not imply missing evidence, loss or complete protection',()=>{
  const html=display({events:[ev('e1')]});
  assert.match(html,/Go overview totals/);
  assert.match(html,/Separately returned samples/);
  assert.match(html,/different bounds/);
  assert.match(html,/not an atomic backend transaction/);
  assert.match(html,/not.*endpoint protection/i);
});
test('empty returned event sample is explicitly unknown coverage',()=>{
  const html=display();
  assert.match(html,/No event records returned/);
  assert.match(html,/monitoring coverage remains unknown/);
  assert.match(html,/Installed policy, actual event collection and endpoint safety remain unknown/);
});
test('a clipboard event can only add a numeric ID count, never display content',()=>{
  const html=display({events:[ev('clipboard',{
    source_event_id:24,process_guid:'',image:'',file_path:'',
    detail:'SECRET_UNTRUSTED_CLIPBOARD_CONTENT',source_fields:{},
  })]});
  assert.match(html,/Inspect numeric Sysmon IDs/);
  assert.doesNotMatch(html,/SECRET_UNTRUSTED_CLIPBOARD_CONTENT/);
});
test('untrusted endpoint IDs remain React-escaped text and no script can run',()=>{
  const html=display({endpoints:[ep('<script>alert(1)</script>')]});
  assert.match(html,/&lt;script/);
  assert.doesNotMatch(html,/<script\b/i);
});
test('inventory table uses at most 25 rows on the initial page',()=>{
  const endpoints=Array.from({length:61},(_,i)=>ep('ep-'+i));
  const html=display({endpoints});
  assert.match(html,/61 of 61 enrolled record\(s\) match/);
  assert.match(html,/Page 1 of 3/);
  assert.match(html,/rows 1–25/);
  const table=html.split('class="snapshot-endpoint-table"')[1]||'';
  const body=table.split('<tbody>')[1]?.split('</tbody>')[0]||'';
  assert.equal((body.match(/<tr>/g)||[]).length,25);
});
test('Sysmon 7 and FileCreate 11 are labeled separately, not verified execution',()=>{
  const html=display({events:[ev('load'),ev('create',{source_event_id:11})]});
  assert.match(html,/DLL \/ image load/);
  assert.match(html,/File created/);
  assert.match(html,/not required\/installed policy coverage/);
});
