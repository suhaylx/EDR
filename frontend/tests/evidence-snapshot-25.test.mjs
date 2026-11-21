import test from 'node:test';
import assert from 'node:assert/strict';
import {decodeLabOverview} from '../.test-dist/overview.js';
import {decodeLabDetections} from '../.test-dist/detections.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
import {
  reviewEvidenceSnapshot,evidenceEventTime,isInOverviewWindow,
  filterSnapshotEndpoints,pageSnapshotEndpoints,DEFAULT_SNAPSHOT_FILTERS,
} from '../.test-dist/evidence-snapshot.js';

const now='2026-11-21T12:00:00Z';
const endpoint=(id,status,platform)=>({id,status,platform,last_seen:now,
  events:0,alerts:0,inactive_seconds:0,group:'lab',reported_health:'',
  applied_policy_id:'',applied_revision:0,last_policy_error:''});
const baseOverview=(patch={})=>({
  generated_at:now,window_days:7,data_source:'development_in_memory_retained_telemetry',
  heartbeat_ttl_seconds:300,
  agents:2,online:1,offline:0,unknown:1,events:17,alerts:8,
  high_risk_alerts:0,policy_errors:0,
  scans:{queued:0,leased:0,completed:0,failed:0},
  severity:[],alert_trend:[],top_rules:[],policy_coverage:[],
  most_active:[],inactive_machines:[],
  endpoints:[endpoint('WIN-A','online','windows'),endpoint('linux-B','unknown','linux')],
  unavailable:['source_attestation'],
  ...patch,
});
const detection=(id,patch={})=>({
  id,device_id:'WIN-A',rule_id:'RULE-7',category:'observed_signal',
  severity:'medium',confidence:'low',process_guid:'{p}',
  process_image:'a.exe',module_path:'x.dll',load_event_id:'',
  evidence_event_id:'source-'+id,target_object:'x.dll',
  evidence_source_event_id:7,file_create_event_id:'',
  observed_at:'2026-11-21T11:00:00Z',explanation:'reported lab evidence',...patch,
});
const event=(id,patch={})=>({
  id,device_id:'WIN-A',platform:'windows',source:'sysmon',type:'image_load',
  source_event_id:7,source_record_id:'win-rec-9',
  time:'2026-11-21T11:00:00Z',received_at:'2026-11-21T11:01:00Z',
  time_origin:'sender',process_guid:'{p}',parent_process_guid:'',
  image:'a.exe',file_path:'x.dll',detail:'reported',
  source_fields:{},...patch,
});
const job=(id,patch={})=>({
  id,agent_id:'WIN-A',status:'completed',scan_type:'path',
  verdict:'clean_by_signature',threat_name:'',created_at:'2026-11-21T11:00:00Z',
  engine:'clamav',engine_version:'1.5',database_version:'lab',detail:'reported',
  ...patch,
});
const review=(ds=[],es=[],jobs=[],changes={})=>reviewEvidenceSnapshot(
  decodeLabOverview(baseOverview(changes),changes.window_days??7),
  decodeLabDetections(ds),decodeLabTelemetry(es),decodeScanJobs(jobs));

test('M126 the server-generated UTC anchor is retained, never replaced with browser time',()=>{
  const s=review();assert.equal(s.generatedAt,now);assert.equal(s.days,7);
  assert.equal(s.serverReported.events,17);assert.equal(s.serverReported.alerts,8);
});
test('M127 inclusive one-day and seven-day windows use absolute milliseconds',()=>{
  const end=Date.parse(now);
  assert.equal(isInOverviewWindow(end,end,1),true);
  assert.equal(isInOverviewWindow(end-86400000,end,1),true);
  assert.equal(isInOverviewWindow(end-86400001,end,1),false);
  assert.equal(isInOverviewWindow(end-7*86400000,end,7),true);
});
test('M128 invalid/unknown UTC anchors and windows fail closed',()=>{
  assert.equal(isInOverviewWindow(Date.parse(now),Number.NaN,7),false);
  assert.equal(isInOverviewWindow(null,Date.parse(now),7),false);
  assert.equal(isInOverviewWindow(Date.parse(now),Date.parse(now),14),false);
  const o=decodeLabOverview(baseOverview(),7);
  assert.throws(()=>reviewEvidenceSnapshot({...o,generated_at:'broken'},[],[],[]),/valid server-reported/);
});
test('M129 retained detection timestamps inside and outside the UTC window are separated',()=>{
  const s=review([detection('inside'),detection('old',{
    observed_at:'2026-11-12T10:00:00Z',
  })]);
  assert.equal(s.returned.detections,2);assert.equal(s.returned.detectionsInWindow,1);
  assert.equal(s.returned.detectionsOutsideWindow,1);
});
test('M130 future-dated detections are excluded from window and visibly counted',()=>{
  const s=review([detection('future',{observed_at:'2026-11-21T13:00:00Z'})]);
  assert.equal(s.returned.detectionsAfterOverview,1);
  assert.equal(s.returned.detectionsInWindow,0);
  assert.match(s.warnings.join(' '),/timestamps are later/);
});
test('M131 detection time-zone offsets are compared as instants, not text',()=>{
  const s=review([detection('offset',{
    observed_at:'2026-11-21T16:00:00+05:00',
  })]);
  assert.equal(s.returned.detectionsInWindow,1);
  assert.equal(s.returned.detectionsAfterOverview,0);
});
test('M132 Go receipt time takes precedence over sender-reported event time',()=>{
  const t=evidenceEventTime(event('e',{time:'2026-11-15T01:00:00Z'}));
  assert.equal(t.kind,'server_receipt');
  assert.equal(t.timestamp,'2026-11-21T11:01:00Z');
});
test('M133 sender fallback is explicit when Go receipt time is missing',()=>{
  const t=evidenceEventTime(event('e',{received_at:''}));
  assert.equal(t.kind,'sender_report');assert.equal(t.timestamp,'2026-11-21T11:00:00Z');
  const s=review([],[event('e',{received_at:''})]);
  assert.equal(s.returned.eventsUsingSenderClock,1);
  assert.match(s.warnings.join(' '),/sender-reported time/);
});
test('M134 no usable timestamps means unknown; not silently zero-time event activity',()=>{
  const s=review([],[event('e',{received_at:'',time:''})]);
  assert.equal(s.returned.eventsUnknownTime,1);
  assert.equal(s.returned.eventsInWindow,0);
  assert.equal(s.returned.eventsOutsideWindow,0);
});
test('M135 empty event response does not mean security collection is complete',()=>{
  const s=review();assert.equal(s.returned.events,0);
  assert.match(s.warnings.join(' '),/monitoring coverage remains unknown/);
});
test('M136 exactly 100 returned events surface the API sample limit',()=>{
  const es=Array.from({length:100},(_,i)=>event('evt-'+i));
  const s=review([],es);assert.equal(s.returned.events,100);
  assert.equal(s.eventSampleAtLimit,true);
  assert.match(s.warnings.join(' '),/100 records/);
});
test('M137 99 returned events do not claim to have reached the API sample limit',()=>{
  const s=review([],Array.from({length:99},(_,i)=>event('evt-'+i)));
  assert.equal(s.eventSampleAtLimit,false);
  assert.ok(!s.warnings.some(x=>x.includes('reached 100 records')));
});
test('M138 non-Sysmon Windows telemetry is an Other report, not policy evidence',()=>{
  const s=review([],[event('other',{source:'legacy',source_event_id:0,type:'legacy'})]);
  assert.equal(s.returned.otherEventsInWindow,1);
  assert.equal(s.returned.windowsSysmonEventsInWindow,0);
});
test('M139 reported Event 7 and Event 11 are separately counted and labeled',()=>{
  const s=review([],[event('load'),event('create',{
    source_event_id:11,type:'file_create',
  })]);
  assert.deepEqual(s.sysmonTypes.map(x=>x.id),[7,11]);
  assert.match(s.sysmonTypes[0].label,/image load/);
  assert.match(s.sysmonTypes[1].label,/File created/);
});
test('M140 Linux collector records cannot count as Windows Sysmon coverage',()=>{
  const s=review([],[event('linux',{
    device_id:'linux-B',platform:'linux',source:'procfs',
    source_event_id:0,type:'process_snapshot',
  })]);
  assert.equal(s.returned.linuxEventsInWindow,1);
  assert.equal(s.returned.windowsSysmonEventsInWindow,0);
  assert.equal(s.endpointRows[1].observedSysmonTypes,0);
});
test('M141 Sysmon 24 clipboard detail is never copied into snapshot rollups',()=>{
  const s=review([],[event('clipboard',{
    source_event_id:24,process_guid:'',image:'',file_path:'',
    detail:'SECRET_CLIPBOARD_PAYLOAD',source_fields:{},
  })]);
  assert.equal(s.sysmonTypes.find(x=>x.id===24)?.count,1);
  assert.ok(!JSON.stringify(s).includes('SECRET_CLIPBOARD_PAYLOAD'));
});
test('M142 the three event classes partition in-window reports without invented totals',()=>{
  const s=review([],[event('sysmon'),event('linux',{
    device_id:'linux-B',platform:'linux',source:'procfs',source_event_id:0,
  }),event('legacy',{source:'other',source_event_id:0})]);
  assert.equal(s.returned.eventsInWindow,3);
  assert.deepEqual([s.returned.windowsSysmonEventsInWindow,s.returned.linuxEventsInWindow,
    s.returned.otherEventsInWindow],[1,1,1]);
});
test('M143 event receipt newer than overview is flagged and excluded, not called lost',()=>{
  const s=review([],[event('future',{received_at:'2026-11-21T13:00:00Z'})]);
  assert.equal(s.returned.eventsAfterOverview,1);
  assert.equal(s.returned.eventsInWindow,0);
  assert.equal(s.returned.eventsOutsideWindow,1);
  assert.match(s.warnings.join(' '),/not synchronized/);
});
test('M144 event references join exactly to an enrolled opaque endpoint ID',()=>{
  const s=review([detection('a')],[event('source-a')],[job('job-a')]);
  const row=s.endpointRows.find(x=>x.id==='WIN-A');
  assert.equal(row?.detectionsInWindow,1);
  assert.equal(row?.eventsInWindow,1);
  assert.equal(row?.scanJobsReturned,1);
});
test('M145 a case variation of endpoint ID is not silently treated as the same device',()=>{
  const s=review([detection('a',{device_id:'win-a'})],[],[]);
  assert.equal(s.returned.detectionsNotInInventory,1);
  assert.equal(s.endpointRows[0].detectionsInWindow,0);
});
test('M146 unmatched reported endpoint IDs are counted, not labeled tenant breaches',()=>{
  const s=review([detection('a',{device_id:'third-host'})],
    [event('third',{device_id:'third-host'})],[job('third',{agent_id:'third-host'})]);
  assert.deepEqual([s.returned.detectionsNotInInventory,
    s.returned.eventsNotInInventory,s.returned.scanJobsNotInInventory],[1,1,1]);
  assert.match(s.warnings.join(' '),/not an authenticated cross-tenant/);
});
test('M147 scan jobs are counted as returned records, not forced into alert UTC windows',()=>{
  const s=review([],[],[job('old',{created_at:'2026-10-01T12:00:00Z'})]);
  assert.equal(s.returned.scanJobs,1);
  assert.equal(s.endpointRows[0].scanJobsReturned,1);
});
test('M148 unsupported claimed quick/full successes are counted only as inconsistencies',()=>{
  const s=review([],[],[job('quick',{scan_type:'quick',verdict:'malicious',threat_name:'Synthetic.Test'}),
    job('full',{scan_type:'full'})]);
  assert.equal(s.returned.unsupportedScanClaims,2);
  assert.match(s.warnings.join(' '),/does not support/);
});
test('M149 reported signature-negative, unscanned and unknown outcomes remain distinct',()=>{
  const s=review([],[],[job('negative'),job('unscanned',{verdict:'unscanned'}),
    job('unknown',{status:'completed',verdict:'none',scan_type:'unknown'})]);
  assert.equal(s.returned.signatureNegative,1);
  assert.equal(s.returned.unscanned,1);
  assert.equal(s.returned.unknownScanState,1);
  assert.match(s.warnings.join(' '),/do not attest endpoint protection/);
});
test('M150 exact inventory filtering, deterministic sorting and paging never mutate source',()=>{
  const s=review();
  assert.deepEqual(filterSnapshotEndpoints(s.endpointRows,{
    search:'windows',status:'all',sort:'id',
  }).map(x=>x.id),['WIN-A']);
  assert.deepEqual(filterSnapshotEndpoints(s.endpointRows,{
    search:'',status:'unknown',sort:'heartbeat',
  }).map(x=>x.id),['linux-B']);
  assert.deepEqual(filterSnapshotEndpoints(s.endpointRows,{
    ...DEFAULT_SNAPSHOT_FILTERS,sort:'heartbeat',
  }).map(x=>x.id),['linux-B','WIN-A']);
  const rows=Array.from({length:61},(_,i)=>({
    id:'host-'+String(i).padStart(3,'0'),platform:'windows',heartbeat:'online',
    detectionsInWindow:0,eventsInWindow:0,scanJobsReturned:0,observedSysmonTypes:0,
  }));
  const slices=[0,1,2].map(p=>pageSnapshotEndpoints(rows,p,25));
  assert.deepEqual(slices.map(x=>[x.start,x.end]),[[1,25],[26,50],[51,61]]);
  assert.equal(new Set(slices.flatMap(x=>x.rows.map(y=>y.id))).size,61);
  assert.equal(pageSnapshotEndpoints(rows,999,25).page,2);
  assert.equal(pageSnapshotEndpoints([],0,25).start,0);
  assert.throws(()=>pageSnapshotEndpoints(rows,1,5));
  assert.throws(()=>pageSnapshotEndpoints(rows,Number.NaN,25));
  assert.deepEqual(rows.map(x=>x.id).slice(0,2),['host-000','host-001']);
});
