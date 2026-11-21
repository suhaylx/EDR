import test from 'node:test';
import assert from 'node:assert/strict';
import {
  scanContextAnchor,sameReportedEndpoint,eventClock,eventEvidenceHeading,
  eventEvidenceDescription,buildScanContext,filterScanContext,pageScanContext,
  DEFAULT_CONTEXT_OPTIONS,
} from '../.test-dist/scan-context.js';
import {decodeLabTelemetry} from '../.test-dist/telemetry.js';

const t0='2026-11-21T12:00:00Z';
const scan=(id,patch={})=>({
  id,agent_id:'WIN-A',status:'completed',scan_type:'path',
  verdict:'clean_by_signature',threat_name:'',engine:'clamav',
  created_at:t0,engine_version:'1.5',database_version:'daily-lab',detail:'reported',
  ...patch,
});
const detection=(id,patch={})=>({
  id,device_id:'WIN-A',rule_id:'R-11',category:'signal',severity:'medium',
  confidence:'low',process_guid:'{abc}',process_image:'a.exe',module_path:'',
  load_event_id:'',evidence_event_id:'go-'+id,target_object:'HKLM\\Run',
  evidence_source_event_id:13,file_create_event_id:'',
  observed_at:'2026-11-21T12:01:00Z',explanation:'report',...patch,
});
const event=(id,patch={})=>({
  id,device_id:'WIN-A',platform:'windows',source:'sysmon',type:'process',
  time:'2026-11-21T06:00:00Z',received_at:'2026-11-21T12:05:00Z',
  time_origin:'sender',source_event_id:1,source_record_id:'124',
  process_guid:'{abc}',parent_process_guid:'',
  image:'process.exe',file_path:'',detail:'untrusted',source_fields:{},...patch,
});
const context=(options={})=>{
  const job=scan('selected',options.selected||{});
  return buildScanContext(job,options.jobs||[job,scan('other')],
    options.detections||[detection('one')],
    options.events||[event('go-one')],options.generatedAt||'2026-11-21T14:00:00Z');
};
const filter=(c,options={})=>filterScanContext(c.entries,c.anchor,{...DEFAULT_CONTEXT_OPTIONS,...options});

test('M76 exact opaque endpoint identity is the only cross-response join key',()=>{
  assert.equal(sameReportedEndpoint('WIN-A','WIN-A'),true);
  assert.equal(sameReportedEndpoint('WIN-A','WIN'),false);
  assert.equal(sameReportedEndpoint('WIN-A','WIN-A '),false);
  assert.equal(sameReportedEndpoint('',''),false);
});
test('M77 source identity comparison is deliberately case-sensitive',()=>{
  assert.equal(sameReportedEndpoint('WIN-A','win-a'),false);
});
test('M78 same process GUID on another endpoint never joins selected job',()=>{
  const c=context({detections:[detection('same'),detection('other',{device_id:'WIN-B'})],
    events:[event('x'),event('y',{device_id:'WIN-B'})]});
  assert.equal(c.counts.detections,1);
  assert.equal(c.counts.events,1);
});
test('M79 selected scan job is not duplicated among other scan entries',()=>{
  const c=context();
  assert.equal(c.counts.scans,1);
  assert.ok(!c.entries.some(x=>x.refID==='selected'));
});
test('M80 count totals describe the returned samples, not fleet coverage',()=>{
  const c=context();
  assert.deepEqual(c.counts,{scans:1,detections:1,events:1});
  assert.equal(c.entries.length,3);
});
test('M81 scan, detection, and telemetry entries retain source-specific identity',()=>{
  const c=context();
  assert.deepEqual(c.entries.map(x=>x.key),
    ['scan:other','detection:one','event:go-one']);
  assert.equal(c.entries.filter(x=>x.deviceID!=='WIN-A').length,0);
});
test('M82 Sysmon class label requires Windows Sysmon numeric source',()=>{
  assert.match(eventEvidenceHeading(event('p',{source_event_id:1})),/Process create/);
  assert.match(eventEvidenceHeading(event('p',{source_event_id:3})),/Network connection/);
  assert.match(eventEvidenceHeading(event('p',{source_event_id:22})),/DNS query/);
  assert.doesNotMatch(eventEvidenceHeading(event('p',{
    platform:'linux',source:'procfs',source_event_id:0,type:'proc_snapshot',
  })),/Sysmon ID/);
});
test('M83 Sysmon 11 FileCreate and 7 ImageLoad are never conflated',()=>{
  const file=eventEvidenceHeading(event('a',{source_event_id:11}));
  const image=eventEvidenceHeading(event('b',{source_event_id:7}));
  assert.match(file,/File created/);
  assert.match(image,/DLL \/ image load/);
  assert.notEqual(file,image);
});
test('M84 clipboard Sysmon 24 description does not expose a reported payload',()=>{
  const raw=event('clip',{source_event_id:24,detail:'SECRET_CLIPBOARD',
    process_guid:'',image:'',file_path:'',source_fields:{}});
  const parsed=decodeLabTelemetry([raw])[0];
  const description=eventEvidenceDescription(parsed);
  assert.match(description,/content withheld/);
  assert.doesNotMatch(description,/SECRET_CLIPBOARD/);
});
test('M85 clipboard detail is excluded even from context text search',()=>{
  const raw=event('clip',{source_event_id:24,detail:'SECRET_CLIPBOARD',
    process_guid:'',image:'',file_path:'',source_fields:{}});
  const c=context({events:decodeLabTelemetry([raw])});
  assert.deepEqual(filter(c,{search:'SECRET_CLIPBOARD'}),[]);
});
test('M86 Go-received time takes precedence over sender time for telemetry',()=>{
  const clock=eventClock(event('a'));
  assert.equal(clock.basis,'server_received');
  assert.equal(clock.time,'2026-11-21T12:05:00Z');
  assert.equal(clock.ms,Date.parse('2026-11-21T12:05:00Z'));
});
test('M87 fallback sender time remains visibly marked as sender-reported',()=>{
  const clock=eventClock(event('a',{received_at:''}));
  assert.equal(clock.basis,'sender_reported');
  assert.equal(clock.time,'2026-11-21T06:00:00Z');
});
test('M88 event without either timestamp is an unknown-time record',()=>{
  const clock=eventClock(event('a',{received_at:'',time:''}));
  assert.equal(clock.basis,'unknown');
  assert.equal(clock.ms,null);
});
test('M89 scan temporal anchor is only the reported job creation time',()=>{
  assert.equal(scanContextAnchor(scan('a')),Date.parse(t0));
  assert.equal(scanContextAnchor(scan('a',{created_at:undefined})),null);
});
test('M90 temporal selection fails closed when selected job time is missing',()=>{
  const c=context({selected:{created_at:undefined}});
  assert.equal(c.anchor,null);
  assert.equal(filter(c,{window:'1h'}).length,0);
  assert.equal(filter(c,{window:'all'}).length,3);
});
test('M91 inclusive plus/minus one-hour boundaries are handled symmetrically',()=>{
  const c=context({jobs:[scan('selected'),scan('before',{created_at:'2026-11-21T11:00:00Z'}),
    scan('after',{created_at:'2026-11-21T13:00:00Z'})],
    detections:[],events:[]});
  assert.deepEqual(filter(c,{window:'1h'}).map(x=>x.refID),['after','before']);
});
test('M92 events outside the selected one-hour window are excluded locally',()=>{
  const c=context({jobs:[scan('selected'),scan('far',{created_at:'2026-11-21T13:00:01Z'})],
    detections:[],events:[]});
  assert.equal(filter(c,{window:'1h'}).length,0);
});
test('M93 one-day window includes close observations but not 25-hour records',()=>{
  const c=context({jobs:[scan('selected'),scan('inside',{created_at:'2026-11-20T12:00:00Z'}),
    scan('outside',{created_at:'2026-11-20T10:59:59Z'})],detections:[],events:[]});
  assert.deepEqual(filter(c,{window:'24h'}).map(x=>x.refID),['inside']);
});
test('M94 seven-day time window is not a historical retention guarantee',()=>{
  const c=context({jobs:[scan('selected'),scan('inside',{created_at:'2026-11-14T12:00:00Z'}),
    scan('outside',{created_at:'2026-11-14T11:59:59Z'})],detections:[],events:[]});
  assert.deepEqual(filter(c,{window:'7d'}).map(x=>x.refID),['inside']);
});
test('M95 sender timestamps later than overview generation are flagged, not trusted',()=>{
  const c=context({generatedAt:'2026-11-21T11:00:00Z'});
  assert.equal(c.hasFuture,true);
  assert.ok(c.entries.some(x=>x.futureOfServer));
});
test('M96 missing record time remains visible in all-results view but not nearby time',()=>{
  const c=context({events:[event('undated',{received_at:'',time:''})],jobs:[scan('selected')],
    detections:[]});
  assert.equal(filter(c,{window:'all'}).length,1);
  assert.equal(filter(c,{window:'24h'}).length,0);
  assert.equal(filter(c,{window:'all'})[0].timeBasis,'unknown');
});
test('M97 source-type filters separate scans, detections and events',()=>{
  const c=context();
  assert.deepEqual(filter(c,{source:'scan'}).map(x=>x.refID),['other']);
  assert.deepEqual(filter(c,{source:'detection'}).map(x=>x.refID),['one']);
  assert.deepEqual(filter(c,{source:'event'}).map(x=>x.refID),['go-one']);
});
test('M98 local metadata search is case-insensitive and exact host-scoped',()=>{
  const c=context();
  assert.deepEqual(filter(c,{search:'r-11'}).map(x=>x.refID),['one']);
  assert.deepEqual(filter(c,{search:'go-one'}).map(x=>x.refID),
    ['go-one','one']);
  assert.deepEqual(filter(c,{search:'nomatch'}),[]);
});
test('M99 sorting compares UTC offsets correctly and places undated evidence last',()=>{
  const c=context({jobs:[scan('selected'),
    scan('later',{created_at:'2026-11-21T16:00:00+03:00'}),
    scan('earlier',{created_at:'2026-11-21T11:00:00Z'}),
    scan('missing',{created_at:undefined})],detections:[],events:[]});
  assert.deepEqual(filter(c,{sort:'newest'}).map(x=>x.refID),['later','earlier','missing']);
  assert.deepEqual(filter(c,{sort:'oldest'}).map(x=>x.refID),['earlier','later','missing']);
});
test('M100 pagination bounds, empty states and bad pages fail closed',()=>{
  const c=context({jobs:[scan('selected'),
    ...Array.from({length:61},(_,i)=>scan('j'+i))],detections:[],events:[]});
  const ordered=filter(c);
  const slices=[0,1,2].map(i=>pageScanContext(ordered,i,25));
  assert.deepEqual(slices.map(x=>[x.start,x.end]),[[1,25],[26,50],[51,61]]);
  assert.equal(new Set(slices.flatMap(x=>x.rows.map(y=>y.key))).size,61);
  assert.equal(pageScanContext(ordered,999,25).page,2);
  assert.deepEqual(pageScanContext([],0,25).rows,[]);
  assert.throws(()=>pageScanContext(ordered,0,5));
  assert.throws(()=>pageScanContext(ordered,Number.NaN,25));
});
