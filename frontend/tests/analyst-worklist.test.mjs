import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeLabDetections } from '../.test-dist/detections.js';
import { decodeLabTelemetry } from '../.test-dist/telemetry.js';
import {EMPTY_ANALYST_FILTERS,filterAnalystWorklist,sortAnalystWorklist,
  paginateWorklist,sourcePresentInReturnedSample} from '../.test-dist/analyst-worklist.js';

const row=(id,patch={})=>({
  id,device_id:'WIN-A',rule_id:'Rule-A',category:'behavior',
  severity:'medium',confidence:'low',process_guid:'{A}',
  process_image:'cmd.exe',module_path:'',load_event_id:'',
  evidence_event_id:'go-'+id,evidence_source_event_id:13,
  target_object:'RegistryTarget',file_create_event_id:'file-'+id,
  observed_at:'2026-11-21T10:00:00Z',explanation:'Reported lab signal',...patch,
});
const ev=(id,patch={})=>({
  id,device_id:'WIN-A',platform:'windows',source:'sysmon',
  type:'registry',source_event_id:13,source_record_id:'9',
  time:'2026-11-21T10:00:00Z',received_at:'2026-11-21T10:00:01Z',
  time_origin:'reported',process_guid:'{A}',parent_process_guid:'',
  image:'',file_path:'',detail:'metadata',source_fields:{},...patch,
});
const rec=(...items)=>decodeLabDetections(items);
const apply=(rows,patch={},events=[])=>filterAnalystWorklist(rows,events,{...EMPTY_ANALYST_FILTERS,...patch}).map(d=>d.id);
const two=()=>rec(row('a'),row('b',{
  device_id:'LINUX-B',rule_id:'Rule-B',category:'dns',
  confidence:'medium',process_guid:'',target_object:'',
  file_create_event_id:'',module_path:'',evidence_event_id:'go-b',
}));

test('M01 exact host filter ignores letter case, not partial host names',()=>{
  assert.deepEqual(apply(two(),{host:'linux-b'}),['b']);
  assert.deepEqual(apply(two(),{host:'LINUX'}),[]);
});
test('M02 exact rule filter is scoped to returned records',()=>{
  assert.deepEqual(apply(two(),{rule:'rule-a'}),['a']);
});
test('M03 exact category filter is not substring search',()=>{
  assert.deepEqual(apply(two(),{category:'DNS'}),['b']);
  assert.deepEqual(apply(two(),{category:'dn'}),[]);
});
test('M04 exact confidence filter is read-only reported metadata',()=>{
  assert.deepEqual(apply(two(),{confidence:'MEDIUM'}),['b']);
});
test('M05 process GUID presence and absence are not inferred',()=>{
  assert.deepEqual(apply(two(),{processGuid:'present'}),['a']);
  assert.deepEqual(apply(two(),{processGuid:'absent'}),['b']);
});
test('M06 linked FileCreate reference is distinct from source classification',()=>{
  assert.deepEqual(apply(two(),{fileCreate:'present'}),['a']);
  assert.deepEqual(apply(two(),{fileCreate:'absent'}),['b']);
});
test('M07 reported target presence does not prove malicious behavior',()=>{
  assert.deepEqual(apply(two(),{target:'present'}),['a']);
  assert.deepEqual(apply(two(),{target:'absent'}),['b']);
});
test('M08 source sample lookup requires same Go event ID and endpoint',()=>{
  const detections=two(),events=decodeLabTelemetry([ev('go-a')]);
  assert.deepEqual(apply(detections,{sample:'in_sample'},events),['a']);
  assert.deepEqual(apply(detections,{sample:'not_in_sample'},events),['b']);
});
test('M09 cannot match matching event ID on another host',()=>{
  const events=decodeLabTelemetry([ev('go-a',{device_id:'LINUX-B',platform:'linux',source:'procfs',source_event_id:0,source_fields:{}})]);
  assert.equal(sourcePresentInReturnedSample(two()[0],events),false);
});
test('M10 newest sorting uses absolute timestamps, not lexical offset strings',()=>{
  const rows=rec(row('old',{observed_at:'2026-11-21T09:00:00Z'}),
    row('new',{observed_at:'2026-11-21T11:00:00+02:00'}),row('latest',{observed_at:'2026-11-21T10:30:00Z'}));
  assert.deepEqual(sortAnalystWorklist(rows,'newest').map(d=>d.id),['latest','new','old']);
});
test('M11 oldest sorting is the inverse on distinct timestamps',()=>{
  const rows=rec(row('a',{observed_at:'2026-11-21T09:00:00Z'}),
    row('b',{observed_at:'2026-11-21T11:00:00Z'}));
  assert.deepEqual(sortAnalystWorklist(rows,'oldest').map(d=>d.id),['a','b']);
});
test('M12 severity sort preserves unclassified severities after low',()=>{
  const rows=rec(row('unknown',{severity:'INFO'}),row('critical',{severity:'critical'}),
    row('low',{severity:'low'}),row('high',{severity:'High'}));
  assert.deepEqual(sortAnalystWorklist(rows,'severity').map(d=>d.id),
    ['critical','high','low','unknown']);
});
test('M13 endpoint sort uses the reported ID, not any implied host risk',()=>{
  const rows=rec(row('z',{device_id:'Zulu'}),row('a',{device_id:'Alpha'}));
  assert.deepEqual(sortAnalystWorklist(rows,'endpoint').map(d=>d.id),['a','z']);
});
test('M14 rule sort uses reported rule ID only',()=>{
  const rows=rec(row('z',{rule_id:'z-rule'}),row('a',{rule_id:'A-rule'}));
  assert.deepEqual(sortAnalystWorklist(rows,'rule').map(d=>d.id),['a','z']);
});
test('M15 confidence sort remains explicitly reported classification',()=>{
  const rows=rec(row('low',{confidence:'low'}),row('high',{confidence:'high'}),
    row('other',{confidence:'unset'}));
  assert.deepEqual(sortAnalystWorklist(rows,'confidence').map(d=>d.id),
    ['high','low','other']);
});
test('M16 page sizes 25, 50 and 100 are bounded local slices',()=>{
  const rows=Array.from({length:132},(_,i)=>i);
  for(const size of [25,50,100]){
    const first=paginateWorklist(rows,0,size);
    assert.equal(first.records.length,size);
    assert.equal(first.pages,Math.ceil(rows.length/size));
    assert.equal(first.total,132);
  }
});
test('M17 pagination exposes next and previous page indices without duplicate rows',()=>{
  const rows=Array.from({length:61},(_,i)=>i);
  const first=paginateWorklist(rows,0,25), second=paginateWorklist(rows,1,25);
  const third=paginateWorklist(rows,2,25);
  assert.deepEqual([first.start,first.end,second.start,second.end,third.start,third.end],
    [1,25,26,50,51,61]);
  assert.equal(new Set([...first.records,...second.records,...third.records]).size,61);
});
test('M18 out of range pages clamp and malformed page size fails closed',()=>{
  assert.equal(paginateWorklist([1,2,3],999,25).page,0);
  assert.equal(paginateWorklist([],0,25).pages,1);
  assert.equal(paginateWorklist([],0,25).start,0);
  assert.throws(()=>paginateWorklist([1],0,7));
  assert.throws(()=>paginateWorklist([1],Number.NaN,25));
});
test('M19 sorting and filtering never mutate shared API rows',()=>{
  const rows=two(), ids=rows.map(d=>d.id);
  sortAnalystWorklist(rows,'rule');
  filterAnalystWorklist(rows,[],{...EMPTY_ANALYST_FILTERS,host:'WIN-A'});
  assert.deepEqual(rows.map(d=>d.id),ids);
});
test('M20 multiple exact analyst constraints compose without broadening evidence',()=>{
  assert.deepEqual(apply(two(),{host:'WIN-A',rule:'Rule-A',confidence:'LOW'}),['a']);
  assert.deepEqual(apply(two(),{host:'WIN-A',rule:'Rule-B'}),[]);
});
