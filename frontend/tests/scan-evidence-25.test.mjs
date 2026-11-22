import test from 'node:test';
import assert from 'node:assert/strict';
import {
  scanEvidenceKind,scanEvidenceFlags,scanNeedsAttention,filterReportedScanJobs,
  sortReportedScanJobs,paginateReportedScanJobs,summarizeReportedScanJobs,
  DEFAULT_SCAN_QUERY,SCAN_KIND_LABELS,SCAN_FLAG_LABELS,
} from '../.test-dist/scan-evidence.js';
import {describeScan} from '../.test-dist/scan-state.js';
import {decodeScanJobs} from '../.test-dist/lab-api.js';

const job=(change={})=>({
  id:'scan-1',agent_id:'WIN-A',status:'completed',
  scan_type:'path',verdict:'malicious',threat_name:'Synthetic.Test',
  created_at:'2026-11-21T12:00:00Z',engine:'clamav',
  engine_version:'1.5.5',database_version:'daily-test',detail:'reported',
  ...change,
});
const rows=(...v)=>v.map((p,i)=>job({id:'scan-'+i,...p}));
const ids=(jobs,query)=>filterReportedScanJobs(jobs,{...DEFAULT_SCAN_QUERY,...query}).map(j=>j.id);

test('M51 unsupported quick/full success is never trusted, regardless of claimed verdict',()=>{
 for(const mode of ['quick','full']) for(const verdict of ['malicious','suspicious','clean_by_signature']){
  const row=job({scan_type:mode,verdict});
  assert.equal(scanEvidenceKind(row),'unsupported_claim');
  assert.equal(describeScan(row).heading,'Unsupported scan claim');
  assert.ok(scanEvidenceFlags(row).includes('quick_full_success_unsupported'));
 }
});
test('M52 quick/full reported errors are scanner errors, not success',()=>{
 for(const mode of ['quick','full']){
  assert.equal(scanEvidenceKind(job({scan_type:mode,verdict:'error'})),'scanner_error');
 }
});
test('M53 quick/full unscanned is distinct from completed scan',()=>{
 for(const mode of ['quick','full']){
  assert.equal(scanEvidenceKind(job({scan_type:mode,verdict:'unscanned'})),'unscanned');
  assert.equal(describeScan(job({scan_type:mode,verdict:'unscanned'})).heading,'Unscanned');
 }
});
test('M54 path malicious with a named synthetic signature remains reported-only',()=>{
 const row=job();
 assert.equal(scanEvidenceKind(row),'reported_match');
 assert.match(SCAN_KIND_LABELS.reported_match,/not attested/);
 assert.equal(describeScan(row).attested,false);
});
test('M55 path suspicious is not confirmed malware',()=>{
 const row=job({verdict:'suspicious',threat_name:''});
 assert.equal(scanEvidenceKind(row),'reported_suspicious');
 assert.match(SCAN_KIND_LABELS.reported_suspicious,/not attested/);
});
test('M56 path signature-negative is never safe or protected',()=>{
 const row=job({verdict:'clean_by_signature',threat_name:''});
 assert.equal(scanEvidenceKind(row),'signature_negative');
 assert.match(SCAN_KIND_LABELS.signature_negative,/not proof of safety/);
});
test('M57 completed delivery with scanner error is not completed scan evidence',()=>{
 const row=job({verdict:'error',threat_name:''});
 assert.equal(scanEvidenceKind(row),'scanner_error');
 assert.equal(describeScan(row).tone,'danger');
});
test('M58 completed delivery with unscanned result is not protection',()=>{
 const row=job({verdict:'unscanned',threat_name:''});
 assert.equal(scanEvidenceKind(row),'unscanned');
 assert.match(describeScan(row).explanation,/not performed/i);
});
test('M59 missing scan mode cannot certify a positive result',()=>{
 for(const mode of ['',undefined,'mystery']){
  const row=job({scan_type:mode});
  assert.equal(scanEvidenceKind(row),'unverified_completion');
  assert.ok(scanEvidenceFlags(row).includes('completed_without_path_mode'));
 }
});
test('M60 positive verdict on failed/queued/leased jobs is explicitly inconsistent',()=>{
 for(const state of ['failed','queued','leased','expired']){
  const row=job({status:state});
  assert.ok(scanEvidenceFlags(row).includes('positive_verdict_without_completed_status'));
  assert.notEqual(scanEvidenceKind(row),'reported_match');
 }
});
test('M61 malicious claim without a named signature stays insufficient',()=>{
 const row=job({threat_name:''});
 assert.equal(scanEvidenceKind(row),'unverified_completion');
 assert.ok(scanEvidenceFlags(row).includes('malicious_without_signature'));
});
test('M62 non-malicious with a named signature is flagged as inconsistent',()=>{
 const row=job({verdict:'clean_by_signature',threat_name:'Unexpected.Signature'});
 assert.ok(scanEvidenceFlags(row).includes('unexpected_threat_name'));
 assert.match(SCAN_FLAG_LABELS.unexpected_threat_name,/non-malicious/);
});
test('M63 missing engine, engine version, and database version are separate gaps',()=>{
 const row=job({engine:'',engine_version:'',database_version:''});
 assert.deepEqual(scanEvidenceFlags(row).filter(x=>x.endsWith('_missing')).sort(),
   ['database_version_missing','engine_missing','engine_version_missing'].sort());
});
test('M64 missing timestamp and unknown mode never indicate freshness',()=>{
 const row=job({created_at:undefined,scan_type:undefined});
 const flags=scanEvidenceFlags(row);
 assert.ok(flags.includes('created_time_missing'));
 assert.ok(flags.includes('unrecognized_mode'));
});
test('M65 unknown states and verdicts remain unknown without coercion',()=>{
 const row=job({status:'protected',verdict:'safe'});
 assert.equal(scanEvidenceKind(row),'unknown_state');
 assert.ok(scanEvidenceFlags(row).includes('unrecognized_state'));
 assert.ok(scanEvidenceFlags(row).includes('unrecognized_verdict'));
});
test('M66 pending filter separates queued and leased from completed jobs',()=>{
 const input=rows({status:'queued',verdict:undefined,threat_name:''},
  {status:'leased',verdict:undefined,threat_name:''},{});
 assert.deepEqual(ids(input,{kind:'pending'}),['scan-0','scan-1']);
});
test('M67 failed/error filter includes expired, failed and reported scanner errors',()=>{
 const input=rows({status:'expired',verdict:undefined,threat_name:''},
  {status:'failed',verdict:'unscanned',threat_name:''},
  {verdict:'error',threat_name:''},{});
 assert.deepEqual(ids(input,{kind:'failed_or_error'}),['scan-0','scan-1','scan-2']);
 assert.deepEqual(ids(input,{kind:'unscanned'}),['scan-1']);
});
test('M68 unsupported quick/full claims have a separate analyst filter',()=>{
 const input=rows({scan_type:'quick'}, {scan_type:'full'}, {scan_type:'path'});
 assert.deepEqual(ids(input,{kind:'unsupported_claim'}),['scan-0','scan-1']);
});
test('M69 path reported match, suspicious, and signature-negative stay distinct',()=>{
 const input=rows({},{verdict:'suspicious',threat_name:''},
  {verdict:'clean_by_signature',threat_name:''},{scan_type:'quick'});
 assert.deepEqual(ids(input,{kind:'reported_match'}),['scan-0']);
 assert.deepEqual(ids(input,{kind:'suspicious'}),['scan-1']);
 assert.deepEqual(ids(input,{kind:'signature_negative'}),['scan-2']);
});
test('M70 analyst attention includes errors and gaps, but not attested health',()=>{
 const input=rows({status:'queued',verdict:undefined,threat_name:''},
  {verdict:'error',threat_name:''},{});
 assert.deepEqual(ids(input,{kind:'attention'}),['scan-1']);
 assert.equal(scanNeedsAttention(input[2]),false);
});
test('M71 exact endpoint filter is case-insensitive but not substring-based',()=>{
 const input=rows({agent_id:'WINDOWS-A'},{agent_id:'WINDOWS-B'});
 assert.deepEqual(ids(input,{endpoint:'windows-a'}),['scan-0']);
 assert.deepEqual(ids(input,{endpoint:'windows'}),[]);
});
test('M72 text search excludes private worker detail but searches bounded metadata',()=>{
 const input=rows({engine:'clamav',detail:'Observed scanner ERROR'},
  {engine:'Other',detail:'none'});
 assert.deepEqual(ids(input,{search:'scanner error'}),[]);
 assert.deepEqual(ids(input,{search:'clamav'}),['scan-0']);
 assert.deepEqual(ids(input,{search:'other'}),['scan-1']);
});
test('M73 metadata and mode filters are read-only and combine exactly',()=>{
 const input=rows({},{scan_type:'quick'},{database_version:''});
 assert.deepEqual(ids(input,{metadata:'complete',mode:'path'}),['scan-0']);
 assert.deepEqual(ids(input,{metadata:'missing',mode:'quick'}),['scan-1']);
 assert.deepEqual(ids(input,{mode:'path',metadata:'missing'}),['scan-2']);
 assert.deepEqual(input.map(x=>x.id),['scan-0','scan-1','scan-2']);
});
test('M74 chronological sorting uses time offsets, missing time last and stable tie-breakers',()=>{
 const input=rows({created_at:'2026-11-21T11:00:00Z'},
  {created_at:'2026-11-21T14:00:00+02:00'},
  {created_at:undefined},{created_at:'2026-11-21T10:00:00Z'});
 assert.deepEqual(sortReportedScanJobs(input,'newest').map(x=>x.id),
   ['scan-1','scan-0','scan-3','scan-2']);
 assert.deepEqual(sortReportedScanJobs(input,'oldest').map(x=>x.id),
   ['scan-3','scan-0','scan-1','scan-2']);
 assert.equal(sortReportedScanJobs(input,'classification').length,4);
 assert.deepEqual(input.map(x=>x.id),['scan-0','scan-1','scan-2','scan-3']);
});
test('M75 pagination, summary and strict scan API boundaries fail closed',()=>{
 const input=Array.from({length:61},(_,i)=>job({id:'scan-'+i}));
 const pages=[0,1,2].map(i=>paginateReportedScanJobs(input,i,25));
 assert.deepEqual(pages.map(x=>[x.start,x.end]),[[1,25],[26,50],[51,61]]);
 assert.equal(new Set(pages.flatMap(x=>x.rows.map(row=>row.id))).size,61);
 assert.equal(paginateReportedScanJobs(input,999,25).page,2);
 assert.throws(()=>paginateReportedScanJobs(input,1,10));
 assert.throws(()=>paginateReportedScanJobs(input,Number.NaN,25));
 const summary=summarizeReportedScanJobs(input);
 assert.equal(summary.returned,61);
 assert.equal(summary.kinds.reported_match,61);
 assert.equal(summary.metadataGaps,0);
 assert.throws(()=>decodeScanJobs([job({id:'one'}),job({id:'one'})]),/Duplicate/);
 assert.throws(()=>decodeScanJobs([job({id:'bad'+String.fromCharCode(10)+'newline'})]),/record/);
 assert.throws(()=>decodeScanJobs([job({detail:'x'.repeat(1025)})]),/record/);
 assert.throws(()=>decodeScanJobs([job({created_at:'not-an-iso-date'})]),/timestamp/);
});
