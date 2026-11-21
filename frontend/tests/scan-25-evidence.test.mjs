import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
import {describeScan,scanEngineEvidence,isUnsupportedLabScanClaim,isUnverifiedLabScanMode}
  from '../.test-dist/scan-state.js';
import {classifyScanEvidence,filterScanEvidence,sortScanEvidence,
  pageScanEvidence,summarizeScanEvidence,scanTimestamp,scanNeedsAttention,
  scanEvidenceLabel,INITIAL_SCAN_QUERY} from '../.test-dist/scan-evidence.js';

const job=(id,patch={})=>({
  id,agent_id:'win-lab-01',scan_type:'path',status:'completed',
  verdict:'clean_by_signature',created_at:'2026-11-21T12:00:00Z',
  engine:'clamav',engine_version:'1.5.5',database_version:'test-db',
  threat_name:'',detail:'reported',...patch,
});
const read=(...rows)=>decodeScanJobs(rows);
const category=(patch={})=>classifyScanEvidence(read(job('r',patch))[0]);
const ids=(rows,categoryName='all',patch={})=>
  filterScanEvidence(rows,{...INITIAL_SCAN_QUERY,category:categoryName,...patch}).map(x=>x.id);

test('M26 queued request never asserts execution',()=>{
  const record=job('queued',{status:'queued',verdict:''});
  assert.equal(category(record),'queued');
  assert.equal(describeScan(record).heading,'Queued');
  assert.equal(scanNeedsAttention(record),false);
});
test('M27 leased worker has no accepted scan completion',()=>{
  const record=job('leased',{status:'leased',verdict:''});
  assert.equal(category(record),'leased');
  assert.match(describeScan(record).explanation,/completion is not reported/);
});
test('M28 expired queue item is not completed',()=>{
  const record=job('expired',{status:'expired',verdict:''});
  assert.equal(category(record),'expired');
  assert.equal(scanNeedsAttention(record),true);
});
test('M29 generic failed request has no successful signature result',()=>{
  const record=job('failed',{status:'failed',verdict:''});
  assert.equal(category(record),'failed');
  assert.notEqual(describeScan(record).heading,'Clean by signature (reported)');
});
test('M30 failed unscanned remains distinct from an error',()=>{
  const record=job('unscanned',{status:'failed',verdict:'unscanned'});
  assert.equal(category(record),'unscanned');
  assert.equal(describeScan(record).heading,'Unscanned');
});
test('M31 failed scanner error is conspicuous danger',()=>{
  const record=job('error',{status:'failed',verdict:'error'});
  assert.equal(category(record),'scanner_error');
  assert.equal(describeScan(record).tone,'danger');
});
test('M32 completed delivery plus error does not attest a scan',()=>{
  const record=job('bad',{status:'completed',verdict:'error'});
  assert.equal(category(record),'scanner_error');
  assert.match(describeScan(record).explanation,/No successful scan/);
});
test('M33 completed delivery plus unscanned is still unscanned',()=>{
  const record=job('bad',{status:'completed',verdict:'unscanned'});
  assert.equal(category(record),'unscanned');
  assert.equal(describeScan(record).attested,false);
});
test('M34 claimed quick malicious completion is unsupported even with signature name',()=>{
  const record=job('q1',{scan_type:'quick',verdict:'malicious',threat_name:'EICAR-LAB'});
  assert.equal(category(record),'unsupported_claim');
  assert.equal(describeScan(record).heading,'Unsupported scan claim');
  assert.equal(ids(read(record),'reported_match').length,0);
});
test('M35 claimed quick suspicious completion is unsupported',()=>{
  const record=job('q2',{scan_type:'quick',verdict:'suspicious'});
  assert.equal(category(record),'unsupported_claim');
  assert.equal(ids(read(record),'suspicious').length,0);
});
test('M36 claimed quick signature-negative completion is unsupported',()=>{
  const record=job('q3',{scan_type:'quick',verdict:'clean_by_signature'});
  assert.equal(category(record),'unsupported_claim');
  assert.equal(ids(read(record),'signature_negative').length,0);
});
test('M37 claimed full malicious completion is unsupported',()=>{
  const record=job('f1',{scan_type:'full',verdict:'malicious',threat_name:'EICAR-LAB'});
  assert.equal(category(record),'unsupported_claim');
  assert.equal(isUnsupportedLabScanClaim(record),true);
});
test('M38 claimed full suspicious completion is unsupported',()=>{
  const record=job('f2',{scan_type:'full',verdict:'suspicious'});
  assert.equal(category(record),'unsupported_claim');
  assert.equal(scanEvidenceLabel(record),'Unsupported scan claim');
});
test('M39 claimed full signature-negative completion is unsupported',()=>{
  const record=job('f3',{scan_type:'full',verdict:'clean_by_signature'});
  assert.equal(category(record),'unsupported_claim');
  assert.deepEqual(ids(read(record),'unsupported'),['f3']);
});
test('M40 reported path signature match is still not attestation',()=>{
  const record=job('p1',{verdict:'malicious',threat_name:'Test.EICAR'});
  assert.equal(category(record),'signature_match');
  assert.equal(describeScan(record).attested,false);
  assert.deepEqual(ids(read(record),'reported_match'),['p1']);
});
test('M41 reported path signature-negative is never proof of safety',()=>{
  const record=job('p2');
  assert.equal(category(record),'signature_negative');
  assert.match(describeScan(record).explanation,/not proof/);
  assert.equal(scanNeedsAttention(record),false);
});
test('M42 suspicious path result is an unverified analyst signal',()=>{
  const record=job('p3',{verdict:'suspicious'});
  assert.equal(category(record),'suspicious');
  assert.equal(describeScan(record).attested,false);
});
test('M43 absent mode with successful verdict is unverified',()=>{
  const record=job('nomode',{scan_type:undefined,verdict:'malicious'});
  assert.equal(category(record),'unverified_mode');
  assert.equal(isUnverifiedLabScanMode(record),true);
  assert.equal(describeScan(record).tone,'danger');
});
test('M44 unknown and case-folded quick/full modes fail closed',()=>{
  const unknown=job('other',{scan_type:'legacy-mode',verdict:'clean_by_signature'});
  assert.equal(category(unknown),'unverified_mode');
  assert.equal(describeScan(unknown).heading,'Unverified scan mode');
  const upper=job('upper',{scan_type:' QUICK ',verdict:'malicious'});
  assert.equal(category(upper),'unsupported_claim');
  assert.deepEqual(ids(read(unknown,upper),'unsupported'),['other','upper']);
});
test('M45 unknown state and malformed completion cannot masquerade as clean',()=>{
  const rows=read(job('unknown',{status:'unexpected',verdict:'clean_by_signature'}),
    job('invalid',{verdict:'not-a-verdict'}));
  assert.deepEqual(rows.map(classifyScanEvidence),['unrecognized','unrecognized']);
  assert.deepEqual(ids(rows,'signature_negative'),[]);
  assert.equal(describeScan(rows[0]).attested,false);
});
test('M46 exact endpoint filter is not a cross-device substring join',()=>{
  const rows=read(job('a'),job('b',{agent_id:'win-lab-010'}));
  assert.deepEqual(ids(rows,'all',{endpoint:'WIN-LAB-01'}),['a']);
  assert.deepEqual(ids(rows,'all',{endpoint:'win-lab'}),[]);
});
test('M47 exact mode and unknown/missing mode filtering work',()=>{
  const rows=read(job('path'),job('quick',{scan_type:'quick',verdict:'unscanned'}),
    job('missing',{scan_type:undefined}),job('unknown',{scan_type:'legacy'}));
  assert.deepEqual(ids(rows,'all',{mode:'path'}),['path']);
  assert.deepEqual(ids(rows,'all',{mode:'__other__'}),['missing','unknown']);
});
test('M48 local query is case insensitive, limited to metadata and nonmutating',()=>{
  const rows=read(job('a',{threat_name:'DEMO-SIGNATURE',verdict:'malicious'}),
    job('b',{agent_id:'linux-lab'}));
  const before=rows.map(x=>({...x}));
  assert.deepEqual(ids(rows,'all',{text:'  demo-signature  '}),['a']);
  assert.deepEqual(ids(rows,'all',{text:'LINUX-LAB'}),['b']);
  assert.deepEqual(rows,before);
});
test('M49 sorting compares timestamp instants and handles missing time',()=>{
  const rows=read(job('old',{created_at:'2026-11-21T09:00:00Z'}),
    job('later',{created_at:'2026-11-21T11:30:00Z'}),
    job('offset',{created_at:'2026-11-21T13:00:00+02:00'}),
    job('missing',{created_at:undefined}));
  assert.deepEqual(sortScanEvidence(rows,'newest').map(x=>x.id),
    ['later','offset','old','missing']);
  assert.deepEqual(sortScanEvidence(rows,'oldest').map(x=>x.id),
    ['old','offset','later','missing']);
  assert.equal(scanTimestamp(rows[3]),null);
  assert.deepEqual(rows.map(x=>x.id),['old','later','offset','missing']);
});
test('M50 paging, summary and exact categories do not inflate scan evidence',()=>{
  const rows=read(...Array.from({length:56},(_,i)=>
    job('n'+i,{status:i<26?'queued':'completed',
      scan_type:i===55?'full':'path',
      verdict:i<26?'':i===55?'malicious':'clean_by_signature'})));
  assert.equal(summarizeScanEvidence(rows).queued,26);
  assert.equal(summarizeScanEvidence(rows).unsupported_claim,1);
  assert.equal(summarizeScanEvidence(rows).signature_negative,29);
  assert.equal(ids(rows,'signature_negative').length,29);
  assert.equal(ids(rows,'reported_match').length,0);
  const pages=[0,1,2].map(n=>pageScanEvidence(rows,n,25));
  assert.deepEqual(pages.map(p=>p.rows.length),[25,25,6]);
  assert.deepEqual(pages.map(p=>[p.first,p.last]),[[1,25],[26,50],[51,56]]);
  assert.equal(pageScanEvidence([],99,25).first,0);
  assert.equal(pageScanEvidence(rows,999,25).page,2);
  assert.throws(()=>pageScanEvidence(rows,0,17));
});
