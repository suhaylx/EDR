import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {decodeLabScanReviewJobs,fetchLabScanJobs} from '../.test-dist/lab-api.js';
import {scanEvidenceKind,scanEvidenceFlags,filterReportedScanJobs,DEFAULT_SCAN_QUERY} from '../.test-dist/scan-evidence.js';
import {describeScan} from '../.test-dist/scan-state.js';
import {ScanEvidenceWorkbench} from '../.test-dist/ScanEvidenceWorkbench.js';

const redacted=(patch={})=>({
  id:'job1',agent_id:'WIN-A',status:'completed',scan_type:'path',
  verdict:'malicious',signature_reported:true,
  created_at:'2026-11-21T12:00:00Z',expires_at:'2026-11-21T12:30:00Z',
  completed_at:'2026-11-21T12:01:00Z',engine:'clamav',engine_version:'1.5.5',
  database_version:'daily-lab',...patch,
});
test('QA scan API requires the metadata-only signature indicator and bounded source',()=>{
 const r=decodeLabScanReviewJobs([redacted()])[0];
 assert.equal(r.signature_reported,true);
 assert.equal(r.threat_name,undefined);
 assert.equal(r.detail,undefined);
 assert.equal(scanEvidenceKind(r),'reported_match');
 assert.ok(!scanEvidenceFlags(r).includes('malicious_without_signature'));
});
test('QA missing or invalid signature indicator fails closed',()=>{
 for(const invalid of [undefined,null,0,1,'true',{},[]]){
  const sample=redacted();
  if(invalid===undefined)delete sample.signature_reported;
  else sample.signature_reported=invalid;
  assert.throws(()=>decodeLabScanReviewJobs([sample]),/signature indicator/);
 }
});
test('QA raw queue fields cannot pass metadata-only response parser',()=>{
 for(const field of ['request_id','path','lease_id','threat_name','detail']){
  assert.throws(()=>decodeLabScanReviewJobs([redacted({[field]:'SECRET'})]),/Unexpected private scan field/);
  assert.throws(()=>decodeLabScanReviewJobs([redacted({[field]:null})]),/Unexpected private scan field/);
 }
});
test('QA legacy scan route response must never silently satisfy frontend fetch',async()=>{
 const legacy=async()=>({ok:true,json:async()=>[redacted({
  path:'C:\\Private\\alice.pdf',request_id:'SECRET_REQUEST',
  threat_name:'SECRET_SIGNATURE',detail:'SECRET_OUTPUT',
 })]});
 await assert.rejects(fetchLabScanJobs('t'.repeat(16),undefined,legacy),/Unexpected private scan field/);
});
test('QA metadata-only scanner verdict remains an unverified report, never attested',()=>{
 const j=decodeLabScanReviewJobs([redacted()])[0];
 const description=describeScan(j);
 assert.equal(description.attested,false);
 assert.match(description.explanation,/withheld/);
 assert.doesNotMatch(description.explanation,/SECRET_SIGNATURE/);
 assert.equal(scanEvidenceKind(j),'reported_match');
});
test('QA raw signature text and worker detail cannot become searchable in workbench',()=>{
 const j=decodeLabScanReviewJobs([redacted()])[0];
 const rows=filterReportedScanJobs([j],{...DEFAULT_SCAN_QUERY,search:'SECRET_SIGNATURE'});
 assert.deepEqual(rows,[]);
 const markup=renderToStaticMarkup(createElement(ScanEvidenceWorkbench,{jobs:[j]}));
 assert.match(markup,/Signature match reported/);
 assert.match(markup,/Present \(name withheld\)/);
 assert.match(markup,/Withheld from analyst metadata view/);
 assert.doesNotMatch(markup,/PRIVATE_REQUEST|SECRET_SIGNATURE|SECRET_OUTPUT|<script\b/i);
});
test('QA non-malicious signature marker is an inconsistency, not a verified clean scan',()=>{
 const j=decodeLabScanReviewJobs([redacted({verdict:'clean_by_signature',signature_reported:true})])[0];
 assert.ok(scanEvidenceFlags(j).includes('unexpected_threat_name'));
 assert.equal(describeScan(j).attested,false);
});
test('QA absence of signature marker does not invent signature match',()=>{
 const j=decodeLabScanReviewJobs([redacted({signature_reported:false})])[0];
 assert.equal(scanEvidenceKind(j),'unverified_completion');
 assert.ok(scanEvidenceFlags(j).includes('malicious_without_signature'));
});
test('QA empty scan metadata list is valid unknown state',()=>{
 assert.deepEqual(decodeLabScanReviewJobs([]),[]);
});
