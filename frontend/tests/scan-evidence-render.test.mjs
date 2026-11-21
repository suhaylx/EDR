import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {ScanEvidenceWorkbench} from '../.test-dist/ScanEvidenceWorkbench.js';
import {decodeScanJobs} from '../.test-dist/lab-api.js';

const row=(id,patch={})=>({
  id,agent_id:'win-A',status:'completed',scan_type:'path',
  verdict:'clean_by_signature',created_at:'2026-11-21T12:00:00Z',
  engine:'clamav',engine_version:'1.5.5',database_version:'daily-test',
  threat_name:'',detail:'Unverified signature result',...patch,
});
const view=jobs=>renderToStaticMarkup(createElement(ScanEvidenceWorkbench,{
  jobs:decodeScanJobs(jobs),
}));

test('read-only scan workbench has labels, status counts, bounded table and no actions',()=>{
  const html=view([row('one')]);
  for(const id of ['scan-triage-kind','scan-triage-mode','scan-triage-metadata',
    'scan-triage-agent','scan-triage-query','scan-triage-sort','scan-triage-pagesize']){
    assert.match(html,new RegExp('for="'+id+'"'));
  }
  assert.match(html,/aria-live="polite"/);
  assert.match(html,/<caption>/);
  assert.match(html,/Inspect one reported fields/);
  assert.match(html,/Clear scan worklist filters/);
  assert.match(html,/Reported signature-negative/);
  assert.match(html,/not proof of safety/i);
  assert.doesNotMatch(html,/<button[^>]*>(Scan now|Quarantine|Isolate|Delete|Disable protection)<\/button>/i);
});
test('unsupported full and quick success appear visibly inconsistent, not clean or verified',()=>{
  const html=view([row('full',{scan_type:'full'}),row('quick',{scan_type:'quick',verdict:'malicious',
    threat_name:'Synthetic.Test'})]);
  assert.match(html,/Unsupported quick\/full success claim/);
  assert.match(html,/reported-evidence warning/);
  assert.doesNotMatch(html,/Verified scan protection|100% protected/i);
});
test('completed scanner error and unscanned remain distinct from successful scan',()=>{
  const html=view([row('error',{verdict:'error',threat_name:''}),
    row('unscanned',{verdict:'unscanned'})]);
  assert.match(html,/Scanner error/);
  assert.match(html,/Unscanned/);
  assert.doesNotMatch(html,/Signature match reported/);
});
test('empty returned queue never displays healthy protection or success',()=>{
  const html=view([]);
  assert.match(html,/No scan jobs were returned/);
  assert.match(html,/does not establish an idle scanner/);
  assert.doesNotMatch(html,/<tbody>/);
});
test('the first 25 of 61 matching rows render in the first page without overflow',()=>{
  const jobs=Array.from({length:61},(_,i)=>row('job-'+i));
  const html=view(jobs);
  assert.match(html,/61 of 61 returned job\(s\) match/);
  assert.match(html,/Page 1 of 3/);
  assert.match(html,/rows 1–25/);
  const table=html.split('<tbody>')[1]?.split('</tbody>')[0]||'';
  assert.equal((table.match(/<tr>/g)||[]).length,25);
});
test('private worker detail and signature name never enter React markup',()=>{
  const html=view([row('unsafe',{detail:'<img src=x onerror=alert(1)>',
    verdict:'malicious',threat_name:'PRIVATE_SIGNATURE_NAME'})]);
  assert.match(html,/name withheld|Name withheld/i);
  assert.match(html,/Withheld from analyst metadata view/);
  assert.doesNotMatch(html,/PRIVATE_SIGNATURE_NAME|&lt;img|onerror|<img\b|<script\b/i);
});
test('missing mode never becomes a trusted positive result in visible UI',()=>{
  const html=view([row('unspecified',{scan_type:undefined,verdict:'malicious',
    threat_name:'Synthetic.Test'})]);
  assert.match(html,/Completed delivery — evidence insufficient/);
  assert.match(html,/no valid scan execution or verdict can be inferred/);
});
