import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {PolicyEvidenceReview} from '../.test-dist/PolicyEvidenceReview.js';
import {ScanLifecycleReview} from '../.test-dist/ScanLifecycleReview.js';
import {decodePolicyMetadata,decodePolicyAssignments} from '../.test-dist/policy-readonly.js';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
const e=(id,patch={})=>({id,platform:'windows',group:'soc',status:'online',applied_policy_id:'',
  applied_revision:0,last_policy_error:'',...patch});
const p=(id,patch={})=>({id,name:'Lab Sysmon policy',platform:'windows',revision:2,
 sha256:'a'.repeat(64),created_at:'2026-11-21T12:00:00Z',
 ...patch});
const a=(id)=>({target_type:'agent',target_id:'WIN-A',platform:'windows',policy_id:id});
const policyView=(endpoints=[e('WIN-A')],policies=[p('p1')],assignments=[a('p1')])=>
 renderToStaticMarkup(createElement(PolicyEvidenceReview,{overview:{endpoints},
 policies:decodePolicyMetadata(policies),assignments:decodePolicyAssignments(assignments)}));
const job=(id,patch={})=>({id,agent_id:'WIN-A',status:'queued',scan_type:'path',
 created_at:'2026-11-21T10:00:00Z',expires_at:'2026-11-21T10:30:00Z',
 lease_id:'PRIVATE_LEASE',path:'C:\\Secret\\file.exe',request_id:'SECRET_REQ',
 ...patch});
const scanView=(jobs)=>renderToStaticMarkup(createElement(ScanLifecycleReview,{
 jobs:decodeScanJobs(jobs),generatedAt:'2026-11-21T12:00:00Z'}));
test('Day2 policy view uses labeled controls, summary and reports desired vs applied',()=>{
 const html=policyView();
 for(const field of ['policy-evidence-state','policy-evidence-host','policy-evidence-page-size'])
  assert.match(html,new RegExp('for="'+field+'"'));
 assert.match(html,/aria-live="polite"/);
 assert.match(html,/Reported applied policy/);
 assert.match(html,/acknowledgment missing/);
 assert.match(html,/<caption>/);
});
test('Day2 metadata-only policy payload cannot render raw Sysmon XML',()=>{
 const html=policyView();
 assert.doesNotMatch(html,/SECRET_POLICY_XML/);
 assert.doesNotMatch(html,/<Sysmon/);
});
test('Day2 sender error detail is withheld entirely from shared-token React view',()=>{
 const html=policyView([e('WIN-A',{last_policy_error:'<img src=x onerror=alert(1)>'})]);
 assert.match(html,/detail withheld/);
 assert.doesNotMatch(html,/onerror|&lt;img|<img\b/i);
});
test('Day2 read-only no POST/assign buttons and 25-row page',()=>{
 const html=policyView(Array.from({length:61},(_,i)=>e('HOST-'+i)),[],[]);
 const body=html.split('<tbody>')[1]?.split('</tbody>')[0]||'';
 assert.equal((body.match(/<tr>/g)||[]).length,25);
 assert.match(html,/Page 1 of 3/);
 assert.doesNotMatch(html,/<button[^>]*>(Apply|Deploy|Disable|Quarantine)<\/button>/i);
});
test('Day3 lifecycle view labels warnings and never shows active lease or scan paths',()=>{
 const html=scanView([job('job-1')]);
 assert.match(html,/Pending after reported expiry/);
 assert.match(html,/scan-lifecycle-only/);
 assert.match(html,/aria-live="polite"/);
 assert.match(html,/<caption>/);
 assert.doesNotMatch(html,/PRIVATE_LEASE|SECRET_REQ|Secret\\file.exe/);
});
test('Day3 empty or consistent lifecycle does not imply verified ClamAV execution',()=>{
 const html=scanView([]);
 assert.match(html,/No reported lifecycle inconsistencies/);
 assert.match(html,/does not certify scan execution/);
});
test('Day3 reported state contradictions render accessible and XSS safe',()=>{
 const html=scanView([job('job-1',{status:'failed',completed_at:'2026-11-21T10:31:00Z',
   detail:'<script>bad()</script>'})]);
 assert.match(html,/Completion later than request expiry/);
 assert.doesNotMatch(html,/<script\b|&lt;script/i);
});
