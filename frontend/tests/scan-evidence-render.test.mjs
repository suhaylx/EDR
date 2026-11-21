import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {decodeScanJobs} from '../.test-dist/lab-api.js';
import {ScanEvidenceWorklist} from '../.test-dist/ScanEvidenceWorklist.js';

const job=(i,patch={})=>({
  id:'job-'+i,agent_id:'win-lab',status:'completed',scan_type:'path',
  verdict:'clean_by_signature',created_at:'2026-11-21T12:00:00Z',
  engine:'clamav',engine_version:'1.5.5',database_version:'lab-signatures',
  detail:'Reported by lab',...patch,
});
const render=jobs=>renderToStaticMarkup(createElement(ScanEvidenceWorklist,{
  jobs:decodeScanJobs(jobs),
}));

test('SSR worklist has semantic labeled controls, live counts, captions and reset',()=>{
  const html=render([job(1)]);
  for(const id of ['scan-category','scan-endpoint','scan-mode','scan-query','scan-sort','scan-size'])
    assert.match(html,new RegExp('for="'+id+'"'));
  assert.match(html,/aria-live="polite"/);
  assert.match(html,/<caption>/);
  assert.match(html,/aria-label="Scan worklist pagination"/);
  assert.match(html,/Clear scan filters/);
  assert.match(html,/1 of 1 scan job record/);
  assert.match(html,/Authenticated scanner result: NO/);
  assert.match(html,/Signature DB age\/integrity: NOT INSTRUMENTED/);
  assert.doesNotMatch(html,/<button[^>]*>Scan now<\/button>/);
});
test('reported quick/full success always displays unsupported danger, never clean',()=>{
  const html=render([
    job('q',{scan_type:'quick',verdict:'clean_by_signature'}),
    job('f',{scan_type:'full',verdict:'malicious',threat_name:'EICAR'}),
  ]);
  assert.equal((html.match(/Unsupported scan claim/g)||[]).length>=2,true);
  assert.match(html,/Unsupported or unverifiable mode/);
  assert.doesNotMatch(html,/class="status status--neutral">Clean by signature/);
});
test('scan table limits 60 records to 25 visible rows and reports page range',()=>{
  const html=render(Array.from({length:60},(_,i)=>job(i)));
  assert.match(html,/60 of 60 scan job record/);
  assert.match(html,/rows 1–25/);
  assert.match(html,/Page 1 of 3/);
  const tbody=html.split('<tbody>')[1]?.split('</tbody>')[0]||'';
  assert.equal((tbody.match(/<tr>/g)||[]).length,25);
});
test('untrusted detail and threat name are React-escaped, never HTML',()=>{
  const html=render([job('x',{
    verdict:'malicious',
    threat_name:'<script>alert(1)</script>',
    detail:'<img src=x onerror=alert(1)>',
  })]);
  assert.match(html,/&lt;script/);
  assert.match(html,/&lt;img/);
  assert.doesNotMatch(html,/<script\b|<img\b/i);
});
test('missing scan jobs say unknown, not safe, and create no scan controls',()=>{
  const html=render([]);
  assert.match(html,/No scan jobs returned/);
  assert.match(html,/No endpoint safety/);
  assert.doesNotMatch(html,/<table\b/);
  assert.doesNotMatch(html,/<button[^>]*>Quarantine<\/button>/i);
});
test('failed and unscanned scan reports remain distinct from completion',()=>{
  const html=render([
    job('failed',{status:'failed',verdict:'error',scan_type:'quick'}),
    job('unscanned',{status:'failed',verdict:'unscanned',scan_type:'full'}),
  ]);
  assert.match(html,/Scanner error/);
  assert.match(html,/Unscanned/);
  assert.match(html,/Raw phase: failed/);
  assert.doesNotMatch(html,/Protected endpoint|Verified healthy/i);
});
