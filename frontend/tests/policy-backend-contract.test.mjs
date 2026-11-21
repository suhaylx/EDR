import test from 'node:test';
import assert from 'node:assert/strict';
import {decodePolicyMetadata,decodePolicyAssignments,reviewPolicyEvidence,desiredPolicyForEndpoint,
 fetchPolicyMetadata,fetchPolicyAssignments} from '../.test-dist/policy-readonly.js';
const digest='a'.repeat(64);
const p=(id,patch={})=>({id,name:'Lab Sysmon',platform:'windows',revision:1,sha256:digest,
 xml:'<Sysmon><EventFiltering/></Sysmon>',created_at:'2026-11-21T12:00:00Z',...patch});
const a=(target_type,target_id,policy_id,patch={})=>({target_type,target_id,platform:'windows',policy_id,...patch});
const e=(id,patch={})=>({id,group:'soc',platform:'windows',status:'online',
 applied_policy_id:'',applied_revision:0,last_policy_error:'',...patch});
const base=(endpoints)=>({endpoints});
test('Day2 decoder only returns bounded policy metadata, never XML',()=>{
 const raw=p('p1');const value=decodePolicyMetadata([raw])[0];
 assert.deepEqual(Object.keys(value).sort(),['created_at','id','name','platform','revision','sha256'].sort());
 assert.equal(JSON.stringify(value).includes('<Sysmon>'),false);
});
test('Day2 empty policy/assignment catalogs are valid unknown coverage',()=>{
 assert.deepEqual(decodePolicyMetadata([]),[]);
 assert.deepEqual(decodePolicyAssignments([]),[]);
 assert.equal(reviewPolicyEvidence(base([e('a')]),[],[])[0].status,'unassigned');
});
test('Day2 reject invalid XML source type even though UI never displays XML',()=>{
 assert.throws(()=>decodePolicyMetadata([p('p1',{xml:23})]),/XML/);
 assert.throws(()=>decodePolicyMetadata([p('p1',{xml:'x'.repeat(65537)})]),/XML/);
});
test('Day2 reject duplicate IDs, invalid revisions, digest and timestamps',()=>{
 assert.throws(()=>decodePolicyMetadata([p('a'),p('a')]),/Duplicate/);
 assert.throws(()=>decodePolicyMetadata([p('a',{revision:-1})]),/revision/);
 assert.throws(()=>decodePolicyMetadata([p('a',{sha256:'not-a-digest'})]),/SHA256/);
 assert.throws(()=>decodePolicyMetadata([p('a',{created_at:'no-date'})]),/timestamp/);
});
test('Day2 assignment decoder rejects unknown targets and duplicated keys',()=>{
 assert.throws(()=>decodePolicyAssignments([a('unknown','x','p1')]),/target type/);
 assert.throws(()=>decodePolicyAssignments([a('agent','x','p1'),a('agent','x','p2')]),/Duplicate/);
 assert.throws(()=>decodePolicyAssignments([a('default','not-star','p1')]),/default target/);
});
test('Day2 agent overrides group and default for matching platform only',()=>{
 const assignments=decodePolicyAssignments([a('default','*','base'),a('group','soc','group'),
   a('agent','x','specific')]);
 const desired=desiredPolicyForEndpoint(e('x'),assignments);
 assert.equal(desired.policy_id,'specific');
 assert.equal(desiredPolicyForEndpoint(e('y'),assignments).policy_id,'group');
 assert.equal(desiredPolicyForEndpoint(e('z',{group:'unknown'}),assignments).policy_id,'base');
});
test('Day2 Windows assignments cannot be applied to Linux endpoint',()=>{
 const assignments=decodePolicyAssignments([a('default','*','p1')]);
 assert.equal(desiredPolicyForEndpoint(e('linux',{platform:'linux'}),assignments),null);
});
test('Day2 reported acknowledgment matches only desired id and revision',()=>{
 const policies=decodePolicyMetadata([p('p1',{revision:2})]);
 const assignments=decodePolicyAssignments([a('agent','x','p1')]);
 assert.equal(reviewPolicyEvidence(base([e('x',{applied_policy_id:'p1',applied_revision:2})]),policies,assignments)[0].status,'applied_reported');
 assert.equal(reviewPolicyEvidence(base([e('x',{applied_policy_id:'p1',applied_revision:1})]),policies,assignments)[0].status,'ack_mismatch');
});
test('Day2 missing catalog, missing ack, and mismatched applied IDs are distinct',()=>{
 const assignments=decodePolicyAssignments([a('agent','x','p1')]);
 assert.equal(reviewPolicyEvidence(base([e('x')]),[],assignments)[0].status,'unknown_policy');
 const policies=decodePolicyMetadata([p('p1')]);
 assert.equal(reviewPolicyEvidence(base([e('x')]),policies,assignments)[0].status,'awaiting_ack');
 assert.equal(reviewPolicyEvidence(base([e('x',{applied_policy_id:'other'})]),policies,assignments)[0].status,'ack_mismatch');
});
test('Day2 reported errors are not misrepresented as enforced policy',()=>{
 const rows=reviewPolicyEvidence(base([e('x',{applied_policy_id:'p1',applied_revision:1,last_policy_error:'failed'})]),
 decodePolicyMetadata([p('p1')]),decodePolicyAssignments([a('agent','x','p1')]));
 assert.equal(rows[0].status,'error_reported');
});
test('Day2 policy GET sends bearer token, no cookies, no writes, no caching',async()=>{
 const calls=[],fetcher=async(url,options)=>{calls.push({url,options});
  return {ok:true,json:async()=>url==='/api/policies'?[p('p1')]:[a('default','*','p1')]};
 };
 await fetchPolicyMetadata('t'.repeat(16),undefined,fetcher);
 await fetchPolicyAssignments('t'.repeat(16),undefined,fetcher);
 assert.deepEqual(calls.map(x=>x.url),['/api/policies','/api/assignments']);
 for(const {options} of calls){
  assert.equal(options.method,'GET');assert.equal(options.credentials,'omit');
  assert.equal(options.cache,'no-store');assert.equal(options.headers.Authorization,'Bearer '+'t'.repeat(16));
 }
});
test('Day2 invalid credentials or HTTP failure cannot yield cached policy evidence',async()=>{
 const fail=async()=>({ok:false,status:401});
 await assert.rejects(fetchPolicyMetadata('short',undefined,fail),/16 characters/);
 await assert.rejects(fetchPolicyAssignments('t'.repeat(16),undefined,fail),/401/);
});
