import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeLabInvestigation, deriveProcessForest, investigationTimeline,
  buildInvestigationPath, fetchLabInvestigation,
} from '../.test-dist/investigation.js';

const deviceID = 'win-lab-01';
const processSeed = {deviceID, kind: 'process', processGUID: '{CHILD-1}'};
const processNode = (id, guid, status = 'observed') =>
  ({id,kind:'process',status,label:id,device_id:deviceID,process_guid:guid});
const event = (id, time) =>
  ({id,kind:'event',status:'observed',label:id,device_id:deviceID,process_guid:'{CHILD-1}',event_id:id,event_type:'process_create',time});
const parent = {from:'parent',to:'child',relation:'parent_process',provenance:'observed',evidence_id:'event-1'};
const base = (changes={}) => ({
  device_id:deviceID,seed_process_guid:'{CHILD-1}',data_source:'development_in_memory_retained_telemetry',
  nodes:[
    processNode('parent','{PARENT}','referenced'),
    processNode('child','{CHILD-1}'),
    event('event-1','2026-11-21T10:00:00Z'),
    event('event-2','2026-11-21T09:00:00Z')
  ],
  edges:[parent,{from:'child',to:'event-1',relation:'observed_event',provenance:'observed',evidence_id:'event-1'}],
  gaps:['Parent event may be absent; retained events only.'],truncated:false,...changes
});
test('decodes read-only retained investigation and renders parent relation provenance',()=>{
  const graph=decodeLabInvestigation(base(),deviceID,processSeed);
  assert.equal(graph.seed_process_guid,'{CHILD-1}');
  assert.equal(graph.nodes.length,4);
  assert.deepEqual(graph.gaps,['Parent event may be absent; retained events only.']);
  const forest=deriveProcessForest(graph);
  assert.equal(forest.length,1);
  assert.equal(forest[0].node.id,'parent');
  assert.equal(forest[0].children[0].node.id,'child');
  assert.equal(forest[0].children[0].parentRelation.provenance,'observed');
  assert.equal(forest[0].children[0].parentRelation.evidence_id,'event-1');
});
test('timeline sorted deterministically and contains only events or detections',()=>{
  const graph=decodeLabInvestigation(base(),deviceID,processSeed);
  assert.deepEqual(investigationTimeline(graph).map(n=>n.id),['event-2','event-1']);
});
test('rejects source spoofing, cross-host evidence, missing seeds and wrong detection',()=>{
  assert.throws(()=>decodeLabInvestigation(base({data_source:'verified_production'}),deviceID,processSeed),/Unexpected investigation data source/);
  assert.throws(()=>decodeLabInvestigation(base({device_id:'win-other'}),deviceID,processSeed),/does not match/);
  const rogue={...processNode('rogue','{OTHER}'),device_id:'win-other'};
  assert.throws(()=>decodeLabInvestigation(base({nodes:[...base().nodes,rogue]}),deviceID,processSeed),/Cross-device/);
  assert.throws(()=>decodeLabInvestigation(base({nodes:[processNode('parent','{PARENT}')]}),deviceID,processSeed),/seed process is absent/);
  assert.throws(()=>decodeLabInvestigation(base({seed_detection_id:'different'}),deviceID,{deviceID,kind:'detection',detectionID:'det-1'}),/detection seed/);
});
test('rejects untrusted node and graph semantics rather than guessing',()=>{
  assert.throws(()=>decodeLabInvestigation(base({truncated:undefined}),deviceID,processSeed),/truncation flag/);
  assert.throws(()=>decodeLabInvestigation(base({nodes:[...base().nodes,base().nodes[0]]}),deviceID,processSeed),/Duplicate/);
  assert.throws(()=>decodeLabInvestigation(base({nodes:[...base().nodes,{...event('bad',''),kind:'infected'}]}),deviceID,processSeed),/node kind\/status/);
  assert.throws(()=>decodeLabInvestigation(base({edges:[{...parent,provenance:'proven'}]}),deviceID,processSeed),/edge provenance/);
  assert.throws(()=>decodeLabInvestigation(base({edges:[{...parent,to:'absent'}]}),deviceID,processSeed),/missing evidence node/);
  assert.throws(()=>decodeLabInvestigation(base({nodes:new Array(501).fill(processNode('p','{CHILD-1}'))}),deviceID,processSeed),/Invalid investigation list/);
});
test('rejects cycles and ambiguous parentage, preserving reported relationship status',()=>{
  const graph=base({edges:[parent,{from:'child',to:'parent',relation:'parent_process',provenance:'reported',evidence_id:''}]});
  assert.throws(()=>decodeLabInvestigation(graph,deviceID,processSeed),/Cyclic process lineage/);
  const third=processNode('third','{THIRD}');
  const ambiguous=base({nodes:[...base().nodes,third],edges:[parent,{from:'third',to:'child',relation:'parent_process',provenance:'reported'}]});
  assert.throws(()=>decodeLabInvestigation(ambiguous,deviceID,processSeed),/Ambiguous process parentage/);
  const reported=decodeLabInvestigation(base({edges:[{...parent,provenance:'reported'}]}),deviceID,processSeed);
  assert.equal(deriveProcessForest(reported)[0].children[0].parentRelation.provenance,'reported');
});
test('constructs properly escaped, same-device read-only request paths',()=>{
  const p=buildInvestigationPath(processSeed);
  const url=new URL(p,'http://127.0.0.1');
  assert.equal(url.pathname,'/api/investigations');
  assert.equal(url.searchParams.get('device_id'),deviceID);
  assert.equal(url.searchParams.get('process_guid'),'{CHILD-1}');
  assert.equal(url.searchParams.get('detection_id'),null);
  assert.equal(url.searchParams.get('max_nodes'),'250');
  const d=buildInvestigationPath({deviceID,kind:'detection',detectionID:'det&1'});
  assert.equal(new URL(d,'http://127.0.0.1').searchParams.get('detection_id'),'det&1');
  assert.throws(()=>buildInvestigationPath({deviceID:'',kind:'process',processGUID:'ok'}),/endpoint ID/);
  assert.throws(()=>buildInvestigationPath({deviceID,kind:'process',processGUID:'\n'}),/process GUID/);
});
test('fetch uses dev bearer in no-store GET and validates response',async()=>{
  let request;
  const fetcher=async (url, options)=>{request={url,options};return {ok:true,json:async()=>base()};};
  const graph=await fetchLabInvestigation('t'.repeat(16),processSeed,undefined,fetcher);
  assert.equal(graph.nodes.length,4);
  assert.equal(request.options.method,'GET');
  assert.equal(request.options.credentials,'omit');
  assert.equal(request.options.cache,'no-store');
  assert.equal(request.options.headers.Authorization,'Bearer '+'t'.repeat(16));
  await assert.rejects(fetchLabInvestigation('short',processSeed,undefined,fetcher),/16 characters/);
  await assert.rejects(fetchLabInvestigation('t'.repeat(16),processSeed,undefined,async()=>({ok:false,status:404})),/No matching seed/);
  await assert.rejects(fetchLabInvestigation('t'.repeat(16),processSeed,undefined,async()=>({ok:false,status:401})),/token rejected/);
});
