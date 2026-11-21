import {test} from 'node:test';
import assert from 'node:assert/strict';
import {filterEndpointInventory,policyEvidenceLabel} from '../.test-dist/endpoint-inventory.js';
const e=(id,status,events=0,inactive_seconds=0,extra={})=>({
  id,status,events,inactive_seconds,alerts:0,platform:'windows',group:'lab',
  applied_policy_id:'',applied_revision:0,last_policy_error:'',reported_health:'ok',
  last_seen:'2026-11-21T10:00:00Z',...extra,
});
test('filters by server heartbeat state, group and case-insensitive ID',()=>{
 const all=[e('WIN-01','online',3),e('WIN-02','offline',5,86400),e('LINUX-01','unknown',0,0,{platform:'linux',group:'test'})];
 assert.deepEqual(filterEndpointInventory(all,'offline','','id').map(x=>x.id),['WIN-02']);
 assert.deepEqual(filterEndpointInventory(all,'all','test','id').map(x=>x.id),['LINUX-01']);
 assert.deepEqual(filterEndpointInventory(all,'all','win','id').map(x=>x.id),['WIN-01','WIN-02']);
 assert.deepEqual(all.map(x=>x.id),['WIN-01','WIN-02','LINUX-01']);
});
test('unknown heartbeat is never ranked as verified inactivity',()=>{
 const all=[e('unknown','unknown',0,0),e('offline','offline',0,86400),e('online','online',2,0)];
 assert.deepEqual(filterEndpointInventory(all,'all','','inactive').map(x=>x.id),['offline','online','unknown']);
 assert.deepEqual(filterEndpointInventory(all,'all','','events').map(x=>x.id),['online','offline','unknown']);
});
test('policy acknowledgement and last error never imply enforcement',()=>{
 assert.match(policyEvidenceLabel(e('a','online')),/No applied policy acknowledgment/);
 assert.match(policyEvidenceLabel(e('b','online',0,0,{applied_policy_id:'p1',applied_revision:2})),/NOT VERIFIED/);
 assert.match(policyEvidenceLabel(e('c','online',0,0,{last_policy_error:'collector failed',applied_policy_id:'p1'})),/Reported policy error/);
});
