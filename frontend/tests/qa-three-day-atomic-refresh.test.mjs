import test from 'node:test';
import assert from 'node:assert/strict';
import {loadSixReadOnlyEvidence} from '../.test-dist/lab-refresh.js';

const six=()=>[1,2,3,4,5,6].map(value=>async()=>value);

test('QA day1: exactly six independent successful sources publish together in order',async()=>{
  const result=await loadSixReadOnlyEvidence(six());
  assert.deepEqual(result,[1,2,3,4,5,6]);
});

test('QA day1: all six sources start; a single failed source aborts publication',async()=>{
  const started=[];
  const loaders=[0,1,2,3,4,5].map(i=>async()=>{
    started.push(i);
    if(i===4)throw new Error('Untrusted policy metadata response');
    return 'source-'+i;
  });
  await assert.rejects(loadSixReadOnlyEvidence(loaders),/policy metadata/);
  assert.deepEqual(started,[0,1,2,3,4,5]);
});

test('QA day1: a failed scan source cannot return partial overview or policies',async()=>{
  const loaders=six();
  loaders[1]=async()=>{throw new Error('Scan metadata HTTP 401');};
  await assert.rejects(loadSixReadOnlyEvidence(loaders),/HTTP 401/);
});

test('QA day1: already aborted request launches none of the six loaders',async()=>{
  const c=new AbortController();
  c.abort();
  let calls=0;
  const loaders=six().map(fn=>async()=>{calls++;return fn();});
  await assert.rejects(loadSixReadOnlyEvidence(loaders,c.signal),/aborted before dispatch/);
  assert.equal(calls,0);
});

test('QA day1: interrupted stale refresh cannot commit even when fetch mocks ignore AbortSignal',async()=>{
  const c=new AbortController();
  let finish;
  const delayed=new Promise(resolve=>{finish=resolve;});
  const loaders=six();
  loaders[5]=()=>delayed;
  const pending=loadSixReadOnlyEvidence(loaders,c.signal);
  c.abort();
  finish('stale-assignments');
  await assert.rejects(pending,/aborted before commit/);
});

test('QA day1: a fresh request can succeed after a previous aborted request',async()=>{
  const bad=new AbortController();bad.abort();
  await assert.rejects(loadSixReadOnlyEvidence(six(),bad.signal),/aborted/);
  assert.deepEqual(await loadSixReadOnlyEvidence(six(),new AbortController().signal),[1,2,3,4,5,6]);
});

test('QA day1: rejecting with no source details does not fabricate an empty success',async()=>{
  const loaders=six();
  loaders[3]=async()=>{throw new Error('telemetry transport disconnected');};
  await assert.rejects(loadSixReadOnlyEvidence(loaders),/transport disconnected/);
});
