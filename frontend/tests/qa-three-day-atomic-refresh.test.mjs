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


test('QA: aborted refresh settles promptly even if one loader never resolves',{timeout:5000},async()=>{
  const controller=new AbortController();
  const loaders=six();
  loaders[2]=()=>new Promise(()=>{});
  const pending=loadSixReadOnlyEvidence(loaders,controller.signal);
  controller.abort();
  await assert.rejects(pending,/aborted before commit/);
});

test('QA: synchronous cancellation during source dispatch cannot publish data',async()=>{
  const controller=new AbortController();
  const loaders=six();
  loaders[4]=()=>{controller.abort();return Promise.resolve('cancelled');};
  await assert.rejects(loadSixReadOnlyEvidence(loaders,controller.signal),/aborted before commit/);
});

test('QA: a late fetch failure after abort cannot publish stale evidence',async()=>{
  const controller=new AbortController();
  let rejectLate;
  const loaders=six();
  loaders[5]=()=>new Promise((_,reject)=>{rejectLate=reject;});
  const stale=loadSixReadOnlyEvidence(loaders,controller.signal);
  controller.abort();
  await assert.rejects(stale,/aborted before commit/);
  rejectLate(new Error('late network error'));
  await Promise.resolve();
  assert.deepEqual(await loadSixReadOnlyEvidence(six(),new AbortController().signal),[1,2,3,4,5,6]);
});

test('QA: successful refresh removes the abort listener',async()=>{
  const controller=new AbortController();
  const realAdd=controller.signal.addEventListener.bind(controller.signal);
  const realRemove=controller.signal.removeEventListener.bind(controller.signal);
  let adds=0,removes=0;
  controller.signal.addEventListener=(...args)=>{if(args[0]==='abort')adds++;return realAdd(...args);};
  controller.signal.removeEventListener=(...args)=>{if(args[0]==='abort')removes++;return realRemove(...args);};
  assert.deepEqual(await loadSixReadOnlyEvidence(six(),controller.signal),[1,2,3,4,5,6]);
  assert.equal(adds,1);
  assert.equal(removes,1);
});
