import {test} from 'node:test';
import assert from 'node:assert/strict';
import {filterScanHistory, scanFilterMatches} from '../.test-dist/scan-history.js';

const records = [
  {id:'queued',agent_id:'win-a',status:'queued'},
  {id:'leased',agent_id:'linux-a',status:'leased'},
  {id:'failed',agent_id:'linux-b',status:'failed',verdict:'unscanned'},
  {id:'error',agent_id:'win-c',status:'failed',verdict:'error'},
  {id:'expired',agent_id:'win-d',status:'expired'},
  {id:'malicious',scan_type:'path',agent_id:'win-e',status:'completed',verdict:'malicious',threat_name:'Test.EICAR'},
  {id:'negative',scan_type:'path',agent_id:'win-f',status:'completed',verdict:'clean_by_signature',engine:'ClamAV'},
  {id:'suspicious',scan_type:'path',agent_id:'win-g',status:'completed',verdict:'suspicious'},
  {id:'bad-completion',agent_id:'win-h',status:'completed',verdict:'error'},
  {id:'unknown',agent_id:'win-i',status:'surprise'},
];
const ids = (filter, query='') => filterScanHistory(records,filter,query).map(j=>j.id);

test('pending filter never implies completed scan',()=>{
  assert.deepEqual(ids('pending'),['queued','leased']);
  assert.equal(scanFilterMatches(records[0],'reported_match'),false);
});
test('failed/error and unscanned are distinct but can overlap',()=>{
  assert.deepEqual(ids('failed_or_error'),['failed','error','expired','bad-completion']);
  assert.deepEqual(ids('unscanned'),['failed']);
});
test('reported positives and negatives require completed job status',()=>{
  assert.deepEqual(ids('reported_match'),['malicious']);
  assert.deepEqual(ids('signature_negative'),['negative']);
  assert.equal(scanFilterMatches({id:'x',agent_id:'a',status:'queued',verdict:'malicious'}, 'reported_match'),false);
  assert.equal(scanFilterMatches({id:'x',agent_id:'a',status:'leased',verdict:'clean_by_signature'},'signature_negative'),false);
});
test('malformed states and completions remain visibly unrecognized',()=>{
  assert.deepEqual(ids('unrecognized'),['bad-completion','unknown']);
  assert.deepEqual(ids('all'),records.map(x=>x.id));
});
test('local search matches all reported source fields without mutation',()=>{
  assert.deepEqual(ids('all','  test.eicar  '),['malicious']);
  assert.deepEqual(ids('signature_negative','CLAMAV'),['negative']);
  assert.deepEqual(ids('all','WIN-A'),['queued']);
  assert.deepEqual(ids('all','not found'),[]);
  assert.equal(records.length,10);
});

test('unsupported quick/full scan success claims are not positive or negative evidence', () => {
  for (const scan_type of ['quick','full']) {
    for (const verdict of ['malicious', 'suspicious', 'clean_by_signature']) {
      const record = {id: scan_type + verdict, agent_id: 'lab', scan_type, status: 'completed', verdict};
      assert.equal(scanFilterMatches(record, 'reported_match'), false);
      assert.equal(scanFilterMatches(record, 'signature_negative'), false);
      assert.equal(scanFilterMatches(record, 'unrecognized'), true);
    }
    assert.equal(scanFilterMatches({id:'fail',agent_id:'lab', scan_type, status:'failed', verdict:'unscanned'},'unscanned'),true);
  }
  const pathResult = {id:'path',agent_id:'lab',scan_type:'path',status:'completed',verdict:'clean_by_signature'};
  assert.equal(scanFilterMatches(pathResult,'signature_negative'),true);
  assert.equal(scanFilterMatches(pathResult,'unrecognized'),false);
});
