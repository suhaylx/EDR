'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {describeScan, scanEngineEvidence} = require('./scan-display.js');
const job = (status, verdict, extra = {}) => ({id: 'job1', agent_id: 'lab1', status, verdict, ...extra});
test('queued, leased and expired are not completed scans', () => {
  for (const status of ['queued', 'leased', 'expired']) {
    const result = describeScan(job(status));
    assert.equal(result.attested, false);
    assert.notEqual(result.heading, 'Clean by signature (reported)');
    assert.match(result.explanation, /not (been observed|reported)|expired/);
  }
});
test('failed unscanned and scanner error are distinct', () => {
  assert.equal(describeScan(job('failed', 'unscanned')).heading, 'Unscanned');
  assert.equal(describeScan(job('failed', 'error')).heading, 'Scanner error');
  assert.equal(describeScan(job('failed', 'error')).tone, 'danger');
});
test('clean signature is not a safety claim, even when completed', () => {
  const result = describeScan(job('completed', 'clean_by_signature'));
  assert.equal(result.attested, false);
  assert.match(result.explanation, /not proof.*safe/);
});
test('malicious, suspicious and malformed completions remain reported', () => {
  assert.equal(describeScan(job('completed', 'malicious', {threat_name: 'Test.EICAR'})).tone, 'danger');
  assert.match(describeScan(job('completed', 'malicious')).explanation, /without a signature name/);
  assert.equal(describeScan(job('completed', 'suspicious')).tone, 'warning');
  assert.equal(describeScan(job('completed')).heading, 'Result not verified');
  assert.equal(describeScan(job('unexpected', 'clean_by_signature')).heading, 'Unknown job state');
});
test('engine fields are reported-only and never claim DB freshness', () => {
  const empty = scanEngineEvidence(job('completed', 'clean_by_signature'));
  assert.match(empty, /signature DB version: not reported/);
  assert.match(empty, /freshness NOT VERIFIED/);
  assert.match(scanEngineEvidence(job('completed', 'malicious', {engine:'ClamAV', database_version:'123'})), /Claimed engine: ClamAV/);
});
test('malicious signature name is data, not formatted as HTML by the helper', () => {
  const text = describeScan(job('completed', 'malicious', {threat_name:'<img src=x onerror=alert(1)>'})).explanation;
  assert.match(text, /<img/);
  // It is deliberately plain text: app.js rows() HTML-escapes before insertion.
});

test('completed scanner errors and unperformed scans remain explicit and unattested', () => {
  for (const [verdict, heading, tone] of [['error', 'Scanner error', 'danger'], ['unscanned', 'Unscanned', 'warning']]) {
    const result = describeScan(job('completed', verdict));
    assert.equal(result.heading, heading);
    assert.equal(result.tone, tone);
    assert.equal(result.attested, false);
    assert.match(result.explanation, /No successful scan|not performed/i);
  }
});
