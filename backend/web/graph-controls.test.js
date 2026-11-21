'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { matchesEvidence, attach } = require('./graph-controls.js');
test('source ID and process GUID searches are case insensitive', () => {
  assert.equal(matchesEvidence('EventID ABC-27 / PROCESS {ABC}', 'abc-27'), true);
  assert.equal(matchesEvidence('EventID ABC-27 / PROCESS {ABC}', '{abc}'), true);
  assert.equal(matchesEvidence('EventID ABC-27 / PROCESS {ABC}', 'not-found'), false);
});
test('blank local search displays the original evidence', () => {
  assert.equal(matchesEvidence('Observed load / user path', '   '), true);
  assert.equal(matchesEvidence(null, ''), true);
});
test('unavailable graph is not presented as an interactive graph', () => {
  assert.equal(attach(null), false);
  assert.equal(attach({querySelector: () => null}), false);
});
