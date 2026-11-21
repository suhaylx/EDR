'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { matchesEvidence, attach, focusEvidence } = require('./graph-controls.js');
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

test('source links reveal locally filtered retained evidence before focusing', () => {
  const actions = [];
  const item = {
    hidden: true,
    focus() { actions.push('focused'); },
    scrollIntoView(options) { assert.deepEqual(options, {block: 'nearest'}); actions.push('scrolled'); }
  };
  const input = {value: 'unrelated-filter'};
  assert.equal(focusEvidence(item, input, () => { actions.push('filter-updated'); item.hidden = false; }), true);
  assert.equal(input.value, '');
  assert.equal(item.hidden, false);
  assert.equal(item.tabIndex, -1);
  assert.deepEqual(actions, ['filter-updated', 'focused', 'scrolled']);
});
test('already-visible source does not clear a local filter', () => {
  const item = {hidden: false, focus() { this.didFocus = true; }};
  const input = {value: 'retained-source'};
  let updated = false;
  assert.equal(focusEvidence(item, input, () => { updated = true; }), true);
  assert.equal(input.value, 'retained-source');
  assert.equal(updated, false);
  assert.equal(item.didFocus, true);
});
test('unresolvable or still-hidden source is not reported as navigated', () => {
  const input = {value: 'test'};
  assert.equal(focusEvidence(null, input, () => {}), false);
  assert.equal(focusEvidence({hidden: false}, null, () => {}), false);
  assert.equal(focusEvidence({hidden: false}, input, null), false);
  let focused = false;
  const item = {hidden: true, focus() { focused = true; }};
  assert.equal(focusEvidence(item, input, () => {}), false);
  assert.equal(focused, false);
});
