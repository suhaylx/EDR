import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AlertsTriageView } from '../.test-dist/AlertsTriageView.js';
import { decodeLabDetections } from '../.test-dist/detections.js';

const at = '2026-11-21T12:00:00Z';
const item = (change={}) => ({
  id:'d1', rule_id:'RULE-1', category:'signal', severity:'high', confidence:'low',
  device_id:'WIN-1', process_guid:'{ABC}', process_image:'cmd.exe',
  module_path:'C:\\Windows\\a.dll', load_event_id:'source-7', file_create_event_id:'event-11',
  observed_at:'2026-11-21T10:00:00Z', explanation:'Review evidence.', ...change,
});
const render = detections => renderToStaticMarkup(createElement(AlertsTriageView,{
  detections, generatedAt:at, days:7, onInvestigate:()=>{},
}));

test('alert queue uses labels, live result count, table headings and working-semantics controls', () => {
  const html=render(decodeLabDetections([item()]));
  assert.match(html, /<section[^>]*aria-labelledby="alerts-title"/);
  assert.match(html, /<label htmlFor=/) === null; // React SSR emits for= instead
  assert.match(html, /for="alert-severity-filter"/);
  assert.match(html, /for="alert-source-filter"/);
  assert.match(html, /for="alert-query"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<caption>/);
  assert.match(html, /<th scope="col">/);
  assert.match(html, /Investigate evidence/);
  assert.match(html, /1 of 1 retained detection record/);
  assert.match(html, /Clear local filters/);
});
test('untrusted strings are React-escaped, not injected as HTML', () => {
  const html=render(decodeLabDetections([item({
    module_path:'<img src=x onerror=alert(1)>',
    rule_id:'<script>bad</script>',
  })]));
  assert.doesNotMatch(html, /<img\b|<script\b/i);
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
});
test('empty window is not mislabeled protected and hides investigation actions', () => {
  const html=render([]);
  assert.match(html, /No detections were returned/);
  assert.match(html, /does not establish complete collection/);
  assert.doesNotMatch(html, /<table\b/);
  assert.doesNotMatch(html, /<button[^>]*class="source-button"/);
});
