import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { LocalCompanionView } from '../.test-dist/LocalCompanionView.js';
import { decodeLocalCompanionSnapshot } from '../.test-dist/local-companion.js';

const base = () => ({
  schema_version:1, source:'local_agent_ipc_v1', platform:'windows',
  observed_at:'2026-11-21T17:00:00Z', core_state:'reported_running',
  clamav_state:'reported_available', telemetry_state:'reported_available',
  policy_revision:5, scan_state:'completed',
});
const render = (snapshot, nowMs) =>
  renderToStaticMarkup(createElement(LocalCompanionView, { snapshot, nowMs }));

test('disconnected companion is informative, semantic and contains no endpoint controls', () => {
  const html = render(null, 0);
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<main/);
  assert.match(html, /<dl/);
  assert.match(html, /Local agent status unavailable/);
  assert.match(html, /UI PROTOTYPE/);
  assert.equal((html.match(/<dt>/g) || []).length, 6);
  assert.doesNotMatch(html, /<button\b|<form\b|<input\b|<select\b/i);
  assert.doesNotMatch(html, /Available \(reported\)|Running \(reported\)/);
});
test('future/stale reports do not leave previous positive-looking health in HTML', () => {
  const snapshot = decodeLocalCompanionSnapshot(base());
  const t = Date.parse(snapshot.observed_at);
  for (const age of [-1000, 61000]) {
    const html = render(snapshot, t + age);
    assert.match(html, /Local agent status not current/);
    assert.doesNotMatch(html, /Available \(reported\)|Running \(reported\)/);
    assert.equal((html.match(/<strong>Unknown<\/strong>/g)||[]).length, 6);
  }
});
test('recent reported data remain explicitly unverified and scan completion is not safety', () => {
  const snapshot = decodeLocalCompanionSnapshot(base());
  const html = render(snapshot, Date.parse(snapshot.observed_at) + 1000);
  assert.match(html, /Windows Sysmon telemetry/);
  assert.match(html, /Completed \(reported\) — verdict unavailable/);
  assert.match(html, /not attested/);
  assert.doesNotMatch(html, /safe endpoint|protection verified/i);
  assert.doesNotMatch(html, /<button\b/i);
});
test('Linux report labels Linux collector, not Windows Sysmon', () => {
  const snapshot = decodeLocalCompanionSnapshot({...base(),platform:'linux'});
  const html = render(snapshot, Date.parse(snapshot.observed_at) + 1000);
  assert.match(html, /Linux telemetry collector/);
  assert.doesNotMatch(html, /Windows Sysmon telemetry/);
});
