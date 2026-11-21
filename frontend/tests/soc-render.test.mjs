import { test } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { OperatorSOCView } from '../.test-dist/OperatorSOC.js';

const session = { tenant_id: 'tenant-a', operator_id: 'operator-a', role: 'viewer', server_time: '2026-11-21T18:00:00Z' };
const empty = { items: [], limit: 25, offset: 0 };
const snapshot = { session, endpoints: empty, endpointStats: { total: 0, windows: 0, linux: 0, online: 0, degraded: 0, stale: 0, unseen: 0, revoked: 0 }, alerts: empty, alertStats: { open: 0, acknowledged: 0, resolved: 0 }, mine: empty };
const render = view => renderToStaticMarkup(React.createElement(OperatorSOCView, { view, onRefresh() {}, onClear() {}, onPage() {}, onActivity() {} }));

test('operator view exposes identity, accessible regions and unknown state without a token/private-key input', () => {
  const html = render({ state: 'ready', snapshot });
  assert.match(html, /tenant-a/);
  assert.match(html, /operator-a/);
  assert.match(html, /viewer/);
  assert.match(html, /Server time after these reads/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /Skip to SOC records/);
  assert.match(html, /No protection state can be inferred/);
  assert.match(html, /does not establish the absence of threats/);
  assert.doesNotMatch(html, /<input|<form|type="password"|localStorage/);
});

test('auth failures and pending states contain no stale snapshot identity or rows', () => {
  for (const view of [{ state: 'error', error: 'unauthorized' }, { state: 'error', error: 'forbidden' }, { state: 'loading' }, { state: 'disconnected' }]) {
    const html = render(view);
    assert.doesNotMatch(html, /tenant-a|operator-a|<table/);
    assert.match(html, /SOC records unavailable/);
  }
});

test('unknown and revoked endpoints remain distinct and never advertise verified protection', () => {
  const endpoints = { ...empty, items: ['unseen', 'revoked'].map(health => ({ agent_id: health + '-01', platform: 'linux', health, last_seen: null, heartbeat_count: 0, agent_version: '', clamav_version: '', signature_version: '', scan_ready: false })) };
  const html = render({ state: 'ready', snapshot: { ...snapshot, endpoints } });
  assert.match(html, /No server-received heartbeat recorded; current protection unknown/);
  assert.match(html, /Enrollment revoked/);
  assert.match(html, /scope="col"/);
  assert.match(html, /<caption>/);
});

test('untrusted signature and case notes render as text with no executable markup', () => {
  const alert = { alert_id: '11111111-1111-4111-8111-111111111111', agent_id: 'linux-01', signature_name: '<img src=x onerror=alert(1)>', state: 'open', updated_at: session.server_time, assigned_to: '' };
  const html = render({ state: 'ready', snapshot: { ...snapshot, alerts: { ...empty, items: [alert] } }, activity: { state: 'ready', alertID: alert.alert_id, page: { ...empty, items: [{ activity_id: '2', actor_id: 'operator-a', action: 'note', note: '<script>alert(1)</script>', occurred_at: session.server_time }] } } });
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img|<script/);
  assert.match(html, /Read activity for alert/);
  assert.match(html, /not a cryptographic audit log/);
});

test('clear-view wording does not claim to revoke the native browser certificate', () => {
  const html = render({ state: 'ready', snapshot });
  assert.match(html, /Clear displayed records/);
  assert.match(html, /does not revoke it or sign out/);
  assert.doesNotMatch(html, />Logout<|>Sign out</);
});
