import { test } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { OperatorSOCView } from '../.test-dist/OperatorSOC.js';
import { alert as caseAlert, job as scanJob, result as scanResult, endpoint as scanEndpoint } from './soc-workflow-fixture.mjs';

const session = { tenant_id: 'tenant-a', operator_id: 'operator-a', role: 'viewer', server_time: '2026-11-21T18:00:00Z' };
const empty = { items: [], limit: 25, offset: 0 };
const snapshot = { session, endpoints: empty, endpointStats: { total: 0, windows: 0, linux: 0, online: 0, degraded: 0, stale: 0, unseen: 0, revoked: 0 }, alerts: empty, alertStats: { open: 0, acknowledged: 0, resolved: 0 }, mine: empty, jobs: empty, results: empty, scanStats: { total: 0, pending: 0, leased: 0, succeeded: 0, failed: 0, cancelled: 0, malicious: 0 } };
const render = view => renderToStaticMarkup(React.createElement(OperatorSOCView, { view, onRefresh() {}, onClear() {}, onPage() {}, onCase() {}, onScan() {}, onMutation() {} }));

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
  assert.match(html, /type="search"/); // The endpoint filter is intentionally available.
  assert.doesNotMatch(html, /type="password"|name="token"|localStorage/);
});

test('password-backed SOC presents a focused workspace with operational navigation', () => {
  const view = { state: 'ready', snapshot };
  const auth = { username: 'admin', role: 'admin', csrf_token: 'a'.repeat(64) };
  const html = renderToStaticMarkup(React.createElement(OperatorSOCView, {
    view, auth, onRefresh() {}, onClear() {}, onPage() {}, onCase() {}, onScan() {}, onMutation() {},
  }));
  assert.match(html, /aria-current="page"/);
  assert.match(html, /id="soc-overview-title"/);
  assert.match(html, /Agent packages/);
  assert.doesNotMatch(html, /id="soc-endpoints-title"|id="soc-alerts-title"|id="soc-scans-title"/);
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
  const html = render({ state: 'ready', snapshot: { ...snapshot, alerts: { ...empty, items: [alert] } }, selection: { kind: 'case', state: 'ready', alertID: alert.alert_id, detail: { alert, activity: { ...empty, items: [{ activity_id: '2', actor_id: 'operator-a', action: 'note', note: '<script>alert(1)</script>', occurred_at: session.server_time }] } } } });
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img|<script/);
  assert.match(html, /Read case and activity for alert/);
  assert.match(html, /not a cryptographic audit log/);
});

test('clear-view wording does not claim to revoke the native browser certificate', () => {
  const html = render({ state: 'ready', snapshot });
  assert.match(html, /Clear displayed records/);
  assert.match(html, /does not revoke your login session/);
  assert.doesNotMatch(html, />Logout<|>Sign out</);
});

test('only scanner-role operators receive an acknowledgement control for open alerts', () => {
  const alerts = { ...empty, items: ['open', 'acknowledged', 'resolved'].map((state, index) => ({ alert_id: `11111111-1111-4111-8111-11111111111${index}`, agent_id: 'linux-01', signature_name: 'Synthetic', state, updated_at: session.server_time, assigned_to: '' })) };
  const viewer = render({ state: 'ready', snapshot: { ...snapshot, alerts } });
  assert.doesNotMatch(viewer, /aria-label="Acknowledge alert/);
  assert.match(viewer, /Viewer role: read-only access/);
  const scanner = render({ state: 'ready', snapshot: { ...snapshot, session: { ...session, role: 'scanner' }, alerts } });
  assert.equal((scanner.match(/aria-label="Acknowledge alert/g) ?? []).length, 1);
  assert.match(scanner, /This does not resolve the case or change the endpoint/);
});

test('pending acknowledgement and uncertain outcome disclose no old snapshot and offer no retry action', () => {
  const pending = render({ state: 'loading', operation: 'ack' });
  assert.match(pending, /Verifying the operator and selected record/);
  assert.doesNotMatch(pending, /<table|tenant-a|operator-a/);
  const unknown = render({ state: 'error', error: 'mutation_unknown' });
  assert.match(unknown, /outcome is unknown/);
  assert.match(unknown, /No automatic retry was sent/);
  assert.doesNotMatch(unknown, /<table|>Retry<|>Acknowledge</);
});

test('accepted acknowledgement with failed refresh is explicit without stale records', () => {
  const html = render({ state: 'error', error: 'forbidden', receipt: { kind: 'ack', reference_id: '11111111-1111-4111-8111-111111111111' } });
  assert.match(html, /Alert acknowledgement accepted/);
  assert.match(html, /current records could not be reloaded/);
  assert.doesNotMatch(html, /<table|tenant-a|operator-a/);
});

test('successful acknowledgement is reported as workflow change rather than remediation', () => {
  const html = render({ state: 'ready', snapshot, receipt: { kind: 'ack', reference_id: '11111111-1111-4111-8111-111111111111' } });
  assert.match(html, /Alert acknowledgement accepted/);
  assert.match(html, /Current SOC records and selected details were reloaded/);
  assert.match(html, /not proof of endpoint execution or remediation/);
});

test('clearing a pending operation discloses uncertainty without exposing old records or retrying', () => {
  const html = render({ state: 'disconnected', interrupted: true });
  assert.match(html, /may already have been accepted/);
  assert.match(html, /No automatic retry was sent/);
  assert.doesNotMatch(html, /<table|tenant-a|operator-a|>Retry</);
});

test('scanner case controls follow the current case state and expose labelled bounded forms', () => {
  for (const state of ['open', 'acknowledged', 'resolved']) {
    const alert = { ...caseAlert, state, assigned_to: 'scanner-b' };
    const html = render({ state: 'ready', snapshot: { ...snapshot, session: { ...session, role: 'scanner' } }, selection: { kind: 'case', state: 'ready', alertID: alert.alert_id, detail: { alert, activity: empty } } });
    assert.match(html, /<label for="soc-case-note">Case note<\/label>/);
    assert.match(html, /id="soc-case-note"[^>]*maxLength="2048"/);
    assert.match(html, /aria-describedby="soc-case-note-help soc-case-note-error"/);
    assert.match(html, /role="alert"/);
    if (state === 'open') { assert.match(html, />Acknowledge this case</); assert.doesNotMatch(html, />Resolve case<|>Reopen case</); }
    if (state === 'acknowledged') { assert.match(html, /<label for="soc-case-resolve">Resolution note<\/label>/); assert.match(html, />Resolve case</); assert.doesNotMatch(html, />Acknowledge this case<|>Reopen case</); }
    if (state === 'resolved') { assert.match(html, />Reopen case</); assert.doesNotMatch(html, />Resolve case<|>Assign case<|>Unassign case</); }
    else { assert.match(html, />Assign case</); assert.match(html, />Unassign case</); }
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map(match => match[1]);
    assert.equal(new Set(ids).size, ids.length, 'form controls and descriptions have unique document IDs');
  }
});

test('viewer case and scan details never contain mutation forms or action controls', () => {
  const selected = { ...caseAlert, assigned_to: session.operator_id, state: 'acknowledged' };
  const caseHTML = render({ state: 'ready', snapshot, selection: { kind: 'case', state: 'ready', alertID: selected.alert_id, detail: { alert: selected, activity: empty } } });
  assert.doesNotMatch(caseHTML, /<form|>Add note<|>Assign case<|>Resolve case<|>Reopen case</);
  const scanHTML = render({ state: 'ready', snapshot: { ...snapshot, jobs: { ...empty, items: [scanJob] } }, selection: { kind: 'scan', state: 'ready', jobID: scanJob.job_id, detail: { job: scanJob, result: null } } });
  assert.doesNotMatch(scanHTML, /<form|>Queue path scan<|>Cancel (this )?pending scan</);
  assert.match(scanHTML, /No result has been returned for this job/);
  assert.match(scanHTML, /scan outcome and endpoint condition are unknown/);
});

test('scan schedule offers the actual inventory and path operation without quick/full profiles', () => {
  const html = render({ state: 'ready', snapshot: { ...snapshot, session: { ...session, role: 'scanner' }, endpoints: { ...empty, items: [scanEndpoint, { ...scanEndpoint, agent_id: 'revoked-a', health: 'revoked' }] } } });
  assert.match(html, /<label for="soc-scan-endpoint">Endpoint to scan<\/label>/);
  assert.match(html, /<label for="soc-scan-path">Absolute local path<\/label>/);
  assert.match(html, /<option value="revoked-a" disabled=""/);
  assert.match(html, /id="soc-scan-path"[^>]*maxLength="512"/);
  assert.match(html, /Queue acceptance does not prove/);
  assert.doesNotMatch(html, />Quick scan<|>Full scan<|type="password"|name="token"/);
});

test('only pending scan rows offer cancellation and delivery success does not imply a clean scan', () => {
  const jobs = { ...empty, items: ['pending', 'leased', 'succeeded', 'failed', 'cancelled'].map((state, index) => ({ ...scanJob, job_id: `22222222-2222-4222-8222-22222222222${index}`, state })) };
  const html = render({ state: 'ready', snapshot: { ...snapshot, session: { ...session, role: 'scanner' }, jobs } });
  assert.equal((html.match(/aria-label="Cancel pending scan /g) ?? []).length, 1);
  assert.match(html, /server enforces ownership/);
  assert.match(html, /Successful delivery is not a clean scan/);
  assert.match(html, /No scan results were returned/);
});

test('scan result verdicts retain unknown-state qualifications and escape reported text', () => {
  const result = { ...scanResult, verdict: 'clean_by_signature', detail: '<script>fixture</script>' };
  const html = render({ state: 'ready', snapshot: { ...snapshot, results: { ...empty, items: [result] } }, selection: { kind: 'scan', state: 'ready', jobID: scanJob.job_id, detail: { job: { ...scanJob, state: 'succeeded' }, result } } });
  assert.match(html, /No signature match reported; endpoint safety is unknown/);
  assert.match(html, /&lt;script&gt;fixture&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>|>Protected<|>Healthy</);
  assert.match(html, /not independent host acceptance evidence/);
});

test('mutation refresh errors report the accepted operation reference without old rows', () => {
  const html = render({ state: 'error', error: 'unauthorized', receipt: { kind: 'schedule', reference_id: scanJob.job_id, created: true } });
  assert.match(html, /Path scan queued, but current records could not be reloaded/);
  assert.match(html, new RegExp(scanJob.job_id));
  assert.doesNotMatch(html, /<table|tenant-a|operator-a|<form/);
});
