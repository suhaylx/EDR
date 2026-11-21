import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeLocalCompanionSnapshot, localCompanionPresentation, localCompanionRows } from '../.test-dist/local-companion.js';

const valid = () => ({
  schema_version: 1, source: 'local_agent_ipc_v1', platform: 'windows',
  observed_at: '2026-11-21T17:00:00Z',
  core_state: 'reported_running', clamav_state: 'reported_available',
  telemetry_state: 'unknown', policy_revision: null, scan_state: 'queued',
});
test('accepts explicit reported states without treating them as attested', () => {
  const payload = decodeLocalCompanionSnapshot(valid());
  assert.equal(payload.platform, 'windows');
  assert.equal(payload.telemetry_state, 'unknown');
  const result = localCompanionPresentation(payload, Date.parse(payload.observed_at) + 1_000);
  assert.equal(result.status, 'reported');
  assert.match(result.explanation, /do not attest/);
});
test('missing connection always reports unavailable coverage', () => {
  assert.equal(localCompanionPresentation(null, Date.now()).status, 'unavailable');
  assert.match(localCompanionPresentation(null, Date.now()).explanation, /unknown/);
});
test('future-dated and stale snapshots fail closed', () => {
  const payload = decodeLocalCompanionSnapshot(valid());
  const t = Date.parse(payload.observed_at);
  assert.equal(localCompanionPresentation(payload, t - 1).status, 'stale');
  assert.equal(localCompanionPresentation(payload, t + 60_001).status, 'stale');
  assert.equal(localCompanionPresentation(payload, Number.NaN).status, 'stale');
});
test('invalid schema, origin label and unexpected component states are rejected', () => {
  for (const patch of [
    {schema_version: 2}, {source: 'remote_web'}, {platform: 'macos'},
    {core_state: 'protected'}, {clamav_state: 'clean'}, {scan_state: 'safe'},
    {policy_revision: -1}, {policy_revision: 1.5},
    {observed_at: 'not-a-date'}, {observed_at: '2026-11-21T17:00:00+05:00'},
  ]) {
    assert.throws(() => decodeLocalCompanionSnapshot({...valid(), ...patch}));
  }
});
test('null or array payload never renders a positive state', () => {
  assert.throws(() => decodeLocalCompanionSnapshot(null));
  assert.throws(() => decodeLocalCompanionSnapshot([]));
});

test('disconnected and stale views erase all previous component reports', () => {
  const snapshot = decodeLocalCompanionSnapshot(valid());
  const fresh = Date.parse(snapshot.observed_at);
  const freshRows = localCompanionRows(snapshot, fresh + 1000);
  assert.equal(freshRows.find(row => row.key === 'core')?.value, 'Running (reported)');
  for (const rows of [localCompanionRows(null, fresh), localCompanionRows(snapshot, fresh + 60001),
    localCompanionRows(snapshot, fresh - 1000)]) {
    assert.equal(rows.length, 6);
    assert.ok(rows.every(row => row.value === 'Unknown'));
    assert.ok(rows.every(row => row.detail.includes('No current authenticated')));
  }
});
test('platform-specific telemetry never labels Linux state as Sysmon', () => {
  const linux = decodeLocalCompanionSnapshot({...valid(), platform:'linux', telemetry_state:'reported_available'});
  const rows = localCompanionRows(linux, Date.parse(linux.observed_at) + 500);
  assert.equal(rows.find(row=>row.key==='telemetry')?.label,'Linux telemetry collector');
  assert.match(rows.find(row=>row.key==='telemetry')?.value || '', /reported/);
  assert.ok(!rows.some(row => /Sysmon/.test(row.label)));
});
test('scan lifecycle never claims a verified verdict, even after completion', () => {
  for (const state of ['queued', 'leased', 'completed', 'failed', 'expired', 'unknown']) {
    const snapshot = decodeLocalCompanionSnapshot({...valid(), scan_state:state});
    const scanRow = localCompanionRows(snapshot, Date.parse(snapshot.observed_at) + 500)
      .find(row=>row.key==='scan');
    assert.ok(scanRow);
    assert.match(scanRow.detail, /not a verified malware verdict/);
    assert.doesNotMatch(scanRow.value, /safe|clean|protected/i);
    if (state === 'completed') assert.match(scanRow.value, /verdict unavailable/);
  }
});
test('unknown policy revision never renders as applied or enforced', () => {
  for (const revision of [null, 0]) {
    const snapshot = decodeLocalCompanionSnapshot({...valid(), policy_revision:revision});
    const policy = localCompanionRows(snapshot, Date.parse(snapshot.observed_at)).find(row=>row.key==='policy');
    assert.match(policy?.value || '', /unknown or zero/);
    assert.match(policy?.detail || '', /not an authenticated/);
  }
});
