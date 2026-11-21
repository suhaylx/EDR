import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeLocalCompanionSnapshot, localCompanionPresentation } from '../.test-dist/local-companion.js';

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
