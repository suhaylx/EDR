import { test } from 'node:test';
import assert from 'node:assert/strict';
import {decodeLabOverview, heartbeatLabel, fetchLabOverview} from '../.test-dist/overview.js';

const base = (changes = {}) => ({
  generated_at: '2026-11-21T15:00:00Z',
  window_days: 7,
  data_source: 'development_in_memory_retained_telemetry',
  heartbeat_ttl_seconds: 300,
  agents: 3, online: 1, offline: 1, unknown: 1,
  events: 8, alerts: 2, high_risk_alerts: 1, policy_errors: 0,
  scans: {queued: 1, leased: 0, completed: 2, failed: 1},
  severity: [{severity: 'high', count: 1}, {severity: 'low', count: 1}],
  alert_trend: [{day: '2026-11-21', count: 2}],
  top_rules: [{rule_id: 'observed-rule', severity: 'high', count: 2}],
  policy_coverage: [],
  most_active: [{id: 'win-1', platform: 'windows', status: 'online', last_seen: '2026-11-21T14:59:00Z', events: 8, alerts: 2, inactive_seconds: 0}],
  inactive_machines: [{id: 'win-2', platform: 'windows', status: 'offline', last_seen: '2026-11-20T14:59:00Z', events: 0, alerts: 0, inactive_seconds: 86460}, {id: 'linux-1', platform: 'linux', status: 'unknown', last_seen: '0001-01-01T00:00:00Z', events: 0, alerts: 0, inactive_seconds: 0}],
  endpoints: [
    {id:'win-1',platform:'windows',group:'lab',status:'online',last_seen:'2026-11-21T14:59:00Z',events:8,alerts:2,inactive_seconds:0,reported_health:'healthy'},
    {id:'win-2',platform:'windows',group:'lab',status:'offline',last_seen:'2026-11-20T14:59:00Z',events:0,alerts:0,inactive_seconds:86460,reported_health:'healthy',applied_policy_id:'p1',applied_revision:2,last_policy_error:'pending'},
    {id:'linux-1',platform:'linux',group:'test',status:'unknown',last_seen:'0001-01-01T00:00:00Z',events:0,alerts:0,inactive_seconds:0,reported_health:''},
  ],
  unavailable: ['signature_database_freshness', 'tenant_isolation'],
  ...changes
});
test('accepts explicit retained lab telemetry, preserving missing coverage', () => {
  const o = decodeLabOverview(base(), 7);
  assert.equal(o.events, 8);
  assert.equal(o.unavailable[0], 'signature_database_freshness');
  assert.equal(o.scans.queued, 1);
  assert.equal(o.most_active[0].events, 8);
});
test('rejects incompatible source and wrong UTC period', () => {
  assert.throws(() => decodeLabOverview(base({data_source: 'production_verified'}), 7), /Unexpected overview data source/);
  assert.throws(() => decodeLabOverview(base({window_days: 1}), 7), /window does not match/);
});
test('rejects fabricated, non-integer, or inconsistent fleet counters', () => {
  assert.throws(() => decodeLabOverview(base({online: 3}), 7), /do not reconcile/);
  assert.throws(() => decodeLabOverview(base({alerts: -1}), 7), /Invalid overview count/);
  assert.throws(() => decodeLabOverview(base({agents: 2.2}), 7), /Invalid overview count/);
  assert.throws(() => decodeLabOverview(base({scans: {queued: 1}}), 7), /Invalid overview count/);
});
test('fails closed on missing lists and impossible status fields', () => {
  assert.throws(() => decodeLabOverview(base({unavailable: null}), 7), /Invalid overview list/);
  assert.throws(() => decodeLabOverview(base({alert_trend: [{day: 'not-a-date', count: 1}]}), 7), /UTC trend day/);
  assert.throws(() => decodeLabOverview(base({most_active: [{id: 'x', status: 'protected'}]}), 7), /heartbeat status/);
});
test('heartbeat semantics never invent offline duration for unknown endpoints', () => {
  const o = decodeLabOverview(base(), 7);
  assert.match(heartbeatLabel(o.inactive_machines[1]), /Unknown/);
  assert.match(heartbeatLabel(o.inactive_machines[0]), /days inactive/);
  assert.match(heartbeatLabel(o.most_active[0]), /server-received heartbeat/);
});
test('uses read-only 7-day Go API and rejects wrong response shape', async () => {
  let called;
  const fetcher = async (url, options) => {called = {url, options}; return {ok: true, json: async () => base()};};
  const result = await fetchLabOverview('t'.repeat(16), 7, undefined, fetcher);
  assert.equal(result.online, 1);
  assert.equal(called.url, '/api/overview?days=7');
  assert.equal(called.options.method, 'GET');
  assert.equal(called.options.cache, 'no-store');
  assert.equal(called.options.credentials, 'omit');
  assert.equal(called.options.headers.Authorization, 'Bearer ' + 't'.repeat(16));
  const bad = async () => ({ok: true, json: async () => ({})});
  await assert.rejects(fetchLabOverview('t'.repeat(16), 7, undefined, bad), /Unexpected overview data source/);
});
test('disallows unsupported windows and short tokens before issuing a request', async () => {
  await assert.rejects(fetchLabOverview('short', 7), /16 characters/);
  await assert.rejects(fetchLabOverview('t'.repeat(16), 14), /Unsupported UTC window/);
});

test('full inventory reconciles heartbeat and reports policy errors without claiming verified coverage', () => {
  const o=decodeLabOverview(base(),7);
  assert.equal(o.endpoints.length,3);
  assert.equal(o.endpoints[1].status,'offline');
  assert.equal(o.endpoints[1].reported_health,'healthy');
  assert.equal(o.endpoints[1].last_policy_error,'pending');
  assert.equal(o.endpoints[1].applied_revision,2);
  assert.equal(o.endpoints[2].applied_policy_id,'');
});
test('inventory missing records, duplicates and false status totals fail closed', () => {
  assert.throws(()=>decodeLabOverview(base({endpoints:[]}),7),/inventory does not match/);
  assert.throws(()=>decodeLabOverview(base({endpoints:[base().endpoints[0],base().endpoints[0],base().endpoints[2]]}),7),/duplicate IDs/);
  assert.throws(()=>decodeLabOverview(base({endpoints:base().endpoints.map(x=>({...x,status:'online'}))}),7),/status does not reconcile/);
  assert.throws(()=>decodeLabOverview(base({endpoints:base().endpoints.map((x,i)=>i===0?{...x,applied_revision:-1}:x)}),7),/Invalid overview count/);
});
