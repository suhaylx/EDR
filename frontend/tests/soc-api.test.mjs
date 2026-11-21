import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeSOCSession, decodeSOCAlert, decodeSOCActivities, loadSOCSnapshot, loadSOCActivity, SOCReadError, socFailureMessages } from '../.test-dist/soc-api.js';
import { socTimestamp } from '../.test-dist/soc-contract.js';
import { selectAppMode } from '../.test-dist/app-mode.js';

export const session = { tenant_id: 'tenant-a', operator_id: 'analyst-1', role: 'viewer', server_time: '2026-11-21T17:40:00Z' };
export const alert = { alert_id: '11111111-1111-4111-8111-111111111111', job_id: '22222222-2222-4222-8222-222222222222', agent_id: 'win-01', category: 'malware_signature', severity: 'high', signature_name: 'Synthetic-Test-Signature', state: 'open', created_at: session.server_time, updated_at: session.server_time, assigned_to: session.operator_id };
export const endpoint = { agent_id: 'win-01', platform: 'windows', health: 'unseen', scan_ready: false, heartbeat_count: 0 };
const page = items => ({ items, limit: 25, offset: 0 });
const stats = { total: 1, windows: 1, linux: 0, online: 0, degraded: 0, stale: 0, unseen: 1, revoked: 0 };
const json = value => new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
function responseFor(path) {
  if (path === '/soc/v1/session') return json(session);
  if (path.endsWith('/endpoint-stats')) return json(stats);
  if (path.includes('/endpoints?')) return json(page([endpoint]));
  if (path.includes('/alerts?') || path.includes('/my-alerts?')) return json(page([alert]));
  if (path.endsWith('/alert-stats')) return json({ open: 1, acknowledged: 0, resolved: 0 });
  if (path.includes('/activity?')) return json(page([]));
  throw new Error('Unexpected test URL');
}
const options = fetcher => ({ protocol: 'https:', fetcher });
const failure = code => error => error instanceof SOCReadError && error.code === code && !error.message.includes('private');

test('only explicit loopback lab route selects legacy token UI; all other defaults require SOC', () => {
  assert.equal(selectAppMode('http:', '127.0.0.1', '/'), 'soc');
  assert.equal(selectAppMode('https:', 'soc.example', '/'), 'soc');
  assert.equal(selectAppMode('https:', 'soc.example', '/soc/'), 'soc');
  assert.equal(selectAppMode('http:', '127.0.0.1', '/lab/'), 'lab');
  assert.equal(selectAppMode('https:', 'soc.example', '/lab/'), 'unavailable');
  assert.equal(selectAppMode('https:', 'soc.example', '/other'), 'unavailable');
});

test('session projects only bounded server-authenticated identity and rejects path/control/role confusion', () => {
  assert.deepEqual(decodeSOCSession({ ...session, private_key: 'private' }), session);
  for (const tenant_id of ['../x', 'x%2fy', '.', '..', 'a/b', 'a\u202e']) assert.throws(() => decodeSOCSession({ ...session, tenant_id }));
  assert.throws(() => decodeSOCSession({ ...session, role: 'administrator' }));
  assert.throws(() => decodeSOCSession({ ...session, server_time: '2026-11-21' }));
});

test('timestamp timezone is mandatory; invalid calendar dates cannot normalize to evidence', () => {
  assert.equal(socTimestamp('2026-11-21T20:40:00+03:00'), '2026-11-21T20:40:00+03:00');
  for (const value of ['2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z', '2026-11-21T24:01:00Z', '2026-11-21T17:40:00']) assert.throws(() => socTimestamp(value));
});

test('SOC transport uses same-origin certificate credentials with no token and no storage/cross-origin redirect', async () => {
  const calls = [];
  const snapshot = await loadSOCSnapshot(options(async (path, init) => { calls.push({ path, init }); return responseFor(path); }));
  assert.equal(snapshot.session.operator_id, session.operator_id);
  assert.equal(snapshot.endpoints.items[0].health, 'unseen');
  assert.equal(calls.length, 7);
  for (const { path, init } of calls) {
    assert.match(path, /^\/soc\/v1\/(session|tenants\/tenant-a\/)/);
    assert.equal(init.method, 'GET');
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.mode, 'same-origin');
    assert.equal(init.cache, 'no-store');
    assert.equal(init.redirect, 'error');
    assert.deepEqual(init.headers, { Accept: 'application/json' });
    assert.equal(init.body, undefined);
  }
});

test('HTTP origin fails before any request, including loopback', async () => {
  let calls = 0;
  await assert.rejects(loadSOCSnapshot({ protocol: 'http:', fetcher: async () => { calls++; throw new Error('unexpected'); } }), failure('insecure_origin'));
  assert.equal(calls, 0);
});

test('authentication and service denial never parse server errors or return partial records', async () => {
  for (const [status, code] of [[401, 'unauthorized'], [403, 'forbidden'], [503, 'unavailable'], [500, 'http_error']]) {
    let errorBodyParsed = false;
    const fetcher = async path => path.includes('/alerts?') ? {
      status, body: null, json() { errorBodyParsed = true; throw new Error('private'); },
    } : responseFor(path);
    await assert.rejects(loadSOCSnapshot(options(fetcher)), failure(code));
    assert.equal(errorBodyParsed, false);
    assert.doesNotMatch(socFailureMessages[code], /private/);
  }
});

test('bad schema and unbounded response bodies reject the whole snapshot', async () => {
  const cases = [
    () => json({ items: null, limit: 25, offset: 0 }),
    () => new Response('<html>private</html>', { headers: { 'content-type': 'text/html' } }),
    () => new Response(JSON.stringify(page([])), { headers: { 'content-type': 'application/json', 'content-length': '600000' } }),
    () => json({ private: 'x'.repeat(524289) }),
  ];
  for (const malformed of cases) {
    await assert.rejects(loadSOCSnapshot(options(async path => path.includes('/endpoints?') ? malformed() : responseFor(path))), failure('invalid_response'));
  }
});

test('a changed operator between reads clears the candidate snapshot', async () => {
  let sessions = 0;
  await assert.rejects(loadSOCSnapshot(options(async path => path === '/soc/v1/session' && ++sessions > 1
    ? json({ ...session, operator_id: 'another-operator' }) : responseFor(path))), failure('identity_changed'));
});

test('my-alerts cannot accept another operator or resolved assignment', async () => {
  for (const patch of [{ assigned_to: 'another-operator' }, { state: 'resolved' }]) {
    await assert.rejects(loadSOCSnapshot(options(async path => path.includes('/my-alerts?') ? json(page([{ ...alert, ...patch }])) : responseFor(path))), failure('invalid_response'));
  }
});

test('requested page offsets are validated and response offsets cannot silently substitute', async () => {
  let calls = 0;
  await assert.rejects(loadSOCSnapshot(options(async path => { calls++; return responseFor(path); }), { endpoints: 1, alerts: 0, mine: 0 }), failure('invalid_response'));
  assert.equal(calls, 0);
  await assert.rejects(loadSOCSnapshot(options(async path => path.includes('/endpoints?') ? json({ ...page([]), offset: 25 }) : responseFor(path))), failure('invalid_response'));
});

test('one failed peer aborts outstanding requests', async () => {
  const signals = [];
  const fetcher = async (path, init) => {
    if (path.includes('/endpoints?')) return new Response('private error', { status: 403 });
    if (path.endsWith('endpoint-stats')) { signals.push(init.signal); return new Promise(() => {}); }
    return responseFor(path);
  };
  await assert.rejects(loadSOCSnapshot(options(fetcher)), failure('forbidden'));
  assert.equal(signals[0].aborted, true);
});

test('abort settles promptly even when a transport ignores its signal', async () => {
  const controller = new AbortController();
  const pending = loadSOCSnapshot({ ...options(async () => new Promise(() => {})), signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, failure('cancelled'));
});

test('deadline settles a stuck request and late transport data cannot become a snapshot', async () => {
  await assert.rejects(loadSOCSnapshot({ ...options(async () => new Promise(() => {})), timeoutMs: 10 }), failure('timeout'));
});

test('activity authorization loss is an error and invalid IDs never reach fetch', async () => {
  await assert.rejects(loadSOCActivity(session, alert.alert_id, options(async path => path.includes('/activity?') ? new Response('private', { status: 401 }) : responseFor(path))), failure('unauthorized'));
  let calls = 0;
  await assert.rejects(loadSOCActivity(session, '../private', options(async path => { calls++; return responseFor(path); })), failure('invalid_response'));
  assert.equal(calls, 0);
});

test('alert and case payloads strip extras, bound text and reject unknown status or duplicate activity', () => {
  assert.equal('lease_id' in decodeSOCAlert({ ...alert, lease_id: 'private' }), false);
  for (const patch of [{ state: 'safe' }, { signature_name: 'x'.repeat(257) }, { signature_name: 'left\u202eright' }, { updated_at: '2026-11-20T12:00:00Z' }]) assert.throws(() => decodeSOCAlert({ ...alert, ...patch }));
  const activity = { activity_id: '33333333-3333-4333-8333-333333333333', actor_id: 'system', action: 'created', occurred_at: session.server_time };
  assert.throws(() => decodeSOCActivities(page([activity, activity])));
  assert.throws(() => decodeSOCActivities(page([{ ...activity, action: 'endpoint_protected' }])));
});
