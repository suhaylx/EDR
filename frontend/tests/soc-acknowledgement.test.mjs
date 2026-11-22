import { test } from 'node:test';
import assert from 'node:assert/strict';
import { acknowledgeSOCAlert, SOCReadError, SOCAcknowledgedRefreshError } from '../.test-dist/soc-api.js';

const session = { tenant_id: 'tenant-a', operator_id: 'scanner-a', role: 'scanner', server_time: '2026-11-21T18:00:00Z' };
const alert = { alert_id: '11111111-1111-4111-8111-111111111111', job_id: '22222222-2222-4222-8222-222222222222', agent_id: 'linux-a', category: 'malware_signature', severity: 'high', signature_name: 'Synthetic-Test', state: 'open', created_at: session.server_time, updated_at: session.server_time, acknowledged_by: '', resolved_by: '', assigned_to: '', resolution_note: '' };
const page = items => ({ items, limit: 25, offset: 0 });
const endpointStats = { total: 0, windows: 0, linux: 0, online: 0, degraded: 0, stale: 0, unseen: 0, revoked: 0 };
const scanStats = { total: 0, pending: 0, leased: 0, succeeded: 0, failed: 0, cancelled: 0, malicious: 0 };
const snapshot = (patch = {}) => ({ session, endpoints: page([]), endpointStats, alerts: page([alert]), alertStats: { open: 1, acknowledged: 0, resolved: 0 }, mine: page([]), jobs: page([]), results: page([]), scanStats, ...patch });
const json = value => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
const failure = code => error => error instanceof SOCReadError && error.code === code && !error.message.includes('PRIVATE-FIXTURE');

function backend(override = () => undefined) {
  const calls = [];
  let accepted = false;
  let sessions = 0;
  const fetcher = async (path, init) => {
    calls.push({ path, init });
    if (path === '/soc/v1/session') sessions++;
    const replacement = await override(path, init, { calls, accepted, sessions });
    if (replacement !== undefined) return replacement;
    if (path === '/soc/v1/session') return json(session);
    if (path.endsWith('/' + alert.alert_id)) return json({ ...alert, state: accepted ? 'acknowledged' : 'open', acknowledged_by: accepted ? session.operator_id : '' });
    if (path.endsWith('/ack')) { accepted = true; return new Response(null, { status: 204 }); }
    if (path.endsWith('/endpoint-stats')) return json(endpointStats);
    if (path.endsWith('/alert-stats')) return json({ open: accepted ? 0 : 1, acknowledged: accepted ? 1 : 0, resolved: 0 });
    if (path.includes('/endpoints?') || path.includes('/my-alerts?')) return json(page([]));
    if (path.includes('/alerts?')) return json(page([{ ...alert, state: accepted ? 'acknowledged' : 'open', acknowledged_by: accepted ? session.operator_id : '' }]));
    if (path.includes('/scan-jobs?') || path.includes('/scan-results?') || path.includes('/activity?')) return json(page([]));
    if (path.endsWith('/scan-stats')) return json(scanStats);
    throw new Error('Unexpected test request');
  };
  return { calls, fetcher, options: { protocol: 'https:', fetcher } };
}

test('scanner acknowledgement rechecks identity and current alert, sends one bodyless POST and reloads all sources', async () => {
  const server = backend();
  const result = await acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options);
  assert.equal(result.alerts.items[0].state, 'acknowledged');
  assert.equal(result.alerts.items[0].acknowledged_by, session.operator_id);
  assert.equal(result.alertStats.open, 0);
  assert.equal(result.alertStats.acknowledged, 1);
  assert.deepEqual(server.calls.slice(0, 3).map(x => [x.init.method, x.path]), [
    ['GET', '/soc/v1/session'],
    ['GET', `/soc/v1/tenants/tenant-a/alerts/${alert.alert_id}`],
    ['POST', `/soc/v1/tenants/tenant-a/alerts/${alert.alert_id}/ack`],
  ]);
  const writes = server.calls.filter(x => x.init.method === 'POST');
  assert.equal(writes.length, 1);
  const init = writes[0].init;
  assert.equal(init.body, undefined);
  assert.equal(init.credentials, 'same-origin');
  assert.equal(init.mode, 'same-origin');
  assert.equal(init.cache, 'no-store');
  assert.equal(init.redirect, 'error');
  assert.deepEqual(init.headers, { Accept: 'application/json' });
  assert.equal(server.calls.length, 17);
  assert.equal(snapshot().alerts.items[0].state, 'open', 'no optimistic mutation of the input snapshot');
});

test('viewer role cannot dispatch any acknowledgement request', async () => {
  const server = backend();
  await assert.rejects(acknowledgeSOCAlert(snapshot({ session: { ...session, role: 'viewer' } }), alert.alert_id, server.options), failure('forbidden'));
  assert.equal(server.calls.length, 0);
});

test('locally non-open alerts and stale selections are denied before any request', async () => {
  for (const state of ['acknowledged', 'resolved']) {
    const server = backend();
    await assert.rejects(acknowledgeSOCAlert(snapshot({ alerts: page([{ ...alert, state }]) }), alert.alert_id, server.options), failure('conflict'));
    assert.equal(server.calls.length, 0);
  }
  const server = backend();
  await assert.rejects(acknowledgeSOCAlert(snapshot({ alerts: page([]) }), alert.alert_id, server.options), failure('stale_selection'));
  assert.equal(server.calls.length, 0);
});

test('malformed IDs, insecure origins and already-aborted requests cannot send a POST', async () => {
  const server = backend();
  await assert.rejects(acknowledgeSOCAlert(snapshot(), '../another-alert', server.options), failure('invalid_response'));
  await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, { ...server.options, protocol: 'http:' }), failure('insecure_origin'));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, { ...server.options, signal: controller.signal }), failure('cancelled'));
  assert.equal(server.calls.length, 0);
});

test('a changed role, operator or tenant in the authoritative session stops the mutation', async () => {
  for (const patch of [{ role: 'viewer' }, { operator_id: 'scanner-b' }, { tenant_id: 'tenant-b' }]) {
    const server = backend(path => path === '/soc/v1/session' ? json({ ...session, ...patch }) : undefined);
    await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options), failure('identity_changed'));
    assert.equal(server.calls.length, 1);
  }
});

test('server-reported stale alert state or mismatched identity never reaches the write', async () => {
  for (const [patch, expected] of [[{ state: 'acknowledged' }, 'conflict'], [{ state: 'resolved' }, 'conflict'], [{ agent_id: 'different-agent' }, 'invalid_response'], [{ alert_id: '33333333-3333-4333-8333-333333333333' }, 'invalid_response']]) {
    const server = backend(path => path.endsWith('/' + alert.alert_id) ? json({ ...alert, ...patch }) : undefined);
    await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options), failure(expected));
    assert.equal(server.calls.filter(x => x.init.method === 'POST').length, 0);
  }
});

test('POST authorization denials and conflict are specific, suppress response text and never retry', async () => {
  for (const [status, expected] of [[401, 'unauthorized'], [403, 'forbidden'], [409, 'conflict']]) {
    const server = backend((path, init) => init.method === 'POST' ? new Response('PRIVATE-FIXTURE', { status }) : undefined);
    await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options), failure(expected));
    assert.equal(server.calls.filter(x => x.init.method === 'POST').length, 1);
    assert.equal(server.calls.length, 3, 'no stale snapshot published after rejection');
  }
});

test('transport failure and unexpected response after POST report uncertain outcome without automatic retry', async () => {
  for (const failPost of [() => { throw new Error('PRIVATE-FIXTURE network detail'); }, () => new Response('PRIVATE-FIXTURE', { status: 500 }), () => new Response('PRIVATE-FIXTURE', { status: 503 }), () => json({ fake_success: true })]) {
    const server = backend((path, init) => init.method === 'POST' ? failPost() : undefined);
    await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options), failure('mutation_unknown'));
    assert.equal(server.calls.filter(x => x.init.method === 'POST').length, 1);
    assert.equal(server.calls.length, 3);
  }
});

test('timeout after dispatch cannot claim the write failed or issue a second POST', async () => {
  const server = backend((path, init) => init.method === 'POST' ? new Promise(() => {}) : undefined);
  await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, { ...server.options, timeoutMs: 10 }), failure('mutation_unknown'));
  assert.equal(server.calls.filter(x => x.init.method === 'POST').length, 1);
});

test('abort after POST reports uncertain outcome; ignored abort and late success cannot trigger a reload', async () => {
  let started;
  let finish;
  const dispatched = new Promise(resolve => { started = resolve; });
  const server = backend((path, init) => {
    if (init.method !== 'POST') return undefined;
    started();
    return new Promise(resolve => { finish = resolve; });
  });
  const controller = new AbortController();
  const pending = acknowledgeSOCAlert(snapshot(), alert.alert_id, { ...server.options, signal: controller.signal });
  await dispatched;
  controller.abort();
  await assert.rejects(pending, failure('mutation_unknown'));
  finish(new Response(null, { status: 204 }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(server.calls.length, 3);
});

test('accepted write followed by failed reload is distinguished from uncertain write and clears snapshot', async () => {
  const server = backend((path, init, state) => path === '/soc/v1/session' && state.accepted ? new Response('PRIVATE-FIXTURE', { status: 403 }) : undefined);
  await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options), error => error instanceof SOCAcknowledgedRefreshError && error.code === 'forbidden');
  assert.equal(server.calls.filter(x => x.init.method === 'POST').length, 1);
});

test('a changed authenticated identity after acceptance prevents publishing the refreshed snapshot', async () => {
  const server = backend((path, init, state) => path === '/soc/v1/session' && state.accepted ? json({ ...session, operator_id: 'scanner-b' }) : undefined);
  await assert.rejects(acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options), error => error instanceof SOCAcknowledgedRefreshError && error.code === 'identity_changed');
  assert.equal(server.calls.filter(x => x.init.method === 'POST').length, 1);
});

test('success reload uses current server state without inventing optimistic counters or acknowledgement', async () => {
  const server = backend(path => path.includes('/alerts?') ? json(page([alert])) : undefined);
  const result = await acknowledgeSOCAlert(snapshot(), alert.alert_id, server.options);
  assert.equal(result.alerts.items[0].state, 'open');
  assert.equal(result.alerts.items[0].acknowledged_by, '');
});
