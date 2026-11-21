import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSOCMutation, loadSOCCase, loadSOCScanDetail, loadSOCSnapshot, SOCReadError, SOCMutationRefreshError, firstSOCPages } from '../.test-dist/soc-api.js';
import { validateSOCScanPath, socBoundedInput, newSOCScanRequestID, decodeSOCScanJob, decodeSOCScanJobs, decodeSOCScanResult, decodeSOCScanStats, socVerdictLabel } from '../.test-dist/soc-scans.js';
import { session, endpoint, alert, job, result, activity, requestID, page, snapshot, json, workflowBackend } from './soc-workflow-fixture.mjs';

const failure = code => error => error instanceof SOCReadError && error.code === code && !error.message.includes('PRIVATE-FIXTURE');
const commandFor = kind => kind === 'schedule' ? { kind, agent_id: endpoint.agent_id, request_id: requestID, scan_root: job.scan_root }
  : kind === 'cancel' ? { kind, job_id: job.job_id }
  : kind === 'resolve' || kind === 'note' ? { kind, alert_id: alert.alert_id, note: 'Analyst synthetic note' }
  : kind === 'assign' ? { kind, alert_id: alert.alert_id, operator_id: 'scanner-b' }
  : { kind, alert_id: alert.alert_id };
const writes = server => server.calls.filter(call => call.init.method === 'POST');

test('path validation accepts only normalized local Windows/Linux paths and enforces UTF-8 limits', () => {
  for (const path of ['/var/data/file', '/tmp/two words', '/tmp/é']) assert.equal(validateSOCScanPath('linux', path), path);
  for (const path of ['C:\\Data\\file.txt', 'd:\\two words\\scan', 'C:\\CONSOLE.txt']) assert.equal(validateSOCScanPath('windows', path), path);
  for (const path of ['/', 'relative', '/a/../b', '/a/./b', '/a//b', '/a/', '//network/path', '/tmp/\nfile', '/tmp/\u202efile', '/a'.repeat(257)]) assert.throws(() => validateSOCScanPath('linux', path));
  for (const path of ['C:\\', '\\\\server\\share', 'C:/Data/file', 'C:\\a\\..\\b', 'C:\\a\\', 'C:\\CON', 'C:\\NUL.txt', 'C:\\COM1.txt', 'C:\\LPT²', 'C:\\name.', 'C:\\name ', 'C:\\x:y', 'C:\\file*']) assert.throws(() => validateSOCScanPath('windows', path));
  assert.equal(validateSOCScanPath('linux', '/' + 'é'.repeat(255)).length, 256);
  assert.throws(() => validateSOCScanPath('linux', '/' + 'é'.repeat(256)));
  assert.throws(() => validateSOCScanPath('macos', '/tmp/file'));
});

test('bounded notes reject control text and excess UTF-8 bytes instead of silently truncating', () => {
  assert.equal(socBoundedInput('é'.repeat(512), 1024), 'é'.repeat(512));
  for (const value of ['', 'é'.repeat(513), 'a\nb', 'a\tb', 'a\u202eb', 'a\ufeffb']) assert.throws(() => socBoundedInput(value, 1024));
});

test('scan request IDs use cryptographic UUIDv4 and refuse a missing generator', () => {
  assert.match(newSOCScanRequestID(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true });
    assert.throws(() => newSOCScanRequestID(), /secure random request key is unavailable/);
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});

test('scan DTOs project only bounded display fields and reject contradictory or malformed evidence', () => {
  assert.equal('lease_token' in decodeSOCScanJob({ ...job, lease_token: 'PRIVATE-FIXTURE' }), false);
  for (const patch of [{ state: 'protected' }, { attempt_count: -1 }, { updated_at: '2026-01-01T00:00:00Z' }, { scan_root: 'a'.repeat(4097) }]) assert.throws(() => decodeSOCScanJob({ ...job, ...patch }));
  assert.throws(() => decodeSOCScanJobs(page([job, job])));
  for (const patch of [{ engine: 'unknown' }, { verdict: 'safe' }, { verdict: 'malicious', threat_name: '' }, { verdict: 'clean_by_signature', threat_name: 'match' }, { detail: 'é'.repeat(513) }]) assert.throws(() => decodeSOCScanResult({ ...result, ...patch }));
  assert.equal(decodeSOCScanResult({ ...result, verdict: 'malicious', threat_name: 'Synthetic' }).verdict, 'malicious');
  assert.throws(() => decodeSOCScanStats({ total: 2, pending: 1, leased: 0, succeeded: 0, failed: 0, cancelled: 0, malicious: 0 }));
  assert.match(socVerdictLabel('clean_by_signature'), /endpoint safety is unknown/);
  assert.match(socVerdictLabel('error'), /coverage is unknown/);
});

test('all write operations are denied to viewer sessions before any fetch', async () => {
  for (const kind of ['ack', 'resolve', 'reopen', 'note', 'assign', 'unassign', 'schedule', 'cancel']) {
    const server = workflowBackend();
    await assert.rejects(runSOCMutation(snapshot({ session: { ...session, role: 'viewer' } }), commandFor(kind), server.options), failure('forbidden'));
    assert.equal(server.calls.length, 0, kind);
  }
});

test('untyped callers cannot introduce an unsupported operation or route', async () => {
  for (const kind of ['delete', '../scan-jobs', '', 'ACK']) {
    const server = workflowBackend();
    await assert.rejects(runSOCMutation(snapshot(), { kind, alert_id: alert.alert_id }, server.options), failure('invalid_request'));
    assert.equal(server.calls.length, 0);
  }
});

test('case transitions, note writes and explicit assignment reload server state and selected activity', async () => {
  for (const kind of ['ack', 'resolve', 'reopen', 'note', 'assign', 'unassign']) {
    const selected = { ...alert, state: kind === 'resolve' ? 'acknowledged' : kind === 'reopen' ? 'resolved' : 'open', assigned_to: kind === 'unassign' ? 'scanner-b' : '' };
    const server = workflowBackend({ initialAlert: selected });
    const outcome = await runSOCMutation(snapshot({ alerts: page([selected]) }), commandFor(kind), server.options);
    assert.equal(writes(server).length, 1, kind);
    assert.equal(outcome.receipt.kind, kind);
    assert.equal(outcome.receipt.reference_id, kind === 'note' ? activity.activity_id : alert.alert_id);
    assert.equal(outcome.caseDetail.alert.alert_id, alert.alert_id);
    assert.equal(server.calls.length, 17, kind + ' reloads 10 snapshot reads and four case reads after preflight/write');
    const call = writes(server)[0];
    assert.equal(call.init.credentials, 'same-origin');
    assert.equal(call.init.redirect, 'error');
    assert.equal(call.init.cache, 'no-store');
    if (kind === 'ack' || kind === 'reopen') { assert.equal(call.init.body, undefined); assert.deepEqual(call.init.headers, { Accept: 'application/json' }); }
    if (kind === 'resolve' || kind === 'note') { assert.deepEqual(JSON.parse(call.init.body), { note: 'Analyst synthetic note' }); assert.equal(call.init.headers['Content-Type'], 'application/json'); }
    if (kind === 'assign' || kind === 'unassign') assert.deepEqual(JSON.parse(call.init.body), { operator_id: kind === 'unassign' ? '' : 'scanner-b' });
    if (kind === 'resolve') assert.equal(outcome.caseDetail.alert.state, 'resolved');
    if (kind === 'reopen') assert.equal(outcome.caseDetail.alert.state, 'open');
    if (kind === 'note') assert.equal(outcome.caseDetail.activity.items[0].note, 'Analyst synthetic note');
    if (kind === 'assign') assert.equal(outcome.caseDetail.alert.assigned_to, 'scanner-b');
    if (kind === 'unassign') assert.equal(outcome.caseDetail.alert.assigned_to, '');
  }
});

test('invalid local transitions, empty assignments and excessive/whitespace notes cannot dispatch', async () => {
  const cases = [
    [commandFor('resolve'), alert, 'conflict'], [commandFor('reopen'), alert, 'conflict'],
    [commandFor('assign'), { ...alert, state: 'resolved' }, 'conflict'],
    [commandFor('assign'), { ...alert, assigned_to: 'scanner-b' }, 'conflict'],
    [commandFor('unassign'), alert, 'conflict'],
    [{ ...commandFor('assign'), operator_id: '' }, alert, 'invalid_request'],
    [{ ...commandFor('assign'), operator_id: '../operator' }, alert, 'invalid_request'],
    [{ ...commandFor('note'), note: '   ' }, alert, 'invalid_request'],
    [{ ...commandFor('note'), note: 'é'.repeat(1025) }, alert, 'invalid_request'],
    [{ ...commandFor('resolve'), note: 'é'.repeat(513) }, { ...alert, state: 'acknowledged' }, 'invalid_request'],
  ];
  for (const [command, selected, code] of cases) {
    const server = workflowBackend();
    await assert.rejects(runSOCMutation(snapshot({ alerts: page([selected]) }), command, server.options), failure(code));
    assert.equal(server.calls.length, 0);
  }
});

test('notes remain permitted on resolved cases; resolved cases remain absent from my active list', async () => {
  const selected = { ...alert, state: 'resolved', assigned_to: session.operator_id };
  const server = workflowBackend({ initialAlert: selected });
  const outcome = await runSOCMutation(snapshot({ alerts: page([selected]) }), commandFor('note'), server.options);
  assert.equal(outcome.caseDetail.alert.state, 'resolved');
  assert.equal(outcome.snapshot.mine.items.length, 0);
});

test('fresh assignment, revision or state changes stop a case write instead of using a stale selection', async () => {
  for (const patch of [{ assigned_to: 'scanner-b' }, { updated_at: '2026-11-21T18:00:01Z' }, { state: 'acknowledged' }]) {
    const server = workflowBackend({ initialAlert: { ...alert, ...patch } });
    await assert.rejects(runSOCMutation(snapshot(), commandFor('note'), server.options), failure('conflict'));
    assert.equal(writes(server).length, 0);
  }
});

test('freshly loaded visible case detail can be acted on without substituting an unrelated row', async () => {
  const selected = { ...alert, state: 'acknowledged' };
  const server = workflowBackend({ initialAlert: selected });
  const outcome = await runSOCMutation(snapshot({ alerts: page([]) }), commandFor('resolve'), server.options, firstSOCPages, { alert: selected });
  assert.equal(outcome.caseDetail.alert.state, 'resolved');
  const other = workflowBackend();
  await assert.rejects(runSOCMutation(snapshot({ alerts: page([]) }), commandFor('note'), other.options, firstSOCPages, { alert: { ...alert, alert_id: job.job_id } }), failure('stale_selection'));
  assert.equal(other.calls.length, 0);
});

test('path scan scheduling uses the current endpoint, a bounded path and one idempotent JSON request', async () => {
  const server = workflowBackend();
  const outcome = await runSOCMutation(snapshot(), commandFor('schedule'), server.options);
  assert.equal(outcome.receipt.kind, 'schedule');
  assert.equal(outcome.receipt.created, true);
  assert.equal(outcome.receipt.reference_id, job.job_id);
  assert.equal(outcome.scanDetail.result, null);
  assert.deepEqual(server.calls.slice(0, 3).map(call => [call.init.method, call.path]), [
    ['GET', '/soc/v1/session'], ['GET', '/soc/v1/tenants/tenant-a/endpoints/linux-a'], ['POST', '/soc/v1/tenants/tenant-a/scan-jobs'],
  ]);
  assert.deepEqual(JSON.parse(writes(server)[0].init.body), { agent_id: endpoint.agent_id, request_id: requestID, scan_root: job.scan_root });
  assert.equal(writes(server).length, 1);
  assert.equal(server.calls.length, 17);
  assert.equal(outcome.scanDetail.job.state, 'pending');
  assert.equal(outcome.snapshot.endpoints.items[0].scan_ready, false, 'queueing must not turn unknown readiness green');
});

test('valid idempotent scheduling response is distinguished from newly created work', async () => {
  const server = workflowBackend({ override: (path, init) => init.method === 'POST' ? json({ job_id: job.job_id, created: false }, 200) : undefined });
  const outcome = await runSOCMutation(snapshot(), commandFor('schedule'), server.options);
  assert.equal(outcome.receipt.created, false);
  assert.equal(writes(server).length, 1);
});

test('schedule rejects malformed keys, invalid platform paths and stale/revoked enrollment before a POST', async () => {
  for (const command of [{ ...commandFor('schedule'), request_id: 'weak-counter' }, { ...commandFor('schedule'), request_id: '44444444-4444-1444-8444-444444444444' }, { ...commandFor('schedule'), scan_root: '/' }]) {
    const server = workflowBackend();
    await assert.rejects(runSOCMutation(snapshot(), command, server.options), failure('invalid_request'));
    assert.equal(server.calls.length, 0);
  }
  for (const [patch, code] of [[{ health: 'revoked' }, 'forbidden'], [{ platform: 'windows' }, 'invalid_response'], [{ agent_id: 'another-agent' }, 'invalid_response']]) {
    const server = workflowBackend({ override: path => path.endsWith('/endpoints/linux-a') ? json({ ...endpoint, ...patch }) : undefined });
    await assert.rejects(runSOCMutation(snapshot(), commandFor('schedule'), server.options), failure(code));
    assert.equal(writes(server).length, 0);
  }
  const server = workflowBackend();
  await assert.rejects(runSOCMutation(snapshot({ endpoints: page([]) }), commandFor('schedule'), server.options), failure('stale_selection'));
  assert.equal(server.calls.length, 0);
});

test('pending scan cancellation is bodyless and reloads state without inventing a result', async () => {
  const server = workflowBackend();
  const outcome = await runSOCMutation(snapshot(), commandFor('cancel'), server.options);
  assert.equal(outcome.scanDetail.job.state, 'cancelled');
  assert.equal(outcome.scanDetail.result, null);
  assert.equal(outcome.snapshot.scanStats.cancelled, 1);
  assert.equal(writes(server)[0].init.body, undefined);
  assert.equal(writes(server)[0].path, '/soc/v1/tenants/tenant-a/scan-jobs/' + job.job_id + '/cancel');
});

test('local terminal/leased scans, fresh leases and server ownership conflicts prevent cancellation', async () => {
  for (const state of ['leased', 'succeeded', 'failed', 'cancelled']) {
    const server = workflowBackend();
    await assert.rejects(runSOCMutation(snapshot({ jobs: page([{ ...job, state }]) }), commandFor('cancel'), server.options), failure('conflict'));
    assert.equal(server.calls.length, 0);
  }
  const leased = workflowBackend({ initialJob: { ...job, state: 'leased' } });
  await assert.rejects(runSOCMutation(snapshot(), commandFor('cancel'), leased.options), failure('conflict'));
  assert.equal(writes(leased).length, 0);
  const otherOwner = workflowBackend({ override: (path, init) => init.method === 'POST' ? new Response('PRIVATE-FIXTURE owner', { status: 409 }) : undefined });
  await assert.rejects(runSOCMutation(snapshot(), commandFor('cancel'), otherOwner.options), failure('conflict'));
  assert.equal(writes(otherOwner).length, 1);
  assert.equal(otherOwner.calls.length, 3);
});

test('a scan result 404 is explicit absence while authorization failure or mismatched evidence rejects detail', async () => {
  const empty = workflowBackend();
  assert.equal((await loadSOCScanDetail(session, job.job_id, empty.options)).result, null);
  const present = workflowBackend({ reportedResult: result });
  assert.equal((await loadSOCScanDetail(session, job.job_id, present.options)).result.verdict, 'unscanned');
  for (const [response, code] of [[() => new Response('PRIVATE-FIXTURE', { status: 403 }), 'forbidden'], [() => json({ ...result, job_id: alert.alert_id }), 'invalid_response'], [() => json({ ...result, agent_id: 'another-agent' }), 'invalid_response']]) {
    const server = workflowBackend({ override: path => path.endsWith('/scan-results/' + job.job_id) ? response() : undefined });
    await assert.rejects(loadSOCScanDetail(session, job.job_id, server.options), failure(code));
  }
});

test('all snapshot pages and scan summary are required; malformed scan evidence cannot leave partial records', async () => {
  const server = workflowBackend({ override: path => path.endsWith('/scan-stats') ? json({ total: 1, pending: 0, leased: 0, succeeded: 0, failed: 0, cancelled: 0, malicious: 0 }) : undefined });
  await assert.rejects(loadSOCSnapshot(server.options), failure('invalid_response'));
  const offsets = { endpoints: 25, alerts: 50, mine: 75, jobs: 100, results: 125 };
  const good = workflowBackend();
  const response = await loadSOCSnapshot(good.options, offsets);
  for (const section of ['endpoints', 'alerts', 'mine', 'jobs', 'results']) assert.equal(response[section].offset, offsets[section]);
  assert.equal(good.calls.length, 10);
});

test('case detail rejects identity drift, mismatched alert IDs and activity authorization loss', async () => {
  for (const [override, code] of [
    [(path, init, state) => path === '/soc/v1/session' && state.sessions > 1 ? json({ ...session, operator_id: 'scanner-b' }) : undefined, 'identity_changed'],
    [path => path.endsWith('/alerts/' + alert.alert_id) ? json({ ...alert, alert_id: job.job_id }) : undefined, 'invalid_response'],
    [path => path.includes('/activity?') ? new Response('PRIVATE-FIXTURE', { status: 401 }) : undefined, 'unauthorized'],
  ]) {
    const server = workflowBackend({ override });
    await assert.rejects(loadSOCCase(session, alert.alert_id, server.options), failure(code));
  }
});

test('authorization changes before every supported write are caught by the authoritative session read', async () => {
  for (const kind of ['ack', 'resolve', 'reopen', 'note', 'assign', 'unassign', 'schedule', 'cancel']) {
    const selected = { ...alert, state: kind === 'resolve' ? 'acknowledged' : kind === 'reopen' ? 'resolved' : 'open', assigned_to: kind === 'unassign' ? 'scanner-b' : '' };
    const server = workflowBackend({ override: path => path === '/soc/v1/session' ? json({ ...session, role: 'viewer' }) : undefined });
    await assert.rejects(runSOCMutation(snapshot({ alerts: page([selected]) }), commandFor(kind), server.options), failure('identity_changed'));
    assert.equal(server.calls.length, 1, kind);
  }
});

test('malformed successful write bodies remain unknown and never cause automatic note/scan retries', async () => {
  for (const [kind, reply] of [
    ['note', () => json({ activity_id: 'bad' }, 201)],
    ['note', () => json({ activity_id: activity.activity_id }, 200)],
    ['schedule', () => json({ job_id: job.job_id, created: false }, 201)],
    ['schedule', () => json({ job_id: '../bad', created: true }, 201)],
    ['cancel', () => new Response('PRIVATE-FIXTURE', { status: 503 })],
  ]) {
    const server = workflowBackend({ override: (path, init) => init.method === 'POST' ? reply() : undefined });
    await assert.rejects(runSOCMutation(snapshot(), commandFor(kind), server.options), failure('mutation_unknown'));
    assert.equal(writes(server).length, 1);
    assert.equal(server.calls.length, 3);
  }
});

test('accepted operations retain a bounded receipt when snapshot or selected detail cannot be refreshed', async () => {
  for (const kind of ['note', 'schedule', 'cancel']) {
    const server = workflowBackend({ override: (path, init, state) => state.posts > 0 && path === '/soc/v1/session' ? new Response('PRIVATE-FIXTURE', { status: 403 }) : undefined });
    await assert.rejects(runSOCMutation(snapshot(), commandFor(kind), server.options), error => error instanceof SOCMutationRefreshError && error.code === 'forbidden' && error.receipt.kind === kind);
    assert.equal(writes(server).length, 1);
  }
  const detailFailure = workflowBackend({ override: (path, init, state) => state.posts > 0 && path.includes('/activity?') ? new Response('PRIVATE-FIXTURE', { status: 401 }) : undefined });
  await assert.rejects(runSOCMutation(snapshot(), commandFor('note'), detailFailure.options), error => error instanceof SOCMutationRefreshError && error.code === 'unauthorized' && error.receipt.reference_id === activity.activity_id);
});

test('an abort while refreshing a preflight target prevents any POST even if transport returns late', async () => {
  let started; let finish;
  const targetRequested = new Promise(resolve => { started = resolve; });
  const controller = new AbortController();
  const server = workflowBackend({ override: path => {
    if (!path.endsWith('/endpoints/linux-a')) return undefined;
    started(); return new Promise(resolve => { finish = resolve; });
  } });
  const pending = runSOCMutation(snapshot(), commandFor('schedule'), { ...server.options, signal: controller.signal });
  await targetRequested; controller.abort();
  await assert.rejects(pending, failure('cancelled'));
  finish(json(endpoint)); await new Promise(resolve => setImmediate(resolve));
  assert.equal(writes(server).length, 0);
});

test('scan dispatch interruption remains unknown and a late accepted response cannot trigger reads or another POST', async () => {
  let started; let finish;
  const dispatched = new Promise(resolve => { started = resolve; });
  const controller = new AbortController();
  const server = workflowBackend({ override: (path, init) => {
    if (init.method !== 'POST') return undefined;
    started(); return new Promise(resolve => { finish = resolve; });
  } });
  const pending = runSOCMutation(snapshot(), commandFor('schedule'), { ...server.options, signal: controller.signal });
  await dispatched; controller.abort();
  await assert.rejects(pending, failure('mutation_unknown'));
  finish(json({ job_id: job.job_id, created: true }, 201)); await new Promise(resolve => setImmediate(resolve));
  assert.equal(writes(server).length, 1);
  assert.equal(server.calls.length, 3);
});
