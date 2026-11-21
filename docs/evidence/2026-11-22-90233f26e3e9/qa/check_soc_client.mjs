import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import https from 'node:https';
import {randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';

// Run the actual compiled frontend API client over a real local mTLS transport.
// This adapter does not emulate browser certificate selection or accessibility.
const fixture = JSON.parse(await readFile(process.env.QA_SOC_FIXTURE, 'utf8'));
const api = await import(pathToFileURL(process.env.QA_SOC_COMPILED + '/soc-api.js').href);
const agent = new https.Agent({
  ca: await readFile(fixture.ca), cert: await readFile(fixture.cert),
  key: await readFile(fixture.key), minVersion: 'TLSv1.3', rejectUnauthorized: true,
});
let posts = 0;
const fetcher = (path, options = {}) => new Promise((resolve, reject) => {
  const target = new URL(path, fixture.origin);
  assert.equal(target.origin, fixture.origin);
  if (options.method === 'POST') posts++;
  const request = https.request(target, {agent, method: options.method || 'GET', headers: options.headers}, response => {
    const chunks = [];
    response.on('data', chunk => chunks.push(chunk));
    response.on('error', reject);
    response.on('end', () => {
      options.signal?.removeEventListener('abort', abort);
      const status = response.statusCode;
      const body = [204, 205, 304].includes(status) ? null : Buffer.concat(chunks);
      resolve(new Response(body, {status, headers: response.headers}));
    });
  });
  const abort = () => request.destroy(new Error('Functional request cancelled'));
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener('abort', abort, {once: true});
  request.on('error', error => {
    options.signal?.removeEventListener('abort', abort);
    reject(error);
  });
  if (options.body) request.write(options.body);
  request.end();
});
const options = {protocol: 'https:', fetcher, timeoutMs: 15000};
const checks = [];
const pass = message => { checks.push(message); console.log('PASS: ' + message); };

try {
  let snapshot = await api.loadSOCSnapshot(options);
  assert.equal(snapshot.session.tenant_id, 'qa-functional');
  assert.equal(snapshot.session.operator_id, 'analyst');
  assert.equal(snapshot.session.role, 'scanner');
  assert.equal(snapshot.endpoints.items[0].agent_id, 'linux.01');
  assert.equal(snapshot.alerts.items.length, 1);
  assert.equal(snapshot.results.items[0].verdict, 'malicious');
  pass('Actual Go query responses decode into the expanded SOC snapshot');
  const alertID = snapshot.alerts.items[0].alert_id;
  const initial = await api.loadSOCCase(snapshot.session, alertID, options);
  assert.equal(initial.alert.state, 'open');
  const mutations = [
    [{kind: 'ack', alert_id: alertID}, 'acknowledged', undefined],
    [{kind: 'note', alert_id: alertID, note: 'Independent functional fixture note'}, 'acknowledged', undefined],
    [{kind: 'assign', alert_id: alertID, operator_id: 'analyst'}, 'acknowledged', 'analyst'],
    [{kind: 'unassign', alert_id: alertID}, 'acknowledged', ''],
    [{kind: 'resolve', alert_id: alertID, note: 'Synthetic fixture resolution; no endpoint remediation claim'}, 'resolved', undefined],
    [{kind: 'reopen', alert_id: alertID}, 'open', undefined],
  ];
  for (const [command, state, assignee] of mutations) {
    const before = posts;
    const result = await api.runSOCMutation(snapshot, command, options);
    assert.equal(posts, before + 1);
    assert.equal(result.receipt.kind, command.kind);
    assert.equal(result.caseDetail.alert.state, state);
    if (assignee !== undefined) assert.equal(result.caseDetail.alert.assigned_to, assignee);
    snapshot = result.snapshot;
    pass('Compiled SOC client ' + command.kind + ' operation persists and reloads its actual case response');
  }
  const requestID = randomUUID();
  const scheduled = await api.runSOCMutation(snapshot, {
    kind: 'schedule', agent_id: 'linux.01', request_id: requestID, scan_root: fixture.sample,
  }, options);
  assert.equal(scheduled.receipt.created, true);
  assert.equal(scheduled.scanDetail.job.state, 'pending');
  assert.equal(scheduled.scanDetail.result, null);
  pass('Compiled SOC client schedules a path scan and decodes pending/no-result detail');
  const cancelled = await api.runSOCMutation(scheduled.snapshot, {
    kind: 'cancel', job_id: scheduled.receipt.reference_id,
  }, options);
  assert.equal(cancelled.scanDetail.job.state, 'cancelled');
  assert.equal(cancelled.scanDetail.result, null);
  assert.equal(cancelled.snapshot.scanStats.cancelled, 1);
  assert.equal(posts, 8);
  pass('Compiled SOC client cancels its pending scan and reloads actual job/stat responses');
  const finalCase = await api.loadSOCCase(cancelled.snapshot.session, alertID, options);
  assert.equal(finalCase.alert.state, 'open');
  for (const action of ['created', 'acknowledged', 'note', 'assigned', 'unassigned', 'resolved', 'reopened']) {
    assert(finalCase.activity.items.some(row => row.action === action), action);
  }
  pass('Actual PostgreSQL activity contains the complete exercised case workflow');
  console.log(JSON.stringify({result: 'PASS', checks: checks.length, mutation_posts: posts,
    scope: 'compiled frontend API client + actual Go/PostgreSQL, temporary local mTLS fixture',
    browser_acceptance: 'not-executed', infosec_approval: 'not-claimed'}));
} finally {
  agent.destroy();
}
