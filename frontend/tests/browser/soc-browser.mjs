/** Browser contract tests against ephemeral TLS/HTTP fixtures, NOT real-host acceptance. */
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createServer as createHTTPServer } from 'node:http';
import { createServer as createHTTPSServer } from 'node:https';
import { tmpdir } from 'node:os';
import { resolve, join, extname } from 'node:path';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

const resultsDir = resolve('test-results');
await mkdir(resultsDir, { recursive: true });
const fixtureDir = await mkdtemp(join(tmpdir(), 'turansec-browser-fixture-'));
const originalMask = process.umask(0o077);
const report = {
  scope: 'Built React browser contract and accessibility checks using synthetic local API fixtures with ephemeral mTLS. This is not Go/PostgreSQL integration, real Windows/Linux host acceptance or production approval.',
  started_at: new Date().toISOString(), cases: [], accessibility: [], browser: '', status: 'running',
};
let tlsServer, labServer, browser;
let mode = 'ready';
let labDenied = false;
let delayedFinished = Promise.resolve();
let delayedReceived = () => undefined;
const observedSOC = [];
const observedLab = [];
const now = '2026-11-21T18:00:00Z';
const session = { tenant_id: 'fixture-tenant', operator_id: 'fixture-viewer', role: 'viewer', server_time: now };
const alertID = '11111111-1111-4111-8111-111111111111';
const alert = { alert_id: alertID, job_id: '22222222-2222-4222-8222-222222222222', agent_id: 'fixture-linux', category: 'malware_signature', severity: 'high', signature_name: 'Synthetic-browser-test-signature', state: 'open', created_at: now, updated_at: now, assigned_to: session.operator_id };
const endpoints = [
  { agent_id: 'fixture-linux', platform: 'linux', health: 'online', scan_ready: true, last_seen: now, heartbeat_count: 3, agent_version: 'fixture-only', clamav_version: 'fixture-only', signature_version: 'fixture-only' },
  { agent_id: 'fixture-windows', platform: 'windows', health: 'unseen', scan_ready: false, heartbeat_count: 0 },
];
const page = (items, url) => ({ items, limit: 25, offset: Number(url.searchParams.get('offset') ?? 0) });
function sendJSON(response, value, code = 200) { response.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(value)); }
function socReply(url) {
  const empty = mode === 'empty';
  if (url.pathname === '/soc/v1/session') return session;
  if (url.pathname.endsWith('/endpoint-stats')) return empty
    ? { total: 0, windows: 0, linux: 0, online: 0, degraded: 0, stale: 0, unseen: 0, revoked: 0 }
    : { total: 2, windows: 1, linux: 1, online: 1, degraded: 0, stale: 0, unseen: 1, revoked: 0 };
  if (url.pathname.endsWith('/endpoints')) return page(empty ? [] : endpoints, url);
  if (url.pathname.endsWith('/alert-stats')) return { open: empty ? 0 : 1, acknowledged: 0, resolved: 0 };
  if (url.pathname.endsWith('/alerts') || url.pathname.endsWith('/my-alerts')) return page(empty ? [] : [alert], url);
  if (url.pathname.endsWith('/activity')) return page([{ activity_id: '33333333-3333-4333-8333-333333333333', actor_id: 'fixture-viewer', action: 'note', note: '<script>fixture-untrusted-text</script>', occurred_at: now }], url);
  return undefined;
}
const labOverview = days => ({
  generated_at: now, window_days: days, data_source: 'development_in_memory_retained_telemetry', heartbeat_ttl_seconds: 300,
  agents: 0, online: 0, offline: 0, unknown: 0, events: 0, alerts: 0, high_risk_alerts: 0, policy_errors: 0,
  scans: { queued: 0, leased: 0, completed: 0, failed: 0 }, severity: [], alert_trend: [], top_rules: [], policy_coverage: [],
  most_active: [], inactive_machines: [], endpoints: [], unavailable: ['Synthetic fixture: host protection not verified'],
});

async function handler(request, response, secure) {
  const url = new URL(request.url, 'https://fixture.invalid');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  if (url.pathname.startsWith('/soc/v1/')) {
    observedSOC.push({ path: url.pathname, method: request.method, authorizedTLS: Boolean(request.socket.authorized), bearerPresent: Boolean(request.headers.authorization) });
    if (!secure || !request.socket.authorized) return sendJSON(response, { error: 'denied' }, 401);
    if (mode === 'deny' || mode === 'forbidden' || mode === 'unavailable') return sendJSON(response, { error: 'DO-NOT-RENDER-FIXTURE-ERROR' }, mode === 'deny' ? 401 : mode === 'forbidden' ? 403 : 503);
    if (mode === 'delay' && url.pathname === '/soc/v1/session') {
      delayedFinished = new Promise(resolveDelay => setTimeout(() => { sendJSON(response, session); resolveDelay(); }, 250));
      delayedReceived();
      return;
    }
    const data = socReply(url);
    return sendJSON(response, data ?? { error: 'not found' }, data === undefined ? 404 : 200);
  }
  if (url.pathname.startsWith('/api/')) {
    observedLab.push({ path: url.pathname, method: request.method });
    if (secure || labDenied || request.headers.authorization !== 'Bearer synthetic-browser-lab-token') return sendJSON(response, { error: 'DO-NOT-RENDER-FIXTURE-ERROR' }, 401);
    const data = url.pathname === '/api/overview' ? labOverview(Number(url.searchParams.get('days'))) : [];
    return sendJSON(response, data);
  }
  const relative = ['/', '/soc', '/soc/', '/lab', '/lab/'].includes(url.pathname) ? 'index.html' : url.pathname.slice(1);
  if (!/^(index\.html|assets\/[A-Za-z0-9_.-]+)$/.test(relative)) { response.writeHead(404); response.end(); return; }
  try {
    const file = await readFile(join(resolve('dist'), relative));
    const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' }[extname(relative)];
    response.writeHead(200, { 'content-type': mime ?? 'application/octet-stream' }); response.end(file);
  } catch { response.writeHead(404); response.end(); }
}
async function check(name, action) {
  const start = Date.now();
  try { await action(); report.cases.push({ name, status: 'pass', milliseconds: Date.now() - start }); console.log('PASS ' + name); }
  catch (error) { report.cases.push({ name, status: 'fail', milliseconds: Date.now() - start, error: String(error) }); throw error; }
}
async function waitText(page, text) { await page.getByText(text, { exact: false }).first().waitFor({ state: 'visible' }); }
async function accessibility(page, name) {
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  report.accessibility.push({ name, violations: result.violations, incomplete: result.incomplete.map(x => ({ id: x.id, impact: x.impact, description: x.description })) });
  assert.deepEqual(result.violations.map(x => ({ id: x.id, impact: x.impact, nodes: x.nodes.map(n => n.target) })), [], name + ' accessibility violations');
}
try {
  const openssl = (...args) => execFileSync('openssl', args, { cwd: fixtureDir, stdio: 'ignore' });
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=TuranSec synthetic browser test CA');
  for (const kind of ['server', 'client']) {
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', kind + '.key', '-out', kind + '.csr', '-subj', '/CN=TuranSec synthetic browser ' + kind);
    await writeFile(join(fixtureDir, kind + '.ext'), kind === 'server' ? 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' : 'extendedKeyUsage=clientAuth\n');
    openssl('x509', '-req', '-in', kind + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-sha256', '-extfile', kind + '.ext', '-out', kind + '.crt');
  }
  tlsServer = createHTTPSServer({ key: await readFile(join(fixtureDir, 'server.key')), cert: await readFile(join(fixtureDir, 'server.crt')), ca: await readFile(join(fixtureDir, 'ca.crt')), requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, (q, r) => { void handler(q, r, true); });
  labServer = createHTTPServer((q, r) => { void handler(q, r, false); });
  await new Promise(resolveListen => tlsServer.listen(0, '127.0.0.1', resolveListen));
  await new Promise(resolveListen => labServer.listen(0, '127.0.0.1', resolveListen));
  const origin = 'https://127.0.0.1:' + tlsServer.address().port;
  const labOrigin = 'http://127.0.0.1:' + labServer.address().port;
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined, headless: true });
  report.browser = browser.version();
  await check('TLS fixture refuses a browser without an operator client certificate', async () => {
    const deniedContext = await browser.newContext({ ignoreHTTPSErrors: true });
    const deniedPage = await deniedContext.newPage();
    await assert.rejects(deniedPage.goto(origin));
    await deniedContext.close();
  });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 }, clientCertificates: [{ origin, certPath: join(fixtureDir, 'client.crt'), keyPath: join(fixtureDir, 'client.key') }] });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await check('keyboard reaches skip link and Connect; browser certificate reads the SOC fixture', async () => {
    await page.goto(origin);
    await page.keyboard.press('Tab');
    assert.equal(await page.locator(':focus').textContent(), 'Skip to SOC records');
    await page.keyboard.press('Tab');
    assert.equal(await page.locator(':focus').textContent(), 'Connect to SOC');
    await page.keyboard.press('Enter');
    await waitText(page, 'Loaded records for tenant');
    assert.equal(await page.getByRole('heading', { name: 'Operator SOC', exact: true }).count(), 1);
    assert.equal(await page.locator('input[type=password]').count(), 0);
    assert.match(await page.locator('body').innerText(), /fixture-tenant.*fixture-viewer/s);
    assert.ok(observedSOC.length >= 7);
    assert.ok(observedSOC.every(x => x.method === 'GET' && x.authorizedTLS && !x.bearerPresent));
    await page.screenshot({ path: join(resultsDir, 'operator-ready.png'), fullPage: true });
    await accessibility(page, 'Operator ready desktop');
  });
  await check('unknown endpoint and readonly case activity stay honest and render untrusted text safely', async () => {
    await waitText(page, 'No server-received heartbeat recorded; current protection unknown');
    await page.getByRole('button', { name: 'Read activity for alert ' + alertID }).first().click();
    await waitText(page, '<script>fixture-untrusted-text</script>');
    assert.equal(await page.locator('script').count(), 1);
    await accessibility(page, 'Operator case activity desktop');
    await page.screenshot({ path: join(resultsDir, 'operator-activity.png'), fullPage: true });
  });
  await check('authorization failure during case read clears all previously loaded records', async () => {
    mode = 'forbidden';
    await page.getByRole('button', { name: 'Read activity for alert ' + alertID }).first().click();
    await waitText(page, 'This operator is not authorized');
    assert.equal(await page.locator('table').count(), 0);
    assert.doesNotMatch(await page.locator('body').innerText(), /fixture-tenant|fixture-viewer|DO-NOT-RENDER/);
    await accessibility(page, 'Operator forbidden');
    await page.screenshot({ path: join(resultsDir, 'operator-auth-denied.png'), fullPage: true });
  });
  await check('empty inventory stays unknown on a narrow viewport with accessible controls', async () => {
    mode = 'empty';
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole('button', { name: 'Connect to SOC', exact: true }).click();
    await waitText(page, 'Loaded records for tenant');
    await waitText(page, 'No protection state can be inferred');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await accessibility(page, 'Operator empty mobile');
    await page.screenshot({ path: join(resultsDir, 'operator-empty-mobile.png'), fullPage: true });
  });
  await check('401 and unavailable service errors are bounded and clear the current records', async () => {
    for (const [nextMode, expected] of [['deny', 'Operator authorization was denied'], ['unavailable', 'The authenticated SOC service is unavailable']]) {
      mode = nextMode;
      await page.getByRole('button', { name: /Refresh SOC records|Connect to SOC/ }).click();
      await waitText(page, expected);
      assert.equal(await page.locator('table').count(), 0);
      assert.doesNotMatch(await page.locator('body').innerText(), /fixture-tenant|DO-NOT-RENDER/);
    }
  });
  await check('clearing an in-flight request cannot resurrect a stale snapshot', async () => {
    mode = 'delay';
    const received = new Promise(resolveReceived => { delayedReceived = resolveReceived; });
    await page.getByRole('button', { name: 'Connect to SOC', exact: true }).click();
    await received;
    await page.getByRole('button', { name: 'Clear displayed records' }).click();
    await delayedFinished;
    await waitText(page, 'No records loaded');
    assert.equal(await page.locator('table').count(), 0);
    assert.doesNotMatch(await page.locator('body').innerText(), /fixture-tenant|fixture-viewer/);
  });
  await check('HTTP default route refuses SOC fetch without falling back to development tokens', async () => {
    await page.goto(labOrigin);
    const before = observedSOC.length;
    await page.getByRole('button', { name: 'Connect to SOC', exact: true }).click();
    await waitText(page, 'No SOC request was sent over this origin');
    assert.equal(observedSOC.length, before);
    assert.equal(await page.locator('input[type=password]').count(), 0);
  });
  await check('original local companion loads all six read-only fixtures, preserves tabs and clears on auth loss', async () => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(labOrigin + '/lab/');
    await page.getByLabel('Development API token').fill('synthetic-browser-lab-token');
    await page.getByRole('button', { name: 'Connect / refresh', exact: true }).click();
    await waitText(page, 'Showing retained lab evidence');
    assert.equal(new Set(observedLab.map(x => x.path)).size, 6);
    assert.ok(observedLab.every(x => x.method === 'GET'));
    await accessibility(page, 'Original local SOC overview');
    for (const name of ['Policy evidence', 'Endpoints', 'Security alerts', 'Sysmon & telemetry', 'Scan history', 'Evidence snapshot']) {
      await page.getByRole('button', { name, exact: true }).click();
      assert.equal(await page.getByRole('button', { name, exact: true }).getAttribute('aria-current'), 'page');
    }
    await page.screenshot({ path: join(resultsDir, 'local-companion.png'), fullPage: true });
    labDenied = true;
    await page.getByRole('button', { name: 'Connect / refresh', exact: true }).click();
    await waitText(page, 'Connection failed:');
    assert.equal(await page.locator('table').count(), 0);
    assert.doesNotMatch(await page.locator('body').innerText(), /DO-NOT-RENDER/);
    await page.getByRole('button', { name: 'Disconnect / clear', exact: true }).click();
    assert.equal(await page.getByLabel('Development API token').inputValue(), '');
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  });
  assert.deepEqual(errors, [], 'Browser runtime errors');
  report.status = 'pass';
} catch (error) {
  report.status = 'fail';
  report.error = String(error);
  console.error(error);
  process.exitCode = 1;
} finally {
  await browser?.close();
  for (const server of [tlsServer, labServer]) if (server) {
    server.closeAllConnections();
    await new Promise(resolveClose => server.close(resolveClose));
  }
  await rm(fixtureDir, { recursive: true, force: true });
  process.umask(originalMask);
  report.finished_at = new Date().toISOString();
  await writeFile(join(resultsDir, 'soc-browser-report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(`Browser contract checks: ${report.cases.filter(x => x.status === 'pass').length}/${report.cases.length}; status=${report.status}; browser=${report.browser}`);
}
