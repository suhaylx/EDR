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
  started_at: new Date().toISOString(), cases: [], accessibility: [], layout: [], browser: '', status: 'running',
};
let tlsServer, labServer, browser;
let mode = 'ready';
let operatorRole = 'viewer';
let alertState = 'open';
let labDenied = false;
let delayedFinished = Promise.resolve();
let delayedReceived = () => undefined;
const observedSOC = [];
const observedBrowserSOC = [];
const observedLab = [];
const now = '2026-11-21T18:00:00Z';
const session = { tenant_id: 'fixture-tenant', operator_id: 'fixture-viewer', role: 'viewer', server_time: now };
const alertID = '11111111-1111-4111-8111-111111111111';
const alert = { alert_id: alertID, job_id: '22222222-2222-4222-8222-222222222222', agent_id: 'fixture-linux', category: 'malware_signature', severity: 'high', signature_name: 'Synthetic-browser-test-signature', state: 'open', created_at: now, updated_at: now, assigned_to: session.operator_id };
const caseFields = { assigned_to: session.operator_id, acknowledged_by: '', resolved_by: '', resolution_note: '' };
const caseActivity = [{ activity_id: '33333333-3333-4333-8333-333333333333', actor_id: session.operator_id, action: 'note', note: '<script>fixture-untrusted-text</script>', occurred_at: now }];
let scanJob = null;
const scanJobID = '55555555-5555-4555-8555-555555555555';
const endpoints = [
  { agent_id: 'fixture-linux', platform: 'linux', health: 'online', scan_ready: true, last_seen: now, heartbeat_count: 3, agent_version: 'fixture-only', clamav_version: 'fixture-only', signature_version: 'fixture-only' },
  { agent_id: 'fixture-windows', platform: 'windows', health: 'unseen', scan_ready: false, heartbeat_count: 0 },
];
const page = (items, url) => ({ items, limit: 25, offset: Number(url.searchParams.get('offset') ?? 0) });
function sendJSON(response, value, code = 200) { response.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(value)); }
function socReply(url) {
  const empty = mode === 'empty';
  if (url.pathname === '/soc/v1/session') return { ...session, role: operatorRole };
  if (url.pathname.endsWith('/endpoint-stats')) return empty
    ? { total: 0, windows: 0, linux: 0, online: 0, degraded: 0, stale: 0, unseen: 0, revoked: 0 }
    : { total: 2, windows: 1, linux: 1, online: 1, degraded: 0, stale: 0, unseen: 1, revoked: 0 };
  if (url.pathname.endsWith('/endpoints')) return page(empty ? [] : endpoints, url);
  if (url.pathname.includes('/endpoints/')) return endpoints.find(endpoint => url.pathname.endsWith('/' + endpoint.agent_id));
  if (url.pathname.endsWith('/alert-stats')) return { open: !empty && alertState === 'open' ? 1 : 0, acknowledged: !empty && alertState === 'acknowledged' ? 1 : 0, resolved: !empty && alertState === 'resolved' ? 1 : 0 };
  const currentAlert = { ...alert, ...caseFields, state: alertState };
  if (url.pathname.endsWith('/alerts/' + alertID)) return currentAlert;
  if (url.pathname.endsWith('/alerts')) return page(empty ? [] : [currentAlert], url);
  if (url.pathname.endsWith('/my-alerts')) return page(!empty && currentAlert.assigned_to === session.operator_id && alertState !== 'resolved' ? [currentAlert] : [], url);
  if (url.pathname.endsWith('/activity')) return page(caseActivity, url);
  if (url.pathname.endsWith('/scan-jobs')) return page(empty || !scanJob ? [] : [scanJob], url);
  if (url.pathname.endsWith('/scan-results')) return page([], url);
  if (url.pathname.endsWith('/scan-jobs/' + scanJobID)) return scanJob ?? undefined;
  if (url.pathname.endsWith('/scan-stats')) return { total: !empty && scanJob ? 1 : 0, pending: !empty && scanJob?.state === 'pending' ? 1 : 0, leased: 0, succeeded: 0, failed: 0, cancelled: !empty && scanJob?.state === 'cancelled' ? 1 : 0, malicious: 0 };
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
    const observation = { path: url.pathname, method: request.method, mode,
      authorizedTLS: Boolean(request.socket.authorized), bearerPresent: Boolean(request.headers.authorization),
      sameOrigin: request.headers.origin === 'https://' + request.headers.host, fetchSite: request.headers['sec-fetch-site'],
      responseStatus: null, closedBeforeFinish: null, acknowledgementCommitted: false };
    observedSOC.push(observation);
    response.once('finish', () => { observation.responseStatus = response.statusCode; });
    response.once('close', () => { observation.closedBeforeFinish = !response.writableFinished; });
    if (!secure || !request.socket.authorized) return sendJSON(response, { error: 'denied' }, 401);
    if (mode === 'deny' || mode === 'forbidden' || mode === 'unavailable') return sendJSON(response, { error: 'DO-NOT-RENDER-FIXTURE-ERROR' }, mode === 'deny' ? 401 : mode === 'forbidden' ? 403 : 503);
    if (request.method === 'POST') {
      if (operatorRole !== 'scanner' || request.headers.origin !== 'https://' + request.headers.host || request.headers['sec-fetch-site'] !== 'same-origin') return sendJSON(response, { error: 'denied' }, 403);
      const base = `/soc/v1/tenants/${session.tenant_id}/`;
      let raw = '';
      for await (const chunk of request) { raw += chunk; if (Buffer.byteLength(raw) > 8192) return sendJSON(response, { error: 'bad body' }, 400); }
      let body;
      try { body = raw ? JSON.parse(raw) : undefined; } catch { return sendJSON(response, { error: 'bad body' }, 400); }
      if (url.pathname === base + `alerts/${alertID}/ack`) {
        if (alertState !== 'open') return sendJSON(response, { error: 'state conflict' }, 409);
        alertState = 'acknowledged'; caseFields.acknowledged_by = session.operator_id;
        observation.acknowledgementCommitted = true;
        if (mode === 'ack-drop') {
          // The acknowledgement is committed, but incomplete HTTPS headers end at EOF.
          // Partial headers model a truncated response rather than an empty keep-alive
          // close that the browser may transparently retry. A complete 204 header block
          // is already a full acknowledgement (there is no body), so cannot model loss.
          request.socket.end('HTTP/1.1 204 No Content\r\nX-Fixture-Truncated:');
          return;
        }
      } else if (url.pathname === base + `alerts/${alertID}/notes`) {
        if (!body?.note || Buffer.byteLength(body.note) > 2048) return sendJSON(response, { error: 'bad note' }, 400);
        const activity_id = '44444444-4444-4444-8444-444444444444';
        caseActivity.push({ activity_id, actor_id: session.operator_id, action: 'note', note: body.note, occurred_at: now });
        return sendJSON(response, { activity_id }, 201);
      } else if (url.pathname === base + `alerts/${alertID}/assign`) {
        if (alertState === 'resolved' || typeof body?.operator_id !== 'string') return sendJSON(response, { error: 'state conflict' }, 409);
        caseFields.assigned_to = body.operator_id;
      } else if (url.pathname === base + `alerts/${alertID}/resolve`) {
        if (alertState !== 'acknowledged' || !body?.note) return sendJSON(response, { error: 'state conflict' }, 409);
        alertState = 'resolved'; caseFields.resolved_by = session.operator_id; caseFields.resolution_note = body.note;
      } else if (url.pathname === base + `alerts/${alertID}/reopen`) {
        if (alertState !== 'resolved') return sendJSON(response, { error: 'state conflict' }, 409);
        alertState = 'open'; caseFields.acknowledged_by = ''; caseFields.resolved_by = ''; caseFields.resolution_note = '';
      } else if (url.pathname === base + 'scan-jobs') {
        if (body?.agent_id !== 'fixture-linux' || body?.scan_root !== '/var/data/browser-fixture' || !body?.request_id) return sendJSON(response, { error: 'bad scan' }, 400);
        scanJob = { job_id: scanJobID, agent_id: body.agent_id, scan_root: body.scan_root, state: 'pending', attempt_count: 0, created_at: now, updated_at: now };
        return sendJSON(response, { job_id: scanJobID, created: true }, 201);
      } else if (url.pathname === base + 'scan-jobs/' + scanJobID + '/cancel') {
        if (scanJob?.state !== 'pending') return sendJSON(response, { error: 'state conflict' }, 409);
        scanJob.state = 'cancelled';
      } else return sendJSON(response, { error: 'not found' }, 404);
      response.writeHead(204); response.end(); return;
    }
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
function incompleteCheckEvidence(check) {
  const allowed = ['fgColor', 'bgColor', 'contrastRatio', 'expectedContrastRatio', 'fontSize', 'fontWeight', 'messageKey'];
  const data = Object.fromEntries(allowed.filter(key => check.data && Object.hasOwn(check.data, key))
    .map(key => [key, check.data[key]]));
  return { id: check.id, impact: check.impact, message: check.message, data };
}
async function incompleteNodeEvidence(page, node) {
  let computed = { unavailable: 'Selector requires frame or shadow-root traversal' };
  if (node.target.length === 1 && typeof node.target[0] === 'string') {
    computed = await page.locator(node.target[0]).first().evaluate(element => {
      const describe = item => {
        const style = getComputedStyle(item);
        const rect = item.getBoundingClientRect();
        return { tag: item.tagName.toLowerCase(), id: item.id, className: item.getAttribute('class') ?? '',
          color: style.color, backgroundColor: style.backgroundColor, opacity: style.opacity,
          fontSize: style.fontSize, fontWeight: style.fontWeight, visibility: style.visibility,
          display: style.display, overflowX: style.overflowX, overflowY: style.overflowY,
          x: rect.x, y: rect.y, width: rect.width, height: rect.height };
      };
      const ancestors = [];
      for (let parent = element.parentElement; parent && ancestors.length < 6; parent = parent.parentElement) ancestors.push(describe(parent));
      // Computed presentation only; never collect innerHTML, text or input values.
      return { element: describe(element), ancestors };
    }, undefined, { timeout: 1000 }).catch(() => ({ unavailable: 'Unable to measure selector' }));
  }
  return { target: node.target, impact: node.impact, failureSummary: node.failureSummary,
    any: node.any.map(incompleteCheckEvidence), all: node.all.map(incompleteCheckEvidence),
    none: node.none.map(incompleteCheckEvidence), computed };
}
async function accessibility(page, name) {
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  const incomplete = await Promise.all(result.incomplete.map(async rule => ({ id: rule.id, impact: rule.impact,
    description: rule.description, help: rule.help,
    nodes: await Promise.all(rule.nodes.map(node => incompleteNodeEvidence(page, node))) })));
  report.accessibility.push({ name, status: result.violations.length ? 'violations' : incomplete.length ? 'needs-review' : 'no-violations-or-incomplete',
    violations: result.violations, incomplete });
  assert.deepEqual(result.violations.map(x => ({ id: x.id, impact: x.impact, nodes: x.nodes.map(n => n.target) })), [], name + ' accessibility violations');
}
async function accessibilityUnclipped(page, name, screenshotName) {
  const viewport = page.viewportSize();
  assert.ok(viewport, 'The browser check requires a known viewport');
  const position = await page.evaluate(() => ({ x: window.scrollX, y: window.scrollY,
    tables: [...document.querySelectorAll('.table-scroll')].map(element => ({ left: element.scrollLeft, top: element.scrollTop })) }));
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({ path: join(resultsDir, screenshotName), fullPage: true });
    // Preserve the mobile scan and repeat every enabled rule with unclipped tables.
    await accessibility(page, name);
    const scan = report.accessibility.at(-1);
    assert.equal(scan.incomplete.length, 0, name + ' must have no incomplete checks: ' +
      JSON.stringify(scan.incomplete.map(rule => ({ id: rule.id, targets: rule.nodes.map(node => node.target) }))));
  } finally {
    await page.setViewportSize(viewport);
    await page.evaluate(saved => {
      [...document.querySelectorAll('.table-scroll')].forEach((element, index) => {
        const value = saved.tables[index];
        if (value) { element.scrollLeft = value.left; element.scrollTop = value.top; }
      });
      window.scrollTo(saved.x, saved.y);
    }, position);
  }
}
async function recordViewportLayout(page, name) {
  const layout = await page.evaluate(() => {
    const viewportWidth = window.innerWidth;
    const outsideViewport = [...document.querySelectorAll('body *')].flatMap(element => {
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      if (!rect.width || !rect.height || style.visibility === 'hidden' || (rect.left >= 0 && rect.right <= viewportWidth)) return [];
      // Geometry and source CSS identifiers only: never retain input values or raw text.
      return [{ tag: element.tagName.toLowerCase(), id: element.id, className: element.getAttribute('class') ?? '',
        left: rect.left, right: rect.right, width: rect.width, clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
        display: style.display, minWidth: style.minWidth, flexDirection: style.flexDirection, flexWrap: style.flexWrap,
        whiteSpace: style.whiteSpace, overflowX: style.overflowX, insideTableScroll: Boolean(element.closest('.table-scroll')) }];
    }).slice(0, 30);
    return { viewportWidth, documentClientWidth: document.documentElement.clientWidth,
      documentScrollWidth: document.documentElement.scrollWidth, bodyScrollWidth: document.body.scrollWidth,
      outsideViewport };
  });
  report.layout.push({ name, ...layout });
  return layout;
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
  report.browserErrors = errors;
  page.on('pageerror', error => errors.push(error.message));
  const browserRequests = new WeakMap();
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (!path.startsWith('/soc/v1/')) return;
    const observation = { method: request.method(), path, responseStatus: null, failure: null };
    browserRequests.set(request, observation);
    observedBrowserSOC.push(observation);
  });
  page.on('response', response => {
    const observation = browserRequests.get(response.request());
    if (observation) observation.responseStatus = response.status();
  });
  page.on('requestfailed', request => {
    const observation = browserRequests.get(request);
    if (observation) observation.failure = request.failure()?.errorText ?? 'unknown';
  });
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
    assert.ok(observedSOC.length >= 10);
    assert.ok(observedSOC.every(x => x.method === 'GET' && x.authorizedTLS && !x.bearerPresent));
    await page.screenshot({ path: join(resultsDir, 'operator-ready.png'), fullPage: true });
    await accessibility(page, 'Operator ready desktop');
  });
  await check('primary and secondary hover with keyboard focus meet contrast in both color schemes', async () => {
    for (const colorScheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme });
      const controls = [
        ['secondary case button', page.getByRole('button', { name: 'Read case and activity for alert ' + alertID }).first()],
        ['primary refresh button', page.getByRole('button', { name: 'Refresh SOC records', exact: true })],
      ];
      for (const [label, control] of controls) {
        await control.focus();
        // Return through keyboard navigation, then hover without clicking away focus.
        await page.keyboard.press('Shift+Tab');
        await page.keyboard.press('Tab');
        await control.hover();
        assert.ok(await control.evaluate(element => element.matches(':hover') && element.matches(':focus-visible')), label + ' must be hovered and keyboard-focused');
        await accessibility(page, `Operator ${label} hover and focus ${colorScheme}`);
      }
      await page.screenshot({ path: join(resultsDir, `operator-controls-${colorScheme}.png`), fullPage: true });
    }
    await page.emulateMedia({ colorScheme: 'light' });
  });
  await check('unknown endpoint and readonly case activity stay honest and render untrusted text safely', async () => {
    await waitText(page, 'No server-received heartbeat recorded; current protection unknown');
    await page.getByRole('button', { name: 'Read case and activity for alert ' + alertID }).first().click();
    await waitText(page, '<script>fixture-untrusted-text</script>');
    assert.equal(await page.locator('script').count(), 1);
    await accessibility(page, 'Operator case activity desktop');
    await page.screenshot({ path: join(resultsDir, 'operator-activity.png'), fullPage: true });
  });
  await check('authorization failure during case read clears all previously loaded records', async () => {
    mode = 'forbidden';
    await page.getByRole('button', { name: 'Read case and activity for alert ' + alertID }).first().click();
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
    const layout = await recordViewportLayout(page, 'Operator empty mobile');
    await writeFile(join(resultsDir, 'operator-empty-mobile-layout.json'), JSON.stringify(layout, null, 2) + '\n');
    await page.screenshot({ path: join(resultsDir, 'operator-empty-mobile.png'), fullPage: true });
    assert.ok(layout.documentScrollWidth <= layout.viewportWidth, 'Horizontal page overflow: ' + JSON.stringify(layout));
    await accessibility(page, 'Operator empty mobile');
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
  await check('scanner can acknowledge one open alert, with same-origin POST and full reload', async () => {
    mode = 'ready'; operatorRole = 'scanner'; alertState = 'open';
    await page.getByRole('button', { name: 'Connect to SOC', exact: true }).click();
    await waitText(page, 'Loaded records for tenant');
    await page.getByRole('button', { name: 'Acknowledge alert ' + alertID }).first().click();
    await waitText(page, 'Alert acknowledgement accepted');
    assert.equal(await page.getByRole('button', { name: 'Acknowledge alert ' + alertID }).count(), 0);
    const writes = observedSOC.filter(x => x.method === 'POST');
    assert.equal(writes.length, 1);
    assert.ok(writes.every(x => x.sameOrigin && x.fetchSite === 'same-origin' && x.authorizedTLS && !x.bearerPresent));
    await accessibility(page, 'Operator acknowledged case');
    await page.screenshot({ path: join(resultsDir, 'operator-acknowledged.png'), fullPage: true });
    await accessibilityUnclipped(page, 'Operator acknowledged case desktop unclipped', 'operator-acknowledged-desktop.png');
  });
  await check('scanner case forms submit notes, assignment, resolution and reopening with keyboard-accessible controls', async () => {
    await page.getByLabel('Case note', { exact: true }).fill('Synthetic keyboard case note');
    await page.getByLabel('Case note', { exact: true }).press('Enter');
    await waitText(page, 'Case note accepted');
    await waitText(page, 'Synthetic keyboard case note');
    await page.getByLabel('Scanner operator ID', { exact: true }).fill('fixture-scanner-b');
    await page.getByRole('button', { name: 'Assign case', exact: true }).click();
    await waitText(page, 'Case assignment accepted');
    await waitText(page, 'fixture-scanner-b');
    await page.getByRole('button', { name: 'Unassign case', exact: true }).click();
    await waitText(page, 'Case unassignment accepted');
    await page.getByLabel('Resolution note', { exact: true }).fill('Synthetic analyst decision; endpoint state remains unverified');
    await page.getByRole('button', { name: 'Resolve case', exact: true }).click();
    await waitText(page, 'Case resolution accepted');
    assert.equal(await page.getByRole('button', { name: 'Assign case', exact: true }).count(), 0);
    await page.getByRole('button', { name: 'Reopen case', exact: true }).click();
    await waitText(page, 'Case reopening accepted');
    assert.equal(await page.getByRole('button', { name: 'Resolve case', exact: true }).count(), 0);
    await accessibility(page, 'Operator case controls mobile');
    await page.screenshot({ path: join(resultsDir, 'operator-case-workflow.png'), fullPage: true });
    await accessibilityUnclipped(page, 'Operator case controls desktop unclipped', 'operator-case-workflow-desktop.png');
  });
  await check('path request rejects invalid input, queues once and cancels only pending work without inventing a result', async () => {
    await page.getByLabel('Endpoint to scan', { exact: true }).selectOption('fixture-linux');
    await page.getByLabel('Absolute local path', { exact: true }).fill('/');
    const before = observedSOC.filter(x => x.method === 'POST').length;
    await page.getByRole('button', { name: 'Queue path scan', exact: true }).click();
    await waitText(page, 'Enter a normalized, absolute local file or directory path');
    assert.equal(observedSOC.filter(x => x.method === 'POST').length, before);
    await page.getByLabel('Absolute local path', { exact: true }).fill('/var/data/browser-fixture');
    await page.getByLabel('Absolute local path', { exact: true }).press('Enter');
    await waitText(page, 'Path scan queued');
    await waitText(page, 'No result has been returned for this job');
    assert.equal(observedSOC.filter(x => x.method === 'POST').length, before + 1);
    await page.getByRole('button', { name: 'Cancel this pending scan', exact: true }).click();
    await waitText(page, 'Pending scan cancellation accepted');
    assert.equal(await page.getByRole('button', { name: /Cancel (this )?pending scan/ }).count(), 0);
    await waitText(page, 'scan outcome and endpoint condition are unknown');
    assert.equal(observedSOC.filter(x => x.method === 'POST').length, before + 2);
    assert.ok(observedSOC.filter(x => x.method === 'POST').every(x => x.sameOrigin && x.fetchSite === 'same-origin' && x.authorizedTLS && !x.bearerPresent));
    await accessibility(page, 'Operator scan controls mobile');
    await page.screenshot({ path: join(resultsDir, 'operator-scan-workflow.png'), fullPage: true });
    await accessibilityUnclipped(page, 'Operator scan controls desktop unclipped', 'operator-scan-workflow-desktop.png');
  });
  await check('lost acknowledgement response remains uncertain with no automatic retry', async () => {
    mode = 'ack-drop'; alertState = 'open';
    await page.getByRole('button', { name: 'Refresh SOC records', exact: true }).click();
    await waitText(page, 'Loaded records for tenant');
    const before = observedSOC.filter(x => x.method === 'POST').length;
    const serverStart = observedSOC.length;
    const browserStart = observedBrowserSOC.length;
    await page.getByRole('button', { name: 'Acknowledge alert ' + alertID }).first().click();
    try {
      await waitText(page, 'The operation outcome is unknown');
    } finally {
      // Passive diagnostics preserve the original assertion and response-drop behavior.
      const status = await page.locator('[aria-labelledby="soc-connection-title"] [role="status"]').innerText({ timeout: 1000 }).catch(() => 'Connection status unavailable');
      const diagnostics = { fixtureAlertState: alertState, connectionStatus: status.slice(0, 1600),
        serverRequests: observedSOC.slice(serverStart), browserRequests: observedBrowserSOC.slice(browserStart) };
      report.interruptedAcknowledgement = diagnostics;
      await page.screenshot({ path: join(resultsDir, 'operator-interrupted-acknowledgement.png'), fullPage: true }).catch(error => { diagnostics.screenshotError = error.name; });
      await writeFile(join(resultsDir, 'operator-interrupted-acknowledgement.json'), JSON.stringify(diagnostics, null, 2) + '\n');
      console.log('Interrupted acknowledgement diagnostics: ' + JSON.stringify({ fixtureAlertState: diagnostics.fixtureAlertState,
        connectionStatus: diagnostics.connectionStatus, serverPosts: diagnostics.serverRequests.filter(x => x.method === 'POST'),
        browserPosts: diagnostics.browserRequests.filter(x => x.method === 'POST') }));
    }
    assert.equal(await page.locator('table').count(), 0);
    assert.equal(observedSOC.filter(x => x.method === 'POST').length, before + 1);
    mode = 'ready';
    await page.getByRole('button', { name: 'Connect to SOC', exact: true }).click();
    await waitText(page, 'Loaded records for tenant');
    assert.equal(await page.getByRole('button', { name: 'Acknowledge alert ' + alertID }).count(), 0);
    assert.equal(observedSOC.filter(x => x.method === 'POST').length, before + 1);
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
    assert.equal(report.accessibility.at(-1).incomplete.length, 0, 'Original local SOC overview must have no incomplete accessibility checks');
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
  // Only paths, methods, status/failure codes and booleans; no bodies, tokens or keys.
  report.transport = { socServer: observedSOC, socBrowser: observedBrowserSOC, labRequests: observedLab };
  await writeFile(join(resultsDir, 'soc-browser-report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(`Browser contract checks: ${report.cases.filter(x => x.status === 'pass').length}/${report.cases.length}; status=${report.status}; browser=${report.browser}`);
}
