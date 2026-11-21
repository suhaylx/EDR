// Synthetic transport fixture. These tests do not execute Go, PostgreSQL, TLS or a browser.
export const session = { tenant_id: 'tenant-a', operator_id: 'scanner-a', role: 'scanner', server_time: '2026-11-21T18:00:00Z' };
export const endpoint = { agent_id: 'linux-a', platform: 'linux', health: 'unseen', last_seen: null, scan_ready: false, heartbeat_count: 0, agent_version: '', clamav_version: '', signature_version: '' };
export const alert = { alert_id: '11111111-1111-4111-8111-111111111111', job_id: '22222222-2222-4222-8222-222222222222', agent_id: endpoint.agent_id, category: 'malware_signature', severity: 'high', signature_name: 'Synthetic-Test', state: 'open', created_at: session.server_time, updated_at: session.server_time, acknowledged_by: '', resolved_by: '', assigned_to: '', resolution_note: '' };
export const job = { job_id: alert.job_id, agent_id: endpoint.agent_id, scan_root: '/var/data/sample', state: 'pending', attempt_count: 0, created_at: session.server_time, updated_at: session.server_time };
export const result = { job_id: job.job_id, agent_id: job.agent_id, engine: 'clamav', verdict: 'unscanned', threat_name: '', detail: 'Synthetic fixture; not host evidence', observed_at: session.server_time };
export const activity = { activity_id: '33333333-3333-4333-8333-333333333333', actor_id: session.operator_id, action: 'note', note: 'Synthetic note', occurred_at: session.server_time };
export const requestID = '44444444-4444-4444-8444-444444444444';
export const page = (items, offset = 0) => ({ items, limit: 25, offset });
export const endpointStats = { total: 1, windows: 0, linux: 1, online: 0, degraded: 0, stale: 0, unseen: 1, revoked: 0 };
export const scanStats = { total: 1, pending: 1, leased: 0, succeeded: 0, failed: 0, cancelled: 0, malicious: 0 };
export const snapshot = (patch = {}) => ({ session, endpoints: page([endpoint]), endpointStats, alerts: page([alert]), alertStats: { open: 1, acknowledged: 0, resolved: 0 }, mine: page([]), jobs: page([job]), results: page([]), scanStats, ...patch });
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

export function workflowBackend({ initialAlert = alert, initialJob = job, reportedResult = null, override = () => undefined } = {}) {
  const calls = [];
  const state = { alert: { ...initialAlert }, job: { ...initialJob }, result: reportedResult, session: { ...session }, activity: [], posts: 0, sessions: 0 };
  const fetcher = async (path, init) => {
    calls.push({ path, init });
    if (path === '/soc/v1/session') state.sessions++;
    if (init.method === 'POST') state.posts++;
    const replacement = await override(path, init, state);
    if (replacement !== undefined) return replacement;
    const offset = Number(new URL(path, 'https://fixture.invalid').searchParams.get('offset') ?? 0);
    if (path === '/soc/v1/session') return json(state.session);
    if (init.method === 'POST') {
      const body = init.body ? JSON.parse(init.body) : undefined;
      const action = path.split('/').at(-1);
      if (action === 'ack') { state.alert.state = 'acknowledged'; state.alert.acknowledged_by = session.operator_id; }
      else if (action === 'resolve') { state.alert.state = 'resolved'; state.alert.resolution_note = body.note; state.alert.resolved_by = session.operator_id; }
      else if (action === 'reopen') { state.alert.state = 'open'; state.alert.resolution_note = ''; state.alert.resolved_by = ''; state.alert.acknowledged_by = ''; }
      else if (action === 'assign') state.alert.assigned_to = body.operator_id;
      else if (action === 'notes') { state.activity.push({ ...activity, note: body.note }); return json({ activity_id: activity.activity_id }, 201); }
      else if (action === 'cancel') state.job.state = 'cancelled';
      else if (action === 'scan-jobs') { state.job.scan_root = body.scan_root; return json({ job_id: state.job.job_id, created: true }, 201); }
      else throw new Error('Unexpected fixture mutation');
      return new Response(null, { status: 204 });
    }
    if (path.endsWith('/endpoint-stats')) return json(endpointStats);
    if (path.includes('/endpoints?')) return json(page([endpoint], offset));
    if (path.endsWith('/endpoints/' + endpoint.agent_id)) return json(endpoint);
    if (path.endsWith('/alert-stats')) return json({ open: Number(state.alert.state === 'open'), acknowledged: Number(state.alert.state === 'acknowledged'), resolved: Number(state.alert.state === 'resolved') });
    if (path.includes('/alerts?')) return json(page([state.alert], offset));
    if (path.includes('/my-alerts?')) return json(page(state.alert.assigned_to === session.operator_id && state.alert.state !== 'resolved' ? [state.alert] : [], offset));
    if (path.endsWith('/alerts/' + alert.alert_id)) return json(state.alert);
    if (path.includes('/activity?')) return json(page(state.activity, offset));
    if (path.includes('/scan-jobs?')) return json(page([state.job], offset));
    if (path.endsWith('/scan-jobs/' + job.job_id)) return json(state.job);
    if (path.includes('/scan-results?')) return json(page(state.result ? [state.result] : [], offset));
    if (path.endsWith('/scan-results/' + job.job_id)) return state.result ? json(state.result) : new Response(null, { status: 404 });
    if (path.endsWith('/scan-stats')) return json({ total: 1, pending: Number(state.job.state === 'pending'), leased: Number(state.job.state === 'leased'), succeeded: Number(state.job.state === 'succeeded'), failed: Number(state.job.state === 'failed'), cancelled: Number(state.job.state === 'cancelled'), malicious: 0 });
    throw new Error('Unexpected fixture URL');
  };
  return { calls, state, fetcher, options: { protocol: 'https:', fetcher } };
}
