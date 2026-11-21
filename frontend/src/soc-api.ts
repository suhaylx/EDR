import { decodeOperatorInventoryPage, decodeOperatorEndpointStats, type OperatorInventoryPage, type OperatorEndpointStats } from './soc-operator-endpoints.js';
import { socRecord, socText, socIdentity, socUUID, socTimestamp, socCount, socPage, type SOCPage } from './soc-contract.js';

export type SOCSession = Readonly<{ tenant_id: string; operator_id: string; role: 'viewer' | 'scanner'; server_time: string }>;
export type SOCAlert = Readonly<{
  alert_id: string; job_id: string; agent_id: string; category: 'malware_signature'; severity: 'high';
  signature_name: string; state: 'open' | 'acknowledged' | 'resolved'; created_at: string; updated_at: string;
  acknowledged_by: string; resolved_by: string; resolution_note: string; assigned_to: string;
}>;
export type SOCAlertStats = Readonly<{ open: number; acknowledged: number; resolved: number }>;
export type SOCActivity = Readonly<{
  activity_id: string; actor_id: string;
  action: 'created' | 'acknowledged' | 'resolved' | 'reopened' | 'assigned' | 'unassigned' | 'note';
  note: string; occurred_at: string;
}>;
export type SOCOffsets = Readonly<{ endpoints: number; alerts: number; mine: number }>;
export const firstSOCPages: SOCOffsets = { endpoints: 0, alerts: 0, mine: 0 };
export const socPageSize = 25;
export type SOCSnapshot = Readonly<{
  session: SOCSession; endpoints: OperatorInventoryPage; endpointStats: OperatorEndpointStats;
  alerts: SOCPage<SOCAlert>; alertStats: SOCAlertStats; mine: SOCPage<SOCAlert>;
}>;
export type SOCFailure = 'insecure_origin' | 'unauthorized' | 'forbidden' | 'unavailable' | 'invalid_response' | 'http_error' | 'identity_changed' | 'cancelled' | 'timeout';
export class SOCReadError extends Error {
  constructor(readonly code: SOCFailure) { super(code); this.name = 'SOCReadError'; }
}
export const socFailureMessages: Readonly<Record<SOCFailure, string>> = {
  insecure_origin: 'Open the HTTPS operator service to connect. No SOC request was sent over this origin.',
  unauthorized: 'Operator authorization was denied. All displayed records have been cleared. Check the browser certificate and operator enrollment.',
  forbidden: 'This operator is not authorized for the requested records. All displayed records have been cleared.',
  unavailable: 'The authenticated SOC service is unavailable. No current endpoint or alert state can be established.',
  invalid_response: 'The service returned an unexpected or inconsistent response. All displayed records have been cleared.',
  http_error: 'The SOC request failed. All displayed records have been cleared.',
  identity_changed: 'The authenticated operator identity changed. All displayed records have been cleared; reconnect to load the current identity.',
  cancelled: 'The request was cancelled. No current records are displayed.',
  timeout: 'The SOC request timed out. No current endpoint or alert state can be established.',
};
export function socFailure(error: unknown): SOCFailure { return error instanceof SOCReadError ? error.code : 'unavailable'; }

export function decodeSOCSession(value: unknown): SOCSession {
  const s = socRecord(value);
  if (s.role !== 'viewer' && s.role !== 'scanner') throw new Error('Invalid SOC role');
  return { tenant_id: socIdentity(s.tenant_id), operator_id: socIdentity(s.operator_id), role: s.role, server_time: socTimestamp(s.server_time) };
}
const optionalIdentity = (value: unknown): string => value === undefined || value === '' ? '' : socIdentity(value);
export function decodeSOCAlert(value: unknown): SOCAlert {
  const a = socRecord(value);
  if (a.category !== 'malware_signature' || a.severity !== 'high' ||
      (a.state !== 'open' && a.state !== 'acknowledged' && a.state !== 'resolved')) throw new Error('Invalid SOC alert classification');
  const created_at = socTimestamp(a.created_at);
  const updated_at = socTimestamp(a.updated_at);
  if (Date.parse(updated_at) < Date.parse(created_at)) throw new Error('Invalid SOC alert chronology');
  return {
    alert_id: socUUID(a.alert_id), job_id: socUUID(a.job_id), agent_id: socIdentity(a.agent_id),
    category: a.category, severity: a.severity, signature_name: socText(a.signature_name, 256, false), state: a.state,
    created_at, updated_at, acknowledged_by: optionalIdentity(a.acknowledged_by), resolved_by: optionalIdentity(a.resolved_by),
    resolution_note: socText(a.resolution_note ?? '', 1024), assigned_to: optionalIdentity(a.assigned_to),
  };
}
export const decodeSOCAlerts = (value: unknown): SOCPage<SOCAlert> => socPage(value, decodeSOCAlert, a => a.alert_id);
export function decodeSOCAlertStats(value: unknown): SOCAlertStats {
  const s = socRecord(value);
  return { open: socCount(s.open), acknowledged: socCount(s.acknowledged), resolved: socCount(s.resolved) };
}
export function decodeSOCActivity(value: unknown): SOCActivity {
  const a = socRecord(value);
  const action = socText(a.action, 32);
  if (!['created', 'acknowledged', 'resolved', 'reopened', 'assigned', 'unassigned', 'note'].includes(action)) throw new Error('Invalid SOC activity');
  return {
    activity_id: socUUID(a.activity_id), actor_id: socIdentity(a.actor_id), action: action as SOCActivity['action'],
    note: socText(a.note ?? '', 2048), occurred_at: socTimestamp(a.occurred_at),
  };
}
export const decodeSOCActivities = (value: unknown): SOCPage<SOCActivity> => socPage(value, decodeSOCActivity, a => a.activity_id);

export type SOCReadOptions = Readonly<{ protocol: string; fetcher?: typeof fetch; signal?: AbortSignal; timeoutMs?: number }>;
const maxResponseBytes = 512 * 1024;

async function readJSON<T>(path: string, decode: (value: unknown) => T, options: SOCReadOptions, signal: AbortSignal): Promise<T> {
  const response = await (options.fetcher ?? fetch)(path, {
    method: 'GET', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
    referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' }, signal,
  });
  if (response.status !== 200) {
    // Never parse, retain or display arbitrary server error text.
    await response.body?.cancel().catch(() => undefined);
    const code = response.status === 401 ? 'unauthorized' : response.status === 403 ? 'forbidden' :
      response.status === 503 ? 'unavailable' : 'http_error';
    throw new SOCReadError(code);
  }
  if (response.redirected || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '') ||
      Number(response.headers.get('content-length')) > maxResponseBytes || !response.body) {
    await response.body?.cancel().catch(() => undefined);
    throw new SOCReadError('invalid_response');
  }
  const reader = response.body.getReader();
  const textDecoder = new TextDecoder('utf-8', { fatal: true });
  let text = '';
  let bytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (signal.aborted) throw new SOCReadError('cancelled');
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > maxResponseBytes) throw new SOCReadError('invalid_response');
      text += textDecoder.decode(chunk.value, { stream: true });
    }
    text += textDecoder.decode();
    return decode(JSON.parse(text));
  } catch (error) {
    throw error instanceof SOCReadError ? error : new SOCReadError('invalid_response');
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

async function readGroup<T>(options: SOCReadOptions, operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
  if (options.protocol !== 'https:') throw new SOCReadError('insecure_origin');
  if (options.signal?.aborted) throw new SOCReadError('cancelled');
  const controller = new AbortController();
  let rejectStop: (error: SOCReadError) => void = () => undefined;
  const stopped = new Promise<never>((_, reject) => { rejectStop = reject; });
  const stop = (code: 'cancelled' | 'timeout') => { controller.abort(); rejectStop(new SOCReadError(code)); };
  const onAbort = () => stop('cancelled');
  options.signal?.addEventListener('abort', onAbort, { once: true });
  const timeout = setTimeout(() => stop('timeout'), options.timeoutMs ?? 15000);
  try {
    return await Promise.race([operation(controller.signal), stopped]);
  } catch (error) {
    throw error instanceof SOCReadError ? error : new SOCReadError('unavailable');
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', onAbort);
    controller.abort();
  }
}

function sameIdentity(first: SOCSession, last: SOCSession): void {
  if (first.tenant_id !== last.tenant_id || first.operator_id !== last.operator_id || first.role !== last.role) {
    throw new SOCReadError('identity_changed');
  }
}
function validateOffset(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 10000 || value % socPageSize !== 0) throw new SOCReadError('invalid_response');
}
function expectedPage<T>(page: SOCPage<T>, offset: number): SOCPage<T> {
  if (page.limit !== socPageSize || page.offset !== offset) throw new SOCReadError('invalid_response');
  return page;
}

/** All reads succeed together. An auth, schema or network error returns no partial snapshot. */
export async function loadSOCSnapshot(options: SOCReadOptions, offsets: SOCOffsets = firstSOCPages): Promise<SOCSnapshot> {
  for (const offset of [offsets.endpoints, offsets.alerts, offsets.mine]) validateOffset(offset);
  return readGroup(options, async signal => {
    const session = await readJSON('/soc/v1/session', decodeSOCSession, options, signal);
    const base = '/soc/v1/tenants/' + session.tenant_id + '/';
    const [endpoints, endpointStats, alerts, alertStats, mine] = await Promise.all([
      readJSON(base + `endpoints?limit=${socPageSize}&offset=${offsets.endpoints}`, decodeOperatorInventoryPage, options, signal),
      readJSON(base + 'endpoint-stats', decodeOperatorEndpointStats, options, signal),
      readJSON(base + `alerts?limit=${socPageSize}&offset=${offsets.alerts}`, decodeSOCAlerts, options, signal),
      readJSON(base + 'alert-stats', decodeSOCAlertStats, options, signal),
      readJSON(base + `my-alerts?limit=${socPageSize}&offset=${offsets.mine}`, decodeSOCAlerts, options, signal),
    ]);
    if (mine.items.some(a => a.assigned_to !== session.operator_id || a.state === 'resolved')) throw new SOCReadError('invalid_response');
    const finalSession = await readJSON('/soc/v1/session', decodeSOCSession, options, signal);
    sameIdentity(session, finalSession);
    return {
      session: finalSession, endpoints: expectedPage(endpoints, offsets.endpoints), endpointStats,
      alerts: expectedPage(alerts, offsets.alerts), alertStats, mine: expectedPage(mine, offsets.mine),
    };
  });
}

export async function loadSOCActivity(session: SOCSession, alertID: string, options: SOCReadOptions, offset = 0): Promise<SOCPage<SOCActivity>> {
  validateOffset(offset);
  let id: string;
  try { decodeSOCSession(session); id = socUUID(alertID); } catch { throw new SOCReadError('invalid_response'); }
  return readGroup(options, async signal => {
    const current = await readJSON('/soc/v1/session', decodeSOCSession, options, signal);
    sameIdentity(session, current);
    const page = await readJSON(`/soc/v1/tenants/${session.tenant_id}/alerts/${id}/activity?limit=${socPageSize}&offset=${offset}`, decodeSOCActivities, options, signal);
    const finalSession = await readJSON('/soc/v1/session', decodeSOCSession, options, signal);
    sameIdentity(session, finalSession);
    return expectedPage(page, offset);
  });
}
