import { decodeOperatorEndpoint, decodeOperatorInventoryPage, decodeOperatorEndpointStats, type OperatorInventoryPage, type OperatorEndpointStats } from './soc-operator-endpoints.js';
import { socRecord, socText, socIdentity, socUUID, socTimestamp, socCount, socPage, type SOCPage } from './soc-contract.js';
import { decodeSOCScanJob, decodeSOCScanJobs, decodeSOCScanResult, decodeSOCScanResults, decodeSOCScanStats, socBoundedInput, validateSOCScanPath,
  type SOCScanJob, type SOCScanResult, type SOCScanStats, type SOCScanDetail } from './soc-scans.js';

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
export type SOCOffsets = Readonly<{ endpoints: number; alerts: number; mine: number; jobs: number; results: number }>;
export const firstSOCPages: SOCOffsets = { endpoints: 0, alerts: 0, mine: 0, jobs: 0, results: 0 };
export const socPageSize = 25;
export type SOCSnapshot = Readonly<{
  session: SOCSession; endpoints: OperatorInventoryPage; endpointStats: OperatorEndpointStats;
  alerts: SOCPage<SOCAlert>; alertStats: SOCAlertStats; mine: SOCPage<SOCAlert>;
  jobs: SOCPage<SOCScanJob>; results: SOCPage<SOCScanResult>; scanStats: SOCScanStats;
}>;
export type SOCCaseDetail = Readonly<{ alert: SOCAlert; activity: SOCPage<SOCActivity> }>;
export type SOCMutationCommand =
  | Readonly<{ kind: 'ack' | 'reopen' | 'unassign'; alert_id: string }>
  | Readonly<{ kind: 'resolve' | 'note'; alert_id: string; note: string }>
  | Readonly<{ kind: 'assign'; alert_id: string; operator_id: string }>
  | Readonly<{ kind: 'schedule'; agent_id: string; request_id: string; scan_root: string }>
  | Readonly<{ kind: 'cancel'; job_id: string }>;
export type SOCMutationReceipt = Readonly<{ kind: SOCMutationCommand['kind']; reference_id: string; created?: boolean }>;
export type SOCMutationOutcome = Readonly<{ snapshot: SOCSnapshot; receipt: SOCMutationReceipt; caseDetail?: SOCCaseDetail; scanDetail?: SOCScanDetail }>;
export type SOCFailure = 'insecure_origin' | 'unauthorized' | 'forbidden' | 'unavailable' | 'invalid_response' | 'invalid_request' | 'http_error' | 'identity_changed' | 'cancelled' | 'timeout' | 'conflict' | 'mutation_unknown' | 'stale_selection';
export class SOCReadError extends Error {
  constructor(readonly code: SOCFailure) { super(code); this.name = 'SOCReadError'; }
}
/** The server accepted the write, but fresh authorized records could not be published. */
export class SOCMutationRefreshError extends SOCReadError {
  constructor(code: SOCFailure, readonly receipt: SOCMutationReceipt) { super(code); this.name = 'SOCMutationRefreshError'; }
}
export class SOCAcknowledgedRefreshError extends SOCMutationRefreshError {
  constructor(code: SOCFailure, receipt: SOCMutationReceipt) { super(code, receipt); this.name = 'SOCAcknowledgedRefreshError'; }
}
export const socFailureMessages: Readonly<Record<SOCFailure, string>> = {
  insecure_origin: 'Open the HTTPS operator service to connect. No SOC request was sent over this origin.',
  unauthorized: 'Operator authorization was denied. All displayed records have been cleared. Check the browser certificate and operator enrollment.',
  forbidden: 'This operator is not authorized for the requested records. All displayed records have been cleared.',
  unavailable: 'The authenticated SOC service is unavailable. No current endpoint or alert state can be established.',
  invalid_response: 'The service returned an unexpected or inconsistent response. All displayed records have been cleared.',
  invalid_request: 'The operation was not accepted. Check the supplied fields, then reconnect to verify current state before trying again.',
  http_error: 'The SOC request failed. All displayed records have been cleared.',
  identity_changed: 'The authenticated operator identity changed. All displayed records have been cleared; reconnect to load the current identity.',
  cancelled: 'The request was cancelled. No current records are displayed.',
  timeout: 'The SOC request timed out. No current endpoint or alert state can be established.',
  conflict: 'The record changed, the transition is no longer permitted, or this operator cannot cancel that job. Reconnect to verify current state before taking another action.',
  mutation_unknown: 'The operation outcome is unknown because the request did not complete reliably. Reconnect and inspect current state before trying again. No automatic retry was sent.',
  stale_selection: 'The selected record is no longer in the displayed data. Reconnect before taking an action.',
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

function requestSOC(path: string, method: 'GET' | 'POST', options: SOCReadOptions, signal: AbortSignal, payload?: object): Promise<Response> {
  return (options.fetcher ?? fetch)(path, {
    method, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
    referrerPolicy: 'no-referrer', headers: payload === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
    signal, ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
  });
}
function httpFailure(status: number): SOCFailure {
  return status === 401 ? 'unauthorized' : status === 403 ? 'forbidden' : status === 409 ? 'conflict' : status === 400 ? 'invalid_request' :
    status === 503 ? 'unavailable' : 'http_error';
}

async function readJSON<T>(path: string, decode: (value: unknown) => T, options: SOCReadOptions, signal: AbortSignal): Promise<T> {
  const response = await requestSOC(path, 'GET', options, signal);
  if (response.status !== 200) {
    // Never parse, retain or display arbitrary server error text.
    await response.body?.cancel().catch(() => undefined);
    throw new SOCReadError(httpFailure(response.status));
  }
  return decodeJSONResponse(response, decode, signal);
}

async function decodeJSONResponse<T>(response: Response, decode: (value: unknown) => T, signal: AbortSignal): Promise<T> {
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
  for (const offset of [offsets.endpoints, offsets.alerts, offsets.mine, offsets.jobs, offsets.results]) validateOffset(offset);
  return readGroup(options, async signal => {
    const session = await readJSON('/soc/v1/session', decodeSOCSession, options, signal);
    const base = '/soc/v1/tenants/' + session.tenant_id + '/';
    const [endpoints, endpointStats, alerts, alertStats, mine, jobs, results, scanStats] = await Promise.all([
      readJSON(base + `endpoints?limit=${socPageSize}&offset=${offsets.endpoints}`, decodeOperatorInventoryPage, options, signal),
      readJSON(base + 'endpoint-stats', decodeOperatorEndpointStats, options, signal),
      readJSON(base + `alerts?limit=${socPageSize}&offset=${offsets.alerts}`, decodeSOCAlerts, options, signal),
      readJSON(base + 'alert-stats', decodeSOCAlertStats, options, signal),
      readJSON(base + `my-alerts?limit=${socPageSize}&offset=${offsets.mine}`, decodeSOCAlerts, options, signal),
      readJSON(base + `scan-jobs?limit=${socPageSize}&offset=${offsets.jobs}`, decodeSOCScanJobs, options, signal),
      readJSON(base + `scan-results?limit=${socPageSize}&offset=${offsets.results}`, decodeSOCScanResults, options, signal),
      readJSON(base + 'scan-stats', decodeSOCScanStats, options, signal),
    ]);
    if (mine.items.some(a => a.assigned_to !== session.operator_id || a.state === 'resolved')) throw new SOCReadError('invalid_response');
    const finalSession = await readJSON('/soc/v1/session', decodeSOCSession, options, signal);
    sameIdentity(session, finalSession);
    return {
      session: finalSession, endpoints: expectedPage(endpoints, offsets.endpoints), endpointStats,
      alerts: expectedPage(alerts, offsets.alerts), alertStats, mine: expectedPage(mine, offsets.mine),
      jobs: expectedPage(jobs, offsets.jobs), results: expectedPage(results, offsets.results), scanStats,
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

export async function loadSOCCase(session: SOCSession, alertID: string, options: SOCReadOptions, offset = 0): Promise<SOCCaseDetail> {
  validateOffset(offset);
  let id: string;
  try { decodeSOCSession(session); id = socUUID(alertID); } catch { throw new SOCReadError('invalid_response'); }
  return readGroup(options, async signal => {
    sameIdentity(session, await readJSON('/soc/v1/session', decodeSOCSession, options, signal));
    const path = `/soc/v1/tenants/${session.tenant_id}/alerts/${id}`;
    const [alert, activity] = await Promise.all([
      readJSON(path, decodeSOCAlert, options, signal),
      readJSON(path + `/activity?limit=${socPageSize}&offset=${offset}`, decodeSOCActivities, options, signal),
    ]);
    if (alert.alert_id !== id) throw new SOCReadError('invalid_response');
    sameIdentity(session, await readJSON('/soc/v1/session', decodeSOCSession, options, signal));
    return { alert, activity: expectedPage(activity, offset) };
  });
}

export async function loadSOCScanDetail(session: SOCSession, jobID: string, options: SOCReadOptions): Promise<SOCScanDetail> {
  let id: string;
  try { decodeSOCSession(session); id = socUUID(jobID); } catch { throw new SOCReadError('invalid_response'); }
  return readGroup(options, async signal => {
    sameIdentity(session, await readJSON('/soc/v1/session', decodeSOCSession, options, signal));
    const base = `/soc/v1/tenants/${session.tenant_id}/`;
    const job = await readJSON(base + 'scan-jobs/' + id, decodeSOCScanJob, options, signal);
    const response = await requestSOC(base + 'scan-results/' + id, 'GET', options, signal);
    let result: SOCScanResult | null = null;
    if (response.status === 404) await response.body?.cancel().catch(() => undefined);
    else if (response.status === 200) result = await decodeJSONResponse(response, decodeSOCScanResult, signal);
    else {
      await response.body?.cancel().catch(() => undefined);
      throw new SOCReadError(httpFailure(response.status));
    }
    if (job.job_id !== id || (result && (result.job_id !== id || result.agent_id !== job.agent_id))) throw new SOCReadError('invalid_response');
    sameIdentity(session, await readJSON('/soc/v1/session', decodeSOCSession, options, signal));
    return { job, result };
  });
}

export function mutationReceiptLabel(receipt: SOCMutationReceipt): string {
  switch (receipt.kind) {
    case 'ack': return 'Alert acknowledgement accepted';
    case 'resolve': return 'Case resolution accepted';
    case 'reopen': return 'Case reopening accepted';
    case 'note': return 'Case note accepted';
    case 'assign': return 'Case assignment accepted';
    case 'unassign': return 'Case unassignment accepted';
    case 'cancel': return 'Pending scan cancellation accepted';
    case 'schedule': return receipt.created ? 'Path scan queued' : 'Existing path scan request returned';
  }
}

type VisibleDetails = Readonly<{ alert?: SOCAlert; job?: SOCScanJob }>;
type MutationPlan = { path: string; payload?: object; expected: readonly number[]; reference: string };

/** Every supported write uses the same identity, request, ambiguity and reload boundary. */
export async function runSOCMutation(snapshot: SOCSnapshot, command: SOCMutationCommand, options: SOCReadOptions,
  offsets: SOCOffsets = firstSOCPages, visible: VisibleDetails = {}): Promise<SOCMutationOutcome> {
  let session: SOCSession;
  try { session = decodeSOCSession(snapshot.session); } catch { throw new SOCReadError('invalid_response'); }
  if (session.role !== 'scanner') throw new SOCReadError('forbidden');
  if (!command || !['ack', 'resolve', 'reopen', 'note', 'assign', 'unassign', 'schedule', 'cancel'].includes(command.kind)) throw new SOCReadError('invalid_request');
  for (const offset of [offsets.endpoints, offsets.alerts, offsets.mine, offsets.jobs, offsets.results]) validateOffset(offset);
  const base = `/soc/v1/tenants/${session.tenant_id}/`;
  let selectedAlert: SOCAlert | undefined;
  let selectedJob: SOCScanJob | undefined;
  let selectedEndpoint: ReturnType<typeof decodeOperatorEndpoint> | undefined;
  let id: string;
  try {
    if ('alert_id' in command) {
      id = socUUID(command.alert_id);
      const selected = visible.alert?.alert_id === id ? visible.alert : [...snapshot.alerts.items, ...snapshot.mine.items].find(alert => alert.alert_id === id);
      if (!selected) throw new SOCReadError('stale_selection');
      selectedAlert = decodeSOCAlert(selected);
    } else if (command.kind === 'cancel') {
      id = socUUID(command.job_id);
      const selected = visible.job?.job_id === id ? visible.job : snapshot.jobs.items.find(job => job.job_id === id);
      if (!selected) throw new SOCReadError('stale_selection');
      selectedJob = decodeSOCScanJob(selected);
    } else if (command.kind === 'schedule') {
      id = socIdentity(command.agent_id);
      const selected = snapshot.endpoints.items.find(endpoint => endpoint.agent_id === id);
      if (!selected) throw new SOCReadError('stale_selection');
      selectedEndpoint = decodeOperatorEndpoint(selected);
    } else throw new SOCReadError('invalid_request');
  } catch (error) { throw error instanceof SOCReadError ? error : new SOCReadError('invalid_response'); }

  let payload: object | undefined;
  try {
    if (selectedAlert) {
      const required = command.kind === 'ack' ? 'open' : command.kind === 'resolve' ? 'acknowledged' : command.kind === 'reopen' ? 'resolved' : undefined;
      if ((required && selectedAlert.state !== required) || (['assign', 'unassign'].includes(command.kind) && selectedAlert.state === 'resolved')) throw new SOCReadError('conflict');
    }
    if (command.kind === 'resolve' || command.kind === 'note') {
      const note = socBoundedInput(command.note, command.kind === 'resolve' ? 1024 : 2048);
      if (!note.trim()) throw new Error('Empty note');
      payload = { note };
    }
    if (command.kind === 'assign') {
      const assignee = socIdentity(command.operator_id);
      if (selectedAlert?.assigned_to === assignee) throw new SOCReadError('conflict');
      payload = { operator_id: assignee };
    }
    if (command.kind === 'unassign') {
      if (!selectedAlert?.assigned_to) throw new SOCReadError('conflict');
      payload = { operator_id: '' }; // Explicit unassignment, never omitted/null.
    }
    if (command.kind === 'cancel' && selectedJob?.state !== 'pending') throw new SOCReadError('conflict');
    if (command.kind === 'schedule') {
      if (!selectedEndpoint || selectedEndpoint.health === 'revoked') throw new SOCReadError('forbidden');
      const requestID = socUUID(command.request_id);
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestID)) throw new Error('Expected a random UUID request key');
      payload = { agent_id: id, request_id: requestID, scan_root: validateSOCScanPath(selectedEndpoint.platform, command.scan_root) };
    }
  } catch (error) { throw error instanceof SOCReadError ? error : new SOCReadError('invalid_request'); }

  let submitted = false;
  let receipt: SOCMutationReceipt | undefined;
  try {
    await readGroup(options, async signal => {
      sameIdentity(session, await readJSON('/soc/v1/session', decodeSOCSession, options, signal));
      let plan: MutationPlan;
      if (selectedAlert) {
        const fresh = await readJSON(base + 'alerts/' + id, decodeSOCAlert, options, signal);
        if (fresh.alert_id !== id || fresh.job_id !== selectedAlert.job_id || fresh.agent_id !== selectedAlert.agent_id) throw new SOCReadError('invalid_response');
        if (fresh.state !== selectedAlert.state || fresh.assigned_to !== selectedAlert.assigned_to || fresh.updated_at !== selectedAlert.updated_at) throw new SOCReadError('conflict');
        const action = command.kind === 'note' ? 'notes' : command.kind === 'unassign' ? 'assign' : command.kind;
        plan = { path: base + 'alerts/' + id + '/' + action, payload, expected: command.kind === 'note' ? [201] : [204], reference: id };
      } else if (selectedJob) {
        const fresh = await readJSON(base + 'scan-jobs/' + id, decodeSOCScanJob, options, signal);
        if (fresh.job_id !== id || fresh.agent_id !== selectedJob.agent_id || fresh.scan_root !== selectedJob.scan_root) throw new SOCReadError('invalid_response');
        if (fresh.state !== 'pending' || fresh.updated_at !== selectedJob.updated_at) throw new SOCReadError('conflict');
        plan = { path: base + 'scan-jobs/' + id + '/cancel', expected: [204], reference: id };
      } else {
        const fresh = await readJSON(base + 'endpoints/' + id, decodeOperatorEndpoint, options, signal);
        if (fresh.agent_id !== id || fresh.platform !== selectedEndpoint?.platform) throw new SOCReadError('invalid_response');
        if (fresh.health === 'revoked') throw new SOCReadError('forbidden');
        plan = { path: base + 'scan-jobs', payload, expected: [200, 201], reference: id };
      }
      if (signal.aborted) throw new SOCReadError('cancelled');
      submitted = true;
      const response = await requestSOC(plan.path, 'POST', options, signal, plan.payload);
      if (signal.aborted) throw new SOCReadError('cancelled');
      if (!plan.expected.includes(response.status) || response.redirected) {
        await response.body?.cancel().catch(() => undefined);
        throw new SOCReadError(response.redirected ? 'invalid_response' : httpFailure(response.status));
      }
      if (command.kind === 'schedule') {
        const scheduled = await decodeJSONResponse(response, value => {
          const record = socRecord(value);
          if (typeof record.created !== 'boolean' || record.created !== (response.status === 201)) throw new Error('Invalid schedule response');
          return { job_id: socUUID(record.job_id), created: record.created };
        }, signal);
        receipt = { kind: command.kind, reference_id: scheduled.job_id, created: scheduled.created };
      } else if (command.kind === 'note') {
        const activityID = await decodeJSONResponse(response, value => socUUID(socRecord(value).activity_id), signal);
        receipt = { kind: command.kind, reference_id: activityID };
      } else {
        receipt = { kind: command.kind, reference_id: plan.reference };
        await response.body?.cancel().catch(() => undefined);
      }
    });
    if (!receipt) throw new SOCReadError('mutation_unknown');
    const refreshed = await loadSOCSnapshot(options, offsets);
    sameIdentity(session, refreshed.session);
    if (selectedAlert) {
      const caseDetail = await loadSOCCase(session, id, options);
      return { snapshot: refreshed, receipt, caseDetail };
    }
    const scanDetail = await loadSOCScanDetail(session, command.kind === 'schedule' ? receipt.reference_id : id, options);
    return { snapshot: refreshed, receipt, scanDetail };
  } catch (error) {
    const code = socFailure(error);
    if (receipt) throw new SOCMutationRefreshError(code, receipt);
    if (submitted && !['unauthorized', 'forbidden', 'conflict', 'invalid_request'].includes(code)) throw new SOCReadError('mutation_unknown');
    throw error;
  }
}

/** Compatibility entry point for the bounded acknowledgement contract tests. */
export async function acknowledgeSOCAlert(snapshot: SOCSnapshot, alertID: string, options: SOCReadOptions,
  offsets: SOCOffsets = firstSOCPages): Promise<SOCSnapshot> {
  try { return (await runSOCMutation(snapshot, { kind: 'ack', alert_id: alertID }, options, offsets)).snapshot; }
  catch (error) {
    if (error instanceof SOCMutationRefreshError) throw new SOCAcknowledgedRefreshError(error.code, error.receipt);
    throw error;
  }
}
