/** Read-only adapter for the existing Go /api/overview lab contract.
 * Counts are server-generated from retained in-memory evidence, NOT fleet totals. */
export type DayWindow = 1 | 7 | 30;
export type HeartbeatStatus = 'online' | 'offline' | 'unknown';
export type SeverityCount = { severity: string; count: number };
export type DailyCount = { day: string; count: number };
export type RuleHit = { rule_id: string; severity: string; count: number };
export type PolicyCoverage = { policy_id: string; policy_name: string; endpoints: number };
export type EndpointActivity = {
  id: string;
  platform: string;
  status: HeartbeatStatus;
  last_seen: string;
  events: number;
  alerts: number;
  inactive_seconds: number;
};
export type LabSOCOverview = {
  generated_at: string;
  window_days: DayWindow;
  data_source: 'development_in_memory_retained_telemetry';
  heartbeat_ttl_seconds: number;
  agents: number;
  online: number;
  offline: number;
  unknown: number;
  events: number;
  alerts: number;
  high_risk_alerts: number;
  policy_errors: number;
  severity: SeverityCount[];
  alert_trend: DailyCount[];
  top_rules: RuleHit[];
  policy_coverage: PolicyCoverage[];
  most_active: EndpointActivity[];
  inactive_machines: EndpointActivity[];
  scans: { queued: number; leased: number; completed: number; failed: number };
  unavailable: string[];
};
type RecordValue = Record<string, unknown>;
const object = (x: unknown): x is RecordValue => x !== null && typeof x === 'object' && !Array.isArray(x);
const string = (x: unknown, where: string): string => {
  if (typeof x !== 'string') throw new Error('Invalid overview field: ' + where);
  return x;
};
const count = (x: unknown, where: string): number => {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 0) {
    throw new Error('Invalid overview count: ' + where);
  }
  return x;
};
const boundedList = (x: unknown, where: string, max = 1000): unknown[] => {
  if (!Array.isArray(x) || x.length > max) throw new Error('Invalid overview list: ' + where);
  return x as unknown[];
};
const record = (x: unknown, where: string): RecordValue => {
  if (!object(x)) throw new Error('Invalid overview object: ' + where);
  return x;
};
const validUTC = (x: unknown, where: string): string => {
  const value = string(x, where);
  if (!/^\d{4}-\d\d-\d\dT/.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new Error('Invalid overview timestamp: ' + where);
  }
  return value;
};
const endpoint = (x: unknown, index: number): EndpointActivity => {
  const e = record(x, 'endpoint ' + index);
  const status = string(e.status, 'endpoint.status');
  if (status !== 'online' && status !== 'offline' && status !== 'unknown') {
    throw new Error('Invalid endpoint heartbeat status');
  }
  return {
    id: string(e.id, 'endpoint.id'),
    platform: string(e.platform, 'endpoint.platform'),
    status,
    last_seen: string(e.last_seen, 'endpoint.last_seen'),
    events: count(e.events, 'endpoint.events'),
    alerts: count(e.alerts, 'endpoint.alerts'),
    inactive_seconds: count(e.inactive_seconds, 'endpoint.inactive_seconds'),
  };
};
const parseList = <T>(x: unknown, name: string, make: (v: unknown, i: number) => T, max = 1000): T[] =>
  boundedList(x, name, max).map(make);

export function decodeLabOverview(raw: unknown, requestedDays: DayWindow): LabSOCOverview {
  const o = record(raw, 'root');
  if (o.data_source !== 'development_in_memory_retained_telemetry') {
    throw new Error('Unexpected overview data source; refusing to infer fleet coverage.');
  }
  if (o.window_days !== requestedDays) {
    throw new Error('Overview window does not match the requested UTC period.');
  }
  const agents = count(o.agents, 'agents');
  const online = count(o.online, 'online');
  const offline = count(o.offline, 'offline');
  const unknown = count(o.unknown, 'unknown');
  if (online + offline + unknown !== agents) throw new Error('Overview heartbeat counts do not reconcile.');
  const scans = record(o.scans, 'scans');
  return {
    generated_at: validUTC(o.generated_at, 'generated_at'),
    window_days: requestedDays,
    data_source: 'development_in_memory_retained_telemetry',
    heartbeat_ttl_seconds: count(o.heartbeat_ttl_seconds, 'heartbeat_ttl_seconds'),
    agents, online, offline, unknown,
    events: count(o.events, 'events'),
    alerts: count(o.alerts, 'alerts'),
    high_risk_alerts: count(o.high_risk_alerts, 'high_risk_alerts'),
    policy_errors: count(o.policy_errors, 'policy_errors'),
    scans: {
      queued: count(scans.queued, 'scans.queued'),
      leased: count(scans.leased, 'scans.leased'),
      completed: count(scans.completed, 'scans.completed'),
      failed: count(scans.failed, 'scans.failed'),
    },
    severity: parseList(o.severity, 'severity', (item, i) => {
      const v = record(item, 'severity ' + i);
      return {severity: string(v.severity, 'severity.name'), count: count(v.count, 'severity.count')};
    }, 20),
    alert_trend: parseList(o.alert_trend, 'alert_trend', (item, i) => {
      const v = record(item, 'trend ' + i);
      const day = string(v.day, 'trend.day');
      if (!/^\d{4}-\d\d-\d\d$/.test(day) || !Number.isFinite(Date.parse(day + 'T00:00:00Z'))) {
        throw new Error('Invalid overview UTC trend day');
      }
      return {day, count: count(v.count, 'trend.count')};
    }, 30),
    top_rules: parseList(o.top_rules, 'top_rules', (item, i) => {
      const v = record(item, 'rule ' + i);
      return {rule_id: string(v.rule_id, 'rule_id'), severity: string(v.severity, 'rule.severity'), count: count(v.count, 'rule.count')};
    }, 50),
    policy_coverage: parseList(o.policy_coverage, 'policy_coverage', (item, i) => {
      const v = record(item, 'policy ' + i);
      return {policy_id: string(v.policy_id, 'policy_id'), policy_name: string(v.policy_name, 'policy_name'), endpoints: count(v.endpoints, 'policy.endpoints')};
    }, 200),
    most_active: parseList(o.most_active, 'most_active', endpoint, 200),
    inactive_machines: parseList(o.inactive_machines, 'inactive_machines', endpoint, 1000),
    unavailable: parseList(o.unavailable, 'unavailable', (item, i) => string(item, 'unavailable ' + i), 200),
  };
}

export function heartbeatLabel(endpoint: EndpointActivity): string {
  if (endpoint.status === 'unknown') return 'Unknown — no trustworthy server heartbeat';
  if (endpoint.status === 'online') return 'Online (server-received heartbeat)';
  const seconds = endpoint.inactive_seconds;
  if (seconds >= 86400) return (seconds / 86400).toFixed(1) + ' days inactive';
  if (seconds >= 3600) return Math.floor(seconds / 3600) + ' hours inactive';
  return Math.floor(seconds / 60) + ' minutes inactive';
}

/** Keep this endpoint read-only and scoped to explicit 1/7/30-day requests. */
export async function fetchLabOverview(
  token: string, days: DayWindow, signal?: AbortSignal, fetcher: typeof fetch = fetch,
): Promise<LabSOCOverview> {
  if (token.length < 16) throw new Error('The development token must contain at least 16 characters.');
  if (days !== 1 && days !== 7 && days !== 30) throw new Error('Unsupported UTC window.');
  const response = await fetcher('/api/overview?days=' + days, {
    method: 'GET', credentials: 'omit', cache: 'no-store', signal,
    headers: {Authorization: 'Bearer ' + token},
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Development token rejected (HTTP 401).');
    throw new Error('Lab overview API returned HTTP ' + response.status + '.');
  }
  return decodeLabOverview(await response.json() as unknown, days);
}
