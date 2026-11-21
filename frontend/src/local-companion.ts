/**
 * Proposed read-only local companion IPC v1 payload.
 * This is a frontend contract prototype, NOT an implemented Rust IPC channel.
 * The UI process must never decide or override Rust agent policy.
 */
export type LocalPlatform = 'windows' | 'linux';
export type ReportedComponentState = 'reported_available' | 'reported_unavailable' | 'unknown';
export type ReportedScanState = 'queued' | 'leased' | 'completed' | 'failed' | 'expired' | 'unknown';
export type LocalCompanionSnapshot = {
  schema_version: 1;
  source: 'local_agent_ipc_v1';
  platform: LocalPlatform;
  observed_at: string;
  core_state: 'reported_running' | 'reported_degraded' | 'reported_stopped' | 'unknown';
  clamav_state: ReportedComponentState;
  telemetry_state: ReportedComponentState;
  policy_revision: number | null;
  scan_state: ReportedScanState;
};
type JsonObject = Record<string, unknown>;
const isObject = (x: unknown): x is JsonObject =>
  x !== null && typeof x === 'object' && !Array.isArray(x);
const enumeration = <T extends string>(value: unknown, allowed: readonly T[], field: string): T => {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new Error('Invalid local status field: ' + field);
  }
  return value as T;
};

/** Parse unknown IPC data without trusting health, origin, or policy compliance. */
export function decodeLocalCompanionSnapshot(input: unknown): LocalCompanionSnapshot {
  if (!isObject(input)) throw new Error('Invalid local status payload');
  if (input.schema_version !== 1 || input.source !== 'local_agent_ipc_v1') {
    throw new Error('Unsupported local companion status contract');
  }
  const observed = input.observed_at;
  if (typeof observed !== 'string' || observed.length > 40 ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(observed) ||
      !Number.isFinite(Date.parse(observed))) {
    throw new Error('Invalid local companion timestamp');
  }
  const revision = input.policy_revision;
  if (revision !== null && (typeof revision !== 'number' ||
      !Number.isSafeInteger(revision) || revision < 0)) {
    throw new Error('Invalid reported policy revision');
  }
  return {
    schema_version: 1,
    source: 'local_agent_ipc_v1',
    platform: enumeration(input.platform, ['windows', 'linux'], 'platform'),
    observed_at: observed,
    core_state: enumeration(input.core_state,
      ['reported_running', 'reported_degraded', 'reported_stopped', 'unknown'], 'core_state'),
    clamav_state: enumeration(input.clamav_state,
      ['reported_available', 'reported_unavailable', 'unknown'], 'clamav_state'),
    telemetry_state: enumeration(input.telemetry_state,
      ['reported_available', 'reported_unavailable', 'unknown'], 'telemetry_state'),
    policy_revision: revision as number | null,
    scan_state: enumeration(input.scan_state,
      ['queued', 'leased', 'completed', 'failed', 'expired', 'unknown'], 'scan_state'),
  };
}

export type LocalCompanionPresentation = {
  status: 'unavailable' | 'stale' | 'reported';
  heading: string;
  explanation: string;
};

/** All missing, future-dated or stale records fail closed to UNKNOWN coverage. */
export function localCompanionPresentation(
  snapshot: LocalCompanionSnapshot | null, nowMs: number, maxAgeMs = 60_000,
): LocalCompanionPresentation {
  if (!snapshot) return {
    status: 'unavailable',
    heading: 'Local agent status unavailable',
    explanation: 'No authenticated local IPC session is available. Protection and scan coverage are unknown.',
  };
  const age = nowMs - Date.parse(snapshot.observed_at);
  if (!Number.isFinite(nowMs) || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0 ||
      !Number.isFinite(age) || age < 0 || age > maxAgeMs) {
    return {
      status: 'stale',
      heading: 'Local agent status not current',
      explanation: 'The local status timestamp is stale, future-dated, or cannot be trusted. Protection is unknown.',
    };
  }
  return {
    status: 'reported',
    heading: 'Recent local agent report (not attested)',
    explanation: 'Component and scan states are reported status only; they do not attest endpoint protection, signature freshness, or policy enforcement.',
  };
}

/**
 * Presentation rows are derived from a confirmed recent report only.
 * Stale or missing snapshots must not leak previous positive-looking statuses.
 * This function does not authenticate IPC; its caller must do so separately.
 */
export type LocalCompanionRow = {
  key: string;
  label: string;
  value: string;
  detail: string;
};
const unknown = (key: string, label: string): LocalCompanionRow => ({
  key, label, value: 'Unknown', detail: 'No current authenticated local status.',
});

export function localCompanionRows(
  snapshot: LocalCompanionSnapshot | null, nowMs: number,
): LocalCompanionRow[] {
  const current = localCompanionPresentation(snapshot, nowMs);
  if (current.status !== 'reported' || !snapshot) {
    return [
      unknown('core', 'TuranSec Rust core'),
      unknown('clamav', 'ClamAV scanner'),
      unknown('telemetry', 'Endpoint telemetry'),
      unknown('policy', 'Policy acknowledgement'),
      unknown('scan', 'Last reported scan job'),
      unknown('timestamp', 'Last status report'),
    ];
  }
  const core: Record<LocalCompanionSnapshot['core_state'], string> = {
    reported_running: 'Running (reported)',
    reported_degraded: 'Degraded (reported)',
    reported_stopped: 'Stopped (reported)',
    unknown: 'Unknown',
  };
  const component: Record<ReportedComponentState, string> = {
    reported_available: 'Available (reported)',
    reported_unavailable: 'Unavailable (reported)',
    unknown: 'Unknown',
  };
  const scan: Record<ReportedScanState, string> = {
    queued: 'Queued — not yet scanned',
    leased: 'Leased — result pending',
    completed: 'Completed (reported) — verdict unavailable',
    failed: 'Failed (reported) — no valid verdict',
    expired: 'Expired (reported) — no valid verdict',
    unknown: 'Unknown — no scan result evidence',
  };
  return [
    {key: 'core', label: 'TuranSec Rust core', value: core[snapshot.core_state],
      detail: 'A local status report is not proof of tamper resistance or active protection.'},
    {key: 'clamav', label: 'ClamAV scanner', value: component[snapshot.clamav_state],
      detail: 'Engine execution, signatures, database freshness and file safety are not attested.'},
    {key: 'telemetry',
      label: snapshot.platform === 'windows' ? 'Windows Sysmon telemetry' : 'Linux telemetry collector',
      value: component[snapshot.telemetry_state],
      detail: 'Collector readiness, event loss and required event coverage are not attested.'},
    {key: 'policy', label: 'Policy acknowledgement',
      value: snapshot.policy_revision === null || snapshot.policy_revision === 0
        ? 'Revision unknown or zero' : 'Revision ' + snapshot.policy_revision + ' (reported)',
      detail: 'Applied revision is not an authenticated policy enforcement confirmation.'},
    {key: 'scan', label: 'Last reported scan job', value: scan[snapshot.scan_state],
      detail: 'A job lifecycle state is not a verified malware verdict or endpoint safety claim.'},
    {key: 'timestamp', label: 'Last status report', value: snapshot.observed_at,
      detail: 'Wall-clock time alone is not replay resistance or transport authentication.'},
  ];
}
