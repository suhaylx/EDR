import type { ScanJob } from './scan-state.js';

// Untrusted lab API data must be validated before reaching React components.
// This is NOT production tenant authorization, endpoint attestation or a
// validated signature result. The Go API exposes these as reported fields.
type JsonRecord = Record<string, unknown>;
const isObject = (value: unknown): value is JsonRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const isText = (value: unknown): value is string => typeof value === 'string';
const optionalText = (value: unknown): boolean => value === undefined || value === null || isText(value);
const required = ['id', 'agent_id', 'status'] as const;
const optional = ['verdict', 'scan_type', 'created_at', 'engine', 'engine_version', 'database_version', 'threat_name', 'detail'] as const;
const maxLength: Record<string,number> = {
  id: 160, agent_id: 96, status: 40, verdict: 64,
  scan_type: 32, created_at: 64, engine: 128,
  engine_version: 96, database_version: 96, threat_name: 256, detail: 1024,
};
const safeField = (name: string, value: unknown): boolean => {
  const limit = maxLength[name];
  return typeof value === 'string' && limit !== undefined && value.length <= limit &&
    !/[\x00-\x1f\x7f]/.test(value);
};

export type LabScanJob = ScanJob & { scan_type?: string; created_at?: string };

export function decodeScanJobs(value: unknown): LabScanJob[] {
  if (!Array.isArray(value)) throw new Error('Malformed lab scan response: expected a list.');
  if (value.length > 5000) throw new Error('Lab scan response exceeds the read-only UI limit.');
  const seen = new Set<string>();
  return value.map((item: unknown, index: number): LabScanJob => {
    if (!isObject(item) || required.some(k => !isText(item[k])) || optional.some(k => !optionalText(item[k]))) {
      throw new Error('Malformed scan job at record ' + (index + 1) + '.');
    }
    // Bound untrusted strings before they reach React or browser accessibility
    // labels. Duplicate IDs cannot identify a unique retained job.
    for (const k of required) {
      if (!safeField(k,item[k]) || !(item[k] as string).trim()) {
        throw new Error('Malformed scan job at record ' + (index + 1) + '.');
      }
    }
    for (const k of optional) {
      if (item[k] !== undefined && item[k] !== null && !safeField(k,item[k])) {
        throw new Error('Malformed scan job at record ' + (index + 1) + '.');
      }
    }
    const id = item.id as string;
    if (seen.has(id)) throw new Error('Duplicate lab scan job ID in response.');
    seen.add(id);
    const created = item.created_at;
    if (typeof created === 'string' && created !== '' &&
      (!/^\d{4}-\d\d-\d\dT/.test(created) || !Number.isFinite(Date.parse(created)))) {
      throw new Error('Invalid lab scan job UTC timestamp at record ' + (index + 1));
    }
    // Preserve server-reported fields without inventing missing metadata.
    const get = (k: string) => isText(item[k]) ? item[k] as string : undefined;
    return {
      id: item.id as string,
      agent_id: item.agent_id as string,
      status: item.status as string,
      verdict: get('verdict'),
      scan_type: get('scan_type'),
      created_at: get('created_at'),
      engine: get('engine'),
      engine_version: get('engine_version'),
      database_version: get('database_version'),
      threat_name: get('threat_name'),
      detail: get('detail'),
    };
  });
}

export async function fetchLabScanJobs(
  token: string, signal?: AbortSignal, fetcher: typeof fetch = fetch,
): Promise<LabScanJob[]> {
  if (token.length < 16) throw new Error('The development token must contain at least 16 characters.');
  const response = await fetcher('/api/scan-jobs', {
    method: 'GET',
    headers: { Authorization: 'Bearer ' + token },
    credentials: 'omit',
    cache: 'no-store',
    signal,
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Development token rejected (HTTP 401).');
    throw new Error('Lab scan API returned HTTP ' + response.status + '.');
  }
  return decodeScanJobs(await response.json() as unknown);
}
