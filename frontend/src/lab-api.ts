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

export type LabScanJob = ScanJob & { scan_type?: string; created_at?: string };

export function decodeScanJobs(value: unknown): LabScanJob[] {
  if (!Array.isArray(value)) throw new Error('Malformed lab scan response: expected a list.');
  if (value.length > 5000) throw new Error('Lab scan response exceeds the read-only UI limit.');
  return value.map((item: unknown, index: number): LabScanJob => {
    if (!isObject(item) || required.some(k => !isText(item[k])) || optional.some(k => !optionalText(item[k]))) {
      throw new Error('Malformed scan job at record ' + (index + 1) + '.');
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
