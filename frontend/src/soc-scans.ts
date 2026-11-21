import { socRecord, socIdentity, socUUID, socText, socTimestamp, socCount, socPage, type SOCPage } from './soc-contract.js';

export type SOCJobState = 'pending' | 'leased' | 'succeeded' | 'failed' | 'cancelled';
export type SOCScanJob = Readonly<{
  job_id: string; agent_id: string; scan_root: string; state: SOCJobState;
  attempt_count: number; created_at: string; updated_at: string;
}>;
export type SOCScanResult = Readonly<{
  job_id: string; agent_id: string; engine: 'clamav';
  verdict: 'malicious' | 'clean_by_signature' | 'error' | 'unscanned';
  threat_name: string; detail: string; observed_at: string;
}>;
export type SOCScanStats = Readonly<{
  total: number; pending: number; leased: number; succeeded: number; failed: number; cancelled: number; malicious: number;
}>;
export type SOCScanDetail = Readonly<{ job: SOCScanJob; result: SOCScanResult | null }>;

export function newSOCScanRequestID(): string {
  if (typeof globalThis.crypto?.randomUUID !== 'function') throw new Error('A secure random request key is unavailable; no scan was requested');
  return globalThis.crypto.randomUUID();
}

export function socBoundedInput(value: unknown, maxBytes: number, allowEmpty = false): string {
  const text = socText(value, maxBytes, allowEmpty);
  if (new TextEncoder().encode(text).byteLength > maxBytes) throw new Error('Text exceeds the UTF-8 byte limit');
  return text;
}

/** Match the existing Go path-only contract; never invent quick/full scan profiles. */
export function validateSOCScanPath(platform: 'windows' | 'linux', value: unknown): string {
  const path = socBoundedInput(value, 512);
  if (platform === 'windows') {
    if (!/^[A-Za-z]:\\/.test(path) || path.includes('/')) throw new Error('Use an absolute Windows drive path');
    for (const part of path.slice(3).split('\\')) {
      const base = part.split('.')[0]?.trim().toUpperCase() ?? '';
      if (!part || part === '.' || part === '..' || /[. ]$/.test(part) || /[<>:"|?*]/.test(part) ||
          ['CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'].includes(base) || /^(COM|LPT)[1-9¹²³]$/.test(base)) {
        throw new Error('Use an ordinary local Windows file or directory path');
      }
    }
  } else if (platform !== 'linux' || !path.startsWith('/') || path === '/' || path.slice(1).split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error('Use a normalized absolute Linux file or directory path other than /');
  }
  return path;
}

export function decodeSOCScanJob(value: unknown): SOCScanJob {
  const job = socRecord(value);
  const state = socText(job.state, 16);
  if (!['pending', 'leased', 'succeeded', 'failed', 'cancelled'].includes(state)) throw new Error('Invalid scan delivery state');
  const created_at = socTimestamp(job.created_at);
  const updated_at = socTimestamp(job.updated_at);
  if (Date.parse(updated_at) < Date.parse(created_at)) throw new Error('Invalid scan chronology');
  return {
    job_id: socUUID(job.job_id), agent_id: socIdentity(job.agent_id), scan_root: socBoundedInput(job.scan_root, 4096),
    state: state as SOCJobState, attempt_count: socCount(job.attempt_count), created_at, updated_at,
  };
}
export const decodeSOCScanJobs = (value: unknown): SOCPage<SOCScanJob> => socPage(value, decodeSOCScanJob, job => job.job_id);

export function decodeSOCScanResult(value: unknown): SOCScanResult {
  const result = socRecord(value);
  if (result.engine !== 'clamav' || !['malicious', 'clean_by_signature', 'error', 'unscanned'].includes(String(result.verdict))) throw new Error('Invalid scan result');
  const threat_name = socBoundedInput(result.threat_name, 256, true);
  if ((result.verdict === 'malicious' && !threat_name.trim()) || (result.verdict !== 'malicious' && threat_name !== '')) throw new Error('Conflicting scan verdict');
  return {
    job_id: socUUID(result.job_id), agent_id: socIdentity(result.agent_id), engine: 'clamav',
    verdict: result.verdict as SOCScanResult['verdict'], threat_name,
    detail: socBoundedInput(result.detail, 1024, true), observed_at: socTimestamp(result.observed_at),
  };
}
export const decodeSOCScanResults = (value: unknown): SOCPage<SOCScanResult> => socPage(value, decodeSOCScanResult, result => result.job_id);

export function decodeSOCScanStats(value: unknown): SOCScanStats {
  const stats = socRecord(value);
  const keys = ['total', 'pending', 'leased', 'succeeded', 'failed', 'cancelled', 'malicious'] as const;
  const result = Object.fromEntries(keys.map(key => [key, socCount(stats[key])])) as unknown as SOCScanStats;
  if (result.pending + result.leased + result.succeeded + result.failed + result.cancelled !== result.total) throw new Error('Unreconciled scan delivery counts');
  // Malicious results are counted by a separate query and are not a safe-health count.
  return result;
}

export function socVerdictLabel(verdict: SOCScanResult['verdict']): string {
  switch (verdict) {
    case 'malicious': return 'Signature match reported; not independently attested';
    case 'clean_by_signature': return 'No signature match reported; endpoint safety is unknown';
    case 'error': return 'Scanner error reported; scan coverage is unknown';
    case 'unscanned': return 'Not scanned; endpoint condition is unknown';
  }
}
