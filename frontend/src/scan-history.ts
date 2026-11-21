/** Presentation-only filtering of untrusted, lab-reported scan jobs.
 * Filtering does not request more work, attest a result, or change endpoint state. */
import type { LabScanJob } from './lab-api.js';

export type ScanHistoryFilter =
  'all' | 'pending' | 'failed_or_error' | 'unscanned' | 'reported_match' | 'signature_negative' | 'unrecognized';

export function scanFilterMatches(job: LabScanJob, filter: ScanHistoryFilter): boolean {
  // Current lab worker reports quick/full as unscanned: a "successful" claim
  // for either mode is inconsistent and must not enter signature categories.
  const unsupportedSuccess = (job.scan_type === 'quick' || job.scan_type === 'full') &&
    job.status === 'completed' &&
    ['clean_by_signature', 'malicious', 'suspicious'].includes(job.verdict || '');
  switch (filter) {
    case 'all': return true;
    case 'pending': return job.status === 'queued' || job.status === 'leased';
    case 'failed_or_error': return job.status === 'failed' || job.status === 'expired' || job.verdict === 'error';
    case 'unscanned': return job.verdict === 'unscanned';
    case 'reported_match': return !unsupportedSuccess && job.status === 'completed' && job.verdict === 'malicious';
    case 'signature_negative': return !unsupportedSuccess && job.status === 'completed' && job.verdict === 'clean_by_signature';
    case 'unrecognized': {
      if (!['queued', 'leased', 'failed', 'expired', 'completed'].includes(job.status)) return true;
      if (job.status === 'completed') {
        return unsupportedSuccess || !['malicious', 'suspicious', 'clean_by_signature'].includes(job.verdict || '');
      }
      return false;
    }
  }
}

export function filterScanHistory(jobs: readonly LabScanJob[], filter: ScanHistoryFilter, query: string): LabScanJob[] {
  // Search only returned metadata, never device contents or remote data.
  const needle = query.trim().toLocaleLowerCase();
  return jobs.filter(job => {
    if (!scanFilterMatches(job, filter)) return false;
    if (!needle) return true;
    return [job.id, job.agent_id, job.status, job.verdict, job.scan_type, job.created_at,
      job.engine, job.engine_version, job.database_version, job.threat_name, job.detail]
      .some(value => (value || '').toLocaleLowerCase().includes(needle));
  });
}
