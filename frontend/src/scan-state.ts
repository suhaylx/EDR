/** Lab API scan job interpretation. Display-only; never authorizes endpoint actions. */
export type JobStatus = 'queued' | 'leased' | 'completed' | 'failed' | 'expired';
export type ScanVerdict = 'clean_by_signature' | 'malicious' | 'suspicious' | 'error' | 'unscanned';
export type ScanJob = {
  id: string;
  agent_id: string;
  status: JobStatus | string;
  verdict?: ScanVerdict | string;
  scan_type?: string;
  engine?: string;
  engine_version?: string;
  database_version?: string;
  threat_name?: string; // legacy lab decoder only; never displayed verbatim
  detail?: string; // legacy lab decoder only; never displayed verbatim
  signature_reported?: boolean; // metadata-only Go endpoint, not attested
};
export type ScanDisplay = { heading: string; explanation: string; tone: 'neutral' | 'warning' | 'danger'; attested: false };

/** The dev bearer-token API provides CLAIMED scan results, not scanner attestation. */
export function describeScan(job: ScanJob): ScanDisplay {
  const common = { attested: false as const };
  switch (job.status) {
    case 'queued': return { ...common, heading: 'Queued', explanation: 'Request recorded; endpoint execution has not been observed.', tone: 'neutral' };
    case 'leased': return { ...common, heading: 'Leased', explanation: 'A lab worker claimed the job; completion is not reported.', tone: 'warning' };
    case 'expired': return { ...common, heading: 'Expired', explanation: 'The request expired without an accepted completion.', tone: 'warning' };
    case 'failed':
      if (job.verdict === 'unscanned') return { ...common, heading: 'Unscanned', explanation: 'Worker reported that this scan was not performed.', tone: 'warning' };
      if (job.verdict === 'error') return { ...common, heading: 'Scanner error', explanation: 'Worker reported an error; the scan did not complete successfully.', tone: 'danger' };
      return { ...common, heading: 'Failed', explanation: 'No successful scan completion; inspect the reported details.', tone: 'danger' };
    case 'completed':
      // Defense in depth for stale/forged lab responses: the Rust lab worker
      // implements path only. Go currently rejects quick/full success claims,
      // but the read-only UI must not promote inconsistent source responses.
      if ((job.scan_type === 'quick' || job.scan_type === 'full') &&
        ['clean_by_signature', 'malicious', 'suspicious'].includes(job.verdict || '')) {
        return { ...common, heading: 'Unsupported scan claim', explanation: 'This lab worker does not implement quick/full scanning. A claimed successful verdict is inconsistent and not scan evidence.', tone: 'danger' };
      }
      // A completed job can still report a failed or unsupported scanner run.
      // Delivery completion never certifies scan execution or protection.
      if (job.verdict === 'error') return { ...common, heading: 'Scanner error', explanation: 'Job delivery completed, but the worker reported a scanner error. No successful scan is established.', tone: 'danger' };
      if (job.verdict === 'unscanned') return { ...common, heading: 'Unscanned', explanation: 'Job delivery completed, but the requested scan was not performed. No protection is established.', tone: 'warning' };
      if (job.verdict === 'malicious') return { ...common, heading: 'Signature match reported', explanation: (job.signature_reported || job.threat_name?.trim()) ? 'Lab worker reported a signature match; signature name withheld. Not independently attested.' : 'Malicious verdict reported without a signature indicator; investigate data integrity.', tone: 'danger' };
      if (job.verdict === 'clean_by_signature') return { ...common, heading: 'Clean by signature (reported)', explanation: 'No signature matched in the claimed scan. This is not proof the file or endpoint is safe.', tone: 'neutral' };
      if (job.verdict === 'suspicious') return { ...common, heading: 'Suspicious (reported)', explanation: 'Unconfirmed suspicious result. Analyst review required.', tone: 'warning' };
      return { ...common, heading: 'Result not verified', explanation: 'Completion lacks a recognized successful scan verdict.', tone: 'warning' };
    default: return { ...common, heading: 'Unknown job state', explanation: 'The backend returned an unrecognized state; do not infer protection.', tone: 'warning' };
  }
}

export function scanEngineEvidence(job: ScanJob): string {
  const engine = job.engine?.trim() || 'not reported';
  const version = job.engine_version?.trim() || 'not reported';
  const database = job.database_version?.trim() || 'not reported';
  return `Claimed engine: ${engine}; engine version: ${version}; signature DB version: ${database}. Authenticity and freshness NOT VERIFIED.`;
}
