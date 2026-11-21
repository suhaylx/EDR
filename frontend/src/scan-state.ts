/** Lab API scan job interpretation. Display-only; never authorizes endpoint actions. */
export type JobStatus = 'queued' | 'leased' | 'completed' | 'failed' | 'expired';
export type ScanVerdict = 'clean_by_signature' | 'malicious' | 'suspicious' | 'error' | 'unscanned';
export type ScanJob = {
  id: string;
  agent_id: string;
  status: JobStatus | string;
  verdict?: ScanVerdict | string;
  engine?: string;
  engine_version?: string;
  database_version?: string;
  threat_name?: string;
  detail?: string;
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
      if (job.verdict === 'malicious') return { ...common, heading: 'Signature match reported', explanation: job.threat_name?.trim() ? `Lab worker reported signature: ${job.threat_name}. Not independently attested.` : 'Malicious verdict reported without a signature name; investigate data integrity.', tone: 'danger' };
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
