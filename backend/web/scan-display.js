'use strict';
// Lab SOC scan status presenter. Raw API fields are untrusted; the renderer must
// HTML-escape ALL returned strings. No scanner/endpoint attestation exists here.
(function (root) {
  function describeScan(job) {
    const status = job && job.status;
    const verdict = job && job.verdict;
    const name = job && typeof job.threat_name === 'string' ? job.threat_name.trim() : '';
    const out = (heading, explanation, tone) => ({heading, explanation, tone, attested: false});
    switch (status) {
      case 'queued': return out('Queued', 'Request recorded; endpoint execution has not been observed.', 'neutral');
      case 'leased': return out('Leased', 'A lab worker claimed the job; completion is not reported.', 'warning');
      case 'expired': return out('Expired', 'The request expired without an accepted completion.', 'warning');
      case 'failed':
        if (verdict === 'unscanned') return out('Unscanned', 'Worker reported that this scan was not performed.', 'warning');
        if (verdict === 'error') return out('Scanner error', 'Worker reported an error; the scan did not complete successfully.', 'danger');
        return out('Failed', 'No successful scan completion; inspect the reported details.', 'danger');
      case 'completed':
        // Quick/full execution is unsupported by the current lab Rust worker.
        // Refuse a successful claim even if a malformed backend response includes one.
        if ((job.scan_type === 'quick' || job.scan_type === 'full') &&
            ['clean_by_signature', 'malicious', 'suspicious'].includes(verdict)) {
          return out('Unsupported scan claim',
            'A successful quick/full scan was reported, but this lab worker does not implement these modes. The result is not scanning evidence.', 'danger');
        }
        // Job completion is transport state, not a successful scanner attestation.
        if (verdict === 'error') return out('Scanner error', 'Job delivery completed, but the worker reported a scanner error. No successful scan is established.', 'danger');
        if (verdict === 'unscanned') return out('Unscanned', 'Job delivery completed, but the requested scan was not performed. No protection is established.', 'warning');
        if (verdict === 'malicious') return out('Signature match reported', name
          ? `Lab worker reported signature: ${name}. Not independently attested.`
          : 'Malicious verdict reported without a signature name; investigate data integrity.', 'danger');
        if (verdict === 'clean_by_signature') return out('Clean by signature (reported)',
          'No signature matched in the claimed scan. This is not proof the file or endpoint is safe.', 'neutral');
        if (verdict === 'suspicious') return out('Suspicious (reported)',
          'Unconfirmed suspicious result. Analyst review required.', 'warning');
        return out('Result not verified', 'Completion lacks a recognized successful scan verdict.', 'warning');
      default: return out('Unknown job state', 'The backend returned an unrecognized state; do not infer protection.', 'warning');
    }
  }
  function scanEngineEvidence(job) {
    const reported = value => typeof value === 'string' && value.trim() ? value.trim() : 'not reported';
    const engine = reported(job && job.engine);
    const version = reported(job && job.engine_version);
    const database = reported(job && job.database_version);
    return `Claimed engine: ${engine}; engine version: ${version}; signature DB version: ${database}. Authenticity and freshness NOT VERIFIED.`;
  }
  const publicAPI = Object.freeze({describeScan, scanEngineEvidence});
  if (typeof module !== 'undefined' && module.exports) module.exports = publicAPI;
  if (root) root.TuranScanDisplay = publicAPI;
})(typeof globalThis === 'undefined' ? null : globalThis);
