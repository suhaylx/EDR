/**
 * Read-only classification of untrusted lab scan-job reports.
 *
 * Current Go/Rust laboratory contract executes path scans only.
 * Quick/full success claims and unrecognized modes are *not* malware evidence.
 * No field here authenticates endpoint identity, scanner, signature database,
 * tenant scope, execution, or safety. A completed job is not a completed scan.
 */
import type { LabScanJob } from './lab-api.js';
import { describeScan, isUnsupportedLabScanClaim, isUnverifiedLabScanMode } from './scan-state.js';

export type ScanEvidenceCategory =
  'queued' | 'leased' | 'expired' | 'failed' | 'scanner_error' |
  'unscanned' | 'unsupported_claim' | 'unverified_mode' |
  'signature_match' | 'signature_negative' | 'suspicious' | 'unrecognized';
export type ScanEvidenceFilter =
  'all' | 'pending' | 'needs_attention' | 'failed_expired_error' |
  'unscanned' | 'unsupported' | 'reported_match' |
  'signature_negative' | 'suspicious' | 'unrecognized';
export type ScanSort = 'newest' | 'oldest' | 'endpoint' | 'mode' | 'attention';
export type ScanPageSize = 25 | 50 | 100;
export type ScanWorklistQuery = Readonly<{
  category: ScanEvidenceFilter;
  endpoint: string;
  mode: string;
  text: string;
  sort: ScanSort;
}>;

export const INITIAL_SCAN_QUERY: ScanWorklistQuery = {
  category: 'all', endpoint: '', mode: '', text: '', sort: 'newest',
};

const successfulVerdicts = ['malicious','suspicious','clean_by_signature'];

export function classifyScanEvidence(job: LabScanJob): ScanEvidenceCategory {
  if (job.status === 'queued') return 'queued';
  if (job.status === 'leased') return 'leased';
  if (job.status === 'expired') return 'expired';
  if (job.status === 'failed') {
    if (job.verdict === 'error') return 'scanner_error';
    if (job.verdict === 'unscanned') return 'unscanned';
    return 'failed';
  }
  if (job.status !== 'completed') return 'unrecognized';
  if (isUnsupportedLabScanClaim(job)) return 'unsupported_claim';
  if (isUnverifiedLabScanMode(job)) return 'unverified_mode';
  if (job.verdict === 'error') return 'scanner_error';
  if (job.verdict === 'unscanned') return 'unscanned';
  // Only a claimed *path* completion can enter signature categories.
  if ((job.scan_type || '').trim().toLocaleLowerCase() !== 'path' &&
      successfulVerdicts.includes(job.verdict || '')) return 'unverified_mode';
  if (job.verdict === 'malicious') return 'signature_match';
  if (job.verdict === 'clean_by_signature') return 'signature_negative';
  if (job.verdict === 'suspicious') return 'suspicious';
  return 'unrecognized';
}

export function scanNeedsAttention(job: LabScanJob): boolean {
  return [
    'expired','failed','scanner_error','unscanned','unsupported_claim',
    'unverified_mode','signature_match','suspicious','unrecognized',
  ].includes(classifyScanEvidence(job));
}

const matchesCategory = (category: ScanEvidenceCategory, filter: ScanEvidenceFilter) => {
  switch (filter) {
    case 'all': return true;
    case 'pending': return category === 'queued' || category === 'leased';
    case 'needs_attention': return !['queued','leased','signature_negative'].includes(category);
    case 'failed_expired_error': return ['expired','failed','scanner_error'].includes(category);
    case 'unscanned': return category === 'unscanned';
    case 'unsupported': return category === 'unsupported_claim' || category === 'unverified_mode';
    case 'reported_match': return category === 'signature_match';
    case 'signature_negative': return category === 'signature_negative';
    case 'suspicious': return category === 'suspicious';
    case 'unrecognized': return category === 'unrecognized';
  }
};

export function filterScanEvidence(jobs: readonly LabScanJob[], query: ScanWorklistQuery): LabScanJob[] {
  const target=query.endpoint.trim().toLocaleLowerCase();
  const mode=query.mode.trim().toLocaleLowerCase();
  const needle=query.text.trim().toLocaleLowerCase();
  return jobs.filter(job => {
    if (!matchesCategory(classifyScanEvidence(job),query.category)) return false;
    if (target && job.agent_id.trim().toLocaleLowerCase() !== target) return false;
    if (mode) {
      const reportedMode=(job.scan_type || '').trim().toLocaleLowerCase();
      if (mode==='__other__' ? ['path','quick','full'].includes(reportedMode) : reportedMode!==mode) return false;
    }
    if (!needle) return true;
    // No remote search, no privileged file access; bounded in-memory metadata.
    return [
      job.id, job.agent_id, job.status, job.verdict, job.scan_type,
      job.created_at, job.engine, job.engine_version,
      job.database_version, job.threat_name, job.detail,
    ].some(value => (value || '').toLocaleLowerCase().includes(needle));
  });
}

export function scanTimestamp(job: LabScanJob): number | null {
  const reported = job.created_at?.trim();
  if (!reported || reported.length > 64 || !/^\d{4}-\d\d-\d\dT/.test(reported)) return null;
  const value = Date.parse(reported);
  return Number.isFinite(value) ? value : null;
}
const categoryPriority: Record<ScanEvidenceCategory,number> = {
  unsupported_claim:0,unverified_mode:1,signature_match:2,
  scanner_error:3,failed:4,expired:5,unscanned:6,
  suspicious:7,unrecognized:8,leased:9,queued:10,signature_negative:11,
};
const cmp = (a:string,b:string):number => a.localeCompare(b,'en',{sensitivity:'base'});
const newest = (a:LabScanJob,b:LabScanJob):number =>
  (scanTimestamp(b) ?? Number.NEGATIVE_INFINITY) -
  (scanTimestamp(a) ?? Number.NEGATIVE_INFINITY);
export function sortScanEvidence(jobs: readonly LabScanJob[], sort: ScanSort): LabScanJob[] {
  return [...jobs].sort((a,b) => {
    let primary=0;
    switch(sort) {
      case 'newest': primary=newest(a,b); break;
      case 'oldest': {
        const at=scanTimestamp(a), bt=scanTimestamp(b);
        primary=at===null ? (bt===null ? 0 : 1) : bt===null ? -1 : at-bt;
        break;
      }
      case 'endpoint': primary=cmp(a.agent_id,b.agent_id); break;
      case 'mode': primary=cmp(a.scan_type || '',b.scan_type || ''); break;
      case 'attention': primary=categoryPriority[classifyScanEvidence(a)]-
        categoryPriority[classifyScanEvidence(b)]; break;
    }
    return primary || newest(a,b) || cmp(a.agent_id,b.agent_id) || cmp(a.id,b.id);
  });
}

export type ScanPage = Readonly<{
  rows:LabScanJob[]; total:number; page:number; pageCount:number; first:number; last:number;
}>;
export function pageScanEvidence(jobs:readonly LabScanJob[],requestedPage:number,pageSize:ScanPageSize):ScanPage {
  if (!Number.isSafeInteger(requestedPage) || ![25,50,100].includes(pageSize)) {
    throw new Error('Invalid scan worklist pagination');
  }
  const pageCount=Math.max(1,Math.ceil(jobs.length/pageSize));
  const page=Math.max(0,Math.min(requestedPage,pageCount-1));
  const first=jobs.length ? page*pageSize+1 : 0;
  const last=Math.min(jobs.length,(page+1)*pageSize);
  return {rows:jobs.slice(page*pageSize,(page+1)*pageSize),
    total:jobs.length,page,pageCount,first,last};
}

export type ScanEvidenceCounts=Readonly<Record<ScanEvidenceCategory,number>>;
export function summarizeScanEvidence(jobs:readonly LabScanJob[]):ScanEvidenceCounts {
  const counts:Record<ScanEvidenceCategory,number>={
    queued:0,leased:0,expired:0,failed:0,scanner_error:0,unscanned:0,
    unsupported_claim:0,unverified_mode:0,signature_match:0,
    signature_negative:0,suspicious:0,unrecognized:0,
  };
  for(const job of jobs)counts[classifyScanEvidence(job)]++;
  return counts;
}

/** A text label is never stronger than the underlying reported scan classification. */
export function scanEvidenceLabel(job:LabScanJob):string {
  const evidence=classifyScanEvidence(job);
  if (evidence==='unverified_mode')return 'Unverified scan mode';
  if (evidence==='unsupported_claim')return 'Unsupported scan claim';
  return describeScan(job).heading;
}
