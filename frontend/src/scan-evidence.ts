/** Read-only scan-evidence triage over the in-memory lab queue.
 * No scan trigger, endpoint execution, signature attestation or tenant isolation.
 * Future real quick/full worker support requires Agent 1/2/3 gated contract change.
 */
import type { LabScanJob } from './lab-api.js';

export type ScanKind =
  'queued'|'leased'|'expired'|'failed'|'scanner_error'|'unscanned'|
  'unsupported_claim'|'reported_match'|'reported_suspicious'|
  'signature_negative'|'unverified_completion'|'unknown_state';
export type ScanFilter =
  'all'|'attention'|'pending'|'failed_or_error'|'unscanned'|'unsupported_claim'|
  'reported_match'|'signature_negative'|'suspicious'|'unknown';
export type ScanModeFilter = 'all'|'path'|'quick'|'full'|'other';
export type MetadataFilter = 'all'|'missing'|'complete';
export type ScanSort = 'newest'|'oldest'|'endpoint'|'mode'|'classification';
export type ScanPageSize = 25|50|100;

const positiveVerdict = (v: string|undefined) =>
  v === 'malicious' || v === 'suspicious' || v === 'clean_by_signature';

export function scanEvidenceKind(job: LabScanJob): ScanKind {
  if (job.status === 'queued') return 'queued';
  if (job.status === 'leased') return 'leased';
  if (job.status === 'expired') return 'expired';
  if (job.status === 'failed') {
    if (job.verdict === 'error') return 'scanner_error';
    if (job.verdict === 'unscanned') return 'unscanned';
    return 'failed';
  }
  if (job.status !== 'completed') return 'unknown_state';
  // Lab Rust worker does not implement quick/full. The Go API currently
  // rejects the claims, but frontend must fail closed on inconsistent rows.
  if ((job.scan_type === 'quick' || job.scan_type === 'full') &&
    positiveVerdict(job.verdict)) return 'unsupported_claim';
  if (job.verdict === 'error') return 'scanner_error';
  if (job.verdict === 'unscanned') return 'unscanned';
  // Do not classify successful signature evidence if mode is not a path scan.
  if (job.scan_type !== 'path') return 'unverified_completion';
  if (job.verdict === 'malicious' && job.threat_name?.trim()) return 'reported_match';
  if (job.verdict === 'suspicious') return 'reported_suspicious';
  if (job.verdict === 'clean_by_signature') return 'signature_negative';
  return 'unverified_completion';
}

export const SCAN_KIND_LABELS: Readonly<Record<ScanKind,string>> = {
  queued:'Queued (no execution observed)',
  leased:'Leased (no result accepted)',
  expired:'Expired without completion',
  failed:'Failed (no valid scan verdict)',
  scanner_error:'Scanner error (reported)',
  unscanned:'Unscanned (reported)',
  unsupported_claim:'Unsupported quick/full success claim',
  reported_match:'Reported signature match — not attested',
  reported_suspicious:'Reported suspicious result — not attested',
  signature_negative:'Reported signature-negative — not proof of safety',
  unverified_completion:'Completed delivery — evidence insufficient',
  unknown_state:'Unknown job state — no protection inferred',
};
export type ScanFlag =
  'quick_full_success_unsupported'|'completed_without_path_mode'|
  'completed_without_verdict'|'malicious_without_signature'|
  'unexpected_threat_name'|'positive_verdict_without_completed_status'|
  'engine_missing'|'engine_version_missing'|'database_version_missing'|
  'created_time_missing'|'unrecognized_mode'|'unrecognized_state'|
  'unrecognized_verdict';

export const SCAN_FLAG_LABELS: Readonly<Record<ScanFlag,string>> = {
  quick_full_success_unsupported:'Quick/full reported success, but this lab worker has no such capability',
  completed_without_path_mode:'Successful-looking completion lacks a supported path mode',
  completed_without_verdict:'Completed job has no usable verdict',
  malicious_without_signature:'Malicious result reported without a named signature',
  unexpected_threat_name:'Signature name supplied for a non-malicious verdict',
  positive_verdict_without_completed_status:'Successful-looking verdict conflicts with non-completed job state',
  engine_missing:'Reported scan engine missing',
  engine_version_missing:'Reported scan engine version missing',
  database_version_missing:'Reported signature database version missing',
  created_time_missing:'Job creation time missing or unrecognized',
  unrecognized_mode:'Scan mode is not one of quick, full or path',
  unrecognized_state:'Job state not recognized',
  unrecognized_verdict:'Verdict value not recognized',
};
const knownVerdicts = new Set(['malicious','suspicious','clean_by_signature','error','unscanned']);
const knownModes = new Set(['path','quick','full']);
const knownStatuses = new Set(['queued','leased','completed','failed','expired']);

export function scanEvidenceFlags(job: LabScanJob): ScanFlag[] {
  const flags: ScanFlag[]=[];
  const completed = job.status === 'completed';
  if (completed && (job.scan_type === 'quick'||job.scan_type === 'full') &&
    positiveVerdict(job.verdict)) flags.push('quick_full_success_unsupported');
  if (completed && positiveVerdict(job.verdict) && job.scan_type !== 'path')
    flags.push('completed_without_path_mode');
  if (completed && (!job.verdict?.trim())) flags.push('completed_without_verdict');
  if (job.verdict === 'malicious' && !job.threat_name?.trim())
    flags.push('malicious_without_signature');
  if (job.threat_name?.trim() && job.verdict !== 'malicious')
    flags.push('unexpected_threat_name');
  if (!completed && positiveVerdict(job.verdict))
    flags.push('positive_verdict_without_completed_status');
  // Metadata completeness only applies when claiming an actual scan result;
  // queued/unscanned/error cases must not be treated as scanner-health claims.
  if (completed && positiveVerdict(job.verdict)) {
    if (!job.engine?.trim()) flags.push('engine_missing');
    if (!job.engine_version?.trim()) flags.push('engine_version_missing');
    if (!job.database_version?.trim()) flags.push('database_version_missing');
  }
  if (!job.created_at || !Number.isFinite(Date.parse(job.created_at)))
    flags.push('created_time_missing');
  if (!job.scan_type || !knownModes.has(job.scan_type))
    flags.push('unrecognized_mode');
  if (!knownStatuses.has(job.status)) flags.push('unrecognized_state');
  if (job.verdict && !knownVerdicts.has(job.verdict))
    flags.push('unrecognized_verdict');
  return flags;
}

export function scanNeedsAttention(job: LabScanJob): boolean {
  const kind=scanEvidenceKind(job);
  return ['expired','failed','scanner_error','unscanned','unsupported_claim',
    'unverified_completion','unknown_state'].includes(kind) ||
    scanEvidenceFlags(job).length>0;
}
export type ScanQuery = Readonly<{
  kind:ScanFilter;
  mode:ScanModeFilter;
  metadata:MetadataFilter;
  endpoint:string;
  search:string;
}>;

export const DEFAULT_SCAN_QUERY:ScanQuery = {
  kind:'all',mode:'all',metadata:'all',endpoint:'',search:'',
};

export function filterReportedScanJobs(
  jobs: readonly LabScanJob[], query:ScanQuery,
): LabScanJob[] {
  const endpoint=query.endpoint.trim().toLocaleLowerCase();
  const needle=query.search.trim().toLocaleLowerCase();
  return jobs.filter(job=>{
    const kind=scanEvidenceKind(job);
    if(query.kind==='attention' && !scanNeedsAttention(job))return false;
    if(query.kind==='pending' && kind!=='queued' && kind!=='leased')return false;
    if(query.kind==='failed_or_error' && job.status!=='failed' &&
      !['expired','failed','scanner_error'].includes(kind))return false;
    if(query.kind==='unscanned' && kind!=='unscanned')return false;
    if(query.kind==='unsupported_claim' && kind!=='unsupported_claim')return false;
    if(query.kind==='reported_match' && kind!=='reported_match')return false;
    if(query.kind==='signature_negative' && kind!=='signature_negative')return false;
    if(query.kind==='suspicious' && kind!=='reported_suspicious')return false;
    if(query.kind==='unknown' &&
      kind!=='unverified_completion' && kind!=='unknown_state')return false;
    if(query.mode!=='all' &&
      (query.mode==='other' ? ['quick','full','path'].includes(job.scan_type||'')
        : job.scan_type!==query.mode))return false;
    if(query.metadata==='missing' && scanEvidenceFlags(job).length===0)return false;
    if(query.metadata==='complete' && scanEvidenceFlags(job).length>0)return false;
    if(endpoint && job.agent_id.trim().toLocaleLowerCase()!==endpoint)return false;
    return !needle || [job.id,job.agent_id,job.status,job.verdict,
      job.scan_type,job.created_at,job.engine,job.engine_version,
      job.database_version,job.threat_name,job.detail].some(v=>
      (v||'').toLocaleLowerCase().includes(needle));
  });
}

const byTime=(job:LabScanJob):number => job.created_at ? Date.parse(job.created_at) : NaN;
const textCmp=(a:string,b:string):number => a.localeCompare(b,'en',{sensitivity:'base'});
const priority:Readonly<Record<ScanKind,number>>={
  unsupported_claim:0,scanner_error:1,failed:2,expired:3,
  unverified_completion:4,unknown_state:5,unscanned:6,
  reported_match:7,reported_suspicious:8,signature_negative:9,
  leased:10,queued:11,
};
export function sortReportedScanJobs(jobs:readonly LabScanJob[],sort:ScanSort):LabScanJob[] {
  return [...jobs].sort((a,b)=>{
    const ta=byTime(a), tb=byTime(b);
    const missingA=!Number.isFinite(ta), missingB=!Number.isFinite(tb);
    const newest = missingA!==missingB ? (missingA?1:-1)
      : (missingA?0:tb-ta);
    let leading:number=0;
    switch(sort){
      case 'newest':leading=newest;break;
      case 'oldest':leading=missingA!==missingB?(missingA?1:-1):(missingA?0:ta-tb);break;
      case 'endpoint':leading=textCmp(a.agent_id,b.agent_id);break;
      case 'mode':leading=textCmp(a.scan_type||'',b.scan_type||'');break;
      case 'classification':leading=priority[scanEvidenceKind(a)]-priority[scanEvidenceKind(b)];break;
    }
    return leading || newest || textCmp(a.id,b.id);
  });
}
export function paginateReportedScanJobs(
  jobs:readonly LabScanJob[],page:number,size:ScanPageSize,
) {
  if(!Number.isSafeInteger(page)||![25,50,100].includes(size))
    throw new Error('Invalid local scan page controls');
  const pages=Math.max(1,Math.ceil(jobs.length/size));
  const index=Math.min(Math.max(page,0),pages-1);
  return {rows:jobs.slice(index*size,(index+1)*size),total:jobs.length,
    page:index,pages,start:jobs.length?index*size+1:0,
    end:Math.min(jobs.length,(index+1)*size)};
}

export function summarizeReportedScanJobs(jobs:readonly LabScanJob[]) {
  const kinds: Record<ScanKind,number>={
    queued:0,leased:0,expired:0,failed:0,scanner_error:0,unscanned:0,
    unsupported_claim:0,reported_match:0,reported_suspicious:0,
    signature_negative:0,unverified_completion:0,unknown_state:0,
  };
  let attention=0,metadataGaps=0;
  for(const job of jobs){
    kinds[scanEvidenceKind(job)]++;
    if(scanNeedsAttention(job))attention++;
    if(scanEvidenceFlags(job).length)metadataGaps++;
  }
  return {returned:jobs.length,attention,metadataGaps,kinds};
}
