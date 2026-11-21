/** Backend scan-job lifecycle review. Inspection only: no lease capabilities,
 * raw scan path or worker secrets are retained or displayed in this model.
 */
import type {LabScanJob} from './lab-api.js';
export type LifecycleWarning='missing_created'|'missing_expiry'|'expiry_before_creation'|
 'pending_after_expiry'|'completed_without_timestamp'|'complete_before_creation'|
 'complete_after_expiry'|'pending_with_completion'|'lease_after_expiry'|
 'terminal_with_lease'|'created_after_overview'|'completion_after_overview';
export const LIFECYCLE_LABELS:Readonly<Record<LifecycleWarning,string>>={
 missing_created:'Go job creation timestamp not reported',
 missing_expiry:'Go job expiry timestamp not reported',
 expiry_before_creation:'Expiry is not later than request creation',
 pending_after_expiry:'Still queued/leased beyond reported expiry at overview generation',
 completed_without_timestamp:'Terminal job lacks completion timestamp',
 complete_before_creation:'Completion earlier than request creation',
 complete_after_expiry:'Completion later than request expiry',
 pending_with_completion:'Pending job already has a completion timestamp',
 lease_after_expiry:'Lease deadline later than job expiry',
 terminal_with_lease:'Terminal job still reports a lease deadline',
 created_after_overview:'Job creation newer than overview generation time',
 completion_after_overview:'Job completion newer than overview generation time',
};
const time=(s?:string)=>s&&Number.isFinite(Date.parse(s))?Date.parse(s):null;
export type LifecycleRow=Readonly<{
 jobID:string;endpointID:string;status:string;mode:string;
 createdAt:string;expiresAt:string;completedAt:string;
 warnings:readonly LifecycleWarning[];
}>;
export function reviewScanLifecycle(jobs:readonly LabScanJob[],generatedAt:string):LifecycleRow[]{
 const now=time(generatedAt);
 if(now===null)throw new Error('Invalid Go server overview time for lifecycle review');
 return jobs.map(job=>{
  const created=time(job.created_at),expires=time(job.expires_at),
    completed=time(job.completed_at),lease=time(job.lease_until);
  const terminal=['completed','failed','expired'].includes(job.status);
  const pending=['queued','leased'].includes(job.status);
  const warnings:LifecycleWarning[]=[];
  if(created===null)warnings.push('missing_created');
  if(expires===null)warnings.push('missing_expiry');
  if(created!==null&&expires!==null&&expires<=created)warnings.push('expiry_before_creation');
  if(pending&&expires!==null&&expires<=now)warnings.push('pending_after_expiry');
  if(terminal&&job.status!=='expired'&&completed===null)warnings.push('completed_without_timestamp');
  if(completed!==null&&created!==null&&completed<created)warnings.push('complete_before_creation');
  if(completed!==null&&expires!==null&&completed>expires)warnings.push('complete_after_expiry');
  if(pending&&completed!==null)warnings.push('pending_with_completion');
  if(lease!==null&&expires!==null&&lease>expires)warnings.push('lease_after_expiry');
  if(terminal&&lease!==null)warnings.push('terminal_with_lease');
  if(created!==null&&created>now)warnings.push('created_after_overview');
  if(completed!==null&&completed>now)warnings.push('completion_after_overview');
  return {jobID:job.id,endpointID:job.agent_id,status:job.status,mode:job.scan_type||'not reported',
    createdAt:job.created_at||'',expiresAt:job.expires_at||'',
    completedAt:job.completed_at||'',warnings};
 });
}
export function lifecycleTotals(rows:readonly LifecycleRow[]){
 return {jobs:rows.length,withWarnings:rows.filter(x=>x.warnings.length>0).length,
   pendingAfterExpiry:rows.filter(x=>x.warnings.includes('pending_after_expiry')).length,
   unreportedCompletion:rows.filter(x=>x.warnings.includes('completed_without_timestamp')).length,
   futureClock:rows.filter(x=>x.warnings.includes('created_after_overview')||
     x.warnings.includes('completion_after_overview')).length};
}
