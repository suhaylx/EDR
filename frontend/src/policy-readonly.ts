/** Read-only Go Store policy contracts: backend/internal/edr/{http,store}.go.
 * Server must exclude raw XML from the response; UI rejects it if present. Policy, assignment and acks are only
 * lab sender-reported management records; NOT verified Sysmon enforcement.
 */
import type { LabSOCOverview, EndpointActivity } from './overview.js';
export type PolicyMeta=Readonly<{id:string;name:string;platform:'windows'|'linux';
  revision:number;sha256:string;created_at:string}>;
export type PolicyAssignment=Readonly<{target_type:'agent'|'group'|'default';target_id:string;
  platform:'windows'|'linux';policy_id:string}>;
type Data=Record<string,unknown>;
const rec=(x:unknown):x is Data=>!!x&&typeof x==='object'&&!Array.isArray(x);
const clean=(x:unknown,max:number,name:string)=>{
 if(typeof x!=='string'||!x||x.length>max||/[\x00-\x1f\x7f]/.test(x))
   throw new Error('Invalid lab policy '+name);
 return x;
};
const platform=(x:unknown):'windows'|'linux'=> {
 if(x!=='windows'&&x!=='linux')throw new Error('Invalid lab policy platform');
 return x;
};
const id=(x:unknown,name:string)=>{
 const t=clean(x,96,name);if(!/^[A-Za-z0-9._-]+$/.test(t))throw new Error('Invalid lab policy '+name);
 return t;
};
export function decodePolicyMetadata(raw:unknown):PolicyMeta[]{
 if(!Array.isArray(raw)||raw.length>1000)throw new Error('Invalid lab policy list');
 const seen=new Set<string>();
 return raw.map((value,i)=>{
   if(!rec(value))throw new Error('Malformed policy '+i);
   const policyID=id(value.id,'id');
   if(seen.has(policyID))throw new Error('Duplicate policy ID');seen.add(policyID);
   const name=clean(value.name,96,'name');
   const os=platform(value.platform);
   const rev=value.revision;
   if(typeof rev!=='number'||!Number.isSafeInteger(rev)||rev<1)throw new Error('Invalid policy revision');
   const sha=clean(value.sha256,64,'digest');
   if(!/^[a-fA-F0-9]{64}$/.test(sha))throw new Error('Invalid policy SHA256 metadata');
   const created=clean(value.created_at,64,'timestamp');
   if(!/^\d{4}-\d\d-\d\dT/.test(created)||!Number.isFinite(Date.parse(created)))
     throw new Error('Invalid policy creation timestamp');
   // Never accept a fallback to the legacy XML-bearing /api/policies
   // response. Metadata-only payloads must be produced by the backend.
   if(Object.hasOwn(value,'xml'))
     throw new Error('Unexpected Sysmon XML in policy metadata response');
   return {id:policyID,name,platform:os,revision:rev,sha256:sha,created_at:created};
 });
}
export function decodePolicyAssignments(raw:unknown):PolicyAssignment[]{
 if(!Array.isArray(raw)||raw.length>5000)throw new Error('Invalid policy assignment list');
 const keys=new Set<string>();
 return raw.map((value,i)=>{
   if(!rec(value))throw new Error('Malformed assignment '+i);
   const tt=value.target_type;
   if(tt!=='agent'&&tt!=='group'&&tt!=='default')throw new Error('Invalid target type');
   const target=tt==='default'
     ? (value.target_id==='*'?'*':(()=>{throw new Error('Invalid default target');})())
     : id(value.target_id,'target_id');
   const os=platform(value.platform),policyID=id(value.policy_id,'assignment policy_id');
   const key=[tt,target,os].join('\u0000');
   if(keys.has(key))throw new Error('Duplicate policy assignment target');
   keys.add(key);
   return {target_type:tt,target_id:target,platform:os,policy_id:policyID};
 });
}
async function read(token:string,url:string,signal?:AbortSignal,fetcher:typeof fetch=fetch):Promise<unknown>{
 if(token.length<16)throw new Error('The development token must contain at least 16 characters.');
 const response=await fetcher(url,{method:'GET',credentials:'omit',cache:'no-store',signal,
   headers:{Authorization:'Bearer '+token}});
 if(!response.ok)throw new Error(response.status===401?'Development token rejected (HTTP 401).':
   'Lab policy API returned HTTP '+response.status+'.');
 return await response.json() as unknown;
}
export async function fetchPolicyMetadata(token:string,signal?:AbortSignal,fetcher:typeof fetch=fetch){
 return decodePolicyMetadata(await read(token,'/api/policy-metadata',signal,fetcher));
}
export async function fetchPolicyAssignments(token:string,signal?:AbortSignal,fetcher:typeof fetch=fetch){
 return decodePolicyAssignments(await read(token,'/api/assignments',signal,fetcher));
}
export type PolicyReviewState='unassigned'|'unknown_policy'|'platform_mismatch'|'applied_reported'|
 'ack_mismatch'|'awaiting_ack'|'error_reported';
export type PolicyReviewRow=Readonly<{endpointID:string;platform:string;group:string;heartbeat:string;
 desiredID:string;desiredRevision:number;desiredName:string;
 assignmentLevel:'agent'|'group'|'default'|'none';
 appliedID:string;appliedRevision:number;error:string;status:PolicyReviewState}>;
export function desiredPolicyForEndpoint(e:EndpointActivity,assignments:readonly PolicyAssignment[]){
 for(const type of ['agent','group','default'] as const){
  const target=type==='agent'?e.id:type==='group'?e.group:'*';
  const a=assignments.find(a=>a.platform===e.platform&&a.target_type===type&&a.target_id===target);
  if(a)return a;
 }
 return null;
}
export function reviewPolicyEvidence(overview:LabSOCOverview,
 policies:readonly PolicyMeta[],assignments:readonly PolicyAssignment[]):PolicyReviewRow[]{
 const index=new Map(policies.map(p=>[p.id,p]));
 return overview.endpoints.map(e=>{
  const assigned=desiredPolicyForEndpoint(e,assignments),desired=assigned?index.get(assigned.policy_id):undefined;
  let state:PolicyReviewState;
  if(e.last_policy_error)state='error_reported';
  else if(!assigned)state='unassigned';
  else if(!desired)state='unknown_policy';
  else if(desired.platform!==e.platform)state='platform_mismatch';
  else if(e.applied_policy_id===desired.id&&e.applied_revision===desired.revision)state='applied_reported';
  else if(e.applied_policy_id)state='ack_mismatch';
  else state='awaiting_ack';
  return {endpointID:e.id,platform:e.platform,group:e.group,heartbeat:e.status,
    desiredID:assigned?.policy_id||'',desiredRevision:desired?.revision||0,
    desiredName:desired?.name||'',assignmentLevel:assigned?.target_type||'none',
    appliedID:e.applied_policy_id,appliedRevision:e.applied_revision,error:e.last_policy_error,status:state};
 });
}
