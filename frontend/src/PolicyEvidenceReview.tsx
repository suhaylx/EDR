import {useState} from 'react';
import type {LabSOCOverview} from './overview.js';
import type {PolicyMeta,PolicyAssignment,PolicyReviewState} from './policy-readonly.js';
import {reviewPolicyEvidence} from './policy-readonly.js';
const LABELS:Readonly<Record<PolicyReviewState,string>>={
 unassigned:'No desired assignment found',unknown_policy:'Assigned policy ID not in returned catalog',
 platform_mismatch:'Desired policy platform disagreement',applied_reported:'Reported acknowledgment matches desired ID/revision (not verified)',
 ack_mismatch:'Reported applied ID/revision differs from desired',
 awaiting_ack:'Desired assignment reported; acknowledgment missing',
 error_reported:'Endpoint reports a policy error (not authenticated)',
};
export function PolicyEvidenceReview({overview,policies,assignments}:{
 overview:LabSOCOverview;policies:readonly PolicyMeta[];assignments:readonly PolicyAssignment[];
}){
 const [filter,setFilter]=useState<PolicyReviewState|'all'>('all');
 const [host,setHost]=useState('');
 const [page,setPage]=useState(0);
 const [size,setSize]=useState<25|50|100>(25);
 const rows=reviewPolicyEvidence(overview,policies,assignments);
 const matching=rows.filter(r=>(filter==='all'||r.status===filter)&&
   (!host.trim()||r.endpointID.toLowerCase()===host.trim().toLowerCase()));
 const pages=Math.max(1,Math.ceil(matching.length/size)),p=Math.min(page,pages-1);
 const visible=matching.slice(p*size,(p+1)*size);
 const statusCounts=Object.keys(LABELS).map(key=>({
   key:key as PolicyReviewState,count:rows.filter(r=>r.status===key).length,
 }));
 return <section className="panel" aria-labelledby="policy-review-title">
  <h2 id="policy-review-title">Policy intention and acknowledgment evidence</h2>
  <p>Read-only Go <code>/api/policy-metadata</code> and <code>/api/assignments</code> are
    compared with server overview enrollment records. Agent assignments override
    group assignments; group overrides default, separately per platform. These
    are shared-token lab reports, <strong>not verified Sysmon enforcement</strong>.
    No policy XML is displayed.</p>
  <dl className="policy-evidence-summary">
    <div><dt>Catalog metadata records</dt><dd>{policies.length}</dd></div>
    <div><dt>Desired assignment records</dt><dd>{assignments.length}</dd></div>
    {statusCounts.map(s=><div key={s.key}><dt>{LABELS[s.key]}</dt><dd>{s.count}</dd></div>)}
  </dl>
  <div className="policy-evidence-controls">
    <div className="field"><label htmlFor="policy-evidence-state">Reported policy state</label>
      <select id="policy-evidence-state" value={filter}
        onChange={e=>{setFilter(e.target.value as PolicyReviewState|'all');setPage(0);}}>
        <option value="all">All reported states</option>
        {statusCounts.map(x=><option key={x.key} value={x.key}>{LABELS[x.key]}</option>)}
      </select></div>
    <div className="field"><label htmlFor="policy-evidence-host">Exact endpoint ID</label>
      <input id="policy-evidence-host" type="search" maxLength={96} value={host}
        autoComplete="off" onChange={e=>{setHost(e.target.value);setPage(0);}}/></div>
    <div className="field"><label htmlFor="policy-evidence-page-size">Rows per page</label>
      <select id="policy-evidence-page-size" value={size}
        onChange={e=>{setSize(Number(e.target.value) as 25|50|100);setPage(0);}}>
        <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
      </select></div>
  </div>
  <button type="button" className="secondary" onClick={()=>{setFilter('all');setHost('');setSize(25);setPage(0);}}
    disabled={filter==='all'&&!host&&size===25}>Clear local policy filters</button>
  <p role="status" aria-live="polite">
    {matching.length} of {rows.length} returned endpoint record(s) match.
    Page {p+1} of {pages}; rows {matching.length?p*size+1:0}–{Math.min(matching.length,(p+1)*size)}.
  </p>
  {matching.length===0?<p className="empty">No matching returned enrollment evidence;
    this does not prove any endpoint is configured, unconfigured or protected.</p>
  : <><div className="table-scroll"><table className="policy-evidence-table">
      <caption>Reported desired assignment and policy acknowledgment. A matching acknowledgment is not host attestation.</caption>
      <thead><tr>
       <th scope="col">Endpoint</th><th scope="col">Heartbeat</th>
       <th scope="col">Desired policy (source)</th><th scope="col">Reported applied policy</th>
       <th scope="col">Review outcome</th>
      </tr></thead>
      <tbody>{visible.map(r=><tr key={r.endpointID}>
       <th scope="row">{r.endpointID}<span className="minor">{r.platform} / {r.group||'no group'}</span></th>
       <td>{r.heartbeat} — Go-received heartbeat state, not policy health</td>
       <td>{r.desiredID||'Not assigned'}<span className="minor">
         {r.desiredName||'No catalog name'}; revision {r.desiredRevision||'unknown'};
         source {r.assignmentLevel}</span></td>
       <td>{r.appliedID||'Not reported'}<span className="minor">
         Revision {r.appliedRevision||'not reported'}</span></td>
       <td><strong>{LABELS[r.status]}</strong>
         {r.errorReported&&<span className="minor">Reported policy error detail withheld from shared-token lab UI</span>}</td>
      </tr>)}</tbody>
    </table></div>
    <div className="analyst-paging" role="group" aria-label="Local policy evidence pages">
      <button type="button" className="secondary" disabled={p===0}
        onClick={()=>setPage(p-1)}>Previous policy page</button>
      <span>Page {p+1} of {pages}</span>
      <button type="button" className="secondary" disabled={p===pages-1}
        onClick={()=>setPage(p+1)}>Next policy page</button>
    </div></>}
  <p className="minor">The backend supports POST policy and assignment mutation, but this
    screen deliberately sends only GET requests. Production policy application requires
    tenant-scoped authorization, signed commands, canary, rollback, and independent
    endpoint Sysmon verification. An absent acknowledgment is not enforcement failure proof.</p>
 </section>;
}
