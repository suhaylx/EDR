import {useState} from 'react';
import type {LabScanJob} from './lab-api.js';
import {LIFECYCLE_LABELS,reviewScanLifecycle,lifecycleTotals} from './scan-lifecycle.js';
export function ScanLifecycleReview({jobs,generatedAt}:{
 jobs:readonly LabScanJob[];generatedAt:string;
}){
 const [warningsOnly,setWarningsOnly]=useState(true);
 const [page,setPage]=useState(0);
 const rows=reviewScanLifecycle(jobs,generatedAt);
 const summary=lifecycleTotals(rows);
 const filtered=warningsOnly?rows.filter(x=>x.warnings.length>0):rows;
 const pages=Math.max(1,Math.ceil(filtered.length/25)),current=Math.min(page,pages-1);
 const visible=filtered.slice(current*25,(current+1)*25);
 return <section className="panel scan-lifecycle" aria-labelledby="scan-lifecycle-title">
  <h2 id="scan-lifecycle-title">Backend scan-job lifecycle review</h2>
  <p>Go reports job creation, expiry, lease deadline and completion separately.
    The reference clock is the overview generated at <strong>{generatedAt}</strong>.
    This is a consistency review of lab control-plane records, not a ClamAV
    execution attestation or endpoint audit.</p>
  <dl className="scan-lifecycle-metrics">
   <div><dt>Returned jobs</dt><dd>{summary.jobs}</dd></div>
   <div><dt>Jobs with timestamp warnings</dt><dd>{summary.withWarnings}</dd></div>
   <div><dt>Pending after reported expiry</dt><dd>{summary.pendingAfterExpiry}</dd></div>
   <div><dt>Terminal completion timestamp absent</dt><dd>{summary.unreportedCompletion}</dd></div>
   <div><dt>Future relative to overview generation</dt><dd>{summary.futureClock}</dd></div>
  </dl>
  <label className="scan-lifecycle-toggle" htmlFor="scan-lifecycle-only">
   <input id="scan-lifecycle-only" type="checkbox" checked={warningsOnly}
     onChange={e=>{setWarningsOnly(e.target.checked);setPage(0);}}/>
   Show only jobs with modeled lifecycle warnings
  </label>
  <p role="status" aria-live="polite">{filtered.length} of {rows.length} job records displayed by filter.
    Page {current+1} of {pages}.</p>
  {filtered.length===0
  ? <p className="empty">No reported lifecycle inconsistencies among these
      returned jobs. This does not certify scan execution, authentic leases
      or an operational scanner.</p>
  : <><div className="table-scroll"><table className="scan-lifecycle-table">
     <caption>Reported Go job lifecycle times and consistency checks; scan paths,
       request IDs and active lease capabilities are not exposed.</caption>
     <thead><tr>
       <th scope="col">Job / endpoint</th><th scope="col">State / mode</th>
       <th scope="col">Request time</th><th scope="col">Expiry time</th>
       <th scope="col">Completion time</th><th scope="col">Review notes</th>
     </tr></thead>
     <tbody>{visible.map(r=><tr key={r.jobID}>
       <th scope="row">{r.jobID}<span className="minor">{r.endpointID}</span></th>
       <td>{r.status}<span className="minor">{r.mode}</span></td>
       <td>{r.createdAt||'not reported'}</td><td>{r.expiresAt||'not reported'}</td>
       <td>{r.completedAt||'not reported'}</td>
       <td>{r.warnings.length? <ul>{r.warnings.map(w=><li key={w}>{LIFECYCLE_LABELS[w]}</li>)}</ul>
         :'No modeled timestamp discrepancy (not proof of scanning)'}</td>
     </tr>)}</tbody>
   </table></div>
   <div className="analyst-paging" role="group" aria-label="Scan lifecycle review pages">
    <button type="button" className="secondary" disabled={current===0} onClick={()=>setPage(current-1)}>Previous lifecycle page</button>
    <span>Page {current+1} of {pages}</span>
    <button type="button" className="secondary" disabled={current===pages-1} onClick={()=>setPage(current+1)}>Next lifecycle page</button>
   </div></>}
  <p className="minor">An expired pending job may reflect stale lab queue state,
    not a running scan. The Go server advances some states during lease
    requests. All endpoint identities and result metadata are unverified
    development reports; no scan retry, cancellation or command is sent.</p>
 </section>;
}
