import { useState } from 'react';
import type { LabScanJob } from './lab-api.js';
import { describeScan, scanEngineEvidence } from './scan-state.js';
import {
  INITIAL_SCAN_QUERY, filterScanEvidence, pageScanEvidence, scanEvidenceLabel,
  scanNeedsAttention, sortScanEvidence, summarizeScanEvidence,
  type ScanEvidenceFilter, type ScanSort, type ScanPageSize,
} from './scan-evidence.js';

/** Standalone read-only scan-job worklist. No scan scheduling or agent commands. */
export function ScanEvidenceWorklist({jobs}:{jobs:readonly LabScanJob[]}) {
  const [category,setCategory] = useState<ScanEvidenceFilter>('all');
  const [endpoint,setEndpoint] = useState('');
  const [mode,setMode] = useState('');
  const [search,setSearch] = useState('');
  const [sort,setSort] = useState<ScanSort>('newest');
  const [pageSize,setPageSize] = useState<ScanPageSize>(25);
  const [pageIndex,setPageIndex] = useState(0);

  const query={category,endpoint,mode,text:search,sort};
  const matching=filterScanEvidence(jobs,query);
  const ordered=sortScanEvidence(matching,sort);
  const page=pageScanEvidence(ordered,pageIndex,pageSize);
  const counts=summarizeScanEvidence(jobs);
  const attention=jobs.filter(scanNeedsAttention).length;
  const resetPage=()=>setPageIndex(0);
  const reset=()=>{
    setCategory(INITIAL_SCAN_QUERY.category);
    setEndpoint('');setMode('');setSearch('');
    setSort(INITIAL_SCAN_QUERY.sort);
    setPageSize(25);resetPage();
  };
  const changed=category!=='all'||endpoint!==''||mode!==''||search!==''||
    sort!=='newest'||pageSize!==25;

  return <div className="scan-evidence-worklist">
    <p>Read-only scan <strong>job reports</strong> from the laboratory Go API.
      These are not independently attested ClamAV executions. The lab worker
      currently implements path scans only; quick/full completion claiming a
      successful verdict is inconsistent and must not be treated as detection evidence.</p>
    <dl className="scan-evidence-summary" aria-label="Counts from returned scan jobs only">
      <div><dt>Requests pending</dt><dd>{counts.queued+counts.leased}</dd></div>
      <div><dt>Reported scanner errors / failures</dt>
        <dd>{counts.scanner_error+counts.failed+counts.expired}</dd></div>
      <div><dt>Unscanned</dt><dd>{counts.unscanned}</dd></div>
      <div><dt>Unsupported or unverifiable mode</dt>
        <dd>{counts.unsupported_claim+counts.unverified_mode}</dd></div>
      <div><dt>Reported signature matches</dt><dd>{counts.signature_match}</dd></div>
      <div><dt>Reported signature-negative path results</dt><dd>{counts.signature_negative}</dd></div>
    </dl>
    <p className="minor">{attention} of {jobs.length} returned job(s) need analyst
      attention under the lab classification. Counts are local to received records,
      not a count of protected, scanned or clean endpoints.</p>
    <div className="scan-evidence-filters">
      <div className="field"><label htmlFor="scan-category">Job evidence category</label>
        <select id="scan-category" value={category}
          onChange={e=>{setCategory(e.target.value as ScanEvidenceFilter);resetPage();}}>
          <option value="all">All reported job states</option>
          <option value="pending">Queued or leased</option>
          <option value="needs_attention">Analyst attention</option>
          <option value="failed_expired_error">Failed, expired or scanner error</option>
          <option value="unscanned">Unscanned</option>
          <option value="unsupported">Unsupported / unverifiable mode</option>
          <option value="reported_match">Reported path signature match</option>
          <option value="signature_negative">Reported path signature-negative</option>
          <option value="suspicious">Suspicious report</option>
          <option value="unrecognized">Unrecognized or incomplete state</option>
        </select></div>
      <div className="field"><label htmlFor="scan-endpoint">Exact endpoint ID</label>
        <input id="scan-endpoint" type="text" maxLength={96} autoComplete="off"
          value={endpoint} onChange={e=>{setEndpoint(e.target.value);resetPage();}}/></div>
      <div className="field"><label htmlFor="scan-mode">Reported scan mode</label>
        <select id="scan-mode" value={mode}
          onChange={e=>{setMode(e.target.value);resetPage();}}>
          <option value="">Any reported mode</option>
          <option value="path">Path</option>
          <option value="quick">Quick (not implemented)</option>
          <option value="full">Full (not implemented)</option>
          <option value="unknown">Unknown/unrecognized string (use search)</option>
        </select></div>
      <div className="field"><label htmlFor="scan-query">Search job metadata</label>
        <input id="scan-query" type="search" maxLength={200} autoComplete="off"
          value={search} onChange={e=>{setSearch(e.target.value);resetPage();}}
          aria-describedby="scan-scope-notice"/></div>
      <div className="field"><label htmlFor="scan-sort">Order by reported metadata</label>
        <select id="scan-sort" value={sort}
          onChange={e=>{setSort(e.target.value as ScanSort);resetPage();}}>
          <option value="newest">Newest reported request</option>
          <option value="oldest">Oldest reported request</option>
          <option value="endpoint">Endpoint ID</option>
          <option value="mode">Scan mode</option>
          <option value="attention">Attention / unsupported first</option>
        </select></div>
      <div className="field"><label htmlFor="scan-size">Rows per page</label>
        <select id="scan-size" value={pageSize}
          onChange={e=>{setPageSize(Number(e.target.value) as ScanPageSize);resetPage();}}>
          <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
        </select></div>
    </div>
    <p className="minor" id="scan-scope-notice">Search examines only the already
      returned job metadata; exact endpoint and mode filters do not request
      or inspect files. Missing timestamps sort last. No automatic polling
      or endpoint actions occur.</p>
    <button type="button" className="secondary" onClick={reset} disabled={!changed}>
      Clear scan filters
    </button>
    <p role="status" aria-live="polite" aria-atomic="true">
      {page.total} of {jobs.length} scan job record(s) match. Page {page.page+1}
      of {page.pageCount}; rows {page.first}–{page.last}.
    </p>
    {jobs.length===0
      ? <p className="empty">No scan jobs returned. No endpoint safety, scanning
          coverage, or protection can be inferred.</p>
      : page.total===0
      ? <p className="empty">No returned scan jobs match these local filters.
          This does not establish a successful scan or safe endpoint.</p>
      : <>
        <div className="table-scroll"><table>
          <caption>Filtered laboratory scan-job evidence. Malicious and
            signature-negative outcomes are reported claims, not attestations.</caption>
          <thead><tr>
            <th scope="col">Requested / ID</th><th scope="col">Endpoint / mode</th>
            <th scope="col">Job phase and reported verdict</th>
            <th scope="col">Analyst interpretation</th>
            <th scope="col">Reported scanner provenance</th>
          </tr></thead>
          <tbody>{page.rows.map((job,index)=>{
            const result=describeScan(job);
            return <tr key={job.id+':'+index}>
              <td>{job.created_at || 'Timestamp not reported'}
                <span className="minor">Job ID: {job.id}</span></td>
              <td>{job.agent_id || 'Endpoint not reported'}
                <span className="minor">Mode: {job.scan_type || 'not reported'}</span></td>
              <td><span className={'status status--'+result.tone}>
                  {scanEvidenceLabel(job)}</span>
                <span className="minor">Raw phase: {job.status || 'missing'};
                  verdict: {job.verdict || 'not reported'}</span></td>
              <td>{result.explanation}
                {job.detail && <details className="scan-evidence-detail">
                  <summary>View reported worker detail</summary>
                  <p>{job.detail}</p>
                </details>}
                {job.threat_name && <span className="minor">
                  Claimed signature: {job.threat_name}</span>}
              </td>
              <td>{scanEngineEvidence(job)}
                <span className="minor">Authenticated scanner result: NO.
                  Signature DB age/integrity: NOT INSTRUMENTED.</span></td>
            </tr>;
          })}</tbody>
        </table></div>
        <div className="scan-evidence-paging" role="group" aria-label="Scan worklist pagination">
          <button type="button" className="secondary" disabled={page.page===0}
            onClick={()=>setPageIndex(page.page-1)}>Previous scan page</button>
          <span aria-live="polite">Page {page.page+1} of {page.pageCount}</span>
          <button type="button" className="secondary"
            disabled={page.page===page.pageCount-1}
            onClick={()=>setPageIndex(page.page+1)}>Next scan page</button>
        </div>
      </>}
    <p className="minor">No scan request, quarantine, process termination, network
      isolation, incident closure, signature update or policy override can be
      performed from this view. Backend authorization and Agent 3 independent
      QA are required before production controls are designed.</p>
  </div>;
}
