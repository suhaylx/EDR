import { useState } from 'react';
import type { LabScanJob } from './lab-api.js';
import { describeScan, scanEngineEvidence } from './scan-state.js';
import {
  DEFAULT_SCAN_QUERY, SCAN_KIND_LABELS, SCAN_FLAG_LABELS,
  filterReportedScanJobs, paginateReportedScanJobs, scanEvidenceFlags,
  scanEvidenceKind, sortReportedScanJobs, summarizeReportedScanJobs,
  type ScanQuery, type ScanFilter, type ScanModeFilter,
  type MetadataFilter, type ScanSort, type ScanPageSize,
} from './scan-evidence.js';

/** Never issues scan commands or assumes reported ClamAV evidence is authentic. */
export function ScanEvidenceWorkbench({jobs,onInspectContext}: {
  jobs:readonly LabScanJob[];
  onInspectContext?: (id:string)=>void;
}) {
  const [filter,setFilter]=useState<ScanQuery>(DEFAULT_SCAN_QUERY);
  const [sort,setSort]=useState<ScanSort>('newest');
  const [pageSize,setPageSize]=useState<ScanPageSize>(25);
  const [pageIndex,setPageIndex]=useState(0);
  const matched=filterReportedScanJobs(jobs,filter);
  const ordered=sortReportedScanJobs(matched,sort);
  const page=paginateReportedScanJobs(ordered,pageIndex,pageSize);
  const overview=summarizeReportedScanJobs(jobs);
  const update=<K extends keyof ScanQuery>(key:K,value:ScanQuery[K])=>{
    setFilter(old=>({...old,[key]:value}));
    setPageIndex(0);
  };
  const reset=()=>{
    setFilter(DEFAULT_SCAN_QUERY);
    setSort('newest');setPageSize(25);setPageIndex(0);
  };
  const active=Object.keys(DEFAULT_SCAN_QUERY).some(key=>
    filter[key as keyof ScanQuery]!==DEFAULT_SCAN_QUERY[key as keyof ScanQuery]) ||
    sort!=='newest'||pageSize!==25;

  return <section className="scan-evidence" aria-labelledby="history-title">
    <div className="heading">
      <h2 id="history-title">Retained scan jobs — evidence workbench</h2>
      <span className="subtle">No automatic polling or endpoint commands</span>
    </div>
    <p>Job delivery is not proof of scan execution. Current Rust lab worker does
      not support quick/full scans. Path-mode signature reports are unverified
      claims, and signature-negative does not mean that any endpoint is safe.</p>
    <dl className="scan-evidence-summary" aria-label="Returned scan-job evidence summary">
      <div><dt>Returned jobs</dt><dd>{overview.returned}</dd></div>
      <div><dt>Needs analyst review</dt><dd>{overview.attention}</dd></div>
      <div><dt>Unsupported quick/full claims</dt><dd>{overview.kinds.unsupported_claim}</dd></div>
      <div><dt>Reported scanner errors</dt><dd>{overview.kinds.scanner_error}</dd></div>
      <div><dt>Unscanned</dt><dd>{overview.kinds.unscanned}</dd></div>
      <div><dt>Reported signature matches</dt><dd>{overview.kinds.reported_match}</dd></div>
      <div><dt>Reported signature-negative</dt><dd>{overview.kinds.signature_negative}</dd></div>
      <div><dt>Unrecognized or missing metadata</dt><dd>{overview.metadataGaps}</dd></div>
    </dl>
    <div className="scan-evidence-filters">
      <div className="field"><label htmlFor="scan-triage-kind">Job evidence status</label>
        <select id="scan-triage-kind" value={filter.kind}
          onChange={e=>update('kind',e.target.value as ScanFilter)}>
          <option value="all">All returned jobs</option>
          <option value="attention">Needs analyst review</option>
          <option value="pending">Queued or leased</option>
          <option value="failed_or_error">Failed, expired or scanner error</option>
          <option value="unscanned">Not scanned</option>
          <option value="unsupported_claim">Unsupported quick/full success</option>
          <option value="reported_match">Path signature match (reported)</option>
          <option value="signature_negative">Path signature-negative (reported)</option>
          <option value="suspicious">Path suspicious (reported)</option>
          <option value="unknown">Unknown/unsupported completion</option>
        </select></div>
      <div className="field"><label htmlFor="scan-triage-mode">Reported scan mode</label>
        <select id="scan-triage-mode" value={filter.mode}
          onChange={e=>update('mode',e.target.value as ScanModeFilter)}>
          <option value="all">All reported modes</option><option value="path">Path</option>
          <option value="quick">Quick — not supported by lab worker</option>
          <option value="full">Full — not supported by lab worker</option>
          <option value="other">Missing / unknown mode</option>
        </select></div>
      <div className="field"><label htmlFor="scan-triage-metadata">Reported metadata</label>
        <select id="scan-triage-metadata" value={filter.metadata}
          onChange={e=>update('metadata',e.target.value as MetadataFilter)}>
          <option value="all">Any metadata state</option>
          <option value="missing">Missing/inconsistent fields</option>
          <option value="complete">No modeled metadata warnings</option>
        </select></div>
      <div className="field"><label htmlFor="scan-triage-agent">Exact endpoint ID</label>
        <input id="scan-triage-agent" type="search" maxLength={96}
          autoComplete="off" value={filter.endpoint}
          onChange={e=>update('endpoint',e.target.value)} /></div>
      <div className="field"><label htmlFor="scan-triage-query">Search returned job metadata</label>
        <input id="scan-triage-query" type="search" maxLength={200}
          autoComplete="off" value={filter.search}
          onChange={e=>update('search',e.target.value)}
          aria-describedby="scan-evidence-query-note" /></div>
      <div className="field"><label htmlFor="scan-triage-sort">Order returned jobs</label>
        <select id="scan-triage-sort" value={sort}
          onChange={e=>{setSort(e.target.value as ScanSort);setPageIndex(0);}}>
          <option value="newest">Newest reported creation first</option>
          <option value="oldest">Oldest reported creation first</option>
          <option value="endpoint">Endpoint ID</option>
          <option value="mode">Reported scan mode</option>
          <option value="classification">Evidence quality / analyst attention</option>
        </select></div>
      <div className="field"><label htmlFor="scan-triage-pagesize">Rows per page</label>
        <select id="scan-triage-pagesize" value={pageSize}
          onChange={e=>{setPageSize(Number(e.target.value) as ScanPageSize);setPageIndex(0);}}>
          <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
        </select></div>
    </div>
    <p className="minor" id="scan-evidence-query-note">Search and filters are
      local to the retained development response. Counts are not verified
      endpoint health, database freshness or production tenant isolation.</p>
    <button type="button" className="secondary" onClick={reset} disabled={!active}>
      Clear scan worklist filters
    </button>
    <p role="status" aria-live="polite" aria-atomic="true">
      {page.total} of {overview.returned} returned job(s) match.
      Page {page.page+1} of {page.pages}; rows {page.start}–{page.end}.
    </p>
    {jobs.length===0
      ? <p className="empty">No scan jobs were returned by this lab API.
          This does not establish an idle scanner, a clean host or protection.</p>
      : page.total===0
      ? <p className="empty">No returned jobs match these local filters.
          This does not establish the absence of scans or threats.</p>
      : <><div className="table-scroll"><table>
        <caption>Locally sorted lab scan requests, with separately reported
          delivery state, scan verdict and evidence integrity warnings.</caption>
        <thead><tr>
          <th scope="col">Job / created</th>
          <th scope="col">Endpoint / mode</th>
          <th scope="col">Delivery state / reported verdict</th>
          <th scope="col">Evidence interpretation</th>
          <th scope="col">Reported scanner</th>
          <th scope="col">Inspect metadata</th>
          {onInspectContext && <th scope="col">Adjacent evidence</th>}
        </tr></thead>
        <tbody>{page.rows.map(job=>{
          const kind=scanEvidenceKind(job);
          const flags=scanEvidenceFlags(job);
          const described=describeScan(job);
          const insufficient = kind==='unverified_completion' || kind==='unknown_state';
          return <tr key={job.id}>
            <td><strong>{job.id}</strong><span className="minor">
              {job.created_at || 'Creation time not reported'}</span></td>
            <td>{job.agent_id}<span className="minor">
              Mode: {job.scan_type || 'not reported'}</span></td>
            <td>{job.status}<span className="minor">
              Verdict: {job.verdict || 'not reported'}</span></td>
            <td><strong className={'status status--'+
              (kind==='unsupported_claim'||kind==='scanner_error'||kind==='reported_match'
                ?'danger':kind==='signature_negative'||kind==='queued'?'neutral':'warning')}>
              {SCAN_KIND_LABELS[kind]}</strong>
              <span className="minor">{insufficient
                ? 'Unrecognized or unsupported completion metadata; no valid scan execution or verdict can be inferred.'
                : described.explanation}</span>
              <span className="minor">{flags.length
                ? flags.length+' reported-evidence warning(s)' : 'No modeled metadata warning; not attested'}</span></td>
            <td>{scanEngineEvidence(job)}</td>
            <td><details><summary>Inspect {job.id} reported fields</summary>
              <dl className="scan-job-detail">
                <div><dt>Reported job ID</dt><dd>{job.id}</dd></div>
                <div><dt>Endpoint</dt><dd>{job.agent_id}</dd></div>
                <div><dt>Raw state</dt><dd>{job.status}</dd></div>
                <div><dt>Raw verdict</dt><dd>{job.verdict || 'not reported'}</dd></div>
                <div><dt>Raw scan mode</dt><dd>{job.scan_type || 'not reported'}</dd></div>
                <div><dt>Created at</dt><dd>{job.created_at || 'not reported'}</dd></div>
                <div><dt>Reported engine</dt><dd>{job.engine || 'not reported'}</dd></div>
                <div><dt>Engine version</dt><dd>{job.engine_version || 'not reported'}</dd></div>
                <div><dt>Signature DB version</dt><dd>{job.database_version || 'not reported'}</dd></div>
                <div><dt>Reported signature indicator</dt><dd>{job.signature_reported || !!job.threat_name?.trim() ? 'Present (name withheld)' : 'Not reported'}</dd></div>
                <div><dt>Worker detail</dt><dd>Withheld from analyst metadata view</dd></div>
              </dl>
              {flags.length>0 && <div className="scan-evidence-warnings">
                <strong>Inconsistent/missing reported metadata</strong>
                <ul>{flags.map(flag=><li key={flag}>{SCAN_FLAG_LABELS[flag]}</li>)}</ul>
              </div>}
              <p className="minor">Only bounded, redacted laboratory metadata is displayed;
                this view cannot attest ClamAV signature
                updates, scan execution or tamper resistance.</p>
            </details></td>
            {onInspectContext && <td><button type="button" className="source-button"
              aria-label={'Inspect same-endpoint retained context for scan job '+job.id}
              onClick={()=>onInspectContext(job.id)}>Inspect same-endpoint evidence</button></td>}
          </tr>;
        })}</tbody>
      </table></div>
      <div className="analyst-paging" role="group" aria-label="Local scan result pages">
        <button type="button" className="secondary" disabled={page.page===0}
          onClick={()=>setPageIndex(page.page-1)}>Previous scan page</button>
        <span aria-live="polite">Page {page.page+1} of {page.pages}</span>
        <button type="button" className="secondary" disabled={page.page>=page.pages-1}
          onClick={()=>setPageIndex(page.page+1)}>Next scan page</button>
      </div></>}
    <p className="minor">Current Go lab API exposes a shared dev bearer token
      and reported worker metadata only. There is no endpoint attestation,
      tenant authorization, production scan scheduling or quarantine action.</p>
  </section>;
}
