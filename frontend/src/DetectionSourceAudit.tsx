import { useState } from 'react';
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import type { InvestigationSeed } from './investigation.js';
import type { RetainedSourceSelection } from './multisignal-alert-triage.js';
import {
  AUDIT_FLAG_LABELS,PRIMARY_LABELS,FILE_LABELS,DEFAULT_AUDIT_QUERY,
  auditDetectionSources,filterAuditRows,pageAudit,summarizeAudit,
  type AuditQuery,type AuditFilter,type AuditSort,type AuditPageSize,
} from './detection-source-audit.js';

/** Lab-only evidence consistency: ID matches and metadata are not attestations. */
export function DetectionSourceAudit({detections,events,generatedAt,onInspectSource,onInvestigate}:{
  detections:readonly LabDetection[];
  events:readonly LabTelemetryEvent[];
  generatedAt:string;
  onInspectSource:(selection:RetainedSourceSelection)=>void;
  onInvestigate:(seed:InvestigationSeed)=>void;
}) {
  const [query,setQuery]=useState<AuditQuery>(DEFAULT_AUDIT_QUERY);
  const [size,setSize]=useState<AuditPageSize>(25);
  const [requestedPage,setRequestedPage]=useState(0);
  const rows=auditDetectionSources(detections,events,generatedAt);
  const results=filterAuditRows(rows,query);
  const page=pageAudit(results,requestedPage,size);
  const summary=summarizeAudit(rows);
  const update=<K extends keyof AuditQuery>(key:K,value:AuditQuery[K])=>{
    setQuery(old=>({...old,[key]:value}));setRequestedPage(0);
  };
  const clear=()=>{setQuery({...DEFAULT_AUDIT_QUERY,state:'all'});setSize(25);setRequestedPage(0);};
  const allRecordsBaseline:AuditQuery={...DEFAULT_AUDIT_QUERY,state:'all'};
  const active=Object.entries(query).some(([k,v])=>
    v!==allRecordsBaseline[k as keyof AuditQuery])||size!==25;
  return <section className="detection-audit" aria-labelledby="detection-audit-title">
    <h3 id="detection-audit-title">Detection-source integrity audit</h3>
    <p>Compares claimed Go event IDs, numeric Sysmon types, process GUIDs and
      separately linked FileCreate references against the <strong>current returned
      telemetry sample (maximum 100 events)</strong>. Matching reported values
      is not signed provenance, installed policy coverage or confirmed infection.
      Unavailable references are not proof of lost events.</p>
    <dl className="detection-audit-summary" aria-label="Returned detection source-reference audit">
      <div><dt>Returned detections</dt><dd>{summary.reviewedRecords}</dd></div>
      <div><dt>Primary IDs unavailable</dt><dd>{summary.primaryUnavailable}</dd></div>
      <div><dt>Reported type disagreement</dt><dd>{summary.typeConflict}</dd></div>
      <div><dt>Reported GUID disagreement</dt><dd>{summary.guidConflict}</dd></div>
      <div><dt>Separate FileCreate reference issues</dt><dd>{summary.filecreateIssue}</dd></div>
      <div><dt>Reported type agreement (not attested)</dt><dd>{summary.reportedAgreement}</dd></div>
      <div><dt>Detection process GUID absent</dt><dd>{summary.missingGuid}</dd></div>
      <div><dt>Source receipt later than overview</dt><dd>{summary.futureReceipt}</dd></div>
    </dl>
    <div className="detection-audit-filters">
      <div className="field"><label htmlFor="audit-state">Source-reference category</label>
        <select id="audit-state" value={query.state}
          onChange={e=>update('state',e.target.value as AuditFilter)}>
          <option value="review">Reported warnings or evidence gaps</option>
          <option value="all">All returned detection references</option>
          <option value="reported_agreement">Numeric source type agrees (not attested)</option>
          <option value="missing_primary">Missing / unavailable primary Go event ID</option>
          <option value="type_conflict">Claimed numeric Sysmon type disagreement</option>
          <option value="guid_conflict">Reported process GUID disagreement</option>
          <option value="filecreate_issue">Separate FileCreate reference issue</option>
          <option value="no_guid">Detection process GUID absent</option>
        </select></div>
      <div className="field"><label htmlFor="audit-severity">Reported severity</label>
        <select id="audit-severity" value={query.severity}
          onChange={e=>update('severity',e.target.value)}>
          <option value="all">All</option><option value="critical">Critical</option>
          <option value="high">High</option><option value="medium">Medium</option>
          <option value="low">Low</option><option value="other">Other / unclassified</option>
        </select></div>
      <div className="field"><label htmlFor="audit-host">Exact endpoint ID</label>
        <input id="audit-host" value={query.endpoint} type="search"
          maxLength={96} autoComplete="off"
          onChange={e=>update('endpoint',e.target.value)}/></div>
      <div className="field"><label htmlFor="audit-query">Search returned reference metadata</label>
        <input id="audit-query" value={query.query} type="search"
          maxLength={200} autoComplete="off"
          onChange={e=>update('query',e.target.value)}
          aria-describedby="audit-limitations"/></div>
      <div className="field"><label htmlFor="audit-sort">Order audit records</label>
        <select id="audit-sort" value={query.sort}
          onChange={e=>update('sort',e.target.value as AuditSort)}>
          <option value="issues">Most modeled warnings first</option>
          <option value="severity">Reported severity</option>
          <option value="endpoint">Endpoint ID</option>
          <option value="rule">Reported rule ID</option>
          <option value="source_status">Primary source disagreement first</option>
        </select></div>
      <div className="field"><label htmlFor="audit-page-size">Records per page</label>
        <select id="audit-page-size" value={size}
          onChange={e=>{setSize(Number(e.target.value) as AuditPageSize);setRequestedPage(0);}}>
          <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
        </select></div>
    </div>
    <p className="minor" id="audit-limitations">Search is local to the two returned
      responses. The audit does not search raw source details, sender clipboard
      data, hidden endpoints, persisted history, or production tenants.</p>
    <button type="button" className="secondary" onClick={clear}
      disabled={!active}>Show all audit records and reset filters</button>
    <p role="status" aria-live="polite" aria-atomic="true">
      {page.total} of {rows.length} returned detection reference(s) match.
      Page {page.page+1} of {page.pages}; rows {page.start}–{page.end}.
    </p>
    {rows.length===0
      ? <p className="empty">No detections returned in this lab response.
          This does not establish clean endpoints, complete collection or
          verified Sysmon policy enforcement.</p>
      : results.length===0
      ? <p className="empty">No returned detection references match these local
          filters. No modeled warning is not proof of source authenticity.</p>
      : <><div className="table-scroll"><table className="detection-audit-table">
        <caption>Reported Go event reference consistency, not verified endpoint
          provenance or maliciousness. Source ID, numeric type and GUID are independent checks.</caption>
        <thead><tr>
          <th scope="col">Detection / endpoint</th>
          <th scope="col">Primary Go reference</th>
          <th scope="col">Claimed vs returned Sysmon ID</th>
          <th scope="col">Separate FileCreate source</th>
          <th scope="col">Evidence warnings</th>
          <th scope="col">Read-only investigation</th>
        </tr></thead>
        <tbody>{page.rows.map(row=><tr key={row.detectionID}>
          <td><strong>{row.detectionID}</strong>
            <span className="minor">Endpoint: {row.deviceID}</span>
            <span className="minor">Rule: {row.ruleID}</span></td>
          <td>{row.primaryID||'Not reported'}
            <span className="minor">{PRIMARY_LABELS[row.primaryState]}</span></td>
          <td>Claimed: {row.expectedEventID||'not reported'}
            <span className="minor">Returned: {row.returnedEventID??'not in sample'}</span></td>
          <td>{row.fileID||'No separate ID'}
            <span className="minor">{FILE_LABELS[row.fileState]}</span></td>
          <td>{row.flags.length===0
            ? 'No modeled discrepancy (not authenticated)'
            : <details><summary>{row.flags.length} warning(s)</summary>
                <ul>{row.flags.map(flag=><li key={flag}>{AUDIT_FLAG_LABELS[flag]}</li>)}</ul>
              </details>}</td>
          <td><div className="alert-triage-actions">
            {row.sourceAvailable&&<button type="button" className="source-button"
              aria-label={'Inspect same-host primary Go event '+row.primaryID+' for detection '+row.detectionID}
              onClick={()=>onInspectSource({deviceID:row.deviceID,eventID:row.primaryID})}>
              Inspect primary source</button>}
            {row.fileSourceAvailable&&<button type="button" className="source-button"
              aria-label={'Inspect same-host FileCreate reference '+row.fileID+' for detection '+row.detectionID}
              onClick={()=>onInspectSource({deviceID:row.deviceID,eventID:row.fileID,expectedSysmonID:11})}>
              Inspect FileCreate claim</button>}
            <button type="button" className="source-button"
              aria-label={'Inspect reported detection '+row.detectionID+' on '+row.deviceID}
              onClick={()=>onInvestigate({kind:'detection',detectionID:row.detectionID,deviceID:row.deviceID})}>
              Inspect detection</button>
          </div></td>
        </tr>)}</tbody>
      </table></div>
      <div className="analyst-paging" role="group" aria-label="Detection source audit pages">
        <button type="button" className="secondary" disabled={page.page===0}
          onClick={()=>setRequestedPage(page.page-1)}>Previous audit page</button>
        <span aria-live="polite">Page {page.page+1} of {page.pages}</span>
        <button type="button" className="secondary" disabled={page.page===page.pages-1}
          onClick={()=>setRequestedPage(page.page+1)}>Next audit page</button>
      </div></>}
    <p className="minor">An Event 11 FileCreate report is separate from
      an Event 7 image-load report. Even agreement between two untrusted
      records cannot establish secure source provenance or scan coverage.
      No quarantine, isolation, policy, dismissal or scan command is available.</p>
  </section>;
}
