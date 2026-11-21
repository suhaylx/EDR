import { useState } from 'react';
import type { LabSOCOverview } from './overview.js';
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import type { LabScanJob } from './lab-api.js';
import {
  reviewEvidenceSnapshot, filterSnapshotEndpoints,pageSnapshotEndpoints,
  DEFAULT_SNAPSHOT_FILTERS,type SnapshotFilters,type SnapshotSort,
  type SnapshotStatus,type SnapshotPageSize,
} from './evidence-snapshot.js';

/** Review only the current, already-loaded API responses.
 * This is not collection completeness, tenant security or endpoint attestation.
 */
export function EvidenceSnapshotReview({overview,detections,events,jobs}:{
  overview:LabSOCOverview;
  detections:readonly LabDetection[];
  events:readonly LabTelemetryEvent[];
  jobs:readonly LabScanJob[];
}) {
  const [filters,setFilters]=useState<SnapshotFilters>(DEFAULT_SNAPSHOT_FILTERS);
  const [size,setSize]=useState<SnapshotPageSize>(25);
  const [requested,setRequested]=useState(0);
  const snapshot=reviewEvidenceSnapshot(overview,detections,events,jobs);
  const filtered=filterSnapshotEndpoints(snapshot.endpointRows,filters);
  const page=pageSnapshotEndpoints(filtered,requested,size);
  const update=<K extends keyof SnapshotFilters>(key:K,value:SnapshotFilters[K])=>{
    setFilters(old=>({...old,[key]:value}));setRequested(0);
  };
  const reset=()=>{setFilters(DEFAULT_SNAPSHOT_FILTERS);setSize(25);setRequested(0);};
  const changed=Object.entries(filters).some(([key,value])=>
    value!==DEFAULT_SNAPSHOT_FILTERS[key as keyof SnapshotFilters])||size!==25;
  return <section className="panel snapshot-review" aria-labelledby="snapshot-review-title">
    <h2 id="snapshot-review-title">Evidence snapshot review</h2>
    <p>Compares four individually fetched, read-only laboratory API responses.
      The server reports its overview was generated at <strong>{snapshot.generatedAt}</strong>
      for {snapshot.days} UTC day(s). Requests are not an atomic backend transaction,
      and none of the data confirms active endpoint protection.</p>
    <div className="snapshot-review-columns">
      <section aria-labelledby="snapshot-server-title">
        <h3 id="snapshot-server-title">Go overview totals — reported</h3>
        <dl className="snapshot-review-metrics">
          <div><dt>Enrolled records</dt><dd>{snapshot.serverReported.agents}</dd></div>
          <div><dt>Alert count in Go overview</dt><dd>{snapshot.serverReported.alerts}</dd></div>
          <div><dt>Event count in Go overview</dt><dd>{snapshot.serverReported.events}</dd></div>
        </dl>
      </section>
      <section aria-labelledby="snapshot-samples-title">
        <h3 id="snapshot-samples-title">Separately returned samples</h3>
        <dl className="snapshot-review-metrics">
          <div><dt>Alert records in UTC window</dt><dd>{snapshot.returned.detectionsInWindow}</dd></div>
          <div><dt>Event records in UTC window</dt><dd>{snapshot.returned.eventsInWindow}</dd></div>
          <div><dt>Scan jobs returned (all available job dates)</dt><dd>{snapshot.returned.scanJobs}</dd></div>
          <div><dt>Alert records outside window</dt><dd>{snapshot.returned.detectionsOutsideWindow}</dd></div>
          <div><dt>Event records outside window</dt><dd>{snapshot.returned.eventsOutsideWindow}</dd></div>
          <div><dt>Events without usable time</dt><dd>{snapshot.returned.eventsUnknownTime}</dd></div>
        </dl>
      </section>
    </div>
    <section aria-labelledby="snapshot-source-title">
      <h3 id="snapshot-source-title">Returned event classification and time origin</h3>
      <dl className="snapshot-review-metrics">
        <div><dt>Windows Sysmon reports in window</dt><dd>{snapshot.returned.windowsSysmonEventsInWindow}</dd></div>
        <div><dt>Linux event reports in window</dt><dd>{snapshot.returned.linuxEventsInWindow}</dd></div>
        <div><dt>Other event reports in window</dt><dd>{snapshot.returned.otherEventsInWindow}</dd></div>
        <div><dt>Go receipt timestamp available (not window cutoff)</dt><dd>{snapshot.returned.eventsUsingServerClock}</dd></div>
        <div><dt>Sender time fallback used</dt><dd>{snapshot.returned.eventsUsingSenderClock}</dd></div>
        <div><dt>Event timestamps after overview generation</dt><dd>{snapshot.returned.eventsAfterOverview}</dd></div>
        <div><dt>Alert timestamps after overview generation</dt><dd>{snapshot.returned.detectionsAfterOverview}</dd></div>
        <div><dt>Successful-looking quick/full claims unsupported</dt><dd>{snapshot.returned.unsupportedScanClaims}</dd></div>
        <div><dt>Reported signature-negative path results</dt><dd>{snapshot.returned.signatureNegative}</dd></div>
      </dl>
      <details className="snapshot-sysmon">
        <summary>Inspect numeric Sysmon IDs observed in the returned UTC window</summary>
        {snapshot.sysmonTypes.length===0
          ? <p className="empty">No Windows Sysmon event types were observed in the returned sample.
            Installed policy, actual event collection and endpoint safety remain unknown.</p>
          : <div className="table-scroll"><table>
            <caption>Observed numeric Sysmon IDs (not required/installed policy coverage)</caption>
            <thead><tr><th scope="col">Event ID</th><th scope="col">Event label</th><th scope="col">Returned records</th></tr></thead>
            <tbody>{snapshot.sysmonTypes.map(e=><tr key={e.id}>
              <th scope="row">{e.id}</th><td>{e.label}</td><td>{e.count}</td>
            </tr>)}</tbody>
          </table></div>}
      </details>
    </section>
    <section aria-labelledby="snapshot-limits-title" className="snapshot-limits">
      <h3 id="snapshot-limits-title">Scope limits and uncertainty</h3>
      <ul>{snapshot.warnings.map(w=><li key={w}>{w}</li>)}</ul>
      <dl className="snapshot-review-metrics">
        <div><dt>Event IDs not in current inventory</dt><dd>{snapshot.returned.eventsNotInInventory}</dd></div>
        <div><dt>Alert endpoint IDs not in inventory</dt><dd>{snapshot.returned.detectionsNotInInventory}</dd></div>
        <div><dt>Scan endpoint IDs not in inventory</dt><dd>{snapshot.returned.scanJobsNotInInventory}</dd></div>
        <div><dt>Unscanned job reports</dt><dd>{snapshot.returned.unscanned}</dd></div>
        <div><dt>Unknown / unsupported job completions</dt><dd>{snapshot.returned.unknownScanState}</dd></div>
      </dl>
    </section>
    <section aria-labelledby="snapshot-endpoints-title">
      <h3 id="snapshot-endpoints-title">Endpoint IDs present in the overview inventory</h3>
      <p>Totals below count only reports in this response set and the selected
        overview window. A zero is not a negative security finding. Scan job
        counts are returned job records and are not restricted to this time window.</p>
      <div className="snapshot-review-filters">
        <div className="field"><label htmlFor="snapshot-search">Filter endpoint ID or platform</label>
          <input id="snapshot-search" type="search" maxLength={100}
            autoComplete="off" value={filters.search}
            onChange={e=>update('search',e.target.value)}/></div>
        <div className="field"><label htmlFor="snapshot-heartbeat">Reported heartbeat</label>
          <select id="snapshot-heartbeat" value={filters.status}
            onChange={e=>update('status',e.target.value as SnapshotStatus)}>
            <option value="all">All states</option><option value="online">Online</option>
            <option value="offline">Offline</option><option value="unknown">Unknown</option>
          </select></div>
        <div className="field"><label htmlFor="snapshot-sort">Sort inventory rows</label>
          <select id="snapshot-sort" value={filters.sort}
            onChange={e=>update('sort',e.target.value as SnapshotSort)}>
            <option value="id">Exact endpoint ID</option>
            <option value="alerts">Returned alert count</option>
            <option value="events">Returned event count</option>
            <option value="scans">Returned scan job count</option>
            <option value="heartbeat">Unknown/offline heartbeat first</option>
          </select></div>
        <div className="field"><label htmlFor="snapshot-page-size">Rows per page</label>
          <select id="snapshot-page-size" value={size}
            onChange={e=>{setSize(Number(e.target.value) as SnapshotPageSize);setRequested(0);}}>
            <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
          </select></div>
      </div>
      <button type="button" className="secondary"
        onClick={reset} disabled={!changed}>Clear local snapshot filters</button>
      <p role="status" aria-live="polite" aria-atomic="true">
        {page.total} of {snapshot.endpointRows.length} enrolled record(s) match.
        Page {page.page+1} of {page.pages}; rows {page.start}–{page.end}.
      </p>
      {page.total===0
        ? <p className="empty">No enrolled records match these local filters.
            This does not prove absence of activity, protection or threats.</p>
        : <><div className="table-scroll"><table className="snapshot-endpoint-table">
          <caption>Only the overview's enrolled IDs, with same-ID returned
            evidence samples; no unverified cross-tenant or causal association.</caption>
          <thead><tr>
            <th scope="col">Endpoint</th><th scope="col">Reported platform</th>
            <th scope="col">Heartbeat</th><th scope="col">Returned alerts in window</th>
            <th scope="col">Returned events in window</th>
            <th scope="col">Returned scan job records</th>
            <th scope="col">Distinct observed Sysmon IDs</th>
          </tr></thead>
          <tbody>{page.rows.map(r=><tr key={r.id}>
            <th scope="row">{r.id}</th><td>{r.platform}</td>
            <td>{r.heartbeat} (Go heartbeat classification)</td>
            <td>{r.detectionsInWindow}</td><td>{r.eventsInWindow}</td>
            <td>{r.scanJobsReturned}</td><td>{r.observedSysmonTypes}</td>
          </tr>)}</tbody>
        </table></div>
        <div className="analyst-paging" role="group" aria-label="Evidence snapshot endpoint pages">
          <button type="button" className="secondary" disabled={page.page===0}
            onClick={()=>setRequested(page.page-1)}>Previous snapshot page</button>
          <span aria-live="polite">Page {page.page+1} of {page.pages}</span>
          <button type="button" className="secondary" disabled={page.page===page.pages-1}
            onClick={()=>setRequested(page.page+1)}>Next snapshot page</button>
        </div></>}
    </section>
    <p className="minor">This is an ephemeral, non-persisted lab UX review.
      No verification of signatures, endpoint policy, Sysmon configuration,
      agent installation, tenant scope, malware verdict or data durability is performed.</p>
  </section>;
}
