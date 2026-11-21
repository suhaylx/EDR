import { useEffect, useRef, useState } from 'react';
import type { LabScanJob } from './lab-api.js';
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import type { InvestigationSeed } from './investigation.js';
import type { RetainedSourceSelection } from './multisignal-alert-triage.js';
import { scanEvidenceFlags, scanEvidenceKind, SCAN_FLAG_LABELS, SCAN_KIND_LABELS } from './scan-evidence.js';
import {
  buildScanContext, filterScanContext, pageScanContext,
  DEFAULT_CONTEXT_OPTIONS, type ContextOptions, type ContextWindow,
  type ContextSource, type ContextSort, type ContextPageSize,
  type ContextTimeBasis,
} from './scan-context.js';

const TIME_BASIS:Record<ContextTimeBasis,string>={
  server_created:'Go server-recorded job creation time',
  server_received:'Go server receipt time',
  sender_reported:'Sender-reported event time (not server receipt)',
  detection_reported:'Detection observation time (lab reported)',
  unknown:'Time unavailable',
};
/** All data already came from four successfully decoded read-only lab calls.
 * No new network call, response command, or scan scheduling is performed.
 */
export function ScanEvidenceContext({selected,jobs,detections,events,generatedAt,
  onBack,onInspectSource,onInvestigate,onSelectScan}:{
  selected:LabScanJob;
  jobs:readonly LabScanJob[];
  detections:readonly LabDetection[];
  events:readonly LabTelemetryEvent[];
  generatedAt:string;
  onBack:()=>void;
  onInspectSource:(selection:RetainedSourceSelection)=>void;
  onInvestigate:(seed:InvestigationSeed)=>void;
  onSelectScan:(id:string)=>void;
}) {
  const heading=useRef<HTMLHeadingElement>(null);
  const [options,setOptions]=useState<ContextOptions>(DEFAULT_CONTEXT_OPTIONS);
  const [pageSize,setPageSize]=useState<ContextPageSize>(25);
  const [page,setPage]=useState(0);
  const context=buildScanContext(selected,jobs,detections,events,generatedAt);
  const filtered=filterScanContext(context.entries,context.anchor,options);
  const visible=pageScanContext(filtered,page,pageSize);
  const flags=scanEvidenceFlags(selected);
  const kind=scanEvidenceKind(selected);
  const update=<K extends keyof ContextOptions>(key:K,value:ContextOptions[K])=>{
    setOptions(old=>({...old,[key]:value}));setPage(0);
  };
  useEffect(()=>{
    heading.current?.focus();
    setPage(0);
    setOptions(DEFAULT_CONTEXT_OPTIONS);
  },[selected.id]);

  return <section className="panel scan-context" aria-labelledby="scan-context-title">
    <button type="button" className="secondary" onClick={onBack}>
      Back to scan evidence worklist
    </button>
    <h2 id="scan-context-title" ref={heading} tabIndex={-1}>
      Scan-adjacent retained evidence
    </h2>
    <p>Selected Go lab job <strong>{selected.id}</strong> for endpoint
      <strong> {selected.agent_id}</strong>. This view shows records
      reported for exactly the same opaque endpoint ID. A shared endpoint
      and nearby timestamps do not prove that this scan ran, caused an
      event, or detected any infection.</p>

    <section aria-labelledby="scan-context-job-title" className="scan-context-selected">
      <h3 id="scan-context-job-title">Selected job — reported request metadata</h3>
      <dl className="scan-context-metrics">
        <div><dt>Job lifecycle</dt><dd>{selected.status}</dd></div>
        <div><dt>Evidence interpretation</dt><dd>{SCAN_KIND_LABELS[kind]}</dd></div>
        <div><dt>Reported scan mode</dt><dd>{selected.scan_type||'unknown'}</dd></div>
        <div><dt>Claimed result</dt><dd>{selected.verdict||'not reported'}</dd></div>
        <div><dt>Request creation UTC</dt><dd>{selected.created_at||'not reported'}</dd></div>
        <div><dt>Scan result authenticity</dt><dd>Not attested by lab API</dd></div>
      </dl>
      {flags.length>0
        ? <details className="scan-context-flags"><summary>{flags.length} reported evidence warning(s)</summary>
          <ul>{flags.map(flag=><li key={flag}>{SCAN_FLAG_LABELS[flag]}</li>)}</ul></details>
        : <p className="minor">No modeled metadata warning; this is not proof of protection.</p>}
    </section>

    <section aria-labelledby="scan-context-sample-title">
      <h3 id="scan-context-sample-title">Same-endpoint records in returned responses</h3>
      <dl className="scan-context-metrics">
        <div><dt>Other reported scan jobs</dt><dd>{context.counts.scans}</dd></div>
        <div><dt>Reported detections</dt><dd>{context.counts.detections}</dd></div>
        <div><dt>Retained telemetry events</dt><dd>{context.counts.events}</dd></div>
        <div><dt>Time anchor available</dt><dd>{context.anchor===null?'No':'Yes — job request time'}</dd></div>
      </dl>
      <p className="minor">The Go lab telemetry endpoint returns at most 100
        recent event records, while scan jobs and detections are different
        retention sources. These are sampled counts, not installed coverage,
        scan-file evidence, authentication, or complete history.</p>
      {context.hasFuture &&
        <p role="status" className="graph-warning">Some reported timestamps are later
          than the overview generation time. Clock alignment and provenance
          are not verified; do not assume a reliable causal timeline.</p>}
    </section>

    <section aria-labelledby="scan-context-filter-title">
      <h3 id="scan-context-filter-title">Filter co-observed records locally</h3>
      <div className="scan-context-filters">
        <div className="field">
          <label htmlFor="scan-context-window">Reported time distance from job request</label>
          <select id="scan-context-window" value={options.window}
            onChange={e=>update('window',e.target.value as ContextWindow)}>
            <option value="all">All returned same-endpoint records</option>
            <option value="1h">Within ±1 hour</option>
            <option value="24h">Within ±24 hours</option>
            <option value="7d">Within ±7 days</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="scan-context-kind">Evidence source</label>
          <select id="scan-context-kind" value={options.source}
            onChange={e=>update('source',e.target.value as ContextSource)}>
            <option value="all">Scans, detections and telemetry</option>
            <option value="scan">Other scan jobs only</option>
            <option value="detection">Reported detections only</option>
            <option value="event">Retained telemetry events only</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="scan-context-search">Search returned evidence IDs or metadata</label>
          <input id="scan-context-search" type="search" maxLength={200}
            autoComplete="off" value={options.search}
            onChange={e=>update('search',e.target.value)}
            aria-describedby="scan-context-clock-note"/>
        </div>
        <div className="field">
          <label htmlFor="scan-context-sort">Evidence time order</label>
          <select id="scan-context-sort" value={options.sort}
            onChange={e=>update('sort',e.target.value as ContextSort)}>
            <option value="newest">Newest reported time</option>
            <option value="oldest">Oldest reported time</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="scan-context-size">Rows per page</label>
          <select id="scan-context-size" value={pageSize}
            onChange={e=>{setPageSize(Number(e.target.value) as ContextPageSize);setPage(0);}}>
            <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
          </select>
        </div>
      </div>
      <p id="scan-context-clock-note" className="minor">Time filters are symmetric
        around the selected job's server-reported creation timestamp, not its
        scan execution. Telemetry uses Go receipt time when present, otherwise
        the explicitly reported sender clock. A detection uses its reported
        observation time. These clock sources are not independently attested.</p>
      <button className="secondary" type="button"
        onClick={()=>{setOptions(DEFAULT_CONTEXT_OPTIONS);setPageSize(25);setPage(0);}}
        disabled={options.window==='all'&&options.source==='all'&&options.sort==='newest'&&
          options.search===''&&pageSize===25}>Clear context filters</button>
      {context.anchor===null && options.window!=='all' &&
        <p role="status" className="graph-warning">Job request time is absent.
          Time-window matching is unavailable; choose All returned records
          to inspect host-scoped evidence without asserting temporal proximity.</p>}
      <p role="status" aria-live="polite" aria-atomic="true">
        {visible.total} of {context.entries.length} same-endpoint record(s) match.
        Page {visible.page+1} of {visible.pages}; rows {visible.start}–{visible.end}.
      </p>
    </section>

    {context.entries.length===0
      ? <p className="empty">No other records for this exact endpoint in the returned
          lab responses. This is not proof the endpoint had no activity.</p>
      : visible.total===0
      ? <p className="empty">No returned records match these local filters or
          time limits. Missing timestamps and retention may exclude events;
          this is not proof of no activity or scan coverage.</p>
      : <><div className="table-scroll"><table className="scan-context-table">
        <caption>Co-observed, read-only records. No attack-chain edges or
          scan-to-event causation are inferred.</caption>
        <thead><tr>
          <th scope="col">Record type</th><th scope="col">Go identity</th>
          <th scope="col">Reported class / rule</th>
          <th scope="col">Timestamp and basis</th>
          <th scope="col">Supported read-only inspection</th>
        </tr></thead>
        <tbody>{visible.rows.map(entry=><tr key={entry.key}>
          <td>{entry.kind}</td>
          <td>{entry.refID}</td>
          <td><strong>{entry.heading}</strong>
            <span className="minor">{entry.secondary}</span>
            {entry.processGUID && <span className="minor">Process GUID: {entry.processGUID}</span>}
          </td>
          <td>{entry.observedAt||'not reported'}
            <span className="minor">{TIME_BASIS[entry.timeBasis]}</span>
            {entry.futureOfServer &&
              <span className="minor">Later than overview generation time — clock unknown</span>}
          </td>
          <td>{entry.kind==='event'
            ? <button type="button" className="source-button"
                aria-label={'Inspect exact Go event '+entry.refID+' on '+entry.deviceID}
                onClick={()=>onInspectSource({deviceID:entry.deviceID,eventID:entry.refID})}>
                Inspect retained source
              </button>
            : entry.kind==='detection'
            ? <button type="button" className="source-button"
                aria-label={'Inspect detection '+entry.refID+' on '+entry.deviceID}
                onClick={()=>onInvestigate({
                  deviceID:entry.deviceID,kind:'detection',detectionID:entry.refID,
                })}>
                Inspect reported detection
              </button>
            : <button type="button" className="source-button"
                onClick={()=>onSelectScan(entry.refID)}>
                Inspect other reported scan job
              </button>}</td>
        </tr>)}</tbody>
      </table></div>
      <div className="analyst-paging" role="group" aria-label="Local scan context pages">
        <button type="button" className="secondary" disabled={visible.page===0}
          onClick={()=>setPage(visible.page-1)}>Previous context page</button>
        <span aria-live="polite">Page {visible.page+1} of {visible.pages}</span>
        <button type="button" className="secondary" disabled={visible.page===visible.pages-1}
          onClick={()=>setPage(visible.page+1)}>Next context page</button>
      </div></>}
    <p className="minor">All associations are based on the same unverified,
      sender- or server-reported endpoint ID, within separately retained
      lab response samples. No signed provenance, tenant/device authorization,
      causality, verified signature database, or response control exists here.</p>
  </section>;
}
