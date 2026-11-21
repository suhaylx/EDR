import { useState } from 'react';
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import { detectionsInWindow, seedForDetection } from './detections.js';
import type { DayWindow } from './overview.js';
import type { InvestigationSeed } from './investigation.js';
import {
  filteredRetainedAlerts, primaryDetectionSource, linkedFileCreateSource, retainedAlertCounts,
  type SeverityFilter, type SourceFilter, type RetainedSourceSelection,
} from './multisignal-alert-triage.js';
import {EMPTY_ANALYST_FILTERS, filterAnalystWorklist, sortAnalystWorklist,
  paginateWorklist, type AnalystFilters, type WorklistSort, type PageSize} from './analyst-worklist.js';
import { summarizeReturnedEvidenceGaps } from './evidence-gaps.js';

/**
 * Retained detection triage: Source IDs identify Go-retained events, not
 * authenticated endpoint/tenant evidence. No endpoint response controls.
 */
export function MultisignalAlertTriage({detections,events,generatedAt,days,onInvestigate,onInspectSource}: {
  detections: LabDetection[];
  events: readonly LabTelemetryEvent[];
  generatedAt: string;
  days: DayWindow;
  onInvestigate: (seed: InvestigationSeed) => void;
  onInspectSource: (selection: RetainedSourceSelection) => void;
}) {
  const [severity,setSeverity] = useState<SeverityFilter>('all');
  const [source,setSource] = useState<SourceFilter>('all');
  const [query,setQuery] = useState('');
  const [analyst,setAnalyst] = useState<AnalystFilters>(EMPTY_ANALYST_FILTERS);
  const [sort,setSort] = useState<WorklistSort>('newest');
  const [pageSize,setPageSize] = useState<PageSize>(25);
  const [pageIndex,setPageIndex] = useState(0);
  const retained = detectionsInWindow(detections,generatedAt,days);
  const initial = filteredRetainedAlerts(retained,severity,source,query);
  const filtered = filterAnalystWorklist(initial,events,analyst);
  const ordered = sortAnalystWorklist(filtered,sort);
  const page = paginateWorklist(ordered,pageIndex,pageSize);
  const counts = retainedAlertCounts(retained);
  const gaps = summarizeReturnedEvidenceGaps(retained,events);
  const canClear = severity !== 'all' || source !== 'all' || query !== '' ||
    sort !== 'newest' || pageSize !== 25 ||
    Object.entries(analyst).some(([key,value]) =>
      value !== EMPTY_ANALYST_FILTERS[key as keyof AnalystFilters]);
  const updateAnalyst = <K extends keyof AnalystFilters>(key:K,value:AnalystFilters[K]) => {
    setAnalyst(current=>({...current,[key]:value}));setPageIndex(0);
  };
  const clear = () => {setSeverity('all');setSource('all');setQuery('');
    setAnalyst(EMPTY_ANALYST_FILTERS);setSort('newest');setPageSize(25);setPageIndex(0);};

  return <section className="panel" aria-labelledby="alerts-title">
    <h2 id="alerts-title">Observed detection signals</h2>
    <p>Heuristic multisignal matches returned by the development API for the selected
      {days}-day UTC window, not confirmed incidents or infections. Counts refer
      only to the retained evidence, not installed detection-policy coverage.</p>
    <dl className="alert-triage-summary" aria-label="Reported severity distribution">
      <div><dt>Critical + high</dt><dd>{counts.critical + counts.high}</dd></div>
      <div><dt>Medium</dt><dd>{counts.medium}</dd></div>
      <div><dt>Low</dt><dd>{counts.low}</dd></div>
      <div><dt>Other / unclassified</dt><dd>{counts.other}</dd></div>
    </dl>
    <div className="alert-triage-filters">
      <div className="field"><label htmlFor="alert-triage-severity">Severity</label>
        <select id="alert-triage-severity" value={severity}
          onChange={e=>{setSeverity(e.target.value as SeverityFilter);setPageIndex(0);}}>
          <option value="all">All reported severities</option>
          <option value="critical_high">Critical or high</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="other">Other / unclassified</option>
        </select></div>
      <div className="field"><label htmlFor="alert-triage-source">Source event classification</label>
        <select id="alert-triage-source" value={source}
          onChange={e=>{setSource(e.target.value as SourceFilter);setPageIndex(0);}}>
          <option value="all">Any reported source type</option>
          <option value="with_event_type">Numeric Sysmon ID reported</option>
          <option value="unknown_event_type">Numeric Sysmon ID not reported</option>
        </select></div>
      <div className="field"><label htmlFor="alert-triage-search">Search retained evidence</label>
        <input id="alert-triage-search" type="search" maxLength={200}
          autoComplete="off" value={query} onChange={e=>{setQuery(e.target.value);setPageIndex(0);}}
          aria-describedby="alert-triage-note" /></div>
    </div>
    <details className="analyst-filters">
      <summary>Additional analyst filters (local evidence only)</summary>
      <div className="analyst-filter-grid">
        <div className="field"><label htmlFor="analyst-host">Exact endpoint ID</label>
          <input id="analyst-host" type="text" maxLength={96} autoComplete="off"
            value={analyst.host} onChange={e=>updateAnalyst('host',e.target.value)}/></div>
        <div className="field"><label htmlFor="analyst-rule">Exact rule ID</label>
          <input id="analyst-rule" type="text" maxLength={160} autoComplete="off"
            value={analyst.rule} onChange={e=>updateAnalyst('rule',e.target.value)}/></div>
        <div className="field"><label htmlFor="analyst-category">Exact reported category</label>
          <input id="analyst-category" type="text" maxLength={160} autoComplete="off"
            value={analyst.category} onChange={e=>updateAnalyst('category',e.target.value)}/></div>
        <div className="field"><label htmlFor="analyst-confidence">Exact reported confidence</label>
          <input id="analyst-confidence" type="text" maxLength={80} autoComplete="off"
            value={analyst.confidence} onChange={e=>updateAnalyst('confidence',e.target.value)}/></div>
        <div className="field"><label htmlFor="analyst-process">Process GUID evidence</label>
          <select id="analyst-process" value={analyst.processGuid}
            onChange={e=>updateAnalyst('processGuid',e.target.value as AnalystFilters['processGuid'])}>
            <option value="all">Any</option><option value="present">Reported GUID</option>
            <option value="absent">No reported GUID</option>
          </select></div>
        <div className="field"><label htmlFor="analyst-filecreate">Linked FileCreate ID</label>
          <select id="analyst-filecreate" value={analyst.fileCreate}
            onChange={e=>updateAnalyst('fileCreate',e.target.value as AnalystFilters['fileCreate'])}>
            <option value="all">Any</option><option value="present">Linked ID reported</option>
            <option value="absent">No linked ID reported</option>
          </select></div>
        <div className="field"><label htmlFor="analyst-target">Reported target object</label>
          <select id="analyst-target" value={analyst.target}
            onChange={e=>updateAnalyst('target',e.target.value as AnalystFilters['target'])}>
            <option value="all">Any</option><option value="present">Target reported</option>
            <option value="absent">Target not reported</option>
          </select></div>
        <div className="field"><label htmlFor="analyst-sample">Primary source in returned event sample</label>
          <select id="analyst-sample" value={analyst.sample}
            onChange={e=>updateAnalyst('sample',e.target.value as AnalystFilters['sample'])}>
            <option value="all">Any</option><option value="in_sample">Found in sample</option>
            <option value="not_in_sample">Not in sample (not proof of loss)</option>
          </select></div>
      </div>
    </details>
    <div className="analyst-sorting">
      <div className="field"><label htmlFor="analyst-sort">Order locally</label>
        <select id="analyst-sort" value={sort} onChange={e=>{setSort(e.target.value as WorklistSort);setPageIndex(0);}}>
          <option value="newest">Newest reported observation</option>
          <option value="oldest">Oldest reported observation</option>
          <option value="severity">Reported severity (critical first)</option>
          <option value="endpoint">Endpoint ID</option>
          <option value="rule">Rule ID</option>
          <option value="confidence">Reported confidence (high first)</option>
        </select></div>
      <div className="field"><label htmlFor="analyst-page-size">Rows per page</label>
        <select id="analyst-page-size" value={pageSize} onChange={e=>{setPageSize(Number(e.target.value) as PageSize);setPageIndex(0);}}>
          <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
        </select></div>
    </div>
    <section aria-labelledby="alert-evidence-gap-title" className="alert-evidence-gap-summary">
      <h3 id="alert-evidence-gap-title">Returned-record evidence gaps (not security coverage)</h3>
      <dl>
        <div><dt>No process GUID</dt><dd>{gaps.missingProcessGuid}</dd></div>
        <div><dt>Numeric Sysmon type unknown</dt><dd>{gaps.unknownNumericEventType}</dd></div>
        <div><dt>No separate FileCreate ID linked</dt><dd>{gaps.noLinkedFileCreate}</dd></div>
        <div><dt>No target object reported</dt><dd>{gaps.noTargetObject}</dd></div>
        <div><dt>Primary event not in current 100-record sample</dt><dd>{gaps.primaryNotInEventSample}</dd></div>
        <div><dt>Primary event found in returned sample</dt><dd>{gaps.primaryInEventSample}</dd></div>
      </dl>
      <p className="minor">These are properties of the two lab API responses,
        not proof of Sysmon policy coverage, missing event ingestion, or a clean endpoint.</p>
    </section>
    <p id="alert-triage-note" className="minor">Local filters search returned
      endpoint, rule, target, process and source identifiers only. Missing
      source type or process GUID means unknown evidence, not a missing threat.</p>
    <button className="secondary" type="button" disabled={!canClear}
      onClick={clear}>Clear local filters</button>
    <p role="status" aria-live="polite" aria-atomic="true">
      {page.total} of {retained.length} retained detection record(s) match. Page {page.page+1} of {page.pages}; rows {page.start}–{page.end}.
    </p>
    {retained.length === 0
      ? <p className="empty">No retained detection signals returned for this UTC window.
        This does not establish complete collection or endpoint safety.</p>
      : filtered.length === 0
      ? <p className="empty">No retained detection records match these local filters.
        This does not establish that the fleet is safe.</p>
      : <><div className="table-scroll"><table>
        <caption>Locally sorted retained lab evidence. Source inspection matches
          the exact Go event ID and endpoint only; no endpoint action is issued.</caption>
        <thead><tr>
          <th scope="col">Observed UTC</th><th scope="col">Severity / confidence</th>
          <th scope="col">Endpoint / process</th><th scope="col">Rule / category</th>
          <th scope="col">Reported target</th><th scope="col">Source evidence</th>
          <th scope="col">Inspect retained evidence</th>
        </tr></thead>
        <tbody>{page.records.map(d=>{
          const primary = primaryDetectionSource(d);
          const linkedFile = linkedFileCreateSource(d);
          return <tr key={d.id}>
            <td>{d.observed_at}</td>
            <td>{d.severity} / {d.confidence}</td>
            <td>{d.device_id}<span className="minor">Process GUID: {d.process_guid || 'not reported'}</span></td>
            <td>{d.rule_id}<span className="minor">{d.category}</span></td>
            <td>{d.target_object || d.module_path || 'Target not reported'}
              <span className="minor">Process image: {d.process_image || 'not reported'}</span></td>
            <td>{primary?.eventID || 'Not reported'}
              <span className="minor">{d.evidence_source_event_id
                ? 'Reported Sysmon Event ID ' + d.evidence_source_event_id
                : 'Numeric event type unknown'}</span>
              {d.file_create_event_id && <span className="minor">
                Separate linked FileCreate ID: {d.file_create_event_id}</span>}</td>
            <td><div className="alert-triage-actions">
              {primary
                ? <button type="button" className="source-button"
                    onClick={()=>onInspectSource(primary)}
                    aria-label={'Inspect retained source event '+primary.eventID+' on '+primary.deviceID}>
                    Inspect source event</button>
                : <span className="minor">No source ID reported</span>}
              {linkedFile
                ? <button type="button" className="source-button"
                    onClick={()=>onInspectSource(linkedFile)}
                    aria-label={'Inspect separately reported FileCreate source '+linkedFile.eventID+' on '+linkedFile.deviceID}>
                    Inspect linked FileCreate reference</button>
                : null}
              {d.process_guid
                ? <button type="button" className="source-button"
                    onClick={()=>onInvestigate(seedForDetection(d))}
                    aria-label={'Inspect process evidence for '+d.rule_id+' on '+d.device_id}>
                    Inspect process evidence</button>
                : <span className="minor">No process GUID for process investigation</span>}
            </div></td>
          </tr>;
        })}</tbody>
      </table></div>
        <div className="analyst-paging" role="group" aria-label="Local alert result pages">
          <button className="secondary" type="button" disabled={page.page===0}
            onClick={()=>setPageIndex(page.page-1)}>Previous page</button>
          <span aria-live="polite">Page {page.page+1} of {page.pages}</span>
          <button className="secondary" type="button" disabled={page.page>=page.pages-1}
            onClick={()=>setPageIndex(page.page+1)}>Next page</button>
        </div></>}
    <p className="minor">Source ID references the Go retained event ID, not the
      Windows EventRecordID. FileCreate evidence is not DLL execution.
      All records are lab reports without authenticated endpoint provenance.
      There are no containment, quarantine, policy or incident-close controls.</p>
  </section>;
}
