import { useState } from 'react';
import type { LabDetection } from './detections.js';
import { detectionsInWindow, seedForDetection } from './detections.js';
import type { DayWindow } from './overview.js';
import type { InvestigationSeed } from './investigation.js';
import {
  filteredRetainedAlerts, primaryDetectionSource, retainedAlertCounts,
  type SeverityFilter, type SourceFilter, type RetainedSourceSelection,
} from './multisignal-alert-triage.js';

/**
 * Retained detection triage: Source IDs identify Go-retained events, not
 * authenticated endpoint/tenant evidence. No endpoint response controls.
 */
export function MultisignalAlertTriage({detections,generatedAt,days,onInvestigate,onInspectSource}: {
  detections: LabDetection[];
  generatedAt: string;
  days: DayWindow;
  onInvestigate: (seed: InvestigationSeed) => void;
  onInspectSource: (selection: RetainedSourceSelection) => void;
}) {
  const [severity,setSeverity] = useState<SeverityFilter>('all');
  const [source,setSource] = useState<SourceFilter>('all');
  const [query,setQuery] = useState('');
  const retained = detectionsInWindow(detections,generatedAt,days);
  const filtered = filteredRetainedAlerts(retained,severity,source,query);
  const counts = retainedAlertCounts(retained);
  const canClear = severity !== 'all' || source !== 'all' || query !== '';

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
          onChange={e=>setSeverity(e.target.value as SeverityFilter)}>
          <option value="all">All reported severities</option>
          <option value="critical_high">Critical or high</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="other">Other / unclassified</option>
        </select></div>
      <div className="field"><label htmlFor="alert-triage-source">Source event classification</label>
        <select id="alert-triage-source" value={source}
          onChange={e=>setSource(e.target.value as SourceFilter)}>
          <option value="all">Any reported source type</option>
          <option value="with_event_type">Numeric Sysmon ID reported</option>
          <option value="unknown_event_type">Numeric Sysmon ID not reported</option>
        </select></div>
      <div className="field"><label htmlFor="alert-triage-search">Search retained evidence</label>
        <input id="alert-triage-search" type="search" maxLength={200}
          autoComplete="off" value={query} onChange={e=>setQuery(e.target.value)}
          aria-describedby="alert-triage-note" /></div>
    </div>
    <p id="alert-triage-note" className="minor">Local filters search returned
      endpoint, rule, target, process and source identifiers only. Missing
      source type or process GUID means unknown evidence, not a missing threat.</p>
    <button className="secondary" type="button" disabled={!canClear}
      onClick={()=>{setSeverity('all');setSource('all');setQuery('');}}>Clear local filters</button>
    <p role="status" aria-live="polite" aria-atomic="true">
      {filtered.length} of {retained.length} retained detection record(s) shown.
    </p>
    {retained.length === 0
      ? <p className="empty">No retained detection signals returned for this UTC window.
        This does not establish complete collection or endpoint safety.</p>
      : filtered.length === 0
      ? <p className="empty">No retained detection records match these local filters.
        This does not establish that the fleet is safe.</p>
      : <div className="table-scroll"><table>
        <caption>Lab detection evidence, newest first. Source inspection matches
          the exact Go event ID and endpoint only; no endpoint action is issued.</caption>
        <thead><tr>
          <th scope="col">Observed UTC</th><th scope="col">Severity / confidence</th>
          <th scope="col">Endpoint / process</th><th scope="col">Rule / category</th>
          <th scope="col">Reported target</th><th scope="col">Source evidence</th>
          <th scope="col">Inspect retained evidence</th>
        </tr></thead>
        <tbody>{filtered.map(d=>{
          const primary = primaryDetectionSource(d);
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
              {d.process_guid
                ? <button type="button" className="source-button"
                    onClick={()=>onInvestigate(seedForDetection(d))}
                    aria-label={'Inspect process evidence for '+d.rule_id+' on '+d.device_id}>
                    Inspect process evidence</button>
                : <span className="minor">No process GUID for process investigation</span>}
            </div></td>
          </tr>;
        })}</tbody>
      </table></div>}
    <p className="minor">Source ID references the Go retained event ID, not the
      Windows EventRecordID. FileCreate evidence is not DLL execution.
      All records are lab reports without authenticated endpoint provenance.
      There are no containment, quarantine, policy or incident-close controls.</p>
  </section>;
}
