import { useState } from 'react';
import type { DayWindow } from './overview.js';
import type { LabDetection } from './detections.js';
import { detectionsInWindow, seedForDetection } from './detections.js';
import type { InvestigationSeed } from './investigation.js';
import {
  filterRetainedAlerts, summarizeRetainedAlerts,
  type AlertSeverityFilter, type AlertSourceFilter,
} from './alert-triage.js';

/** Server-observed detections only. Filtering and investigation navigation are read-only. */
export function AlertsTriageView({detections, generatedAt, days, onInvestigate}: {
  detections: LabDetection[];
  generatedAt: string;
  days: DayWindow;
  onInvestigate: (seed: InvestigationSeed) => void;
}) {
  const [severity, setSeverity] = useState<AlertSeverityFilter>('all');
  const [source, setSource] = useState<AlertSourceFilter>('all');
  const [query, setQuery] = useState('');
  const retained = detectionsInWindow(detections, generatedAt, days);
  const filtered = filterRetainedAlerts(retained, severity, source, query);
  const counts = summarizeRetainedAlerts(retained);

  return <section className="panel" aria-labelledby="alerts-title">
    <h2 id="alerts-title">Observed detection signals</h2>
    <p>These are heuristic detections retained by the lab API, not confirmed
      incidents or infections. The {days}-day window ends at the Go server's
      reported generation timestamp. Local filtering never issues new endpoint commands.</p>
    <dl className="alert-triage-summary" aria-label="Retained detection severity totals">
      <div><dt>Critical + high</dt><dd>{counts.critical + counts.high}</dd></div>
      <div><dt>Medium</dt><dd>{counts.medium}</dd></div>
      <div><dt>Low</dt><dd>{counts.low}</dd></div>
      <div><dt>Other / unclassified</dt><dd>{counts.other}</dd></div>
    </dl>
    <div className="alert-triage-filters">
      <div className="field">
        <label htmlFor="alert-severity-filter">Severity</label>
        <select id="alert-severity-filter" value={severity}
          onChange={event => setSeverity(event.target.value as AlertSeverityFilter)}>
          <option value="all">All reported severities</option>
          <option value="critical_high">Critical or high</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="other">Other / unclassified</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="alert-source-filter">Linked file-create evidence</label>
        <select id="alert-source-filter" value={source}
          onChange={event => setSource(event.target.value as AlertSourceFilter)}>
          <option value="all">Any retained source evidence</option>
          <option value="file_create_linked">File-create ID linked in record</option>
          <option value="file_create_not_linked">No file-create ID linked in record</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="alert-query">Search endpoint, rule, process, or source ID</label>
        <input id="alert-query" type="search" maxLength={200} autoComplete="off"
          value={query} onChange={event => setQuery(event.target.value)}
          aria-describedby="alert-filter-explanation"/>
      </div>
    </div>
    <p id="alert-filter-explanation" className="minor">Search and filters examine only
      already returned detection records. An absent linked file-create ID is not
      proof that a FileCreate event never occurred. Event IDs and paths are
      unverified lab evidence, rendered as text.</p>
    <button type="button" className="secondary alert-clear"
      onClick={() => { setSeverity('all'); setSource('all'); setQuery(''); }}>
      Clear local filters
    </button>
    <p role="status" aria-live="polite" aria-atomic="true">
      {filtered.length} of {retained.length} retained detection record(s) shown.
      {counts.other > 0 ? ' Includes reported severities outside critical/high/medium/low.' : ''}
    </p>
    {retained.length === 0
      ? <p className="empty">No detections were returned for this UTC window.
          This does not establish complete collection or a safe endpoint.</p>
      : filtered.length === 0
      ? <p className="empty">No retained detections match these local filters.
          This does not establish that the fleet is safe.</p>
      : <div className="table-scroll"><table>
        <caption>Filtered retained detections (newest first). Investigate opens
          a prefilled read-only evidence query; no containment is performed.</caption>
        <thead><tr>
          <th scope="col">Observed time</th>
          <th scope="col">Severity / confidence</th>
          <th scope="col">Endpoint / process</th>
          <th scope="col">Detection rule</th>
          <th scope="col">Reported artifact</th>
          <th scope="col">Source IDs</th>
          <th scope="col">Investigation</th>
        </tr></thead>
        <tbody>{filtered.map(d => <tr key={d.id}>
          <td>{d.observed_at}</td>
          <td>{d.severity} / {d.confidence}</td>
          <td>{d.device_id}<span className="minor">Process GUID: {d.process_guid}</span></td>
          <td>{d.rule_id}<span className="minor">{d.category}</span></td>
          <td>{d.module_path || 'Artifact not reported'}
            <span className="minor">Process image: {d.process_image || 'not reported'}</span></td>
          <td>{d.load_event_id}
            {d.file_create_event_id
              ? <span className="minor">Linked file-create: {d.file_create_event_id}</span>
              : <span className="minor">No linked file-create ID reported</span>}</td>
          <td><button type="button" className="source-button"
            aria-label={'Investigate evidence for ' + d.rule_id + ' on ' + d.device_id}
            onClick={() => onInvestigate(seedForDetection(d))}>
            Investigate evidence
          </button></td>
        </tr>)}</tbody>
      </table></div>}
    <p className="minor">A file-create observation is separate from an observed
      module load. Source identifiers are not authenticated endpoint provenance.
      No policy changes, quarantine, isolation or other response operations occur.</p>
  </section>;
}
