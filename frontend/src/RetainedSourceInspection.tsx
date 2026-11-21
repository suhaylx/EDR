import type { LabTelemetryEvent } from './telemetry.js';
import { SYSMON_EVENT_NAMES } from './telemetry.js';
import { locateRetainedSource } from './retained-source.js';
import type { RetainedSourceSelection } from './multisignal-alert-triage.js';
import type { InvestigationSeed } from './investigation.js';

/** Only the last 100 lab API events are available; no historical-source claim. */
export function RetainedSourceInspection({events,selection,onBack,onInvestigate}: {
  events: readonly LabTelemetryEvent[];
  selection: RetainedSourceSelection;
  onBack: () => void;
  onInvestigate: (seed: InvestigationSeed) => void;
}) {
  const event = locateRetainedSource(events,selection);
  const sysmon = event?.source === 'sysmon' && event.source_event_id > 0;
  return <section className="panel" aria-labelledby="source-inspection-title">
    <h2 id="source-inspection-title">Inspect retained source event</h2>
    <p>Selected Go event ID <strong>{selection.eventID}</strong> on endpoint
      <strong> {selection.deviceID}</strong>. This lookup uses both identifiers;
      it does not match other endpoints or guess from a Windows EventRecordID.</p>
    <button className="secondary" type="button" onClick={onBack}>
      Back to retained event list
    </button>
    {event ? <>
      <p className="source-selection" role="status">
        Matching event is present among the {events.length} returned lab event record(s).
        Source identity and telemetry are reported, not authenticated endpoint evidence.
      </p>
      <dl className="source-inspection-details">
        <div><dt>Go event ID</dt><dd>{event.id}</dd></div>
        <div><dt>Endpoint / platform</dt><dd>{event.device_id} / {event.platform}</dd></div>
        <div><dt>Reported collector</dt><dd>{event.source || 'unknown'}</dd></div>
        <div><dt>Event classification</dt><dd>{sysmon
          ? 'Sysmon ID ' + event.source_event_id + ' — ' +
            (SYSMON_EVENT_NAMES[event.source_event_id] || 'unclassified')
          : 'Source class not established — ' + (event.type || 'unreported')}</dd></div>
        <div><dt>Windows source RecordID</dt><dd>{event.source_record_id || 'not reported'}
          <span className="minor">Informational only; not the lookup key or verified provenance.</span></dd></div>
        <div><dt>Reported event time</dt><dd>{event.time || 'not reported'}</dd></div>
        <div><dt>Server receipt time</dt><dd>{event.received_at || 'not reported'}</dd></div>
        <div><dt>Reported time origin</dt><dd>{event.time_origin || 'not established'}</dd></div>
        <div><dt>Process GUID</dt><dd>{event.process_guid || 'not reported'}</dd></div>
        <div><dt>Process image</dt><dd>{event.image || 'not reported'}</dd></div>
        <div><dt>Reported object path</dt><dd>{event.file_path || 'not reported'}</dd></div>
      </dl>
      {event.source_event_id === 24
        ? <p className="minor">Sysmon Event 24 is clipboard-change metadata only.
            Clipboard contents are intentionally not shown.</p>
        : <>
          {event.detail && <p className="source-detail">Reported detail: {event.detail}</p>}
          {Object.keys(event.source_fields).length > 0 && <details className="event-field-details">
            <summary>Reported source metadata ({Object.keys(event.source_fields).length})</summary>
            <dl>{Object.entries(event.source_fields).map(([key,value]) =>
              <div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{value}</dd></div>)}</dl>
          </details>}
        </>}
      {event.process_guid
        ? <button className="source-button" type="button" onClick={() =>
            onInvestigate({deviceID:event.device_id,kind:'process',processGUID:event.process_guid})}>
            Inspect retained process evidence
          </button>
        : <p className="minor">No process GUID was reported for this source event.
            Process investigation is unavailable without a supported seed.</p>}
    </> : <p className="empty" role="status">
      The selected source event is not among the {events.length} events returned
      by the lab API (at most 100 recent records). It may be older, evicted,
      unavailable, or excluded from this response. No cross-endpoint or
      RecordID fallback is attempted; absence is not proof the event never occurred.
    </p>}
    <p className="minor">This read-only view cannot verify event provenance,
      telemetry completeness, policy enforcement or incident causation. No
      quarantine, isolation or privileged endpoint command is available.</p>
  </section>;
}
