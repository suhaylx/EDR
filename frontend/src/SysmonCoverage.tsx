import { useMemo, useState } from 'react';
import { observedSysmonCounts, SYSMON_EVENT_NAMES, type LabTelemetryEvent } from './telemetry.js';
import type { InvestigationSeed } from './investigation.js';

/** Read-only SOC evidence view. No inferred infection edges or coverage claims. */
export function SysmonCoverage({events,onInvestigate}:{
  events:readonly LabTelemetryEvent[];
  onInvestigate:(seed:InvestigationSeed)=>void;
}) {
  const [device,setDevice]=useState('');
  const [category,setCategory]=useState<'all'|'sysmon'|'procfs'>('all');
  const [sysmonID,setSysmonID]=useState('all');
  const [query,setQuery]=useState('');
  const scope=useMemo(()=>events.filter(e=>
    (!device || e.device_id===device) &&
    (category==='all' || e.source===category)
  ),[events,device,category]);
  const counts=useMemo(()=>observedSysmonCounts(scope),[scope]);
  const filtered=useMemo(()=>scope.filter(e=>
    (sysmonID==='all'||(e.source==='sysmon' && String(e.source_event_id)===sysmonID)) &&
    (!query.trim() || [
      e.device_id,e.type,e.source_record_id,e.process_guid,e.image,e.file_path,
      e.detail, ...Object.values(e.source_fields),
    ].some(x=>x.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())))
  ),[scope,sysmonID,query]);
  const devices=[...new Set(events.map(e=>e.device_id))].sort();
  const observed=[...counts].filter(([,n])=>n>0).length;
  const unclassified=scope.filter(e=>e.source==='sysmon'&&!SYSMON_EVENT_NAMES[e.source_event_id]).length;

  return <div className="telemetry-page">
    <section className="panel" aria-labelledby="telemetry-title">
      <div className="heading"><h2 id="telemetry-title">Sysmon telemetry &amp; endpoint evidence</h2>
        <span className="subtle">Read-only · development records</span></div>
      <p>These counts represent only the last 100 retained Go API events, not all events on the endpoint. An unobserved ID is <strong>not proof the Sysmon policy disabled it</strong>. Source fields and timestamps are sender-reported, not authenticated forensic evidence.</p>
      <div className="telemetry-summary" role="group" aria-label="Retained evidence summary">
        <div><strong>{scope.length}</strong><span>API events in view</span></div>
        <div><strong>{observed} / 30</strong><span>Sysmon event classes observed</span></div>
        <div><strong>{unclassified}</strong><span>Legacy records without numeric ID</span></div>
        <div><strong>{scope.filter(e=>e.source==='procfs').length}</strong><span>Linux /proc snapshots</span></div>
      </div>
      <div className="telemetry-filters">
        <div className="field"><label htmlFor="telemetry-device">Endpoint</label>
          <select id="telemetry-device" value={device} onChange={e=>setDevice(e.target.value)}>
            <option value="">All retained endpoints</option>{devices.map(d=><option key={d} value={d}>{d}</option>)}
          </select></div>
        <div className="field"><label htmlFor="telemetry-source">Source</label>
          <select id="telemetry-source" value={category} onChange={e=>setCategory(e.target.value as 'all'|'sysmon'|'procfs')}>
            <option value="all">All source types</option><option value="sysmon">Windows Sysmon</option><option value="procfs">Linux procfs</option>
          </select></div>
        <div className="field"><label htmlFor="telemetry-id">Sysmon event ID</label>
          <select id="telemetry-id" value={sysmonID} onChange={e=>setSysmonID(e.target.value)}>
            <option value="all">All event IDs</option>{Object.entries(SYSMON_EVENT_NAMES).map(([id,name])=><option key={id} value={id}>{id} — {name}</option>)}
          </select></div>
        <div className="field"><label htmlFor="telemetry-search">Search evidence</label>
          <input id="telemetry-search" type="search" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Process GUID, image, destination" autoComplete="off"/></div>
      </div>
    </section>
    <section className="panel" aria-labelledby="telemetry-classes-title">
      <h2 id="telemetry-classes-title">Observed Sysmon event classes</h2>
      <p>Only numbers with retained evidence have counts. The missing classes may be unconfigured, filtered, unavailable, lost or simply not encountered.</p>
      <div className="event-coverage-grid">
        {Object.entries(SYSMON_EVENT_NAMES).map(([id,name])=>{
          const n=counts.get(Number(id))||0;
          return <button key={id} type="button"
            className={'event-coverage-item'+(sysmonID===id?' event-coverage-item--selected':'')}
            aria-pressed={sysmonID===id} onClick={()=>setSysmonID(sysmonID===id?'all':id)}>
            <span className="event-class-id">{id}</span><span className="event-class-name">{name}</span>
            <span className="event-class-count">{n ? n+' observed':'Not observed'}</span>
          </button>;
        })}
      </div>
    </section>
    <section className="panel" aria-labelledby="telemetry-evidence-title">
      <div className="heading"><h2 id="telemetry-evidence-title">Retained source events</h2>
        <span className="subtle">{filtered.length} / {events.length} records shown</span></div>
      {filtered.length === 0
        ? <p className="empty">No matching retained source evidence. This does not establish the endpoint or network is safe.</p>
        : <div className="table-scroll"><table>
          <caption>Events received by the development Go API. No automated endpoint actions or inferred compromise.</caption>
          <thead><tr><th scope="col">Reported event</th><th scope="col">Endpoint</th><th scope="col">Source provenance</th><th scope="col">Process / object</th><th scope="col">Investigation</th></tr></thead>
          <tbody>{[...filtered].reverse().map(e=><tr key={e.id}>
            <td><strong>{e.source==='sysmon'
              ? e.source_event_id ? 'ID '+e.source_event_id+' · '+(SYSMON_EVENT_NAMES[e.source_event_id]||e.type) : 'Legacy Sysmon · '+e.type
              : e.type}</strong>
              <span className="minor">Reported: {e.time||'unknown'}</span>
              <span className="minor">Received: {e.received_at||'unknown'}</span></td>
            <td><strong>{e.device_id}</strong><span className="minor">{e.platform} / {e.source||'source unknown'}</span></td>
            <td><span className="minor">RecordID: {e.source_record_id||'not reported'}</span>
              <span className="minor">Source time: {e.time_origin||'not established'}</span>
              <span className="minor">Go event ID: {e.id}</span>
              {Object.keys(e.source_fields).length>0 && <details className="event-field-details">
                <summary>Source metadata ({Object.keys(e.source_fields).length})</summary>
                <dl>{Object.entries(e.source_fields).map(([key,val])=><div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{val}</dd></div>)}</dl>
              </details>}</td>
            <td><span>{e.image||e.file_path||'Process image not reported'}</span>
              {e.file_path&&e.image&&<span className="minor">Object: {e.file_path}</span>}
              <span className="minor">Process GUID: {e.process_guid||'not reported'}</span>
              <span className="minor">Parent: {e.source_event_id===1?e.parent_process_guid||'not reported':'not asserted by this event'}</span></td>
            <td>{e.process_guid
              ? <button type="button" className="secondary" onClick={()=>onInvestigate({deviceID:e.device_id,kind:'process',processGUID:e.process_guid})}>Inspect process evidence</button>
              : <span className="subtle">No reported process GUID</span>}</td>
          </tr>)}</tbody>
        </table></div>}
      <p className="minor">Sysmon Modular is a policy/reference project; collecting event IDs and presenting a table does not establish coverage, prevention, detection quality, or chain-of-custody. Clipboard Event 24 exposes metadata only.</p>
    </section>
  </div>;
}
