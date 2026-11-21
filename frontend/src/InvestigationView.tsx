import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import {
  deriveProcessForest, fetchLabInvestigation, investigationTimeline,
  type InvestigationNode, type LabInvestigation, type InvestigationSeed, type ProcessBranch,
} from './investigation.js';

type SourceLink = {anchor: string; sourceID: string};
function ProcessLineage({
  branches, sources, onSource,
}: {
  branches: ProcessBranch[];
  sources: Map<string, SourceLink>;
  onSource: (anchor: string) => void;
}) {
  return <ul className="process-list">{branches.map(branch => {
    const n = branch.node;
    const source = sources.get(n.process_guid);
    const content = <><strong>{n.image || n.label}</strong>
      <span className="minor">Process GUID: {n.process_guid || 'not reported'}</span>
      <span className="minor">Node: {n.status === 'observed' ? 'Has retained associated events' : 'Referenced only — no retained event for this process'}</span>
      <span className="minor">Parent link: {branch.parentRelation
        ? branch.parentRelation.provenance + ' / ' + (branch.parentRelation.evidence_id || 'source ID not reported')
        : 'root or not known'}</span></>;
    return <li key={n.id}>
      {branch.children.length > 0
        ? <details open><summary className="process-entry">{content}</summary><ProcessLineage branches={branch.children} sources={sources} onSource={onSource}/></details>
        : <div className="process-entry">{content}</div>}
      {source && <button className="source-button" type="button" onClick={() => onSource(source.anchor)}>
        Inspect retained source {source.sourceID}
      </button>}
    </li>;
  })}</ul>;
}

export function InvestigationView({token, initialSeed}: {token: string; initialSeed?: InvestigationSeed | null}) {
  const [deviceID,setDeviceID] = useState(initialSeed?.deviceID || '');
  const [seedKind,setSeedKind] = useState<'process'|'detection'>(initialSeed?.kind || 'process');
  const [processGUID,setProcessGUID] = useState(initialSeed?.kind === 'process' ? initialSeed.processGUID : '');
  const [detectionID,setDetectionID] = useState(initialSeed?.kind === 'detection' ? initialSeed.detectionID : '');
  const [graph,setGraph] = useState<LabInvestigation | null>(null);
  const [filter,setFilter] = useState('');
  const [focusTarget,setFocusTarget] = useState<string | null>(null);
  const [error,setError] = useState('');
  const [loading,setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  // Seed navigation fills fields only. Analyst explicitly starts the request,
  // keeping the API read-only and avoiding automatic re-fetch on navigation.
  useEffect(() => {
    if (!initialSeed) return;
    controller.current?.abort();
    setGraph(null);
    setError('');
    setFilter('');
    setFocusTarget(null);
    setLoading(false);
    setDeviceID(initialSeed.deviceID);
    setSeedKind(initialSeed.kind);
    setProcessGUID(initialSeed.kind === 'process' ? initialSeed.processGUID : '');
    setDetectionID(initialSeed.kind === 'detection' ? initialSeed.detectionID : '');
  }, [initialSeed]);
  useEffect(() => {
    if (!focusTarget) return;
    const element = document.getElementById(focusTarget);
    if (element) {
      element.focus();
      element.scrollIntoView({block:'nearest'});
    }
    setFocusTarget(null);
  }, [filter, focusTarget]);

  function clearResult() {
    controller.current?.abort();
    setLoading(false);
    setGraph(null);
    setError('');
    setFilter('');
    setFocusTarget(null);
  }
  async function load(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearResult();
    const seed: InvestigationSeed = seedKind === 'process'
      ? {deviceID:deviceID.trim(),kind:'process',processGUID:processGUID.trim()}
      : {deviceID:deviceID.trim(),kind:'detection',detectionID:detectionID.trim()};
    const abort = new AbortController();
    controller.current = abort;
    setLoading(true);
    try {
      const result = await fetchLabInvestigation(token,seed,abort.signal);
      if (abort.signal.aborted) return;
      setGraph(result);
    } catch (cause:unknown) {
      if (abort.signal.aborted) return;
      setError(cause instanceof Error ? cause.message : 'Unknown lab investigation error');
    } finally {
      if (!abort.signal.aborted) setLoading(false);
    }
  }
  const timeline = useMemo(() => graph ? investigationTimeline(graph) : [], [graph]);
  const forest = useMemo(() => graph ? deriveProcessForest(graph) : [], [graph]);
  const matching = useMemo(() => {
    const needle = filter.trim().toLocaleLowerCase();
    if (!needle) return timeline;
    return timeline.filter(n => [
      n.id,n.event_id,n.event_type,n.label,n.process_guid,n.file_path,n.detail,n.severity,n.confidence,
    ].some(field => field.toLocaleLowerCase().includes(needle)));
  }, [timeline,filter]);
  const sources = useMemo(() => {
    const map = new Map<string, SourceLink>();
    for (let i=0; i<timeline.length; i++) {
      const n = timeline[i];
      if (n?.kind === 'event' && n.process_guid && !map.has(n.process_guid)) {
        map.set(n.process_guid, {anchor:'evidence-entry-'+i,sourceID:n.event_id || n.id});
      }
    }
    return map;
  }, [timeline]);
  const anchors = useMemo(() => {
    const map = new Map<string, string>();
    timeline.forEach((n,i) => map.set(n.id,'evidence-entry-'+i));
    return map;
  }, [timeline]);

  return <>
    <section className="panel" aria-labelledby="investigation-title">
      <h2 id="investigation-title">Retained process evidence investigation</h2>
      <p>Search for one observed process GUID or one detection ID on an endpoint.
        These are shared-token development records, not authenticated endpoint forensic evidence.</p>
      {initialSeed?.kind === 'detection' && <p className="source-selection">Selected retained detection {initialSeed.detectionID} on endpoint {initialSeed.deviceID}. Review the seed, then build its graph.</p>}
      <form onSubmit={event => void load(event)} className="investigation-form">
        <div className="field"><label htmlFor="investigation-device">Endpoint ID</label>
          <input id="investigation-device" required maxLength={96} value={deviceID}
            onChange={e=>{clearResult();setDeviceID(e.target.value);}} placeholder="win-lab-01" autoComplete="off"/></div>
        <fieldset><legend>Evidence seed</legend><div className="seed-choices">
          <label><input type="radio" name="evidence-seed" checked={seedKind==='process'} onChange={() => {clearResult();setSeedKind('process');}}/> Process GUID</label>
          <label><input type="radio" name="evidence-seed" checked={seedKind==='detection'} onChange={() => {clearResult();setSeedKind('detection');}}/> Detection ID</label>
        </div></fieldset>
        {seedKind==='process'
          ? <div className="field"><label htmlFor="investigation-guid">Observed process GUID</label>
              <input id="investigation-guid" required maxLength={160} value={processGUID} onChange={e=>{clearResult();setProcessGUID(e.target.value);}} placeholder="{process-guid}" autoComplete="off"/></div>
          : <div className="field"><label htmlFor="investigation-detection">Retained detection ID</label>
              <input id="investigation-detection" required maxLength={160} value={detectionID} onChange={e=>{clearResult();setDetectionID(e.target.value);}} placeholder="detection-record-id" autoComplete="off"/></div>}
        <div className="actions"><button type="submit" disabled={loading}>{loading?'Loading evidence…':'Build retained evidence graph'}</button>
          <button type="button" className="secondary" onClick={clearResult}>Clear evidence</button></div>
      </form>
      <p role="status" aria-live="polite" className="feedback">
        {loading ? 'Requesting bounded retained evidence…' :
          error ? 'Investigation unavailable: '+error :
            graph ? 'Showing '+graph.nodes.length+' evidence node(s), '+graph.edges.length+' reported edge(s).' :
              'No investigation loaded. Missing evidence must not be treated as a clean endpoint.'}
      </p>
    </section>
    {graph && <>
      <section className="panel" aria-labelledby="investigation-context-title">
        <h2 id="investigation-context-title">Evidence scope and source</h2>
        <p>Endpoint: <strong>{graph.device_id}</strong> · Seed process GUID: <code>{graph.seed_process_guid}</code>
          {graph.seed_detection_id && <> · Detection seed: <code>{graph.seed_detection_id}</code></>}</p>
        <p>Data source: {graph.data_source}. Process relationships labeled observed or reported reflect retained lab records only.
          Neither designation independently verifies execution, causality, compromise, or complete capture.</p>
        {graph.truncated && <p className="graph-warning" role="status">Graph truncated at the backend node limit; missing nodes or edges do not prove no activity.</p>}
      </section>
      <div className="overview-columns">
        <section className="panel" aria-labelledby="process-lineage-title">
          <h2 id="process-lineage-title">Process lineage</h2>
          <p>Expand or collapse branches with Enter/Space. Parent evidence ID is shown when supplied.</p>
          {forest.length
            ? <ProcessLineage branches={forest} sources={sources} onSource={anchor => {setFilter('');setFocusTarget(anchor);}}/>
            : <p className="empty">No process lineage in the returned retained nodes.</p>}
        </section>
        <section className="panel" aria-labelledby="timeline-title">
          <h2 id="timeline-title">Retained evidence timeline</h2>
          <p>Local filter only; no further event collection is triggered.</p>
          <div className="field"><label htmlFor="investigation-filter">Filter by event type, process GUID, path or source ID</label>
            <input type="search" id="investigation-filter" value={filter} onChange={e=>setFilter(e.target.value)}
              aria-controls="investigation-timeline" autoComplete="off"/></div>
          <p role="status" aria-live="polite">{matching.length} of {timeline.length} retained timeline record(s) shown.</p>
          {matching.length ? <ol className="timeline" id="investigation-timeline">
            {matching.map((n:InvestigationNode) => <li key={n.id} id={anchors.get(n.id)} tabIndex={-1}>
              <strong>{n.kind==='detection'?'Detection · '+n.label:n.event_type || n.label}</strong>
              <span className="minor">Time: {n.time || 'not reported'} · Kind: {n.kind} · Status: {n.status}</span>
              <span className="minor">Source ID: {n.event_id || n.id}</span>
              <span className="minor">Process GUID: {n.process_guid || 'not reported'}</span>
              {(n.file_path || n.detail) && <p>{n.file_path || n.detail}</p>}
              {n.kind==='detection' && <span className="minor">Reported severity: {n.severity || 'unknown'} / confidence: {n.confidence || 'unknown'}</span>}
            </li>)}
          </ol> : <p className="empty" id="investigation-timeline">No matching retained evidence. Clearing the filter does not fetch new events.</p>}
        </section>
      </div>
      <section className="panel" aria-labelledby="coverage-gaps-title">
        <h2 id="coverage-gaps-title">Evidence gaps and limitations</h2>
        {graph.gaps.length ? <ul className="coverage-list">{graph.gaps.map((gap,i)=><li key={i}>{gap}</li>)}</ul>
          : <p className="empty">No gap labels returned. This does not establish complete collection.</p>}
        <p className="minor">Source events, detections, file references and edge provenance remain separate from analyst conclusions.</p>
      </section>
    </>}
  </>;
}
