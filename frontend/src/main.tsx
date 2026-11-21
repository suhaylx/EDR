import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { fetchLabScanJobs, type LabScanJob } from './lab-api.js';
import { describeScan, scanEngineEvidence } from './scan-state.js';
import { fetchLabOverview, heartbeatLabel, type LabSOCOverview, type DayWindow } from './overview.js';
import './styles.css';

type LoadState = 'disconnected' | 'loading' | 'ready' | 'error';

function ScanHistory({ jobs }: { jobs: LabScanJob[] }) {
  if (jobs.length === 0) return <p className="empty">No scan jobs returned by this lab API. This does not establish endpoint coverage or safety.</p>;
  return <div className="table-scroll"><table>
    <caption>Latest server-reported scan jobs; authenticity and freshness are not verified.</caption>
    <thead><tr><th scope="col">Requested</th><th scope="col">Endpoint</th><th scope="col">Mode</th><th scope="col">State</th><th scope="col">Analyst interpretation</th><th scope="col">Claimed scanner</th></tr></thead>
    <tbody>{[...jobs].reverse().map((job, index) => {
      const result = describeScan(job);
      return <tr key={job.id + ':' + index}>
        <td>{job.created_at || 'Not reported'}</td>
        <td>{job.agent_id}</td><td>{job.scan_type || 'Unknown'}</td>
        <td><span className={'status status--' + result.tone}>{result.heading}</span><span className="minor">Raw state: {job.status}; verdict: {job.verdict || 'not reported'}</span></td>
        <td>{result.explanation}{job.detail && <span className="minor">Worker detail: {job.detail}</span>}</td>
        <td>{scanEngineEvidence(job)}</td>
      </tr>;
    })}</tbody>
  </table></div>;
}

function Overview({ overview }: { overview: LabSOCOverview }) {
  const counts = [
    ['Enrolled lab endpoints', overview.agents, 'Enrollment records, not verified installations'],
    ['Online', overview.online, 'Recent server-received heartbeats'],
    ['Offline', overview.offline, 'Heartbeat older than server threshold'],
    ['Unknown', overview.unknown, 'No trustworthy heartbeat evidence'],
    ['Observed alerts', overview.alerts, 'Retained lab detections in selected window'],
    ['Critical + high', overview.high_risk_alerts, 'Detected alert severity, not confirmed incidents'],
    ['Retained events', overview.events, 'Observed event records in selected window'],
    ['Failed / expired jobs', overview.scans.failed, 'Reported failed or expired scan requests'],
  ] as const;
  return <>
    <section className="panel" aria-labelledby="overview-title">
      <div className="heading"><h2 id="overview-title">Fleet and security activity</h2><span className="subtle">{overview.window_days} UTC day(s) · lab retained data</span></div>
      <p>Connectivity is calculated by the Go server from received heartbeats using a {overview.heartbeat_ttl_seconds / 60}-minute threshold. In-memory events do not establish historical fleet security or prevention.</p>
      <div className="metric-grid">{counts.map(([label, value, detail]) =>
        <div key={label} className="metric"><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{detail}</small></div>)}</div>
    </section>
    <div className="overview-columns">
      <section className="panel" aria-labelledby="trend-title"><h2 id="trend-title">Observed alert trend</h2>
        <p>UTC days. Zero means no alerts in the retained data, not no threats.</p>
        {overview.alert_trend.length
          ? <div className="table-scroll"><table className="compact-table"><thead><tr><th scope="col">UTC day</th><th scope="col">Alerts</th></tr></thead><tbody>{overview.alert_trend.map(x=><tr key={x.day}><th scope="row">{x.day}</th><td>{x.count}</td></tr>)}</tbody></table></div>
          : <p className="empty">Daily alert coverage is not available.</p>}
      </section>
      <section className="panel" aria-labelledby="severity-title"><h2 id="severity-title">Alerts by severity</h2>
        {overview.severity.length
          ? <div className="table-scroll"><table className="compact-table"><thead><tr><th scope="col">Severity</th><th scope="col">Retained alerts</th></tr></thead><tbody>{overview.severity.map(x=><tr key={x.severity}><th scope="row">{x.severity}</th><td>{x.count}</td></tr>)}</tbody></table></div>
          : <p className="empty">No severity summary available.</p>}
        <p>Alert volume is not a confirmed infection or incident count.</p>
      </section>
    </div>
    <div className="overview-columns">
      <section className="panel" aria-labelledby="active-title"><h2 id="active-title">Most active observed endpoints</h2>
        <p>Ranked by retained event count—not CPU, bandwidth, or threat level.</p>
        {overview.most_active.length
          ? <div className="table-scroll"><table className="compact-table"><thead><tr><th scope="col">Endpoint</th><th scope="col">Events</th><th scope="col">Alerts</th><th scope="col">Heartbeat</th></tr></thead><tbody>{overview.most_active.map((x,i)=><tr key={x.id+':'+i}><th scope="row">{x.id}</th><td>{x.events}</td><td>{x.alerts}</td><td>{heartbeatLabel(x)}</td></tr>)}</tbody></table></div>
          : <p className="empty">No enrolled endpoints returned.</p>}
      </section>
      <section className="panel" aria-labelledby="inactive-title"><h2 id="inactive-title">Offline and unknown endpoints</h2>
        <p>Unknown never means offline for an inferred number of days.</p>
        {overview.inactive_machines.length
          ? <div className="table-scroll"><table className="compact-table"><thead><tr><th scope="col">Endpoint</th><th scope="col">OS</th><th scope="col">Status / duration</th></tr></thead><tbody>{overview.inactive_machines.map((x,i)=><tr key={x.id+':'+i}><th scope="row">{x.id}</th><td>{x.platform}</td><td>{heartbeatLabel(x)}</td></tr>)}</tbody></table></div>
          : <p className="empty">No offline or unknown enrolled endpoints were reported.</p>}
      </section>
    </div>
    <div className="overview-columns">
      <section className="panel" aria-labelledby="rules-title"><h2 id="rules-title">Detection rules that fired</h2>
        <p>These are observed detection-rule hits, not the Sysmon policy rule count.</p>
        {overview.top_rules.length
          ? <div className="table-scroll"><table className="compact-table"><thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Hits</th></tr></thead><tbody>{overview.top_rules.map((x,i)=><tr key={x.rule_id+':'+i}><th scope="row">{x.rule_id}</th><td>{x.severity}</td><td>{x.count}</td></tr>)}</tbody></table></div>
          : <p className="empty">No rule hits recorded in the retained window.</p>}
      </section>
      <section className="panel" aria-labelledby="scan-health-title"><h2 id="scan-health-title">Reported scan job health</h2>
        <dl className="scan-summary"><div><dt>Queued</dt><dd>{overview.scans.queued}</dd></div><div><dt>Leased</dt><dd>{overview.scans.leased}</dd></div><div><dt>Completed (reported)</dt><dd>{overview.scans.completed}</dd></div><div><dt>Failed / expired</dt><dd>{overview.scans.failed}</dd></div></dl>
        <p>Completion is not scanner attestation. Signature database freshness and missed scans remain unverified.</p>
      </section>
    </div>
    <section className="panel" aria-labelledby="coverage-title"><h2 id="coverage-title">Unverified or unavailable coverage</h2>
      {overview.unavailable.length
        ? <ul className="coverage-list">{overview.unavailable.map((x,i)=><li key={x+':'+i}>{x.replaceAll('_',' ')}</li>)}</ul>
        : <p className="empty">The backend returned no coverage-gap labels. This alone does not verify protection.</p>}
      <p className="minor">Data source: {overview.data_source} · generated {overview.generated_at}. No tenant isolation, historical guarantee, or endpoint protection attestation is claimed by this lab view.</p>
    </section>
  </>;
}

function App() {
  const [token, setToken] = useState('');
  const [status, setStatus] = useState<LoadState>('disconnected');
  const [jobs, setJobs] = useState<LabScanJob[]>([]);
  const [overview, setOverview] = useState<LabSOCOverview | null>(null);
  const [days, setDays] = useState<DayWindow>(7);
  const [view, setView] = useState<'overview' | 'scans'>('overview');
  const [error, setError] = useState('');
  const [loadedAt, setLoadedAt] = useState<Date | null>(null);
  const request = useRef<AbortController | null>(null);
  const tokenRef = useRef('');
  useEffect(() => { tokenRef.current = token; }, [token]);
  useEffect(() => () => request.current?.abort(), []);

  async function refresh() {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setStatus('loading');
    setError('');
    setOverview(null);
    setJobs([]);
    setLoadedAt(null);
    try {
      // Both requests must succeed; do not display stale or partially labeled
      // metrics after a failed refresh or a changed UTC window.
      const [nextOverview, data] = await Promise.all([
        fetchLabOverview(tokenRef.current, days, controller.signal),
        fetchLabScanJobs(tokenRef.current, controller.signal),
      ]);
      if (controller.signal.aborted) return;
      setOverview(nextOverview);
      setJobs(data);
      setLoadedAt(new Date());
      setStatus('ready');
    } catch (cause: unknown) {
      if (controller.signal.aborted) return;
      setJobs([]);
      setOverview(null);
      setLoadedAt(null);
      setStatus('error');
      setError(cause instanceof Error ? cause.message : 'Unknown lab API error');
    }
  }

  function disconnect() {
    request.current?.abort();
    tokenRef.current = '';
    setToken('');
    setJobs([]);
    setOverview(null);
    setLoadedAt(null);
    setError('');
    setStatus('disconnected');
  }

  function updateWindow(value: DayWindow) {
    request.current?.abort();
    setDays(value);
    setOverview(null);
    setJobs([]);
    setLoadedAt(null);
    setError('');
    setStatus('disconnected');
  }

  return <div className="layout">
    <header className="masthead">
      <div><div className="eyebrow">TURANSEC / SOC LAB</div><h1>SOC overview and scan history</h1><p>Read-only React + TypeScript evaluation surface. Does not replace the existing Go-served SOC console.</p></div>
      <div className="lab-indicator" aria-label="Laboratory environment">LAB ONLY</div>
    </header>
    <main>
      <section className="panel" aria-labelledby="connection-title">
        <h2 id="connection-title">Development API connection</h2>
        <p>Connect to a locally running Go API. The shared development token stays in this tab's memory; do not reuse production credentials.</p>
        <form className="form" onSubmit={e => { e.preventDefault(); void refresh(); }}>
          <label htmlFor="lab-token">Development API token</label>
          <input id="lab-token" type="password" value={token} onChange={e => setToken(e.target.value)} autoComplete="off" placeholder="EDR_DEV_TOKEN" aria-describedby="token-note" />
          <div id="token-note" className="minor">At least 16 characters. No token persistence; the current Go API is not production authentication.</div>
          <div className="actions">
            <button disabled={status === 'loading' || token.length < 16} type="submit">{status === 'loading' ? 'Loading…' : 'Connect / refresh'}</button>
            <button type="button" className="secondary" onClick={disconnect} disabled={!token && status === 'disconnected'}>Disconnect / clear</button>
          </div>
        </form>
        <p role="status" aria-live="polite" className="feedback">{status === 'disconnected' ? 'Disconnected — no fleet status inferred.' : status === 'loading' ? 'Requesting retained scan jobs…' : status === 'error' ? 'Connection failed: ' + error : 'Showing retained lab evidence for ' + days + ' UTC day(s) and ' + jobs.length + ' reported scan job(s); fetched at ' + (loadedAt?.toLocaleTimeString() || 'unknown') + ' (local clock).'}</p>
      </section>
      <nav className="section-tabs" aria-label="SOC lab views">
        <button type="button" aria-current={view === 'overview' ? 'page' : undefined} onClick={() => setView('overview')}>SOC overview</button>
        <button type="button" aria-current={view === 'scans' ? 'page' : undefined} onClick={() => setView('scans')}>Scan history</button>
      </nav>
      {view === 'overview' ? <>
        <section className="panel field compact-window">
          <label htmlFor="days">Retained activity period (UTC)</label>
          <select id="days" value={days} onChange={e => updateWindow(Number(e.target.value) as DayWindow)}>
            <option value={1}>Last 1 day</option><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option>
          </select>
          <p className="minor">Changing the period clears prior results; reconnect to load a matching overview.</p>
        </section>
        {status === 'ready' && overview ? <Overview overview={overview}/> :
          <section className="panel"><p className="empty">No current overview. Connect and refresh to request retained evidence for the selected UTC period.</p></section>}
      </> : <section className="panel" aria-labelledby="history-title">
        <div className="heading"><h2 id="history-title">Retained scan jobs</h2><span className="subtle">No automatic polling</span></div>
        <p>Queued and leased jobs are not completed scans. “Clean by signature” is not a claim that a file or endpoint is safe.</p>
        {status === 'ready' ? <ScanHistory jobs={jobs} /> : <p className="empty">No scan results displayed until a successful authenticated lab request.</p>}
      </section>}
    </main>
    <footer>Endpoint actions, quarantine, signed scanner evidence and managed policy are not available from this read-only UI. Requires Agent 2 API/identity integration and Agent 3 browser QA.</footer>
  </div>;
}

const root = document.getElementById('root');
if (!root) throw new Error('Missing React root element');
createRoot(root).render(<React.StrictMode><App /></React.StrictMode>);
