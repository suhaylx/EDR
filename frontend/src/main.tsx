import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { fetchLabScanJobs, type LabScanJob } from './lab-api.js';
import { describeScan, scanEngineEvidence } from './scan-state.js';
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

function App() {
  const [token, setToken] = useState('');
  const [status, setStatus] = useState<LoadState>('disconnected');
  const [jobs, setJobs] = useState<LabScanJob[]>([]);
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
    try {
      const data = await fetchLabScanJobs(tokenRef.current, controller.signal);
      if (controller.signal.aborted) return;
      setJobs(data);
      setLoadedAt(new Date());
      setStatus('ready');
    } catch (cause: unknown) {
      if (controller.signal.aborted) return;
      setJobs([]);
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
    setLoadedAt(null);
    setError('');
    setStatus('disconnected');
  }

  return <div className="layout">
    <header className="masthead">
      <div><div className="eyebrow">TURANSEC / SOC LAB</div><h1>Scan history</h1><p>Read-only React + TypeScript evaluation surface. Does not replace the existing Go-served SOC console.</p></div>
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
        <p role="status" aria-live="polite" className="feedback">{status === 'disconnected' ? 'Disconnected — no fleet status inferred.' : status === 'loading' ? 'Requesting retained scan jobs…' : status === 'error' ? 'Connection failed: ' + error : 'Showing ' + jobs.length + ' reported job(s), fetched at ' + (loadedAt?.toLocaleTimeString() || 'unknown') + ' (local clock).'}</p>
      </section>
      <section className="panel" aria-labelledby="history-title">
        <div className="heading"><h2 id="history-title">Retained scan jobs</h2><span className="subtle">No automatic polling</span></div>
        <p>Queued and leased jobs are not completed scans. “Clean by signature” is not a claim that a file or endpoint is safe.</p>
        {status === 'ready' ? <ScanHistory jobs={jobs} /> : <p className="empty">No scan results displayed until a successful authenticated lab request.</p>}
      </section>
    </main>
    <footer>Endpoint actions, quarantine, signed scanner evidence and managed policy are not available from this read-only UI. Requires Agent 2 API/identity integration and Agent 3 browser QA.</footer>
  </div>;
}

const root = document.getElementById('root');
if (!root) throw new Error('Missing React root element');
createRoot(root).render(<React.StrictMode><App /></React.StrictMode>);
