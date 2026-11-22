import React, { useState } from 'react';
import { socIdentity, type SOCPage } from './soc-contract.js';
import { socPageSize, type SOCAlert, type SOCMutationCommand, type SOCOffsets, type SOCSnapshot } from './soc-api.js';
import { newSOCScanRequestID, socBoundedInput, socVerdictLabel, validateSOCScanPath, type SOCScanDetail } from './soc-scans.js';

export const socUTC = (value: string): string => new Date(value).toISOString();
type Mutate = (command: SOCMutationCommand) => void;

export function SOCPaging({ page, label, onChange }: { page: SOCPage<unknown>; label: string; onChange: (offset: number) => void }) {
  return <div className="analyst-paging" role="group" aria-label={label + ' pages'}>
    <button type="button" className="secondary" disabled={page.offset === 0} onClick={() => onChange(page.offset - socPageSize)}>Previous {label}</button>
    <span>Page {page.offset / socPageSize + 1} · {page.items.length} returned record(s)</span>
    <button type="button" className="secondary" disabled={page.items.length < page.limit || page.offset >= 10000}
      onClick={() => onChange(page.offset + socPageSize)}>Next {label}</button>
  </div>;
}

function ScanRequestForm({ snapshot, onMutation, preferredAgentID }: { snapshot: SOCSnapshot; onMutation: Mutate; preferredAgentID?: string }) {
  const [agentID, setAgentID] = useState(preferredAgentID && snapshot.endpoints.items.some(item=>item.agent_id===preferredAgentID&&item.health!=='revoked') ? preferredAgentID : '');
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  const endpoint = snapshot.endpoints.items.find(item => item.agent_id === agentID);
  const canSelect = snapshot.endpoints.items.some(item => item.health !== 'revoked');
  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    if (!endpoint || endpoint.health === 'revoked') { setError('Select an enrolled endpoint that has not been revoked.'); return; }
    let scanRoot: string;
    try { scanRoot = validateSOCScanPath(endpoint.platform, path); }
    catch { setError('Enter a normalized, absolute local file or directory path within 512 UTF-8 bytes. Network paths, drive roots, traversal and Windows device aliases are not accepted.'); return; }
    let requestID: string;
    try { requestID = newSOCScanRequestID(); }
    catch { setError('A secure random request key is unavailable. No scan was requested.'); return; }
    onMutation({ kind: 'schedule', agent_id: endpoint.agent_id, scan_root: scanRoot, request_id: requestID });
  };
  return <form className="soc-form" onSubmit={submit} aria-labelledby="soc-schedule-title">
    <fieldset><legend id="soc-schedule-title">Request a path scan</legend>
      <div className="field"><label htmlFor="soc-scan-endpoint">Endpoint to scan</label>
        <select id="soc-scan-endpoint" value={agentID} required disabled={!canSelect} aria-describedby="soc-scan-endpoint-help"
          onChange={event => { setAgentID(event.target.value); setPath(''); setError(''); }}>
          <option value="">Select an endpoint from this inventory page</option>
          {snapshot.endpoints.items.map(item => <option key={item.agent_id} value={item.agent_id} disabled={item.health === 'revoked'}>{item.agent_id} · {item.platform} · {item.health}</option>)}
        </select>
        <p id="soc-scan-endpoint-help" className="minor">Only this inventory page is listed. Use the endpoint pages above for other enrollments. A missing or stale heartbeat does not establish scan readiness.</p>
      </div>
      <div className="field"><label htmlFor="soc-scan-path">Absolute local path</label>
        <input id="soc-scan-path" type="text" value={path} required maxLength={512} autoComplete="off" spellCheck={false}
          disabled={!endpoint} aria-invalid={Boolean(error)} aria-describedby="soc-scan-path-help soc-scan-error"
          placeholder={endpoint?.platform === 'windows' ? 'C:\\Data\\file.txt' : '/var/data/file.txt'}
          onChange={event => { setPath(event.target.value); setError(''); }} />
        <p id="soc-scan-path-help" className="minor">{endpoint?.platform === 'windows' ? 'Use a Windows drive path to an ordinary file or directory.' : 'Use a normalized absolute Linux file or directory path, other than /.'} Maximum 512 UTF-8 bytes. The endpoint still applies its configured scan restrictions.</p>
      </div>
      <p id="soc-scan-error" role="alert" className="feedback">{error}</p>
      <button type="submit" disabled={!endpoint || endpoint.health === 'revoked'}>Queue path scan</button>
      <p className="minor">This requests one path scan. Queue acceptance does not prove that the agent has received or executed it. A new request is never sent automatically after an uncertain outcome.</p>
    </fieldset>
  </form>;
}

export function SOCScanWorkspace({ snapshot, onPage, onScan, onMutation, preferredAgentID }: {
  snapshot: SOCSnapshot; onPage: (section: keyof SOCOffsets, offset: number) => void; onScan: (jobID: string) => void; onMutation: Mutate; preferredAgentID?: string;
}) {
  const canWrite = snapshot.session.role === 'scanner';
  return <section className="panel" aria-labelledby="soc-scans-title">
    <h2 id="soc-scans-title">Path scans and reported results</h2>
    <div className="metric-grid">{[
      ['Queued', snapshot.scanStats.pending], ['Leased to an agent', snapshot.scanStats.leased],
      ['Delivery succeeded', snapshot.scanStats.succeeded], ['Delivery failed', snapshot.scanStats.failed],
      ['Cancelled before delivery', snapshot.scanStats.cancelled], ['Reported signature matches', snapshot.scanStats.malicious],
    ].map(([label, count]) => <div className="metric" key={label}><span>{label}</span><strong>{count}</strong></div>)}</div>
    <p>{snapshot.scanStats.total} total job record(s). Delivery state and scanner verdict are separate evidence. Successful delivery is not a clean scan or proof of endpoint protection.</p>
    {canWrite ? <ScanRequestForm key={preferredAgentID ?? ''} snapshot={snapshot} onMutation={onMutation} preferredAgentID={preferredAgentID} /> : <p>Viewer role: read-only access. A scanner-role operator is required to request or cancel a scan.</p>}
    <h3>Scan jobs</h3>
    {snapshot.jobs.items.length ? <div className="table-scroll" tabIndex={0} role="region" aria-label="Scan jobs table"><table>
      <caption>Tenant scan queue. Only pending requests created by the authenticated operator can be cancelled; the server enforces ownership.</caption>
      <thead><tr><th scope="col">Job / endpoint</th><th scope="col">Requested path</th><th scope="col">Delivery state</th><th scope="col">Last update (UTC)</th><th scope="col">Scan actions</th></tr></thead>
      <tbody>{snapshot.jobs.items.map(job => <tr key={job.job_id}>
        <th scope="row"><span className="soc-reference">{job.job_id}</span><span className="minor">{job.agent_id}</span></th>
        <td>{job.scan_root}</td><td>{job.state}<span className="minor">{job.attempt_count} delivery attempt(s)</span></td>
        <td><time dateTime={job.updated_at}>{socUTC(job.updated_at)}</time></td>
        <td><div className="actions"><button type="button" className="secondary" onClick={() => onScan(job.job_id)} aria-label={'Read scan details for job ' + job.job_id}>Read scan details</button>
          {canWrite && job.state === 'pending' && <button type="button" onClick={() => onMutation({ kind: 'cancel', job_id: job.job_id })} aria-label={'Cancel pending scan ' + job.job_id}>Cancel pending scan</button>}
        </div></td>
      </tr>)}</tbody>
    </table></div> : <p className="empty">No scan jobs were returned on this page. Scan coverage is unknown.</p>}
    <SOCPaging page={snapshot.jobs} label="scan jobs" onChange={offset => onPage('jobs', offset)} />
    <h3>Reported scan results</h3>
    {snapshot.results.items.length ? <div className="table-scroll" tabIndex={0} role="region" aria-label="Reported scan results table"><table>
      <caption>Endpoint-reported ClamAV results. No signature match does not establish endpoint safety.</caption>
      <thead><tr><th scope="col">Job / endpoint</th><th scope="col">Reported verdict</th><th scope="col">Reported detail</th><th scope="col">Observed time (UTC)</th><th scope="col">Details</th></tr></thead>
      <tbody>{snapshot.results.items.map(result => <tr key={result.job_id}>
        <th scope="row"><span className="soc-reference">{result.job_id}</span><span className="minor">{result.agent_id}</span></th>
        <td>{result.verdict}<span className="minor">{socVerdictLabel(result.verdict)}</span>{result.threat_name && <span className="minor">{result.threat_name}</span>}</td>
        <td>{result.detail || 'No detail reported'}</td><td><time dateTime={result.observed_at}>{socUTC(result.observed_at)}</time></td>
        <td><button type="button" className="secondary" onClick={() => onScan(result.job_id)} aria-label={'Read result details for job ' + result.job_id}>Read result details</button></td>
      </tr>)}</tbody>
    </table></div> : <p className="empty">No scan results were returned on this page. There is no basis to infer that an endpoint was scanned or is safe.</p>}
    <SOCPaging page={snapshot.results} label="scan results" onChange={offset => onPage('results', offset)} />
  </section>;
}

export function SOCScanDetailView({ detail, canWrite, onMutation }: { detail: SOCScanDetail; canWrite: boolean; onMutation: Mutate }) {
  const { job, result } = detail;
  return <>
    <dl className="soc-details"><div><dt>Endpoint</dt><dd>{job.agent_id}</dd></div><div><dt>Requested path</dt><dd>{job.scan_root}</dd></div>
      <div><dt>Delivery state</dt><dd>{job.state}</dd></div><div><dt>Delivery attempts</dt><dd>{job.attempt_count}</dd></div>
      <div><dt>Created (UTC)</dt><dd><time dateTime={job.created_at}>{socUTC(job.created_at)}</time></dd></div>
      <div><dt>Last update (UTC)</dt><dd><time dateTime={job.updated_at}>{socUTC(job.updated_at)}</time></dd></div></dl>
    {result ? <><h3>Endpoint-reported result</h3><p>{socVerdictLabel(result.verdict)}</p>
      <dl className="soc-details"><div><dt>Engine / verdict</dt><dd>{result.engine} · {result.verdict}</dd></div>
        <div><dt>Signature name</dt><dd>{result.threat_name || 'No signature match reported'}</dd></div>
        <div><dt>Detail</dt><dd>{result.detail || 'No detail reported'}</dd></div>
        <div><dt>Observed time (UTC)</dt><dd><time dateTime={result.observed_at}>{socUTC(result.observed_at)}</time></dd></div></dl>
    </> : <p className="empty">No result has been returned for this job. Its scan outcome and endpoint condition are unknown, regardless of delivery state.</p>}
    {canWrite && job.state === 'pending' && <button type="button" onClick={() => onMutation({ kind: 'cancel', job_id: job.job_id })}>Cancel this pending scan</button>}
    <p className="minor">Cancellation is limited to your own pending request. Leased work cannot be cancelled here. Result text is reported by the endpoint and is not independent host acceptance evidence.</p>
  </>;
}

function CaseTextForm({ alert, kind, onMutation }: { alert: SOCAlert; kind: 'note' | 'resolve'; onMutation: Mutate }) {
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const limit = kind === 'note' ? 2048 : 1024;
  const name = kind === 'note' ? 'Case note' : 'Resolution note';
  const id = 'soc-case-' + kind;
  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const text = socBoundedInput(note, limit);
      if (!text.trim()) throw new Error('Empty note');
      setError('');
      onMutation({ kind, alert_id: alert.alert_id, note: text });
    } catch { setError('Enter a nonempty, single-line note within ' + limit + ' UTF-8 bytes, without control or hidden direction characters.'); }
  };
  return <form className="soc-form" onSubmit={submit} aria-label={kind === 'note' ? 'Add a case note' : 'Resolve the acknowledged case'}>
    <fieldset><legend>{kind === 'note' ? 'Add a case note' : 'Resolve the acknowledged case'}</legend>
      <label htmlFor={id}>{name}</label>
      <input id={id} type="text" value={note} required maxLength={limit} autoComplete="off" aria-invalid={Boolean(error)} aria-describedby={id + '-help ' + id + '-error'} onChange={event => { setNote(event.target.value); setError(''); }} />
      <p id={id + '-help'} className="minor">Single-line text, up to {limit} UTF-8 bytes.{kind === 'resolve' ? ' Resolution records an analyst decision; it does not remediate or attest the endpoint.' : ' Notes remain available for open, acknowledged and resolved cases.'}</p>
      <p id={id + '-error'} role="alert" className="feedback">{error}</p>
      <button type="submit">{kind === 'note' ? 'Add note' : 'Resolve case'}</button>
    </fieldset>
  </form>;
}

function CaseAssignmentForm({ alert, onMutation }: { alert: SOCAlert; onMutation: Mutate }) {
  const [operatorID, setOperatorID] = useState('');
  const [error, setError] = useState('');
  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const id = socIdentity(operatorID);
      if (id === alert.assigned_to) { setError('This case is already assigned to that operator.'); return; }
      setError(''); onMutation({ kind: 'assign', alert_id: alert.alert_id, operator_id: id });
    } catch { setError('Enter an existing scanner operator ID using 1–96 letters, digits, dots, underscores or hyphens.'); }
  };
  return <form className="soc-form" onSubmit={submit} aria-label="Assign the active case">
    <fieldset><legend>Assign the active case</legend>
      <label htmlFor="soc-case-assignee">Scanner operator ID</label>
      <input id="soc-case-assignee" type="text" value={operatorID} required maxLength={96} autoComplete="off" spellCheck={false}
        aria-invalid={Boolean(error)} aria-describedby="soc-case-assignee-help soc-case-assignee-error" onChange={event => { setOperatorID(event.target.value); setError(''); }} />
      <p id="soc-case-assignee-help" className="minor">The server verifies that this operator is an active scanner in your tenant. An operator directory is not exposed by this service.</p>
      <p id="soc-case-assignee-error" role="alert" className="feedback">{error}</p>
      <div className="actions"><button type="submit">Assign case</button>
        {alert.assigned_to && <button type="button" className="secondary" onClick={() => onMutation({ kind: 'unassign', alert_id: alert.alert_id })}>Unassign case</button>}
      </div>
    </fieldset>
  </form>;
}

export function SOCCaseControls({ alert, canWrite, onMutation }: { alert: SOCAlert; canWrite: boolean; onMutation: Mutate }) {
  if (!canWrite) return <p>Viewer role: read-only case details and activity. A scanner-role operator is required to change a case.</p>;
  return <div className="soc-case-controls">
    <p>These actions record analyst workflow. The app reloads your identity and case details before sending a request; the service authorizes each write. Another operator may still update the case between reads.</p>
    {alert.state === 'open' && <button type="button" onClick={() => onMutation({ kind: 'ack', alert_id: alert.alert_id })}>Acknowledge this case</button>}
    {alert.state === 'acknowledged' && <CaseTextForm alert={alert} kind="resolve" onMutation={onMutation} />}
    {alert.state === 'resolved' && <button type="button" onClick={() => onMutation({ kind: 'reopen', alert_id: alert.alert_id })}>Reopen case</button>}
    {alert.state !== 'resolved' && <CaseAssignmentForm alert={alert} onMutation={onMutation} />}
    <CaseTextForm alert={alert} kind="note" onMutation={onMutation} />
  </div>;
}
