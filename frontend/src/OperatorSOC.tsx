import React, { useEffect, useRef, useState } from 'react';
import { getPasswordSession, PasswordLogin, AdminPackageGenerator, type PasswordSession } from './SOCLogin.js';
import { operatorHealthLabel } from './soc-operator-endpoints.js';
import {
  runSOCMutation, SOCMutationRefreshError, mutationReceiptLabel,
  firstSOCPages, loadSOCCase, loadSOCScanDetail, loadSOCSnapshot, socFailure, socFailureMessages, setSOCCSRF,
  type SOCCaseDetail, type SOCAlert, type SOCFailure, type SOCMutationCommand, type SOCMutationReceipt, type SOCOffsets, type SOCSnapshot,
} from './soc-api.js';
import type { SOCPage } from './soc-contract.js';
import type { SOCScanDetail } from './soc-scans.js';
import { SOCPaging as Paging, SOCCaseControls, SOCScanWorkspace, SOCScanDetailView, socUTC as utc } from './SOCControls.js';

type Selection = Readonly<{ kind: 'case'; alertID: string; state: 'loading' }> |
  Readonly<{ kind: 'case'; alertID: string; state: 'ready'; detail: SOCCaseDetail }> |
  Readonly<{ kind: 'scan'; jobID: string; state: 'loading' }> |
  Readonly<{ kind: 'scan'; jobID: string; state: 'ready'; detail: SOCScanDetail }>;
export type OperatorViewState = Readonly<{ state: 'disconnected'; interrupted?: boolean }> |
  Readonly<{ state: 'loading'; operation?: SOCMutationCommand['kind'] }> |
  Readonly<{ state: 'error'; error: SOCFailure; receipt?: SOCMutationReceipt }> |
  Readonly<{ state: 'ready'; snapshot: SOCSnapshot; selection?: Selection; receipt?: SOCMutationReceipt }>;
type ViewProps = Readonly<{
  view: OperatorViewState;
  onRefresh: () => void;
  onClear: () => void;
  onPage: (section: keyof SOCOffsets, offset: number) => void;
  onCase: (alertID: string, offset?: number) => void;
  onScan: (jobID: string) => void;
  onMutation: (command: SOCMutationCommand) => void;
  auth?: PasswordSession | null;
  onSignOut?: () => void;
  logoutError?: string;
}>;

function AlertTable({ page, label, canAcknowledge, onCase, onMutation }: {
  page: SOCPage<SOCAlert>; label: string; canAcknowledge: boolean;
  onCase: ViewProps['onCase']; onMutation: ViewProps['onMutation'];
}) {
  if (!page.items.length) return <p className="empty">No {label.toLowerCase()} were returned on this page. This does not establish the absence of threats.</p>;
  return <div className="table-scroll" tabIndex={0} role="region" aria-label={label + ' table'}>
    <table><caption>{label}. Signature detections are endpoint reports; case state is analyst workflow metadata.</caption>
      <thead><tr><th scope="col">Alert / endpoint</th><th scope="col">Reported detection</th><th scope="col">Case state / owner</th><th scope="col">Last update (UTC)</th><th scope="col">Case actions</th></tr></thead>
      <tbody>{page.items.map(alert => <tr key={alert.alert_id}>
        <th scope="row"><span className="soc-reference">{alert.alert_id}</span><span className="minor">{alert.agent_id}</span></th>
        <td><span className="soc-severity">High</span><span className="soc-signature">Malware signature</span><span className="minor">{alert.signature_name}</span></td>
        <td><span className={'soc-state soc-state--' + alert.state}>{alert.state}</span><span className="minor">{alert.assigned_to ? 'Assigned to ' + alert.assigned_to : 'Unassigned'}</span></td>
        <td><time dateTime={alert.updated_at}>{utc(alert.updated_at)}</time></td>
        <td><div className="actions">
          <button type="button" className="secondary" onClick={() => onCase(alert.alert_id)} aria-label={'Read case and activity for alert ' + alert.alert_id}>Read case and activity</button>
          {canAcknowledge && alert.state === 'open' && <button type="button" onClick={() => onMutation({ kind: 'ack', alert_id: alert.alert_id })} aria-label={'Acknowledge alert ' + alert.alert_id}>Acknowledge</button>}
        </div></td>
      </tr>)}</tbody>
    </table>
  </div>;
}

export function OperatorSOCView({ view, onRefresh, onClear, onPage, onCase, onScan, onMutation, auth, onSignOut, logoutError }: ViewProps) {
  const [endpointQuery, setEndpointQuery] = useState('');
  const visibleEndpoints = view.state === 'ready' ? view.snapshot.endpoints.items.filter(item =>
    (item.agent_id + ' ' + item.platform + ' ' + item.health).toLowerCase().includes(endpointQuery.trim().toLowerCase())) : [];
  return <div className="layout soc-layout">
    <a className="skip-link" href="#soc-content">Skip to SOC records</a>
    <header className="masthead soc-topbar">
      <div className="soc-topbar-name"><span className="soc-mark" aria-hidden="true">T</span><div>
        <p className="eyebrow">TURANSEC / SECURITY OPERATIONS</p><h1>Operator SOC</h1>
      </div></div>
      <div className="soc-topbar-right"><span className="soc-environment">LOCAL LAB</span>
        <span className={'soc-live-status ' + (view.state === 'ready' ? 'soc-live-status--ready' : '')}><span className="soc-pulse" aria-hidden="true" />{view.state === 'ready' ? 'Session connected' : 'Awaiting data'}</span>
      </div>
    </header>
    <div className="soc-shell">
    <section className="panel soc-connection" aria-labelledby="soc-connection-title">
      <div className="heading"><div><p className="soc-section-label">CONTROL CENTER</p><h2 id="soc-connection-title">Operational overview</h2></div><div className="actions">
        <button type="button" onClick={onRefresh} disabled={view.state === 'loading'}>{view.state === 'ready' ? 'Refresh SOC records' : 'Connect to SOC'}</button>
        <button type="button" className="secondary" onClick={onClear} disabled={view.state === 'disconnected'}>Clear displayed records</button>
      </div></div>
      <p className="soc-context-line">Live server records only. No simulated endpoints, fabricated detections, or cached security state.</p>
      <p className="minor">Clearing displayed records does not revoke your login session. Use Sign out to end password access.</p>
      <div role="status" aria-live="polite" aria-atomic="true">
        {view.state === 'disconnected' && <p>No records loaded. Endpoint condition is unknown until the authenticated service returns evidence.</p>}
        {view.state === 'disconnected' && view.interrupted && <p>An operation was interrupted while clearing the view. It may already have been accepted by the server. Reconnect and inspect the current state before acting again. No automatic retry was sent.</p>}
        {view.state === 'loading' && <p>{view.operation
          ? 'Verifying the operator and selected record before sending the requested operation. Previous records have been cleared; the outcome is pending. No automatic retry will be sent.'
          : 'Verifying the operator and loading bounded SOC pages. Previous records have been cleared.'}</p>}
        {view.state === 'error' && <p className="status status--warning">{socFailureMessages[view.error]}</p>}
        {view.state === 'ready' && <p>Loaded records for tenant <strong>{view.snapshot.session.tenant_id}</strong>, operator <strong>{view.snapshot.session.operator_id}</strong> ({view.snapshot.session.role}).</p>}
        {view.state === 'ready' && view.receipt && <p>{mutationReceiptLabel(view.receipt)}. Current SOC records and selected details were reloaded. This queue or analyst workflow change is not proof of endpoint execution or remediation. Reference: <span className="soc-reference">{view.receipt.reference_id}</span>.</p>}
        {view.state === 'error' && view.receipt && <p>{mutationReceiptLabel(view.receipt)}, but current records could not be reloaded. Reconnect to verify state before taking another action. Reference: <span className="soc-reference">{view.receipt.reference_id}</span>.</p>}
      </div>
      {view.state === 'ready' && <p className="minor">Server time after these reads: <time dateTime={view.snapshot.session.server_time}>{utc(view.snapshot.session.server_time)}</time>. Pages and summaries are separate reads, not an atomic database snapshot. Refresh to recheck authorization and current state.</p>}
    </section>
    <aside className="soc-sidebar">
      <div className="soc-sidebar-intro"><span className="soc-side-overline">WORKSPACES</span><strong>Detection &amp; response</strong></div>
      <nav className="soc-nav" aria-label="SOC workspaces">
        <a href="#soc-overview-title"><span aria-hidden="true" className="soc-nav-glyph">◫</span>Overview</a>
        <a href="#soc-endpoints-title"><span aria-hidden="true" className="soc-nav-glyph">▦</span>Endpoints</a>
        <a href="#soc-alerts-title"><span aria-hidden="true" className="soc-nav-glyph">◇</span>Alerts &amp; triage</a>
        <a href="#soc-mine-title"><span aria-hidden="true" className="soc-nav-glyph">☰</span>My cases</a>
        <a href="#soc-scans-title"><span aria-hidden="true" className="soc-nav-glyph">◎</span>Scan operations</a>
        {auth?.role === 'admin' && <a href="#agent-gen-title"><span aria-hidden="true" className="soc-nav-glyph">⊞</span>Agent packages</a>}
      </nav>
      <div className="soc-sidebar-foot"><span className="soc-side-overline">CURRENT IDENTITY</span>
        <strong>{auth?.username ?? (view.state === 'ready' ? view.snapshot.session.operator_id : 'Not connected')}</strong>
        <span className="soc-side-role">{auth?.role ?? (view.state === 'ready' ? view.snapshot.session.role : 'Local lab')}</span>
        {auth && onSignOut && <button type="button" className="soc-signout" onClick={onSignOut}>Sign out</button>}
        {logoutError && <p role="alert" className="soc-signout-error">{logoutError}</p>}
      </div>
    </aside>
    <main className="soc-workspace" id="soc-content" tabIndex={-1} aria-busy={view.state === 'loading'}>
      {view.state === 'ready' ? <>
        <section className="panel soc-overview-panel" aria-labelledby="soc-overview-title">
          <div className="soc-panel-heading"><div><p className="soc-section-label">FLEET POSTURE</p><h2 id="soc-overview-title">Returned fleet and alert summary</h2></div><span className="soc-panel-chip">Server reported</span></div>
          <div className="metric-grid soc-kpi-grid">{[
            ['Enrolled endpoints', view.snapshot.endpointStats.total, 'Registry records, not verified installations'],
            ['Recent heartbeat', view.snapshot.endpointStats.online, 'Scanner readiness is endpoint-reported'],
            ['Degraded readiness', view.snapshot.endpointStats.degraded, 'Recent heartbeat; reported scanner unavailable'],
            ['Stale heartbeat', view.snapshot.endpointStats.stale, 'Current condition unknown'],
            ['No heartbeat', view.snapshot.endpointStats.unseen, 'Current condition unknown'],
            ['Revoked enrollment', view.snapshot.endpointStats.revoked, 'Agent access revoked'],
            ['Open alerts', view.snapshot.alertStats.open, 'Reported signature detections awaiting triage'],
            ['Acknowledged alerts', view.snapshot.alertStats.acknowledged, 'Analyst workflow state'],
            ['Resolved alerts', view.snapshot.alertStats.resolved, 'Resolution does not prove endpoint remediation'],
          ].map(([label, count, detail], index) => <div className={'metric soc-metric soc-metric--' + index} key={label}><span>{label}</span><strong>{count}</strong><small>{detail}</small></div>)}</div>
          <p>Heartbeat and scanner metadata do not attest endpoint protection. An empty page or zero alert count does not establish that the fleet is safe.</p>
        </section>
        <section className="panel soc-data-panel" aria-labelledby="soc-endpoints-title">
          <div className="soc-panel-heading"><div><p className="soc-section-label">ASSET VISIBILITY</p><h2 id="soc-endpoints-title">Endpoint inventory</h2></div><span className="soc-panel-chip">{view.snapshot.endpointStats.total} enrolled</span></div>
          <div className="soc-filter-line"><p>Search the loaded page by endpoint, OS or health.</p>
            <label htmlFor="soc-endpoint-search">Filter endpoints
              <input id="soc-endpoint-search" type="search" value={endpointQuery} onChange={event => setEndpointQuery(event.target.value)} placeholder="Search current page" autoComplete="off" />
            </label>
          </div>
          {view.snapshot.endpoints.items.length ? <div className="table-scroll" tabIndex={0} role="region" aria-label="Endpoint inventory table"><table>
            <caption>Enrolled Windows and Linux agents. Health is derived from server-received heartbeats and endpoint-reported readiness.</caption>
            <thead><tr><th scope="col">Endpoint</th><th scope="col">Platform</th><th scope="col">Heartbeat / evidence</th><th scope="col">Reported versions</th><th scope="col">Reported scanner readiness</th></tr></thead>
            <tbody>{visibleEndpoints.map(endpoint => <tr key={endpoint.agent_id}>
              <th scope="row">{endpoint.agent_id}</th><td>{endpoint.platform}</td>
              <td><strong>{endpoint.health}</strong><span className="minor">{operatorHealthLabel(endpoint)}</span><span className="minor">{endpoint.last_seen ? 'Last server receipt: ' + utc(endpoint.last_seen) : 'No server receipt time'}</span></td>
              <td>Agent: {endpoint.agent_version || 'Not reported'}<span className="minor">ClamAV: {endpoint.clamav_version || 'Not reported'}</span><span className="minor">Signatures: {endpoint.signature_version || 'Not reported'}</span></td>
              <td>{endpoint.scan_ready ? 'Reported ready; not verified' : 'Not reported ready; current protection unknown'}</td>
            </tr>)}</tbody>
          </table>{visibleEndpoints.length === 0 && <p className="empty">No endpoints match the current page filter.</p>}</div> : <p className="empty">No enrolled endpoints were returned on this page. No protection state can be inferred.</p>}
          <Paging page={view.snapshot.endpoints} label="endpoints" onChange={offset => onPage('endpoints', offset)} />
        </section>
        <section className="panel soc-data-panel" aria-labelledby="soc-alerts-title"><div className="soc-panel-heading"><div><p className="soc-section-label">THREAT MONITORING</p><h2 id="soc-alerts-title">Detection alerts</h2></div><span className="soc-panel-chip">{view.snapshot.alertStats.open} open</span></div>
          <p>{view.snapshot.session.role === 'scanner'
            ? 'Acknowledge an open alert to record that triage has started. This does not resolve the case or change the endpoint.'
            : 'Viewer role: read-only access. A scanner-role operator is required to acknowledge an alert.'}</p>
          <AlertTable page={view.snapshot.alerts} label="Detection alerts" canAcknowledge={view.snapshot.session.role === 'scanner'} onCase={onCase} onMutation={onMutation} />
          <Paging page={view.snapshot.alerts} label="alerts" onChange={offset => onPage('alerts', offset)} />
        </section>
        <section className="panel soc-data-panel" aria-labelledby="soc-mine-title"><div className="soc-panel-heading"><div><p className="soc-section-label">ANALYST QUEUE</p><h2 id="soc-mine-title">My assigned cases</h2></div><span className="soc-panel-chip">{view.snapshot.mine.items.length} on page</span></div>
          <p>Active alerts assigned by the server to the authenticated operator. Open a case to review its current state, notes and assignment before taking an action.</p>
          <AlertTable page={view.snapshot.mine} label="Assigned active cases" canAcknowledge={view.snapshot.session.role === 'scanner'} onCase={onCase} onMutation={onMutation} />
          <Paging page={view.snapshot.mine} label="assigned cases" onChange={offset => onPage('mine', offset)} />
        </section>
        {view.selection?.kind === 'case' && <section className="panel" aria-labelledby="soc-activity-title" aria-busy={view.selection.state === 'loading'}>
          <h2 id="soc-activity-title">Case details and activity</h2><p>Alert <span className="soc-reference">{view.selection.alertID}</span></p>
          <div role="status" aria-live="polite">{view.selection.state === 'loading' ? 'Loading the selected case details and activity.' : `${view.selection.detail.activity.items.length} activity record(s) returned.`}</div>
          {view.selection.state === 'ready' && <>
            <dl className="soc-details"><div><dt>Current case state</dt><dd>{view.selection.detail.alert.state}</dd></div>
              <div><dt>Current assignment</dt><dd>{view.selection.detail.alert.assigned_to || 'Unassigned'}</dd></div>
              <div><dt>Reported signature</dt><dd>{view.selection.detail.alert.signature_name}</dd></div>
              <div><dt>Acknowledged by</dt><dd>{view.selection.detail.alert.acknowledged_by || 'Not recorded'}</dd></div>
              <div><dt>Resolved by</dt><dd>{view.selection.detail.alert.resolved_by || 'Not recorded'}</dd></div>
              <div><dt>Resolution note</dt><dd>{view.selection.detail.alert.resolution_note || 'Not recorded'}</dd></div></dl>
            <SOCCaseControls key={view.selection.alertID + view.selection.detail.alert.updated_at} alert={view.selection.detail.alert} canWrite={view.snapshot.session.role === 'scanner'} onMutation={onMutation} />
            <h3>Recorded activity</h3>
            {view.selection.detail.activity.items.length ? <ol className="soc-activity">{view.selection.detail.activity.items.map(event => <li key={event.activity_id}>
              <strong>{event.action}</strong> · {event.actor_id}<span className="minor"><time dateTime={event.occurred_at}>{utc(event.occurred_at)}</time></span>
              {event.note && <p>{event.note}</p>}
            </li>)}</ol> : <p className="empty">No activity was returned on this page. Earlier history may be unavailable.</p>}
            <Paging page={view.selection.detail.activity} label="activity" onChange={offset => { if (view.selection?.kind === 'case') onCase(view.selection.alertID, offset); }} />
          </>}
          <p className="minor">Database activity is workflow evidence. It is not a cryptographic audit log or proof that an endpoint action occurred.</p>
        </section>}
        <SOCScanWorkspace snapshot={view.snapshot} onPage={onPage} onScan={onScan} onMutation={onMutation} />
        {view.selection?.kind === 'scan' && <section className="panel" aria-labelledby="soc-scan-detail-title" aria-busy={view.selection.state === 'loading'}>
          <h2 id="soc-scan-detail-title">Selected scan details</h2><p>Job <span className="soc-reference">{view.selection.jobID}</span></p>
          <div role="status" aria-live="polite">{view.selection.state === 'loading' ? 'Loading the selected scan job and optional reported result.' : 'Current scan details loaded.'}</div>
          {view.selection.state === 'ready' && <SOCScanDetailView detail={view.selection.detail} canWrite={view.snapshot.session.role === 'scanner'} onMutation={onMutation} />}
        </section>}
      </> : <section className="panel soc-unavailable"><span className="soc-unavailable-icon" aria-hidden="true">⌁</span><h2>SOC records unavailable</h2><p>Connect to the operator service to load records. No cached endpoint health or alert data is displayed.</p></section>}
      {auth?.role === 'admin' && <AdminPackageGenerator session={auth} />}
    </main>
    </div>
  </div>;
}

export function OperatorSOC() {
  const [authMode, setAuthMode] = useState<'checking' | 'password' | 'legacy' | 'error'>('checking');
  const [auth, setAuth] = useState<PasswordSession | null>(null);
  const [logoutError, setLogoutError] = useState('');
  const [view, setView] = useState<OperatorViewState>({ state: 'disconnected' });
  const offsets = useRef<SOCOffsets>(firstSOCPages);
  const generation = useRef(0);
  const request = useRef<AbortController | null>(null);
  const mutationPending = useRef(false);
  const interruptedWrite = useRef(false);
  const clear = () => {
    generation.current++;
    request.current?.abort();
    request.current = null;
    if (mutationPending.current) interruptedWrite.current = true;
    mutationPending.current = false;
    offsets.current = firstSOCPages;
    setView({ state: 'disconnected', interrupted: interruptedWrite.current });
  };
  const begin = () => {
    generation.current++;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    return { controller, number: generation.current };
  };
  const refresh = async (pages = offsets.current) => {
    if (mutationPending.current) return;
    const { controller, number } = begin();
    offsets.current = pages;
    setView({ state: 'loading' });
    try {
      const snapshot = await loadSOCSnapshot({ protocol: window.location.protocol, signal: controller.signal }, pages);
      if (number === generation.current && !controller.signal.aborted) { interruptedWrite.current = false; setView({ state: 'ready', snapshot }); }
    } catch (error) {
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'error', error: socFailure(error) });
    }
  };
  const readCase = async (alertID: string, offset = 0) => {
    if (view.state !== 'ready' || mutationPending.current) return;
    const snapshot = view.snapshot;
    const { controller, number } = begin();
    setView({ state: 'ready', snapshot, selection: { kind: 'case', state: 'loading', alertID } });
    try {
      const detail = await loadSOCCase(snapshot.session, alertID, { protocol: window.location.protocol, signal: controller.signal }, offset);
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'ready', snapshot, selection: { kind: 'case', state: 'ready', alertID, detail } });
    } catch (error) {
      // Authorization loss during a detail read clears the entire snapshot.
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'error', error: socFailure(error) });
    }
  };
  const readScan = async (jobID: string) => {
    if (view.state !== 'ready' || mutationPending.current) return;
    const snapshot = view.snapshot;
    const { controller, number } = begin();
    setView({ state: 'ready', snapshot, selection: { kind: 'scan', state: 'loading', jobID } });
    try {
      const detail = await loadSOCScanDetail(snapshot.session, jobID, { protocol: window.location.protocol, signal: controller.signal });
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'ready', snapshot, selection: { kind: 'scan', state: 'ready', jobID, detail } });
    } catch (error) {
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'error', error: socFailure(error) });
    }
  };
  const mutate = async (command: SOCMutationCommand) => {
    if (view.state !== 'ready' || mutationPending.current) return;
    mutationPending.current = true;
    interruptedWrite.current = false;
    const { controller, number } = begin();
    setView({ state: 'loading', operation: command.kind });
    try {
      const visible = view.selection?.state === 'ready'
        ? view.selection.kind === 'case' ? { alert: view.selection.detail.alert } : { job: view.selection.detail.job }
        : {};
      const outcome = await runSOCMutation(view.snapshot, command,
        { protocol: window.location.protocol, signal: controller.signal }, offsets.current, visible);
      if (number === generation.current && !controller.signal.aborted) {
        const selection: Selection | undefined = outcome.caseDetail
          ? { kind: 'case', state: 'ready', alertID: outcome.caseDetail.alert.alert_id, detail: outcome.caseDetail }
          : outcome.scanDetail ? { kind: 'scan', state: 'ready', jobID: outcome.scanDetail.job.job_id, detail: outcome.scanDetail } : undefined;
        setView({ state: 'ready', snapshot: outcome.snapshot, selection, receipt: outcome.receipt });
      }
    } catch (error) {
      if (number === generation.current && !controller.signal.aborted) {
        setView({ state: 'error', error: socFailure(error), receipt: error instanceof SOCMutationRefreshError ? error.receipt : undefined });
      }
    } finally {
      if (number === generation.current) mutationPending.current = false;
    }
  };
  useEffect(() => {
    const onPageHide = () => clear();
    const onPageShow = (event: PageTransitionEvent) => { if (event.persisted) clear(); };
    window.addEventListener('pagehide', onPageHide);
    window.addEventListener('pageshow', onPageShow);
    return () => {
      generation.current++;
      request.current?.abort();
      window.removeEventListener('pagehide', onPageHide);
      window.removeEventListener('pageshow', onPageShow);
    };
  }, []);
  useEffect(() => {
    let active = true;
    void getPasswordSession().then(result => {
      if (!active) return;
      setAuthMode(result.mode);
      if (result.session) {
        setAuth(result.session);
        setSOCCSRF(result.session.csrf_token);
        void refresh();
      }
    });
    return () => { active = false; };
  }, []);
  const authenticated = (session: PasswordSession) => {
    setAuth(session);
    setSOCCSRF(session.csrf_token);
    setLogoutError('');
    void refresh();
  };
  const signOut = async () => {
    if (!auth) return;
    try {
      const result = await fetch('/auth/logout', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'X-TuranSec-CSRF': auth.csrf_token },
      });
      if (result.status !== 204) throw new Error('Logout rejected');
      clear();
      setSOCCSRF('');
      setAuth(null);
      setLogoutError('');
    } catch { setLogoutError('Sign out could not be confirmed; session may remain active.'); }
  };
  if (authMode === 'checking') return <main className="layout"><p role="status">Checking the secured SOC login…</p></main>;
  if (authMode === 'error') return <main className="layout"><h1>SOC login unavailable</h1><p>Refresh after checking the login gateway service. No SOC data is displayed.</p></main>;
  if (authMode === 'password' && !auth) return <PasswordLogin onAuthenticated={authenticated} />;
  return <OperatorSOCView view={view} auth={auth} onSignOut={() => { void signOut(); }} logoutError={logoutError} onRefresh={() => { void refresh(); }} onClear={clear}
      onPage={(section, offset) => { void refresh({ ...offsets.current, [section]: offset }); }}
      onCase={(alertID, offset) => { void readCase(alertID, offset); }}
      onScan={jobID => { void readScan(jobID); }}
      onMutation={command => { void mutate(command); }} />;
}
