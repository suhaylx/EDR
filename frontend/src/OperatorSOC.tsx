import React, { useEffect, useRef, useState } from 'react';
import { operatorHealthLabel } from './soc-operator-endpoints.js';
import {
  firstSOCPages, loadSOCActivity, loadSOCSnapshot, socFailure, socFailureMessages, socPageSize,
  type SOCActivity, type SOCAlert, type SOCFailure, type SOCOffsets, type SOCSnapshot,
} from './soc-api.js';
import type { SOCPage } from './soc-contract.js';

type ActivityState = Readonly<{ alertID: string; state: 'loading' }> |
  Readonly<{ alertID: string; state: 'ready'; page: SOCPage<SOCActivity> }>;
export type OperatorViewState = Readonly<{ state: 'disconnected' | 'loading' }> |
  Readonly<{ state: 'error'; error: SOCFailure }> |
  Readonly<{ state: 'ready'; snapshot: SOCSnapshot; activity?: ActivityState }>;
type ViewProps = Readonly<{
  view: OperatorViewState;
  onRefresh: () => void;
  onClear: () => void;
  onPage: (section: keyof SOCOffsets, offset: number) => void;
  onActivity: (alertID: string, offset?: number) => void;
}>;

const utc = (value: string): string => new Date(value).toISOString();

function Paging({ page, label, onChange }: { page: SOCPage<unknown>; label: string; onChange: (offset: number) => void }) {
  return <div className="analyst-paging" role="group" aria-label={label + ' pages'}>
    <button type="button" className="secondary" disabled={page.offset === 0} onClick={() => onChange(page.offset - socPageSize)}>Previous {label}</button>
    <span>Page {page.offset / socPageSize + 1} · {page.items.length} returned record(s)</span>
    <button type="button" className="secondary" disabled={page.items.length < page.limit || page.offset >= 10000}
      onClick={() => onChange(page.offset + socPageSize)}>Next {label}</button>
  </div>;
}

function AlertTable({ page, label, onActivity }: { page: SOCPage<SOCAlert>; label: string; onActivity: ViewProps['onActivity'] }) {
  if (!page.items.length) return <p className="empty">No {label.toLowerCase()} were returned on this page. This does not establish the absence of threats.</p>;
  return <div className="table-scroll" tabIndex={0} role="region" aria-label={label + ' table'}>
    <table><caption>{label}. Signature detections are endpoint reports; case state is analyst workflow metadata.</caption>
      <thead><tr><th scope="col">Alert / endpoint</th><th scope="col">Reported detection</th><th scope="col">Case state / owner</th><th scope="col">Last update (UTC)</th><th scope="col">Case activity</th></tr></thead>
      <tbody>{page.items.map(alert => <tr key={alert.alert_id}>
        <th scope="row"><span className="soc-reference">{alert.alert_id}</span><span className="minor">{alert.agent_id}</span></th>
        <td>High · malware signature<span className="minor">{alert.signature_name}</span></td>
        <td>{alert.state}<span className="minor">{alert.assigned_to ? 'Assigned to ' + alert.assigned_to : 'Unassigned'}</span></td>
        <td><time dateTime={alert.updated_at}>{utc(alert.updated_at)}</time></td>
        <td><button type="button" className="secondary" onClick={() => onActivity(alert.alert_id)} aria-label={'Read activity for alert ' + alert.alert_id}>Read activity</button></td>
      </tr>)}</tbody>
    </table>
  </div>;
}

export function OperatorSOCView({ view, onRefresh, onClear, onPage, onActivity }: ViewProps) {
  return <div className="layout soc-layout">
    <a className="skip-link" href="#soc-content">Skip to SOC records</a>
    <header className="masthead"><div><p className="eyebrow">TuranSec EDR</p><h1>Operator SOC</h1>
      <p>Read endpoint inventory, detection alerts and assigned cases from the authenticated service.</p></div>
      <span className="lab-indicator">{view.state === 'ready' ? 'Operator certificate accepted' : 'Operator certificate required'}</span>
    </header>
    <section className="panel" aria-labelledby="soc-connection-title">
      <div className="heading"><h2 id="soc-connection-title">Operator connection</h2><div className="actions">
        <button type="button" onClick={onRefresh} disabled={view.state === 'loading'}>{view.state === 'ready' ? 'Refresh SOC records' : 'Connect to SOC'}</button>
        <button type="button" className="secondary" onClick={onClear} disabled={view.state === 'disconnected'}>Clear displayed records</button>
      </div></div>
      <p>Your browser uses its installed operator client certificate. The application does not request a token or private key.</p>
      <p className="minor">Clearing this view removes displayed records. Your browser still manages the certificate; this action does not revoke it or sign out of the TLS connection.</p>
      <div role="status" aria-live="polite" aria-atomic="true">
        {view.state === 'disconnected' && <p>No records loaded. Endpoint condition is unknown until the authenticated service returns evidence.</p>}
        {view.state === 'loading' && <p>Verifying the operator and loading bounded SOC pages. Previous records have been cleared.</p>}
        {view.state === 'error' && <p className="status status--warning">{socFailureMessages[view.error]}</p>}
        {view.state === 'ready' && <p>Loaded records for tenant <strong>{view.snapshot.session.tenant_id}</strong>, operator <strong>{view.snapshot.session.operator_id}</strong> ({view.snapshot.session.role}).</p>}
      </div>
      {view.state === 'ready' && <p className="minor">Server time after these reads: <time dateTime={view.snapshot.session.server_time}>{utc(view.snapshot.session.server_time)}</time>. Pages and summaries are separate reads, not an atomic database snapshot. Refresh to recheck authorization and current state.</p>}
    </section>
    <main id="soc-content" tabIndex={-1} aria-busy={view.state === 'loading'}>
      {view.state === 'ready' ? <>
        <section className="panel" aria-labelledby="soc-overview-title"><h2 id="soc-overview-title">Returned fleet and alert summary</h2>
          <div className="metric-grid">{[
            ['Enrolled endpoints', view.snapshot.endpointStats.total, 'Registry records, not verified installations'],
            ['Recent heartbeat', view.snapshot.endpointStats.online, 'Scanner readiness is endpoint-reported'],
            ['Degraded readiness', view.snapshot.endpointStats.degraded, 'Recent heartbeat; reported scanner unavailable'],
            ['Stale heartbeat', view.snapshot.endpointStats.stale, 'Current condition unknown'],
            ['No heartbeat', view.snapshot.endpointStats.unseen, 'Current condition unknown'],
            ['Revoked enrollment', view.snapshot.endpointStats.revoked, 'Agent access revoked'],
            ['Open alerts', view.snapshot.alertStats.open, 'Reported signature detections awaiting triage'],
            ['Acknowledged alerts', view.snapshot.alertStats.acknowledged, 'Analyst workflow state'],
            ['Resolved alerts', view.snapshot.alertStats.resolved, 'Resolution does not prove endpoint remediation'],
          ].map(([label, count, detail]) => <div className="metric" key={label}><span>{label}</span><strong>{count}</strong><small>{detail}</small></div>)}</div>
          <p>Heartbeat and scanner metadata do not attest endpoint protection. An empty page or zero alert count does not establish that the fleet is safe.</p>
        </section>
        <section className="panel" aria-labelledby="soc-endpoints-title"><h2 id="soc-endpoints-title">Endpoint inventory</h2>
          {view.snapshot.endpoints.items.length ? <div className="table-scroll" tabIndex={0} role="region" aria-label="Endpoint inventory table"><table>
            <caption>Enrolled Windows and Linux agents. Health is derived from server-received heartbeats and endpoint-reported readiness.</caption>
            <thead><tr><th scope="col">Endpoint</th><th scope="col">Platform</th><th scope="col">Heartbeat / evidence</th><th scope="col">Reported versions</th><th scope="col">Reported scanner readiness</th></tr></thead>
            <tbody>{view.snapshot.endpoints.items.map(endpoint => <tr key={endpoint.agent_id}>
              <th scope="row">{endpoint.agent_id}</th><td>{endpoint.platform}</td>
              <td><strong>{endpoint.health}</strong><span className="minor">{operatorHealthLabel(endpoint)}</span><span className="minor">{endpoint.last_seen ? 'Last server receipt: ' + utc(endpoint.last_seen) : 'No server receipt time'}</span></td>
              <td>Agent: {endpoint.agent_version || 'Not reported'}<span className="minor">ClamAV: {endpoint.clamav_version || 'Not reported'}</span><span className="minor">Signatures: {endpoint.signature_version || 'Not reported'}</span></td>
              <td>{endpoint.scan_ready ? 'Reported ready; not verified' : 'Not reported ready; current protection unknown'}</td>
            </tr>)}</tbody>
          </table></div> : <p className="empty">No enrolled endpoints were returned on this page. No protection state can be inferred.</p>}
          <Paging page={view.snapshot.endpoints} label="endpoints" onChange={offset => onPage('endpoints', offset)} />
        </section>
        <section className="panel" aria-labelledby="soc-alerts-title"><h2 id="soc-alerts-title">Detection alerts</h2>
          <AlertTable page={view.snapshot.alerts} label="Detection alerts" onActivity={onActivity} />
          <Paging page={view.snapshot.alerts} label="alerts" onChange={offset => onPage('alerts', offset)} />
        </section>
        <section className="panel" aria-labelledby="soc-mine-title"><h2 id="soc-mine-title">My assigned cases</h2>
          <p>Active alerts assigned by the server to the authenticated operator. This view cannot assign, resolve or modify a case.</p>
          <AlertTable page={view.snapshot.mine} label="Assigned active cases" onActivity={onActivity} />
          <Paging page={view.snapshot.mine} label="assigned cases" onChange={offset => onPage('mine', offset)} />
        </section>
        {view.activity && <section className="panel" aria-labelledby="soc-activity-title" aria-busy={view.activity.state === 'loading'}>
          <h2 id="soc-activity-title">Case activity</h2><p>Alert <span className="soc-reference">{view.activity.alertID}</span></p>
          <div role="status" aria-live="polite">{view.activity.state === 'loading' ? 'Loading the selected case activity.' : `${view.activity.page.items.length} activity record(s) returned.`}</div>
          {view.activity.state === 'ready' && <>
            {view.activity.page.items.length ? <ol className="soc-activity">{view.activity.page.items.map(event => <li key={event.activity_id}>
              <strong>{event.action}</strong> · {event.actor_id}<span className="minor"><time dateTime={event.occurred_at}>{utc(event.occurred_at)}</time></span>
              {event.note && <p>{event.note}</p>}
            </li>)}</ol> : <p className="empty">No activity was returned on this page. Earlier history may be unavailable.</p>}
            <Paging page={view.activity.page} label="activity" onChange={offset => onActivity(view.activity!.alertID, offset)} />
          </>}
          <p className="minor">Database activity is workflow evidence. It is not a cryptographic audit log or proof that an endpoint action occurred.</p>
        </section>}
      </> : <section className="panel"><h2>SOC records unavailable</h2><p>Connect to the operator service to load records. No cached endpoint health or alert data is displayed.</p></section>}
    </main>
  </div>;
}

export function OperatorSOC() {
  const [view, setView] = useState<OperatorViewState>({ state: 'disconnected' });
  const offsets = useRef<SOCOffsets>(firstSOCPages);
  const generation = useRef(0);
  const request = useRef<AbortController | null>(null);
  const clear = () => {
    generation.current++;
    request.current?.abort();
    request.current = null;
    offsets.current = firstSOCPages;
    setView({ state: 'disconnected' });
  };
  const begin = () => {
    generation.current++;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    return { controller, number: generation.current };
  };
  const refresh = async (pages = offsets.current) => {
    const { controller, number } = begin();
    offsets.current = pages;
    setView({ state: 'loading' });
    try {
      const snapshot = await loadSOCSnapshot({ protocol: window.location.protocol, signal: controller.signal }, pages);
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'ready', snapshot });
    } catch (error) {
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'error', error: socFailure(error) });
    }
  };
  const activity = async (alertID: string, offset = 0) => {
    if (view.state !== 'ready') return;
    const snapshot = view.snapshot;
    const { controller, number } = begin();
    setView({ state: 'ready', snapshot, activity: { state: 'loading', alertID } });
    try {
      const page = await loadSOCActivity(snapshot.session, alertID, { protocol: window.location.protocol, signal: controller.signal }, offset);
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'ready', snapshot, activity: { state: 'ready', alertID, page } });
    } catch (error) {
      // Authorization loss during a detail read clears the entire snapshot.
      if (number === generation.current && !controller.signal.aborted) setView({ state: 'error', error: socFailure(error) });
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
  return <OperatorSOCView view={view} onRefresh={() => { void refresh(); }} onClear={clear}
    onPage={(section, offset) => { void refresh({ ...offsets.current, [section]: offset }); }}
    onActivity={(alertID, offset) => { void activity(alertID, offset); }} />;
}
