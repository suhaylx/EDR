import { useState } from 'react';
import type { LabSOCOverview } from './overview.js';
import { heartbeatLabel } from './overview.js';
import { filterPolicyEndpoints, policyEvidenceState, summarizePolicyEvidence, type PolicyEvidenceFilter } from './policy-evidence.js';

/** Read-only policy evidence: the untrusted lab API cannot prove enforcement. */
export function PolicyEvidenceView({ overview }: { overview: LabSOCOverview }) {
  const [filter, setFilter] = useState<PolicyEvidenceFilter>('attention');
  const [query, setQuery] = useState('');
  const visibleEndpoints = filterPolicyEndpoints(overview.endpoints, filter, query);
  const summary = summarizePolicyEvidence(overview);
  const metrics = [
    ['Enrolled records', summary.total],
    ['Reported policy IDs', summary.reportedPolicyIds],
    ['No policy ID reported', summary.missingPolicyIds],
    ['Policy IDs with absent/zero revision', summary.policyIdsWithoutPositiveRevision],
    ['Endpoints reporting errors', summary.endpointsWithErrors],
    ['Offline/unknown with a policy ID', summary.staleOrUnknownAcknowledgements],
    ['Backend-reported policy errors', summary.serverReportedErrors],
  ] as const;
  return <>
    <section className="panel" aria-labelledby="policy-view-title">
      <h2 id="policy-view-title">Policy acknowledgements and coverage gaps</h2>
      <p>This is a read-only snapshot of <strong>agent-reported policy IDs</strong> in the development API, generated at {overview.generated_at}. A policy ID or revision does not prove that Sysmon rules were installed, applied or enforced. Offline and unknown endpoints are not verified healthy.</p>
      <p className="minor">The {overview.window_days}-day UTC selector affects retained activity metrics, not the current policy snapshot. Policy changes and deployment controls are unavailable.</p>
      <div className="metric-grid">{metrics.map(([label, count]) =>
        <div className="metric" key={label}><span>{label}</span><strong>{count.toLocaleString()}</strong><small>Development API records; not an enforcement attestation</small></div>
      )}</div>
      {summary.discrepancies.length > 0 && <section aria-labelledby="policy-discrepancy-title">
        <h3 id="policy-discrepancy-title">Policy summary consistency warning</h3>
        <p role="status">Server policy aggregates do not reconcile with endpoint acknowledgements. Do not infer deployed policy coverage.</p>
        <ul>{summary.discrepancies.map((message, index)=><li key={index}>{message}</li>)}</ul>
      </section>}
      {summary.serverReportedErrors !== summary.endpointsWithErrors &&
        <p className="graph-warning" role="status">The aggregate policy-error count differs from the endpoint error count. The data sources or scope may differ; neither value attests to policy enforcement.</p>}
    </section>
    <section className="panel" aria-labelledby="policy-aggregate-title">
      <h2 id="policy-aggregate-title">Reported policy IDs by endpoint count</h2>
      <p>API aggregates group claimed applied-policy IDs. Count agreement means only that this response is internally consistent.</p>
      {summary.aggregates.length === 0
        ? <p className="empty">No policy aggregates returned. This does not establish that policies are deployed or that endpoints are protected.</p>
        : <div className="table-scroll"><table>
            <caption>Unverified lab control-plane policy summaries</caption>
            <thead><tr><th scope="col">Policy ID</th><th scope="col">Policy label</th><th scope="col">API aggregate</th><th scope="col">Inventory IDs</th><th scope="col">Count consistency</th></tr></thead>
            <tbody>{summary.aggregates.map((row,index)=><tr key={row.policyId+':'+index}>
              <th scope="row">{row.policyId || 'Not reported'}</th>
              <td>{row.policyName || 'Not reported'}</td>
              <td>{row.reportedByServer}</td><td>{row.seenInInventory}</td>
              <td><span className={'status status--'+(row.consistent?'neutral':'warning')}>
                {row.consistent?'Counts match; enforcement NOT VERIFIED':'Data disagreement — coverage UNKNOWN'}
              </span></td>
            </tr>)}</tbody>
          </table></div>}
    </section>
    <section className="panel" aria-labelledby="policy-endpoint-title">
      <h2 id="policy-endpoint-title">Endpoint-level policy evidence</h2>
      <p>Policy values and errors are agent-supplied claims; only the heartbeat state is calculated by the server.</p>
      <div className="inventory-filters">
        <div className="field">
          <label htmlFor="policy-filter">Reported evidence filter</label>
          <select id="policy-filter" value={filter} onChange={event => setFilter(event.target.value as PolicyEvidenceFilter)}>
            <option value="attention">Needs analyst attention (including revision gaps)</option>
            <option value="all">All returned endpoints</option>
            <option value="offline_unknown">Offline or unknown heartbeat</option>
            <option value="reported_error">Reported policy error</option>
            <option value="missing_id">No policy ID reported</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="policy-search">Search returned endpoint or policy evidence</label>
          <input id="policy-search" type="search" autoComplete="off" maxLength={200}
            value={query} onChange={event => setQuery(event.target.value)} />
        </div>
      </div>
      <p role="status" aria-live="polite">{visibleEndpoints.length} of {overview.endpoints.length} lab endpoint record(s) shown. Local filter only; no endpoint command sent.</p>
      {overview.endpoints.length === 0
        ? <p className="empty">No enrolled lab endpoints were returned. Actual deployed coverage is unknown.</p>
        : visibleEndpoints.length === 0
        ? <p className="empty">No returned endpoint records match this local filter. This does not establish policy enforcement or protection.</p>
        : <div className="table-scroll"><table>
            <caption>Locally filtered policy evidence, with reported errors and missing policy IDs first</caption>
            <thead><tr><th scope="col">Endpoint</th><th scope="col">OS / group</th><th scope="col">Heartbeat</th><th scope="col">Reported policy / revision</th><th scope="col">Reported error</th><th scope="col">Interpretation</th></tr></thead>
            <tbody>{visibleEndpoints.map(e=><tr key={e.id}>
              <th scope="row">{e.id}</th>
              <td>{e.platform}<span className="minor">{e.group || 'No group reported'}</span></td>
              <td>{e.status}<span className="minor">{heartbeatLabel(e)}</span></td>
              <td>{e.applied_policy_id || 'No policy ID reported'}<span className="minor">Revision: {e.applied_policy_id ? (e.applied_revision === 0 ? 'not reported or zero' : e.applied_revision) : 'not reported'}</span></td>
              <td>{e.last_policy_error || 'No error reported (not proof of success)'}</td>
              <td>{policyEvidenceState(e)}</td>
            </tr>)}</tbody>
          </table></div>}
      <p className="minor">Unavailable: signed desired/applied policy hashes, authoritative Sysmon Event 1/7/11 collector health, signature freshness, tamper signals, tenant-scoped rollout logs, rollback and signed policy enforcement checks. Agent 2 must provide verified versioned contracts; Agent 3 must independently test them.</p>
    </section>
  </>;
}
