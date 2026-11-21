/**
 * Read-only interpretation of the development overview's policy acknowledgements.
 * Server aggregates are derived from agent-reported management state, not proof
 * of installed/enforced Sysmon policy, signature freshness, or endpoint safety.
 */
import type { EndpointActivity, LabSOCOverview } from './overview.js';

export type PolicyAggregateRow = {
  policyId: string;
  policyName: string;
  reportedByServer: number;
  seenInInventory: number;
  consistent: boolean;
};
export type PolicyEvidenceSummary = {
  total: number;
  reportedPolicyIds: number;
  missingPolicyIds: number;
  endpointsWithErrors: number;
  staleOrUnknownAcknowledgements: number;
  serverReportedErrors: number;
  aggregates: PolicyAggregateRow[];
  discrepancies: string[];
};

export function summarizePolicyEvidence(overview: LabSOCOverview): PolicyEvidenceSummary {
  const inventoryCountByPolicy = new Map<string, number>();
  let reportedPolicyIds = 0;
  let endpointsWithErrors = 0;
  let staleOrUnknownAcknowledgements = 0;
  for (const endpoint of overview.endpoints) {
    const id = endpoint.applied_policy_id.trim();
    if (id) {
      inventoryCountByPolicy.set(id, (inventoryCountByPolicy.get(id) || 0) + 1);
      reportedPolicyIds++;
      if (endpoint.status !== 'online') staleOrUnknownAcknowledgements++;
    }
    if (endpoint.last_policy_error.trim()) endpointsWithErrors++;
  }
  const seenPolicyIds = new Set<string>();
  const discrepancies: string[] = [];
  const aggregates: PolicyAggregateRow[] = overview.policy_coverage.map(item => {
    const policyId = item.policy_id.trim();
    const seenInInventory = inventoryCountByPolicy.get(policyId) || 0;
    const consistent = item.endpoints === seenInInventory && !seenPolicyIds.has(policyId) && !!policyId;
    if (!policyId || seenPolicyIds.has(policyId)) {
      discrepancies.push('Server policy summary contains an empty or duplicate policy ID.');
    } else if (!consistent) {
      discrepancies.push('Policy ' + policyId + ': server aggregate and endpoint records disagree.');
    }
    seenPolicyIds.add(policyId);
    return {
      policyId: item.policy_id,
      policyName: item.policy_name,
      reportedByServer: item.endpoints,
      seenInInventory,
      consistent,
    };
  });
  for (const policyId of inventoryCountByPolicy.keys()) {
    if (!seenPolicyIds.has(policyId)) {
      discrepancies.push('Policy ' + policyId + ': endpoint acknowledgement absent from policy summary.');
    }
  }
  return {
    total: overview.endpoints.length,
    reportedPolicyIds,
    missingPolicyIds: overview.endpoints.length - reportedPolicyIds,
    endpointsWithErrors,
    staleOrUnknownAcknowledgements,
    serverReportedErrors: overview.policy_errors,
    aggregates,
    discrepancies,
  };
}

/** Human-readable uncertainty: an applied-policy ID is NOT an enforcement attestation. */
export function policyEvidenceState(endpoint: EndpointActivity): string {
  const policy = endpoint.applied_policy_id.trim();
  if (endpoint.last_policy_error.trim()) return 'Policy error reported — enforcement NOT VERIFIED';
  if (!policy) return 'No applied-policy ID reported — coverage UNKNOWN';
  if (endpoint.status !== 'online') return 'Reported policy ID; stale/unknown heartbeat — enforcement NOT VERIFIED';
  return 'Reported policy ID — enforcement NOT VERIFIED';
}

/** Local-only policy evidence triage; never changes the server policy or scopes API data. */
export type PolicyEvidenceFilter = 'all' | 'attention' | 'offline_unknown' | 'reported_error' | 'missing_id';

export function filterPolicyEndpoints(
  endpoints: readonly EndpointActivity[],
  filter: PolicyEvidenceFilter,
  search: string,
): EndpointActivity[] {
  const query = search.trim().toLocaleLowerCase();
  const requiresAttention = (endpoint: EndpointActivity) =>
    !!endpoint.last_policy_error.trim() || !endpoint.applied_policy_id.trim() || endpoint.status !== 'online';
  const priority = (endpoint: EndpointActivity) =>
    endpoint.last_policy_error.trim() ? 0 :
    !endpoint.applied_policy_id.trim() ? 1 :
    endpoint.status !== 'online' ? 2 : 3;
  return endpoints.filter(endpoint => {
    const matchesFilter =
      filter === 'all' ||
      (filter === 'attention' && requiresAttention(endpoint)) ||
      (filter === 'offline_unknown' && endpoint.status !== 'online') ||
      (filter === 'reported_error' && !!endpoint.last_policy_error.trim()) ||
      (filter === 'missing_id' && !endpoint.applied_policy_id.trim());
    if (!matchesFilter) return false;
    if (!query) return true;
    return [endpoint.id, endpoint.platform, endpoint.group, endpoint.applied_policy_id,
      endpoint.last_policy_error].some(value => value.toLocaleLowerCase().includes(query));
  }).sort((a, b) => priority(a) - priority(b) || a.id.localeCompare(b.id));
}
