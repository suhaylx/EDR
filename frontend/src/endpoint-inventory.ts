import type {EndpointActivity, HeartbeatStatus} from './overview.js';

export type InventoryFilter = 'all' | HeartbeatStatus;
export type InventorySort = 'id' | 'inactive' | 'events';

export function filterEndpointInventory(
  endpoints: readonly EndpointActivity[],
  status: InventoryFilter,
  search: string,
  sort: InventorySort,
): EndpointActivity[] {
  const needle = search.trim().toLocaleLowerCase();
  const filtered = endpoints.filter(endpoint =>
    (status === 'all' || endpoint.status === status) &&
    [endpoint.id,endpoint.platform,endpoint.group,endpoint.applied_policy_id].some(
      text => text.toLocaleLowerCase().includes(needle),
    ),
  );
  return [...filtered].sort((a,b) => {
    if (sort === 'inactive') {
      // Unknown heartbeat has no meaningful elapsed duration; never rank it as
      // a verified 0-second inactive device.
      if (a.status === 'unknown' && b.status !== 'unknown') return 1;
      if (b.status === 'unknown' && a.status !== 'unknown') return -1;
      if (a.inactive_seconds !== b.inactive_seconds) return b.inactive_seconds - a.inactive_seconds;
    }
    if (sort === 'events' && a.events !== b.events) return b.events - a.events;
    return a.id.localeCompare(b.id);
  });
}

export function policyEvidenceLabel(endpoint: EndpointActivity): string {
  // The shared-token lab inventory has no role-specific right to display
  // arbitrary endpoint error detail (paths, user names, scanner output, etc.).
  if (endpoint.last_policy_error.trim()) return 'Reported policy error (details withheld; enforcement not verified)';
  if (!endpoint.applied_policy_id) return 'No applied policy acknowledgment reported';
  return 'Agent-reported applied policy ' + endpoint.applied_policy_id +
    ' (revision ' + endpoint.applied_revision + '); enforcement NOT VERIFIED';
}
