/**
 * Agent 5: type-safe decoding for Agent 2's *operator mTLS* SOC endpoint inventory.
 * NOT the shared-token /api/overview lab endpoint. The browser uses the separate
 * same-origin operator mTLS listener; keys remain in the browser/OS certificate store.
 * All version/readiness fields are endpoint-reported, not attested protection.
 */
import { socIdentity, socTimestamp } from './soc-contract.js';
export type OperatorHealth = 'online' | 'degraded' | 'stale' | 'unseen' | 'revoked';
export type OperatorPlatform = 'windows' | 'linux';
export type OperatorEndpoint = Readonly<{
  agent_id: string;
  platform: OperatorPlatform;
  health: OperatorHealth;
  agent_version: string;
  clamav_version: string;
  signature_version: string;
  scan_ready: boolean;
  last_seen: string | null;
  heartbeat_count: number;
}>;
export type OperatorInventoryPage = Readonly<{
  items: OperatorEndpoint[];
  limit: number;
  offset: number;
}>;
export type OperatorEndpointStats = Readonly<{
  total: number;
  windows: number;
  linux: number;
  online: number;
  degraded: number;
  stale: number;
  unseen: number;
  revoked: number;
}>;
export type OperatorInventoryResult =
  | Readonly<{ state: 'ready'; page: OperatorInventoryPage }>
  | Readonly<{ state: 'unauthorized' | 'forbidden' | 'unavailable' | 'invalid_response' | 'http_error' }>;

const healthValues: readonly string[] = ['online', 'degraded', 'stale', 'unseen', 'revoked'];
const platforms: readonly string[] = ['windows', 'linux'];
const object = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === 'object' && !Array.isArray(x);
const record = (x: unknown, field: string): Record<string, unknown> => {
  if (!object(x)) throw new Error('Invalid operator SOC field: ' + field);
  return x;
};
const text = (x: unknown, field: string, max = 160): string => {
  if (typeof x !== 'string' || x.length > max || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff\ufffd]/u.test(x)) {
    throw new Error('Invalid operator SOC text field: ' + field);
  }
  return x;
};
const integer = (x: unknown, field: string): number => {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 0) {
    throw new Error('Invalid operator SOC count: ' + field);
  }
  return x;
};
const utc = (x: unknown): string | null => {
  if (x == null) return null;
  return socTimestamp(x);
};

export function decodeOperatorEndpoint(value: unknown): OperatorEndpoint {
  const e = record(value, 'endpoint');
  const agent_id = socIdentity(e.agent_id);
  const platform = text(e.platform, 'platform');
  const health = text(e.health, 'health');
  if (!platforms.includes(platform) || !healthValues.includes(health)) {
    throw new Error('Unsupported operator endpoint platform or health');
  }
  if (typeof e.scan_ready !== 'boolean') throw new Error('Invalid reported scan_ready');
  const last_seen = utc(e.last_seen);
  const heartbeat_count = integer(e.heartbeat_count, 'heartbeat_count');
  if ((health === 'online' && !e.scan_ready) || (health === 'degraded' && e.scan_ready) ||
      (health === 'unseen' && e.scan_ready)) throw new Error('Contradictory scanner health');
  if (health === 'unseen' && (last_seen !== null || heartbeat_count !== 0)) {
    throw new Error('Unseen endpoint conflicts with a reported heartbeat');
  }
  if (['online', 'degraded', 'stale'].includes(health) &&
      (last_seen === null || heartbeat_count === 0)) {
    throw new Error('Active/stale endpoint lacks a server heartbeat');
  }
  // Whitelist only the known non-secret fields. Never retain extra sender data.
  return {
    agent_id,
    platform: platform as OperatorPlatform,
    health: health as OperatorHealth,
    agent_version: text(e.agent_version ?? '', 'agent_version'),
    clamav_version: text(e.clamav_version ?? '', 'clamav_version'),
    signature_version: text(e.signature_version ?? '', 'signature_version'),
    scan_ready: e.scan_ready,
    last_seen,
    heartbeat_count,
  };
}

/** Exact Go GET /soc/v1/tenants/{tenant}/endpoints envelope (PR #150). */
export function decodeOperatorInventoryPage(value: unknown): OperatorInventoryPage {
  const o = record(value, 'page');
  const limit = integer(o.limit, 'limit');
  const offset = integer(o.offset, 'offset');
  if (limit < 1 || limit > 100 || offset > 10000 || !Array.isArray(o.items) || o.items.length > limit) {
    throw new Error('Invalid operator SOC inventory page bounds');
  }
  const items = o.items.map(decodeOperatorEndpoint);
  if (new Set(items.map(e => e.agent_id)).size !== items.length) {
    throw new Error('Duplicate operator SOC endpoint in page');
  }
  return { items, limit, offset };
}

/** Exact Go GET /soc/v1/tenants/{tenant}/endpoint-stats envelope (PR #150). */
export function decodeOperatorEndpointStats(value: unknown): OperatorEndpointStats {
  const o = record(value, 'stats');
  const keys = ['total', 'windows', 'linux', 'online', 'degraded', 'stale', 'unseen', 'revoked'] as const;
  const numbers = Object.fromEntries(keys.map(key => [key, integer(o[key], key)])) as unknown as OperatorEndpointStats;
  if (numbers.windows + numbers.linux !== numbers.total ||
      numbers.online + numbers.degraded + numbers.stale + numbers.unseen + numbers.revoked !== numbers.total) {
    throw new Error('Unreconciled operator SOC endpoint stats');
  }
  return numbers;
}

/** Maps HTTP outcomes without preserving stale endpoint records or server error bodies. */
export function interpretOperatorInventoryHTTP(status: number, body: unknown): OperatorInventoryResult {
  if (status === 401) return {state: 'unauthorized'};
  if (status === 403) return {state: 'forbidden'};
  if (status === 503) return {state: 'unavailable'};
  if (status !== 200) return {state: 'http_error'};
  try {
    return {state: 'ready', page: decodeOperatorInventoryPage(body)};
  } catch {
    return {state: 'invalid_response'};
  }
}

export function operatorHealthLabel(endpoint: OperatorEndpoint): string {
  switch (endpoint.health) {
    case 'online': return 'Recent server heartbeat; scanner readiness is self-reported, NOT verified protection';
    case 'degraded': return 'Recent heartbeat; scanner readiness reported unavailable, scan outcome unknown';
    case 'stale': return 'Server heartbeat is stale; current protection unknown';
    case 'unseen': return 'No server-received heartbeat recorded; current protection unknown';
    case 'revoked': return 'Enrollment revoked; never show this device as protected';
  }
}
