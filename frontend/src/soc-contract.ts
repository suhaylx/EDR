/** Bounded decoders for the certificate-authenticated SOC API. */
export function socRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid SOC object');
  return value as Record<string, unknown>;
}

export function socText(value: unknown, max: number, allowEmpty = true): string {
  if (typeof value !== 'string' || value.length > max || (!allowEmpty && !value.trim()) ||
      /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff\ufffd]/u.test(value)) {
    throw new Error('Invalid SOC text');
  }
  return value;
}

export function socIdentity(value: unknown): string {
  const id = socText(value, 96, false);
  if (!/^[A-Za-z0-9_.-]+$/.test(id) || id === '.' || id === '..') throw new Error('Invalid SOC identity');
  return id;
}

export function socUUID(value: unknown): string {
  const id = socText(value, 36, false);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error('Invalid SOC reference');
  }
  return id.toLowerCase();
}

export function socCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('Invalid SOC count');
  return value;
}

/** Require an explicit RFC3339 timezone and reject normalized invalid dates. */
export function socTimestamp(value: unknown): string {
  const text = socText(value, 64, false);
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(text);
  if (!parts) throw new Error('Invalid SOC timestamp');
  const [year, month, day, hour, minute, second] = parts.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(0, 0, 0, 0);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day ||
      hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(text))) {
    throw new Error('Invalid SOC timestamp');
  }
  return text;
}

export type SOCPage<T> = Readonly<{ items: T[]; limit: number; offset: number }>;

export function socPage<T>(value: unknown, decode: (entry: unknown) => T, key: (entry: T) => string): SOCPage<T> {
  const page = socRecord(value);
  const limit = socCount(page.limit);
  const offset = socCount(page.offset);
  if (limit < 1 || limit > 100 || offset > 10000 || !Array.isArray(page.items) || page.items.length > limit) {
    throw new Error('Invalid SOC page');
  }
  const items = page.items.map(decode);
  if (new Set(items.map(key)).size !== items.length) throw new Error('Duplicate SOC reference');
  return { items, limit, offset };
}
