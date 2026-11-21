/** Heuristic lab detections are investigation signals, not confirmed infections.
 * This module never performs responses, containment, or tenant authorization. */
import type { DayWindow } from './overview.js';
import type { InvestigationSeed } from './investigation.js';

export type LabDetection = {
  id: string;
  rule_id: string;
  category: string;
  severity: string;
  confidence: string;
  device_id: string;
  process_guid: string;
  process_image: string;
  module_path: string;
  load_event_id: string;
  evidence_event_id: string;
  target_object: string;
  evidence_source_event_id: number;
  file_create_event_id: string;
  observed_at: string;
  explanation: string;
};

type Rec = Record<string, unknown>;
function text(value: unknown, field: string, optional = false): string {
  if (optional && (value === undefined || value === null)) return '';
  if (typeof value !== 'string' || value.length > 8192) throw new Error('Invalid lab detection field: ' + field);
  return value;
}
function record(value: unknown, index: number): Rec {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid lab detection record ' + index);
  }
  return value as Rec;
}
const safeID = (value: string, max: number) => value.length > 0 && value.length <= max &&
  !/[\x00-\x1f\x7f]/.test(value);

export function decodeLabDetections(raw: unknown): LabDetection[] {
  if (!Array.isArray(raw) || raw.length > 5000) {
    throw new Error('Invalid lab detection response: expected at most 5,000 records.');
  }
  const seen = new Set<string>();
  return raw.map((value, index): LabDetection => {
    const d = record(value, index + 1);
    const item: LabDetection = {
      id: text(d.id, 'id'), rule_id: text(d.rule_id, 'rule_id'),
      category: text(d.category, 'category'), severity: text(d.severity, 'severity'),
      confidence: text(d.confidence, 'confidence'), device_id: text(d.device_id, 'device_id'),
      process_guid: text(d.process_guid, 'process_guid'),
      process_image: text(d.process_image, 'process_image'),
      module_path: text(d.module_path, 'module_path'),
      load_event_id: text(d.load_event_id, 'load_event_id', true),
      evidence_event_id: text(d.evidence_event_id, 'evidence_event_id', true),
      target_object: text(d.target_object, 'target_object', true),
      evidence_source_event_id: d.evidence_source_event_id === undefined || d.evidence_source_event_id === null ? 0 : Number(d.evidence_source_event_id),
      file_create_event_id: text(d.file_create_event_id, 'file_create_event_id', true),
      observed_at: text(d.observed_at, 'observed_at'),
      explanation: text(d.explanation, 'explanation'),
    };
    // Agent 1 behavioral signals may have no process GUID or DLL load.
    // Keep their real primary evidence ID, never fabricate a DLL observation.
    const primaryID = item.evidence_event_id || item.load_event_id;
    if (!safeID(item.id, 160) || !safeID(item.device_id, 96) ||
        (item.process_guid !== '' && !safeID(item.process_guid, 160)) ||
        !safeID(primaryID, 256) || item.target_object.length > 1024 ||
        !Number.isInteger(item.evidence_source_event_id) || item.evidence_source_event_id < 0 ||
        item.evidence_source_event_id > 255 ||
        (item.evidence_source_event_id !== 0 &&
          !((item.evidence_source_event_id >= 1 && item.evidence_source_event_id <= 29) || item.evidence_source_event_id === 255))) {
      throw new Error('Detection missing bounded endpoint, evidence source or valid Sysmon ID at record ' + (index + 1));
    }
    const time = Date.parse(item.observed_at);
    if (!Number.isFinite(time) || !/^\d{4}-\d\d-\d\dT/.test(item.observed_at)) {
      throw new Error('Invalid detection observation timestamp at record ' + (index + 1));
    }
    if (seen.has(item.id)) throw new Error('Duplicate lab detection ID in response.');
    seen.add(item.id);
    return item;
  });
}

/** Uses the overview's server-generated UTC timestamp, not the analyst's wall clock. */
export function detectionsInWindow(
  detections: readonly LabDetection[], generatedAt: string, days: DayWindow,
): LabDetection[] {
  const now = Date.parse(generatedAt);
  if (!Number.isFinite(now) || ![1, 7, 30].includes(days))
    throw new Error('Cannot determine the retained UTC detection window.');
  const start = now - days * 24 * 60 * 60 * 1000;
  return detections.filter(d => {
    const t = Date.parse(d.observed_at);
    return Number.isFinite(t) && t >= start && t <= now;
  }).sort((a, b) => b.observed_at.localeCompare(a.observed_at) || a.id.localeCompare(b.id));
}

export function seedForDetection(detection: LabDetection): InvestigationSeed {
  return {deviceID: detection.device_id, kind: 'detection', detectionID: detection.id};
}

export async function fetchLabDetections(
  token: string, signal?: AbortSignal, fetcher: typeof fetch = fetch,
): Promise<LabDetection[]> {
  if (token.length < 16) throw new Error('The development token must contain at least 16 characters.');
  const response = await fetcher('/api/detections', {
    method: 'GET',
    headers: {Authorization: 'Bearer ' + token},
    credentials: 'omit', cache: 'no-store', signal,
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Development token rejected (HTTP 401).');
    throw new Error('Lab detections API returned HTTP ' + response.status + '.');
  }
  return decodeLabDetections(await response.json() as unknown);
}
