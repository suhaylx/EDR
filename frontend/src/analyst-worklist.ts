/** Agent 5 read-only analyst worklist controls.
 * These filters operate on already-decoded lab evidence, never backend policy.
 */
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import { primaryDetectionSource } from './multisignal-alert-triage.js';
import { locateRetainedSource } from './retained-source.js';

export type EvidencePresence = 'all' | 'present' | 'absent';
export type SamplePresence = 'all' | 'in_sample' | 'not_in_sample';
export type WorklistSort = 'newest' | 'oldest' | 'severity' | 'endpoint' | 'rule' | 'confidence';
export type PageSize = 25 | 50 | 100;
export type AnalystFilters = Readonly<{
  host: string;
  rule: string;
  category: string;
  confidence: string;
  processGuid: EvidencePresence;
  fileCreate: EvidencePresence;
  target: EvidencePresence;
  sample: SamplePresence;
}>;
export const EMPTY_ANALYST_FILTERS: AnalystFilters = {
  host: '', rule: '', category: '', confidence: '',
  processGuid: 'all', fileCreate: 'all', target: 'all', sample: 'all',
};

const exact = (reported: string, typed: string): boolean =>
  !typed.trim() || reported.trim().toLocaleLowerCase() === typed.trim().toLocaleLowerCase();
const matchesPresence = (value: boolean, filter: EvidencePresence): boolean =>
  filter === 'all' || (filter === 'present' && value) || (filter === 'absent' && !value);

export function sourcePresentInReturnedSample(
  detection: LabDetection, events: readonly LabTelemetryEvent[],
): boolean {
  const source = primaryDetectionSource(detection);
  return !!source && !!locateRetainedSource(events, source);
}

export function filterAnalystWorklist(
  detections: readonly LabDetection[], events: readonly LabTelemetryEvent[], filters: AnalystFilters,
): LabDetection[] {
  return detections.filter(detection => {
    if (!exact(detection.device_id, filters.host) ||
        !exact(detection.rule_id, filters.rule) ||
        !exact(detection.category, filters.category) ||
        !exact(detection.confidence, filters.confidence)) return false;
    if (!matchesPresence(!!detection.process_guid.trim(), filters.processGuid) ||
        !matchesPresence(!!detection.file_create_event_id.trim(), filters.fileCreate) ||
        !matchesPresence(!!(detection.target_object || detection.module_path).trim(), filters.target)) {
      return false;
    }
    if (filters.sample === 'all') return true;
    const present = sourcePresentInReturnedSample(detection, events);
    return filters.sample === 'in_sample' ? present : !present;
  });
}

const severityOrder: Record<string, number> = {critical: 0, high: 1, medium: 2, low: 3};
const confidenceOrder: Record<string, number> = {high: 0, medium: 1, low: 2};
const severityRank = (s: string): number => severityOrder[s.trim().toLocaleLowerCase()] ?? 4;
const confidenceRank = (s: string): number => confidenceOrder[s.trim().toLocaleLowerCase()] ?? 3;
const cmpText = (a: string,b: string): number => a.localeCompare(b, 'en', {sensitivity:'base'});
const newestFirst = (a: LabDetection,b: LabDetection) => Date.parse(b.observed_at) - Date.parse(a.observed_at);

export function sortAnalystWorklist(
  detections: readonly LabDetection[], sort: WorklistSort,
): LabDetection[] {
  return [...detections].sort((a,b) => {
    let primary = 0;
    switch (sort) {
      case 'newest': primary = newestFirst(a,b); break;
      case 'oldest': primary = -newestFirst(a,b); break;
      case 'severity': primary = severityRank(a.severity) - severityRank(b.severity); break;
      case 'endpoint': primary = cmpText(a.device_id,b.device_id); break;
      case 'rule': primary = cmpText(a.rule_id,b.rule_id); break;
      case 'confidence': primary = confidenceRank(a.confidence) - confidenceRank(b.confidence); break;
    }
    // Stable deterministic tie-break, independent of API array order.
    return primary || newestFirst(a,b) || cmpText(a.id,b.id);
  });
}

export type PageResult<T> = Readonly<{
  records: T[];
  total: number;
  page: number;
  pages: number;
  start: number;
  end: number;
}>;
export function paginateWorklist<T>(
  records: readonly T[], requestedPage: number, size: PageSize,
): PageResult<T> {
  if (![25,50,100].includes(size) || !Number.isSafeInteger(requestedPage)) {
    throw new Error('Invalid local worklist pagination controls');
  }
  const pages = Math.max(1, Math.ceil(records.length / size));
  const page = Math.max(0,Math.min(requestedPage,pages-1));
  const start = records.length === 0 ? 0 : page * size + 1;
  const end = Math.min(records.length,(page+1)*size);
  return {records:records.slice(page*size,(page+1)*size),total:records.length,
    page,pages,start,end};
}
