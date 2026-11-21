/** Read-only triage of the already returned multisignal lab detections.
 * No assumptions about installed Sysmon rules, true severity or a complete event feed.
 */
import type { LabDetection } from './detections.js';

export type SeverityFilter = 'all' | 'critical_high' | 'medium' | 'low' | 'other';
export type SourceFilter = 'all' | 'with_event_type' | 'unknown_event_type';
export type SeverityBucket = 'critical' | 'high' | 'medium' | 'low' | 'other';
export type RetainedSourceSelection = Readonly<{deviceID: string; eventID: string}>;

export function severityBucket(value: string): SeverityBucket {
  const normalized = value.trim().toLowerCase();
  return normalized === 'critical' || normalized === 'high' ||
    normalized === 'medium' || normalized === 'low' ? normalized : 'other';
}

export function retainedAlertCounts(detections: readonly LabDetection[]): Record<SeverityBucket, number> {
  const result = {critical: 0, high: 0, medium: 0, low: 0, other: 0};
  for (const detection of detections) result[severityBucket(detection.severity)]++;
  return result;
}

/** Source is Go's retained event ID, not a Sysmon EventRecordID or DLL-load assertion. */
export function primaryDetectionSource(detection: LabDetection): RetainedSourceSelection | null {
  const eventID = detection.evidence_event_id || detection.load_event_id;
  return eventID ? {deviceID: detection.device_id, eventID} : null;
}

export function filteredRetainedAlerts(
  detections: readonly LabDetection[],
  severity: SeverityFilter,
  source: SourceFilter,
  query: string,
): LabDetection[] {
  const term = query.trim().toLocaleLowerCase();
  return detections.filter(detection => {
    const bucket = severityBucket(detection.severity);
    if (severity === 'critical_high' && bucket !== 'critical' && bucket !== 'high') return false;
    if (severity !== 'all' && severity !== 'critical_high' && bucket !== severity) return false;
    const typed = detection.evidence_source_event_id > 0;
    if (source === 'with_event_type' && !typed) return false;
    if (source === 'unknown_event_type' && typed) return false;
    return !term || [
      detection.id, detection.device_id, detection.rule_id, detection.category,
      detection.severity, detection.process_guid, detection.process_image,
      detection.target_object, detection.module_path, detection.evidence_event_id,
      detection.load_event_id, detection.file_create_event_id,
      String(detection.evidence_source_event_id),
    ].some(field => field.toLocaleLowerCase().includes(term));
  });
}
