/** Read-only alert triage for retained lab detections, not incidents or confirmed infections. */
import type { LabDetection } from './detections.js';

export type AlertSeverityFilter = 'all' | 'critical_high' | 'medium' | 'low' | 'other';
export type AlertSourceFilter = 'all' | 'file_create_linked' | 'file_create_not_linked';
export type AlertSeverityBucket = 'critical' | 'high' | 'medium' | 'low' | 'other';

export function alertSeverityBucket(severity: string): AlertSeverityBucket {
  const value = severity.trim().toLocaleLowerCase();
  return value === 'critical' || value === 'high' || value === 'medium' || value === 'low'
    ? value : 'other';
}

export function summarizeRetainedAlerts(detections: readonly LabDetection[]) {
  const counts: Record<AlertSeverityBucket, number> = {
    critical: 0, high: 0, medium: 0, low: 0, other: 0,
  };
  for (const detection of detections) counts[alertSeverityBucket(detection.severity)]++;
  return counts;
}

/** All filters are local to records already accepted by detectionsInWindow(). */
export function filterRetainedAlerts(
  detections: readonly LabDetection[],
  severity: AlertSeverityFilter,
  source: AlertSourceFilter,
  search: string,
): LabDetection[] {
  const query = search.trim().toLocaleLowerCase();
  return detections.filter(detection => {
    const bucket = alertSeverityBucket(detection.severity);
    if (severity === 'critical_high' && bucket !== 'critical' && bucket !== 'high') return false;
    if (severity !== 'all' && severity !== 'critical_high' && bucket !== severity) return false;
    const linked = detection.file_create_event_id.trim() !== '';
    if (source === 'file_create_linked' && !linked) return false;
    if (source === 'file_create_not_linked' && linked) return false;
    if (!query) return true;
    return [
      detection.id, detection.rule_id, detection.category, detection.severity,
      detection.device_id, detection.process_guid, detection.process_image,
      detection.module_path, detection.load_event_id, detection.file_create_event_id,
    ].some(value => value.toLocaleLowerCase().includes(query));
  });
}
