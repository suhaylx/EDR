/** Evidence-quality flags derived only from the returned lab response.
 * A missing value is an observability gap, never proof of a malicious or safe host.
 */
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import { sourcePresentInReturnedSample } from './analyst-worklist.js';

export type EvidenceGapSummary = Readonly<{
  returnedDetections: number;
  missingProcessGuid: number;
  unknownNumericEventType: number;
  noLinkedFileCreate: number;
  noTargetObject: number;
  primaryNotInEventSample: number;
  primaryInEventSample: number;
  withReportedSourceTime: number;
}>;

export function summarizeReturnedEvidenceGaps(
  detections: readonly LabDetection[], events: readonly LabTelemetryEvent[],
): EvidenceGapSummary {
  let missingProcessGuid=0, unknownNumericEventType=0, noLinkedFileCreate=0;
  let noTargetObject=0, primaryNotInEventSample=0, primaryInEventSample=0;
  let withReportedSourceTime=0;
  const byKey = new Map(events.map(e=>[e.device_id+'\u0000'+e.id,e]));
  for (const d of detections) {
    if (!d.process_guid.trim()) missingProcessGuid++;
    if (d.evidence_source_event_id === 0) unknownNumericEventType++;
    if (!d.file_create_event_id.trim()) noLinkedFileCreate++;
    if (!(d.target_object || d.module_path).trim()) noTargetObject++;
    // Same host AND Go event ID. No Windows EventRecordID or time fallback.
    const primaryID = d.evidence_event_id || d.load_event_id;
    const source = byKey.get(d.device_id+'\u0000'+primaryID);
    if (source && sourcePresentInReturnedSample(d,events)) {
      primaryInEventSample++;
      if (source.time) withReportedSourceTime++;
    } else primaryNotInEventSample++;
  }
  return {returnedDetections:detections.length,missingProcessGuid,
    unknownNumericEventType,noLinkedFileCreate,noTargetObject,
    primaryNotInEventSample,primaryInEventSample,withReportedSourceTime};
}

/** Co-observed events share a reported host and GUID, never inferred parentage. */
export function otherReportedProcessEvents(
  primary: LabTelemetryEvent, events: readonly LabTelemetryEvent[], limit=10,
): {events: LabTelemetryEvent[]; total: number} {
  if (!primary.process_guid.trim() || !Number.isSafeInteger(limit) || limit<1 || limit>100)
    return {events:[],total:0};
  const related=events.filter(event=>event.id!==primary.id &&
    event.device_id===primary.device_id && event.process_guid===primary.process_guid);
  related.sort((a,b)=>
    (Date.parse(b.received_at||b.time)||0)-(Date.parse(a.received_at||a.time)||0) ||
    a.id.localeCompare(b.id));
  return {events:related.slice(0,limit),total:related.length};
}
