/** Exact Go event ID + endpoint match only. Windows EventRecordID is not a
 * globally unique alert reference; never use it as a fallback.
 */
import type { LabTelemetryEvent } from './telemetry.js';
import type { RetainedSourceSelection } from './multisignal-alert-triage.js';

export function locateRetainedSource(
  events: readonly LabTelemetryEvent[], selection: RetainedSourceSelection,
): LabTelemetryEvent | null {
  return events.find(event =>
    event.device_id === selection.deviceID && event.id === selection.eventID) ?? null;
}
