/**
 * Read-only scan-adjacent lab workbench. "Same host" and "nearby time"
 * never imply a scan caused an event, malware verdict, or device protection.
 * All records are from the already fetched, untrusted development responses.
 */
import type { LabScanJob } from './lab-api.js';
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import { SYSMON_EVENT_NAMES } from './telemetry.js';
import { SCAN_KIND_LABELS, scanEvidenceKind, scanEvidenceFlags } from './scan-evidence.js';

export type ContextWindow = 'all'|'1h'|'24h'|'7d';
export type ContextSource = 'all'|'scan'|'detection'|'event';
export type ContextSort = 'newest'|'oldest';
export type ContextPageSize = 25|50|100;
export type ContextTimeBasis = 'server_created'|'server_received'|'sender_reported'|'detection_reported'|'unknown';
export type ContextEntry = Readonly<{
  key: string;
  refID: string;
  deviceID: string;
  kind: 'scan'|'detection'|'event';
  heading: string;
  secondary: string;
  observedAt: string;
  timeMs: number|null;
  timeBasis: ContextTimeBasis;
  processGUID: string;
  sourceEventID: number|null;
  futureOfServer: boolean;
}>;
export type ContextOptions = Readonly<{
  window: ContextWindow;
  source: ContextSource;
  sort: ContextSort;
  search: string;
}>;
export const DEFAULT_CONTEXT_OPTIONS:ContextOptions={
  window:'all',source:'all',sort:'newest',search:'',
};
const windowMs:Readonly<Record<Exclude<ContextWindow,'all'>,number>>={
  '1h':60*60*1000,'24h':24*60*60*1000,'7d':7*24*60*60*1000,
};
const validTime=(timestamp:string|undefined):number|null=>{
  if(!timestamp)return null;
  const n=Date.parse(timestamp);
  return Number.isFinite(n)?n:null;
};
const makeEntry=(data:Omit<ContextEntry,'futureOfServer'>,serverTime:number|null):ContextEntry=>({
  ...data,
  futureOfServer:data.timeMs!==null && serverTime!==null && data.timeMs>serverTime,
});
export function scanContextAnchor(job:LabScanJob):number|null {
  return validTime(job.created_at);
}
export function sameReportedEndpoint(a:string,b:string):boolean {
  // Device IDs are opaque identity keys. No case-folding or partial matching.
  return !!a && !!b && a===b;
}
export function eventClock(event:LabTelemetryEvent):{
  time:string;basis:ContextTimeBasis;ms:number|null;
} {
  if(event.received_at){
    return {time:event.received_at,basis:'server_received',ms:validTime(event.received_at)};
  }
  if(event.time){
    return {time:event.time,basis:'sender_reported',ms:validTime(event.time)};
  }
  return {time:'',basis:'unknown',ms:null};
}
export function eventEvidenceHeading(event:LabTelemetryEvent):string {
  return event.source==='sysmon' && event.platform==='windows' &&
    event.source_event_id>0
    ? 'Sysmon ID '+event.source_event_id+' — '+
      (SYSMON_EVENT_NAMES[event.source_event_id]||'Unclassified')
    : 'Other reported event — '+(event.type||'unclassified');
}

/** 24 is clipboard-change metadata: no clipboard body, source_fields or detail. */
export function eventEvidenceDescription(event:LabTelemetryEvent):string {
  if(event.source==='sysmon' && event.source_event_id===24)
    return 'Clipboard-change metadata only; content withheld';
  return 'Go event ID '+event.id+
    '; process GUID '+(event.process_guid||'not reported')+
    '; source RecordID '+(event.source_record_id||'not reported')+
    ' (display only, not lookup identity)';
}
export function buildScanContext(
  selected:LabScanJob, jobs:readonly LabScanJob[],
  detections:readonly LabDetection[], events:readonly LabTelemetryEvent[],
  generatedAt:string,
):{entries:ContextEntry[];counts:Readonly<{scans:number;detections:number;events:number}>;
  anchor:number|null;serverTime:number|null;hasFuture:boolean} {
  const anchor=scanContextAnchor(selected);
  const serverTime=validTime(generatedAt);
  const output:ContextEntry[]=[];
  let scans=0,observations=0,telemetry=0;
  for(const job of jobs) {
    if(!sameReportedEndpoint(job.agent_id,selected.agent_id)||job.id===selected.id)continue;
    scans++;
    const timeMs=validTime(job.created_at);
    output.push(makeEntry({
      key:'scan:'+job.id,refID:job.id,deviceID:job.agent_id,kind:'scan',
      heading:'Other reported scan job — '+SCAN_KIND_LABELS[scanEvidenceKind(job)],
      secondary:'Job ID '+job.id+'; scan mode '+(job.scan_type||'unknown')+
        '; metadata warnings '+scanEvidenceFlags(job).length,
      observedAt:job.created_at||'',timeMs,
      timeBasis:timeMs===null?'unknown':'server_created',
      processGUID:'',sourceEventID:null,
    },serverTime));
  }
  for(const detection of detections) {
    if(!sameReportedEndpoint(detection.device_id,selected.agent_id))continue;
    observations++;
    const timeMs=validTime(detection.observed_at);
    output.push(makeEntry({
      key:'detection:'+detection.id,refID:detection.id,deviceID:detection.device_id,
      kind:'detection',heading:'Reported alert — '+detection.rule_id,
      secondary:'Severity '+detection.severity+'; confidence '+detection.confidence+
        '; primary Go event '+(detection.evidence_event_id||detection.load_event_id||'not reported')+
        '; FileCreate link '+(detection.file_create_event_id||'not reported'),
      observedAt:detection.observed_at,timeMs,timeBasis:'detection_reported',
      processGUID:detection.process_guid,sourceEventID:detection.evidence_source_event_id||null,
    },serverTime));
  }
  for(const event of events) {
    if(!sameReportedEndpoint(event.device_id,selected.agent_id))continue;
    telemetry++;
    const clock=eventClock(event);
    output.push(makeEntry({
      key:'event:'+event.id,refID:event.id,deviceID:event.device_id,
      kind:'event',heading:eventEvidenceHeading(event),
      secondary:eventEvidenceDescription(event),
      observedAt:clock.time,timeMs:clock.ms,timeBasis:clock.basis,
      processGUID:event.process_guid,sourceEventID:event.source_event_id||null,
    },serverTime));
  }
  return {entries:output,counts:{scans,detections:observations,events:telemetry},
    anchor,serverTime,hasFuture:output.some(x=>x.futureOfServer) ||
      (anchor!==null && serverTime!==null && anchor>serverTime)};
}
export function filterScanContext(
  entries:readonly ContextEntry[],anchor:number|null,options:ContextOptions,
):ContextEntry[] {
  const query=options.search.trim().toLocaleLowerCase();
  return entries.filter(entry=>{
    if(options.source!=='all' && entry.kind!==options.source)return false;
    if(options.window!=='all'){
      if(anchor===null||entry.timeMs===null) return false;
      if(Math.abs(entry.timeMs-anchor)>windowMs[options.window])return false;
    }
    return !query || [
      entry.refID,entry.deviceID,entry.heading,entry.secondary,
      entry.processGUID,String(entry.sourceEventID??''),
    ].some(value=>value.toLocaleLowerCase().includes(query));
  }).sort((a,b)=>{
    // Missing timestamps must never silently become the newest evidence.
    const missingA=a.timeMs===null,missingB=b.timeMs===null;
    if(missingA!==missingB)return missingA?1:-1;
    const c=missingA?0:options.sort==='newest'
      ? (b.timeMs as number)-(a.timeMs as number)
      : (a.timeMs as number)-(b.timeMs as number);
    return c||a.key.localeCompare(b.key);
  });
}
export function pageScanContext(
  entries:readonly ContextEntry[],requestedPage:number,size:ContextPageSize,
) {
  if(!Number.isSafeInteger(requestedPage)||![25,50,100].includes(size))
    throw new Error('Invalid local scan context page');
  const pages=Math.max(1,Math.ceil(entries.length/size));
  const page=Math.min(Math.max(requestedPage,0),pages-1);
  return {rows:entries.slice(page*size,(page+1)*size),page,pages,total:entries.length,
    start:entries.length?1+page*size:0,end:Math.min(entries.length,(page+1)*size)};
}
