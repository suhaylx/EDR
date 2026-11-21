/**
 * One-read-only-frontend-refresh overview of four independently fetched Go lab
 * endpoints. No atomic backend transaction, signed device origin, durable
 * retention, tenant authorization or Sysmon policy attestation is implied.
 */
import type { LabSOCOverview, DayWindow, HeartbeatStatus } from './overview.js';
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import type { LabScanJob } from './lab-api.js';
import { scanEvidenceKind } from './scan-evidence.js';
import { SYSMON_EVENT_NAMES } from './telemetry.js';

export type SourceClock = 'server_receipt' | 'sender_report' | 'unknown';
export type EvidenceEventTime = Readonly<{
  kind: SourceClock; timestamp: string; value: number | null;
}>;
export type EvidenceEndpointRow = Readonly<{
  id: string;
  platform: string;
  heartbeat: HeartbeatStatus;
  eventsInWindow: number;
  detectionsInWindow: number;
  scanJobsReturned: number;
  observedSysmonTypes: number;
}>;
export type EvidenceSnapshot = Readonly<{
  generatedAt: string;
  days: DayWindow;
  serverReported: Readonly<{events: number; alerts: number; agents: number}>;
  returned: Readonly<{
    detections: number;
    detectionsInWindow: number;
    detectionsOutsideWindow: number;
    events: number;
    eventsInWindow: number;
    eventsOutsideWindow: number;
    eventsUnknownTime: number;
    eventsUsingSenderClock: number;
    eventsUsingServerClock: number;
    scanJobs: number;
    unsupportedScanClaims: number;
    signatureNegative: number;
    unscanned: number;
    unknownScanState: number;
    windowsSysmonEventsInWindow: number;
    linuxEventsInWindow: number;
    otherEventsInWindow: number;
    eventsAfterOverview: number;
    detectionsAfterOverview: number;
    eventsNotInInventory: number;
    detectionsNotInInventory: number;
    scanJobsNotInInventory: number;
  }>;
  endpointRows: EvidenceEndpointRow[];
  sysmonTypes: ReadonlyArray<Readonly<{id:number; label:string; count:number}>>;
  eventSampleAtLimit: boolean;
  warnings: string[];
}>;

const ms = (value: string | undefined): number | null => {
  if (!value) return null;
  const parsed=Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
};
/** Prefer Go receipt time. Missing receipt is NOT a received heartbeat. */
export function evidenceEventTime(event:LabTelemetryEvent):EvidenceEventTime {
  const received=ms(event.received_at);
  if(received!==null) return {kind:'server_receipt',timestamp:event.received_at,value:received};
  const sender=ms(event.time);
  if(sender!==null) return {kind:'sender_report',timestamp:event.time,value:sender};
  return {kind:'unknown',timestamp:'',value:null};
}
/** Use an inclusive, server-reported UTC duration, never the browser clock. */
export function isInOverviewWindow(timestamp:number|null,generated:number,days:DayWindow):boolean {
  if(!Number.isFinite(generated)||![1,7,30].includes(days))return false;
  return timestamp!==null && Number.isFinite(timestamp) &&
    timestamp>=generated-days*24*60*60*1000 && timestamp<=generated;
}
const isSysmon=(e:LabTelemetryEvent):boolean=>
  e.platform==='windows' && e.source==='sysmon' &&
  Object.hasOwn(SYSMON_EVENT_NAMES,e.source_event_id);
const isLinux=(e:LabTelemetryEvent):boolean=>e.platform==='linux';
/** Returns count-only rollups; never copies event detail/clipboard into state. */
export function reviewEvidenceSnapshot(
  overview:LabSOCOverview,
  detections:readonly LabDetection[],
  events:readonly LabTelemetryEvent[],
  jobs:readonly LabScanJob[],
):EvidenceSnapshot {
  if(!Array.isArray(detections)||!Array.isArray(events)||!Array.isArray(jobs))
    throw new Error('All four decoded lab responses are required for evidence review.');
  const generated=ms(overview.generated_at);
  if(generated===null||![1,7,30].includes(overview.window_days))
    throw new Error('A valid server-reported UTC window is required for evidence review.');
  const known=new Set(overview.endpoints.map(e=>e.id));
  const perHost=new Map<string,{events:number;detections:number;scans:number;types:Set<number>}>();
  for(const endpoint of overview.endpoints)
    perHost.set(endpoint.id,{events:0,detections:0,scans:0,types:new Set()});

  let detectionsInWindow=0,detectionsAfterOverview=0,detectionsNotInInventory=0;
  for(const detection of detections){
    const t=ms(detection.observed_at);
    if(t!==null&&t>generated)detectionsAfterOverview++;
    if(!known.has(detection.device_id))detectionsNotInInventory++;
    if(isInOverviewWindow(t,generated,overview.window_days)){
      detectionsInWindow++;
      const row=perHost.get(detection.device_id);if(row)row.detections++;
    }
  }
  let eventsInWindow=0,eventsUnknownTime=0,eventsUsingSenderClock=0;
  let eventsUsingServerClock=0,windowsSysmonEventsInWindow=0;
  let linuxEventsInWindow=0,otherEventsInWindow=0;
  let eventsAfterOverview=0,eventsNotInInventory=0;
  const types=new Map<number,number>();
  for(const event of events){
    const time=evidenceEventTime(event);
    if(time.kind==='unknown')eventsUnknownTime++;
    if(time.kind==='sender_report')eventsUsingSenderClock++;
    if(time.kind==='server_receipt')eventsUsingServerClock++;
    if(time.value!==null&&time.value>generated)eventsAfterOverview++;
    if(!known.has(event.device_id))eventsNotInInventory++;
    if(!isInOverviewWindow(time.value,generated,overview.window_days))continue;
    eventsInWindow++;
    const row=perHost.get(event.device_id);if(row)row.events++;
    if(isSysmon(event)){
      windowsSysmonEventsInWindow++;
      types.set(event.source_event_id,(types.get(event.source_event_id)||0)+1);
      if(row)row.types.add(event.source_event_id);
    }else if(isLinux(event))linuxEventsInWindow++;
    else otherEventsInWindow++;
  }
  let scanJobsNotInInventory=0,unsupportedScanClaims=0;
  let signatureNegative=0,unscanned=0,unknownScanState=0;
  for(const job of jobs){
    if(!known.has(job.agent_id))scanJobsNotInInventory++;
    const row=perHost.get(job.agent_id);if(row)row.scans++;
    const kind=scanEvidenceKind(job);
    if(kind==='unsupported_claim')unsupportedScanClaims++;
    if(kind==='signature_negative')signatureNegative++;
    if(kind==='unscanned')unscanned++;
    if(kind==='unverified_completion'||kind==='unknown_state')unknownScanState++;
  }
  const endpointRows:EvidenceEndpointRow[]=overview.endpoints.map(endpoint=>{
    const r=perHost.get(endpoint.id);
    return {id:endpoint.id,platform:endpoint.platform,heartbeat:endpoint.status,
      eventsInWindow:r?.events||0,detectionsInWindow:r?.detections||0,
      scanJobsReturned:r?.scans||0,observedSysmonTypes:r?.types.size||0};
  });
  const warnings:string[]=[
    'Four read-only API responses are not an atomic server snapshot; discrepancies are not proof of dropped telemetry.',
    'Overview totals and returned event/detection samples have different bounds. Count equality is not verified collection.',
    'Reported heartbeat, scan job and event metadata do not attest endpoint protection, policy enforcement or scanner authenticity.',
  ];
  if(events.length===100)warnings.push('Event API sample reached 100 records; older matching evidence may be absent.');
  if(events.length===0)warnings.push('No event records returned; monitoring coverage remains unknown.');
  if(eventsUnknownTime)warnings.push('Some event records have no usable reported timestamp.');
  if(eventsUsingSenderClock)warnings.push('Some event time filters use sender-reported time because Go receipt time is unavailable.');
  if(eventsAfterOverview||detectionsAfterOverview)
    warnings.push('Some reported timestamps are later than overview generation; API collection time and clocks are not synchronized.');
  if(eventsNotInInventory||detectionsNotInInventory||scanJobsNotInInventory)
    warnings.push('Some records refer to endpoints not listed in this overview inventory; not an authenticated cross-tenant finding.');
  if(unsupportedScanClaims)
    warnings.push('Current lab Rust worker does not support claimed successful quick/full scan modes.');
  return {
    generatedAt:overview.generated_at,days:overview.window_days,
    serverReported:{events:overview.events,alerts:overview.alerts,agents:overview.agents},
    returned:{
      detections:detections.length,detectionsInWindow,
      detectionsOutsideWindow:detections.length-detectionsInWindow,
      events:events.length,eventsInWindow,eventsOutsideWindow:events.length-eventsInWindow-eventsUnknownTime,
      eventsUnknownTime,eventsUsingSenderClock,eventsUsingServerClock,
      scanJobs:jobs.length,unsupportedScanClaims,signatureNegative,unscanned,unknownScanState,
      windowsSysmonEventsInWindow,linuxEventsInWindow,otherEventsInWindow,
      eventsAfterOverview,detectionsAfterOverview,eventsNotInInventory,
      detectionsNotInInventory,scanJobsNotInInventory,
    },endpointRows,sysmonTypes:[...types].sort((a,b)=>a[0]-b[0]).map(([id,count])=>
      ({id,label:SYSMON_EVENT_NAMES[id]||'Unclassified',count})),
    eventSampleAtLimit:events.length===100,warnings,
  };
}
export type SnapshotSort='id'|'alerts'|'events'|'scans'|'heartbeat';
export type SnapshotStatus='all'|'online'|'offline'|'unknown';
export type SnapshotPageSize=25|50|100;
export type SnapshotFilters=Readonly<{search:string;status:SnapshotStatus;sort:SnapshotSort}>;
export const DEFAULT_SNAPSHOT_FILTERS:SnapshotFilters={search:'',status:'all',sort:'id'};
const statusRank=(s:HeartbeatStatus)=>s==='unknown'?0:s==='offline'?1:2;
export function filterSnapshotEndpoints(rows:readonly EvidenceEndpointRow[],filter:SnapshotFilters):EvidenceEndpointRow[]{
  const q=filter.search.trim().toLocaleLowerCase();
  return rows.filter(r=>(filter.status==='all'||r.heartbeat===filter.status) &&
    (!q||[r.id,r.platform].some(v=>v.toLocaleLowerCase().includes(q))))
    .sort((a,b)=>{
      let primary=0;
      switch(filter.sort){
        case 'alerts':primary=b.detectionsInWindow-a.detectionsInWindow;break;
        case 'events':primary=b.eventsInWindow-a.eventsInWindow;break;
        case 'scans':primary=b.scanJobsReturned-a.scanJobsReturned;break;
        case 'heartbeat':primary=statusRank(a.heartbeat)-statusRank(b.heartbeat);break;
      }
      return primary||a.id.localeCompare(b.id,'en',{sensitivity:'base'});
    });
}
export function pageSnapshotEndpoints(rows:readonly EvidenceEndpointRow[],requested:number,size:SnapshotPageSize){
  if(!Number.isSafeInteger(requested)||![25,50,100].includes(size))
    throw new Error('Invalid snapshot review page');
  const pages=Math.max(1,Math.ceil(rows.length/size));
  const page=Math.max(0,Math.min(requested,pages-1));
  return {rows:rows.slice(page*size,(page+1)*size),page,pages,total:rows.length,
    start:rows.length?page*size+1:0,end:Math.min(rows.length,(page+1)*size)};
}
