/**
 * Read-only audit of references between retained lab detections and the current
 * at-most-100 Go event sample. A matched ID is NOT authenticated provenance,
 * a verified Sysmon policy, an incident, or evidence of event completeness.
 */
import type { LabDetection } from './detections.js';
import type { LabTelemetryEvent } from './telemetry.js';
import { primaryDetectionSource } from './multisignal-alert-triage.js';

export type PrimaryAuditState =
  'missing_reference'|'not_in_sample'|'untyped_source'|'type_unreported'|
  'type_conflict'|'reported_type_agrees';
export type FileAuditState =
  'no_link'|'same_primary_reference'|'not_in_sample'|'not_sysmon_11'|'reported_filecreate_11';
export type AuditFlag =
  'primary_reference_missing'|'primary_not_retained'|'primary_type_unreported'|
  'source_type_unreported'|'source_type_conflict'|'process_guid_conflict'|
  'no_process_guid'|'filecreate_not_retained'|'filecreate_type_conflict'|
  'filecreate_is_primary'|'future_source_receipt'|'source_receipt_unknown';
export const AUDIT_FLAG_LABELS:Readonly<Record<AuditFlag,string>> = {
  primary_reference_missing:'No primary Go event ID reported by the detection',
  primary_not_retained:'Primary Go event ID not present on the same endpoint in the returned sample',
  primary_type_unreported:'Detection did not report a numeric Sysmon event type',
  source_type_unreported:'Returned source does not report a numeric Windows Sysmon event type',
  source_type_conflict:'Claimed numeric event type conflicts with returned source event type',
  process_guid_conflict:'Both reported process GUIDs are present but disagree',
  no_process_guid:'Detection process GUID not reported; ancestry cannot be checked',
  filecreate_not_retained:'Separate FileCreate reference is not in the returned event sample',
  filecreate_type_conflict:'Separate FileCreate reference is not a reported Windows Sysmon Event 11',
  filecreate_is_primary:'FileCreate reference repeats the primary Go event ID, not independent evidence',
  future_source_receipt:'Go source receipt timestamp is later than overview generation time',
  source_receipt_unknown:'Go receipt timestamp absent; cannot compare against overview generation time',
};
export const PRIMARY_LABELS:Readonly<Record<PrimaryAuditState,string>> = {
  missing_reference:'Primary source ID not reported',
  not_in_sample:'Primary source not in returned sample',
  untyped_source:'Returned source type not established',
  type_unreported:'Detection Sysmon type not reported',
  type_conflict:'Reported numeric source types disagree',
  reported_type_agrees:'Reported Sysmon type agrees (not attested)',
};
export const FILE_LABELS:Readonly<Record<FileAuditState,string>> = {
  no_link:'No separate FileCreate source ID',
  same_primary_reference:'FileCreate ID repeats primary ID',
  not_in_sample:'Linked FileCreate source not in sample',
  not_sysmon_11:'Linked reference is not reported Sysmon Event 11',
  reported_filecreate_11:'Linked source reports Sysmon Event 11 (not attested)',
};
export type AuditRow = Readonly<{
  detectionID:string; deviceID:string; ruleID:string; severity:string;
  primaryID:string; expectedEventID:number; returnedEventID:number|null;
  primaryState:PrimaryAuditState; fileID:string; fileState:FileAuditState;
  processGUID:string; flags:readonly AuditFlag[];
  sourceAvailable:boolean; fileSourceAvailable:boolean;
}>;

export function indexRetainedEventSample(events:readonly LabTelemetryEvent[]) {
  const index = new Map<string,Map<string,LabTelemetryEvent>>();
  const ambiguous = new Map<string,Set<string>>();
  for(const event of events){
    let byID=index.get(event.device_id);
    if(!byID){byID=new Map();index.set(event.device_id,byID);}
    let excluded=ambiguous.get(event.device_id);
    if(!excluded){excluded=new Set();ambiguous.set(event.device_id,excluded);}
    // Never promote second, third, or later collisions to positive evidence.
    if(excluded.has(event.id))continue;
    if(byID.has(event.id)){byID.delete(event.id);excluded.add(event.id);}
    else byID.set(event.id,event);
  }
  return index;
}
function isReportedSysmon(event:LabTelemetryEvent|undefined,expected?:number) {
  return !!event && event.platform==='windows' && event.source==='sysmon' &&
    event.source_event_id>0 && (expected===undefined || event.source_event_id===expected);
}
function sourceFromIndex(index:ReturnType<typeof indexRetainedEventSample>,
  host:string,id:string):LabTelemetryEvent|undefined {
  return id ? index.get(host)?.get(id) : undefined;
}
/** Run once for the entire returned detection set; never fetch per row. */
export function auditDetectionSources(detections:readonly LabDetection[],
  events:readonly LabTelemetryEvent[],overviewGeneratedAt:string):AuditRow[] {
  const index=indexRetainedEventSample(events);
  const overviewMs=Date.parse(overviewGeneratedAt);
  return detections.map(d=>{
    const primaryID=primaryDetectionSource(d)?.eventID||'';
    const primary=sourceFromIndex(index,d.device_id,primaryID);
    const primaryState:PrimaryAuditState=!primaryID?'missing_reference':
      !primary?'not_in_sample':!isReportedSysmon(primary)?'untyped_source':
      d.evidence_source_event_id===0?'type_unreported':
      primary.source_event_id!==d.evidence_source_event_id?'type_conflict':'reported_type_agrees';
    const fileID=d.file_create_event_id.trim();
    const samePrimary=!!fileID && fileID===primaryID;
    const fileSource=!samePrimary?sourceFromIndex(index,d.device_id,fileID):undefined;
    const fileState:FileAuditState=!fileID?'no_link':samePrimary?'same_primary_reference':
      !fileSource?'not_in_sample':!isReportedSysmon(fileSource,11)?'not_sysmon_11':
      'reported_filecreate_11';
    const flags:AuditFlag[]=[];
    switch(primaryState){
      case 'missing_reference':flags.push('primary_reference_missing');break;
      case 'not_in_sample':flags.push('primary_not_retained');break;
      case 'untyped_source':flags.push('source_type_unreported');break;
      case 'type_unreported':flags.push('primary_type_unreported');break;
      case 'type_conflict':flags.push('source_type_conflict');break;
    }
    if(!d.process_guid.trim())flags.push('no_process_guid');
    else if(primary?.process_guid && primary.process_guid!==d.process_guid)
      flags.push('process_guid_conflict');
    if(fileState==='not_in_sample')flags.push('filecreate_not_retained');
    else if(fileState==='not_sysmon_11')flags.push('filecreate_type_conflict');
    else if(fileState==='same_primary_reference')flags.push('filecreate_is_primary');
    if(primary){
      const received=Date.parse(primary.received_at);
      if(!Number.isFinite(received))flags.push('source_receipt_unknown');
      else if(Number.isFinite(overviewMs) && received>overviewMs)
        flags.push('future_source_receipt');
    }
    return {
      detectionID:d.id,deviceID:d.device_id,ruleID:d.rule_id,severity:d.severity,
      primaryID,expectedEventID:d.evidence_source_event_id,
      returnedEventID:primary?.source_event_id??null,primaryState,
      fileID,fileState,processGUID:d.process_guid,flags,
      sourceAvailable:!!primary,fileSourceAvailable:!!fileSource,
    };
  });
}
export type AuditFilter = 'all'|'review'|'reported_agreement'|'missing_primary'|
  'type_conflict'|'guid_conflict'|'filecreate_issue'|'no_guid';
export type AuditSort = 'severity'|'endpoint'|'rule'|'source_status'|'issues';
export type AuditPageSize = 25|50|100;
export type AuditQuery = Readonly<{
  state:AuditFilter;severity:string;endpoint:string;query:string;sort:AuditSort;
}>;
export const DEFAULT_AUDIT_QUERY:AuditQuery={
  state:'review',severity:'all',endpoint:'',query:'',sort:'issues',
};
const severityRank=(s:string)=>({critical:0,high:1,medium:2,low:3} as Record<string,number>)[s.toLowerCase()]??4;
const primaryRank=(s:PrimaryAuditState)=>({
  type_conflict:0,missing_reference:1,not_in_sample:2,untyped_source:3,
  type_unreported:4,reported_type_agrees:5,
} as Record<PrimaryAuditState,number>)[s];
const cmp=(a:string,b:string)=>a.localeCompare(b,'en',{sensitivity:'base'});
export function filterAuditRows(rows:readonly AuditRow[],filter:AuditQuery):AuditRow[] {
  const endpoint=filter.endpoint.trim().toLocaleLowerCase();
  const query=filter.query.trim().toLocaleLowerCase();
  return rows.filter(r=>{
    const severity=r.severity.toLocaleLowerCase();
    const knownSeverity=['critical','high','medium','low'].includes(severity);
    if(filter.severity!=='all' &&
      (filter.severity==='other'?knownSeverity:severity!==filter.severity))return false;
    if(endpoint && r.deviceID.trim().toLocaleLowerCase()!==endpoint)return false;
    switch(filter.state){
      case 'review':if(r.flags.length===0)return false;break;
      case 'reported_agreement':if(r.primaryState!=='reported_type_agrees')return false;break;
      case 'missing_primary':if(r.primaryState!=='missing_reference'&&r.primaryState!=='not_in_sample')return false;break;
      case 'type_conflict':if(r.primaryState!=='type_conflict')return false;break;
      case 'guid_conflict':if(!r.flags.includes('process_guid_conflict'))return false;break;
      case 'filecreate_issue':if(!['same_primary_reference','not_in_sample','not_sysmon_11'].includes(r.fileState))return false;break;
      case 'no_guid':if(!r.flags.includes('no_process_guid'))return false;break;
    }
    return !query || [
      r.detectionID,r.deviceID,r.ruleID,r.primaryID,r.fileID,r.severity,
      r.processGUID,String(r.expectedEventID),String(r.returnedEventID??''),
    ].some(v=>v.toLocaleLowerCase().includes(query));
  }).sort((a,b)=>{
    let key=0;
    switch(filter.sort){
      case 'severity':key=severityRank(a.severity)-severityRank(b.severity);break;
      case 'endpoint':key=cmp(a.deviceID,b.deviceID);break;
      case 'rule':key=cmp(a.ruleID,b.ruleID);break;
      case 'source_status':key=primaryRank(a.primaryState)-primaryRank(b.primaryState);break;
      case 'issues':key=b.flags.length-a.flags.length;break;
    }
    return key||cmp(a.deviceID,b.deviceID)||cmp(a.detectionID,b.detectionID);
  });
}
export function summarizeAudit(rows:readonly AuditRow[]) {
  return {
    reviewedRecords:rows.length,
    reportedAgreement:rows.filter(r=>r.primaryState==='reported_type_agrees').length,
    primaryUnavailable:rows.filter(r=>['missing_reference','not_in_sample'].includes(r.primaryState)).length,
    typeConflict:rows.filter(r=>r.primaryState==='type_conflict').length,
    guidConflict:rows.filter(r=>r.flags.includes('process_guid_conflict')).length,
    filecreateIssue:rows.filter(r=>r.flags.some(f=>['filecreate_not_retained','filecreate_type_conflict','filecreate_is_primary'].includes(f))).length,
    missingGuid:rows.filter(r=>r.flags.includes('no_process_guid')).length,
    futureReceipt:rows.filter(r=>r.flags.includes('future_source_receipt')).length,
  };
}
export function pageAudit(rows:readonly AuditRow[],requested:number,size:AuditPageSize) {
  if(!Number.isSafeInteger(requested)||![25,50,100].includes(size))
    throw new Error('Invalid source audit paging');
  const pages=Math.max(1,Math.ceil(rows.length/size));
  const page=Math.min(Math.max(requested,0),pages-1);
  return {rows:rows.slice(page*size,(page+1)*size),page,pages,total:rows.length,
    start:rows.length?page*size+1:0,end:Math.min(rows.length,(page+1)*size)};
}
