/** TuranSec lab telemetry browser contract.
 * Counts reflect only the last 100 Go API records, not installed Sysmon
 * rules, actual event loss, complete endpoint activity or verified origin.
 */
export type LabTelemetryEvent = {
  id: string; device_id: string; platform: string; source: string;
  type: string; time: string; received_at: string; time_origin: string;
  source_event_id: number; source_record_id: string; process_guid: string;
  parent_process_guid: string; image: string; file_path: string; detail: string;
  source_fields: Record<string, string>;
};

export const SYSMON_EVENT_NAMES: Readonly<Record<number, string>> = Object.freeze({
  1:'Process create', 2:'File creation time', 3:'Network connection',
  4:'Service state change', 5:'Process terminate', 6:'Driver load',
  7:'DLL / image load', 8:'Remote thread', 9:'Raw disk access',
  10:'Process access', 11:'File created', 12:'Registry object',
  13:'Registry value changed', 14:'Registry renamed', 15:'File stream hash',
  16:'Configuration changed', 17:'Pipe created', 18:'Pipe connected',
  19:'WMI filter', 20:'WMI consumer', 21:'WMI binding',
  22:'DNS query', 23:'File delete (archive)', 24:'Clipboard change (metadata)',
  25:'Process tampering', 26:'File delete detected',
  27:'Executable blocked', 28:'Shredding blocked', 29:'Executable detected',
  255:'Sysmon error',
});

const fieldNames = new Set([
  'rule_name','destination_ip','destination_port','source_ip','source_port',
  'protocol','query_name','target_object','pipe_name','source_image',
  'target_image','source_process_guid','target_process_guid','image_loaded',
  'operation','event_type','query_status','target_filename','initiated',
]);

type Rec = Record<string, unknown>;
function record(value: unknown, label: string): Rec {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid lab telemetry ' + label);
  }
  return value as Rec;
}
function bounded(value: unknown, name: string, max = 1024, fallback = ''): string {
  if (value === null || value === undefined) return fallback;
  if (typeof value !== 'string' || value.length > max || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value))
    throw new Error('Invalid lab telemetry field ' + name);
  return value;
}
function timestamp(value: unknown, name: string): string {
  const val = bounded(value, name, 64);
  if (val && (!/^\d{4}-\d\d-\d\dT/.test(val) || !Number.isFinite(Date.parse(val)))) {
    throw new Error('Invalid lab telemetry timestamp ' + name);
  }
  return val;
}
export function decodeLabTelemetry(raw: unknown): LabTelemetryEvent[] {
  if (!Array.isArray(raw) || raw.length > 100) {
    throw new Error('Invalid lab telemetry response: max 100 retained API records.');
  }
  const ids = new Set<string>();
  return raw.map((value,index) => {
    const v=record(value,'record '+index);
    const id=bounded(v.id,'id',128);
    const deviceID=bounded(v.device_id,'device_id',96);
    const source=bounded(v.source,'source',128);
    const platform=bounded(v.platform,'platform',32);
    if (!id || !deviceID || !['windows','linux'].includes(platform) || ids.has(id))
      throw new Error('Invalid or duplicated telemetry event identity');
    ids.add(id);
    const sourceEventID=v.source_event_id === undefined || v.source_event_id === null ? 0 : v.source_event_id;
    if (!Number.isInteger(sourceEventID) || typeof sourceEventID !== 'number' || sourceEventID < 0 || sourceEventID > 255)
      throw new Error('Invalid Sysmon numeric Event ID');
    if (sourceEventID !== 0 && (!(sourceEventID in SYSMON_EVENT_NAMES) || source !== 'sysmon' || platform !== 'windows'))
      throw new Error('Inconsistent Sysmon source event ID');
    const fieldsValue = v.source_fields ?? {};
    const fields=record(fieldsValue,'source_fields');
    if (Object.keys(fields).length > 19) throw new Error('Too many Sysmon source fields');
    const sourceFields:Record<string,string>={};
    for (const [key,val] of Object.entries(fields)) {
      if (!fieldNames.has(key) || sourceEventID===0 || sourceEventID===24)
        throw new Error('Private or unverified Sysmon field rejected');
      sourceFields[key]=bounded(val,'source_fields.'+key,512);
    }
    const guid=bounded(v.process_guid,'process_guid',128);
    const parent=bounded(v.parent_process_guid,'parent_process_guid',128);
    if (sourceEventID === 24 && (guid || parent || v.image || v.file_path))
      throw new Error('Clipboard event payload must remain metadata only');
    if (sourceEventID > 0 && sourceEventID !== 1 && parent)
      throw new Error('Only Sysmon Event ID 1 can report creation parentage');
    return {
      id, device_id:deviceID, platform, source,
      type:bounded(v.type,'type',80),
      time:timestamp(v.time,'time'), received_at:timestamp(v.received_at,'received_at'),
      time_origin:bounded(v.time_origin,'time_origin',64),
      source_event_id:sourceEventID,
      source_record_id:bounded(v.source_record_id,'source_record_id',256),
      process_guid:guid, parent_process_guid:parent,
      image:bounded(v.image,'image',1024),
      file_path:bounded(v.file_path,'file_path',1024),
      detail:bounded(v.detail,'detail',4096),
      source_fields:sourceFields,
    };
  });
}

export function observedSysmonCounts(events:readonly LabTelemetryEvent[]): Map<number,number> {
  const counts=new Map<number,number>();
  for (const e of events) {
    if (e.source !== 'sysmon' || !SYSMON_EVENT_NAMES[e.source_event_id]) continue;
    counts.set(e.source_event_id,(counts.get(e.source_event_id) ?? 0)+1);
  }
  return counts;
}

export async function fetchLabTelemetry(
  token:string, signal?:AbortSignal, fetcher:typeof fetch=fetch,
):Promise<LabTelemetryEvent[]> {
  if (token.length < 16) throw new Error('A development token of at least 16 characters is required.');
  const response=await fetcher('/api/events',{
    method:'GET',headers:{Authorization:'Bearer '+token},
    credentials:'omit',cache:'no-store',signal,
  });
  if (!response.ok) {
    if (response.status===401) throw new Error('Development token rejected (HTTP 401).');
    throw new Error('Lab telemetry API returned HTTP '+response.status+'.');
  }
  return decodeLabTelemetry(await response.json() as unknown);
}
