/** The Go lab investigation response is retained, untrusted EVIDENCE.
 * No parent relationship, edge or finding proves causality or compromise. */
export type InvestigationNode = {
  id: string;
  kind: 'process' | 'event' | 'file' | 'detection';
  status: 'observed' | 'referenced';
  label: string;
  device_id: string;
  process_guid: string;
  event_id: string;
  event_type: string;
  file_path: string;
  image: string;
  detail: string;
  severity: string;
  confidence: string;
  time: string;
};
export type InvestigationEdge = {
  from: string;
  to: string;
  relation: string;
  provenance: 'observed' | 'reported';
  evidence_id: string;
};
export type LabInvestigation = {
  device_id: string;
  seed_process_guid: string;
  seed_detection_id: string;
  data_source: 'development_in_memory_retained_telemetry';
  nodes: InvestigationNode[];
  edges: InvestigationEdge[];
  gaps: string[];
  truncated: boolean;
};
export type InvestigationSeed =
  | {deviceID: string; kind: 'process'; processGUID: string}
  | {deviceID: string; kind: 'detection'; detectionID: string};
export type ProcessBranch = {
  node: InvestigationNode;
  parentRelation: InvestigationEdge | null;
  children: ProcessBranch[];
};

type Rec = Record<string, unknown>;
const rec = (value: unknown, at: string): Rec => {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new Error('Invalid investigation object: ' + at);
  return value as Rec;
};
const string = (value: unknown, at: string, fallback?: string): string => {
  if ((value === undefined || value === null) && fallback !== undefined) return fallback;
  if (typeof value !== 'string' || value.length > 8192)
    throw new Error('Invalid investigation text: ' + at);
  return value;
};
const list = (value: unknown, at: string, cap: number): unknown[] => {
  if (!Array.isArray(value) || value.length > cap)
    throw new Error('Invalid investigation list: ' + at);
  return value as unknown[];
};
const safeID = (value: string, max: number): boolean =>
  value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);

export function decodeLabInvestigation(raw: unknown, requestedDevice: string, seed: InvestigationSeed): LabInvestigation {
  const graph = rec(raw, 'root');
  if (graph.data_source !== 'development_in_memory_retained_telemetry')
    throw new Error('Unexpected investigation data source: evidence provenance unverified.');
  const deviceID = string(graph.device_id, 'device_id');
  if (deviceID !== requestedDevice)
    throw new Error('Investigation response does not match the requested device.');
  const processGUID = string(graph.seed_process_guid, 'seed_process_guid');
  const detectionID = string(graph.seed_detection_id, 'seed_detection_id', '');
  if (!safeID(processGUID, 160)) throw new Error('Invalid returned seed process GUID.');
  if (seed.kind === 'process' && processGUID !== seed.processGUID)
    throw new Error('Investigation process seed does not match the request.');
  if (seed.kind === 'detection' && detectionID !== seed.detectionID)
    throw new Error('Investigation detection seed does not match the request.');
  if (typeof graph.truncated !== 'boolean')
    throw new Error('Missing investigation truncation flag.');
  const nodes = list(graph.nodes, 'nodes', 500).map((value, index): InvestigationNode => {
    const n = rec(value, 'node ' + index);
    const kind = string(n.kind, 'node.kind');
    const status = string(n.status, 'node.status');
    if (!['process', 'event', 'file', 'detection'].includes(kind) ||
        (status !== 'observed' && status !== 'referenced'))
      throw new Error('Unrecognized investigation node kind/status.');
    if (string(n.device_id, 'node.device_id') !== deviceID)
      throw new Error('Cross-device investigation node rejected.');
    const node: InvestigationNode = {
      id: string(n.id, 'node.id'), kind: kind as InvestigationNode['kind'],
      status, label: string(n.label, 'node.label'), device_id: deviceID,
      process_guid: string(n.process_guid, 'node.process_guid', ''),
      event_id: string(n.event_id, 'node.event_id', ''),
      event_type: string(n.event_type, 'node.event_type', ''),
      file_path: string(n.file_path, 'node.file_path', ''),
      image: string(n.image, 'node.image', ''),
      detail: string(n.detail, 'node.detail', ''),
      severity: string(n.severity, 'node.severity', ''),
      confidence: string(n.confidence, 'node.confidence', ''),
      time: string(n.time, 'node.time', ''),
    };
    if (!safeID(node.id, 256)) throw new Error('Invalid investigation node ID.');
    return node;
  });
  const byID = new Map<string, InvestigationNode>();
  for (const n of nodes) {
    if (byID.has(n.id)) throw new Error('Duplicate investigation node ID.');
    byID.set(n.id, n);
  }
  if (!nodes.some(n => n.kind === 'process' && n.process_guid === processGUID))
    throw new Error('Investigation seed process is absent from retained nodes.');
  const edges = list(graph.edges, 'edges', 5000).map((value, index): InvestigationEdge => {
    const e = rec(value, 'edge ' + index);
    const provenance = string(e.provenance, 'edge.provenance');
    if (provenance !== 'observed' && provenance !== 'reported')
      throw new Error('Unrecognized investigation edge provenance.');
    const from = string(e.from, 'edge.from'), to = string(e.to, 'edge.to');
    if (!byID.has(from) || !byID.has(to))
      throw new Error('Investigation edge references a missing evidence node.');
    const relation = string(e.relation, 'edge.relation');
    if (relation === 'parent_process' &&
        (byID.get(from)?.kind !== 'process' || byID.get(to)?.kind !== 'process'))
      throw new Error('Invalid parent-process evidence relation.');
    return {from, to, relation, provenance, evidence_id: string(e.evidence_id, 'edge.evidence_id', '')};
  });
  const gaps = list(graph.gaps, 'gaps', 200).map((x, i) => string(x, 'gap ' + i));
  const result: LabInvestigation = {
    device_id: deviceID, seed_process_guid: processGUID, seed_detection_id: detectionID,
    data_source: 'development_in_memory_retained_telemetry',
    nodes, edges, gaps, truncated: graph.truncated,
  };
  // A cycle or multiple parent links cannot safely be described as process lineage.
  deriveProcessForest(result);
  return result;
}

/** Only retained parent_process edges become parent relationships; never infer one. */
export function deriveProcessForest(graph: LabInvestigation): ProcessBranch[] {
  const processes = new Map(graph.nodes.filter(n => n.kind === 'process').map(n => [n.id, n]));
  const parent = new Map<string, InvestigationEdge>();
  for (const e of graph.edges.filter(e => e.relation === 'parent_process')) {
    if (!processes.has(e.from) || !processes.has(e.to))
      throw new Error('Parent-process edge has no process nodes.');
    if (e.from === e.to || parent.has(e.to))
      throw new Error('Ambiguous process parentage; refusing to infer a process tree.');
    parent.set(e.to, e);
  }
  // Detect cycles before rendering a nested tree (and reject ambiguous lineage).
  for (const id of processes.keys()) {
    const seen = new Set<string>();
    let cursor: string | undefined = id;
    while (cursor !== undefined) {
      if (seen.has(cursor)) throw new Error('Cyclic process lineage rejected.');
      seen.add(cursor);
      cursor = parent.get(cursor)?.from;
    }
  }
  const children = new Map<string, string[]>();
  for (const e of parent.values()) {
    const ids = children.get(e.from) || [];
    ids.push(e.to);
    children.set(e.from, ids);
  }
  const order = (a: string, b: string) => {
    const aNode = processes.get(a), bNode = processes.get(b);
    return (aNode?.label || '').localeCompare(bNode?.label || '') || a.localeCompare(b);
  };
  function build(id: string): ProcessBranch {
    const node = processes.get(id);
    if (!node) throw new Error('Missing process evidence node.');
    return {node, parentRelation: parent.get(id) || null,
      children: (children.get(id) || []).sort(order).map(build)};
  }
  return [...processes.keys()].filter(id => !parent.has(id)).sort(order).map(build);
}

export function investigationTimeline(graph: LabInvestigation): InvestigationNode[] {
  return graph.nodes.filter(n => n.kind === 'event' || n.kind === 'detection')
    .sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
}

export function buildInvestigationPath(seed: InvestigationSeed): string {
  const deviceID = seed.deviceID.trim();
  if (!safeID(deviceID, 96)) throw new Error('Enter a valid endpoint ID (maximum 96 characters).');
  const params = new URLSearchParams({device_id: deviceID, depth: '4', max_nodes: '250'});
  if (seed.kind === 'process') {
    if (!safeID(seed.processGUID.trim(), 160))
      throw new Error('Enter a valid process GUID (maximum 160 characters).');
    params.set('process_guid', seed.processGUID.trim());
  } else {
    if (!safeID(seed.detectionID.trim(), 160))
      throw new Error('Enter a valid detection ID (maximum 160 characters).');
    params.set('detection_id', seed.detectionID.trim());
  }
  return '/api/investigations?' + params.toString();
}

export async function fetchLabInvestigation(
  token: string, seed: InvestigationSeed, signal?: AbortSignal, fetcher: typeof fetch = fetch,
): Promise<LabInvestigation> {
  if (token.length < 16) throw new Error('The development token must contain at least 16 characters.');
  const path = buildInvestigationPath(seed);
  const response = await fetcher(path, {
    method: 'GET', credentials: 'omit', cache: 'no-store', signal,
    headers: {Authorization: 'Bearer ' + token},
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Development token rejected (HTTP 401).');
    if (response.status === 404) throw new Error('No matching seed in retained lab evidence (HTTP 404).');
    throw new Error('Lab investigation API returned HTTP ' + response.status + '.');
  }
  const result = await response.json() as unknown;
  const requestedDevice = seed.deviceID.trim();
  const normalizedSeed: InvestigationSeed = seed.kind === 'process'
    ? {deviceID: requestedDevice, kind: 'process', processGUID: seed.processGUID.trim()}
    : {deviceID: requestedDevice, kind: 'detection', detectionID: seed.detectionID.trim()};
  return decodeLabInvestigation(result, requestedDevice, normalizedSeed);
}
