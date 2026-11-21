import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeLabDetections, detectionsInWindow } from '../.test-dist/detections.js';
import { alertSeverityBucket, filterRetainedAlerts, summarizeRetainedAlerts } from '../.test-dist/alert-triage.js';

const detection = (id, severity, patch={}) => ({
  id, rule_id:'TURAN-WIN-LAB-1', category:'observed_signal',
  severity, confidence:'low', device_id:'WIN-01', process_guid:'{ONE}',
  process_image:'cmd.exe', module_path:'C:\\Users\\sample.dll',
  load_event_id:'source-'+id, file_create_event_id:'',
  observed_at:'2026-11-21T10:00:00Z', explanation:'Review retained evidence.', ...patch,
});
const parsed = (...items) => decodeLabDetections(items);

test('severity bucketing retains unknown and unusual labels without inventing priority', () => {
  assert.equal(alertSeverityBucket(' HIGH '),'high');
  assert.equal(alertSeverityBucket('CRITICAL'),'critical');
  assert.equal(alertSeverityBucket('informational'),'other');
  assert.equal(alertSeverityBucket('not-set'),'other');
  const rows=parsed(detection('a','critical'), detection('b','High'),
    detection('c','medium'), detection('d','low'), detection('e','unknown'));
  assert.deepEqual(summarizeRetainedAlerts(rows),
    {critical:1,high:1,medium:1,low:1,other:1});
  assert.deepEqual(filterRetainedAlerts(rows,'critical_high','all','').map(d=>d.id),['a','b']);
  assert.deepEqual(filterRetainedAlerts(rows,'other','all','').map(d=>d.id),['e']);
});

test('file-create linking is just a record field, not coverage inference', () => {
  const rows=parsed(detection('a','high', {file_create_event_id:'event-11'}),
    detection('b','high'));
  assert.deepEqual(filterRetainedAlerts(rows,'all','file_create_linked','').map(d=>d.id),['a']);
  assert.deepEqual(filterRetainedAlerts(rows,'all','file_create_not_linked','').map(d=>d.id),['b']);
});

test('case-insensitive source/host/rule search leaves original data and order unchanged', () => {
  const rows=parsed(detection('a','high',{device_id:'WIN-01',file_create_event_id:'Record-119'}),
    detection('b','medium',{device_id:'LINUX-02',rule_id:'unusual-child'}));
  const before=rows.map(d=>d.id);
  assert.deepEqual(filterRetainedAlerts(rows,'all','all','record-119').map(d=>d.id),['a']);
  assert.deepEqual(filterRetainedAlerts(rows,'all','all','linux-02').map(d=>d.id),['b']);
  assert.deepEqual(filterRetainedAlerts(rows,'medium','all','UNUSUAL').map(d=>d.id),['b']);
  assert.deepEqual(filterRetainedAlerts(rows,'all','all',' no match '),[]);
  assert.deepEqual(rows.map(d=>d.id),before);
});

test('UTC retained window is applied before local triage, excluding future and out-of-window signals',()=>{
  const rows=parsed(detection('old','critical',{observed_at:'2026-11-10T10:00:00Z'}),
    detection('new','low',{observed_at:'2026-11-21T10:00:00Z'}),
    detection('future','critical',{observed_at:'2026-11-22T10:00:00Z'}));
  const retained=detectionsInWindow(rows,'2026-11-21T12:00:00Z',7);
  assert.deepEqual(filterRetainedAlerts(retained,'all','all','').map(d=>d.id),['new']);
  assert.equal(summarizeRetainedAlerts(retained).critical,0);
});

test('empty returned data is not classified as a safe endpoint', () => {
  assert.deepEqual(filterRetainedAlerts([],'critical_high','all','WIN-1'),[]);
  assert.deepEqual(summarizeRetainedAlerts([]),
    {critical:0,high:0,medium:0,low:0,other:0});
});
