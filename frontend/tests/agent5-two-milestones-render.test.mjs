import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { decodeLabDetections } from '../.test-dist/detections.js';
import { decodeLabTelemetry } from '../.test-dist/telemetry.js';
import { MultisignalAlertTriage } from '../.test-dist/MultisignalAlertTriage.js';
import { RetainedSourceInspection } from '../.test-dist/RetainedSourceInspection.js';

const detection = (patch={}) => ({
  id:'d1',device_id:'host-A',rule_id:'RULE-REGISTRY',category:'registry_value',
  severity:'medium',confidence:'low',process_guid:'',process_image:'',
  module_path:'',load_event_id:'',evidence_event_id:'go-source-1',
  target_object:'HKEY_LOCAL_MACHINE\\Software',evidence_source_event_id:13,
  file_create_event_id:'',observed_at:'2026-11-21T10:00:00Z',
  explanation:'Review reported evidence',...patch,
});
const event = (patch={}) => ({
  id:'go-source-1',device_id:'host-A',platform:'windows',source:'sysmon',
  type:'registry_update',source_event_id:13,source_record_id:'124',
  time:'2026-11-21T10:00:00Z',received_at:'2026-11-21T10:00:01Z',
  time_origin:'sender', process_guid:'',parent_process_guid:'',
  image:'',file_path:'',detail:'reported',source_fields:{},...patch,
});
const alerts = rows => renderToStaticMarkup(createElement(MultisignalAlertTriage,{
  detections:decodeLabDetections(rows),generatedAt:'2026-11-21T12:00:00Z',days:7,
  onInvestigate:()=>{},onInspectSource:()=>{},
}));
const source = (rows, selection={deviceID:'host-A',eventID:'go-source-1'}) =>
  renderToStaticMarkup(createElement(RetainedSourceInspection,{
    events:decodeLabTelemetry(rows),selection,onBack:()=>{},onInvestigate:()=>{},
  }));

test('multisignal triage is labeled, screenreader count is live and action is evidence-only',()=>{
  const html=alerts([detection()]);
  assert.match(html, /for="alert-triage-severity"/);
  assert.match(html, /for="alert-triage-source"/);
  assert.match(html, /for="alert-triage-search"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<caption>/);
  assert.match(html, /Inspect source event/);
  assert.match(html, /No process GUID for process investigation/);
  assert.doesNotMatch(html, /<button[^>]*>Quarantine<\/button>/i);
});
test('unknown source event type never becomes a DLL load and untrusted strings stay escaped',()=>{
  const html=alerts([detection({evidence_source_event_id:0,
    target_object:'<img src=x onerror=alert(1)>',
    rule_id:'<script>alert(1)</script>'})]);
  assert.match(html, /Numeric event type unknown/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img\b|<script\b/i);
  assert.doesNotMatch(html, /DLL load observed/);
});
test('source detail is exact-host only with a missing-retention fallback',()=>{
  const html=source([event()]);
  assert.match(html, /Matching event is present/);
  assert.match(html, /Sysmon ID 13/);
  assert.match(html, /Go event ID/);
  const wrong=source([event({device_id:'host-B'})]);
  assert.match(wrong, /not among the 1 events returned/);
  assert.match(wrong, /absence is not proof/);
  assert.doesNotMatch(wrong, /Sysmon ID 13/);
});
test('source details use React escaping and never use RecordID as a fallback',()=>{
  const html=source([event({source_record_id:'go-source-1',detail:'<script>bad()</script>',
    source_fields:{target_object:'<img src=x onerror=alert(1)>'}})],
    {deviceID:'host-A',eventID:'missing-id'});
  assert.match(html, /not among the 1 events returned/);
  assert.doesNotMatch(html, /Reported detail/);
  const shown=source([event({detail:'<script>bad()</script>',source_fields:{
    target_object:'<img src=x onerror=alert(1)>',
  }})]);
  assert.match(shown, /&lt;script/);
  assert.match(shown, /&lt;img/);
  assert.doesNotMatch(shown, /<script\b|<img\b/i);
});
test('clipboard Event 24 renders metadata only, not its reported detail',()=>{
  const html=source([event({
    source_event_id:24,process_guid:'',image:'',file_path:'',
    source_fields:{},detail:'SENSITIVE_CLIPBOARD_CONTENT',
  })]);
  assert.match(html, /clipboard-change metadata only/);
  assert.doesNotMatch(html, /SENSITIVE_CLIPBOARD_CONTENT/);
});
