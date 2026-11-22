import test from 'node:test';
import assert from 'node:assert/strict';
import {backendUTCWindow,withinBackendUTCWindow} from '../.test-dist/backend-utc-window.js';
import {detectionsInWindow} from '../.test-dist/detections.js';
import {isInOverviewWindow} from '../.test-dist/evidence-snapshot.js';
const sample=(id,observed_at)=>({id,observed_at});
test('Day1 Go 1-day starts at midnight rather than rolling 24h',()=>{
 const w=backendUTCWindow('2026-11-21T23:50:00Z',1);
 assert.equal(w.startDay,'2026-11-21');
 assert.ok(withinBackendUTCWindow(Date.parse('2026-11-21T00:00:00Z'),w));
 assert.equal(withinBackendUTCWindow(Date.parse('2026-11-20T23:59:59Z'),w),false);
});
test('Day1 Go 7-day start includes exactly seven UTC calendar dates',()=>{
 const w=backendUTCWindow('2026-11-21T12:00:00Z',7);
 assert.equal(w.startDay,'2026-11-15');
 assert.equal(withinBackendUTCWindow(Date.parse('2026-11-15T00:00:00Z'),w),true);
 assert.equal(withinBackendUTCWindow(Date.parse('2026-11-14T23:59:59Z'),w),false);
});
test('Day1 30-day window crosses calendar months without local timezone',()=>{
 const w=backendUTCWindow('2026-11-21T12:00:00+05:00',30);
 assert.equal(w.startDay,'2026-10-23');
});
test('Day1 ISO offsets are treated as UTC instants',()=>{
 const w=backendUTCWindow('2026-11-21T02:00:00+05:00',1);
 assert.equal(w.startDay,'2026-11-20');
 assert.equal(withinBackendUTCWindow(Date.parse('2026-11-20T23:00:00Z'),w),false);
});
test('Day1 current future event is excluded even within same calendar day',()=>{
 const w=backendUTCWindow('2026-11-21T12:00:00Z',7);
 assert.equal(withinBackendUTCWindow(Date.parse('2026-11-21T12:00:01Z'),w),false);
});
test('Day1 detection and evidence-snapshot components use identical backend bounds',()=>{
 const generated='2026-11-21T12:00:00Z';
 const rows=[sample('start','2026-11-15T00:00:00Z'),sample('old','2026-11-14T23:59:59Z'),
   sample('future','2026-11-21T12:00:01Z')];
 const detections=detectionsInWindow(rows,generated,7).map(x=>x.id);
 assert.deepEqual(detections,['start']);
 for (const x of rows) assert.equal(isInOverviewWindow(Date.parse(x.observed_at),Date.parse(generated),7),detections.includes(x.id));
});
test('Day1 malformed dates and unsupported days cannot yield positive evidence',()=>{
 assert.throws(()=>backendUTCWindow('bad',7));
 assert.throws(()=>backendUTCWindow('2026-11-21T12:00:00Z',14));
 const w=backendUTCWindow('2026-11-21T12:00:00Z',7);
 assert.equal(withinBackendUTCWindow(NaN,w),false);
 assert.equal(withinBackendUTCWindow(null,w),false);
});
