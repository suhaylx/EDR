-- Sprint Day 3: SOC case assignment, analyst notes and append-only audit.
-- Run only in disposable PostgreSQL after migrations 0001 through 0012.
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
 VALUES ('caseA','Case A'),('caseB','Case B');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
 VALUES ('caseA','win01','windows'),('caseB','win01','windows');
INSERT INTO edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role)
 VALUES ('caseA','lead',decode(repeat('a1',32),'hex'),'scanner'),
        ('caseA','investigator',decode(repeat('b2',32),'hex'),'scanner'),
        ('caseA','viewer',decode(repeat('c3',32),'hex'),'viewer'),
        ('caseB','lead',decode(repeat('d4',32),'hex'),'scanner');

DO $verify$
DECLARE
 leased record;
 case_id uuid;
 note_id uuid;
 changed boolean;
BEGIN
 INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
 VALUES ('11111111-1111-4111-8111-111111111161','caseA','win01','C:/Lab/case');
 SELECT * INTO leased FROM edr_claim_scan_job('caseA','win01','win01',
  '22222222-2222-4222-8222-222222222222',60);
 IF leased.job_id IS DISTINCT FROM
    '11111111-1111-4111-8111-111111111161'::uuid THEN
  RAISE EXCEPTION 'case fixture job not leased'; END IF;
 IF NOT edr_complete_scan_job_with_result('caseA','win01',leased.job_id,
  '22222222-2222-4222-8222-222222222222','malicious',
  'Lab-Case-Signature','') THEN
  RAISE EXCEPTION 'case fixture malware result failed'; END IF;
 SELECT alert_id INTO case_id FROM edr_soc_alerts
 WHERE tenant_id='caseA' AND job_id=leased.job_id;
 IF case_id IS NULL THEN RAISE EXCEPTION 'malware alert not created'; END IF;
 IF NOT EXISTS(
   SELECT 1 FROM edr_soc_alert_activity WHERE tenant_id='caseA'
    AND alert_id=case_id AND actor_id='system' AND action='created') THEN
  RAISE EXCEPTION 'initial alert creation not audited'; END IF;
 changed:=edr_soc_assign_alert('caseA','viewer',case_id,'investigator');
 IF changed THEN RAISE EXCEPTION 'viewer assigned case'; END IF;
 changed:=edr_soc_assign_alert('caseB','lead',case_id,'lead');
 IF changed THEN RAISE EXCEPTION 'cross-tenant case assignment'; END IF;
 changed:=edr_soc_assign_alert('caseA','lead',case_id,'viewer');
 IF changed THEN RAISE EXCEPTION 'viewer assigned to case'; END IF;
 changed:=edr_soc_assign_alert('caseA','lead',case_id,'investigator');
 IF NOT changed THEN RAISE EXCEPTION 'active investigator assignment failed'; END IF;
 changed:=edr_soc_assign_alert('caseA','lead',case_id,'investigator');
 IF changed THEN RAISE EXCEPTION 'repeat assignment returned success'; END IF;
 IF NOT EXISTS (SELECT 1 FROM edr_soc_alert_activity
  WHERE tenant_id='caseA' AND alert_id=case_id AND action='assigned'
    AND actor_id='lead' AND note='investigator') THEN
  RAISE EXCEPTION 'assignment attribution missing'; END IF;

 note_id:=edr_soc_add_alert_note('caseA','viewer',case_id,'unapproved');
 IF note_id IS NOT NULL THEN RAISE EXCEPTION 'viewer added case note'; END IF;
 note_id:=edr_soc_add_alert_note('caseB','lead',case_id,'cross-tenant');
 IF note_id IS NOT NULL THEN RAISE EXCEPTION 'cross-tenant case note'; END IF;
 note_id:=edr_soc_add_alert_note('caseA','investigator',case_id,'');
 IF note_id IS NOT NULL THEN RAISE EXCEPTION 'blank note accepted'; END IF;
 note_id:=edr_soc_add_alert_note('caseA','investigator',case_id,
  'Investigated signature in isolated lab; evidence preserved');
 IF note_id IS NULL THEN RAISE EXCEPTION 'valid analyst note rejected'; END IF;
 IF NOT EXISTS (SELECT 1 FROM edr_soc_alert_activity
   WHERE tenant_id='caseA' AND activity_id=note_id
     AND actor_id='investigator' AND action='note') THEN
  RAISE EXCEPTION 'analyst note audit missing'; END IF;

 IF NOT edr_soc_change_alert_state('caseA','investigator',case_id,'ack','') THEN
  RAISE EXCEPTION 'investigator acknowledgment failed'; END IF;
 changed:=edr_soc_assign_alert('caseA','lead',case_id,'');
 IF NOT changed THEN RAISE EXCEPTION 'case unassignment failed'; END IF;
 IF NOT edr_soc_change_alert_state('caseA','lead',case_id,'resolve',
  'Reviewed and retained sample for separate approved remediation') THEN
  RAISE EXCEPTION 'resolution failed'; END IF;
 IF NOT edr_soc_change_alert_state('caseA','lead',case_id,'reopen','') THEN
  RAISE EXCEPTION 'reopen failed'; END IF;
 IF (SELECT count(*) FROM edr_soc_alert_activity
    WHERE tenant_id='caseA' AND alert_id=case_id)<>7 THEN
  RAISE EXCEPTION 'expected 7 append-only actions'; END IF;
 IF NOT EXISTS (SELECT 1 FROM edr_soc_alert_activity
  WHERE tenant_id='caseA' AND alert_id=case_id AND action='reopened'
   AND actor_id='lead') THEN
  RAISE EXCEPTION 'reopen actor missing from audit'; END IF;

 BEGIN
  UPDATE edr_soc_alert_activity SET note='tampered' WHERE activity_id=note_id;
  RAISE EXCEPTION 'SOC activity UPDATE unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  DELETE FROM edr_soc_alert_activity WHERE activity_id=note_id;
  RAISE EXCEPTION 'SOC activity DELETE unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 IF EXISTS (SELECT 1 FROM edr_soc_alert_activity WHERE tenant_id='caseB') THEN
  RAISE EXCEPTION 'cross-tenant activity leaked'; END IF;
END $verify$;
ROLLBACK;
