-- Disposable database after migrations 0001 through 0011.
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('alertA','Alert A'),('alertB','Alert B');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('alertA','win01','windows'),('alertB','win01','windows');
INSERT INTO edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role)
VALUES ('alertA','analyst',decode(repeat('aa',32),'hex'),'scanner'),
       ('alertA','viewer',decode(repeat('bb',32),'hex'),'viewer'),
       ('alertB','analyst',decode(repeat('cc',32),'hex'),'scanner');
DO $test$
DECLARE
 leased record; alert_uuid uuid; done boolean;
BEGIN
 INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
 VALUES ('11111111-1111-4111-8111-111111111151','alertA','win01','C:/Lab/malware');
 SELECT * INTO leased FROM edr_claim_scan_job(
  'alertA','win01','win01','22222222-2222-4222-8222-222222222222',60);
 IF leased.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111151'::uuid THEN
  RAISE EXCEPTION 'malware job not leased'; END IF;
 done:=edr_complete_scan_job_with_result('alertA','win01',leased.job_id,
  '22222222-2222-4222-8222-222222222222','malicious','Lab-Signature','');
 IF NOT done THEN RAISE EXCEPTION 'malware result failed'; END IF;
 SELECT alert_id INTO alert_uuid FROM edr_soc_alerts WHERE tenant_id='alertA';
 IF alert_uuid IS NULL THEN RAISE EXCEPTION 'malicious scan did not emit SOC alert'; END IF;
 IF (SELECT count(*) FROM edr_soc_alerts WHERE tenant_id='alertA')<>1 THEN
  RAISE EXCEPTION 'duplicate SOC malware alert'; END IF;
 IF edr_soc_change_alert_state('alertA','viewer',alert_uuid,'ack','') THEN
  RAISE EXCEPTION 'viewer acknowledged alert'; END IF;
 IF edr_soc_change_alert_state('alertB','analyst',alert_uuid,'ack','') THEN
  RAISE EXCEPTION 'cross-tenant alert acknowledgment'; END IF;
 IF NOT edr_soc_change_alert_state('alertA','analyst',alert_uuid,'ack','') THEN
  RAISE EXCEPTION 'valid acknowledgment denied'; END IF;
 IF edr_soc_change_alert_state('alertA','analyst',alert_uuid,'ack','') THEN
  RAISE EXCEPTION 'duplicate acknowledgment succeeded'; END IF;
 IF edr_soc_change_alert_state('alertA','analyst',alert_uuid,'resolve','') THEN
  RAISE EXCEPTION 'empty resolution note accepted'; END IF;
 IF NOT edr_soc_change_alert_state('alertA','analyst',alert_uuid,
      'resolve','Reviewed in isolated lab; no action taken') THEN
  RAISE EXCEPTION 'analyst could not resolve alert'; END IF;
 IF NOT EXISTS (SELECT 1 FROM edr_soc_alerts WHERE alert_id=alert_uuid
  AND state='resolved' AND acknowledged_by='analyst' AND resolved_by='analyst'
  AND resolution_note LIKE 'Reviewed%') THEN
  RAISE EXCEPTION 'SOC triage state or attribution not persisted'; END IF;
 IF NOT edr_soc_change_alert_state('alertA','analyst',alert_uuid,'reopen','') THEN
  RAISE EXCEPTION 'analyst could not reopen alert'; END IF;
 IF (SELECT state FROM edr_soc_alerts WHERE alert_id=alert_uuid)<>'open' THEN
  RAISE EXCEPTION 'reopened alert did not return to open'; END IF;
 INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
 VALUES ('11111111-1111-4111-8111-111111111152','alertA','win01','C:/Lab/clean');
 SELECT * INTO leased FROM edr_claim_scan_job(
  'alertA','win01','win01','33333333-3333-4333-8333-333333333333',60);
 IF leased.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111152'::uuid THEN
  RAISE EXCEPTION 'clean job not leased'; END IF;
 IF NOT edr_complete_scan_job_with_result('alertA','win01',leased.job_id,
  '33333333-3333-4333-8333-333333333333','clean_by_signature','','') THEN
  RAISE EXCEPTION 'clean scan result rejected'; END IF;
 IF (SELECT count(*) FROM edr_soc_alerts WHERE tenant_id='alertA')<>1 THEN
  RAISE EXCEPTION 'clean result emitted false malware alert'; END IF;
END $test$;
ROLLBACK;
