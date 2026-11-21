-- Disposable PostgreSQL, after migrations 0001..0010.
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('socA','SOC A'),('socB','SOC B');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('socA','win01','windows'),('socB','win01','windows');
INSERT INTO edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role)
VALUES ('socA','analyst',decode(repeat('aa',32),'hex'),'scanner'),
       ('socA','viewer',decode(repeat('bb',32),'hex'),'viewer'),
       ('socB','analyst',decode(repeat('cc',32),'hex'),'scanner');

DO $test$
DECLARE r record;
BEGIN
 SELECT * INTO r FROM edr_enqueue_operator_scan_job(
  'socA','viewer','win01','11111111-1111-4111-8111-111111111111',
  'request-1','C:/Lab/file');
 IF FOUND THEN RAISE EXCEPTION 'viewer queued scan'; END IF;
 SELECT * INTO r FROM edr_enqueue_operator_scan_job(
  'socA','analyst','win01','11111111-1111-4111-8111-111111111111',
  'request-1','C:/Lab/file');
 IF r.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111111'::uuid
  OR r.created IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'operator failed to schedule scan'; END IF;
 SELECT * INTO r FROM edr_enqueue_operator_scan_job(
  'socA','analyst','win01','22222222-2222-4222-8222-222222222222',
  'request-1','C:/Lab/file');
 IF r.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111111'::uuid
   OR r.created IS DISTINCT FROM false THEN
   RAISE EXCEPTION 'request idempotency failed'; END IF;
 SELECT * INTO r FROM edr_enqueue_operator_scan_job(
  'socA','analyst','win01','33333333-3333-4333-8333-333333333333',
  'request-1','C:/Lab/different');
 IF FOUND THEN RAISE EXCEPTION 'changed request parameters reused key'; END IF;
 SELECT * INTO r FROM edr_enqueue_operator_scan_job(
  'socB','analyst','win01','44444444-4444-4444-8444-444444444444',
  'request-1','C:/Lab/other');
 IF r.job_id IS DISTINCT FROM '44444444-4444-4444-8444-444444444444'::uuid THEN
  RAISE EXCEPTION 'cross-tenant request key collision'; END IF;
 IF edr_cancel_operator_scan_job('socA','viewer',
    '11111111-1111-4111-8111-111111111111') THEN
  RAISE EXCEPTION 'viewer cancelled job'; END IF;
 IF edr_cancel_operator_scan_job('socB','analyst',
    '11111111-1111-4111-8111-111111111111') THEN
  RAISE EXCEPTION 'cross-tenant cancellation'; END IF;
 IF NOT edr_cancel_operator_scan_job('socA','analyst',
    '11111111-1111-4111-8111-111111111111') THEN
  RAISE EXCEPTION 'owner cancellation failed'; END IF;
 IF edr_cancel_operator_scan_job('socA','analyst',
    '11111111-1111-4111-8111-111111111111') THEN
  RAISE EXCEPTION 'repeated cancellation reported success'; END IF;
 UPDATE edr_soc_operators SET revoked_at=now()
 WHERE tenant_id='socA' AND operator_id='analyst';
 SELECT * INTO r FROM edr_enqueue_operator_scan_job(
  'socA','analyst','win01','55555555-5555-4555-8555-555555555555',
  'request-2','C:/Lab/file');
 IF FOUND THEN RAISE EXCEPTION 'revoked operator queued job'; END IF;
END $test$;
ROLLBACK;
