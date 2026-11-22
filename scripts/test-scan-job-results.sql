-- BE-114: isolated PostgreSQL 16 integration. Requires migrations 0001..0008
-- and a disposable DB; transaction rolls back all fixtures.
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('resultA','Result A'),('resultB','Result B');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('resultA','win01','windows'),('resultB','win01','windows'),
       ('resultA','revoked','linux');

DO $regression$
DECLARE
  job record;
  accepted boolean;
  target_job uuid;
  verdict_kind text;
  expected_state text;
  token uuid;
BEGIN
  -- BE-111: cross-tenant and stale-token submissions cannot persist malware evidence.
  INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
  VALUES ('11111111-1111-4111-8111-111111111101','resultA','win01','C:/Lab/test');
  token:='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  SELECT * INTO job FROM edr_claim_scan_job('resultA','win01','win01',token,60);
  IF job.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111101'::uuid THEN
    RAISE EXCEPTION 'malicious scan was not leased'; END IF;
  accepted:=edr_complete_scan_job_with_result('resultB','win01',job.job_id,
      token,'malicious','Lab-Signature','');
  IF accepted THEN RAISE EXCEPTION 'cross-tenant verdict accepted'; END IF;
  accepted:=edr_complete_scan_job_with_result('resultA','win01',job.job_id,
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','malicious','Lab-Signature','');
  IF accepted THEN RAISE EXCEPTION 'wrong lease token accepted'; END IF;
  accepted:=edr_complete_scan_job_with_result('resultA','win01',job.job_id,
      token,'malicious','','');
  IF accepted THEN RAISE EXCEPTION 'empty malicious signature accepted'; END IF;
  accepted:=edr_complete_scan_job_with_result('resultA','win01',job.job_id,
      token,'malicious','Lab-Signature',E'newline\ninside');
  IF accepted THEN RAISE EXCEPTION 'control-character detail accepted'; END IF;
  accepted:=edr_complete_scan_job_with_result('resultA','win01',job.job_id,
      token,'malicious','Lab-Signature','');
  IF NOT accepted THEN RAISE EXCEPTION 'malicious verdict was not persisted'; END IF;
  IF NOT EXISTS (
      SELECT 1 FROM edr_scan_jobs AS j
      JOIN edr_scan_job_results AS r ON r.job_id=j.job_id
      WHERE j.job_id=job.job_id AND j.state='succeeded'
        AND j.lease_token IS NULL AND r.tenant_id='resultA'
        AND r.agent_id='win01' AND r.verdict='malicious'
        AND r.threat_name='Lab-Signature') THEN
    RAISE EXCEPTION 'malware evidence integrity failed'; END IF;
  accepted:=edr_complete_scan_job_with_result('resultA','win01',job.job_id,
      token,'malicious','Changed-Signature','');
  IF accepted THEN RAISE EXCEPTION 'replayed verdict overwrote evidence'; END IF;
  -- BE-112: direct evidence modification and deletion are denied.
  BEGIN
    UPDATE edr_scan_job_results SET threat_name='tamper'
    WHERE job_id=job.job_id;
    RAISE EXCEPTION 'UPDATE of malware evidence succeeded';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    DELETE FROM edr_scan_job_results WHERE job_id=job.job_id;
    RAISE EXCEPTION 'DELETE of malware evidence succeeded';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  -- BE-113: scope FK must fail before any job_id uniqueness conflict.
  -- Use a cancelled, result-free job so no other constraint masks the FK.
  INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,state)
  VALUES ('11111111-1111-4111-8111-111111111107','resultA','win01',
      'C:/Lab/unclaimed','cancelled');
  BEGIN
    INSERT INTO edr_scan_job_results(
        job_id,tenant_id,agent_id,engine,verdict)
    VALUES ('11111111-1111-4111-8111-111111111107',
        'resultB','win01','clamav','error');
    RAISE EXCEPTION 'cross-tenant result row inserted';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;

  -- BE-114: distinguish clean signature outcome, scanner error and unscanned.
  FOR target_job,verdict_kind,expected_state IN
    SELECT * FROM (VALUES
      ('11111111-1111-4111-8111-111111111102'::uuid,'clean_by_signature','succeeded'),
      ('11111111-1111-4111-8111-111111111103'::uuid,'error','failed'),
      ('11111111-1111-4111-8111-111111111104'::uuid,'unscanned','failed')
    ) AS cases(job_id,verdict,state)
  LOOP
    INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
    VALUES (target_job,'resultA','win01','C:/Lab/test');
    token:=gen_random_uuid();
    SELECT * INTO job FROM edr_claim_scan_job('resultA','win01','win01',token,60);
    IF job.job_id IS DISTINCT FROM target_job THEN
      RAISE EXCEPTION 'wrong job leased for %',verdict_kind; END IF;
    accepted:=edr_complete_scan_job_with_result(
        'resultA','win01',job.job_id,token,verdict_kind,'','Lab scanner outcome');
    IF NOT accepted THEN RAISE EXCEPTION 'valid result denied for %',verdict_kind; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM edr_scan_job_results AS r
        JOIN edr_scan_jobs AS j ON j.job_id=r.job_id
        WHERE r.job_id=target_job AND r.verdict=verdict_kind
          AND j.state=expected_state) THEN
      RAISE EXCEPTION 'wrong terminal state for %',verdict_kind; END IF;
  END LOOP;
  IF (SELECT count(*) FROM edr_scan_job_results WHERE tenant_id='resultA')<>4 THEN
    RAISE EXCEPTION 'incorrect durable verdict count'; END IF;

  -- BE-115: expiry and revocation deny completion while preserving leased rows.
  INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
  VALUES ('11111111-1111-4111-8111-111111111105','resultA','win01','C:/Lab/expired');
  token:=gen_random_uuid();
  SELECT * INTO job FROM edr_claim_scan_job('resultA','win01','win01',token,60);
  IF job.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111105'::uuid THEN
    RAISE EXCEPTION 'expired fixture claim failed'; END IF;
  UPDATE edr_scan_jobs SET lease_expires_at=now()-interval '1 second'
  WHERE job_id=job.job_id;
  accepted:=edr_complete_scan_job_with_result(
      'resultA','win01',job.job_id,token,'clean_by_signature','','');
  IF accepted THEN RAISE EXCEPTION 'expired lease verdict accepted'; END IF;
  IF EXISTS (SELECT 1 FROM edr_scan_job_results WHERE job_id=job.job_id) THEN
    RAISE EXCEPTION 'expired lease inserted verdict'; END IF;

  INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
  VALUES ('11111111-1111-4111-8111-111111111106','resultA','revoked','/lab/revoked');
  token:=gen_random_uuid();
  SELECT * INTO job FROM edr_claim_scan_job('resultA','revoked','revoked',token,60);
  IF job.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111106'::uuid THEN
    RAISE EXCEPTION 'revoked fixture claim failed'; END IF;
  UPDATE edr_agents SET revoked_at=now()
  WHERE tenant_id='resultA' AND agent_id='revoked';
  accepted:=edr_complete_scan_job_with_result(
      'resultA','revoked',job.job_id,token,'malicious','Lab-Signature','');
  IF accepted THEN RAISE EXCEPTION 'revoked device verdict accepted'; END IF;
  IF EXISTS (SELECT 1 FROM edr_scan_job_results WHERE job_id=job.job_id) THEN
    RAISE EXCEPTION 'revoked device inserted verdict'; END IF;
END $regression$;
ROLLBACK;
