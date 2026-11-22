\set ON_ERROR_STOP on
SELECT set_config('edr.test_expected_login', :'expected_login', false) AS expected_login \gset
DO $flow$
DECLARE
  scheduled record;
  claimed record;
  case_id uuid;
  note_id uuid;
  bad_command text;
  denied_count integer:=0;
BEGIN
  IF current_user<>current_setting('edr.test_expected_login')
     OR session_user<>current_setting('edr.test_expected_login')
     OR current_user='edr_api_functions' THEN
    RAISE EXCEPTION 'test is not connected as the actual restricted runtime login';
  END IF;
  -- The DO statement is one transaction: authorization locks remain held
  -- throughout the following mutations, exactly as the Go transaction wrapper.
  IF NOT public.edr_authorize_agent_certificate('grantA','linux01',decode(repeat('ab',32),'hex'))
     OR NOT public.edr_authorize_operator_certificate('grantA','scanner',decode(repeat('a1',32),'hex'),'scanner') THEN
    RAISE EXCEPTION 'exact certificate/role authorization failed';
  END IF;
  IF public.edr_authorize_agent_certificate('grantA','linux01',decode(repeat('ac',32),'hex'))
     OR public.edr_authorize_agent_certificate('grantA','linux01',decode('ab','hex'))
     OR public.edr_authorize_agent_certificate('grantA','linux01',NULL)
     OR public.edr_authorize_agent_certificate('grantB','linux01',decode(repeat('ab',32),'hex'))
     OR public.edr_authorize_agent_certificate('grantA','expired',decode(repeat('c1',32),'hex'))
     OR public.edr_authorize_agent_certificate('grantA','future',decode(repeat('c2',32),'hex'))
     OR public.edr_authorize_operator_certificate('grantA','scanner',decode(repeat('a1',32),'hex'),'viewer')
     OR public.edr_authorize_operator_certificate('grantA','scanner',decode(repeat('af',32),'hex'),'scanner')
     OR public.edr_authorize_operator_certificate('grantA','scanner',decode('a1','hex'),'scanner')
     OR public.edr_authorize_operator_certificate('grantA','revoked',decode(repeat('d4',32),'hex'),'scanner')
     OR public.edr_authorize_operator_certificate('grantDisabled','scanner',decode(repeat('f6',32),'hex'),'scanner') THEN
    RAISE EXCEPTION 'invalid, expired, future, cross-tenant or changed principal authorized';
  END IF;
  IF NOT public.edr_record_agent_heartbeat('grantA','linux01','linux','test-agent','test-clamav','test-db',true) THEN
    RAISE EXCEPTION 'runtime heartbeat failed';
  END IF;
  IF (SELECT received_count FROM public.edr_agent_heartbeats WHERE tenant_id='grantA' AND agent_id='linux01')<>1 THEN
    RAISE EXCEPTION 'runtime heartbeat was not persisted';
  END IF;
  IF public.edr_record_agent_heartbeat('grantDisabled','linux01','linux','test-agent','','',true)
     OR public.edr_record_agent_heartbeat('grantA','revoked','linux','test-agent','','',true) THEN
    RAISE EXCEPTION 'disabled/revoked principal wrote a heartbeat';
  END IF;
  SELECT * INTO scheduled FROM public.edr_enqueue_operator_scan_job(
    'grantA','viewer','linux01','11111111-1111-4111-8111-111111111111','grant-one','/tmp/fixture');
  IF FOUND THEN RAISE EXCEPTION 'viewer scheduled a scan'; END IF;
  SELECT * INTO scheduled FROM public.edr_enqueue_operator_scan_job(
    'grantA','revoked','linux01','11111111-1111-4111-8111-111111111111','grant-one','/tmp/fixture');
  IF FOUND THEN RAISE EXCEPTION 'revoked operator scheduled a scan'; END IF;
  SELECT * INTO scheduled FROM public.edr_enqueue_operator_scan_job(
    'grantDisabled','scanner','linux01','11111111-1111-4111-8111-111111111111','grant-one','/tmp/fixture');
  IF FOUND THEN RAISE EXCEPTION 'disabled tenant scheduled a scan'; END IF;
  SELECT * INTO scheduled FROM public.edr_enqueue_operator_scan_job(
    'grantA','scanner','linux01','11111111-1111-4111-8111-111111111111','grant-one','/tmp/fixture');
  IF scheduled.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111111'::uuid
     OR scheduled.created IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'runtime schedule failed';
  END IF;
  -- The SOC count(*) query must work with column-only jobs SELECT privileges.
  IF (SELECT count(*) FROM public.edr_scan_jobs WHERE tenant_id='grantA')<>1 THEN
    RAISE EXCEPTION 'restricted SOC jobs read failed';
  END IF;
  SELECT * INTO claimed FROM public.edr_claim_scan_job(
    'grantB','linux01','linux01','22222222-2222-4222-8222-222222222222',60);
  IF FOUND THEN RAISE EXCEPTION 'other tenant claimed the job'; END IF;
  SELECT * INTO claimed FROM public.edr_claim_scan_job(
    'grantA','linux01','linux01','22222222-2222-4222-8222-222222222222',60);
  IF claimed.job_id IS DISTINCT FROM scheduled.job_id OR claimed.attempt_count<>1 THEN
    RAISE EXCEPTION 'runtime claim failed';
  END IF;
  IF NOT public.edr_renew_scan_job_lease('grantA','linux01',claimed.job_id,'linux01',
      '22222222-2222-4222-8222-222222222222',60) THEN
    RAISE EXCEPTION 'runtime renew failed';
  END IF;
  IF public.edr_complete_scan_job_with_result('grantB','linux01',claimed.job_id,
      '22222222-2222-4222-8222-222222222222','malicious','Synthetic-Test-Signature','') THEN
    RAISE EXCEPTION 'cross-tenant completion succeeded';
  END IF;
  IF NOT public.edr_complete_scan_job_with_result('grantA','linux01',claimed.job_id,
      '22222222-2222-4222-8222-222222222222','malicious','Synthetic-Test-Signature','') THEN
    RAISE EXCEPTION 'runtime result completion failed';
  END IF;
  IF public.edr_complete_scan_job_with_result('grantA','linux01',claimed.job_id,
      '22222222-2222-4222-8222-222222222222','malicious','Synthetic-Test-Signature','') THEN
    RAISE EXCEPTION 'result replay succeeded';
  END IF;
  SELECT alert_id INTO case_id FROM public.edr_soc_alerts
    WHERE tenant_id='grantA' AND job_id=claimed.job_id;
  IF case_id IS NULL OR NOT EXISTS (SELECT 1 FROM public.edr_soc_alert_activity
    WHERE tenant_id='grantA' AND alert_id=case_id AND action='created' AND actor_id='system') THEN
    RAISE EXCEPTION 'nested result-to-alert-to-activity triggers failed';
  END IF;
  IF public.edr_soc_assign_alert('grantB','scanner',case_id,'scanner')
     OR public.edr_soc_assign_alert('grantA','viewer',case_id,'investigator') THEN
    RAISE EXCEPTION 'cross-tenant/viewer case assignment succeeded';
  END IF;
  IF NOT public.edr_soc_assign_alert('grantA','scanner',case_id,'investigator') THEN
    RAISE EXCEPTION 'runtime assignment failed';
  END IF;
  note_id:=public.edr_soc_add_alert_note('grantA','investigator',case_id,'Synthetic case review evidence');
  IF note_id IS NULL THEN RAISE EXCEPTION 'runtime case note failed'; END IF;
  IF NOT public.edr_soc_change_alert_state('grantA','investigator',case_id,'ack','')
     OR NOT public.edr_soc_change_alert_state('grantA','investigator',case_id,'resolve','Synthetic review complete')
     OR NOT public.edr_soc_change_alert_state('grantA','scanner',case_id,'reopen','') THEN
    RAISE EXCEPTION 'runtime case transitions failed';
  END IF;
  IF (SELECT count(*) FROM public.edr_soc_alert_activity WHERE tenant_id='grantA' AND alert_id=case_id)<>6 THEN
    RAISE EXCEPTION 'expected six attributed case activity rows';
  END IF;
  SELECT * INTO scheduled FROM public.edr_enqueue_operator_scan_job(
    'grantA','scanner','linux01','33333333-3333-4333-8333-333333333333','grant-cancel','/tmp/fixture');
  IF NOT public.edr_cancel_operator_scan_job('grantA','scanner',scheduled.job_id) THEN
    RAISE EXCEPTION 'runtime cancel failed';
  END IF;

  FOREACH bad_command IN ARRAY ARRAY[
    'UPDATE public.edr_tenants SET disabled_at=NULL',
    'UPDATE public.edr_agents SET revoked_at=NULL',
    'UPDATE public.edr_agents SET platform=''windows''',
    'UPDATE public.edr_soc_operators SET role=''scanner''',
    'UPDATE public.edr_soc_operators SET fingerprint_sha256=decode(repeat(''ff'',32),''hex'')',
    'UPDATE public.edr_agent_certificates SET revoked_at=NULL',
    'UPDATE public.edr_tenants SET runtime_lock=false',
    'INSERT INTO public.edr_scan_jobs(job_id,tenant_id,agent_id,scan_root) VALUES(gen_random_uuid(),''grantA'',''linux01'',''/tmp/forged'')',
    'UPDATE public.edr_scan_jobs SET state=''pending''',
    'INSERT INTO public.edr_scan_job_results(job_id,tenant_id,agent_id,engine,verdict) VALUES(gen_random_uuid(),''grantA'',''linux01'',''clamav'',''clean_by_signature'')',
    'UPDATE public.edr_scan_job_results SET verdict=''clean_by_signature''',
    'INSERT INTO public.edr_soc_alert_activity(tenant_id,alert_id,actor_id,action,note) SELECT tenant_id,alert_id,''forged'',''note'',''forged'' FROM public.edr_soc_alerts',
    'UPDATE public.edr_soc_alert_activity SET note=''forged''',
    'DELETE FROM public.edr_soc_alert_activity',
    'TRUNCATE public.edr_soc_alert_activity',
    'ALTER TABLE public.edr_soc_alert_activity DISABLE TRIGGER ALL',
    'ALTER FUNCTION public.edr_claim_scan_job(varchar,varchar,text,uuid,integer) SECURITY INVOKER',
    'CREATE TABLE public.edr_forbidden_test(id integer)',
    'CREATE TEMP TABLE edr_forbidden_temp(id integer)',
    'CREATE SCHEMA edr_forbidden_schema',
    'SET ROLE edr_api_functions',
    'SET ROLE edr_identity_ro',
    'SET SESSION AUTHORIZATION edr_api_functions',
    'SELECT public.edr_recover_expired_scan_jobs(1)',
    'SELECT public.edr_complete_scan_job(''grantA'',''linux01'',''11111111-1111-4111-8111-111111111111'',''22222222-2222-4222-8222-222222222222'',true)',
    'SELECT public.edr_rotate_agent_certificate(''grantA'',''linux01'',decode(repeat(''ab'',32),''hex''),decode(repeat(''cd'',32),''hex''),now()-interval ''1 minute'',now()+interval ''1 day'',''forged'')',
    'SELECT public.edr_revoke_agent_certificate(''grantA'',''linux01'',decode(repeat(''ab'',32),''hex''),''forged'',''forged'')',
    'SELECT lease_token FROM public.edr_scan_jobs',
    'SELECT lease_owner FROM public.edr_scan_jobs',
    'SELECT lease_expires_at FROM public.edr_scan_jobs',
    'SELECT fingerprint_sha256 FROM public.edr_agent_certificates',
    'SELECT * FROM public.edr_scan_jobs',
    'UPDATE public.edr_schema_capabilities SET version=2',
    'INSERT INTO public.edr_schema_capabilities(capability,version) VALUES(''forged'',1)',
    'TRUNCATE public.edr_schema_capabilities'
  ] LOOP
    BEGIN
      EXECUTE bad_command;
      RAISE EXCEPTION 'forbidden runtime operation succeeded: %',bad_command;
    EXCEPTION WHEN insufficient_privilege THEN denied_count:=denied_count+1;
    END;
  END LOOP;
  RAISE NOTICE 'PASS: actual runtime login completed nested lifecycle and % forbidden operations were denied',denied_count;
END;
$flow$;
