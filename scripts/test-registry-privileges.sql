\set ON_ERROR_STOP on
SELECT set_config('edr.test_expected_login', :'expected_login', false) AS expected_login \gset
DO $registry$
DECLARE
  bad_command text;
  denied_count integer:=0;
BEGIN
  IF current_user<>current_setting('edr.test_expected_login')
     OR session_user<>current_setting('edr.test_expected_login')
     OR current_setting('transaction_read_only')<>'on' THEN
    RAISE EXCEPTION 'registry connection is not the expected readonly login';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.edr_agent_certificates c
    JOIN public.edr_agents a ON a.tenant_id=c.tenant_id AND a.agent_id=c.agent_id
    JOIN public.edr_tenants t ON t.tenant_id=c.tenant_id
    WHERE c.tenant_id='grantA' AND c.agent_id='linux01'
      AND c.revoked_at IS NULL AND a.revoked_at IS NULL AND t.disabled_at IS NULL
      AND c.not_before<=now() AND c.not_after>now()
      AND octet_length(c.fingerprint_sha256)=32
  ) OR NOT EXISTS (SELECT 1 FROM public.edr_soc_operators o
    JOIN public.edr_tenants t ON t.tenant_id=o.tenant_id
    WHERE o.tenant_id='grantA' AND o.operator_id='scanner'
      AND o.revoked_at IS NULL AND t.disabled_at IS NULL) THEN
    RAISE EXCEPTION 'readonly registry lookup failed';
  END IF;
  FOREACH bad_command IN ARRAY ARRAY[
    'UPDATE public.edr_tenants SET disabled_at=NULL',
    'UPDATE public.edr_agents SET revoked_at=NULL',
    'UPDATE public.edr_agent_certificates SET revoked_at=NULL',
    'UPDATE public.edr_soc_operators SET role=''scanner''',
    'SELECT tenant_id FROM public.edr_tenants FOR SHARE',
    'SELECT public.edr_record_agent_heartbeat(''grantA'',''linux01'',''linux'',''test'','''','''',true)',
    'SELECT * FROM public.edr_claim_scan_job(''grantA'',''linux01'',''linux01'',''22222222-2222-4222-8222-222222222222'',60)',
    'SELECT public.edr_authorize_agent_certificate(''grantA'',''linux01'',decode(repeat(''ab'',32),''hex''))',
    'SELECT public.edr_authorize_operator_certificate(''grantA'',''scanner'',decode(repeat(''a1'',32),''hex''),''scanner'')',
    'SELECT * FROM public.edr_scan_job_results',
    'SELECT * FROM public.edr_soc_alert_activity',
    'SET ROLE edr_runtime',
    'SET ROLE edr_api_functions',
    'CREATE TEMP TABLE edr_forbidden_registry_temp(id integer)',
    'UPDATE public.edr_schema_capabilities SET version=2',
    'INSERT INTO public.edr_schema_capabilities(capability,version) VALUES(''forged'',1)',
    'TRUNCATE public.edr_schema_capabilities'
  ] LOOP
    BEGIN
      EXECUTE bad_command;
      RAISE EXCEPTION 'forbidden registry operation succeeded: %',bad_command;
    EXCEPTION WHEN insufficient_privilege OR read_only_sql_transaction THEN denied_count:=denied_count+1;
    END;
  END LOOP;
  RAISE NOTICE 'PASS: actual readonly registry login resolved both identities and % forbidden operations were denied',denied_count;
END;
$registry$;
