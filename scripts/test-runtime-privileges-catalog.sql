\set ON_ERROR_STOP on
SELECT set_config('edr.test_runtime', :'runtime_login', false) AS test_runtime \gset
SELECT set_config('edr.test_registry', :'registry_login', false) AS test_registry \gset
DO $catalog$
DECLARE
  item record;
  candidate text;
  table_name text;
  expected_count integer := 0;
  runtime_name text := current_setting('edr.test_runtime');
  registry_name text := current_setting('edr.test_registry');
  signatures text[] := ARRAY[
    'public.edr_authorize_agent_certificate(varchar,varchar,bytea)',
    'public.edr_authorize_operator_certificate(varchar,varchar,bytea,text)',
    'public.edr_claim_scan_job(varchar,varchar,text,uuid,integer)',
    'public.edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer)',
    'public.edr_complete_scan_job_with_result(varchar,varchar,uuid,uuid,text,text,text)',
    'public.edr_record_agent_heartbeat(varchar,varchar,text,varchar,varchar,varchar,boolean)',
    'public.edr_enqueue_operator_scan_job(varchar,varchar,varchar,uuid,varchar,text)',
    'public.edr_cancel_operator_scan_job(varchar,varchar,uuid)',
    'public.edr_soc_change_alert_state(varchar,varchar,uuid,text,text)',
    'public.edr_soc_assign_alert(varchar,varchar,uuid,varchar)',
    'public.edr_soc_add_alert_note(varchar,varchar,uuid,text)'
  ];
BEGIN
  FOR item IN SELECT p.*,r.rolname,n.nspname
    FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
    JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND left(p.proname,4)='edr_'
  LOOP
    IF item.oid=ANY(ARRAY(SELECT to_regprocedure(s)::oid FROM unnest(signatures) s)) THEN
      expected_count:=expected_count+1;
      IF NOT item.prosecdef OR item.rolname<>'edr_api_functions'
         OR NOT ('search_path=pg_catalog, public, pg_temp'=ANY(item.proconfig))
         OR NOT has_function_privilege(runtime_name,item.oid,'EXECUTE') THEN
        RAISE EXCEPTION 'runtime function configuration is unsafe: %',item.proname;
      END IF;
    ELSIF has_function_privilege(runtime_name,item.oid,'EXECUTE') THEN
      RAISE EXCEPTION 'runtime can execute an administrative/internal function: %',item.proname;
    END IF;
    IF has_function_privilege(registry_name,item.oid,'EXECUTE') THEN
      RAISE EXCEPTION 'registry can execute a mutation/internal function: %',item.proname;
    END IF;
    IF EXISTS (SELECT 1 FROM aclexplode(COALESCE(item.proacl,acldefault('f',item.proowner)))
      WHERE grantee=0 AND privilege_type='EXECUTE') THEN
      RAISE EXCEPTION 'PUBLIC can execute an EDR function: %',item.proname;
    END IF;
  END LOOP;
  IF expected_count<>11 THEN RAISE EXCEPTION 'expected exactly eleven runtime functions'; END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
    WHERE r.rolname='edr_api_functions'
      AND NOT (p.oid=ANY(ARRAY(SELECT to_regprocedure(s)::oid FROM unnest(signatures) s)))) THEN
    RAISE EXCEPTION 'function-owner owns unreviewed routines';
  END IF;

  FOREACH candidate IN ARRAY ARRAY['edr_runtime','edr_identity_ro','edr_api_functions',runtime_name,registry_name] LOOP
    SELECT * INTO STRICT item FROM pg_roles WHERE rolname=candidate;
    IF item.rolsuper OR item.rolcreatedb OR item.rolcreaterole OR item.rolreplication OR item.rolbypassrls
       OR (candidate IN ('edr_runtime','edr_identity_ro','edr_api_functions') AND item.rolcanlogin) THEN
      RAISE EXCEPTION 'unsafe role attributes: %',candidate;
    END IF;
    IF has_schema_privilege(candidate,'public','CREATE')
       OR has_database_privilege(candidate,current_database(),'CREATE')
       OR has_database_privilege(candidate,current_database(),'TEMPORARY')
       OR EXISTS (SELECT 1 FROM pg_class WHERE relowner=item.oid)
       OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner=item.oid) THEN
      RAISE EXCEPTION 'role has DDL/temporary/ownership authority: %',candidate;
    END IF;
    IF candidate<>'edr_api_functions' AND pg_has_role(candidate,'edr_api_functions','MEMBER') THEN
      RAISE EXCEPTION 'application can assume function-owner role: %',candidate;
    END IF;
  END LOOP;
  FOREACH candidate IN ARRAY ARRAY[runtime_name,registry_name,'edr_api_functions'] LOOP
    IF has_column_privilege(candidate,'public.edr_tenants','disabled_at','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agents','revoked_at','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agents','platform','UPDATE')
       OR has_column_privilege(candidate,'public.edr_soc_operators','role','UPDATE')
       OR has_column_privilege(candidate,'public.edr_soc_operators','fingerprint_sha256','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agent_certificates','fingerprint_sha256','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agent_certificates','not_before','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agent_certificates','not_after','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agent_certificates','revoked_at','UPDATE')
       OR has_column_privilege(candidate,'public.edr_agent_certificates','revoke_reason','UPDATE') THEN
      RAISE EXCEPTION 'role can change identity trust fields: %',candidate;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY['edr_tenants','edr_agents','edr_agent_certificates','edr_soc_operators'] LOOP
    IF NOT has_column_privilege('edr_api_functions','public.'||table_name,'runtime_lock','UPDATE')
       OR has_column_privilege(runtime_name,'public.'||table_name,'runtime_lock','UPDATE')
       OR has_column_privilege(registry_name,'public.'||table_name,'runtime_lock','UPDATE') THEN
      RAISE EXCEPTION 'lock-column privilege boundary is wrong: %',table_name;
    END IF;
  END LOOP;
  FOR item IN SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND left(c.relname,4)='edr_' AND c.relkind='r'
  LOOP
    FOREACH candidate IN ARRAY ARRAY[runtime_name,registry_name] LOOP
      IF has_any_column_privilege(candidate,item.oid,'INSERT')
         OR has_any_column_privilege(candidate,item.oid,'UPDATE')
         OR has_table_privilege(candidate,item.oid,'DELETE')
         OR has_table_privilege(candidate,item.oid,'TRUNCATE')
         OR has_table_privilege(candidate,item.oid,'TRIGGER') THEN
        RAISE EXCEPTION 'application has direct write/trigger privilege: %/%',candidate,item.relname;
      END IF;
    END LOOP;
  END LOOP;
  IF has_column_privilege(runtime_name,'public.edr_scan_jobs','lease_token','SELECT')
     OR has_column_privilege(runtime_name,'public.edr_scan_jobs','lease_owner','SELECT')
     OR has_column_privilege(runtime_name,'public.edr_scan_jobs','lease_expires_at','SELECT')
     OR has_column_privilege(runtime_name,'public.edr_agent_certificates','fingerprint_sha256','SELECT')
     OR NOT has_column_privilege(registry_name,'public.edr_agent_certificates','fingerprint_sha256','SELECT') THEN
    RAISE EXCEPTION 'runtime/registry sensitive-read separation is wrong';
  END IF;
  IF (SELECT version FROM public.edr_schema_capabilities WHERE capability='scan_lease_wallclock') IS DISTINCT FROM 1
     OR (SELECT version FROM public.edr_schema_capabilities WHERE capability='enrollment_wallclock') IS DISTINCT FROM 1
     OR NOT has_table_privilege(runtime_name,'public.edr_schema_capabilities','SELECT')
     OR NOT has_table_privilege(registry_name,'public.edr_schema_capabilities','SELECT')
     OR has_table_privilege('edr_api_functions','public.edr_schema_capabilities','SELECT') THEN
    RAISE EXCEPTION 'required admin-owned clock capabilities or their read-only grants are wrong';
  END IF;
  RAISE NOTICE 'PASS: exact function allowlist, safe owners/search paths, no PUBLIC mutation execution, least-privilege role catalog';
END;
$catalog$;
