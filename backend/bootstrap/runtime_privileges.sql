-- Operator bootstrap for a DEDICATED EDR database after migrations 0001..0013.
-- This is intentionally separate from portable schema migrations: PostgreSQL
-- roles are cluster-wide and login authentication belongs to the operator.
-- Required psql variables: runtime_login, registry_login, dedicated_edr_database.
-- Both logins must already exist, be distinct, and be unprivileged.
-- No passwords, certificates, or connection strings belong in this file.
\set ON_ERROR_STOP on
\set ECHO none
\if :{?runtime_login}
\else
  \echo 'ERROR: runtime_login must name an existing dedicated application login'
  \quit 2
\endif
\if :{?registry_login}
\else
  \echo 'ERROR: registry_login must name a different existing readonly login'
  \quit 2
\endif
\if :{?dedicated_edr_database}
  \if :dedicated_edr_database
  \else
    \echo 'ERROR: this bootstrap is only for a dedicated EDR database'
    \quit 2
  \endif
\else
  \echo 'ERROR: set dedicated_edr_database=true after verifying the target database'
  \quit 2
\endif

BEGIN;
SET LOCAL search_path = pg_catalog, public, pg_temp;
SELECT set_config('edr.bootstrap_runtime_login', :'runtime_login', true) AS bootstrap_runtime \gset
SELECT set_config('edr.bootstrap_registry_login', :'registry_login', true) AS bootstrap_registry \gset

DO $roles$
DECLARE
  role_name text;
  item record;
  runtime_name text := current_setting('edr.bootstrap_runtime_login');
  registry_name text := current_setting('edr.bootstrap_registry_login');
BEGIN
  IF current_database() IN ('postgres', 'template0', 'template1') THEN
    RAISE EXCEPTION 'refusing bootstrap in a PostgreSQL administrative database';
  END IF;
  IF runtime_name = registry_name OR runtime_name = current_user
     OR registry_name = current_user
     OR runtime_name IN ('edr_runtime', 'edr_identity_ro', 'edr_api_functions')
     OR registry_name IN ('edr_runtime', 'edr_identity_ro', 'edr_api_functions') THEN
    RAISE EXCEPTION 'two distinct dedicated unprivileged login roles are required';
  END IF;
  IF to_regclass('public.edr_soc_alert_activity') IS NULL THEN
    RAISE EXCEPTION 'apply migrations 0001 through 0013 before runtime bootstrap';
  END IF;
  IF to_regclass('public.edr_schema_capabilities') IS NULL THEN
    RAISE EXCEPTION 'apply migration 0013 before runtime bootstrap';
  END IF;
  IF (SELECT version FROM public.edr_schema_capabilities
      WHERE capability='scan_lease_wallclock') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'required scan_lease_wallclock capability version 1 is absent';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_proc
      WHERE oid=ANY(ARRAY[
        to_regprocedure('public.edr_claim_scan_job(varchar,varchar,text,uuid,integer)'),
        to_regprocedure('public.edr_complete_scan_job(varchar,varchar,uuid,uuid,boolean)'),
        to_regprocedure('public.edr_recover_expired_scan_jobs(integer)'),
        to_regprocedure('public.edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer)'),
        to_regprocedure('public.edr_complete_scan_job_with_result(varchar,varchar,uuid,uuid,text,text,text)')
      ]::oid[])
      AND strpos(prosrc,'clock_timestamp()')>0
      AND strpos(prosrc,'transaction_timestamp()')=0)<>5 THEN
    RAISE EXCEPTION 'installed lease functions lack the 0013 wall-clock correction';
  END IF;

  FOREACH role_name IN ARRAY ARRAY['edr_runtime','edr_identity_ro','edr_api_functions'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      BEGIN
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', role_name);
      EXCEPTION WHEN duplicate_object THEN NULL;
      END;
    END IF;
    SELECT * INTO STRICT item FROM pg_roles WHERE rolname=role_name;
    IF item.rolcanlogin OR item.rolsuper OR item.rolcreatedb OR item.rolcreaterole
       OR item.rolreplication OR item.rolbypassrls
       OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=item.oid) THEN
      RAISE EXCEPTION 'existing EDR privilege role has unsafe attributes or memberships: %', role_name;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relowner=item.oid)
       OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner=item.oid)
       OR EXISTS (SELECT 1 FROM pg_database WHERE datdba=item.oid)
       OR (role_name<>'edr_api_functions' AND EXISTS (SELECT 1 FROM pg_proc WHERE proowner=item.oid)) THEN
      RAISE EXCEPTION 'EDR privilege roles have unexpected object ownership: %', role_name;
    END IF;
  END LOOP;

  FOREACH role_name IN ARRAY ARRAY[runtime_name,registry_name] LOOP
    SELECT * INTO item FROM pg_roles WHERE rolname=role_name;
    IF NOT FOUND OR NOT item.rolcanlogin OR NOT item.rolinherit
       OR item.rolsuper OR item.rolcreatedb OR item.rolcreaterole
       OR item.rolreplication OR item.rolbypassrls THEN
      RAISE EXCEPTION 'dedicated login must exist with LOGIN INHERIT and no administrative attributes: %', role_name;
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid
      WHERE m.member=item.oid AND (m.admin_option OR parent.rolname <>
        CASE WHEN role_name=runtime_name THEN 'edr_runtime' ELSE 'edr_identity_ro' END)
    ) OR EXISTS (SELECT 1 FROM pg_class WHERE relowner=item.oid)
      OR EXISTS (SELECT 1 FROM pg_proc WHERE proowner=item.oid)
      OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner=item.oid)
      OR EXISTS (SELECT 1 FROM pg_database WHERE datdba=item.oid) THEN
      RAISE EXCEPTION 'dedicated logins must have no unrelated memberships or owned database objects: %', role_name;
    END IF;
  END LOOP;
END;
$roles$;

-- Row-lock privilege only. No application operation changes these constants.
-- PostgreSQL FOR SHARE needs UPDATE on one column; trust fields remain denied.
DO $locks$
DECLARE
  table_name text;
  constraint_name text;
  column_item record;
  constraint_definition text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['edr_tenants','edr_agents','edr_agent_certificates','edr_soc_operators'] LOOP
    EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS runtime_lock boolean NOT NULL DEFAULT false', table_name);
    SELECT a.atttypid,a.attnotnull,pg_get_expr(d.adbin,d.adrelid) AS default_value
      INTO STRICT column_item
      FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
      WHERE a.attrelid=format('public.%I',table_name)::regclass
        AND a.attname='runtime_lock' AND NOT a.attisdropped;
    IF column_item.atttypid <> 'boolean'::regtype OR NOT column_item.attnotnull
       OR column_item.default_value IS DISTINCT FROM 'false' THEN
      RAISE EXCEPTION 'unexpected preexisting runtime_lock column on %', table_name;
    END IF;
    constraint_name := table_name || '_runtime_lock_constant';
    SELECT pg_get_constraintdef(oid) INTO constraint_definition
      FROM pg_constraint WHERE conrelid=format('public.%I',table_name)::regclass
        AND conname=constraint_name;
    IF NOT FOUND THEN
      EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (runtime_lock = false)', table_name,constraint_name);
    ELSIF constraint_definition IS DISTINCT FROM 'CHECK ((runtime_lock = false))' THEN
      RAISE EXCEPTION 'unexpected preexisting lock constraint on %', table_name;
    END IF;
  END LOOP;
END;
$locks$;

-- A trusted schema and explicit pg_temp-last path prevent object masking.
-- Revoking PUBLIC TEMP affects this dedicated database only.
REVOKE CREATE ON SCHEMA public FROM PUBLIC,edr_runtime,edr_identity_ro,edr_api_functions;
GRANT USAGE ON SCHEMA public TO edr_runtime,edr_identity_ro,edr_api_functions;
DO $reset$
DECLARE
  relation_item record;
  routine_item record;
  runtime_name text := current_setting('edr.bootstrap_runtime_login');
  registry_name text := current_setting('edr.bootstrap_registry_login');
BEGIN
  EXECUTE format('REVOKE CREATE,TEMPORARY ON DATABASE %I FROM PUBLIC,edr_runtime,edr_identity_ro,edr_api_functions,%I,%I',current_database(),runtime_name,registry_name);
  EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I,%I',runtime_name,registry_name);
  FOR relation_item IN
    SELECT c.oid::regclass AS object_name,c.relkind FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND left(c.relname,4)='edr_' AND c.relkind IN ('r','p','v','m','S')
  LOOP
    -- ALL is revoked explicitly, including any previous column grants below.
    IF relation_item.relkind='S' THEN
      EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC,edr_runtime,edr_identity_ro,edr_api_functions,%I,%I',relation_item.object_name,runtime_name,registry_name);
    ELSE
      EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC,edr_runtime,edr_identity_ro,edr_api_functions,%I,%I',relation_item.object_name,runtime_name,registry_name);
      EXECUTE (
        SELECT format('REVOKE ALL (%s) ON TABLE %s FROM PUBLIC,edr_runtime,edr_identity_ro,edr_api_functions,%I,%I',
          string_agg(quote_ident(attname),','),relation_item.object_name,runtime_name,registry_name)
        FROM pg_attribute WHERE attrelid=relation_item.object_name::oid AND attnum>0 AND NOT attisdropped
      );
    END IF;
  END LOOP;
  FOR routine_item IN
    SELECT p.oid::regprocedure AS signature FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND left(p.proname,4)='edr_'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,edr_runtime,edr_identity_ro,edr_api_functions,%I,%I',routine_item.signature,runtime_name,registry_name);
  END LOOP;
END;
$reset$;

GRANT SELECT ON public.edr_tenants,public.edr_agents,
  public.edr_agent_certificates,public.edr_soc_operators TO edr_identity_ro;
GRANT SELECT ON public.edr_schema_capabilities TO edr_identity_ro,edr_runtime;
GRANT SELECT ON public.edr_tenants,public.edr_agents,public.edr_agent_heartbeats,
  public.edr_scan_job_results,public.edr_soc_alerts,public.edr_soc_alert_activity
  TO edr_runtime;
-- Runtime SQL reads do not need any lease token/owner/expiry column.
GRANT SELECT (job_id,tenant_id,agent_id,scan_root,state,created_at,updated_at,
  attempt_count,max_attempts,request_key,created_by_operator)
  ON public.edr_scan_jobs TO edr_runtime;

GRANT SELECT ON public.edr_tenants,public.edr_agents,public.edr_agent_certificates,public.edr_soc_operators,
  public.edr_scan_jobs,public.edr_scan_job_results,public.edr_agent_heartbeats,
  public.edr_soc_alerts,public.edr_soc_alert_activity TO edr_api_functions;
GRANT UPDATE (runtime_lock) ON public.edr_tenants,public.edr_agents,
  public.edr_agent_certificates,public.edr_soc_operators TO edr_api_functions;
GRANT INSERT (job_id,tenant_id,agent_id,scan_root,request_key,created_by_operator),
  UPDATE (state,lease_owner,lease_token,lease_expires_at,attempt_count,updated_at)
  ON public.edr_scan_jobs TO edr_api_functions;
GRANT INSERT (job_id,tenant_id,agent_id,engine,verdict,threat_name,detail)
  ON public.edr_scan_job_results TO edr_api_functions;
GRANT INSERT (tenant_id,agent_id,platform,agent_version,clamav_version,signature_version,scan_ready),
  UPDATE (platform,agent_version,clamav_version,signature_version,scan_ready,last_seen,received_count)
  ON public.edr_agent_heartbeats TO edr_api_functions;
GRANT INSERT (job_id,tenant_id,agent_id,signature_name),
  UPDATE (state,updated_at,last_action_by,acknowledged_by,acknowledged_at,
    resolved_by,resolved_at,resolution_note,assigned_to)
  ON public.edr_soc_alerts TO edr_api_functions;
GRANT INSERT (tenant_id,alert_id,actor_id,action,note)
  ON public.edr_soc_alert_activity TO edr_api_functions;

-- These guards must execute in the SAME explicit transaction as the operation.
-- HTTP certificate validation alone cannot serialize a later SQL mutation with
-- certificate revocation/rotation or an operator-role change.
CREATE OR REPLACE FUNCTION public.edr_authorize_agent_certificate(
  p_tenant varchar,p_agent varchar,p_fingerprint bytea
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $agent_authorization$
DECLARE
  valid_from timestamptz;
  valid_until timestamptz;
  checked_at timestamptz;
BEGIN
  IF p_tenant IS NULL OR p_agent IS NULL OR p_fingerprint IS NULL
     OR octet_length(p_fingerprint)<>32 THEN
    RETURN false;
  END IF;
  -- Match the established rotation lock order: agent/tenant, then certificate.
  -- Locking the certificate first would invert rotation's agent-before-cert
  -- order and introduce an avoidable deadlock.
  PERFORM 1 FROM public.edr_agents AS a
    JOIN public.edr_tenants AS t ON t.tenant_id=a.tenant_id
    WHERE a.tenant_id=p_tenant AND a.agent_id=p_agent
      AND a.revoked_at IS NULL AND t.disabled_at IS NULL
    FOR SHARE OF a,t;
  IF NOT FOUND THEN RETURN false; END IF;

  SELECT c.not_before,c.not_after INTO valid_from,valid_until
    FROM public.edr_agent_certificates AS c
    WHERE c.tenant_id=p_tenant AND c.agent_id=p_agent
      AND c.fingerprint_sha256=p_fingerprint AND c.revoked_at IS NULL
    FOR SHARE OF c;
  IF NOT FOUND THEN RETURN false; END IF;
  -- Authorization linearizes here, after any conflicting admin lock wait.
  -- A transaction-start timestamp could accept a leaf that expired while
  -- waiting. The shared locks persist until the caller commits/rolls back.
  checked_at:=clock_timestamp();
  RETURN valid_from<=checked_at AND valid_until>checked_at;
END;
$agent_authorization$;

CREATE OR REPLACE FUNCTION public.edr_authorize_operator_certificate(
  p_tenant varchar,p_operator varchar,p_fingerprint bytea,p_role text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $operator_authorization$
BEGIN
  IF p_tenant IS NULL OR p_operator IS NULL OR p_fingerprint IS NULL
     OR octet_length(p_fingerprint)<>32 OR p_role IS NULL
     OR p_role NOT IN ('viewer','scanner') THEN
    RETURN false;
  END IF;
  PERFORM 1 FROM public.edr_soc_operators AS o
    JOIN public.edr_tenants AS t ON t.tenant_id=o.tenant_id
    WHERE o.tenant_id=p_tenant AND o.operator_id=p_operator
      AND o.fingerprint_sha256=p_fingerprint AND o.role=p_role
      AND o.revoked_at IS NULL AND t.disabled_at IS NULL
    FOR SHARE OF o,t;
  -- A successful locked-row match is the operator authorization
  -- linearization point; the existing role/fingerprint cannot change before
  -- the transaction finishes. TLS leaf validity is also enforced by Go.
  RETURN FOUND;
END;
$operator_authorization$;

-- Only these eleven functions cross the privilege boundary. Enrollment,
-- rotation, revocation, boolean-only completion and recovery stay admin-only.
-- The owner is not a table owner and receives CREATE only transactionally
-- while transferring function ownership; it is revoked before commit.
GRANT CREATE ON SCHEMA public TO edr_api_functions;
DO $functions$
DECLARE
  signature text;
  allowed_signatures text[] := ARRAY[
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
  FOREACH signature IN ARRAY allowed_signatures LOOP
    IF to_regprocedure(signature) IS NULL THEN
      RAISE EXCEPTION 'required runtime function is absent: %',signature;
    END IF;
    EXECUTE format('ALTER FUNCTION %s OWNER TO edr_api_functions',signature);
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',signature);
    EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp',signature);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,edr_identity_ro',signature);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO edr_runtime',signature);
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
    WHERE r.rolname='edr_api_functions'
      AND NOT (p.oid=ANY(ARRAY(SELECT to_regprocedure(s)::oid FROM unnest(allowed_signatures) s)))
  ) THEN
    RAISE EXCEPTION 'function-owner role owns routines outside the reviewed allowlist';
  END IF;
  -- Existing triggers remain invoker functions. Their inserts run under the
  -- constrained owner context of the outer operation, not elevated ownership.
  FOREACH signature IN ARRAY ARRAY[
    'public.edr_create_alert_from_malicious_result()',
    'public.edr_record_soc_alert_activity()',
    'public.edr_deny_scan_result_mutation()',
    'public.edr_deny_soc_alert_activity_mutation()'
  ] LOOP
    EXECUTE format('ALTER FUNCTION %s SECURITY INVOKER',signature);
    EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp',signature);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO edr_api_functions',signature);
  END LOOP;
END;
$functions$;
REVOKE CREATE ON SCHEMA public FROM edr_api_functions;

DO $logins$
DECLARE
  runtime_name text := current_setting('edr.bootstrap_runtime_login');
  registry_name text := current_setting('edr.bootstrap_registry_login');
BEGIN
  EXECUTE format('GRANT edr_runtime TO %I',runtime_name);
  EXECUTE format('GRANT edr_identity_ro TO %I',registry_name);
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I,%I',current_database(),runtime_name,registry_name);
  EXECUTE format('ALTER ROLE %I IN DATABASE %I SET search_path = pg_catalog, public, pg_temp',runtime_name,current_database());
  EXECUTE format('ALTER ROLE %I IN DATABASE %I SET search_path = pg_catalog, public, pg_temp',registry_name,current_database());
  EXECUTE format('ALTER ROLE %I IN DATABASE %I SET default_transaction_read_only = off',runtime_name,current_database());
  EXECUTE format('ALTER ROLE %I IN DATABASE %I SET default_transaction_read_only = on',registry_name,current_database());
END;
$logins$;

COMMIT;
\echo 'EDR runtime privileges applied; login authentication remains operator-managed.'
