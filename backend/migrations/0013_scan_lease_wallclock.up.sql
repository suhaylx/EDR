-- 0013: fresh wall-clock lease checks after authorization and job-row locks.
-- Apply as an authorized migration operator after 0012, with listeners drained.
-- Idempotent for both pre-bootstrap invoker and post-bootstrap definer installs.
-- CREATE OR REPLACE retains object OIDs, owners and ACLs. Explicitly preserve
-- SECURITY mode and all function-local settings as those would otherwise reset.
-- Only migration capability metadata is written; operational rows, role
-- memberships and existing function grants are unchanged.
BEGIN;
SET LOCAL search_path = pg_catalog, public, pg_temp;
DO $lease_upgrade$
DECLARE
  signatures text[] := ARRAY[
    'public.edr_claim_scan_job(varchar,varchar,text,uuid,integer)',
    'public.edr_complete_scan_job(varchar,varchar,uuid,uuid,boolean)',
    'public.edr_recover_expired_scan_jobs(integer)',
    'public.edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer)',
    'public.edr_complete_scan_job_with_result(varchar,varchar,uuid,uuid,text,text,text)'
  ];
  definitions text[] := ARRAY[
    $definition_0$
CREATE OR REPLACE FUNCTION public.edr_claim_scan_job(
    p_tenant_id varchar, p_agent_id varchar, p_lease_owner text,
    p_lease_token uuid, p_lease_seconds integer
) RETURNS TABLE(job_id uuid, scan_root text, attempt_count integer)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE
    picked_job uuid;
    leased_at timestamptz;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_lease_owner IS NULL OR length(p_lease_owner) NOT BETWEEN 1 AND 256
       OR p_lease_token IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'invalid lease parameters' USING ERRCODE='invalid_parameter_value';
    END IF;
    -- Serialize claim authorization with concurrent device revocation and
    -- tenant disablement. A snapshot-only JOIN on these tables is unsafe:
    -- an in-flight revoke could otherwise commit before the claim returns.
    -- SHARE locks permit concurrent claims while blocking administrative
    -- UPDATE/DELETE until this short claim transaction finishes.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant_id AND a.agent_id=p_agent_id
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
    FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT j.job_id INTO picked_job FROM public.edr_scan_jobs AS j
        JOIN public.edr_agents AS a
          ON a.tenant_id=j.tenant_id AND a.agent_id=j.agent_id
        JOIN public.edr_tenants AS t ON t.tenant_id=j.tenant_id
        WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id
          AND a.revoked_at IS NULL AND t.disabled_at IS NULL
          AND j.state='pending' AND j.attempt_count < j.max_attempts
        ORDER BY j.created_at, j.job_id
        FOR UPDATE OF j SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    -- Start the full lease after authorization/pick locks, never at BEGIN.
    leased_at:=clock_timestamp();
    RETURN QUERY
    UPDATE public.edr_scan_jobs AS j
    SET state='leased', lease_owner=p_lease_owner, lease_token=p_lease_token,
        lease_expires_at=leased_at+make_interval(secs=>p_lease_seconds),
        attempt_count=j.attempt_count+1, updated_at=leased_at
    WHERE j.job_id=picked_job
    RETURNING j.job_id,j.scan_root,j.attempt_count;
END;
$$;
$definition_0$,
    $definition_1$
CREATE OR REPLACE FUNCTION public.edr_complete_scan_job(
    p_tenant_id varchar, p_agent_id varchar, p_job_id uuid,
    p_lease_token uuid, p_success boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE changed integer;
        lease_deadline timestamptz;
        checked_at timestamptz;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL OR p_job_id IS NULL
       OR p_lease_token IS NULL OR p_success IS NULL THEN RETURN false; END IF;
    -- A lease alone cannot authorize completion after revocation/disablement.
    -- Lock the current principal and tenant for the duration of the update,
    -- serializing this authorization check with administrative revocations.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant_id AND a.agent_id=p_agent_id
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
    FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN false; END IF;

    -- Do not evaluate lease expiry before a conflicting job lock has cleared.
    SELECT j.lease_expires_at INTO lease_deadline
    FROM public.edr_scan_jobs AS j
    WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id AND j.job_id=p_job_id
      AND j.state='leased' AND j.lease_token=p_lease_token
    FOR UPDATE OF j;
    IF NOT FOUND THEN RETURN false; END IF;
    checked_at:=clock_timestamp();
    IF lease_deadline IS NULL OR lease_deadline<=checked_at THEN RETURN false; END IF;

    UPDATE public.edr_scan_jobs AS j
    SET state=CASE WHEN p_success THEN 'succeeded' ELSE 'failed' END,
        lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
        updated_at=checked_at
    WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id AND j.job_id=p_job_id
      AND j.state='leased' AND j.lease_token=p_lease_token
      AND j.lease_expires_at > checked_at;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed=1;
END;
$$;
$definition_1$,
    $definition_2$
CREATE OR REPLACE FUNCTION public.edr_recover_expired_scan_jobs(p_limit integer)
RETURNS integer LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE changed integer;
        expired_jobs uuid[];
        recovered_at timestamptz;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'invalid recovery limit' USING ERRCODE='invalid_parameter_value';
    END IF;
    SELECT array_agg(locked.job_id) INTO expired_jobs FROM (
        SELECT job_id FROM public.edr_scan_jobs
        WHERE state='leased' AND lease_expires_at <= clock_timestamp()
        ORDER BY lease_expires_at,job_id FOR UPDATE SKIP LOCKED LIMIT p_limit
    ) AS locked;
    IF expired_jobs IS NULL THEN RETURN 0; END IF;
    recovered_at:=clock_timestamp();
    UPDATE public.edr_scan_jobs AS j
    SET state=CASE WHEN j.attempt_count < j.max_attempts THEN 'pending' ELSE 'failed' END,
        lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
        updated_at=recovered_at
    WHERE j.job_id=ANY(expired_jobs) AND j.state='leased'
      AND j.lease_expires_at<=recovered_at;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;
$definition_2$,
    $definition_3$
CREATE OR REPLACE FUNCTION public.edr_renew_scan_job_lease(
    p_tenant_id varchar, p_agent_id varchar, p_job_id uuid,
    p_lease_owner text, p_lease_token uuid, p_lease_seconds integer
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE changed integer;
        lease_deadline timestamptz;
        renewed_at timestamptz;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL OR p_job_id IS NULL
       OR p_lease_owner IS NULL OR length(p_lease_owner) NOT BETWEEN 1 AND 256
       OR p_lease_token IS NULL OR p_lease_seconds IS NULL
       OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN RETURN false; END IF;

    -- Serialize authorization with concurrent tenant/device revocation.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant_id AND a.agent_id=p_agent_id
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
    FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN false; END IF;

    SELECT j.lease_expires_at INTO lease_deadline
    FROM public.edr_scan_jobs AS j
    WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id AND j.job_id=p_job_id
      AND j.state='leased' AND j.lease_owner=p_lease_owner
      AND j.lease_token=p_lease_token
    FOR UPDATE OF j;
    IF NOT FOUND THEN RETURN false; END IF;
    -- A lease that expired during either certificate or job-row locking
    -- cannot be revived using the transaction's earlier start time.
    renewed_at:=clock_timestamp();
    IF lease_deadline IS NULL OR lease_deadline<=renewed_at THEN RETURN false; END IF;
    UPDATE public.edr_scan_jobs AS j
    SET lease_expires_at=GREATEST(j.lease_expires_at,renewed_at+make_interval(secs=>p_lease_seconds)),
        updated_at=renewed_at
    WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id AND j.job_id=p_job_id
      AND j.state='leased' AND j.lease_owner=p_lease_owner
      AND j.lease_token=p_lease_token
      AND j.lease_expires_at > renewed_at;
    GET DIAGNOSTICS changed=ROW_COUNT;
    RETURN changed=1;
END;
$$;
$definition_3$,
    $definition_4$
CREATE OR REPLACE FUNCTION public.edr_complete_scan_job_with_result(
    p_tenant_id varchar,p_agent_id varchar,p_job_id uuid,
    p_lease_token uuid,p_verdict text,p_threat_name text,p_detail text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE changed integer;
        lease_deadline timestamptz;
        completed_at timestamptz;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL OR p_job_id IS NULL
       OR p_lease_token IS NULL OR p_verdict IS NULL
       OR p_verdict NOT IN ('clean_by_signature','malicious','error','unscanned')
       OR p_threat_name IS NULL OR length(p_threat_name)>256
       OR p_detail IS NULL OR length(p_detail)>1024
       OR p_threat_name ~ '[[:cntrl:]]' OR p_detail ~ '[[:cntrl:]]'
       OR (p_verdict='malicious' AND p_threat_name='')
       OR (p_verdict<>'malicious' AND p_threat_name<>'') THEN
        RETURN false;
    END IF;
    -- Recheck active tenant/device under locks, serializing administrative revocation.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant_id AND a.agent_id=p_agent_id
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
    FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT j.lease_expires_at INTO lease_deadline
    FROM public.edr_scan_jobs AS j
    WHERE j.job_id=p_job_id AND j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id
      AND j.state='leased' AND j.lease_token=p_lease_token
    FOR UPDATE OF j;
    IF NOT FOUND THEN RETURN false; END IF;
    -- Both certificate authorization and job locking may have waited.
    -- Expiry is checked only after the matching job is exclusively locked.
    completed_at:=clock_timestamp();
    IF lease_deadline IS NULL OR lease_deadline<=completed_at THEN RETURN false; END IF;
    -- The result insert and lease consumption are one transaction; a conflict
    -- rolls back the UPDATE, and a replay cannot overwrite the existing result.
    WITH updated AS (
        UPDATE public.edr_scan_jobs AS j
        SET state=CASE WHEN p_verdict IN ('malicious','clean_by_signature')
                      THEN 'succeeded' ELSE 'failed' END,
            lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
            updated_at=completed_at
        WHERE j.job_id=p_job_id AND j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id
          AND j.state='leased' AND j.lease_token=p_lease_token
          AND j.lease_expires_at>completed_at
        RETURNING j.job_id,j.tenant_id,j.agent_id
    )
    INSERT INTO public.edr_scan_job_results(
        job_id,tenant_id,agent_id,engine,verdict,threat_name,detail)
    SELECT job_id,tenant_id,agent_id,'clamav',p_verdict,p_threat_name,p_detail
    FROM updated;
    GET DIAGNOSTICS changed=ROW_COUNT;
    RETURN changed=1;
END;
$$;
$definition_4$
  ];
  ordinal integer;
  signature text;
  previous record;
  replaced record;
  setting text;
  setting_name text;
  setting_value text;
  session_value text;
BEGIN
  -- Validate the entire upgrade target set before replacing any function.
  FOREACH signature IN ARRAY signatures LOOP
    IF pg_catalog.to_regprocedure(signature) IS NULL THEN
      RAISE EXCEPTION 'lease-clock upgrade requires existing function: %',signature;
    END IF;
  END LOOP;
  FOR ordinal IN 1..array_length(signatures,1) LOOP
    signature:=signatures[ordinal];
    SELECT p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig
      INTO STRICT previous FROM pg_catalog.pg_proc p
      WHERE p.oid=pg_catalog.to_regprocedure(signature);
    EXECUTE definitions[ordinal];
    EXECUTE format('ALTER FUNCTION %s SECURITY %s',signature,
      CASE WHEN previous.prosecdef THEN 'DEFINER' ELSE 'INVOKER' END);
    EXECUTE format('ALTER FUNCTION %s RESET ALL',signature);
    FOREACH setting IN ARRAY COALESCE(previous.proconfig,ARRAY[]::text[]) LOOP
      setting_name:=split_part(setting,'=',1);
      setting_value:=substr(setting,strpos(setting,'=')+1);
      session_value:=pg_catalog.current_setting(setting_name,true);
      -- GUC values never become executable SQL. SET FROM CURRENT round-trips
      -- list-valued settings such as search_path without ambiguous SQL quoting.
      PERFORM pg_catalog.set_config(setting_name,setting_value,true);
      EXECUTE format('ALTER FUNCTION %s SET %I FROM CURRENT',signature,setting_name);
      PERFORM pg_catalog.set_config(setting_name,session_value,true);
    END LOOP;
    SELECT p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig
      INTO STRICT replaced FROM pg_catalog.pg_proc p
      WHERE p.oid=pg_catalog.to_regprocedure(signature);
    IF replaced.oid<>previous.oid OR replaced.proowner<>previous.proowner
       OR replaced.proacl IS DISTINCT FROM previous.proacl
       OR replaced.prosecdef IS DISTINCT FROM previous.prosecdef
       OR replaced.proconfig IS DISTINCT FROM previous.proconfig THEN
      RAISE EXCEPTION 'lease-clock upgrade changed owner, ACL, security mode or settings: %',signature;
    END IF;
  END LOOP;
END;
$lease_upgrade$;
CREATE TABLE IF NOT EXISTS public.edr_schema_capabilities(
  capability text PRIMARY KEY,
  version integer NOT NULL CHECK(version>0)
);
DO $capability_shape$
DECLARE relation_id oid:='public.edr_schema_capabilities'::regclass;
BEGIN
  IF (SELECT relkind FROM pg_catalog.pg_class WHERE oid=relation_id)<>'r'
     OR (SELECT count(*) FROM pg_catalog.pg_attribute
         WHERE attrelid=relation_id AND attnum>0 AND NOT attisdropped)<>2
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=relation_id
         AND attname='capability' AND atttypid='text'::regtype AND attnotnull AND NOT attisdropped)
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=relation_id
         AND attname='version' AND atttypid='integer'::regtype AND attnotnull AND NOT attisdropped)
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=relation_id
         AND contype='p' AND pg_catalog.pg_get_constraintdef(oid)='PRIMARY KEY (capability)')
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=relation_id
         AND contype='c' AND convalidated AND pg_catalog.pg_get_constraintdef(oid)='CHECK ((version > 0))') THEN
    RAISE EXCEPTION 'unexpected existing EDR schema-capability table shape';
  END IF;
END;
$capability_shape$;
REVOKE ALL ON TABLE public.edr_schema_capabilities FROM PUBLIC;
-- Publish the capability only after all function replacements and metadata
-- checks succeeded. Do not silently downgrade a future capability version.
INSERT INTO public.edr_schema_capabilities(capability,version)
VALUES ('scan_lease_wallclock',1) ON CONFLICT (capability) DO NOTHING;
DO $capability$
BEGIN
  IF (SELECT version FROM public.edr_schema_capabilities
      WHERE capability='scan_lease_wallclock') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'incompatible scan_lease_wallclock capability version';
  END IF;
END;
$capability$;
COMMIT;
