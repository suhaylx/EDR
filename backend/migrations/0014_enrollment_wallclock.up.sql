-- 0014: validate enrollment and rotation deadlines after their row locks.
-- Apply after 0013 as the migration operator with serving processes drained.
-- Existing function identity, owners, grants, security mode and local settings
-- are preserved. This migration does not grant an enrollment/issuance role.
BEGIN;
SET LOCAL search_path = pg_catalog, public, pg_temp;
DO $enrollment_upgrade$
DECLARE
  signatures text[] := ARRAY[
    'public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea)',
    'public.edr_complete_agent_enrollment(uuid,varchar,varchar,bytea,text,bytea,timestamptz,timestamptz,text)',
    'public.edr_rotate_agent_certificate(varchar,varchar,bytea,bytea,timestamptz,timestamptz,text)'
  ];
  definitions text[] := ARRAY[
    $definition_0$
CREATE OR REPLACE FUNCTION public.edr_consume_enrollment_challenge(
    p_challenge_id uuid, p_tenant_id varchar, p_agent_id varchar, p_digest bytea
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE
    deadline timestamptz;
    checked_at timestamptz;
    changed integer;
BEGIN
    IF p_challenge_id IS NULL OR p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_digest IS NULL OR octet_length(p_digest) <> 32 THEN
        RETURN false;
    END IF;
    -- Keep the lock order tenant -> challenge, including standalone callers.
    -- Tenant disablement must not commit between authorization and consumption.
    PERFORM 1 FROM public.edr_tenants
    WHERE tenant_id=p_tenant_id AND disabled_at IS NULL FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    SELECT c.expires_at INTO deadline
    FROM public.edr_enrollment_challenges AS c
    WHERE c.challenge_id=p_challenge_id
      AND c.tenant_id=p_tenant_id AND c.agent_id=p_agent_id
      AND c.challenge_digest=p_digest AND c.consumed_at IS NULL
    FOR UPDATE OF c;
    IF NOT FOUND THEN RETURN false; END IF;

    -- BEGIN time and a timestamp taken before FOR UPDATE can both be stale.
    checked_at:=clock_timestamp();
    IF deadline<=checked_at THEN RETURN false; END IF;
    UPDATE public.edr_enrollment_challenges
    SET consumed_at=checked_at
    WHERE challenge_id=p_challenge_id AND consumed_at IS NULL
      AND expires_at>checked_at;
    GET DIAGNOSTICS changed=ROW_COUNT;
    RETURN changed=1;
END;
$$;
$definition_0$,
    $definition_1$
CREATE OR REPLACE FUNCTION public.edr_complete_agent_enrollment(
    p_challenge_id uuid, p_tenant_id varchar, p_agent_id varchar,
    p_digest bytea, p_platform text, p_fingerprint bytea,
    p_not_before timestamptz, p_not_after timestamptz, p_actor text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE
    checked_at timestamptz;
BEGIN
    IF p_challenge_id IS NULL OR p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_digest IS NULL OR octet_length(p_digest) <> 32
       OR p_platform IS NULL OR p_platform NOT IN ('windows','linux')
       OR p_fingerprint IS NULL OR octet_length(p_fingerprint) <> 32
       OR p_not_before IS NULL OR p_not_after IS NULL
       OR p_not_after<=p_not_before
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256 THEN
        RETURN false;
    END IF;

    -- Serialize enrollment, device existence and tenant disablement together.
    PERFORM 1 FROM public.edr_tenants
    WHERE tenant_id=p_tenant_id AND disabled_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM public.edr_agents
    WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id FOR UPDATE;
    IF FOUND THEN RETURN false; END IF;

    -- Acquire the challenge lock before validating the certificate window.
    -- A rejected certificate must leave its challenge available and unchanged.
    PERFORM 1 FROM public.edr_enrollment_challenges AS c
    WHERE c.challenge_id=p_challenge_id
      AND c.tenant_id=p_tenant_id AND c.agent_id=p_agent_id
      AND c.challenge_digest=p_digest AND c.consumed_at IS NULL
    FOR UPDATE OF c;
    IF NOT FOUND THEN RETURN false; END IF;
    checked_at:=clock_timestamp();
    IF p_not_before>checked_at OR p_not_after<=checked_at THEN
        RETURN false;
    END IF;
    IF NOT public.edr_consume_enrollment_challenge(
        p_challenge_id,p_tenant_id,p_agent_id,p_digest) THEN
        RETURN false;
    END IF;

    INSERT INTO public.edr_agents(tenant_id,agent_id,platform)
    VALUES(p_tenant_id,p_agent_id,p_platform);
    INSERT INTO public.edr_agent_certificates(
        tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
    VALUES(p_tenant_id,p_agent_id,p_fingerprint,p_not_before,p_not_after);
    INSERT INTO public.edr_enrollment_audit(
        tenant_id,agent_id,event_type,actor_id)
    VALUES(p_tenant_id,p_agent_id,'agent_enrolled',p_actor);
    INSERT INTO public.edr_enrollment_audit(
        tenant_id,agent_id,event_type,fingerprint_sha256,actor_id)
    VALUES(p_tenant_id,p_agent_id,'certificate_enrolled',p_fingerprint,p_actor);
    RETURN true;
END;
$$;
$definition_1$,
    $definition_2$
CREATE OR REPLACE FUNCTION public.edr_rotate_agent_certificate(
    p_tenant_id varchar, p_agent_id varchar, p_old_fingerprint bytea,
    p_new_fingerprint bytea, p_not_before timestamptz,
    p_not_after timestamptz, p_actor_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE
    checked_at timestamptz;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_old_fingerprint IS NULL OR octet_length(p_old_fingerprint) <> 32
       OR p_new_fingerprint IS NULL OR octet_length(p_new_fingerprint) <> 32
       OR p_old_fingerprint=p_new_fingerprint
       OR p_not_before IS NULL OR p_not_after IS NULL
       OR p_not_before>=p_not_after THEN
        RAISE EXCEPTION 'invalid certificate rotation parameters'
            USING ERRCODE='invalid_parameter_value';
    END IF;

    -- Follow tenant -> agent -> certificate order before reading the clock.
    PERFORM 1 FROM public.edr_tenants
    WHERE tenant_id=p_tenant_id AND disabled_at IS NULL FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM public.edr_agents
    WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id AND revoked_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM public.edr_agent_certificates
    WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id
      AND fingerprint_sha256=p_old_fingerprint AND revoked_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;

    checked_at:=clock_timestamp();
    IF p_not_before>checked_at OR p_not_after<=checked_at THEN
        RAISE EXCEPTION 'invalid certificate rotation parameters'
            USING ERRCODE='invalid_parameter_value';
    END IF;
    UPDATE public.edr_agent_certificates
    SET revoked_at=checked_at,revoke_reason='rotation'
    WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id
      AND fingerprint_sha256=p_old_fingerprint AND revoked_at IS NULL;
    INSERT INTO public.edr_enrollment_audit(
        tenant_id,agent_id,event_type,fingerprint_sha256,actor_id)
    VALUES(p_tenant_id,p_agent_id,'certificate_revoked',p_old_fingerprint,p_actor_id);
    INSERT INTO public.edr_agent_certificates(
        tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
    VALUES(p_tenant_id,p_agent_id,p_new_fingerprint,p_not_before,p_not_after);
    INSERT INTO public.edr_enrollment_audit(
        tenant_id,agent_id,event_type,fingerprint_sha256,actor_id)
    VALUES(p_tenant_id,p_agent_id,'certificate_enrolled',p_new_fingerprint,p_actor_id);
    RETURN true;
END;
$$;
$definition_2$
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
  IF pg_catalog.to_regclass('public.edr_schema_capabilities') IS NULL THEN
    RAISE EXCEPTION 'enrollment-clock upgrade requires migration 0013';
  END IF;
  FOREACH signature IN ARRAY signatures LOOP
    IF pg_catalog.to_regprocedure(signature) IS NULL THEN
      RAISE EXCEPTION 'enrollment-clock upgrade requires existing function: %',signature;
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
      RAISE EXCEPTION 'enrollment-clock upgrade changed function metadata: %',signature;
    END IF;
  END LOOP;
END;
$enrollment_upgrade$;
INSERT INTO public.edr_schema_capabilities(capability,version)
VALUES('enrollment_wallclock',1) ON CONFLICT(capability) DO NOTHING;
DO $capability$
BEGIN
  IF (SELECT version FROM public.edr_schema_capabilities
      WHERE capability='enrollment_wallclock') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'incompatible enrollment_wallclock capability version';
  END IF;
END;
$capability$;
COMMIT;
