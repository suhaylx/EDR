-- Disposable PostgreSQL 16 only, after 0014. Timing/lock races are exercised
-- separately by test-enrollment-wallclock-races.py. This file verifies public
-- function behavior, no partial mutation, and metadata-preserving reapplication.
\set ON_ERROR_STOP on

BEGIN;
INSERT INTO public.edr_tenants(tenant_id,display_name,disabled_at)
VALUES ('qawall_a','Enrollment boundary QA A',NULL),
       ('qawall_b','Enrollment boundary QA B',NULL),
       ('qawall_disabled','Disabled enrollment boundary QA',clock_timestamp());
INSERT INTO public.edr_enrollment_challenges(
  challenge_id,tenant_id,agent_id,challenge_digest,created_at,expires_at)
VALUES
 ('14000000-0000-4000-8000-000000000001','qawall_a','consume',decode(repeat('11',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour'),
 ('14000000-0000-4000-8000-000000000002','qawall_a','expired',decode(repeat('12',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()),
 ('14000000-0000-4000-8000-000000000003','qawall_disabled','disabled',decode(repeat('13',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour'),
 ('14000000-0000-4000-8000-000000000010','qawall_a','enroll',decode(repeat('21',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour'),
 ('14000000-0000-4000-8000-000000000011','qawall_a','enroll',decode(repeat('22',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour'),
 ('14000000-0000-4000-8000-000000000012','qawall_a','revoked_enroll',decode(repeat('23',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour');
INSERT INTO public.edr_agents(tenant_id,agent_id,platform,revoked_at)
VALUES ('qawall_a','revoked_enroll','linux',clock_timestamp()),
       ('qawall_disabled','rotate','linux',NULL);
INSERT INTO public.edr_agent_certificates(
  tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('qawall_disabled','rotate',decode(repeat('41',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day');

DO $behavior$
DECLARE
  challenge uuid := '14000000-0000-4000-8000-000000000001';
  enrollment uuid := '14000000-0000-4000-8000-000000000010';
  item record;
  started timestamptz;
  consumed timestamptz;
  before_time timestamptz;
  after_time timestamptz;
BEGIN
  -- A valid secret cannot be consumed by a different tenant or device.
  IF public.edr_consume_enrollment_challenge(challenge,'qawall_b','consume',decode(repeat('11',32),'hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge(challenge,'qawall_a','other',decode(repeat('11',32),'hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge(challenge,'qawall_a','consume',decode(repeat('10',32),'hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge(challenge,'qawall_a','consume',decode('11','hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge(NULL,'qawall_a','consume',decode(repeat('11',32),'hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge(challenge,'qawall_a','consume',NULL) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'challenge boundary accepted invalid identity/digest';
  END IF;
  IF (SELECT consumed_at FROM public.edr_enrollment_challenges WHERE challenge_id=challenge) IS NOT NULL THEN
    RAISE EXCEPTION 'rejected challenge input mutated consumption';
  END IF;
  started:=clock_timestamp();
  IF public.edr_consume_enrollment_challenge(challenge,'qawall_a','consume',decode(repeat('11',32),'hex')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'valid challenge consumption failed';
  END IF;
  SELECT consumed_at INTO consumed FROM public.edr_enrollment_challenges WHERE challenge_id=challenge;
  IF consumed IS NULL OR consumed<started OR consumed>clock_timestamp() THEN
    RAISE EXCEPTION 'challenge consumption is not attributed to the current clock';
  END IF;
  IF public.edr_consume_enrollment_challenge(challenge,'qawall_a','consume',decode(repeat('11',32),'hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge('14000000-0000-4000-8000-000000000002','qawall_a','expired',decode(repeat('12',32),'hex')) IS DISTINCT FROM false
     OR public.edr_consume_enrollment_challenge('14000000-0000-4000-8000-000000000003','qawall_disabled','disabled',decode(repeat('13',32),'hex')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'replayed/expired/disabled-tenant challenge accepted';
  END IF;

  -- Invalid certificates and inputs must not consume the still-valid challenge.
  FOR item IN SELECT * FROM (VALUES
      (NULL::text,decode(repeat('31',32),'hex'),'issuer'::text),
      ('macos',decode(repeat('31',32),'hex'),'issuer'),
      ('linux',NULL::bytea,'issuer'),
      ('linux',decode('31','hex'),'issuer'),
      ('linux',decode(repeat('31',32),'hex'),NULL::text),
      ('linux',decode(repeat('31',32),'hex'),''),
      ('linux',decode(repeat('31',32),'hex'),repeat('a',257))
    ) bad(platform,fingerprint,actor)
  LOOP
    IF public.edr_complete_agent_enrollment(enrollment,'qawall_a','enroll',decode(repeat('21',32),'hex'),
        item.platform,item.fingerprint,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',item.actor) IS DISTINCT FROM false THEN
      RAISE EXCEPTION 'invalid enrollment parameter accepted';
    END IF;
  END LOOP;
  FOR item IN SELECT * FROM (VALUES
      (NULL::timestamptz,clock_timestamp()+interval '1 hour'),
      (clock_timestamp()-interval '1 hour',NULL::timestamptz),
      (clock_timestamp()-interval '1 hour',clock_timestamp()),
      (clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours'),
      (clock_timestamp()+interval '1 hour',clock_timestamp()))
      bad(not_before,not_after)
  LOOP
    IF public.edr_complete_agent_enrollment(enrollment,'qawall_a','enroll',decode(repeat('21',32),'hex'),
        'linux',decode(repeat('31',32),'hex'),item.not_before,item.not_after,'issuer') IS DISTINCT FROM false THEN
      RAISE EXCEPTION 'invalid/future/expired enrollment certificate accepted';
    END IF;
  END LOOP;
  IF public.edr_complete_agent_enrollment(enrollment,'qawall_b','enroll',decode(repeat('21',32),'hex'),
      'linux',decode(repeat('31',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour','issuer') IS DISTINCT FROM false
     OR public.edr_complete_agent_enrollment(enrollment,'qawall_a','enroll',decode(repeat('20',32),'hex'),
      'linux',decode(repeat('31',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour','issuer') IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'cross-tenant/wrong-digest enrollment accepted';
  END IF;
  IF (SELECT consumed_at FROM public.edr_enrollment_challenges WHERE challenge_id=enrollment) IS NOT NULL
     OR EXISTS(SELECT 1 FROM public.edr_agents WHERE tenant_id='qawall_a' AND agent_id='enroll')
     OR EXISTS(SELECT 1 FROM public.edr_enrollment_audit WHERE tenant_id='qawall_a') THEN
    RAISE EXCEPTION 'rejected enrollment consumed challenge or left device/audit state';
  END IF;
  -- not_before is inclusive, not_after is exclusive.
  before_time:=clock_timestamp();
  after_time:=before_time+interval '1 hour';
  IF public.edr_complete_agent_enrollment(enrollment,'qawall_a','enroll',decode(repeat('21',32),'hex'),
      'linux',decode(repeat('31',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'valid boundary enrollment rejected';
  END IF;
  IF (SELECT count(*) FROM public.edr_agents WHERE tenant_id='qawall_a' AND agent_id='enroll')<>1
     OR (SELECT count(*) FROM public.edr_agent_certificates WHERE tenant_id='qawall_a' AND agent_id='enroll')<>1
     OR (SELECT count(*) FROM public.edr_enrollment_audit WHERE tenant_id='qawall_a' AND agent_id='enroll')<>2 THEN
    RAISE EXCEPTION 'valid enrollment did not create exactly one device/certificate and two audit entries';
  END IF;
  IF public.edr_complete_agent_enrollment(enrollment,'qawall_a','enroll',decode(repeat('21',32),'hex'),
      'linux',decode(repeat('31',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false
     OR public.edr_complete_agent_enrollment('14000000-0000-4000-8000-000000000011','qawall_a','enroll',decode(repeat('22',32),'hex'),
      'linux',decode(repeat('32',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false
     OR public.edr_complete_agent_enrollment('14000000-0000-4000-8000-000000000012','qawall_a','revoked_enroll',decode(repeat('23',32),'hex'),
      'linux',decode(repeat('32',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false
     OR public.edr_complete_agent_enrollment('14000000-0000-4000-8000-000000000003','qawall_disabled','disabled',decode(repeat('13',32),'hex'),
      'linux',decode(repeat('32',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'replayed/existing/revoked/disabled-tenant enrollment accepted';
  END IF;
  IF EXISTS(SELECT 1 FROM public.edr_enrollment_challenges
      WHERE challenge_id IN ('14000000-0000-4000-8000-000000000011','14000000-0000-4000-8000-000000000012','14000000-0000-4000-8000-000000000003')
      AND consumed_at IS NOT NULL) THEN
    RAISE EXCEPTION 'rejected enrollment consumed an unused challenge';
  END IF;

  FOR item IN SELECT * FROM (VALUES
      (decode(repeat('31',32),'hex'),before_time,after_time),
      (decode('32','hex'),before_time,after_time),
      (NULL::bytea,before_time,after_time),
      (decode(repeat('32',32),'hex'),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours'),
      (decode(repeat('32',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()),
      (decode(repeat('32',32),'hex'),NULL::timestamptz,after_time),
      (decode(repeat('32',32),'hex'),before_time,NULL::timestamptz))
      bad(fingerprint,not_before,not_after)
  LOOP
    BEGIN
      PERFORM public.edr_rotate_agent_certificate('qawall_a','enroll',decode(repeat('31',32),'hex'),
          item.fingerprint,item.not_before,item.not_after,'issuer');
      RAISE EXCEPTION 'invalid/future/expired rotation did not raise invalid_parameter_value';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
  END LOOP;
  IF public.edr_rotate_agent_certificate('qawall_b','enroll',decode(repeat('31',32),'hex'),decode(repeat('32',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false
     OR public.edr_rotate_agent_certificate('qawall_a','enroll',decode(repeat('30',32),'hex'),decode(repeat('32',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false
     OR public.edr_rotate_agent_certificate('qawall_a','revoked_enroll',decode(repeat('31',32),'hex'),decode(repeat('32',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false
     OR public.edr_rotate_agent_certificate('qawall_disabled','rotate',decode(repeat('41',32),'hex'),decode(repeat('42',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'cross-tenant/missing-old/revoked/disabled-tenant rotation accepted';
  END IF;
  IF (SELECT revoked_at FROM public.edr_agent_certificates WHERE tenant_id='qawall_a' AND agent_id='enroll') IS NOT NULL
     OR (SELECT count(*) FROM public.edr_agent_certificates WHERE tenant_id='qawall_a' AND agent_id='enroll')<>1
     OR (SELECT count(*) FROM public.edr_enrollment_audit WHERE tenant_id='qawall_a' AND agent_id='enroll')<>2 THEN
    RAISE EXCEPTION 'rejected rotation revoked working certificate or mutated audit/state';
  END IF;
  IF public.edr_rotate_agent_certificate('qawall_a','enroll',decode(repeat('31',32),'hex'),decode(repeat('32',32),'hex'),
      clock_timestamp(),clock_timestamp()+interval '1 hour','issuer') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'valid certificate rotation failed';
  END IF;
  IF (SELECT count(*) FROM public.edr_agent_certificates WHERE tenant_id='qawall_a' AND agent_id='enroll' AND revoked_at IS NULL)<>1
     OR NOT EXISTS(SELECT 1 FROM public.edr_agent_certificates WHERE tenant_id='qawall_a' AND agent_id='enroll'
          AND fingerprint_sha256=decode(repeat('31',32),'hex') AND revoked_at IS NOT NULL AND revoke_reason='rotation')
     OR (SELECT count(*) FROM public.edr_enrollment_audit WHERE tenant_id='qawall_a' AND agent_id='enroll')<>4 THEN
    RAISE EXCEPTION 'valid rotation did not retain atomic revocation/replacement/audit';
  END IF;
  IF public.edr_rotate_agent_certificate('qawall_a','enroll',decode(repeat('31',32),'hex'),decode(repeat('33',32),'hex'),before_time,after_time,'issuer') IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'old-certificate rotation replay accepted';
  END IF;
  RAISE NOTICE 'PASS: challenge/enrollment/rotation positive, identity, digest, malformed, validity, replay and no-partial-mutation boundaries';
END;
$behavior$;
ROLLBACK;

-- Metadata fixture is private to this disposable database. Record and restore
-- the original definitions/owners; no deployment role is created or granted.
CREATE TEMP TABLE edr_enrollment_original_metadata AS
SELECT oid,proowner,proacl,prosecdef,proconfig,pg_catalog.pg_get_functiondef(oid) AS definition,
       pg_catalog.pg_get_userbyid(proowner) AS owner_name
FROM pg_catalog.pg_proc WHERE oid=ANY(ARRAY[
 'public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea)'::regprocedure,
 'public.edr_complete_agent_enrollment(uuid,varchar,varchar,bytea,text,bytea,timestamptz,timestamptz,text)'::regprocedure,
 'public.edr_rotate_agent_certificate(varchar,varchar,bytea,bytea,timestamptz,timestamptz,text)'::regprocedure
]::oid[]);
CREATE TEMP TABLE edr_enrollment_fixture_roles AS
SELECT 'edr_qawall_owner_'||replace(gen_random_uuid()::text,'-','') AS owner_name,
       'edr_qawall_grantee_'||replace(gen_random_uuid()::text,'-','') AS grantee_name;
SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',owner_name)
FROM edr_enrollment_fixture_roles \gexec
SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',grantee_name)
FROM edr_enrollment_fixture_roles \gexec
ALTER FUNCTION public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea) SECURITY DEFINER;
SELECT format('ALTER FUNCTION public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea) OWNER TO %I',owner_name)
FROM edr_enrollment_fixture_roles \gexec
SELECT format('GRANT EXECUTE ON FUNCTION public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea) TO %I',grantee_name)
FROM edr_enrollment_fixture_roles \gexec
ALTER FUNCTION public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea) SET statement_timeout='41s';
ALTER FUNCTION public.edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea) SET edr.qa_metadata='value=kept';
ALTER FUNCTION public.edr_complete_agent_enrollment(uuid,varchar,varchar,bytea,text,bytea,timestamptz,timestamptz,text) SET lock_timeout='7s';
CREATE TEMP TABLE edr_enrollment_upgrade_before AS
SELECT p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig
FROM pg_catalog.pg_proc p JOIN edr_enrollment_original_metadata b ON b.oid=p.oid;
DO $obsolete$
DECLARE item record;
BEGIN
  IF (SELECT count(*) FROM edr_enrollment_upgrade_before)<>3
     OR (SELECT count(*) FROM edr_enrollment_upgrade_before WHERE prosecdef)<>1 THEN
    RAISE EXCEPTION 'enrollment upgrade fixture must contain one definer and two invoker functions';
  END IF;
  FOR item IN SELECT oid FROM edr_enrollment_upgrade_before LOOP
    EXECUTE replace(pg_catalog.pg_get_functiondef(item.oid),'clock_timestamp()','transaction_timestamp()');
  END LOOP;
END;
$obsolete$;
\ir ../backend/migrations/0014_enrollment_wallclock.up.sql
\ir ../backend/migrations/0014_enrollment_wallclock.up.sql
DO $preserved$
DECLARE item record;
BEGIN
  IF (SELECT version FROM public.edr_schema_capabilities WHERE capability='enrollment_wallclock') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'enrollment upgrade capability missing or incompatible';
  END IF;
  FOR item IN
    SELECT b.*,p.oid AS actual_oid,p.proowner AS actual_owner,p.proacl AS actual_acl,
      p.prosecdef AS actual_security,p.proconfig AS actual_settings,p.prosrc
    FROM edr_enrollment_upgrade_before b LEFT JOIN pg_catalog.pg_proc p ON p.oid=b.oid
  LOOP
    IF item.actual_oid IS NULL OR item.actual_owner<>item.proowner
       OR item.actual_acl IS DISTINCT FROM item.proacl
       OR item.actual_security IS DISTINCT FROM item.prosecdef
       OR item.actual_settings IS DISTINCT FROM item.proconfig
       OR strpos(item.prosrc,'clock_timestamp()')=0
       OR strpos(item.prosrc,'transaction_timestamp()')<>0 THEN
      RAISE EXCEPTION '0014 did not replace stale clock while preserving OID/owner/ACL/security/settings';
    END IF;
  END LOOP;
  RAISE NOTICE 'PASS: 0014 replaces obsolete clocks and preserves three function identities, owners, ACLs, invoker/definer modes and local settings across two applications';
END;
$preserved$;
DO $restore$
DECLARE item record; grantee text;
BEGIN
  SELECT grantee_name INTO STRICT grantee FROM edr_enrollment_fixture_roles;
  FOR item IN SELECT * FROM edr_enrollment_original_metadata LOOP
    EXECUTE item.definition;
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I',item.oid::regprocedure,item.owner_name);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',item.oid::regprocedure,grantee);
  END LOOP;
END;
$restore$;
SELECT format('DROP ROLE %I',owner_name) FROM edr_enrollment_fixture_roles \gexec
SELECT format('DROP ROLE %I',grantee_name) FROM edr_enrollment_fixture_roles \gexec
DROP TABLE edr_enrollment_upgrade_before,edr_enrollment_original_metadata,edr_enrollment_fixture_roles;
