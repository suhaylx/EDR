-- Disposable DB only, after runtime privilege bootstrap. This deliberately
-- installs an obsolete transaction-clock behavior as an upgrade fixture, then
-- proves 0013 replaces it without widening or losing the existing privileges.
\set ON_ERROR_STOP on
CREATE TEMP TABLE edr_lease_upgrade_before AS
SELECT oid,proowner,proacl,prosecdef,proconfig
FROM pg_catalog.pg_proc
WHERE oid=ANY(ARRAY[
  'public.edr_claim_scan_job(varchar,varchar,text,uuid,integer)'::regprocedure,
  'public.edr_complete_scan_job(varchar,varchar,uuid,uuid,boolean)'::regprocedure,
  'public.edr_recover_expired_scan_jobs(integer)'::regprocedure,
  'public.edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer)'::regprocedure,
  'public.edr_complete_scan_job_with_result(varchar,varchar,uuid,uuid,text,text,text)'::regprocedure
]::oid[]);
DO $outdated_fixture$
DECLARE item record;
BEGIN
  IF (SELECT count(*) FROM edr_lease_upgrade_before)<>5 THEN
    RAISE EXCEPTION 'upgrade fixture did not find all five functions';
  END IF;
  IF (SELECT count(*) FROM edr_lease_upgrade_before WHERE prosecdef)<>3 THEN
    RAISE EXCEPTION 'upgrade fixture must exercise existing operational definer ownership';
  END IF;
  FOR item IN SELECT oid FROM edr_lease_upgrade_before LOOP
    -- This is an isolated fixture, not a migration down/rollback procedure.
    EXECUTE replace(pg_catalog.pg_get_functiondef(item.oid),'clock_timestamp()','transaction_timestamp()');
  END LOOP;
END;
$outdated_fixture$;

\ir ../backend/migrations/0013_scan_lease_wallclock.up.sql
\ir ../backend/migrations/0013_scan_lease_wallclock.up.sql

DO $verify$
DECLARE item record;
BEGIN
  IF (SELECT version FROM public.edr_schema_capabilities WHERE capability='scan_lease_wallclock') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'idempotent upgrade did not publish its required capability';
  END IF;
  FOR item IN
    SELECT b.*,p.oid AS actual_oid,p.proowner AS actual_owner,p.proacl AS actual_acl,
      p.prosecdef AS actual_security,p.proconfig AS actual_settings,p.prosrc
    FROM edr_lease_upgrade_before b LEFT JOIN pg_catalog.pg_proc p ON p.oid=b.oid
  LOOP
    IF item.actual_oid IS NULL OR item.actual_owner<>item.proowner
       OR item.actual_acl IS DISTINCT FROM item.proacl
       OR item.actual_security IS DISTINCT FROM item.prosecdef
       OR item.actual_settings IS DISTINCT FROM item.proconfig
       OR strpos(item.prosrc,'clock_timestamp()')=0
       OR strpos(item.prosrc,'transaction_timestamp()')<>0 THEN
      RAISE EXCEPTION 'idempotent lease-clock upgrade did not preserve privilege metadata and replace stale body';
    END IF;
  END LOOP;
  RAISE NOTICE 'PASS: 0013 replaces obsolete lease clocks and retains OID/owner/ACL/security mode/settings across two applications';
END;
$verify$;
DROP TABLE edr_lease_upgrade_before;
