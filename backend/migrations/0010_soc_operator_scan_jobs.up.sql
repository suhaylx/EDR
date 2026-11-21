-- BE-126..130: independently authenticated SOC operators and durable scan scheduling.
-- Provision operator fingerprints/roles out-of-band; NEVER use the agent CA.
BEGIN;
CREATE TABLE edr_soc_operators(
 tenant_id varchar(96) NOT NULL REFERENCES edr_tenants(tenant_id) ON DELETE RESTRICT,
 operator_id varchar(96) NOT NULL,
 fingerprint_sha256 bytea NOT NULL CHECK(octet_length(fingerprint_sha256)=32),
 role text NOT NULL CHECK(role IN ('viewer','scanner')),
 revoked_at timestamptz,
 PRIMARY KEY(tenant_id,operator_id)
);
ALTER TABLE edr_scan_jobs
 ADD COLUMN request_key varchar(96),
 ADD COLUMN created_by_operator varchar(96);
CREATE UNIQUE INDEX edr_scan_jobs_tenant_request_key
 ON edr_scan_jobs(tenant_id,request_key) WHERE request_key IS NOT NULL;
CREATE INDEX edr_scan_jobs_operator_lookup
 ON edr_scan_jobs(tenant_id,created_at DESC,job_id DESC);

CREATE FUNCTION edr_enqueue_operator_scan_job(
 p_tenant varchar,p_operator varchar,p_agent varchar,p_job uuid,
 p_key varchar,p_root text
) RETURNS TABLE(job_id uuid, created boolean)
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $func$
BEGIN
 IF p_tenant IS NULL OR p_operator IS NULL OR p_agent IS NULL OR
    p_job IS NULL OR p_key IS NULL OR length(p_key) NOT BETWEEN 1 AND 96 OR
    p_root IS NULL OR length(p_root) NOT BETWEEN 1 AND 4096 OR
    p_root ~ '[[:cntrl:]]' THEN RETURN; END IF;
 -- Serialize operator revocation, tenant disablement and endpoint revocation.
 PERFORM 1 FROM public.edr_tenants AS t
 JOIN public.edr_soc_operators AS o ON o.tenant_id=t.tenant_id
 JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
 WHERE t.tenant_id=p_tenant AND o.operator_id=p_operator AND a.agent_id=p_agent
   AND t.disabled_at IS NULL AND o.revoked_at IS NULL
   AND o.role='scanner' AND a.revoked_at IS NULL
 FOR SHARE OF t,o,a;
 IF NOT FOUND THEN RETURN; END IF;
 RETURN QUERY
 WITH inserted AS (
  INSERT INTO public.edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,
     request_key,created_by_operator)
  VALUES (p_job,p_tenant,p_agent,p_root,p_key,p_operator)
  ON CONFLICT DO NOTHING RETURNING edr_scan_jobs.job_id
 ) SELECT inserted.job_id,true FROM inserted;
 IF FOUND THEN RETURN; END IF;
 -- Retry is idempotent only for the identical operator, device and target.
 RETURN QUERY SELECT j.job_id,false FROM public.edr_scan_jobs AS j
 WHERE j.tenant_id=p_tenant AND j.request_key=p_key
   AND j.created_by_operator=p_operator AND j.agent_id=p_agent
   AND j.scan_root=p_root;
END;
$func$;

CREATE FUNCTION edr_cancel_operator_scan_job(
 p_tenant varchar,p_operator varchar,p_job uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $func$
DECLARE changed integer;
BEGIN
 IF p_tenant IS NULL OR p_operator IS NULL OR p_job IS NULL THEN RETURN false; END IF;
 PERFORM 1 FROM public.edr_tenants AS t
 JOIN public.edr_soc_operators AS o ON o.tenant_id=t.tenant_id
 WHERE t.tenant_id=p_tenant AND o.operator_id=p_operator
  AND t.disabled_at IS NULL AND o.revoked_at IS NULL AND o.role='scanner'
 FOR SHARE OF t,o;
 IF NOT FOUND THEN RETURN false; END IF;
 -- Leased/running jobs cannot be cancelled by this API.
 UPDATE public.edr_scan_jobs AS j
 SET state='cancelled',updated_at=transaction_timestamp()
 WHERE j.tenant_id=p_tenant AND j.job_id=p_job AND j.state='pending'
   AND j.created_by_operator=p_operator;
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END;
$func$;
REVOKE ALL ON TABLE edr_soc_operators FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_enqueue_operator_scan_job(
 varchar,varchar,varchar,uuid,varchar,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_cancel_operator_scan_job(varchar,varchar,uuid) FROM PUBLIC;
COMMIT;
