-- BE-086 / BE-087: durable tenant-scoped scan verdicts, atomic with lease consumption.
-- Apply after 0007_scan_job_lease_renewal.up.sql. No PUBLIC function grants.
BEGIN;
CREATE TABLE edr_scan_job_results(
    job_id uuid PRIMARY KEY REFERENCES edr_scan_jobs(job_id) ON DELETE RESTRICT,
    tenant_id varchar(96) NOT NULL,
    agent_id varchar(96) NOT NULL,
    engine text NOT NULL CHECK(engine='clamav'),
    verdict text NOT NULL CHECK(verdict IN ('clean_by_signature','malicious','error','unscanned')),
    threat_name text NOT NULL DEFAULT '' CHECK(length(threat_name)<=256),
    detail text NOT NULL DEFAULT '' CHECK(length(detail)<=1024),
    observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK ((verdict='malicious' AND length(threat_name)>0)
        OR (verdict<>'malicious' AND threat_name=''))
);
CREATE INDEX edr_scan_job_results_tenant_agent ON
    edr_scan_job_results(tenant_id,agent_id,observed_at DESC);

CREATE FUNCTION edr_complete_scan_job_with_result(
    p_tenant_id varchar,p_agent_id varchar,p_job_id uuid,
    p_lease_token uuid,p_verdict text,p_threat_name text,p_detail text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE changed integer;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL OR p_job_id IS NULL
       OR p_lease_token IS NULL OR p_verdict IS NULL
       OR p_verdict NOT IN ('clean_by_signature','malicious','error','unscanned')
       OR p_threat_name IS NULL OR length(p_threat_name)>256
       OR p_detail IS NULL OR length(p_detail)>1024
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
    -- The result insert and lease consumption are one transaction; a conflict
    -- rolls back the UPDATE, and a replay cannot overwrite the existing result.
    WITH updated AS (
        UPDATE public.edr_scan_jobs AS j
        SET state=CASE WHEN p_verdict IN ('malicious','clean_by_signature')
                      THEN 'succeeded' ELSE 'failed' END,
            lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
            updated_at=transaction_timestamp()
        WHERE j.job_id=p_job_id AND j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id
          AND j.state='leased' AND j.lease_token=p_lease_token
          AND j.lease_expires_at>transaction_timestamp()
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
REVOKE ALL ON FUNCTION edr_complete_scan_job_with_result(
    varchar,varchar,uuid,uuid,text,text,text) FROM PUBLIC;
COMMIT;
