-- BE-121–125: authenticated endpoint liveness/capability snapshot.
-- Device-reported version strings are telemetry, NOT remote attestation.
BEGIN;
CREATE TABLE edr_agent_heartbeats(
    tenant_id varchar(96) NOT NULL,
    agent_id varchar(96) NOT NULL,
    platform text NOT NULL CHECK(platform IN ('windows','linux')),
    agent_version varchar(64) NOT NULL CHECK(length(agent_version)>0),
    clamav_version varchar(64) NOT NULL DEFAULT '',
    signature_version varchar(96) NOT NULL DEFAULT '',
    scan_ready boolean NOT NULL DEFAULT false,
    last_seen timestamptz NOT NULL DEFAULT transaction_timestamp(),
    received_count bigint NOT NULL DEFAULT 1 CHECK(received_count>=1),
    PRIMARY KEY(tenant_id,agent_id),
    FOREIGN KEY(tenant_id,agent_id) REFERENCES edr_agents(tenant_id,agent_id)
      ON DELETE RESTRICT,
    CHECK(agent_version !~ '[[:cntrl:]]' AND clamav_version !~ '[[:cntrl:]]'
        AND signature_version !~ '[[:cntrl:]]')
);
CREATE INDEX edr_agent_heartbeats_recent
    ON edr_agent_heartbeats(tenant_id,last_seen DESC);

CREATE FUNCTION edr_record_agent_heartbeat(
    p_tenant varchar,p_agent varchar,p_platform text,p_version varchar,
    p_clamav varchar,p_signatures varchar,p_ready boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
BEGIN
    IF p_tenant IS NULL OR p_agent IS NULL OR p_platform NOT IN ('windows','linux')
       OR p_version IS NULL OR length(p_version) NOT BETWEEN 1 AND 64
       OR p_clamav IS NULL OR length(p_clamav)>64
       OR p_signatures IS NULL OR length(p_signatures)>96
       OR p_ready IS NULL OR
       p_version ~ '[[:cntrl:]]' OR p_clamav ~ '[[:cntrl:]]' OR
       p_signatures ~ '[[:cntrl:]]' THEN
        RETURN false;
    END IF;
    -- Lock tenant and agent so concurrent revocation/disablement serializes
    -- before recording an authenticated health heartbeat.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant AND a.agent_id=p_agent
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
      AND a.platform=p_platform FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN false; END IF;
    INSERT INTO public.edr_agent_heartbeats(tenant_id,agent_id,platform,
        agent_version,clamav_version,signature_version,scan_ready)
    VALUES(p_tenant,p_agent,p_platform,p_version,p_clamav,p_signatures,p_ready)
    ON CONFLICT (tenant_id,agent_id) DO UPDATE SET
        platform=EXCLUDED.platform,
        agent_version=EXCLUDED.agent_version,
        clamav_version=EXCLUDED.clamav_version,
        signature_version=EXCLUDED.signature_version,
        scan_ready=EXCLUDED.scan_ready,
        last_seen=transaction_timestamp(),
        received_count=public.edr_agent_heartbeats.received_count+1;
    RETURN true;
END;
$body$;
REVOKE ALL ON FUNCTION edr_record_agent_heartbeat(
 varchar,varchar,text,varchar,varchar,varchar,boolean) FROM PUBLIC;
COMMIT;
