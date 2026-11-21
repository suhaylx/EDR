-- Disposable database only, after migrations 0001..0009. No changes persist.
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES
    ('heartbeatA','Heartbeat A'),('heartbeatB','Heartbeat B');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES
    ('heartbeatA','win01','windows'),('heartbeatB','win01','windows');
DO $check$
BEGIN
    IF edr_record_agent_heartbeat('heartbeatB','win02','windows','0.1','','',false) THEN
        RAISE EXCEPTION 'non-enrolled device sent heartbeat'; END IF;
    IF edr_record_agent_heartbeat('heartbeatA','win01','linux','0.1','','',false) THEN
        RAISE EXCEPTION 'wrong device platform accepted'; END IF;
    IF NOT edr_record_agent_heartbeat('heartbeatA','win01','windows','0.1','1.5.5','2026-11-21',true) THEN
        RAISE EXCEPTION 'valid heartbeat rejected'; END IF;
    IF NOT edr_record_agent_heartbeat('heartbeatA','win01','windows','0.2','1.5.5','2026-11-21',false) THEN
        RAISE EXCEPTION 'second heartbeat rejected'; END IF;
    IF NOT EXISTS (SELECT 1 FROM edr_agent_heartbeats WHERE
        tenant_id='heartbeatA' AND agent_id='win01'
        AND received_count=2 AND agent_version='0.2' AND scan_ready=false
        AND clamav_version='1.5.5' AND last_seen IS NOT NULL) THEN
        RAISE EXCEPTION 'latest heartbeat snapshot/count missing'; END IF;
    IF EXISTS (SELECT 1 FROM edr_agent_heartbeats WHERE tenant_id='heartbeatB') THEN
        RAISE EXCEPTION 'cross-tenant heartbeat leaked'; END IF;
    UPDATE edr_agents SET revoked_at=now() WHERE tenant_id='heartbeatA' AND agent_id='win01';
    IF edr_record_agent_heartbeat('heartbeatA','win01','windows','0.3','','',true) THEN
        RAISE EXCEPTION 'revoked agent heartbeat accepted'; END IF;
    IF (SELECT received_count FROM edr_agent_heartbeats
       WHERE tenant_id='heartbeatA' AND agent_id='win01')<>2 THEN
        RAISE EXCEPTION 'revoked heartbeat mutated count'; END IF;
END $check$;
ROLLBACK;
