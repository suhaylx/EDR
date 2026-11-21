-- SQL regression for SOC inventory CTE column naming and fleet health.
-- Run against a disposable PG16 database after migrations 0001..0012.
-- Query columns intentionally mirror backend/internal/edr/soc_endpoint_inventory.go.
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('invA','Inventory A'),('invB','Inventory B');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('invA','linux01','linux'),('invA','win02','windows'),
       ('invA','linux03','linux'),('invA','win04','windows'),
       ('invA','win05','windows'),('invB','linux01','linux');
UPDATE edr_agents SET revoked_at=transaction_timestamp()
WHERE tenant_id='invA' AND agent_id='win05';
INSERT INTO edr_agent_heartbeats(tenant_id,agent_id,platform,agent_version,
  clamav_version,signature_version,scan_ready,last_seen,received_count)
VALUES
 ('invA','linux01','linux','0.1.0','1.5','sig1',true,transaction_timestamp(),5),
 ('invA','win02','windows','0.1.0','','',false,transaction_timestamp(),2),
 ('invA','linux03','linux','0.1.0','1.5','sig1',true,
  transaction_timestamp()-interval '10 minutes',3),
 ('invA','win05','windows','0.1.0','1.5','sig1',true,transaction_timestamp(),1),
 ('invB','linux01','linux','0.1.0','1.5','sig1',true,transaction_timestamp(),9);

-- PREPARE resolves every computed column name as the production Go queries do.
PREPARE qa_soc_inventory_list(varchar,text,text,integer,integer) AS
WITH inventory AS (
 SELECT a.agent_id, a.platform,
  COALESCE(h.agent_version,'') AS agent_version,
  COALESCE(h.clamav_version,'') AS clamav_version,
  COALESCE(h.signature_version,'') AS signature_version,
  COALESCE(h.scan_ready,false) AS scan_ready,
  h.last_seen, COALESCE(h.received_count,0) AS received_count,
  CASE
   WHEN a.revoked_at IS NOT NULL THEN 'revoked'
   WHEN h.last_seen IS NULL THEN 'unseen'
   WHEN h.last_seen < CURRENT_TIMESTAMP-INTERVAL '5 minutes' THEN 'stale'
   WHEN h.scan_ready THEN 'online'
   ELSE 'degraded'
  END AS health
 FROM edr_agents AS a
 JOIN edr_tenants AS t ON t.tenant_id=a.tenant_id
 LEFT JOIN edr_agent_heartbeats AS h
  ON h.tenant_id=a.tenant_id AND h.agent_id=a.agent_id
 WHERE a.tenant_id=$1 AND t.disabled_at IS NULL
)
SELECT agent_id,platform,agent_version,clamav_version,signature_version,
 scan_ready,last_seen,received_count,health
FROM inventory
WHERE ($2='' OR platform=$2) AND ($3='' OR health=$3)
ORDER BY agent_id LIMIT $4 OFFSET $5;
EXECUTE qa_soc_inventory_list('invA','linux','online',10,0);

DO $test$
DECLARE
 total integer;
 online_count integer;
 degraded_count integer;
 stale_count integer;
 unseen_count integer;
 revoked_count integer;
 record_version text;
 record_count bigint;
 BEGIN
 WITH inventory AS (
  SELECT a.agent_id, a.platform,
   COALESCE(h.agent_version,'') AS agent_version,
   COALESCE(h.clamav_version,'') AS clamav_version,
   COALESCE(h.signature_version,'') AS signature_version,
   COALESCE(h.scan_ready,false) AS scan_ready,
   h.last_seen,COALESCE(h.received_count,0) AS received_count,
   CASE
    WHEN a.revoked_at IS NOT NULL THEN 'revoked'
    WHEN h.last_seen IS NULL THEN 'unseen'
    WHEN h.last_seen < CURRENT_TIMESTAMP-INTERVAL '5 minutes' THEN 'stale'
    WHEN h.scan_ready THEN 'online' ELSE 'degraded'
   END AS health
  FROM edr_agents a
  JOIN edr_tenants t ON t.tenant_id=a.tenant_id
  LEFT JOIN edr_agent_heartbeats h
    ON h.tenant_id=a.tenant_id AND h.agent_id=a.agent_id
  WHERE a.tenant_id='invA' AND t.disabled_at IS NULL
 )
 SELECT count(*),
  count(*) FILTER(WHERE health='online'),
  count(*) FILTER(WHERE health='degraded'),
  count(*) FILTER(WHERE health='stale'),
  count(*) FILTER(WHERE health='unseen'),
  count(*) FILTER(WHERE health='revoked')
 INTO total,online_count,degraded_count,stale_count,unseen_count,revoked_count
 FROM inventory;
 IF total<>5 OR online_count<>1 OR degraded_count<>1
    OR stale_count<>1 OR unseen_count<>1 OR revoked_count<>1 THEN
  RAISE EXCEPTION 'unexpected SOC inventory health counts: %/%/%/%/%/%',
    total,online_count,degraded_count,stale_count,unseen_count,revoked_count;
 END IF;
 SELECT h.agent_version,h.received_count INTO record_version,record_count
 FROM edr_agent_heartbeats h WHERE h.tenant_id='invA' AND h.agent_id='linux01';
 IF record_version<>'0.1.0' OR record_count<>5 THEN
   RAISE EXCEPTION 'inventory version/count fixture invalid'; END IF;
END $test$;
DEALLOCATE qa_soc_inventory_list;
ROLLBACK;
