-- Accelerated sprint Day 3: durable SOC analyst assignment and audit notes.
-- This adds case-management metadata only. No endpoint commands are executed.
-- Apply after migration 0011. Separate operator mTLS/DB role authorization
-- is still required. Migrations use a privileged, approved migration role.
BEGIN;

ALTER TABLE edr_soc_alerts
 ADD COLUMN assigned_to varchar(96),
 ADD COLUMN last_action_by varchar(96);

CREATE UNIQUE INDEX edr_soc_alert_tenant_id_scope_key
 ON edr_soc_alerts(tenant_id,alert_id);

CREATE TABLE edr_soc_alert_activity(
 activity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id varchar(96) NOT NULL,
 alert_id uuid NOT NULL,
 actor_id varchar(96) NOT NULL,
 action text NOT NULL CHECK(action IN(
  'created','acknowledged','resolved','reopened','assigned','unassigned','note')),
 note varchar(2048) NOT NULL DEFAULT '',
 occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 FOREIGN KEY(tenant_id,alert_id)
  REFERENCES edr_soc_alerts(tenant_id,alert_id) ON DELETE RESTRICT,
 CHECK(length(actor_id) BETWEEN 1 AND 96 AND actor_id !~ '[[:cntrl:]]'),
 CHECK(note !~ '[[:cntrl:]]')
);
CREATE INDEX edr_soc_alert_activity_feed
 ON edr_soc_alert_activity(tenant_id,alert_id,occurred_at DESC,activity_id DESC);

-- All state changes performed by the existing operator function are now
-- attributed via last_action_by, including reopens after resolution.
CREATE OR REPLACE FUNCTION edr_soc_change_alert_state(
 p_tenant varchar,p_operator varchar,p_alert uuid,p_action text,p_note text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $state$
DECLARE changed integer;
BEGIN
 IF p_tenant IS NULL OR p_operator IS NULL OR p_alert IS NULL OR
  p_action NOT IN ('ack','resolve','reopen') OR p_note IS NULL OR
  length(p_note)>1024 OR p_note ~ '[[:cntrl:]]' OR
  (p_action='resolve' AND length(trim(p_note))=0) OR
  (p_action<>'resolve' AND p_note<>'') THEN RETURN false; END IF;
 PERFORM 1 FROM public.edr_tenants AS t
 JOIN public.edr_soc_operators AS o ON o.tenant_id=t.tenant_id
 WHERE t.tenant_id=p_tenant AND o.operator_id=p_operator
  AND o.role='scanner' AND o.revoked_at IS NULL AND t.disabled_at IS NULL
 FOR SHARE OF t,o;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE public.edr_soc_alerts AS a SET
  state=CASE p_action WHEN 'ack' THEN 'acknowledged'
   WHEN 'resolve' THEN 'resolved' ELSE 'open' END,
  updated_at=transaction_timestamp(),
  last_action_by=p_operator,
  acknowledged_by=CASE WHEN p_action='reopen' THEN NULL
   WHEN p_action='ack' THEN p_operator ELSE a.acknowledged_by END,
  acknowledged_at=CASE WHEN p_action='reopen' THEN NULL
   WHEN p_action='ack' THEN transaction_timestamp() ELSE a.acknowledged_at END,
  resolved_by=CASE WHEN p_action='resolve' THEN p_operator ELSE NULL END,
  resolved_at=CASE WHEN p_action='resolve' THEN transaction_timestamp() ELSE NULL END,
  resolution_note=CASE WHEN p_action='resolve' THEN p_note ELSE '' END
 WHERE a.tenant_id=p_tenant AND a.alert_id=p_alert AND
  ((p_action='ack' AND a.state='open')
   OR (p_action='resolve' AND a.state='acknowledged')
   OR (p_action='reopen' AND a.state='resolved'));
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END;
$state$;

CREATE FUNCTION edr_record_soc_alert_activity()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $audit$
DECLARE
 actor varchar(96);
 event text;
 audit_note varchar(2048);
BEGIN
 IF TG_OP='INSERT' THEN
  actor:='system';
  event:='created';
  audit_note:='';
 ELSIF NEW.state IS DISTINCT FROM OLD.state THEN
  actor:=COALESCE(NEW.last_action_by,'system');
  event:=CASE NEW.state
    WHEN 'acknowledged' THEN 'acknowledged'
    WHEN 'resolved' THEN 'resolved'
    WHEN 'open' THEN 'reopened' END;
  audit_note:=CASE WHEN NEW.state='resolved' THEN NEW.resolution_note ELSE '' END;
 ELSIF NEW.assigned_to IS DISTINCT FROM OLD.assigned_to THEN
  actor:=COALESCE(NEW.last_action_by,'system');
  event:=CASE WHEN NEW.assigned_to IS NULL THEN 'unassigned'
    ELSE 'assigned' END;
  audit_note:=COALESCE(NEW.assigned_to,'');
 ELSE
  RETURN NEW;
 END IF;
 IF event IS NOT NULL THEN
  INSERT INTO public.edr_soc_alert_activity(
    tenant_id,alert_id,actor_id,action,note)
  VALUES(NEW.tenant_id,NEW.alert_id,actor,event,audit_note);
 END IF;
 RETURN NEW;
END;
$audit$;

CREATE TRIGGER edr_soc_alert_audit_insert
AFTER INSERT ON edr_soc_alerts
FOR EACH ROW EXECUTE FUNCTION edr_record_soc_alert_activity();
CREATE TRIGGER edr_soc_alert_audit_update
AFTER UPDATE ON edr_soc_alerts
FOR EACH ROW EXECUTE FUNCTION edr_record_soc_alert_activity();

-- Existing alerts predate this migration; preserve the historical boundary
-- without fabricating the original actor or the past transition timeline.
INSERT INTO edr_soc_alert_activity(tenant_id,alert_id,actor_id,action,note)
SELECT tenant_id,alert_id,'system','created',''
FROM edr_soc_alerts;

CREATE FUNCTION edr_soc_assign_alert(
 p_tenant varchar,p_operator varchar,p_alert uuid,p_assignee varchar
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $assign$
DECLARE changed integer;
BEGIN
 IF p_tenant IS NULL OR p_operator IS NULL OR p_alert IS NULL OR
  p_assignee IS NULL OR length(p_assignee)>96 OR
  p_assignee ~ '[[:cntrl:]]' THEN RETURN false; END IF;
 PERFORM 1 FROM public.edr_tenants AS t
 JOIN public.edr_soc_operators AS o ON o.tenant_id=t.tenant_id
 WHERE t.tenant_id=p_tenant AND o.operator_id=p_operator
  AND o.role='scanner' AND o.revoked_at IS NULL AND t.disabled_at IS NULL
 FOR SHARE OF t,o;
 IF NOT FOUND THEN RETURN false; END IF;
 IF p_assignee<>'' THEN
  PERFORM 1 FROM public.edr_soc_operators AS target
  WHERE target.tenant_id=p_tenant AND target.operator_id=p_assignee
    AND target.role='scanner' AND target.revoked_at IS NULL
  FOR SHARE OF target;
  IF NOT FOUND THEN RETURN false; END IF;
 END IF;
 UPDATE public.edr_soc_alerts AS a
 SET assigned_to=NULLIF(p_assignee,''),
  last_action_by=p_operator,updated_at=transaction_timestamp()
 WHERE a.tenant_id=p_tenant AND a.alert_id=p_alert
  AND a.state IN ('open','acknowledged')
  AND a.assigned_to IS DISTINCT FROM NULLIF(p_assignee,'');
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END;
$assign$;

CREATE FUNCTION edr_soc_add_alert_note(
 p_tenant varchar,p_operator varchar,p_alert uuid,p_note text
) RETURNS uuid
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $note$
DECLARE inserted_id uuid;
BEGIN
 IF p_tenant IS NULL OR p_operator IS NULL OR p_alert IS NULL OR
  p_note IS NULL OR length(trim(p_note))=0 OR length(p_note)>2048 OR
  p_note ~ '[[:cntrl:]]' THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.edr_tenants AS t
 JOIN public.edr_soc_operators AS o ON o.tenant_id=t.tenant_id
 JOIN public.edr_soc_alerts AS a ON a.tenant_id=t.tenant_id
 WHERE t.tenant_id=p_tenant AND o.operator_id=p_operator
  AND a.alert_id=p_alert AND o.role='scanner'
  AND o.revoked_at IS NULL AND t.disabled_at IS NULL
 FOR SHARE OF t,o,a;
 IF NOT FOUND THEN RETURN NULL; END IF;
 INSERT INTO public.edr_soc_alert_activity(
  tenant_id,alert_id,actor_id,action,note)
 VALUES (p_tenant,p_alert,p_operator,'note',p_note)
 RETURNING activity_id INTO inserted_id;
 RETURN inserted_id;
END;
$note$;

CREATE FUNCTION edr_deny_soc_alert_activity_mutation()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $immutable$
BEGIN
 RAISE EXCEPTION 'SOC audit entries cannot be modified'
  USING ERRCODE='insufficient_privilege';
END;
$immutable$;
CREATE TRIGGER edr_soc_alert_activity_immutable
BEFORE UPDATE OR DELETE ON edr_soc_alert_activity
FOR EACH ROW EXECUTE FUNCTION edr_deny_soc_alert_activity_mutation();

REVOKE ALL ON TABLE edr_soc_alert_activity FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_soc_assign_alert(varchar,varchar,uuid,varchar) FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_soc_add_alert_note(varchar,varchar,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_record_soc_alert_activity() FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_deny_soc_alert_activity_mutation() FROM PUBLIC;

COMMIT;
