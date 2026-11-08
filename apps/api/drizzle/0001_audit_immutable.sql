-- La bitácora de auditoría es de solo inserción: nadie (ni la propia aplicación) puede modificar o borrar registros.
CREATE OR REPLACE FUNCTION audit.prevent_audit_change() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit.audit_log es inmutable: no se permite % ', TG_OP;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
DROP TRIGGER IF EXISTS audit_log_immutable ON audit.audit_log;
--> statement-breakpoint
CREATE TRIGGER audit_log_immutable
  BEFORE UPDATE OR DELETE ON audit.audit_log
  FOR EACH ROW EXECUTE FUNCTION audit.prevent_audit_change();
--> statement-breakpoint
-- Vista de apoyo para consultar la trazabilidad completa de un hallazgo desde DBeaver/pgAdmin
CREATE OR REPLACE VIEW analysis.v_finding_trace AS
SELECT
  f.id              AS finding_id,
  f.title,
  coalesce(f.severity_override, f.severity) AS effective_severity,
  f.status,
  rv.username       AS reviewed_by,
  f.reviewed_at,
  a.id              AS analysis_id,
  a.created_at      AS analysis_created_at,
  ca.username       AS analysis_created_by,
  u.id              AS upload_id,
  u.original_name,
  u.sha256          AS upload_sha256,
  up.username       AS uploaded_by,
  e.log_id,
  e.ts,
  e.hostname,
  e.event_id,
  e.user_name,
  e.source_ip,
  e.description,
  e.command_line
FROM analysis.findings f
JOIN analysis.analyses a ON a.id = f.analysis_id
JOIN ingest.uploads u ON u.id = a.upload_id
JOIN auth.users up ON up.id = u.user_id
JOIN auth.users ca ON ca.id = a.created_by
LEFT JOIN auth.users rv ON rv.id = f.reviewed_by
JOIN analysis.finding_evidence fe ON fe.finding_id = f.id
JOIN ingest.log_events e ON e.id = fe.event_id;
