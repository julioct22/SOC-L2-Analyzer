/** Roles del sistema. Para agregar uno nuevo: añádelo aquí, en el enum de la BD (db/schema.ts) y en ROLE_PERMISSIONS. */
export const ROLES = ['admin', 'analyst'] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABELS: Record<Role, string> = {
  admin: 'Administrador',
  analyst: 'Analista SOC L2',
};

/** Permisos por rol. El backend los verifica en cada endpoint; la web los usa para mostrar/ocultar opciones. */
export const PERMISSIONS = [
  'users:manage', // crear/editar/desactivar usuarios
  'audit:read', // ver la bitácora de auditoría
  'uploads:create', // subir archivos de logs
  'uploads:read', // ver cargas y eventos
  'analysis:run', // ejecutar análisis
  'findings:review', // validar hallazgos (confirmar / falso positivo)
  'reports:generate', // generar informe PDF
  'reports:read', // descargar informes
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  // El admin administra la plataforma y puede consultar todo (supervisión), pero no opera el análisis.
  admin: ['users:manage', 'audit:read', 'uploads:read', 'reports:read'],
  analyst: ['uploads:create', 'uploads:read', 'analysis:run', 'findings:review', 'reports:generate', 'reports:read'],
};

export function can(role: Role, perm: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(perm) ?? false;
}

/** Niveles de criticidad requeridos por el curso */
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Medio',
  low: 'Bajo',
};

export const SEVERITY_SCALE_TEXT = 'Escala: Crítico ≥90, Alto ≥70, Medio ≥45, Bajo <45.';

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Umbrales de puntuación (0-100) -> criticidad. Si los cambias, actualiza SEVERITY_SCALE_TEXT. */
export function severityFromScore(score: number): Severity {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 45) return 'medium';
  return 'low';
}

/**
 * Estado de revisión de cada hallazgo.
 * El motor (rol de "analista L1") propone; el analista L2 decide.
 */
export const FINDING_STATUSES = ['pending_review', 'confirmed', 'false_positive'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  pending_review: 'Pendiente de validación L2',
  confirmed: 'Confirmado por L2',
  false_positive: 'Falso positivo',
};

export const L1_VERDICTS = ['likely_true_positive', 'needs_context', 'likely_false_positive'] as const;
export type L1Verdict = (typeof L1_VERDICTS)[number];

export const L1_VERDICT_LABELS: Record<L1Verdict, string> = {
  likely_true_positive: 'Probable verdadero positivo',
  needs_context: 'Requiere más contexto',
  likely_false_positive: 'Probable falso positivo',
};

/** Columnas esperadas del export del SIEM (Excel) */
export const EXPECTED_COLUMNS = [
  'Log_ID',
  'Timestamp',
  'Hostname',
  'Event_ID',
  'User',
  'Source_IP',
  'Destination',
  'Log_Source',
  'Event_Description',
  'Process_CommandLine',
  'Result',
  'Severity',
] as const;

/** Columnas mínimas sin las cuales no se puede analizar */
export const REQUIRED_COLUMNS = ['Log_ID', 'Timestamp', 'Hostname', 'Event_ID', 'Event_Description'] as const;
