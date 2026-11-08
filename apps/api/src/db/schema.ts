/**
 * Esquema de base de datos (PostgreSQL) — fuente única de verdad.
 *
 *  auth      -> usuarios y sesiones (quién entra y cuándo)
 *  ingest    -> archivos subidos y cada evento de log importado
 *  analysis  -> análisis, hallazgos, evidencias y los informes PDF
 *  audit     -> bitácora inmutable de acciones (trazabilidad)
 *
 * Después de modificar este archivo:  yarn db:generate   (crea una nueva migración en /drizzle)
 * Todas las fechas se guardan en UTC (timestamptz) y se muestran en APP_TIMEZONE.
 */
import { sql } from 'drizzle-orm';
import {
  bigserial,
  boolean,
  index,
  integer,
  jsonb,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
  bigint,
} from 'drizzle-orm/pg-core';
import type {
  ActionPlan,
  AnalysisStats,
  DataQualityNote,
  Entities,
  IncidentDTO,
  MitreRef,
  ScoreFactor,
} from '@soc/shared';

const tstz = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

// ───────────────────────────── auth ─────────────────────────────
export const authSchema = pgSchema('auth');
export const roleEnum = authSchema.enum('role', ['admin', 'analyst']);

export const users = authSchema.table(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    username: varchar('username', { length: 64 }).notNull(),
    fullName: varchar('full_name', { length: 128 }).notNull(),
    /** Hash Argon2id (incluye sal y parámetros). Nunca se guarda la clave en texto plano. */
    passwordHash: text('password_hash').notNull(),
    role: roleEnum('role').notNull().default('analyst'),
    isActive: boolean('is_active').notNull().default(true),
    mustChangePassword: boolean('must_change_password').notNull().default(true),
    failedLogins: integer('failed_logins').notNull().default(0),
    lockedUntil: tstz('locked_until'),
    lastLoginAt: tstz('last_login_at'),
    createdAt: tstz('created_at').notNull().defaultNow(),
    updatedAt: tstz('updated_at').notNull().defaultNow(),
    createdBy: uuid('created_by'),
  },
  (t) => [uniqueIndex('users_username_uq').on(sql`lower(${t.username})`)],
);

export const sessions = authSchema.table(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    ip: varchar('ip', { length: 64 }),
    userAgent: text('user_agent'),
    createdAt: tstz('created_at').notNull().defaultNow(),
    expiresAt: tstz('expires_at').notNull(),
    revokedAt: tstz('revoked_at'),
  },
  (t) => [index('sessions_user_idx').on(t.userId)],
);

// ───────────────────────────── ingest ─────────────────────────────
export const ingestSchema = pgSchema('ingest');

export const uploads = ingestSchema.table(
  'uploads',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id),
    originalName: varchar('original_name', { length: 255 }).notNull(),
    /** Nombre en disco: <nombre>_<hh-mm-ss>.xlsx */
    storedName: varchar('stored_name', { length: 255 }).notNull(),
    /** Ruta relativa a DATA_DIR: Logs_Uploaded/<usuario>/<yyyy_mm_dd>/<storedName> */
    storedPath: text('stored_path').notNull(),
    /** Fecha local (APP_TIMEZONE) de la carga, para el calendario */
    uploadDay: varchar('upload_day', { length: 10 }).notNull(),
    /** SHA-256 del archivo original: cadena de custodia de la evidencia */
    sha256: varchar('sha256', { length: 64 }).notNull(),
    sizeBytes: integer('size_bytes').notNull(),
    sheetName: varchar('sheet_name', { length: 128 }).notNull(),
    rowCount: integer('row_count').notNull(),
    uploadedAt: tstz('uploaded_at').notNull().defaultNow(),
  },
  (t) => [index('uploads_user_day_idx').on(t.userId, t.uploadDay), index('uploads_day_idx').on(t.uploadDay)],
);

/** Una fila por evento del Excel. Los tipos replican las columnas del export del SIEM. */
export const logEvents = ingestSchema.table(
  'log_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    uploadId: uuid('upload_id')
      .notNull()
      .references(() => uploads.id, { onDelete: 'cascade' }),
    rowNumber: integer('row_number').notNull(),
    logId: varchar('log_id', { length: 64 }).notNull(),
    /** Hora del evento tal como viene en el log (sin zona horaria: no se asume ninguna) */
    ts: timestamp('ts', { withTimezone: false, mode: 'string' }),
    tsRaw: varchar('ts_raw', { length: 64 }),
    hostname: varchar('hostname', { length: 128 }),
    eventId: varchar('event_id', { length: 64 }),
    userName: varchar('user_name', { length: 256 }),
    sourceIp: varchar('source_ip', { length: 64 }),
    destination: varchar('destination', { length: 512 }),
    logSource: varchar('log_source', { length: 64 }),
    description: text('description'),
    commandLine: text('command_line'),
    result: varchar('result', { length: 64 }),
    severitySrc: varchar('severity_src', { length: 32 }),
  },
  (t) => [index('log_events_upload_ts_idx').on(t.uploadId, t.ts), index('log_events_upload_logid_idx').on(t.uploadId, t.logId)],
);

// ───────────────────────────── analysis ─────────────────────────────
export const analysisSchema = pgSchema('analysis');
export const severityEnum = analysisSchema.enum('severity', ['critical', 'high', 'medium', 'low']);
export const findingStatusEnum = analysisSchema.enum('finding_status', ['pending_review', 'confirmed', 'false_positive']);
export const l1VerdictEnum = analysisSchema.enum('l1_verdict', ['likely_true_positive', 'needs_context', 'likely_false_positive']);

export const analyses = analysisSchema.table(
  'analyses',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    uploadId: uuid('upload_id')
      .notNull()
      .references(() => uploads.id, { onDelete: 'cascade' }),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.id),
    createdAt: tstz('created_at').notNull().defaultNow(),
    completedAt: tstz('completed_at'),
    status: varchar('status', { length: 16 }).notNull().default('running'),
    engineVersion: varchar('engine_version', { length: 16 }).notNull(),
    stats: jsonb('stats').$type<AnalysisStats>(),
    incidents: jsonb('incidents').$type<IncidentDTO[]>().notNull().default([]),
    dataQuality: jsonb('data_quality').$type<DataQualityNote[]>().notNull().default([]),
    aiStatus: varchar('ai_status', { length: 16 }).notNull().default('disabled'),
    aiModel: varchar('ai_model', { length: 64 }),
    aiError: text('ai_error'),
    /** Textos de la IA descartados por la validación anti-alucinación (trazabilidad) */
    aiRejected: jsonb('ai_rejected').$type<string[]>().notNull().default([]),
    executiveSummary: text('executive_summary'),
    generalRecommendations: jsonb('general_recommendations').$type<string[]>().notNull().default([]),
    error: text('error'),
  },
  (t) => [index('analyses_upload_idx').on(t.uploadId)],
);

export const findings = analysisSchema.table(
  'findings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    analysisId: uuid('analysis_id')
      .notNull()
      .references(() => analyses.id, { onDelete: 'cascade' }),
    ruleId: varchar('rule_id', { length: 64 }).notNull(),
    title: text('title').notNull(),
    severity: severityEnum('severity').notNull(),
    score: integer('score').notNull(),
    scoreFactors: jsonb('score_factors').$type<ScoreFactor[]>().notNull(),
    justification: text('justification').notNull(),
    mitre: jsonb('mitre').$type<MitreRef[]>().notNull(),
    entities: jsonb('entities').$type<Entities>().notNull(),
    firstSeen: timestamp('first_seen', { mode: 'string' }),
    lastSeen: timestamp('last_seen', { mode: 'string' }),
    eventCount: integer('event_count').notNull(),
    summary: text('summary').notNull(),
    technicalExplanation: text('technical_explanation').notNull(),
    impact: text('impact').notNull(),
    actionPlan: jsonb('action_plan').$type<ActionPlan>().notNull(),
    incidentKey: varchar('incident_key', { length: 32 }),
    narrativeSource: varchar('narrative_source', { length: 8 }).notNull().default('engine'),
    l1Verdict: l1VerdictEnum('l1_verdict'),
    l1Rationale: text('l1_rationale'),
    // ---- Revisión del analista L2 ----
    status: findingStatusEnum('status').notNull().default('pending_review'),
    severityOverride: severityEnum('severity_override'),
    analystNotes: text('analyst_notes'),
    reviewedBy: uuid('reviewed_by').references(() => users.id),
    reviewedAt: tstz('reviewed_at'),
  },
  (t) => [index('findings_analysis_idx').on(t.analysisId)],
);

/** Relación hallazgo -> eventos de log que lo sustentan (la evidencia) */
export const findingEvidence = analysisSchema.table(
  'finding_evidence',
  {
    findingId: uuid('finding_id')
      .notNull()
      .references(() => findings.id, { onDelete: 'cascade' }),
    eventId: bigint('event_id', { mode: 'number' })
      .notNull()
      .references(() => logEvents.id, { onDelete: 'cascade' }),
    logId: varchar('log_id', { length: 64 }).notNull(),
  },
  (t) => [primaryKey({ columns: [t.findingId, t.eventId] })],
);

export const reports = analysisSchema.table(
  'reports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    analysisId: uuid('analysis_id')
      .notNull()
      .references(() => analyses.id, { onDelete: 'cascade' }),
    generatedBy: uuid('generated_by')
      .notNull()
      .references(() => users.id),
    generatedAt: tstz('generated_at').notNull().defaultNow(),
    fileName: varchar('file_name', { length: 255 }).notNull(),
    /** Ruta relativa a DATA_DIR: Reports/<usuario>/<yyyy_mm_dd>/<archivo>.pdf */
    filePath: text('file_path').notNull(),
    sha256: varchar('sha256', { length: 64 }).notNull(),
    sizeBytes: integer('size_bytes').notNull(),
  },
  (t) => [index('reports_analysis_idx').on(t.analysisId)],
);

// ───────────────────────────── audit ─────────────────────────────
export const auditSchema = pgSchema('audit');

export const auditLog = auditSchema.table(
  'audit_log',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    at: tstz('at').notNull().defaultNow(),
    userId: uuid('user_id'),
    /** Se guarda también el nombre por si el usuario se renombra o desactiva después */
    username: varchar('username', { length: 64 }),
    action: varchar('action', { length: 64 }).notNull(),
    entityType: varchar('entity_type', { length: 32 }),
    entityId: varchar('entity_id', { length: 64 }),
    ip: varchar('ip', { length: 64 }),
    details: jsonb('details').$type<Record<string, unknown>>(),
  },
  (t) => [index('audit_at_idx').on(t.at), index('audit_user_idx').on(t.userId), index('audit_action_idx').on(t.action)],
);
