import type { FastifyInstance, FastifyRequest } from 'fastify';
import { and, desc, eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import { FINDING_STATUSES, SEVERITIES, type AnalysisListItem } from '@soc/shared';
import { db } from '../../db/client.js';
import { analyses, findings, uploads, users } from '../../db/schema.js';
import { badRequest, conflict, forbidden, notFound } from '../../lib/errors.js';
import { requirePerm } from '../../plugins/auth.js';
import { audit } from '../audit/audit.service.js';
import { runAiForAnalysis } from '../ai/narrative.service.js';
import { getUploadForUser } from '../uploads/uploads.routes.js';
import { createAnalysis, getAnalysisDTO, getAnalysisOwner } from './analysis.service.js';

const uuid = z.string().uuid();

export async function assertAnalysisAccess(req: FastifyRequest, analysisId: string) {
  if (!uuid.safeParse(analysisId).success) throw notFound('Análisis no encontrado');
  const owner = await getAnalysisOwner(analysisId);
  if (!owner) throw notFound('Análisis no encontrado');
  if (req.user.role !== 'admin' && owner.uploadOwner !== req.user.id) throw forbidden('No tiene acceso a este análisis');
  return owner;
}

const ReviewBody = z
  .object({
    status: z.enum(FINDING_STATUSES).optional(),
    severityOverride: z.enum(SEVERITIES).nullable().optional(),
    analystNotes: z.string().max(5000).nullable().optional(),
  })
  .refine((b) => Object.keys(b).length > 0, 'Nada que actualizar');

export async function analysisRoutes(app: FastifyInstance) {
  const log = { info: (m: string) => app.log.info(m), error: (m: string) => app.log.error(m) };

  // ── Ejecutar análisis sobre una carga ──────────────────────────
  app.post<{ Params: { uploadId: string } }>('/uploads/:uploadId/analyses', { preHandler: requirePerm('analysis:run') }, async (req, reply) => {
    const upload = await getUploadForUser(req, req.params.uploadId);
    const running = await db
      .select({ id: analyses.id })
      .from(analyses)
      .where(and(eq(analyses.uploadId, upload.id), eq(analyses.status, 'running')));
    if (running.length) throw conflict('Ya hay un análisis en curso para esta carga');
    const id = await createAnalysis(upload.id, req.user.id);
    const dto = await getAnalysisDTO(id);
    await audit(req, {
      action: 'analysis.created',
      entityType: 'analysis',
      entityId: id,
      details: { uploadId: upload.id, file: upload.originalName, findings: dto.findings.length, incidents: dto.incidents.length },
    });
    // La redacción con IA corre en segundo plano; la web consulta el estado (aiStatus)
    if (dto.aiStatus === 'pending') void runAiForAnalysis(id, log);
    reply.code(201);
    return dto;
  });

  // ── Listado (por carga o recientes) ────────────────────────────
  app.get('/analyses', { preHandler: requirePerm('uploads:read') }, async (req): Promise<AnalysisListItem[]> => {
    const q = z.object({ uploadId: uuid.optional() }).parse(req.query);
    const where = [];
    if (q.uploadId) where.push(eq(analyses.uploadId, q.uploadId));
    if (req.user.role !== 'admin') where.push(eq(uploads.userId, req.user.id));
    const rows = await db
      .select({ a: analyses, uploadName: uploads.originalName, createdBy: users.username })
      .from(analyses)
      .innerJoin(uploads, eq(uploads.id, analyses.uploadId))
      .innerJoin(users, eq(users.id, analyses.createdBy))
      .where(where.length ? and(...where) : undefined)
      .orderBy(desc(analyses.createdAt))
      .limit(q.uploadId ? 100 : 10);
    const counts = rows.length
      ? await db
          .select({
            analysisId: findings.analysisId,
            total: sql<number>`count(*)::int`,
            critical: sql<number>`count(*) filter (where coalesce(${findings.severityOverride}, ${findings.severity}) = 'critical' and ${findings.status} <> 'false_positive')::int`,
            high: sql<number>`count(*) filter (where coalesce(${findings.severityOverride}, ${findings.severity}) = 'high' and ${findings.status} <> 'false_positive')::int`,
            pending: sql<number>`count(*) filter (where ${findings.status} = 'pending_review')::int`,
          })
          .from(findings)
          .where(inArray(findings.analysisId, rows.map((r) => r.a.id)))
          .groupBy(findings.analysisId)
      : [];
    return rows.map((r) => {
      const c = counts.find((x) => x.analysisId === r.a.id);
      return {
        id: r.a.id,
        uploadId: r.a.uploadId,
        uploadName: r.uploadName,
        createdAt: r.a.createdAt.toISOString(),
        createdBy: r.createdBy,
        status: r.a.status,
        findingsCount: c?.total ?? 0,
        criticalCount: c?.critical ?? 0,
        highCount: c?.high ?? 0,
        pendingCount: c?.pending ?? 0,
      };
    });
  });

  app.get<{ Params: { id: string } }>('/analyses/:id', { preHandler: requirePerm('uploads:read') }, async (req) => {
    await assertAnalysisAccess(req, req.params.id);
    return getAnalysisDTO(req.params.id);
  });

  // ── Reintentar la redacción con IA ─────────────────────────────
  app.post<{ Params: { id: string } }>('/analyses/:id/ai', { preHandler: requirePerm('analysis:run') }, async (req) => {
    await assertAnalysisAccess(req, req.params.id);
    const [a] = await db.select().from(analyses).where(eq(analyses.id, req.params.id));
    if (a.status !== 'completed') throw badRequest('El análisis no está completado');
    await audit(req, { action: 'analysis.ai_requested', entityType: 'analysis', entityId: a.id });
    void runAiForAnalysis(a.id, log);
    return { ok: true };
  });

  // ── Revisión L2 de un hallazgo ─────────────────────────────────
  app.patch<{ Params: { id: string } }>('/findings/:id', { preHandler: requirePerm('findings:review') }, async (req) => {
    if (!uuid.safeParse(req.params.id).success) throw notFound('Hallazgo no encontrado');
    const body = ReviewBody.parse(req.body);
    const [f] = await db.select().from(findings).where(eq(findings.id, req.params.id));
    if (!f) throw notFound('Hallazgo no encontrado');
    await assertAnalysisAccess(req, f.analysisId);
    if (body.status === 'false_positive' && !(body.analystNotes ?? f.analystNotes)?.trim()) {
      throw badRequest('Para marcar un falso positivo debe registrar la justificación en las notas');
    }
    if (body.severityOverride && body.severityOverride !== f.severity && !(body.analystNotes ?? f.analystNotes)?.trim()) {
      throw badRequest('Para cambiar la criticidad debe registrar la justificación en las notas');
    }
    const [updated] = await db
      .update(findings)
      .set({ ...body, reviewedBy: req.user.id, reviewedAt: new Date() })
      .where(eq(findings.id, f.id))
      .returning();
    await audit(req, {
      action: 'finding.reviewed',
      entityType: 'finding',
      entityId: f.id,
      details: {
        title: f.title,
        before: { status: f.status, severityOverride: f.severityOverride, analystNotes: f.analystNotes },
        after: { status: updated.status, severityOverride: updated.severityOverride, analystNotes: updated.analystNotes },
      },
    });
    return { ok: true };
  });

  // ── Resumen para el dashboard de inicio ────────────────────────
  app.get('/dashboard', { preHandler: requirePerm('uploads:read') }, async (req) => {
    const ownerFilter = req.user.role !== 'admin' ? eq(uploads.userId, req.user.id) : undefined;
    const [{ uploadsCount }] = await db.select({ uploadsCount: sql<number>`count(*)::int` }).from(uploads).where(ownerFilter);
    const [{ analysesCount }] = await db
      .select({ analysesCount: sql<number>`count(*)::int` })
      .from(analyses)
      .innerJoin(uploads, eq(uploads.id, analyses.uploadId))
      .where(ownerFilter);
    const sev = await db
      .select({ severity: sql<string>`coalesce(${findings.severityOverride}, ${findings.severity})`, status: findings.status, count: sql<number>`count(*)::int` })
      .from(findings)
      .innerJoin(analyses, eq(analyses.id, findings.analysisId))
      .innerJoin(uploads, eq(uploads.id, analyses.uploadId))
      .where(ownerFilter)
      .groupBy(sql`1`, findings.status);
    return { uploadsCount, analysesCount, findings: sev };
  });
}
