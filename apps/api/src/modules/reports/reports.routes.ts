import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { asc, desc, eq, inArray } from 'drizzle-orm';
import { z } from 'zod';
import type { ReportDTO } from '@soc/shared';
import { env } from '../../config/env.js';
import { db } from '../../db/client.js';
import { analyses, findingEvidence, logEvents, reports, uploads, users } from '../../db/schema.js';
import { badRequest, notFound } from '../../lib/errors.js';
import { resolveData, safeSegment, writeDataFile } from '../../lib/storage.js';
import { displayDateTime, fileTime, folderDay } from '../../lib/time.js';
import { requirePerm } from '../../plugins/auth.js';
import { audit } from '../audit/audit.service.js';
import { getAnalysisDTO } from '../analysis/analysis.service.js';
import { assertAnalysisAccess } from '../analysis/analysis.routes.js';
import { htmlToPdf } from './pdf.js';
import { renderReport, type EvidenceRow } from './report.template.js';

const GenerateBody = z
  .object({ includePending: z.boolean().default(true), format: z.enum(['summary', 'full']).default('summary') })
  .default({ includePending: true, format: 'summary' });

async function listReports(analysisId: string): Promise<ReportDTO[]> {
  const rows = await db
    .select({ r: reports, by: users.username })
    .from(reports)
    .innerJoin(users, eq(users.id, reports.generatedBy))
    .where(eq(reports.analysisId, analysisId))
    .orderBy(desc(reports.generatedAt));
  return rows.map(({ r, by }) => ({
    id: r.id,
    analysisId: r.analysisId,
    fileName: r.fileName,
    sha256: r.sha256,
    sizeBytes: r.sizeBytes,
    generatedAt: r.generatedAt.toISOString(),
    generatedBy: by,
  }));
}

/** Filas de log que sustentan cada hallazgo (findingId -> filas) */
async function loadEvidence(findingIds: string[]): Promise<Map<string, EvidenceRow[]>> {
  const evidence = new Map<string, EvidenceRow[]>();
  if (!findingIds.length) return evidence;
  const evRows = await db
    .select({ findingId: findingEvidence.findingId, e: logEvents })
    .from(findingEvidence)
    .innerJoin(logEvents, eq(logEvents.id, findingEvidence.eventId))
    .where(inArray(findingEvidence.findingId, findingIds))
    .orderBy(asc(logEvents.ts), asc(logEvents.rowNumber));
  for (const { findingId, e } of evRows) {
    const list = evidence.get(findingId) ?? [];
    list.push({
      logId: e.logId,
      ts: e.ts?.replace('T', ' ').slice(0, 19) ?? e.tsRaw,
      hostname: e.hostname,
      eventId: e.eventId,
      user: e.userName,
      sourceIp: e.sourceIp,
      destination: e.destination,
      description: e.description,
      commandLine: e.commandLine,
      result: e.result,
    });
    evidence.set(findingId, list);
  }
  return evidence;
}

export async function reportsRoutes(app: FastifyInstance) {
  app.get<{ Params: { id: string } }>('/analyses/:id/reports', { preHandler: requirePerm('reports:read') }, async (req) => {
    await assertAnalysisAccess(req, req.params.id);
    return listReports(req.params.id);
  });

  // ── Generar PDF ─────────────────────────────────────────────────
  app.post<{ Params: { id: string } }>('/analyses/:id/reports', { preHandler: requirePerm('reports:generate') }, async (req, reply) => {
    await assertAnalysisAccess(req, req.params.id);
    const body = GenerateBody.parse(req.body ?? {});
    const analysis = await getAnalysisDTO(req.params.id);
    if (analysis.status !== 'completed') throw badRequest('El análisis no está completado');
    if (analysis.aiStatus === 'pending') throw badRequest('La IA aún está redactando el informe; espere a que termine');

    const included = analysis.findings.filter((f) => f.status !== 'false_positive' && (body.includePending || f.status === 'confirmed'));
    const excludedFp = analysis.findings.filter((f) => f.status === 'false_positive').length;
    if (!included.length && analysis.findings.length) throw badRequest('No hay hallazgos para incluir con los filtros seleccionados');

    const evidence = await loadEvidence(included.map((f) => f.id));

    const [up] = await db
      .select({ u: uploads, by: users.username })
      .from(uploads)
      .innerJoin(users, eq(users.id, uploads.userId))
      .where(eq(uploads.id, analysis.uploadId));
    const now = new Date();
    const html = renderReport({
      format: body.format,
      analysis,
      findings: included,
      evidence,
      orgName: env.ORG_NAME,
      generatedAt: displayDateTime(now),
      generatedBy: `${req.user.fullName} (${req.user.username})`,
      upload: {
        originalName: up.u.originalName,
        sha256: up.u.sha256,
        rowCount: up.u.rowCount,
        uploadedAt: displayDateTime(up.u.uploadedAt),
        uploadedBy: up.by,
      },
      includePending: body.includePending,
      excludedFalsePositives: excludedFp,
    });
    const kind = body.format === 'full' ? 'Informe completo' : 'Informe resumido';
    const pdf = await htmlToPdf(html, `${env.ORG_NAME} · ${kind} SOC L2`);
    const sha256 = crypto.createHash('sha256').update(pdf).digest('hex');
    const fileName = `Informe_${body.format === 'full' ? 'Completo' : 'Resumido'}_${safeSegment(path.parse(up.u.originalName).name)}_${fileTime(now)}.pdf`;
    const relPath = path.posix.join('Reports', safeSegment(req.user.username), folderDay(now), fileName);
    await writeDataFile(relPath, pdf);
    const [rep] = await db
      .insert(reports)
      .values({ analysisId: analysis.id, generatedBy: req.user.id, fileName, filePath: relPath, sha256, sizeBytes: pdf.length, generatedAt: now })
      .returning();
    await audit(req, {
      action: 'report.generated',
      entityType: 'report',
      entityId: rep.id,
      details: { analysisId: analysis.id, file: relPath, sha256, findings: included.length, includePending: body.includePending, format: body.format },
    });
    reply.code(201);
    return (await listReports(analysis.id)).find((r) => r.id === rep.id);
  });

  // ── Descargar PDF ───────────────────────────────────────────────
  app.get<{ Params: { id: string } }>('/reports/:id/download', { preHandler: requirePerm('reports:read') }, async (req, reply) => {
    if (!z.string().uuid().safeParse(req.params.id).success) throw notFound('Informe no encontrado');
    const [rep] = await db.select().from(reports).where(eq(reports.id, req.params.id));
    if (!rep) throw notFound('Informe no encontrado');
    await assertAnalysisAccess(req, rep.analysisId);
    const content = await fs.readFile(resolveData(rep.filePath));
    await audit(req, { action: 'report.downloaded', entityType: 'report', entityId: rep.id, details: { file: rep.fileName } });
    const inline = (req.query as Record<string, string>)?.inline === '1';
    reply
      .header('Content-Type', 'application/pdf')
      .header('Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename="${encodeURIComponent(rep.fileName)}"`);
    return content;
  });

  // ── Vista previa HTML (útil para ajustar el diseño del informe) ─
  app.get<{ Params: { id: string } }>('/analyses/:id/report-preview', { preHandler: requirePerm('reports:read') }, async (req, reply) => {
    await assertAnalysisAccess(req, req.params.id);
    const analysis = await getAnalysisDTO(req.params.id);
    const [a] = await db.select().from(analyses).where(eq(analyses.id, analysis.id));
    const [up] = await db.select().from(uploads).where(eq(uploads.id, a.uploadId));
    const included = analysis.findings.filter((f) => f.status !== 'false_positive');
    const format = (req.query as Record<string, string>)?.format === 'full' ? 'full' : 'summary';
    const html = renderReport({
      format,
      analysis,
      findings: included,
      evidence: await loadEvidence(included.map((f) => f.id)),
      orgName: env.ORG_NAME,
      generatedAt: displayDateTime(new Date()),
      generatedBy: req.user.username,
      upload: { originalName: up.originalName, sha256: up.sha256, rowCount: up.rowCount, uploadedAt: displayDateTime(up.uploadedAt), uploadedBy: '' },
      includePending: true,
      excludedFalsePositives: analysis.findings.length - included.length,
    });
    reply.header('Content-Type', 'text/html; charset=utf-8');
    return html;
  });
}
