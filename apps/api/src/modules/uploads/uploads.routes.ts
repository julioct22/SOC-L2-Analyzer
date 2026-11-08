import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { and, asc, desc, eq, ilike, inArray, like, or, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import type { LogEventDTO, Paged, UploadDTO } from '@soc/shared';
import { env } from '../../config/env.js';
import { db } from '../../db/client.js';
import { analyses, findingEvidence, findings, logEvents, uploads, users } from '../../db/schema.js';
import { badRequest, forbidden, notFound } from '../../lib/errors.js';
import { resolveData, safeSegment, writeDataFile } from '../../lib/storage.js';
import { fileTime, folderDay, localDay } from '../../lib/time.js';
import { requirePerm } from '../../plugins/auth.js';
import { audit } from '../audit/audit.service.js';
import { parseWorkbook } from './excel.js';

const ALLOWED_EXT = ['.xlsx'];
const INSERT_BATCH = 500;

/** El analista ve sus propias cargas; el admin (supervisión) ve todas */
export async function getUploadForUser(req: FastifyRequest, uploadId: string) {
  if (!z.string().uuid().safeParse(uploadId).success) throw notFound('Carga no encontrada');
  const [u] = await db.select().from(uploads).where(eq(uploads.id, uploadId));
  if (!u) throw notFound('Carga no encontrada');
  if (req.user.role !== 'admin' && u.userId !== req.user.id) throw forbidden('No tiene acceso a esta carga');
  return u;
}

async function toDTOs(rows: (typeof uploads.$inferSelect)[]): Promise<UploadDTO[]> {
  if (!rows.length) return [];
  const ids = rows.map((r) => r.id);
  const userRows = await db
    .select({ id: users.id, username: users.username })
    .from(users)
    .where(inArray(users.id, [...new Set(rows.map((r) => r.userId))]));
  const analysisRows = await db
    .select({ id: analyses.id, uploadId: analyses.uploadId, createdAt: analyses.createdAt })
    .from(analyses)
    .where(inArray(analyses.uploadId, ids))
    .orderBy(desc(analyses.createdAt));
  return rows.map((r) => {
    const a = analysisRows.filter((x) => x.uploadId === r.id);
    return {
      id: r.id,
      originalName: r.originalName,
      storedName: r.storedName,
      sha256: r.sha256,
      sizeBytes: r.sizeBytes,
      sheetName: r.sheetName,
      rowCount: r.rowCount,
      uploadedAt: r.uploadedAt.toISOString(),
      uploadedBy: userRows.find((u) => u.id === r.userId)?.username ?? '?',
      analysisCount: a.length,
      latestAnalysisId: a[0]?.id ?? null,
    };
  });
}

const ListQuery = z.object({ date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional() });
const DaysQuery = z.object({ month: z.string().regex(/^\d{4}-\d{2}$/) });
const EventsQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(500).default(50),
  q: z.string().trim().max(200).optional(),
  hostname: z.string().optional(),
  eventId: z.string().optional(),
  logSource: z.string().optional(),
  severitySrc: z.string().optional(),
  /** Solo eventos que son evidencia de algún hallazgo de este análisis */
  analysisId: z.string().uuid().optional(),
  findingId: z.string().uuid().optional(),
  sort: z.enum(['ts', 'rowNumber']).default('ts'),
  dir: z.enum(['asc', 'desc']).default('asc'),
});

export async function uploadsRoutes(app: FastifyInstance) {
  // ── Subir archivo ──────────────────────────────────────────────
  app.post('/', { preHandler: requirePerm('uploads:create') }, async (req, reply) => {
    const file = await req.file({ limits: { fileSize: env.MAX_UPLOAD_MB * 1024 * 1024, files: 1 } });
    if (!file) throw badRequest('Debe adjuntar un archivo');
    const ext = path.extname(file.filename).toLowerCase();
    if (!ALLOWED_EXT.includes(ext)) throw badRequest('Solo se permiten archivos Excel .xlsx');
    const buffer = await file.toBuffer();
    if (file.file.truncated) throw badRequest(`El archivo supera el máximo de ${env.MAX_UPLOAD_MB} MB`);
    // Firma ZIP "PK\x03\x04": un .xlsx real es un ZIP. Evita archivos renombrados.
    if (buffer.length < 4 || buffer.readUInt32LE(0) !== 0x04034b50) throw badRequest('El archivo no tiene formato .xlsx válido');

    const parsed = await parseWorkbook(buffer);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const now = new Date();
    const base = safeSegment(path.basename(file.filename, ext));
    const storedName = `${base}_${fileTime(now)}${ext}`;
    const relPath = path.posix.join('Logs_Uploaded', safeSegment(req.user.username), folderDay(now), storedName);
    let finalRel = relPath;
    try {
      await writeDataFile(relPath, buffer);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      finalRel = relPath.replace(ext, `_${crypto.randomBytes(3).toString('hex')}${ext}`);
      await writeDataFile(finalRel, buffer);
    }

    const upload = await db.transaction(async (tx) => {
      const [u] = await tx
        .insert(uploads)
        .values({
          userId: req.user.id,
          originalName: file.filename.slice(0, 255),
          storedName: path.posix.basename(finalRel),
          storedPath: finalRel,
          uploadDay: localDay(now),
          sha256,
          sizeBytes: buffer.length,
          sheetName: parsed.sheetName,
          rowCount: parsed.rows.length,
          uploadedAt: now,
        })
        .returning();
      for (let i = 0; i < parsed.rows.length; i += INSERT_BATCH) {
        await tx.insert(logEvents).values(parsed.rows.slice(i, i + INSERT_BATCH).map((r) => ({ ...r, uploadId: u.id })));
      }
      return u;
    });

    await audit(req, {
      action: 'upload.created',
      entityType: 'upload',
      entityId: upload.id,
      details: { file: upload.originalName, storedPath: upload.storedPath, sha256, rows: upload.rowCount, missingColumns: parsed.missingOptional },
    });
    reply.code(201);
    const [dto] = await toDTOs([upload]);
    return { upload: dto, missingColumns: parsed.missingOptional };
  });

  // ── Listar cargas de un día (calendario) ───────────────────────
  app.get('/', { preHandler: requirePerm('uploads:read') }, async (req) => {
    const q = ListQuery.parse(req.query);
    const where: SQL[] = [eq(uploads.uploadDay, q.date ?? localDay())];
    if (req.user.role !== 'admin') where.push(eq(uploads.userId, req.user.id));
    const rows = await db
      .select()
      .from(uploads)
      .where(and(...where))
      .orderBy(desc(uploads.uploadedAt));
    return toDTOs(rows);
  });

  // ── Últimas cargas (para el dashboard) ─────────────────────────
  app.get('/recent', { preHandler: requirePerm('uploads:read') }, async (req) => {
    const rows = await db
      .select()
      .from(uploads)
      .where(req.user.role !== 'admin' ? eq(uploads.userId, req.user.id) : undefined)
      .orderBy(desc(uploads.uploadedAt))
      .limit(8);
    return toDTOs(rows);
  });

  // ── Días con cargas en un mes (para resaltar el calendario) ────
  app.get('/days', { preHandler: requirePerm('uploads:read') }, async (req) => {
    const q = DaysQuery.parse(req.query);
    const where: SQL[] = [like(uploads.uploadDay, `${q.month}-%`)];
    if (req.user.role !== 'admin') where.push(eq(uploads.userId, req.user.id));
    const rows = await db
      .select({ day: uploads.uploadDay, count: sql<number>`count(*)::int` })
      .from(uploads)
      .where(and(...where))
      .groupBy(uploads.uploadDay);
    return rows;
  });

  app.get<{ Params: { id: string } }>('/:id', { preHandler: requirePerm('uploads:read') }, async (req) => {
    const u = await getUploadForUser(req, req.params.id);
    const [dto] = await toDTOs([u]);
    return dto;
  });

  // ── Eventos (datagrid) con paginación y filtros en servidor ────
  app.get<{ Params: { id: string } }>('/:id/events', { preHandler: requirePerm('uploads:read') }, async (req): Promise<Paged<LogEventDTO>> => {
    const u = await getUploadForUser(req, req.params.id);
    const q = EventsQuery.parse(req.query);
    const where: SQL[] = [eq(logEvents.uploadId, u.id)];
    if (q.q) {
      const like = `%${q.q}%`;
      where.push(
        or(
          ilike(logEvents.logId, like),
          ilike(logEvents.hostname, like),
          ilike(logEvents.userName, like),
          ilike(logEvents.sourceIp, like),
          ilike(logEvents.destination, like),
          ilike(logEvents.description, like),
          ilike(logEvents.commandLine, like),
          ilike(logEvents.eventId, like),
        )!,
      );
    }
    if (q.hostname) where.push(eq(logEvents.hostname, q.hostname));
    if (q.eventId) where.push(eq(logEvents.eventId, q.eventId));
    if (q.logSource) where.push(eq(logEvents.logSource, q.logSource));
    if (q.severitySrc) where.push(eq(logEvents.severitySrc, q.severitySrc));
    if (q.findingId) {
      where.push(inArray(logEvents.id, db.select({ id: findingEvidence.eventId }).from(findingEvidence).where(eq(findingEvidence.findingId, q.findingId))));
    } else if (q.analysisId) {
      where.push(
        inArray(
          logEvents.id,
          db
            .select({ id: findingEvidence.eventId })
            .from(findingEvidence)
            .innerJoin(findings, eq(findings.id, findingEvidence.findingId))
            .where(eq(findings.analysisId, q.analysisId)),
        ),
      );
    }
    const cond = and(...where);
    const [{ total }] = await db.select({ total: sql<number>`count(*)::int` }).from(logEvents).where(cond);
    const sortCol = q.sort === 'ts' ? logEvents.ts : logEvents.rowNumber;
    const rows = await db
      .select()
      .from(logEvents)
      .where(cond)
      .orderBy(q.dir === 'asc' ? asc(sortCol) : desc(sortCol), asc(logEvents.rowNumber))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize);
    return {
      total,
      page: q.page,
      pageSize: q.pageSize,
      items: rows.map((r) => ({
        id: r.id,
        rowNumber: r.rowNumber,
        logId: r.logId,
        ts: r.ts ? r.ts.replace('T', ' ').slice(0, 19) : r.tsRaw,
        hostname: r.hostname,
        eventId: r.eventId,
        user: r.userName,
        sourceIp: r.sourceIp,
        destination: r.destination,
        logSource: r.logSource,
        description: r.description,
        commandLine: r.commandLine,
        result: r.result,
        severitySrc: r.severitySrc,
      })),
    };
  });

  // ── Valores distintos para filtros del datagrid ────────────────
  app.get<{ Params: { id: string } }>('/:id/facets', { preHandler: requirePerm('uploads:read') }, async (req) => {
    const u = await getUploadForUser(req, req.params.id);
    const distinct = async (col: typeof logEvents.hostname | typeof logEvents.eventId | typeof logEvents.logSource | typeof logEvents.severitySrc) =>
      (await db.selectDistinct({ v: col }).from(logEvents).where(eq(logEvents.uploadId, u.id)).orderBy(col)).map((r) => r.v).filter(Boolean);
    return {
      hostname: await distinct(logEvents.hostname),
      eventId: await distinct(logEvents.eventId),
      logSource: await distinct(logEvents.logSource),
      severitySrc: await distinct(logEvents.severitySrc),
    };
  });

  // ── Descargar el archivo original (evidencia) ──────────────────
  app.get<{ Params: { id: string } }>('/:id/download', { preHandler: requirePerm('uploads:read') }, async (req, reply) => {
    const u = await getUploadForUser(req, req.params.id);
    const content = await fs.readFile(resolveData(u.storedPath));
    await audit(req, { action: 'upload.downloaded', entityType: 'upload', entityId: u.id, details: { file: u.storedName } });
    reply
      .header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
      .header('Content-Disposition', `attachment; filename="${encodeURIComponent(u.storedName)}"`);
    return content;
  });
}
