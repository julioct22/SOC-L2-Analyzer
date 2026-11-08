import type { FastifyInstance } from 'fastify';
import { and, desc, eq, gte, ilike, lte, or, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import type { AuditEntryDTO, Paged } from '@soc/shared';
import { db } from '../../db/client.js';
import { auditLog } from '../../db/schema.js';
import { requirePerm } from '../../plugins/auth.js';

const Query = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(50),
  q: z.string().trim().optional(),
  action: z.string().trim().optional(),
  from: z.string().optional(),
  to: z.string().optional(),
});

export async function auditRoutes(app: FastifyInstance) {
  app.get('/', { preHandler: requirePerm('audit:read') }, async (req): Promise<Paged<AuditEntryDTO>> => {
    const q = Query.parse(req.query);
    const where: SQL[] = [];
    if (q.action) where.push(eq(auditLog.action, q.action));
    if (q.q) where.push(or(ilike(auditLog.username, `%${q.q}%`), ilike(auditLog.action, `%${q.q}%`), ilike(auditLog.entityId, `%${q.q}%`))!);
    if (q.from) where.push(gte(auditLog.at, new Date(q.from)));
    if (q.to) where.push(lte(auditLog.at, new Date(q.to)));
    const cond = where.length ? and(...where) : undefined;
    const [{ total }] = await db.select({ total: sql<number>`count(*)::int` }).from(auditLog).where(cond);
    const rows = await db
      .select()
      .from(auditLog)
      .where(cond)
      .orderBy(desc(auditLog.at), desc(auditLog.id))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize);
    return {
      total,
      page: q.page,
      pageSize: q.pageSize,
      items: rows.map((r) => ({
        id: r.id,
        at: r.at.toISOString(),
        username: r.username,
        action: r.action,
        entityType: r.entityType,
        entityId: r.entityId,
        ip: r.ip,
        details: r.details ?? null,
      })),
    };
  });

  app.get('/actions', { preHandler: requirePerm('audit:read') }, async () => {
    const rows = await db.selectDistinct({ action: auditLog.action }).from(auditLog).orderBy(auditLog.action);
    return rows.map((r) => r.action);
  });
}
