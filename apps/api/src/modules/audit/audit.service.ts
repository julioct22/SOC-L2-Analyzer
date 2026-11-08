import type { FastifyRequest } from 'fastify';
import { db } from '../../db/client.js';
import { auditLog } from '../../db/schema.js';

export interface AuditInput {
  action: string;
  entityType?: string;
  entityId?: string;
  details?: Record<string, unknown>;
  /** Para eventos sin sesión (p. ej. login fallido) */
  username?: string;
  userId?: string | null;
}

/**
 * Registra una acción en audit.audit_log. La tabla está protegida por un trigger
 * que impide UPDATE/DELETE (ver migración 0001_audit_immutable.sql).
 */
export async function audit(req: FastifyRequest | null, input: AuditInput): Promise<void> {
  const user = req?.user;
  await db.insert(auditLog).values({
    userId: input.userId !== undefined ? input.userId : (user?.id ?? null),
    username: input.username ?? user?.username ?? null,
    action: input.action,
    entityType: input.entityType,
    entityId: input.entityId,
    ip: req?.ip ?? null,
    details: input.details,
  });
}
