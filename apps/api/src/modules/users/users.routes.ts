import type { FastifyInstance } from 'fastify';
import { and, asc, eq, isNull, sql } from 'drizzle-orm';
import { z } from 'zod';
import { ROLES } from '@soc/shared';
import { db } from '../../db/client.js';
import { sessions, users } from '../../db/schema.js';
import { badRequest, conflict, notFound } from '../../lib/errors.js';
import { hashPassword, passwordPolicyError } from '../../lib/password.js';
import { requirePerm } from '../../plugins/auth.js';
import { audit } from '../audit/audit.service.js';
import { toUserDTO } from './users.mapper.js';

const CreateBody = z.object({
  username: z
    .string()
    .trim()
    .min(3)
    .max(64)
    .regex(/^[A-Za-z0-9._-]+$/, 'Solo letras, números, punto, guion y guion bajo'),
  fullName: z.string().trim().min(3).max(128),
  role: z.enum(ROLES),
  password: z.string().min(1).max(256),
});

const UpdateBody = z.object({
  fullName: z.string().trim().min(3).max(128).optional(),
  role: z.enum(ROLES).optional(),
  isActive: z.boolean().optional(),
});

const ResetBody = z.object({ password: z.string().min(1).max(256) });

/** Administración de usuarios (solo rol admin) */
export async function usersRoutes(app: FastifyInstance) {
  const guard = { preHandler: requirePerm('users:manage') };

  app.get('/', guard, async () => {
    const rows = await db.select().from(users).orderBy(asc(users.username));
    return rows.map(toUserDTO);
  });

  app.post('/', guard, async (req, reply) => {
    const body = CreateBody.parse(req.body);
    const policy = passwordPolicyError(body.password);
    if (policy) throw badRequest(policy);
    const exists = await db.select({ id: users.id }).from(users).where(sql`lower(${users.username}) = lower(${body.username})`);
    if (exists.length) throw conflict('Ya existe un usuario con ese nombre');
    const [created] = await db
      .insert(users)
      .values({
        username: body.username,
        fullName: body.fullName,
        role: body.role,
        passwordHash: await hashPassword(body.password),
        mustChangePassword: true,
        createdBy: req.user.id,
      })
      .returning();
    await audit(req, { action: 'user.created', entityType: 'user', entityId: created.id, details: { username: created.username, role: created.role } });
    reply.code(201);
    return toUserDTO(created);
  });

  app.patch<{ Params: { id: string } }>('/:id', guard, async (req) => {
    const body = UpdateBody.parse(req.body);
    const [target] = await db.select().from(users).where(eq(users.id, req.params.id));
    if (!target) throw notFound('Usuario no encontrado');
    if (target.id === req.user.id && (body.isActive === false || (body.role && body.role !== 'admin'))) {
      throw badRequest('No puede desactivarse ni quitarse el rol de administrador a sí mismo');
    }
    // Evita quedarse sin administradores activos
    if (target.role === 'admin' && (body.isActive === false || (body.role && body.role !== 'admin'))) {
      const [{ count }] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(users)
        .where(and(eq(users.role, 'admin'), eq(users.isActive, true)));
      if (count <= 1) throw badRequest('Debe existir al menos un administrador activo');
    }
    const [updated] = await db
      .update(users)
      .set({ ...body, updatedAt: new Date() })
      .where(eq(users.id, target.id))
      .returning();
    if (body.isActive === false) {
      await db.update(sessions).set({ revokedAt: new Date() }).where(and(eq(sessions.userId, target.id), isNull(sessions.revokedAt)));
    }
    await audit(req, {
      action: 'user.updated',
      entityType: 'user',
      entityId: target.id,
      details: { username: target.username, before: { fullName: target.fullName, role: target.role, isActive: target.isActive }, after: body },
    });
    return toUserDTO(updated);
  });

  app.post<{ Params: { id: string } }>('/:id/reset-password', guard, async (req) => {
    const body = ResetBody.parse(req.body);
    const policy = passwordPolicyError(body.password);
    if (policy) throw badRequest(policy);
    const [target] = await db.select().from(users).where(eq(users.id, req.params.id));
    if (!target) throw notFound('Usuario no encontrado');
    await db
      .update(users)
      .set({ passwordHash: await hashPassword(body.password), mustChangePassword: true, failedLogins: 0, lockedUntil: null, updatedAt: new Date() })
      .where(eq(users.id, target.id));
    await db.update(sessions).set({ revokedAt: new Date() }).where(and(eq(sessions.userId, target.id), isNull(sessions.revokedAt)));
    await audit(req, { action: 'user.password_reset', entityType: 'user', entityId: target.id, details: { username: target.username } });
    return { ok: true };
  });
}
