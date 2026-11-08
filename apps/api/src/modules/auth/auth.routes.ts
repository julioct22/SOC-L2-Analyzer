import type { FastifyInstance } from 'fastify';
import { and, eq, isNull, ne, sql } from 'drizzle-orm';
import { z } from 'zod';
import { ROLE_PERMISSIONS, type MeDTO } from '@soc/shared';
import { env } from '../../config/env.js';
import { db } from '../../db/client.js';
import { sessions, users } from '../../db/schema.js';
import { badRequest, unauthorized } from '../../lib/errors.js';
import { hashPassword, passwordPolicyError, verifyPassword } from '../../lib/password.js';
import { authenticate, SESSION_COOKIE } from '../../plugins/auth.js';
import { audit } from '../audit/audit.service.js';
import { toUserDTO } from '../users/users.mapper.js';

const MAX_FAILED = 5;
const LOCK_MINUTES = 15;

const LoginBody = z.object({ username: z.string().trim().min(1).max(64), password: z.string().min(1).max(256) });
const ChangePwBody = z.object({ currentPassword: z.string().min(1), newPassword: z.string().min(1).max(256) });

export async function authRoutes(app: FastifyInstance) {
  app.post(
    '/login',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const body = LoginBody.parse(req.body);
      const [user] = await db
        .select()
        .from(users)
        .where(sql`lower(${users.username}) = lower(${body.username})`)
        .limit(1);

      const fail = async (reason: string) => {
        await audit(req, { action: 'auth.login_failed', username: body.username, userId: user?.id ?? null, details: { reason } });
        throw unauthorized('Usuario o contraseña incorrectos');
      };

      if (!user) return fail('usuario_inexistente');
      if (!user.isActive) return fail('usuario_desactivado');
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        await audit(req, { action: 'auth.login_blocked', username: user.username, userId: user.id });
        throw unauthorized(`Cuenta bloqueada temporalmente por intentos fallidos. Intente después de ${LOCK_MINUTES} minutos.`);
      }
      if (!(await verifyPassword(user.passwordHash, body.password))) {
        const failed = user.failedLogins + 1;
        const lock = failed >= MAX_FAILED;
        await db
          .update(users)
          .set({ failedLogins: lock ? 0 : failed, lockedUntil: lock ? new Date(Date.now() + LOCK_MINUTES * 60_000) : null })
          .where(eq(users.id, user.id));
        if (lock) await audit(req, { action: 'auth.account_locked', username: user.username, userId: user.id, details: { minutes: LOCK_MINUTES } });
        return fail('clave_incorrecta');
      }

      const expiresAt = new Date(Date.now() + env.SESSION_HOURS * 3600_000);
      const [session] = await db
        .insert(sessions)
        .values({ userId: user.id, ip: req.ip, userAgent: req.headers['user-agent']?.slice(0, 500), expiresAt })
        .returning();
      const [updated] = await db
        .update(users)
        .set({ lastLoginAt: new Date(), failedLogins: 0, lockedUntil: null })
        .where(eq(users.id, user.id))
        .returning();

      const token = await reply.jwtSign({ sub: user.id, sid: session.id });
      reply.setCookie(SESSION_COOKIE, token, {
        path: '/',
        httpOnly: true,
        sameSite: 'strict',
        secure: env.COOKIE_SECURE,
        expires: expiresAt,
      });
      await audit(req, { action: 'auth.login', username: user.username, userId: user.id, entityType: 'session', entityId: session.id });
      return { user: toUserDTO(updated) };
    },
  );

  app.post('/logout', { preHandler: authenticate, config: { allowPendingPasswordChange: true } }, async (req, reply) => {
    await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, req.user.sessionId));
    await audit(req, { action: 'auth.logout', entityType: 'session', entityId: req.user.sessionId });
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    return { ok: true };
  });

  app.get('/me', { preHandler: authenticate, config: { allowPendingPasswordChange: true } }, async (req): Promise<MeDTO> => {
    const [user] = await db.select().from(users).where(eq(users.id, req.user.id));
    return {
      user: toUserDTO(user),
      permissions: [...ROLE_PERMISSIONS[user.role]],
      aiEnabled: env.aiEnabled,
      aiProvider: env.aiProvider,
      aiModel: env.aiModel,
      timezone: env.APP_TIMEZONE,
    };
  });

  app.post('/change-password', { preHandler: authenticate, config: { allowPendingPasswordChange: true } }, async (req) => {
    const body = ChangePwBody.parse(req.body);
    const [user] = await db.select().from(users).where(eq(users.id, req.user.id));
    if (!(await verifyPassword(user.passwordHash, body.currentPassword))) throw badRequest('La contraseña actual no es correcta');
    if (body.currentPassword === body.newPassword) throw badRequest('La nueva contraseña debe ser distinta a la actual');
    const policy = passwordPolicyError(body.newPassword);
    if (policy) throw badRequest(policy);
    await db
      .update(users)
      .set({ passwordHash: await hashPassword(body.newPassword), mustChangePassword: false, updatedAt: new Date() })
      .where(eq(users.id, user.id));
    // Cierra las demás sesiones abiertas del usuario
    await db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(and(eq(sessions.userId, user.id), ne(sessions.id, req.user.sessionId), isNull(sessions.revokedAt)));
    await audit(req, { action: 'auth.password_changed', entityType: 'user', entityId: user.id });
    return { ok: true };
  });
}
