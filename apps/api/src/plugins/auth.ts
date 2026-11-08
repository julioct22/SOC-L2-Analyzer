import fp from 'fastify-plugin';
import cookie from '@fastify/cookie';
import jwt from '@fastify/jwt';
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from 'fastify';
import { and, eq, gt, isNull } from 'drizzle-orm';
import { can, type Permission, type Role } from '@soc/shared';
import { env } from '../config/env.js';
import { db } from '../db/client.js';
import { sessions, users } from '../db/schema.js';
import { forbidden, unauthorized } from '../lib/errors.js';
import { audit } from '../modules/audit/audit.service.js';

export const SESSION_COOKIE = 'soc_session';

export interface AuthUser {
  id: string;
  username: string;
  fullName: string;
  role: Role;
  sessionId: string;
  mustChangePassword: boolean;
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { sub: string; sid: string };
    user: AuthUser;
  }
}

declare module 'fastify' {
  interface FastifyContextConfig {
    /** Permite acceder a la ruta aunque el usuario deba cambiar su contraseña */
    allowPendingPasswordChange?: boolean;
  }
}

/**
 * Autenticación por cookie httpOnly que contiene un JWT con el id de sesión.
 * En cada petición se valida contra auth.sessions (permite cerrar sesiones / desactivar usuarios al instante).
 */
export default fp(async (app) => {
  await app.register(cookie);
  await app.register(jwt, {
    secret: env.JWT_SECRET,
    cookie: { cookieName: SESSION_COOKIE, signed: false },
    sign: { expiresIn: `${env.SESSION_HOURS}h` },
  });
});

export const authenticate: preHandlerAsyncHookHandler = async function (req: FastifyRequest, _reply: FastifyReply) {
  let payload: { sub: string; sid: string };
  try {
    payload = (await req.jwtVerify()) as unknown as { sub: string; sid: string };
  } catch {
    throw unauthorized('Sesión inválida o expirada');
  }
  const [row] = await db
    .select({
      id: users.id,
      username: users.username,
      fullName: users.fullName,
      role: users.role,
      isActive: users.isActive,
      mustChangePassword: users.mustChangePassword,
    })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(and(eq(sessions.id, payload.sid), eq(sessions.userId, payload.sub), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date())))
    .limit(1);

  if (!row || !row.isActive) throw unauthorized('Sesión inválida o expirada');
  req.user = {
    id: row.id,
    username: row.username,
    fullName: row.fullName,
    role: row.role,
    sessionId: payload.sid,
    mustChangePassword: row.mustChangePassword,
  };
  if (row.mustChangePassword && !req.routeOptions.config?.allowPendingPasswordChange) {
    throw forbidden('Debe cambiar su contraseña antes de continuar');
  }
};

/** preHandler que exige sesión válida + un permiso concreto */
export function requirePerm(perm: Permission): preHandlerAsyncHookHandler[] {
  const check: preHandlerAsyncHookHandler = async (req) => {
    if (!can(req.user.role, perm)) {
      // Los intentos de acceso no autorizados también quedan en la auditoría
      await audit(req, { action: 'auth.forbidden', details: { permission: perm, method: req.method, url: req.url } });
      throw forbidden();
    }
  };
  return [authenticate, check];
}
