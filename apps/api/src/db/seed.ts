import { sql } from 'drizzle-orm';
import { env } from '../config/env.js';
import { hashPassword } from '../lib/password.js';
import { db } from './client.js';
import { auditLog, users } from './schema.js';

/** Crea el administrador inicial (desde .env) solo si no existe ningún usuario. */
export async function seedAdmin(log: (msg: string) => void): Promise<void> {
  const [{ count }] = await db.select({ count: sql<number>`count(*)::int` }).from(users);
  if (count > 0) return;
  const [admin] = await db
    .insert(users)
    .values({
      username: env.ADMIN_USERNAME,
      fullName: env.ADMIN_FULL_NAME,
      passwordHash: await hashPassword(env.ADMIN_PASSWORD),
      role: 'admin',
      mustChangePassword: true,
    })
    .returning();
  await db.insert(auditLog).values({
    userId: admin.id,
    username: admin.username,
    action: 'system.seed_admin',
    entityType: 'user',
    entityId: admin.id,
    details: { note: 'Administrador inicial creado desde variables de entorno' },
  });
  log(`Usuario administrador inicial "${admin.username}" creado (deberá cambiar la clave al ingresar)`);
}
