import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import { ZodError } from 'zod';
import { env } from './config/env.js';
import { pool } from './db/client.js';
import { runMigrations } from './db/migrate.js';
import { seedAdmin } from './db/seed.js';
import { HttpError } from './lib/errors.js';
import authPlugin from './plugins/auth.js';
import { authRoutes } from './modules/auth/auth.routes.js';
import { usersRoutes } from './modules/users/users.routes.js';
import { auditRoutes } from './modules/audit/audit.routes.js';
import { uploadsRoutes } from './modules/uploads/uploads.routes.js';
import { analysisRoutes } from './modules/analysis/analysis.routes.js';
import { reportsRoutes } from './modules/reports/reports.routes.js';
import { closeBrowser } from './modules/reports/pdf.js';

const app = Fastify({
  logger: {
    level: env.LOG_LEVEL,
    transport: env.NODE_ENV === 'development' ? { target: 'pino-pretty', options: { translateTime: 'SYS:HH:MM:ss' } } : undefined,
    redact: ['req.headers.cookie', 'req.headers.authorization'],
  },
  trustProxy: true, // detrás de nginx: req.ip = IP real del cliente (para la auditoría)
  bodyLimit: 1024 * 1024,
});

// Errores uniformes { error, details? }
app.setErrorHandler((err, req, reply) => {
  if (err instanceof ZodError) {
    return reply.code(400).send({ error: 'Datos inválidos', details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) });
  }
  if (err instanceof HttpError) return reply.code(err.statusCode).send({ error: err.message, details: err.details });
  const status = (err as { statusCode?: number }).statusCode ?? 500;
  if (status >= 500) req.log.error(err);
  return reply.code(status).send({ error: status >= 500 ? 'Error interno del servidor' : (err as Error).message });
});

await app.register(helmet, { contentSecurityPolicy: false });
await app.register(rateLimit, { global: false });
await app.register(multipart);
await app.register(authPlugin);

app.get('/api/health', async () => {
  await pool.query('select 1');
  return { status: 'ok', ai: env.aiProvider };
});

await app.register(authRoutes, { prefix: '/api/auth' });
await app.register(usersRoutes, { prefix: '/api/users' });
await app.register(auditRoutes, { prefix: '/api/audit' });
await app.register(uploadsRoutes, { prefix: '/api/uploads' });
await app.register(analysisRoutes, { prefix: '/api' });
await app.register(reportsRoutes, { prefix: '/api' });

const log = (m: string) => app.log.info(m);
await runMigrations(log);
await seedAdmin(log);

const shutdown = async (signal: string) => {
  app.log.info(`${signal} recibido, cerrando...`);
  await app.close();
  await closeBrowser();
  await pool.end();
  process.exit(0);
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: '0.0.0.0', port: env.PORT });
app.log.info(`API escuchando en :${env.PORT} (IA ${env.aiEnabled ? `habilitada: ${env.aiProvider} / ${env.aiModel}` : 'deshabilitada'})`);
