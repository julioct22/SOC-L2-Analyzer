import { defineConfig } from 'drizzle-kit';

// Genera migraciones SQL a partir de src/db/schema.ts:  yarn db:generate
// Las migraciones se aplican automáticamente al arrancar la API (src/db/migrate.ts).
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema.ts',
  out: './drizzle',
  schemaFilter: ['auth', 'ingest', 'analysis', 'audit'],
  dbCredentials: {
    url: process.env.DATABASE_URL ?? 'postgres://soc:soc@localhost:5432/soc_l2',
  },
});
