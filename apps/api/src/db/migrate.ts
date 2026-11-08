import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { db, pool } from './client.js';

/** Busca la carpeta /drizzle tanto en desarrollo (src/db) como compilado (dist/). */
function migrationsFolder(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [path.resolve(here, '../drizzle'), path.resolve(here, '../../drizzle')];
  const found = candidates.find((p) => fs.existsSync(path.join(p, 'meta', '_journal.json')));
  if (!found) throw new Error(`No se encontró la carpeta de migraciones (buscado en: ${candidates.join(', ')})`);
  return found;
}

/** Espera a que PostgreSQL acepte conexiones y aplica las migraciones pendientes. */
export async function runMigrations(log: (msg: string) => void): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await pool.query('select 1');
      break;
    } catch (err) {
      if (attempt >= 30) throw err;
      log(`Esperando a PostgreSQL (intento ${attempt})...`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  await migrate(db, { migrationsFolder: migrationsFolder() });
  log('Migraciones aplicadas');
}
