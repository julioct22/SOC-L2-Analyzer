import fs from 'node:fs/promises';
import path from 'node:path';
import { env } from '../config/env.js';

/** Raíz absoluta de datos (volumen Docker /data) */
export const DATA_ROOT = path.resolve(env.DATA_DIR);

/** Limpia un segmento de ruta para que no pueda escapar de la carpeta (path traversal). */
export function safeSegment(name: string): string {
  return (
    name
      .normalize('NFKD')
      .replace(/[̀-ͯ]/g, '')
      .replace(/[^A-Za-z0-9._-]+/g, '_')
      .replace(/^\.+/, '')
      .slice(0, 120) || 'archivo'
  );
}

/** Convierte una ruta relativa guardada en BD en absoluta, verificando que quede dentro de DATA_ROOT. */
export function resolveData(relPath: string): string {
  const abs = path.resolve(DATA_ROOT, relPath);
  if (!abs.startsWith(DATA_ROOT + path.sep)) throw new Error('Ruta fuera del directorio de datos');
  return abs;
}

export async function writeDataFile(relPath: string, content: Buffer): Promise<string> {
  const abs = resolveData(relPath);
  await fs.mkdir(path.dirname(abs), { recursive: true });
  await fs.writeFile(abs, content, { flag: 'wx' });
  return abs;
}
