import { env } from '../config/env.js';

function parts(date: Date, tz = env.APP_TIMEZONE): Record<string, string> {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  return Object.fromEntries(fmt.formatToParts(date).map((p) => [p.type, p.value]));
}

/** yyyy-mm-dd en la zona horaria de la app */
export function localDay(date = new Date()): string {
  const p = parts(date);
  return `${p.year}-${p.month}-${p.day}`;
}

/** yyyy_mm_dd (formato de carpeta) */
export function folderDay(date = new Date()): string {
  return localDay(date).replaceAll('-', '_');
}

/** hh-mm-ss (sufijo de archivo) */
export function fileTime(date = new Date()): string {
  const p = parts(date);
  return `${p.hour}-${p.minute}-${p.second}`;
}

/** "07/11/2026 16:30:05" en la zona de la app (para informes) */
export function displayDateTime(date: Date): string {
  const p = parts(date);
  return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}:${p.second}`;
}
