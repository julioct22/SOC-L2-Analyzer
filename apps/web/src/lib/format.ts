import type { Severity } from '@soc/shared';

let timezone = 'America/Panama';
export const setTimezone = (tz: string) => (timezone = tz);

/** Fecha/hora de un ISO (UTC) mostrada en la zona horaria de la app */
export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const p = Object.fromEntries(
    new Intl.DateTimeFormat('en-GB', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    })
      .formatToParts(new Date(iso))
      .map((x) => [x.type, x.value]),
  );
  return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}:${p.second}`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Intl.DateTimeFormat('es-PA', { timeZone: timezone, hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(iso));
}

/** yyyy-mm-dd de una fecha (por defecto hoy) en la zona de la app */
export function ymdLocal(date: Date | string = new Date()): string {
  const p = Object.fromEntries(
    new Intl.DateTimeFormat('en-CA', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' })
      .formatToParts(typeof date === 'string' ? new Date(date) : date)
      .map((x) => [x.type, x.value]),
  );
  return `${p.year}-${p.month}-${p.day}`;
}

export const todayLocal = () => ymdLocal();

export function dateToYmd(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

export function ymdToDate(s: string): Date {
  const [y, m, d] = s.split('-').map(Number);
  return new Date(y, m - 1, d);
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const SEV_HEX: Record<Severity, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

export const SEV_CLASSES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-300 ring-red-500/40',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  medium: 'bg-yellow-500/15 text-yellow-200 ring-yellow-500/40',
  low: 'bg-blue-500/15 text-blue-300 ring-blue-500/40',
};
