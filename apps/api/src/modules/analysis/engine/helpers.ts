import type { Ev } from './types.js';

export const MIN = 60_000;

/** Rangos privados / reservados (RFC1918, loopback, link-local, CGNAT). Lo demás se considera externo. */
export function isPublicIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false;
  return true;
}

/** Extrae una IP de destino tipo "203.0.113.88:443" */
export function ipOf(value: string): string {
  const m = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(value);
  return m ? m[1] : '';
}

export function isFailedLogon(e: Ev): boolean {
  return e.eventId === '4625' || /failed to log ?on/i.test(e.desc);
}

export function isSuccessLogon(e: Ev): boolean {
  return e.eventId === '4624' || /successfully logged on/i.test(e.desc);
}

export function logonType(e: Ev): number | null {
  const m = /LogonType\s*=\s*(\d+)/i.exec(e.desc);
  return m ? Number(m[1]) : null;
}

export function isPrivilegedLogon(e: Ev): boolean {
  return e.eventId === '4672' || /special privileges assigned/i.test(e.desc);
}

export function isPrivilegedAccount(user: string): boolean {
  const name = user.split('\\').pop()?.toLowerCase() ?? '';
  return /^(admin|administrator|administrador|root|domain ?admins?)$/.test(name) || /^adm[_-]|[_-]adm$/.test(name);
}

const CRITICAL_ASSET = /^(DC|FS|DB|SQL|APP|WEB|EXCH|ADFS|CA)[-_]?|SRV/i;
export function isCriticalAsset(host: string): boolean {
  return CRITICAL_ASSET.test(host);
}

export const SENSITIVE_DATA = /\b(finance|finanzas|legal|hr|rrhh|payroll|nomina|n[oó]mina|confidencial|confidential|contabilidad|budget|presupuesto)\b/i;

export const SUSPICIOUS_PATH = /\\(programdata|temp|tmp|users\\public|appdata|perflogs)\\/i;

export function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

export function nonEmpty(values: string[]): string[] {
  return uniq(values.filter((v) => v && v !== '-'));
}

export function byTime(a: Ev, b: Ev): number {
  return a.t - b.t || a.rowNumber - b.rowNumber;
}

export function fmtList(values: string[], max = 6): string {
  const v = uniq(values);
  if (v.length <= max) return v.join(', ');
  return `${v.slice(0, max).join(', ')} y ${v.length - max} más`;
}

export function hhmm(e: Ev | undefined): string {
  return e?.ts ? e.ts.slice(11, 19) : '¿?';
}

export function span(evs: Ev[]): string {
  const s = [...evs].sort(byTime);
  return `${s[0]?.ts ?? '¿?'} → ${hhmm(s[s.length - 1])}`;
}

export function logIds(evs: Ev[], max = 5): string {
  const ids = [...evs].sort(byTime).map((e) => e.logId);
  return ids.length <= max ? ids.join(', ') : `${ids.slice(0, max).join(', ')}… (${ids.length} eventos)`;
}

/**
 * Agrupa eventos ordenados en "ráfagas": un evento entra en el grupo si ocurre
 * a menos de `gapMs` del evento anterior del mismo grupo.
 */
export function bursts(evs: Ev[], gapMs: number): Ev[][] {
  const sorted = [...evs].sort(byTime);
  const groups: Ev[][] = [];
  for (const e of sorted) {
    const g = groups[groups.length - 1];
    if (g && e.t - g[g.length - 1].t <= gapMs) g.push(e);
    else groups.push([e]);
  }
  return groups;
}

export function groupBy<T>(arr: T[], key: (x: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const x of arr) {
    const k = key(x);
    if (!k) continue;
    const list = m.get(k);
    if (list) list.push(x);
    else m.set(k, [x]);
  }
  return m;
}

export function bytesOut(e: Ev): number {
  const m = /bytes_out\s*=\s*(\d+)/i.exec(`${e.cmd} ${e.desc}`);
  return m ? Number(m[1]) : 0;
}

export function mb(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
