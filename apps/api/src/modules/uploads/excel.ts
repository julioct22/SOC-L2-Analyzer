import { readXlsx, type CellValue, type Sheet } from './xlsx-reader.js';
import { EXPECTED_COLUMNS, REQUIRED_COLUMNS } from '@soc/shared';
import { badRequest } from '../../lib/errors.js';

export interface ParsedRow {
  rowNumber: number;
  logId: string;
  ts: string | null;
  tsRaw: string | null;
  hostname: string | null;
  eventId: string | null;
  userName: string | null;
  sourceIp: string | null;
  destination: string | null;
  logSource: string | null;
  description: string | null;
  commandLine: string | null;
  result: string | null;
  severitySrc: string | null;
}

export interface ParsedWorkbook {
  sheetName: string;
  rows: ParsedRow[];
  missingOptional: string[];
}

const MAX_ROWS = 200_000;
const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

/** Convierte un valor de celda a texto plano */
function cellText(v: CellValue | undefined): string | null {
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return formatDate(v);
  const s = String(v).trim();
  return s === '' ? null : s;
}

function pad(n: number) {
  return String(n).padStart(2, '0');
}

/** Las fechas de Excel no tienen zona horaria: se usan los componentes UTC tal cual */
function formatDate(d: Date): string {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

/** Acepta "2026-10-23 07:46:07", "2026-10-23T07:46:07", "23/10/2026 07:46:07". Devuelve formato ISO local sin zona. */
export function parseTimestamp(raw: string | null): string | null {
  if (!raw) return null;
  let m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/.exec(raw);
  if (m) return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6] ?? '00'}`;
  m = /^(\d{2})\/(\d{2})\/(\d{4})[ T](\d{2}):(\d{2})(?::(\d{2}))?/.exec(raw);
  if (m) return `${m[3]}-${m[2]}-${m[1]} ${m[4]}:${m[5]}:${m[6] ?? '00'}`;
  return null;
}

/**
 * Lee el export del SIEM. Busca la hoja que contenga la cabecera "Log_ID" (primeras 10 filas)
 * y mapea columnas sin importar mayúsculas, espacios o guiones bajos.
 */
export async function parseWorkbook(buffer: Buffer): Promise<ParsedWorkbook> {
  let sheets: Sheet[];
  try {
    sheets = readXlsx(buffer);
  } catch (err) {
    throw badRequest(`El archivo no es un Excel .xlsx válido o está dañado (${(err as Error).message})`);
  }

  for (const ws of sheets) {
    for (let h = 0; h < Math.min(10, ws.rows.length); h++) {
      const header = ws.rows[h] ?? [];
      const colIndex = new Map<string, number>();
      header.forEach((v, col) => {
        const t = cellText(v);
        if (t) colIndex.set(norm(t), col);
      });
      if (!colIndex.has(norm('Log_ID'))) continue;

      const missingRequired = REQUIRED_COLUMNS.filter((c) => !colIndex.has(norm(c)));
      if (missingRequired.length) throw badRequest(`Faltan columnas obligatorias en la hoja "${ws.name}": ${missingRequired.join(', ')}`);
      const missingOptional = EXPECTED_COLUMNS.filter((c) => !colIndex.has(norm(c)));

      const get = (row: CellValue[], col: string) => {
        const idx = colIndex.get(norm(col));
        return idx === undefined ? null : cellText(row[idx]);
      };

      const rows: ParsedRow[] = [];
      for (let r = h + 1; r < ws.rows.length; r++) {
        const row = ws.rows[r];
        if (!row) continue;
        const logId = get(row, 'Log_ID');
        if (!logId) continue; // filas vacías
        if (rows.length >= MAX_ROWS) throw badRequest(`El archivo supera el máximo de ${MAX_ROWS} filas`);
        const tsRaw = get(row, 'Timestamp');
        rows.push({
          rowNumber: r + 1,
          logId: logId.slice(0, 64),
          ts: parseTimestamp(tsRaw),
          tsRaw: tsRaw?.slice(0, 64) ?? null,
          hostname: get(row, 'Hostname'),
          eventId: get(row, 'Event_ID'),
          userName: get(row, 'User'),
          sourceIp: get(row, 'Source_IP'),
          destination: get(row, 'Destination'),
          logSource: get(row, 'Log_Source'),
          description: get(row, 'Event_Description'),
          commandLine: get(row, 'Process_CommandLine'),
          result: get(row, 'Result'),
          severitySrc: get(row, 'Severity'),
        });
      }
      if (!rows.length) throw badRequest(`La hoja "${ws.name}" no contiene eventos`);
      return { sheetName: ws.name, rows, missingOptional };
    }
  }
  throw badRequest(`No se encontró una hoja con la cabecera esperada (${EXPECTED_COLUMNS.join(', ')})`);
}
