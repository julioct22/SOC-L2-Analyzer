/**
 * Lector XLSX mínimo y seguro (sin dependencias con CVEs conocidas).
 *
 * ¿Por qué no ExcelJS/SheetJS? El export de ejemplo del curso lo genera una librería .NET (OpenXML SDK)
 * con rutas absolutas en las relaciones y prefijos de namespace (x:row, x:c) que ExcelJS no soporta, y la
 * versión de SheetJS publicada en npm (0.18.x) tiene vulnerabilidades conocidas al leer archivos manipulados.
 *
 * Este lector: descomprime con fflate (con límite anti zip-bomb), parsea XML ignorando prefijos y soporta
 * shared strings, inline strings, números, booleanos y fechas con formato de fecha.
 */
import { unzipSync, type UnzipFileInfo } from 'fflate';
import { XMLParser } from 'fast-xml-parser';

export type CellValue = string | number | boolean | Date | null;

export interface Sheet {
  name: string;
  /** Filas como arreglos indexados por columna (0 = A). rows[0] es la fila 1 de Excel. */
  rows: CellValue[][];
}

const MAX_UNCOMPRESSED = 300 * 1024 * 1024;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  removeNSPrefix: true,
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: false,
  processEntities: true,
  isArray: (name) => ['sheet', 'Relationship', 'si', 'r', 'row', 'c', 'xf', 'numFmt'].includes(name),
});

type XmlNode = Record<string, unknown>;

function text(node: unknown): string {
  if (node === undefined || node === null) return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (typeof node === 'object' && '#text' in (node as XmlNode)) return String((node as XmlNode)['#text']);
  return '';
}

/** Texto de un <si> o <is>: puede ser <t> simple o varios <r><t> (rich text) */
function richText(node: XmlNode | undefined): string {
  if (!node) return '';
  if (node.t !== undefined) return text(node.t);
  if (Array.isArray(node.r)) return (node.r as XmlNode[]).map((r) => text(r.t)).join('');
  return '';
}

function colIndex(ref: string): number {
  const letters = /^[A-Z]+/.exec(ref)?.[0] ?? 'A';
  let n = 0;
  for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n - 1;
}

function resolveTarget(base: string, target: string): string {
  if (target.startsWith('/')) return target.slice(1);
  const parts = base.split('/').slice(0, -1);
  for (const seg of target.split('/')) {
    if (seg === '..') parts.pop();
    else if (seg !== '.') parts.push(seg);
  }
  return parts.join('/');
}

function relsPath(file: string): string {
  const i = file.lastIndexOf('/');
  return `${file.slice(0, i + 1)}_rels/${file.slice(i + 1)}.rels`;
}

const BUILTIN_DATE_FORMATS = new Set([14, 15, 16, 17, 18, 19, 20, 21, 22, 27, 30, 36, 45, 46, 47, 50, 57]);

/** Serial de Excel (sistema 1900) -> Date UTC "flotante" */
function excelDate(serial: number): Date {
  return new Date(Math.round((serial - 25569) * 86400) * 1000);
}

export function readXlsx(buffer: Buffer): Sheet[] {
  let total = 0;
  const files = unzipSync(new Uint8Array(buffer), {
    filter: (f: UnzipFileInfo) => {
      total += f.originalSize;
      if (total > MAX_UNCOMPRESSED) throw new Error('El archivo descomprimido excede el tamaño permitido');
      return f.name.endsWith('.xml') || f.name.endsWith('.rels');
    },
  });
  const decoder = new TextDecoder('utf-8');
  const read = (name: string): XmlNode | null => {
    const key = Object.keys(files).find((k) => k.toLowerCase() === name.toLowerCase());
    return key ? (parser.parse(decoder.decode(files[key])) as XmlNode) : null;
  };

  const rootRels = read('_rels/.rels');
  const officeRel = ((rootRels?.Relationships as XmlNode)?.Relationship as XmlNode[] | undefined)?.find((r) =>
    String(r['@Type']).endsWith('/officeDocument'),
  );
  const workbookPath = officeRel ? resolveTarget('', String(officeRel['@Target'])) : 'xl/workbook.xml';
  const workbook = read(workbookPath);
  if (!workbook) throw new Error('No se encontró workbook.xml');

  const wbRels = ((read(relsPath(workbookPath))?.Relationships as XmlNode)?.Relationship as XmlNode[] | undefined) ?? [];
  const relTarget = (type: string) => wbRels.find((r) => String(r['@Type']).endsWith(`/${type}`));

  // Shared strings
  const sstRel = relTarget('sharedStrings');
  const sst = sstRel ? read(resolveTarget(workbookPath, String(sstRel['@Target']))) : null;
  const shared = (((sst?.sst as XmlNode)?.si as XmlNode[]) ?? []).map(richText);

  // Estilos: qué índices de estilo son fechas
  const stylesRel = relTarget('styles');
  const styles = stylesRel ? read(resolveTarget(workbookPath, String(stylesRel['@Target']))) : null;
  const ss = styles?.styleSheet as XmlNode | undefined;
  const customFormats = new Map<number, string>(
    (((ss?.numFmts as XmlNode)?.numFmt as XmlNode[]) ?? []).map((f) => [Number(f['@numFmtId']), String(f['@formatCode'])]),
  );
  const dateStyle = (((ss?.cellXfs as XmlNode)?.xf as XmlNode[]) ?? []).map((xf) => {
    const id = Number(xf['@numFmtId'] ?? 0);
    if (BUILTIN_DATE_FORMATS.has(id)) return true;
    const code = customFormats.get(id)?.replace(/"[^"]*"|\[[^\]]*\]/g, '') ?? '';
    return /[dmyhs]/i.test(code) && !/^general$/i.test(code);
  });

  const sheetsMeta = (((workbook.workbook as XmlNode)?.sheets as XmlNode)?.sheet as XmlNode[]) ?? [];
  const sheets: Sheet[] = [];
  for (const meta of sheetsMeta) {
    const rid = String(meta['@id'] ?? '');
    const rel = wbRels.find((r) => String(r['@Id']) === rid);
    if (!rel) continue;
    const doc = read(resolveTarget(workbookPath, String(rel['@Target'])));
    const rowsXml = (((doc?.worksheet as XmlNode)?.sheetData as XmlNode)?.row as XmlNode[]) ?? [];
    const rows: CellValue[][] = [];
    let nextRow = 1;
    for (const row of rowsXml) {
      const r = row['@r'] ? Number(row['@r']) : nextRow;
      nextRow = r + 1;
      const values: CellValue[] = [];
      let nextCol = 0;
      for (const c of (row.c as XmlNode[]) ?? []) {
        const col = c['@r'] ? colIndex(String(c['@r'])) : nextCol;
        nextCol = col + 1;
        const t = String(c['@t'] ?? 'n');
        const raw = text(c.v);
        let value: CellValue = null;
        if (t === 's') value = shared[Number(raw)] ?? null;
        else if (t === 'inlineStr') value = richText(c.is as XmlNode);
        else if (t === 'str') value = raw;
        else if (t === 'b') value = raw === '1';
        else if (t === 'e') value = null;
        else if (raw !== '') {
          const num = Number(raw);
          value = Number.isFinite(num) && dateStyle[Number(c['@s'] ?? 0)] ? excelDate(num) : num;
        }
        values[col] = value === '' ? null : value;
      }
      rows[r - 1] = values;
    }
    sheets.push({ name: String(meta['@name'] ?? `Hoja${sheets.length + 1}`), rows });
  }
  return sheets;
}
