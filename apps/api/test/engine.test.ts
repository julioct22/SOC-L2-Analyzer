/**
 * Pruebas del motor con el archivo de ejemplo del curso (samples/).
 * Ejecutar:  yarn test
 * Si cambias reglas o umbrales, estas pruebas te avisan si se pierde una detección esperada.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, beforeAll } from 'vitest';
import { parseWorkbook } from '../src/modules/uploads/excel.js';
import { runEngine, type EngineResult } from '../src/modules/analysis/engine/index.js';
import { isPublicIp } from '../src/modules/analysis/engine/helpers.js';

const SAMPLE = path.resolve(__dirname, '../../../samples/SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx');

let result: EngineResult;
let rowCount = 0;

beforeAll(async () => {
  const wb = await parseWorkbook(fs.readFileSync(SAMPLE));
  rowCount = wb.rows.length;
  result = runEngine(wb.rows.map((r, i) => ({ ...r, id: i + 1 })));
});

const byRule = (id: string) => result.findings.filter((f) => f.ruleId === id);

describe('lector de Excel', () => {
  it('lee todas las filas del export .NET (rutas absolutas y prefijos x:)', () => {
    expect(rowCount).toBe(715);
  });
});

describe('motor de detección', () => {
  it('detecta el password spraying y la cuenta comprometida', () => {
    const spray = byRule('CRED-SPRAY');
    expect(spray).toHaveLength(1);
    expect(spray[0].evidence).toHaveLength(33);
    const comp = byRule('CRED-COMPROMISE');
    expect(comp).toHaveLength(1);
    expect(comp[0].entities.users).toContain('CORP\\mgarcia');
    expect(comp[0].severity).toBe('critical');
  });

  it('detecta la intrusión RDP y su cadena (lateral, staging, salida)', () => {
    expect(byRule('CRED-RDP-BRUTEFORCE')).toHaveLength(1);
    expect(byRule('LAT-SMB')).toHaveLength(1);
    expect(byRule('C2-OUTBOUND')).toHaveLength(1);
    const inc = result.incidents.find((i) => i.findingKeys.includes(byRule('CRED-RDP-BRUTEFORCE')[0].key));
    expect(inc?.tactics.length).toBeGreaterThanOrEqual(6);
  });

  it('detecta persistencia, borrado de shadow copies, web shell y exfiltración', () => {
    expect(byRule('PERSIST-SCHEDULED-TASK')).toHaveLength(1);
    expect(byRule('PERSIST-SERVICE')).toHaveLength(1);
    expect(byRule('IMPACT-INHIBIT-RECOVERY')).toHaveLength(1);
    expect(byRule('WEB-SHELL')).toHaveLength(1);
    const exfil = byRule('EXFIL-VOLUME');
    expect(exfil).toHaveLength(1);
    expect(exfil[0].evidence).toHaveLength(22);
  });

  it('no inventa: toda evidencia existe y cada hallazgo tiene al menos un evento y técnica MITRE', () => {
    const allIds = new Set(Array.from({ length: rowCount }, (_, i) => i + 1));
    for (const f of result.findings) {
      expect(f.evidence.length).toBeGreaterThan(0);
      expect(f.mitre.length).toBeGreaterThan(0);
      for (const e of f.evidence) expect(allIds.has(e.id)).toBe(true);
    }
  });

  it('no correlaciona incidentes independientes solo por compartir un servidor de archivos', () => {
    const rdp = result.incidents.find((i) => i.findingKeys.includes(byRule('CRED-RDP-BRUTEFORCE')[0].key));
    const exfil = result.incidents.find((i) => i.findingKeys.includes(byRule('EXFIL-VOLUME')[0].key));
    expect(rdp?.key).not.toBe(exfil?.key);
  });

  it('reporta problemas de calidad de datos', () => {
    const types = result.dataQuality.map((d) => d.type);
    expect(types).toContain('host_inconsistente');
    expect(types).toContain('cuentas_similares');
  });
});

describe('helpers', () => {
  it('clasifica IPs privadas y públicas', () => {
    expect(isPublicIp('10.10.1.22')).toBe(false);
    expect(isPublicIp('192.168.1.1')).toBe(false);
    expect(isPublicIp('172.20.0.1')).toBe(false);
    expect(isPublicIp('203.0.113.74')).toBe(true);
  });
});
