/**
 * Textos deterministas (sin IA). Se usan siempre como base y como respaldo
 * cuando la IA está deshabilitada o su salida no supera la validación.
 */
import { MITRE_TACTICS, SEVERITY_LABELS } from '@soc/shared';
import type { EngineResult } from './index.js';

export function buildEngineSummary(r: EngineResult, fileName: string): string {
  const s = r.stats;
  const sev = s.findingsBySeverity;
  const total = r.findings.length;
  if (!total) {
    return `Se analizaron ${s.totalEvents} eventos del archivo "${fileName}" (${s.timeRange.from ?? '¿?'} a ${s.timeRange.to ?? '¿?'}). Las reglas de detección no identificaron actividad sospechosa. Esto no garantiza la ausencia de amenazas: solo refleja lo observable en los registros proporcionados.`;
  }
  const lines: string[] = [];
  lines.push(
    `Se analizaron ${s.totalEvents} eventos del archivo "${fileName}" correspondientes al periodo ${s.timeRange.from} a ${s.timeRange.to}. ` +
      `El análisis automatizado identificó ${total} hallazgos (${sev.critical} críticos, ${sev.high} altos, ${sev.medium} medios y ${sev.low} bajos) sustentados por ${s.suspiciousEventCount} eventos de evidencia` +
      (r.incidents.length ? `, agrupados en ${r.incidents.length} incidentes correlacionados.` : '.'),
  );
  for (const inc of r.incidents) {
    const tactics = inc.tactics.map((t) => MITRE_TACTICS[t].es).join(', ');
    lines.push(`• ${inc.key} [${SEVERITY_LABELS[inc.severity]}] ${inc.title}: ${inc.firstSeen?.slice(11) ?? ''}–${inc.lastSeen?.slice(11) ?? ''}; tácticas ATT&CK: ${tactics}.`);
  }
  const crit = r.findings.filter((f) => f.severity === 'critical');
  if (crit.length) {
    lines.push(`Los hallazgos críticos requieren acción inmediata: ${crit.map((f) => f.title).join('; ')}.`);
  }
  lines.push('Todos los hallazgos deben ser validados por el analista L2 antes de considerarse confirmados.');
  return lines.join('\n');
}

export function buildEngineRecommendations(r: EngineResult): string[] {
  const rules = new Set(r.findings.map((f) => f.ruleId));
  const rec: string[] = [];
  if ([...rules].some((x) => x.startsWith('CRED-') || x === 'ACCESS-EXTERNAL-LOGON'))
    rec.push('Implementar MFA obligatorio para todo acceso remoto y cuentas privilegiadas, y política de bloqueo por intentos fallidos.');
  if (rules.has('CRED-RDP-BRUTEFORCE')) rec.push('Eliminar la exposición de RDP a Internet; usar VPN o Remote Desktop Gateway con MFA.');
  if (rules.has('WEB-SHELL') || rules.has('WEB-SCAN'))
    rec.push('Proteger las aplicaciones web con WAF, deshabilitar la ejecución de scripts en carpetas de subida y restringir paneles administrativos.');
  if ([...rules].some((x) => x.startsWith('PERSIST-'))) rec.push('Monitorear la creación de tareas programadas y servicios (eventos 4698/7045) y aplicar control de aplicaciones (AppLocker/WDAC).');
  if (rules.has('EXEC-ENCODED-PS')) rec.push('Habilitar PowerShell Script Block Logging (4104), AMSI y restringir PowerShell a administradores.');
  if (rules.has('IMPACT-INHIBIT-RECOVERY')) rec.push('Mantener respaldos inmutables y fuera de línea, y probar su restauración periódicamente.');
  if (rules.has('EXFIL-VOLUME') || rules.has('C2-OUTBOUND') || rules.has('COLL-ARCHIVE'))
    rec.push('Forzar la salida a Internet mediante proxy autenticado, implementar DLP y alertas por volumen de datos salientes.');
  if (rules.has('LAT-SMB') || rules.has('COLL-MASS-ACCESS')) rec.push('Segmentar la red, limitar SMB entre servidores y aplicar mínimo privilegio en recursos compartidos y cuentas de servicio.');
  rec.push('Centralizar y retener los logs (Security, PowerShell, Sysmon, proxy, IIS) con sincronización horaria (NTP) y zona horaria documentada.');
  rec.push('Normalizar el inventario de activos y cuentas (CMDB/AD) para evitar nombres inconsistentes que dificultan la correlación.');
  rec.push('Revisar y actualizar el plan de respuesta a incidentes con base en las lecciones de este análisis.');
  return rec;
}
