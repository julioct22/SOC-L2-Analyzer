/**
 * Catálogo MITRE ATT&CK (Enterprise) usado por las reglas de detección.
 * Fuente: https://attack.mitre.org/  — para agregar técnicas, añade una entrada aquí
 * y referénciala desde la regla correspondiente (apps/api/src/modules/analysis/engine/rules.ts).
 */
export const MITRE_TACTICS = {
  TA0043: { name: 'Reconnaissance', es: 'Reconocimiento', order: 1 },
  TA0001: { name: 'Initial Access', es: 'Acceso inicial', order: 2 },
  TA0002: { name: 'Execution', es: 'Ejecución', order: 3 },
  TA0003: { name: 'Persistence', es: 'Persistencia', order: 4 },
  TA0004: { name: 'Privilege Escalation', es: 'Escalada de privilegios', order: 5 },
  TA0005: { name: 'Defense Evasion', es: 'Evasión de defensas', order: 6 },
  TA0006: { name: 'Credential Access', es: 'Acceso a credenciales', order: 7 },
  TA0007: { name: 'Discovery', es: 'Descubrimiento', order: 8 },
  TA0008: { name: 'Lateral Movement', es: 'Movimiento lateral', order: 9 },
  TA0009: { name: 'Collection', es: 'Recolección', order: 10 },
  TA0011: { name: 'Command and Control', es: 'Comando y control', order: 11 },
  TA0010: { name: 'Exfiltration', es: 'Exfiltración', order: 12 },
  TA0040: { name: 'Impact', es: 'Impacto', order: 13 },
} as const;

export type TacticId = keyof typeof MITRE_TACTICS;

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: TacticId[];
}

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  'T1595.003': { id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning', tactics: ['TA0043'] },
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tactics: ['TA0001'] },
  T1133: { id: 'T1133', name: 'External Remote Services', tactics: ['TA0001', 'TA0003'] },
  T1078: { id: 'T1078', name: 'Valid Accounts', tactics: ['TA0001', 'TA0003', 'TA0004', 'TA0005'] },
  'T1110.001': { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactics: ['TA0006'] },
  'T1110.003': { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactics: ['TA0006'] },
  'T1059.001': { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactics: ['TA0002'] },
  'T1059.003': { id: 'T1059.003', name: 'Command and Scripting Interpreter: Windows Command Shell', tactics: ['TA0002'] },
  'T1027.010': { id: 'T1027.010', name: 'Obfuscated Files or Information: Command Obfuscation', tactics: ['TA0005'] },
  'T1053.005': { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task', tactics: ['TA0002', 'TA0003', 'TA0004'] },
  'T1543.003': { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service', tactics: ['TA0003', 'TA0004'] },
  'T1036.004': { id: 'T1036.004', name: 'Masquerading: Masquerade Task or Service', tactics: ['TA0005'] },
  'T1505.003': { id: 'T1505.003', name: 'Server Software Component: Web Shell', tactics: ['TA0003'] },
  T1033: { id: 'T1033', name: 'System Owner/User Discovery', tactics: ['TA0007'] },
  'T1069.001': { id: 'T1069.001', name: 'Permission Groups Discovery: Local Groups', tactics: ['TA0007'] },
  T1135: { id: 'T1135', name: 'Network Share Discovery', tactics: ['TA0007'] },
  'T1021.001': { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol', tactics: ['TA0008'] },
  'T1021.002': { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactics: ['TA0008'] },
  T1039: { id: 'T1039', name: 'Data from Network Shared Drive', tactics: ['TA0009'] },
  'T1560.001': { id: 'T1560.001', name: 'Archive Collected Data: Archive via Utility', tactics: ['TA0009'] },
  'T1074.001': { id: 'T1074.001', name: 'Data Staged: Local Data Staging', tactics: ['TA0009'] },
  'T1071.001': { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactics: ['TA0011'] },
  T1041: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactics: ['TA0010'] },
  'T1048.002': { id: 'T1048.002', name: 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol', tactics: ['TA0010'] },
  T1030: { id: 'T1030', name: 'Data Transfer Size Limits', tactics: ['TA0010'] },
  T1490: { id: 'T1490', name: 'Inhibit System Recovery', tactics: ['TA0040'] },
};

export function mitreUrl(techniqueId: string): string {
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
}

export function tacticsOf(techniqueIds: string[]): TacticId[] {
  const set = new Set<TacticId>();
  for (const id of techniqueIds) MITRE_TECHNIQUES[id]?.tactics.forEach((t) => set.add(t));
  return [...set].sort((a, b) => MITRE_TACTICS[a].order - MITRE_TACTICS[b].order);
}
