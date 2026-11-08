/**
 * Motor de análisis determinista ("analista L1 automático").
 *
 *   eventos normalizados -> reglas -> puntuación -> correlación en incidentes -> estadísticas
 *
 * No usa IA: todo lo que produce es reproducible y trazable a eventos concretos (Log_ID).
 * La IA (módulo ai/) solo redacta sobre este resultado y su salida se valida contra él.
 */
import {
  MITRE_TECHNIQUES,
  SEVERITY_ORDER,
  SEVERITY_SCALE_TEXT,
  severityFromScore,
  tacticsOf,
  MITRE_TACTICS,
  type ActionPlan,
  type AnalysisStats,
  type DataQualityNote,
  type Entities,
  type L1Verdict,
  type MitreRef,
  type ScoreFactor,
  type Severity,
  type TacticId,
} from '@soc/shared';
import { RULES } from './rules.js';
import type { Ev, RawFinding } from './types.js';
import { byTime, ipOf, isCriticalAsset, isPrivilegedAccount, isPublicIp, nonEmpty, uniq, MIN } from './helpers.js';

export const ENGINE_VERSION = '1.0.0';

/** Fila tal como viene de ingest.log_events */
export interface EventRow {
  id: number;
  rowNumber: number;
  logId: string;
  ts: string | null;
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

export interface EngineFinding {
  key: string;
  ruleId: string;
  title: string;
  severity: Severity;
  score: number;
  scoreFactors: ScoreFactor[];
  justification: string;
  mitre: MitreRef[];
  entities: Entities;
  firstSeen: string | null;
  lastSeen: string | null;
  evidence: Ev[];
  summary: string;
  technicalExplanation: string;
  impact: string;
  actionPlan: ActionPlan;
  incidentKey: string | null;
  l1Verdict: L1Verdict;
  l1Rationale: string;
  correlationKeys: string[];
}

export interface EngineIncident {
  key: string;
  title: string;
  severity: Severity;
  findingKeys: string[];
  tactics: TacticId[];
  firstSeen: string | null;
  lastSeen: string | null;
  entities: Entities;
  correlation: string[];
}

export interface EngineResult {
  engineVersion: string;
  findings: EngineFinding[];
  incidents: EngineIncident[];
  stats: AnalysisStats;
  dataQuality: DataQualityNote[];
}

const hostKey = (h: string) => h.toUpperCase().replace(/[^A-Z0-9]/g, '');

export function normalize(rows: EventRow[]): Ev[] {
  return rows.map((r) => {
    const ts = r.ts ? r.ts.replace('T', ' ').slice(0, 19) : null;
    const host = (r.hostname ?? '').trim();
    const user = (r.userName ?? '').trim();
    return {
      id: r.id,
      rowNumber: r.rowNumber,
      logId: r.logId,
      ts,
      t: ts ? Date.parse(ts.replace(' ', 'T') + 'Z') : Number.NaN,
      host,
      hostKey: hostKey(host),
      eventId: (r.eventId ?? '').trim(),
      user,
      userKey: user.toLowerCase(),
      srcIp: (r.sourceIp ?? '').trim(),
      dest: (r.destination ?? '').trim(),
      logSource: (r.logSource ?? '').trim(),
      desc: (r.description ?? '').trim(),
      cmd: (r.commandLine ?? '').trim(),
      result: (r.result ?? '').trim(),
      sevSrc: (r.severitySrc ?? '').trim(),
    };
  });
}

function entitiesOf(evs: Ev[]): Entities {
  return {
    hosts: nonEmpty(evs.map((e) => e.host)),
    users: nonEmpty(evs.map((e) => e.user)),
    ips: nonEmpty([...evs.map((e) => e.srcIp), ...evs.map((e) => ipOf(e.dest)).filter(isPublicIp)]),
  };
}

function defaultKeys(evs: Ev[]): string[] {
  return uniq([
    ...nonEmpty(evs.map((e) => e.hostKey)).map((h) => `host:${h}`),
    ...nonEmpty(evs.map((e) => e.userKey)).map((u) => `user:${u}`),
    ...nonEmpty(evs.map((e) => e.srcIp).filter(isPublicIp)).map((i) => `ip:${i}`),
  ]);
}

/** Puntuación: base de la regla + modificadores de la regla + modificadores genéricos de contexto */
function score(raw: RawFinding): { score: number; factors: ScoreFactor[] } {
  const factors: ScoreFactor[] = [{ label: `Base: ${raw.baseLabel}`, points: raw.baseScore }];
  for (const f of raw.extraFactors ?? []) if (f.points) factors.push(f);
  const ext = nonEmpty([...raw.events.map((e) => e.srcIp), ...raw.events.map((e) => ipOf(e.dest))]).filter(isPublicIp);
  if (ext.length) factors.push({ label: `Involucra IP externa (${ext.slice(0, 3).join(', ')})`, points: 10 });
  const priv = nonEmpty(raw.events.map((e) => e.user)).filter(isPrivilegedAccount);
  if (priv.length) factors.push({ label: `Cuenta privilegiada (${priv.join(', ')})`, points: 10 });
  const crit = nonEmpty(raw.events.map((e) => e.host)).filter(isCriticalAsset);
  if (crit.length) factors.push({ label: `Activo crítico (${crit.slice(0, 3).join(', ')})`, points: 5 });
  return { score: Math.min(100, factors.reduce((s, f) => s + f.points, 0)), factors };
}

export function justify(sev: Severity, total: number, factors: ScoreFactor[]): string {
  const label = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo' }[sev];
  const parts = factors.map((f, i) => (i === 0 ? `${f.label} (${f.points})` : `${f.label} (+${f.points})`));
  return `Criticidad ${label} — puntaje ${total}/100 = ${parts.join('; ')}. ${SEVERITY_SCALE_TEXT}`;
}

function mitreRefs(ids: string[]): MitreRef[] {
  return uniq(ids)
    .filter((id) => MITRE_TECHNIQUES[id])
    .map((id) => ({ id, name: MITRE_TECHNIQUES[id].name, tactics: MITRE_TECHNIQUES[id].tactics }));
}

function l1(scoreValue: number, evidenceCount: number): { verdict: L1Verdict; rationale: string } {
  if (scoreValue >= 70)
    return { verdict: 'likely_true_positive', rationale: `Patrón de alta confianza (puntaje ${scoreValue}) respaldado por ${evidenceCount} evento(s); se recomienda confirmarlo y escalar.` };
  return { verdict: 'needs_context', rationale: `Actividad que puede ser legítima (puntaje ${scoreValue}); requiere validar el contexto de negocio antes de escalar.` };
}

// ───────────────────────────── correlación ─────────────────────────────
const RULE_SHORT: Record<string, string> = {
  'CRED-SPRAY': 'Password spraying',
  'CRED-BRUTEFORCE': 'Fuerza bruta',
  'CRED-COMPROMISE': 'Cuenta comprometida',
  'CRED-GUESS-SUCCESS': 'Fuerza bruta exitosa',
  'CRED-RDP-BRUTEFORCE': 'Acceso RDP por fuerza bruta',
  'WEB-SHELL': 'Web shell',
  'WEB-SCAN': 'Sondeo web',
  'PERSIST-SCHEDULED-TASK': 'Tarea programada',
  'PERSIST-SERVICE': 'Servicio malicioso',
  'IMPACT-INHIBIT-RECOVERY': 'Borrado de shadow copies',
  'EXEC-ENCODED-PS': 'PowerShell codificado',
  'LAT-SMB': 'Movimiento lateral SMB',
  'COLL-MASS-ACCESS': 'Acceso masivo a archivos',
  'EXFIL-VOLUME': 'Exfiltración',
  'COLL-ARCHIVE': 'Compresión de datos',
  'C2-OUTBOUND': 'Conexión saliente',
  'DISC-RECON': 'Reconocimiento',
  'COLL-SENSITIVE-SHARE': 'Acceso a recurso sensible',
  'ACCESS-EXTERNAL-LOGON': 'Logon externo',
};

const CORRELATION_GAP_MIN = 60;

function correlate(findings: EngineFinding[]): EngineIncident[] {
  const parent = findings.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const reasons = new Map<number, Set<string>>();
  const range = (f: EngineFinding) => [f.evidence[0]?.t ?? NaN, f.evidence[f.evidence.length - 1]?.t ?? NaN] as const;

  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const shared = findings[i].correlationKeys.filter((k) => findings[j].correlationKeys.includes(k));
      if (!shared.length) continue;
      const [a0, a1] = range(findings[i]);
      const [b0, b1] = range(findings[j]);
      const gap = Math.max(0, b0 - a1, a0 - b1);
      if (!(gap <= CORRELATION_GAP_MIN * MIN)) continue;
      const ri = find(i);
      const rj = find(j);
      parent[rj] = ri;
      const set = reasons.get(ri) ?? new Set<string>();
      for (const s of reasons.get(rj) ?? []) set.add(s);
      shared.forEach((k) => set.add(k.replace(/^host:/, 'equipo ').replace(/^user:/, 'usuario ').replace(/^ip:/, 'IP ')));
      reasons.set(ri, set);
    }
  }

  const groups = new Map<number, EngineFinding[]>();
  findings.forEach((f, i) => {
    const r = find(i);
    groups.set(r, [...(groups.get(r) ?? []), f]);
  });

  const incidents: EngineIncident[] = [];
  const sorted = [...groups.entries()]
    .filter(([, g]) => g.length >= 2)
    .sort(([, a], [, b]) => (a[0].evidence[0]?.t ?? 0) - (b[0].evidence[0]?.t ?? 0));
  sorted.forEach(([root, group], idx) => {
    const key = `INC-${String(idx + 1).padStart(2, '0')}`;
    const ordered = [...group].sort((a, b) => (a.evidence[0]?.t ?? 0) - (b.evidence[0]?.t ?? 0));
    const allEv = ordered.flatMap((f) => f.evidence).sort(byTime);
    const tactics = tacticsOf(ordered.flatMap((f) => f.mitre.map((m) => m.id)));
    const ents = entitiesOf(allEv);
    ordered.forEach((f) => (f.incidentKey = key));
    const chain = uniq(ordered.map((f) => RULE_SHORT[f.ruleId] ?? f.ruleId)).join(' → ');
    incidents.push({
      key,
      title: `${chain} (${ents.hosts.slice(0, 3).join(', ')})`,
      severity: 'low',
      findingKeys: ordered.map((f) => f.key),
      tactics,
      firstSeen: allEv[0]?.ts ?? null,
      lastSeen: allEv[allEv.length - 1]?.ts ?? null,
      entities: ents,
      correlation: [...(reasons.get(root) ?? [])].map((r) => `Comparten ${r} con menos de ${CORRELATION_GAP_MIN} min de diferencia`),
    });
  });
  return incidents;
}

// ───────────────────────────── calidad de datos ─────────────────────────────
function dataQuality(events: Ev[], findings: EngineFinding[]): DataQualityNote[] {
  const notes: DataQualityNote[] = [];
  // Nombres de host que difieren solo en formato
  const byKey = new Map<string, Set<string>>();
  for (const e of events) if (e.host) byKey.set(e.hostKey, (byKey.get(e.hostKey) ?? new Set()).add(e.host));
  for (const [, names] of byKey)
    if (names.size > 1) {
      const counts = [...names].map((n) => `${n} (${events.filter((e) => e.host === n).length})`);
      notes.push({
        type: 'host_inconsistente',
        message: `El mismo equipo aparece con nombres distintos: ${counts.join(', ')}. Se trataron como el mismo activo para correlacionar; verificar en CMDB/AD que no sea un equipo no autorizado con nombre similar.`,
        values: [...names],
      });
    }
  // Cuentas con nombres casi idénticos
  const users = nonEmpty(events.map((e) => e.user));
  // Mismo nombre con distinto orden/separadores (p. ej. backupsvc vs svc_backup). No se usa distancia de edición
  // porque marcaría como sospechosas cuentas legítimas parecidas (jlopez / slopez).
  const bare = (u: string) => (u.split('\\').pop() ?? u).toLowerCase().replace(/[^a-z0-9]/g, '');
  for (let i = 0; i < users.length; i++)
    for (let j = i + 1; j < users.length; j++) {
      const a = bare(users[i]);
      const b = bare(users[j]);
      if (a.length < 5) continue;
      const anagram = a.length === b.length && [...a].sort().join('') === [...b].sort().join('');
      if (anagram) {
        const ca = events.filter((e) => e.user === users[i]).length;
        const cb = events.filter((e) => e.user === users[j]).length;
        notes.push({
          type: 'cuentas_similares',
          message: `Existen cuentas con nombres muy parecidos: ${users[i]} (${ca} eventos) y ${users[j]} (${cb} eventos). Puede ser una inconsistencia del inventario o una cuenta creada para suplantar a otra; validar en Active Directory.`,
          values: [users[i], users[j]],
        });
      }
    }
  // Event_ID no numéricos
  const nonNumeric = nonEmpty(events.map((e) => e.eventId).filter((v) => v && !/^\d+$/.test(v)));
  if (nonNumeric.length)
    notes.push({
      type: 'event_id_mixto',
      message: `La columna Event_ID mezcla IDs de Windows con etiquetas de otras fuentes: ${nonNumeric.join(', ')}. Se almacenan como texto.`,
      values: nonNumeric,
    });
  // Timestamps faltantes
  const noTs = events.filter((e) => Number.isNaN(e.t));
  if (noTs.length)
    notes.push({ type: 'timestamp_invalido', message: `${noTs.length} evento(s) sin fecha válida; no participan en correlaciones temporales.`, values: noTs.slice(0, 20).map((e) => e.logId) });
  // Severidad de origen subestimada
  const evIds = new Set(findings.flatMap((f) => f.evidence.map((e) => e.id)));
  const informational = events.filter((e) => evIds.has(e.id) && /^info/i.test(e.sevSrc));
  if (informational.length)
    notes.push({
      type: 'severidad_origen',
      message: `${informational.length} evento(s) que forman parte de hallazgos venían clasificados como "Informational" en el SIEM (p. ej. ${informational
        .slice(0, 4)
        .map((e) => e.logId)
        .join(', ')}). La criticidad de este informe se recalculó con reglas propias y no depende de la columna Severity.`,
      values: informational.slice(0, 50).map((e) => e.logId),
    });
  return notes;
}

// ───────────────────────────── estadísticas ─────────────────────────────
function countBy(evs: Ev[], key: (e: Ev) => string, top = 12) {
  const m = new Map<string, number>();
  for (const e of evs) {
    const k = key(e) || '(vacío)';
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()]
    .map(([k, count]) => ({ key: k, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, top);
}

function stats(events: Ev[], findings: EngineFinding[]): AnalysisStats {
  const valid = events.filter((e) => !Number.isNaN(e.t)).sort(byTime);
  const suspicious = new Set(findings.flatMap((f) => f.evidence.map((e) => e.id)));
  const bucketMs = 15 * MIN;
  const timeline: AnalysisStats['timeline'] = [];
  if (valid.length) {
    const start = Math.floor(valid[0].t / bucketMs) * bucketMs;
    const end = valid[valid.length - 1].t;
    for (let b = start; b <= end; b += bucketMs) timeline.push({ bucket: new Date(b).toISOString().slice(0, 16).replace('T', ' '), total: 0, suspicious: 0 });
    for (const e of valid) {
      const slot = timeline[Math.floor((e.t - start) / bucketMs)];
      slot.total++;
      if (suspicious.has(e.id)) slot.suspicious++;
    }
  }
  const findingsBySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => findingsBySeverity[f.severity]++);
  const tacticCount = new Map<TacticId, number>();
  findings.forEach((f) => tacticsOf(f.mitre.map((m) => m.id)).forEach((t) => tacticCount.set(t, (tacticCount.get(t) ?? 0) + 1)));
  const susEvents = events.filter((e) => suspicious.has(e.id));
  return {
    totalEvents: events.length,
    timeRange: { from: valid[0]?.ts ?? null, to: valid[valid.length - 1]?.ts ?? null },
    byLogSource: countBy(events, (e) => e.logSource),
    byEventId: countBy(events, (e) => e.eventId, 15),
    byHost: countBy(events, (e) => e.host, 15),
    bySourceSeverity: countBy(events, (e) => e.sevSrc),
    findingsBySeverity,
    byTactic: [...tacticCount.entries()]
      .sort((a, b) => MITRE_TACTICS[a[0]].order - MITRE_TACTICS[b[0]].order)
      .map(([k, count]) => ({ key: `${k} ${MITRE_TACTICS[k].es}`, count })),
    timeline,
    topSuspiciousIps: countBy(
      susEvents.filter((e) => e.srcIp),
      (e) => e.srcIp,
      10,
    ),
    suspiciousEventCount: suspicious.size,
  };
}

// ───────────────────────────── orquestación ─────────────────────────────
export function runEngine(rows: EventRow[]): EngineResult {
  const events = normalize(rows).sort(byTime);
  const ctx = { events, claimed: new Set<number>() };
  const raws = RULES.flatMap((r) => r.run(ctx));

  const findings: EngineFinding[] = raws.map((raw, i) => {
    const evidence = uniq(raw.events).sort(byTime);
    const s = score({ ...raw, events: evidence });
    const sev = severityFromScore(s.score);
    const verdict = l1(s.score, evidence.length);
    return {
      key: `F${i + 1}`,
      ruleId: raw.ruleId,
      title: raw.title,
      severity: sev,
      score: s.score,
      scoreFactors: s.factors,
      justification: justify(sev, s.score, s.factors),
      mitre: mitreRefs(raw.techniques),
      entities: entitiesOf(evidence),
      firstSeen: evidence[0]?.ts ?? null,
      lastSeen: evidence[evidence.length - 1]?.ts ?? null,
      evidence,
      summary: raw.summary,
      technicalExplanation: raw.technicalExplanation,
      impact: raw.impact,
      actionPlan: raw.actionPlan,
      incidentKey: null,
      l1Verdict: verdict.verdict,
      l1Rationale: verdict.rationale,
      correlationKeys: raw.correlationKeys ?? defaultKeys(evidence),
    };
  });

  const incidents = correlate(findings);

  // Bonificación por cadena de ataque: hallazgos en incidentes que cubren 3+ tácticas ATT&CK
  for (const inc of incidents) {
    if (inc.tactics.length >= 3) {
      for (const f of findings.filter((x) => x.incidentKey === inc.key)) {
        f.scoreFactors.push({ label: `Parte del incidente ${inc.key}, cadena con ${inc.tactics.length} tácticas ATT&CK`, points: 5 });
        f.score = Math.min(100, f.score + 5);
        f.severity = severityFromScore(f.score);
        f.justification = justify(f.severity, f.score, f.scoreFactors);
        const v = l1(f.score, f.evidence.length);
        f.l1Verdict = v.verdict;
        f.l1Rationale = v.rationale;
      }
    }
    inc.severity = findings
      .filter((x) => x.incidentKey === inc.key)
      .reduce<Severity>((max, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[max] ? f.severity : max), 'low');
  }

  findings.sort((a, b) => b.score - a.score || (a.evidence[0]?.t ?? 0) - (b.evidence[0]?.t ?? 0));
  return { engineVersion: ENGINE_VERSION, findings, incidents, stats: stats(events, findings), dataQuality: dataQuality(events, findings) };
}
