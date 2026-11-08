import type { ActionPlan, ScoreFactor } from '@soc/shared';

/** Evento normalizado que consumen las reglas */
export interface Ev {
  id: number;
  rowNumber: number;
  logId: string;
  ts: string | null;
  /** Milisegundos para cálculos de ventanas de tiempo (la hora del log se trata sin zona horaria) */
  t: number;
  host: string;
  hostKey: string;
  eventId: string;
  user: string;
  userKey: string;
  srcIp: string;
  dest: string;
  logSource: string;
  desc: string;
  cmd: string;
  result: string;
  sevSrc: string;
}

/** Hallazgo producido por una regla, antes de puntuar/correlacionar */
export interface RawFinding {
  ruleId: string;
  title: string;
  techniques: string[];
  baseScore: number;
  baseLabel: string;
  /** Modificadores propios de la regla (además de los genéricos de scoring.ts) */
  extraFactors?: ScoreFactor[];
  events: Ev[];
  /** Entidades "actoras" usadas para correlacionar. Si se omite se derivan de los eventos. */
  correlationKeys?: string[];
  /** Usuarios objetivo (no actores), p. ej. cuentas atacadas en un password spraying */
  targetUsers?: string[];
  summary: string;
  technicalExplanation: string;
  impact: string;
  actionPlan: ActionPlan;
}

export interface RuleContext {
  events: Ev[];
  /** Ids de eventos ya usados como evidencia principal por reglas anteriores */
  claimed: Set<number>;
}

export interface Rule {
  id: string;
  name: string;
  run(ctx: RuleContext): RawFinding[];
}
