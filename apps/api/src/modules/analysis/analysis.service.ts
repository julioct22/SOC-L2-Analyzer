import { asc, desc, eq, inArray } from 'drizzle-orm';
import type { AnalysisDTO, FindingDTO, IncidentDTO, Severity } from '@soc/shared';
import { db } from '../../db/client.js';
import { analyses, findingEvidence, findings, logEvents, uploads, users } from '../../db/schema.js';
import { notFound } from '../../lib/errors.js';
import { env } from '../../config/env.js';
import { runEngine, ENGINE_VERSION, type EventRow } from './engine/index.js';
import { buildEngineSummary, buildEngineRecommendations } from './engine/narrative.js';

const EVIDENCE_BATCH = 1000;

/** Ejecuta el motor sobre una carga y guarda todo. Devuelve el id del análisis. */
export async function createAnalysis(uploadId: string, userId: string): Promise<string> {
  const [upload] = await db.select().from(uploads).where(eq(uploads.id, uploadId));
  if (!upload) throw notFound('Carga no encontrada');
  const [analysis] = await db
    .insert(analyses)
    .values({ uploadId, createdBy: userId, engineVersion: ENGINE_VERSION, status: 'running', aiStatus: env.aiEnabled ? 'pending' : 'disabled' })
    .returning();

  try {
    const rows: EventRow[] = await db
      .select({
        id: logEvents.id,
        rowNumber: logEvents.rowNumber,
        logId: logEvents.logId,
        ts: logEvents.ts,
        hostname: logEvents.hostname,
        eventId: logEvents.eventId,
        userName: logEvents.userName,
        sourceIp: logEvents.sourceIp,
        destination: logEvents.destination,
        logSource: logEvents.logSource,
        description: logEvents.description,
        commandLine: logEvents.commandLine,
        result: logEvents.result,
        severitySrc: logEvents.severitySrc,
      })
      .from(logEvents)
      .where(eq(logEvents.uploadId, uploadId))
      .orderBy(asc(logEvents.rowNumber));

    const result = runEngine(rows);

    await db.transaction(async (tx) => {
      const keyToId = new Map<string, string>();
      for (const f of result.findings) {
        const [row] = await tx
          .insert(findings)
          .values({
            analysisId: analysis.id,
            ruleId: f.ruleId,
            title: f.title,
            severity: f.severity,
            score: f.score,
            scoreFactors: f.scoreFactors,
            justification: f.justification,
            mitre: f.mitre,
            entities: f.entities,
            firstSeen: f.firstSeen,
            lastSeen: f.lastSeen,
            eventCount: f.evidence.length,
            summary: f.summary,
            technicalExplanation: f.technicalExplanation,
            impact: f.impact,
            actionPlan: f.actionPlan,
            incidentKey: f.incidentKey,
            l1Verdict: f.l1Verdict,
            l1Rationale: f.l1Rationale,
          })
          .returning({ id: findings.id });
        keyToId.set(f.key, row.id);
        const ev = f.evidence.map((e) => ({ findingId: row.id, eventId: e.id, logId: e.logId }));
        for (let i = 0; i < ev.length; i += EVIDENCE_BATCH) await tx.insert(findingEvidence).values(ev.slice(i, i + EVIDENCE_BATCH));
      }
      const incidents: IncidentDTO[] = result.incidents.map((inc) => ({
        key: inc.key,
        title: inc.title,
        severity: inc.severity,
        findingIds: inc.findingKeys.map((k) => keyToId.get(k)!).filter(Boolean),
        tactics: inc.tactics,
        firstSeen: inc.firstSeen,
        lastSeen: inc.lastSeen,
        entities: inc.entities,
        correlation: inc.correlation,
      }));
      await tx
        .update(analyses)
        .set({
          status: 'completed',
          completedAt: new Date(),
          stats: result.stats,
          incidents,
          dataQuality: result.dataQuality,
          executiveSummary: buildEngineSummary(result, upload.originalName),
          generalRecommendations: buildEngineRecommendations(result),
        })
        .where(eq(analyses.id, analysis.id));
    });
  } catch (err) {
    await db
      .update(analyses)
      .set({ status: 'failed', error: (err as Error).message, aiStatus: 'disabled' })
      .where(eq(analyses.id, analysis.id));
    throw err;
  }
  return analysis.id;
}

function effective(sev: Severity, override: Severity | null): Severity {
  return override ?? sev;
}

export async function getFindingsWithEvidence(analysisId: string): Promise<FindingDTO[]> {
  const rows = await db
    .select({ f: findings, reviewer: users.username })
    .from(findings)
    .leftJoin(users, eq(users.id, findings.reviewedBy))
    .where(eq(findings.analysisId, analysisId))
    .orderBy(desc(findings.score), asc(findings.firstSeen));
  if (!rows.length) return [];
  const ev = await db
    .select({ findingId: findingEvidence.findingId, logId: findingEvidence.logId, ts: logEvents.ts })
    .from(findingEvidence)
    .innerJoin(logEvents, eq(logEvents.id, findingEvidence.eventId))
    .where(inArray(findingEvidence.findingId, rows.map((r) => r.f.id)))
    .orderBy(asc(logEvents.ts), asc(logEvents.rowNumber));
  return rows.map(({ f, reviewer }) => ({
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    effectiveSeverity: effective(f.severity, f.severityOverride),
    score: f.score,
    scoreFactors: f.scoreFactors,
    justification: f.justification,
    mitre: f.mitre,
    entities: f.entities,
    firstSeen: f.firstSeen?.replace('T', ' ').slice(0, 19) ?? null,
    lastSeen: f.lastSeen?.replace('T', ' ').slice(0, 19) ?? null,
    eventCount: f.eventCount,
    summary: f.summary,
    technicalExplanation: f.technicalExplanation,
    impact: f.impact,
    actionPlan: f.actionPlan,
    evidenceLogIds: ev.filter((e) => e.findingId === f.id).map((e) => e.logId),
    incidentKey: f.incidentKey,
    status: f.status,
    l1Verdict: f.l1Verdict,
    l1Rationale: f.l1Rationale,
    narrativeSource: f.narrativeSource === 'ai' ? 'ai' : 'engine',
    severityOverride: f.severityOverride,
    analystNotes: f.analystNotes,
    reviewedBy: reviewer,
    reviewedAt: f.reviewedAt?.toISOString() ?? null,
  }));
}

export async function getAnalysisDTO(analysisId: string): Promise<AnalysisDTO> {
  const [row] = await db
    .select({ a: analyses, uploadName: uploads.originalName, createdBy: users.username, uploadOwner: uploads.userId })
    .from(analyses)
    .innerJoin(uploads, eq(uploads.id, analyses.uploadId))
    .innerJoin(users, eq(users.id, analyses.createdBy))
    .where(eq(analyses.id, analysisId));
  if (!row) throw notFound('Análisis no encontrado');
  const { a } = row;
  return {
    id: a.id,
    uploadId: a.uploadId,
    uploadName: row.uploadName,
    createdAt: a.createdAt.toISOString(),
    createdBy: row.createdBy,
    status: a.status as AnalysisDTO['status'],
    engineVersion: a.engineVersion,
    stats: a.stats ?? null,
    aiStatus: a.aiStatus as AnalysisDTO['aiStatus'],
    aiModel: a.aiModel,
    aiError: a.aiError,
    aiRejected: a.aiRejected,
    executiveSummary: a.executiveSummary,
    generalRecommendations: a.generalRecommendations,
    dataQuality: a.dataQuality,
    incidents: a.incidents,
    findings: await getFindingsWithEvidence(a.id),
    error: a.error,
  };
}

/** Dueño de la carga asociada (para control de acceso) */
export async function getAnalysisOwner(analysisId: string): Promise<{ uploadOwner: string; uploadId: string } | null> {
  const [row] = await db
    .select({ uploadOwner: uploads.userId, uploadId: uploads.id })
    .from(analyses)
    .innerJoin(uploads, eq(uploads.id, analyses.uploadId))
    .where(eq(analyses.id, analysisId));
  return row ?? null;
}
