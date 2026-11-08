/**
 * Redacción asistida por IA con validación anti-alucinación.
 *
 * Flujo:
 *  1. Se envían a la IA SOLO los hallazgos del motor y su evidencia (filas de log reales).
 *  2. La IA devuelve un JSON estructurado (tool use) que se valida con Zod.
 *  3. Cada texto se verifica contra los datos: los Log_ID citados deben pertenecer a la evidencia del hallazgo,
 *     y cualquier Log_ID, IP o técnica MITRE mencionada debe existir en el archivo/hallazgos.
 *  4. Lo que no pasa la verificación se descarta (queda registrado) y se mantiene el texto del motor.
 */
import { asc, eq, inArray } from 'drizzle-orm';
import { MITRE_TECHNIQUES } from '@soc/shared';
import { env } from '../../config/env.js';
import { db } from '../../db/client.js';
import { analyses, findingEvidence, findings, logEvents, uploads } from '../../db/schema.js';
import { AiOutputSchema, type AiOutput } from './schema.js';
import { getProvider } from './provider.js';

const MAX_EVIDENCE_PER_FINDING = 30;

const SYSTEM_PROMPT = `Eres un analista SOC Nivel 1 que prepara el borrador del informe técnico para que un analista SOC Nivel 2 lo valide.
Escribes en español neutro, profesional y preciso.

REGLAS ESTRICTAS (rigor analítico):
- Usa EXCLUSIVAMENTE la información del JSON que recibes. No inventes hallazgos, eventos, IPs, equipos, usuarios, horarios, archivos ni técnicas.
- Devuelve exactamente un elemento en "findings" por cada hallazgo recibido, con el mismo "ref". No agregues ni fusiones hallazgos.
- En cada hallazgo, cita en "cited_log_ids" solo Log_ID que aparezcan en la evidencia de ESE hallazgo, y menciónalos en el texto cuando sustenten una afirmación.
- Solo menciona técnicas MITRE ATT&CK que ya estén asignadas al hallazgo.
- Si la evidencia no permite afirmar algo (p. ej. el contenido de un comando redactado o si una autenticación web tuvo éxito), dilo explícitamente en lugar de suponer.
- Las horas de los logs no tienen zona horaria: preséntalas tal cual.
- No modifiques la criticidad: es calculada por el motor y validada por el L2. Puedes explicarla.
- "l1_verdict": tu recomendación de triaje para el L2 (likely_true_positive | needs_context | likely_false_positive) con su justificación.
- El resumen ejecutivo debe ser comprensible para gerencia, mencionar los incidentes correlacionados y las acciones prioritarias.`;

/** Extrae tokens verificables de un texto */
function tokens(text: string) {
  return {
    logIds: text.match(/\b[A-Z]{2,6}-\d{3,}\b/g) ?? [],
    ips: text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [],
    techniques: text.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? [],
  };
}

interface Facts {
  allLogIds: Set<string>;
  allIps: Set<string>;
  allTechniques: Set<string>;
}

function checkText(text: string, facts: Facts, allowedTechniques: Set<string>, allowedLogIds?: Set<string>): string | null {
  const t = tokens(text);
  const badLog = t.logIds.find((id) => !facts.allLogIds.has(id) || (allowedLogIds && !allowedLogIds.has(id)));
  if (badLog) return `menciona ${badLog}, que no ${facts.allLogIds.has(badLog) ? 'es evidencia de este hallazgo' : 'existe en el archivo'}`;
  const badIp = t.ips.find((ip) => !facts.allIps.has(ip));
  if (badIp) return `menciona la IP ${badIp}, que no aparece en los logs`;
  const badTech = t.techniques.find((x) => !allowedTechniques.has(x) && !allowedTechniques.has(x.split('.')[0]));
  if (badTech) return `menciona la técnica ${badTech}, no asignada${allowedLogIds ? ' a este hallazgo' : ' a ningún hallazgo'}`;
  return null;
}

export async function runAiForAnalysis(analysisId: string, log: { info: (m: string) => void; error: (m: string) => void }): Promise<void> {
  const provider = getProvider();
  if (!provider) {
    await db.update(analyses).set({ aiStatus: 'disabled' }).where(eq(analyses.id, analysisId));
    return;
  }
  await db.update(analyses).set({ aiStatus: 'pending', aiError: null, aiModel: provider.model }).where(eq(analyses.id, analysisId));

  try {
    const [a] = await db
      .select({ a: analyses, fileName: uploads.originalName })
      .from(analyses)
      .innerJoin(uploads, eq(uploads.id, analyses.uploadId))
      .where(eq(analyses.id, analysisId));
    if (!a) throw new Error('Análisis no encontrado');
    const fRows = await db.select().from(findings).where(eq(findings.analysisId, analysisId));
    if (!fRows.length) {
      await db.update(analyses).set({ aiStatus: 'completed' }).where(eq(analyses.id, analysisId));
      return;
    }

    // Hechos verificables del archivo completo
    const all = await db
      .select({ logId: logEvents.logId, srcIp: logEvents.sourceIp, dest: logEvents.destination, desc: logEvents.description, cmd: logEvents.commandLine })
      .from(logEvents)
      .where(eq(logEvents.uploadId, a.a.uploadId));
    const facts: Facts = {
      allLogIds: new Set(all.map((r) => r.logId)),
      allIps: new Set(all.flatMap((r) => tokens(`${r.srcIp ?? ''} ${r.dest ?? ''} ${r.desc ?? ''} ${r.cmd ?? ''}`).ips)),
      allTechniques: new Set(fRows.flatMap((f) => f.mitre.flatMap((m) => [m.id, m.id.split('.')[0]]))),
    };

    const evRows = await db
      .select({ findingId: findingEvidence.findingId, e: logEvents })
      .from(findingEvidence)
      .innerJoin(logEvents, eq(logEvents.id, findingEvidence.eventId))
      .where(inArray(findingEvidence.findingId, fRows.map((f) => f.id)))
      .orderBy(asc(logEvents.ts), asc(logEvents.rowNumber));

    const refs = new Map<string, (typeof fRows)[number]>();
    const payloadFindings = fRows
      .sort((x, y) => y.score - x.score)
      .map((f, i) => {
        const ref = `H${String(i + 1).padStart(2, '0')}`;
        refs.set(ref, f);
        const ev = evRows.filter((r) => r.findingId === f.id);
        return {
          ref,
          title: f.title,
          rule: f.ruleId,
          severity: f.severity,
          score: f.score,
          justification: f.justification,
          mitre: f.mitre.map((m) => `${m.id} ${m.name}`),
          incident: f.incidentKey,
          entities: f.entities,
          first_seen: f.firstSeen,
          last_seen: f.lastSeen,
          engine_summary: f.summary,
          engine_explanation: f.technicalExplanation,
          evidence_total: ev.length,
          evidence: ev.slice(0, MAX_EVIDENCE_PER_FINDING).map(({ e }) => ({
            Log_ID: e.logId,
            Timestamp: e.ts?.replace('T', ' ').slice(0, 19) ?? e.tsRaw,
            Hostname: e.hostname,
            Event_ID: e.eventId,
            User: e.userName,
            Source_IP: e.sourceIp,
            Destination: e.destination,
            Log_Source: e.logSource,
            Event_Description: e.description,
            Process_CommandLine: e.commandLine,
            Result: e.result,
          })),
        };
      });

    const payload = {
      organizacion: env.ORG_NAME,
      archivo: a.fileName,
      estadisticas: a.a.stats
        ? { total_eventos: a.a.stats.totalEvents, periodo: a.a.stats.timeRange, hallazgos_por_criticidad: a.a.stats.findingsBySeverity }
        : null,
      incidentes_correlacionados: a.a.incidents.map((inc) => ({
        key: inc.key,
        title: inc.title,
        severity: inc.severity,
        tacticas: inc.tactics,
        desde: inc.firstSeen,
        hasta: inc.lastSeen,
        hallazgos: inc.findingIds.map((id) => [...refs.entries()].find(([, f]) => f.id === id)?.[0]).filter(Boolean),
        correlacion: inc.correlation,
      })),
      observaciones_calidad_datos: a.a.dataQuality.map((d) => d.message),
      hallazgos: payloadFindings,
    };

    const userMsg = `Redacta el informe técnico a partir de estos datos (JSON). Devuelve el resultado con la estructura solicitada (executive_summary, general_recommendations, findings).\n\n${JSON.stringify(payload)}`;
    const raw = await provider.generate(SYSTEM_PROMPT, userMsg);
    const parsed = AiOutputSchema.safeParse(raw);
    if (!parsed.success) throw new Error(`Respuesta de IA con formato inválido: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);

    const rejected = await applyAiOutput(parsed.data, refs, evRows, facts, analysisId);
    await db.update(analyses).set({ aiStatus: 'completed', aiRejected: rejected }).where(eq(analyses.id, analysisId));
    log.info(`IA completada para análisis ${analysisId} (${rejected.length} texto(s) descartado(s) por validación)`);
  } catch (err) {
    const message = (err as Error).message ?? String(err);
    log.error(`IA falló para análisis ${analysisId}: ${message}`);
    await db.update(analyses).set({ aiStatus: 'failed', aiError: message.slice(0, 1000) }).where(eq(analyses.id, analysisId));
  }
}

async function applyAiOutput(
  out: AiOutput,
  refs: Map<string, { id: string; mitre: { id: string }[]; title: string }>,
  evRows: { findingId: string; e: { logId: string } }[],
  facts: Facts,
  analysisId: string,
): Promise<string[]> {
  const rejected: string[] = [];
  const seen = new Set<string>();

  for (const item of out.findings) {
    const f = refs.get(item.ref);
    if (!f) {
      rejected.push(`Hallazgo "${item.ref}" devuelto por la IA no existe: descartado.`);
      continue;
    }
    if (seen.has(item.ref)) continue;
    seen.add(item.ref);
    const evidence = new Set(evRows.filter((r) => r.findingId === f.id).map((r) => r.e.logId));
    const techniques = new Set(f.mitre.flatMap((m) => [m.id, m.id.split('.')[0]]));
    const badCite = item.cited_log_ids.find((id) => !evidence.has(id));
    const problem =
      (badCite ? `cita ${badCite}, que no es evidencia del hallazgo` : null) ??
      checkText(item.technical_explanation, facts, techniques, evidence) ??
      checkText(item.impact, facts, techniques, evidence) ??
      checkText(item.l1_rationale, facts, techniques, evidence);
    if (problem) {
      rejected.push(`${item.ref} "${f.title}": texto de IA descartado porque ${problem}. Se conserva el texto del motor.`);
      continue;
    }
    await db
      .update(findings)
      .set({
        technicalExplanation: item.technical_explanation,
        impact: item.impact,
        l1Verdict: item.l1_verdict,
        l1Rationale: item.l1_rationale,
        narrativeSource: 'ai',
      })
      .where(eq(findings.id, f.id));
  }
  for (const ref of refs.keys()) if (!seen.has(ref)) rejected.push(`${ref}: la IA no redactó este hallazgo; se conserva el texto del motor.`);

  const summaryProblem = checkText(out.executive_summary, facts, facts.allTechniques);
  const recProblem = out.general_recommendations.map((r) => checkText(r, facts, facts.allTechniques)).find(Boolean);
  const update: Partial<typeof analyses.$inferInsert> = {};
  if (summaryProblem) rejected.push(`Resumen ejecutivo de IA descartado porque ${summaryProblem}. Se conserva el resumen del motor.`);
  else update.executiveSummary = out.executive_summary;
  if (recProblem) rejected.push(`Recomendaciones de IA descartadas porque ${recProblem}.`);
  else update.generalRecommendations = out.general_recommendations;
  if (Object.keys(update).length) await db.update(analyses).set(update).where(eq(analyses.id, analysisId));
  return rejected;
}

/** Utilidad para pruebas: valida un texto contra un conjunto de hechos */
export const _internal = { checkText, tokens, MITRE_TECHNIQUES };
