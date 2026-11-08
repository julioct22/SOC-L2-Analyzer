/**
 * Plantilla HTML del informe técnico (se convierte a PDF con Chromium).
 *
 * Dos formatos:
 *  - summary (resumido, por defecto): ~10-15 páginas. Fichas compactas por hallazgo con evidencia clave.
 *  - full (completo): una página por hallazgo con toda la evidencia y anexos de trazabilidad.
 *
 * Ambos contienen las secciones exigidas: resumen ejecutivo, hallazgos, explicación técnica, evidencias,
 * criticidad y justificación, impacto, plan de acción (investigar/contener/remediar) y recomendaciones.
 *
 * Navegación: índice con enlaces, marcadores del PDF (outline), bandas de sección numeradas,
 * "migas de pan" en cada hallazgo y pie de página con el tipo de informe.
 */
import {
  FINDING_STATUS_LABELS,
  L1_VERDICT_LABELS,
  MITRE_TACTICS,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SEVERITY_SCALE_TEXT,
  mitreUrl,
  type AnalysisDTO,
  type FindingDTO,
  type Severity,
} from '@soc/shared';

export type ReportFormat = 'summary' | 'full';

export interface EvidenceRow {
  logId: string;
  ts: string | null;
  hostname: string | null;
  eventId: string | null;
  user: string | null;
  sourceIp: string | null;
  destination: string | null;
  description: string | null;
  commandLine: string | null;
  result: string | null;
}

export interface ReportContext {
  format: ReportFormat;
  analysis: AnalysisDTO;
  findings: FindingDTO[];
  evidence: Map<string, EvidenceRow[]>;
  orgName: string;
  generatedAt: string;
  generatedBy: string;
  upload: { originalName: string; sha256: string; rowCount: number; uploadedAt: string; uploadedBy: string };
  includePending: boolean;
  excludedFalsePositives: number;
}

const EVIDENCE_ROWS = { summary: 2, full: 15 } as const;
const SEV_COLOR: Record<Severity, string> = { critical: '#b91c1c', high: '#ea580c', medium: '#ca8a04', low: '#2563eb' };
const SEVS: Severity[] = ['critical', 'high', 'medium', 'low'];

const esc = (v: unknown) =>
  String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');

const para = (text: string | null) =>
  esc(text ?? '')
    .split(/\n+/)
    .filter((l) => l.trim())
    .map((l) => (l.trim().startsWith('•') ? `<p class="bullet">${l}</p>` : `<p>${l}</p>`))
    .join('');

const badge = (sev: Severity) => `<span class="badge" style="background:${SEV_COLOR[sev]}">${SEVERITY_LABELS[sev]}</span>`;
const hRef = (i: number) => `H${String(i + 1).padStart(2, '0')}`;

/** Banda de sección numerada (genera marcador en el PDF por ser <h2>) */
function section(num: string, title: string, id: string, opts: { newPage?: boolean } = {}): string {
  return `<div class="band${opts.newPage ? ' new-page' : ''}"><h2 id="${id}" class="section"><span class="snum">${esc(num)}</span><span class="stitle">&nbsp;${esc(title)}</span></h2><a class="toplink" href="#indice">↑ Índice</a></div>`;
}

function barChart(items: { label: string; value: number; color?: string }[], width = 640): string {
  if (!items.length) return '<p class="muted">Sin datos.</p>';
  const max = Math.max(...items.map((i) => i.value), 1);
  const rowH = 20;
  const labelW = Math.min(230, Math.round(width * 0.38));
  const h = items.length * rowH + 6;
  const bars = items
    .map((it, i) => {
      const w = Math.max(2, ((width - labelW - 40) * it.value) / max);
      const y = i * rowH + 3;
      return `<text x="${labelW - 8}" y="${y + 13}" text-anchor="end" class="svg-label">${esc(it.label)}</text>
<rect x="${labelW}" y="${y + 3}" width="${w}" height="12" rx="2" fill="${it.color ?? '#334155'}"/>
<text x="${labelW + w + 5}" y="${y + 13}" class="svg-value">${it.value}</text>`;
    })
    .join('');
  return `<svg width="${width}" height="${h}" viewBox="0 0 ${width} ${h}" xmlns="http://www.w3.org/2000/svg">${bars}</svg>`;
}

function timelineChart(points: { bucket: string; total: number; suspicious: number }[], width = 680, height = 140): string {
  if (!points.length) return '';
  const max = Math.max(...points.map((p) => p.total), 1);
  const padL = 30;
  const padB = 26;
  const bw = (width - padL - 10) / points.length;
  const ch = height - padB - 10;
  const bars = points
    .map((p, i) => {
      const x = padL + i * bw;
      const ht = (ch * p.total) / max;
      const hs = (ch * p.suspicious) / max;
      const label = i % Math.ceil(points.length / 8) === 0 ? `<text x="${x + bw / 2}" y="${height - 9}" text-anchor="middle" class="svg-axis">${esc(p.bucket.slice(11, 16))}</text>` : '';
      return `<rect x="${x + 1}" y="${10 + ch - ht}" width="${Math.max(1, bw - 2)}" height="${ht}" fill="#cbd5e1"/>
<rect x="${x + 1}" y="${10 + ch - hs}" width="${Math.max(1, bw - 2)}" height="${hs}" fill="#dc2626"/>${label}`;
    })
    .join('');
  return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
<line x1="${padL}" y1="${10 + ch}" x2="${width - 10}" y2="${10 + ch}" stroke="#94a3b8"/>
<text x="${padL - 4}" y="16" text-anchor="end" class="svg-axis">${max}</text>${bars}</svg>
<p class="legend"><span class="sw" style="background:#cbd5e1"></span>Eventos totales <span class="sw" style="background:#dc2626"></span>Eventos que son evidencia de hallazgos (intervalos de 15 min)</p>`;
}

function evidenceTable(rows: EvidenceRow[], total: number, max: number, compact: boolean): string {
  const shown = rows.slice(0, max);
  const detail = (e: EvidenceRow) => `${esc(e.description)}${e.commandLine ? `<div class="cmd">${esc(e.commandLine)}</div>` : ''}`;
  const head = compact
    ? '<th>Log_ID</th><th>Hora</th><th>Host</th><th>Usuario</th><th>IP origen</th><th>Detalle</th>'
    : '<th>Log_ID</th><th>Timestamp</th><th>Host</th><th>Event</th><th>Usuario</th><th>IP origen</th><th>Destino</th><th>Descripción / Comando</th><th>Res.</th>';
  const body = shown
    .map((e) =>
      compact
        ? `<tr><td class="mono">${esc(e.logId)}</td><td class="mono">${esc(e.ts?.slice(11))}</td><td>${esc(e.hostname)}</td><td>${esc(e.user)}</td><td class="mono">${esc(e.sourceIp)}</td><td>${detail(e)}</td></tr>`
        : `<tr><td class="mono">${esc(e.logId)}</td><td class="mono">${esc(e.ts)}</td><td>${esc(e.hostname)}</td><td>${esc(e.eventId)}</td><td>${esc(e.user)}</td><td class="mono">${esc(e.sourceIp)}</td><td>${esc(e.destination)}</td><td>${detail(e)}</td><td>${esc(e.result)}</td></tr>`,
    )
    .join('');
  const more =
    total > shown.length
      ? `<p class="muted small">Se muestran ${shown.length} de ${total} eventos. ${compact ? 'El informe completo y la plataforma contienen la lista total.' : 'Lista completa de Log_ID en el anexo B.'}</p>`
      : '';
  return `<table class="evidence${compact ? ' compact' : ''}"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>${more}`;
}

function scoreLine(f: FindingDTO): string {
  const overridden = f.severityOverride && f.severityOverride !== f.severity;
  return `${badge(f.severity)} <b>${f.score}/100</b>${overridden ? ` → ajustada por L2 a ${badge(f.effectiveSeverity)}` : ''} · ${f.scoreFactors
    .map((s, i) => `${esc(s.label)} (${i === 0 ? '' : '+'}${s.points})`)
    .join(' · ')}`;
}

function findingHeader(f: FindingDTO, idx: number, total: number, fmt: ReportFormat): string {
  return `<div class="crumb">6 · Detalle de hallazgos <span>›</span> ${hRef(idx)} de ${hRef(total - 1)}${f.incidentKey ? ` <span>›</span> ${esc(f.incidentKey)}` : ''}</div>
<div class="finding-head" style="border-left-color:${SEV_COLOR[f.effectiveSeverity]}">
  <div class="finding-title"><h3 id="${hRef(idx)}"><span class="fnum">${hRef(idx)}</span>&nbsp;${esc(f.title)}</h3>
    <div class="meta">${badge(f.effectiveSeverity)} <span class="status status-${f.status}">${FINDING_STATUS_LABELS[f.status]}</span>
    <span class="muted">${esc(f.firstSeen)} → ${esc(f.lastSeen?.slice(11))} · ${f.eventCount} evento(s)${fmt === 'full' ? ` · Regla ${esc(f.ruleId)}` : ''}</span></div>
    <div class="mitre-line">${f.mitre.map((m) => `<a href="${mitreUrl(m.id)}"><b>${esc(m.id)}</b> ${esc(m.name)}</a>`).join(' · ')}</div>
  </div>
</div>`;
}

function planBlock(f: FindingDTO, maxItems: number): string {
  const col = (t: string, items: string[]) =>
    `<div><div class="h5">${t}</div><ul>${items
      .slice(0, maxItems)
      .map((x) => `<li>${esc(x)}</li>`)
      .join('')}</ul></div>`;
  return `<div class="plan">${col('1. Investigar', f.actionPlan.investigate)}${col('2. Contener', f.actionPlan.contain)}${col('3. Remediar', f.actionPlan.remediate)}</div>`;
}

/** Ficha compacta (formato resumido) */
function findingCard(f: FindingDTO, idx: number, total: number, ev: EvidenceRow[]): string {
  return `<section class="card-finding">
${findingHeader(f, idx, total, 'summary')}
<div class="grid2">
  <div><div class="h4">Qué pasó</div>${para(f.summary)}</div>
  <div><div class="h4">Posible impacto</div>${para(f.impact)}</div>
</div>
<div class="h4">Explicación técnica${f.narrativeSource === 'ai' ? ' <span class="src">IA validada contra evidencia</span>' : ''}</div>${para(f.technicalExplanation)}
<div class="h4">Evidencias clave</div>${evidenceTable(ev, f.eventCount, EVIDENCE_ROWS.summary, true)}
<div class="h4">Criticidad y justificación</div><p class="small">${scoreLine(f)}</p>
<div class="h4">Plan de acción</div>${planBlock(f, 1)}
${f.analystNotes ? `<div class="notes"><b>Notas del analista L2${f.reviewedBy ? ` (${esc(f.reviewedBy)})` : ''}:</b> ${esc(f.analystNotes)}</div>` : ''}
</section>`;
}

/** Entrada breve (formato resumido, hallazgos Medio/Bajo) */
function findingBrief(f: FindingDTO, idx: number): string {
  return `<div class="brief" style="border-left-color:${SEV_COLOR[f.effectiveSeverity]}">
<div class="brief-head"><h3 id="${hRef(idx)}"><span class="bnum">${hRef(idx)}</span>&nbsp;${esc(f.title)}</h3> ${badge(f.effectiveSeverity)} <span class="status status-${f.status}">${FINDING_STATUS_LABELS[f.status]}</span></div>
<p><b>Qué pasó:</b> ${esc(f.summary)}</p>
<p><b>Explicación técnica:</b> ${esc(f.technicalExplanation)}</p>
<p><b>Impacto:</b> ${esc(f.impact)} <b>Acción prioritaria:</b> ${esc(f.actionPlan.investigate[0] ?? '')} ${esc(f.actionPlan.contain[0] ?? '')}</p>
<p class="small muted"><b>MITRE:</b> ${f.mitre.map((m) => `${esc(m.id)} ${esc(m.name)}`).join(' · ')} · <b>Criticidad:</b> ${f.score}/100 (${f.scoreFactors.map((x, i) => `${esc(x.label)} ${i === 0 ? '' : '+'}${x.points}`).join(' · ')}) · <b>Evidencia:</b> ${esc(f.evidenceLogIds.slice(0, 6).join(', '))}${f.evidenceLogIds.length > 6 ? ` y ${f.evidenceLogIds.length - 6} más` : ''}</p>
</div>`;
}

/** Página completa por hallazgo (formato completo) */
function findingPage(f: FindingDTO, idx: number, total: number, ev: EvidenceRow[]): string {
  return `<section class="finding-page">
${findingHeader(f, idx, total, 'full')}
<div class="h4">Descripción del hallazgo</div>${para(f.summary)}
<div class="h4">Explicación técnica${f.narrativeSource === 'ai' ? ' <span class="src">redacción asistida por IA, validada contra evidencia</span>' : ''}</div>${para(f.technicalExplanation)}
<div class="h4">Evidencias encontradas en los logs</div>${evidenceTable(ev, f.eventCount, EVIDENCE_ROWS.full, false)}
<div class="h4">Criticidad y justificación</div>
<table class="kv"><tbody>${f.scoreFactors.map((s, i) => `<tr><td>${esc(s.label)}</td><td class="num">${i === 0 ? '' : '+'}${s.points}</td></tr>`).join('')}
<tr class="total"><td>Total (máx. 100) — ${SEVERITY_LABELS[f.severity]}${f.severityOverride && f.severityOverride !== f.severity ? ` → ajustada por L2 a ${SEVERITY_LABELS[f.effectiveSeverity]}` : ''}</td><td class="num">${f.score}</td></tr></tbody></table>
<p class="muted small">${SEVERITY_SCALE_TEXT}</p>
${f.l1Verdict ? `<p class="small"><b>Triaje L1:</b> ${L1_VERDICT_LABELS[f.l1Verdict]} — ${esc(f.l1Rationale)}</p>` : ''}
<div class="h4">Posible impacto en la organización</div>${para(f.impact)}
<div class="h4">Plan de acción</div>${planBlock(f, 10)}
${f.analystNotes ? `<div class="notes"><b>Notas del analista L2${f.reviewedBy ? ` (${esc(f.reviewedBy)})` : ''}:</b>${para(f.analystNotes)}</div>` : ''}
</section>`;
}

export function renderReport(ctx: ReportContext): string {
  const { analysis: a, findings, format: fmt } = ctx;
  const full = fmt === 'full';
  const s = a.stats;
  const sevCount: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => sevCount[f.effectiveSeverity]++);
  const confirmed = findings.filter((f) => f.status === 'confirmed').length;
  const pending = findings.filter((f) => f.status === 'pending_review').length;
  const idxOf = new Map(findings.map((f, i) => [f.id, i]));
  const incidents = a.incidents
    .map((inc) => ({ ...inc, refs: inc.findingIds.filter((id) => idxOf.has(id)).map((id) => hRef(idxOf.get(id)!)) }))
    .filter((inc) => inc.refs.length);
  const link = (ref: string) => `<a href="#${ref}">${ref}</a>`;

  const techMap = new Map<string, { name: string; tactics: string; refs: string[] }>();
  findings.forEach((f, i) =>
    f.mitre.forEach((m) => {
      const e = techMap.get(m.id) ?? { name: m.name, tactics: m.tactics.map((t) => MITRE_TACTICS[t].es).join(', '), refs: [] };
      e.refs.push(hRef(i));
      techMap.set(m.id, e);
    }),
  );

  const toc: [string, string, string][] = [
    ['1', 'Resumen ejecutivo', 's1'],
    ['2', 'Alcance y metodología', 's2'],
    ['3', 'Panorama general', 's3'],
    ['4', 'Incidentes correlacionados', 's4'],
    ['5', 'Hallazgos identificados', 's5'],
    ['6', 'Detalle de hallazgos', 's6'],
    ['7', 'Recomendaciones generales', 's7'],
    ['8', 'Calidad de datos', 's8'],
    ['A', 'Anexo: matriz MITRE ATT&CK', 'sA'],
    ...(full ? ([['B', 'Anexo: trazabilidad', 'sB']] as [string, string, string][]) : []),
  ];

  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Informe técnico de seguridad${full ? '' : ' (resumido)'}</title>
<style>
@page { size: A4; }
* { box-sizing: border-box; }
body { font-family: 'DejaVu Sans', 'Liberation Sans', Arial, sans-serif; color: #0f172a; font-size: ${full ? '9.5pt' : '8.4pt'}; line-height: ${full ? '1.42' : '1.35'}; margin: 0; }
a { color: #1d4ed8; text-decoration: none; }
h1 { font-size: 22pt; margin: 0 0 6px; }
h3 { font-size: 11pt; margin: 0; }
.h4 { font-size: 8.5pt; margin: 9px 0 3px; color: #475569; text-transform: uppercase; letter-spacing: .6px; page-break-after: avoid; }
.h5 { font-size: 8.5pt; margin: 0 0 3px; font-weight: bold; }
p { margin: 2px 0 5px; } p.bullet { margin-left: 10px; }
.muted { color: #64748b; } .small { font-size: 8pt; }
.mono { font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace; font-size: 7.3pt; }

/* ---- Banda de sección: muy visible para ubicarse ---- */
.band { display: flex; align-items: center; background: #0f172a; padding: 7px 12px; margin: 18px 0 10px; border-radius: 4px; page-break-after: avoid; page-break-inside: avoid; }
.band.new-page { page-break-before: always; margin-top: 0; }
h2.section { display: flex; align-items: center; gap: 6px; color: #fff; margin: 0; font-size: 13pt; flex: 1; }
h2.section .snum { background: #f97316; color: #fff; min-width: 26px; height: 26px; border-radius: 4px; display: inline-flex; align-items: center; justify-content: center; font-size: 12pt; }
h2.section .stitle { flex: 1; }
.band .toplink { color: #94a3b8; font-size: 7.5pt; }

.cover { height: 250mm; display: flex; flex-direction: column; justify-content: space-between; page-break-after: always; }
.cover-top { border-left: 8px solid #f97316; padding-left: 18px; margin-top: 35mm; }
.cover .label { text-transform: uppercase; letter-spacing: 2px; color: #f97316; font-weight: bold; font-size: 9pt; }
.cover .org { font-size: 13pt; color: #334155; }
.cover .kind { display: inline-block; background: #0f172a; color: #fff; padding: 3px 10px; font-size: 9pt; border-radius: 3px; margin-top: 8px; }
.classification { display: inline-block; border: 1.5px solid #b91c1c; color: #b91c1c; padding: 3px 10px; font-weight: bold; font-size: 8.5pt; letter-spacing: 1px; margin-top: 12px; }

.toc { border: 1px solid #cbd5e1; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; }
.toc a { display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px dotted #cbd5e1; color: #0f172a; }
.toc a b { color: #f97316; display: inline-block; width: 22px; }
.toc .refs { font-size: 7.5pt; color: #64748b; margin-top: 6px; line-height: 1.7; }
.toc .refs a { display: inline; border: 0; color: #1d4ed8; padding: 0 2px; }

table { border-collapse: collapse; width: 100%; margin: 3px 0 7px; }
th, td { border: 1px solid #cbd5e1; padding: 3px 5px; text-align: left; vertical-align: top; }
th { background: #f1f5f9; font-size: 7.8pt; }
table.kv td { font-size: 8.3pt; } td.num { text-align: right; width: 55px; } tr.total td { font-weight: bold; background: #f8fafc; }
table.evidence { font-size: 7pt; } table.evidence td { word-break: break-word; }
table.evidence.compact { font-size: 6.8pt; }
.cmd { font-family: 'DejaVu Sans Mono', monospace; color: #7c2d12; font-size: 6.6pt; margin-top: 1px; }
.badge { color: #fff; padding: 1px 7px; border-radius: 3px; font-size: 7.3pt; font-weight: bold; white-space: nowrap; }
.status { font-size: 7.3pt; padding: 1px 6px; border-radius: 3px; border: 1px solid; white-space: nowrap; }
.status-confirmed { color: #166534; border-color: #166534; } .status-pending_review { color: #92400e; border-color: #92400e; } .status-false_positive { color: #475569; border-color: #475569; }
.src { font-weight: normal; font-size: 6.8pt; color: #7c3aed; border: 1px solid #c4b5fd; border-radius: 3px; padding: 0 4px; margin-left: 4px; text-transform: none; letter-spacing: 0; }
.kpis { display: flex; gap: 8px; margin: 6px 0 10px; }
.kpi { flex: 1; border: 1px solid #cbd5e1; border-radius: 4px; padding: 7px; text-align: center; font-size: 8pt; }
.kpi b { display: block; font-size: 16pt; }

/* ---- Hallazgos ---- */
.crumb { font-size: 7.5pt; color: #64748b; margin-bottom: 3px; text-transform: uppercase; letter-spacing: .5px; }
.crumb span { color: #f97316; font-weight: bold; }
.finding-head { display: flex; gap: 10px; border-left: 6px solid; padding: 6px 10px; background: #f8fafc; margin-bottom: 4px; }
.fnum { color: #f97316; margin-right: 4px; }
.finding-title .meta { margin-top: 3px; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-size: 7.8pt; }
.mitre-line { font-size: 7.3pt; margin-top: 3px; color: #334155; } .mitre-line a { color: #334155; }
.finding-page { page-break-before: always; }
.card-finding { border-top: 2px solid #e2e8f0; padding-top: 6px; margin-top: 10px; }
.card-finding .h4 { margin: 5px 0 2px; }
.card-finding .plan li { font-size: 7.6pt; }
.card-finding:first-of-type { border-top: 0; margin-top: 0; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.plan { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; page-break-inside: avoid; }
.plan > div { border: 1px solid #cbd5e1; border-radius: 4px; padding: 5px; }
.plan ul { margin: 0; padding-left: 13px; } .plan li { margin-bottom: 2px; font-size: 8pt; }
.notes { border: 1px dashed #64748b; padding: 5px 8px; margin-top: 6px; background: #fffbeb; font-size: 8pt; }
.brief { border-left: 4px solid; padding: 4px 10px; margin: 8px 0; background: #f8fafc; page-break-inside: avoid; font-size: 8.3pt; }
.brief-head { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 3px; } .brief h3 { font-size: 9.5pt; margin: 0; } .brief p { margin: 2px 0; }
.bnum { color: #475569; }
h3.subsection { margin: 16px 0 4px; font-size: 10.5pt; border-bottom: 2px solid #f97316; padding-bottom: 3px; }
.svg-label { font-size: 8.5px; fill: #0f172a; } .svg-value { font-size: 8.5px; fill: #475569; } .svg-axis { font-size: 8px; fill: #64748b; }
.legend { font-size: 7.3pt; color: #475569; } .sw { display: inline-block; width: 9px; height: 9px; margin: 0 3px 0 10px; vertical-align: middle; }
.two { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.avoid { page-break-inside: avoid; }
</style></head><body>

<div class="cover">
  <div class="cover-top">
    <div class="label">Informe técnico de seguridad · SOC Nivel 2</div>
    <h1>Análisis de eventos de seguridad</h1>
    <div class="org">${esc(ctx.orgName)}</div>
    <div class="kind">${full ? 'Informe completo' : 'Informe resumido'}</div>
    <p class="muted" style="margin-top:14px">Fuente: ${esc(ctx.upload.originalName)} · ${s?.totalEvents ?? 0} eventos · Periodo ${esc(s?.timeRange.from)} → ${esc(s?.timeRange.to)}</p>
    <div class="kpis" style="max-width:150mm">
      ${SEVS.map((k) => `<div class="kpi" style="border-top:4px solid ${SEV_COLOR[k]}"><b>${sevCount[k]}</b>${SEVERITY_LABELS[k]}</div>`).join('')}
    </div>
    <div class="classification">CONFIDENCIAL — USO INTERNO</div>
  </div>
  <table class="kv" style="width:125mm"><tbody>
    <tr><td>Generado</td><td>${esc(ctx.generatedAt)} por ${esc(ctx.generatedBy)}</td></tr>
    <tr><td>Análisis</td><td class="mono">${esc(a.id)}</td></tr>
    <tr><td>Validación L2</td><td>${confirmed} confirmados · ${pending} pendientes${ctx.excludedFalsePositives ? ` · ${ctx.excludedFalsePositives} falsos positivos excluidos` : ''}</td></tr>
  </tbody></table>
</div>

<div class="band"><h2 id="indice" class="section"><span class="snum">≡</span><span class="stitle">&nbsp;Índice</span></h2></div>
<div class="toc">
${toc.map(([n, t, id]) => `<a href="#${id}"><span><b>${n}</b>${esc(t)}</span><span class="muted">ir ›</span></a>`).join('')}
<div class="refs">Hallazgos: ${findings.map((_, i) => link(hRef(i))).join(' ')}</div>
</div>

${section('1', 'Resumen ejecutivo', 's1')}
<div class="kpis">
<div class="kpi"><b>${s?.totalEvents ?? 0}</b>eventos analizados</div>
<div class="kpi"><b>${findings.length}</b>hallazgos</div>
<div class="kpi"><b>${incidents.length}</b>incidentes</div>
${SEVS.map((k) => `<div class="kpi" style="border-top:3px solid ${SEV_COLOR[k]}"><b>${sevCount[k]}</b>${SEVERITY_LABELS[k]}</div>`).join('')}
</div>
${para(a.executiveSummary)}
${pending && ctx.includePending ? `<p class="small muted">Nota: ${pending} hallazgo(s) aún no han sido validados por el analista L2 y se identifican como "Pendiente de validación".</p>` : ''}

${section('2', 'Alcance y metodología', 's2', { newPage: full })}
<table class="kv"><tbody>
<tr><td style="width:150px">Archivo analizado</td><td>${esc(ctx.upload.originalName)} (${ctx.upload.rowCount} filas) · cargado ${esc(ctx.upload.uploadedAt)} por ${esc(ctx.upload.uploadedBy)}</td></tr>
<tr><td>SHA-256 del archivo</td><td class="mono">${esc(ctx.upload.sha256)}</td></tr>
<tr><td>Periodo de los eventos</td><td>${esc(s?.timeRange.from)} → ${esc(s?.timeRange.to)} (hora del log, sin zona horaria declarada)</td></tr>
<tr><td>Método</td><td>Motor de reglas v${esc(a.engineVersion)} mapeado a MITRE ATT&amp;CK, correlación por entidades y tiempo · ${
    a.aiStatus === 'completed' ? `redacción asistida por IA (${esc(a.aiModel)}) validada contra la evidencia` : 'textos generados por el motor (sin IA)'
  } · validación humana del analista L2</td></tr>
<tr><td>Criticidad</td><td>${SEVERITY_SCALE_TEXT} Base de la técnica + contexto (origen externo, cuenta privilegiada, activo crítico, cadena de ataque).</td></tr>
</tbody></table>
<p class="small">Principio de rigor: toda conclusión está sustentada en eventos concretos del archivo, identificados por su Log_ID. Lo que los registros no permiten afirmar se indica explícitamente.</p>

${section('3', 'Panorama general', 's3')}
<div class="avoid"><div class="h4">Actividad en el tiempo</div>${timelineChart(s?.timeline ?? [])}</div>
<div class="two avoid">
<div><div class="h4">Hallazgos por criticidad</div>${barChart(SEVS.map((k) => ({ label: SEVERITY_LABELS[k], value: sevCount[k], color: SEV_COLOR[k] })), 330)}</div>
<div><div class="h4">Tácticas ATT&amp;CK (n.º de hallazgos)</div>${barChart((s?.byTactic ?? []).map((t) => ({ label: t.key.replace(/^TA\d+ /, ''), value: t.count, color: '#f97316' })), 330)}</div>
</div>
${
  full
    ? `<div class="two avoid">
<div><div class="h4">Eventos por fuente</div>${barChart((s?.byLogSource ?? []).map((x) => ({ label: x.key, value: x.count })), 330)}</div>
<div><div class="h4">IPs de origen en evidencias</div>${barChart((s?.topSuspiciousIps ?? []).map((x) => ({ label: x.key, value: x.count, color: '#b91c1c' })), 330)}</div>
</div>`
    : ''
}

${section('4', 'Incidentes correlacionados', 's4', { newPage: full })}
${
  !incidents.length
    ? '<p>No se identificaron cadenas de hallazgos correlacionados.</p>'
    : full
      ? incidents
          .map(
            (inc) => `<div class="avoid" style="margin-bottom:10px"><h3 style="margin:8px 0 4px">${esc(inc.key)} ${badge(inc.severity)} ${esc(inc.title)}</h3>
<table class="kv"><tbody>
<tr><td style="width:150px">Ventana temporal</td><td>${esc(inc.firstSeen)} → ${esc(inc.lastSeen)}</td></tr>
<tr><td>Hallazgos (cronológico)</td><td>${inc.refs.map(link).join(' → ')}</td></tr>
<tr><td>Tácticas ATT&amp;CK</td><td>${inc.tactics.map((t) => MITRE_TACTICS[t].es).join(' · ')}</td></tr>
<tr><td>Equipos / usuarios / IPs</td><td>${esc(inc.entities.hosts.join(', '))}<br>${esc(inc.entities.users.slice(0, 10).join(', '))}${inc.entities.users.length > 10 ? '…' : ''}<br><span class="mono">${esc(inc.entities.ips.join(', '))}</span></td></tr>
<tr><td>Criterio de correlación</td><td class="small">${inc.correlation.map(esc).join('<br>')}</td></tr>
</tbody></table></div>`,
          )
          .join('')
      : `<table><thead><tr><th>Incidente</th><th>Criticidad</th><th>Cadena de ataque</th><th>Ventana</th><th>Hallazgos</th></tr></thead><tbody>
${incidents
  .map(
    (inc) =>
      `<tr><td class="mono"><b>${esc(inc.key)}</b></td><td>${badge(inc.severity)}</td><td>${esc(inc.title)}<div class="muted small">${inc.tactics.map((t) => MITRE_TACTICS[t].es).join(' › ')}</div></td><td class="mono">${esc(inc.firstSeen?.slice(11, 16))}–${esc(inc.lastSeen?.slice(11, 16))}</td><td>${inc.refs.map(link).join(' ')}</td></tr>`,
  )
  .join('')}</tbody></table>`
}

${section('5', 'Hallazgos identificados', 's5')}
<table><thead><tr><th>#</th><th>Hallazgo</th><th>Criticidad</th><th>MITRE</th><th>Inc.</th><th>Ev.</th><th>Estado L2</th></tr></thead><tbody>
${findings
  .map(
    (f, i) =>
      `<tr><td>${link(hRef(i))}</td><td>${esc(f.title)}</td><td>${badge(f.effectiveSeverity)}</td><td class="mono">${f.mitre.map((m) => esc(m.id)).join(', ')}</td><td>${esc(f.incidentKey ?? '—')}</td><td class="num">${f.eventCount}</td><td class="small">${FINDING_STATUS_LABELS[f.status]}</td></tr>`,
  )
  .join('')}
</tbody></table>

${section('6', 'Detalle de hallazgos', 's6', { newPage: full })}
<p class="small muted">Para cada hallazgo: qué pasó, explicación técnica, evidencias en los logs, criticidad con su justificación, impacto y plan de acción (investigar → contener → remediar).${full ? '' : ' En este formato resumido los hallazgos Críticos y Altos tienen ficha completa y los Medios/Bajos una ficha breve.'}</p>
${
  full
    ? findings.map((f, i) => findingPage(f, i, findings.length, ctx.evidence.get(f.id) ?? [])).join('')
    : `${findings
        .map((f, i) => (SEVERITY_ORDER[f.effectiveSeverity] >= 3 ? findingCard(f, i, findings.length, ctx.evidence.get(f.id) ?? []) : ''))
        .join('')}${
        findings.some((f) => SEVERITY_ORDER[f.effectiveSeverity] < 3)
          ? `<h3 class="subsection">Hallazgos de criticidad Media y Baja</h3>${findings
              .map((f, i) => (SEVERITY_ORDER[f.effectiveSeverity] < 3 ? findingBrief(f, i) : ''))
              .join('')}`
          : ''
      }`
}

${section('7', 'Recomendaciones generales de seguridad', 's7', { newPage: full })}
<ol>${a.generalRecommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ol>

${section('8', 'Observaciones de calidad de datos', 's8')}
${a.dataQuality.length ? `<ul class="small">${a.dataQuality.map((d) => `<li>${esc(d.message)}</li>`).join('')}</ul>` : '<p>Sin observaciones.</p>'}

${section('A', 'Anexo: matriz MITRE ATT&CK', 'sA', { newPage: full })}
<table><thead><tr><th>Técnica</th><th>Nombre</th><th>Táctica(s)</th><th>Hallazgos</th></tr></thead><tbody>
${[...techMap.entries()]
  .sort(([x], [y]) => x.localeCompare(y))
  .map(([id, t]) => `<tr><td class="mono"><a href="${mitreUrl(id)}">${esc(id)}</a></td><td>${esc(t.name)}</td><td>${esc(t.tactics)}</td><td>${t.refs.map(link).join(' ')}</td></tr>`)
  .join('')}
</tbody></table>

${
  full
    ? `${section('B', 'Anexo: trazabilidad', 'sB')}
<table class="kv"><tbody>
${findings
  .map(
    (f, i) =>
      `<tr><td style="width:40px">${link(hRef(i))}</td><td>${FINDING_STATUS_LABELS[f.status]}${f.reviewedBy ? ` por ${esc(f.reviewedBy)} (${esc(f.reviewedAt?.slice(0, 16).replace('T', ' '))} UTC)` : ''}</td><td class="mono small">${esc(f.evidenceLogIds.join(', '))}</td></tr>`,
  )
  .join('')}
</tbody></table>
${a.aiRejected.length ? `<div class="h4">Textos de IA descartados por la validación anti-alucinación</div><ul class="small">${a.aiRejected.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}`
    : ''
}
<p class="small muted" style="margin-top:14px">Documento generado por SOC L2 Analyzer (${full ? 'formato completo' : 'formato resumido'}). El SHA-256 de este PDF queda registrado en la bitácora de auditoría.</p>
</body></html>`;
}
