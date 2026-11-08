import { useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router';
import { ArrowLeft, Bot, AlertTriangle, Database, GitBranch, Loader2 } from 'lucide-react';
import { MITRE_TACTICS, SEVERITIES, SEVERITY_LABELS, type AnalysisDTO, type TacticId } from '@soc/shared';
import { useAnalysis } from '../api/hooks';
import { Chart, axisStyle } from '../components/Chart';
import { EventsGrid } from '../components/EventsGrid';
import { PageHeader, SeverityBadge, Spinner, Stat, Tabs, StatusBadge } from '../components/ui';
import { FindingsTab } from '../components/analysis/FindingsTab';
import { ReportTab } from '../components/analysis/ReportTab';
import { SEV_HEX, fmtDateTime } from '../lib/format';

type Tab = 'overview' | 'findings' | 'incidents' | 'mitre' | 'events' | 'report';

function AiBanner({ a }: { a: AnalysisDTO }) {
  if (a.aiStatus === 'pending')
    return (
      <div className="mb-5 flex items-center gap-3 rounded-lg border border-violet-500/30 bg-violet-500/10 px-4 py-3 text-sm text-violet-200">
        <Loader2 className="h-4 w-4 animate-spin" /> La IA está redactando explicaciones, impacto y resumen ejecutivo. Puedes ir revisando los hallazgos; se actualizarán solos.
      </div>
    );
  if (a.aiStatus === 'failed')
    return (
      <div className="mb-5 flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
        <AlertTriangle className="h-4 w-4" /> La redacción con IA falló ({a.aiError}). Se usan los textos del motor; puedes reintentar desde la pestaña Informe.
      </div>
    );
  return null;
}

function Overview({ a, goFindings }: { a: AnalysisDTO; goFindings: () => void }) {
  const s = a.stats!;
  const sevCount = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    a.findings.filter((f) => f.status !== 'false_positive').forEach((f) => c[f.effectiveSeverity]++);
    return c;
  }, [a.findings]);
  const pending = a.findings.filter((f) => f.status === 'pending_review').length;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 xl:grid-cols-8">
        <Stat label="Eventos" value={s.totalEvents} hint={`${s.timeRange.from?.slice(11, 16)} → ${s.timeRange.to?.slice(11, 16)}`} />
        <Stat label="Evidencias" value={s.suspiciousEventCount} hint={`${((s.suspiciousEventCount / Math.max(1, s.totalEvents)) * 100).toFixed(1)}% del total`} />
        <Stat label="Hallazgos" value={a.findings.length} hint={`${pending} por validar`} />
        <Stat label="Incidentes" value={a.incidents.length} hint="correlacionados" />
        {SEVERITIES.map((k) => (
          <Stat key={k} label={SEVERITY_LABELS[k]} value={sevCount[k]} accent={SEV_HEX[k]} />
        ))}
      </div>

      <div className="card p-5">
        <h3 className="font-semibold text-white">Actividad en el tiempo</h3>
        <p className="text-xs text-slate-500">Eventos por intervalo de 15 min; en rojo, los que son evidencia de algún hallazgo</p>
        <Chart
          height={260}
          option={{
            tooltip: { trigger: 'axis' },
            legend: { top: 0, right: 0, textStyle: { color: '#94a3b8' } },
            grid: { left: 40, right: 10, top: 30, bottom: 30 },
            xAxis: { type: 'category', data: s.timeline.map((t) => t.bucket.slice(11)), ...axisStyle },
            yAxis: { type: 'value', ...axisStyle },
            series: [
              { name: 'Normales', type: 'bar', stack: 't', data: s.timeline.map((t) => t.total - t.suspicious), itemStyle: { color: '#2b3a5c' } },
              { name: 'Evidencia', type: 'bar', stack: 't', data: s.timeline.map((t) => t.suspicious), itemStyle: { color: '#ef4444' } },
            ],
          }}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="card p-5">
          <h3 className="font-semibold text-white">Hallazgos por criticidad</h3>
          <Chart
            height={240}
            onClick={goFindings}
            option={{
              tooltip: { trigger: 'item' },
              legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
              series: [
                {
                  type: 'pie',
                  radius: ['50%', '75%'],
                  itemStyle: { borderColor: '#0b1220', borderWidth: 3 },
                  label: { color: '#cbd5e1', formatter: '{c}' },
                  data: SEVERITIES.map((k) => ({ name: SEVERITY_LABELS[k], value: sevCount[k], itemStyle: { color: SEV_HEX[k] } })).filter((d) => d.value),
                },
              ],
            }}
          />
        </div>
        <div className="card p-5 lg:col-span-2">
          <h3 className="font-semibold text-white">Tácticas MITRE ATT&amp;CK observadas</h3>
          <Chart
            height={240}
            option={{
              tooltip: { trigger: 'axis' },
              grid: { left: 150, right: 20, top: 10, bottom: 20 },
              xAxis: { type: 'value', minInterval: 1, ...axisStyle },
              yAxis: { type: 'category', inverse: true, data: s.byTactic.map((t) => t.key.replace(/^TA\d+ /, '')), ...axisStyle },
              series: [{ type: 'bar', data: s.byTactic.map((t) => t.count), itemStyle: { color: '#f97316', borderRadius: [0, 4, 4, 0] }, barMaxWidth: 16 }],
            }}
          />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {[
          { title: 'Eventos por host', data: s.byHost, color: '#3b82f6' },
          { title: 'IPs de origen en evidencias', data: s.topSuspiciousIps, color: '#ef4444' },
          { title: 'Eventos por Event_ID', data: s.byEventId, color: '#64748b' },
        ].map((c) => (
          <div key={c.title} className="card p-5">
            <h3 className="font-semibold text-white">{c.title}</h3>
            <Chart
              height={Math.max(180, c.data.length * 22)}
              option={{
                tooltip: { trigger: 'axis' },
                grid: { left: 110, right: 30, top: 10, bottom: 10 },
                xAxis: { type: 'value', show: false },
                yAxis: { type: 'category', inverse: true, data: c.data.map((d) => d.key), ...axisStyle },
                series: [{ type: 'bar', data: c.data.map((d) => d.count), itemStyle: { color: c.color, borderRadius: [0, 3, 3, 0] }, barMaxWidth: 12, label: { show: true, position: 'right', color: '#94a3b8', fontSize: 10 } }],
              }}
            />
          </div>
        ))}
      </div>

      {a.dataQuality.length > 0 && (
        <div className="card p-5">
          <h3 className="flex items-center gap-2 font-semibold text-white">
            <Database className="h-4 w-4 text-amber-400" /> Observaciones de calidad de datos
          </h3>
          <ul className="mt-3 space-y-2 text-sm text-slate-300">
            {a.dataQuality.map((d, i) => (
              <li key={i} className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2">
                {d.message}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Incidents({ a, openFinding }: { a: AnalysisDTO; openFinding: (id: string) => void }) {
  if (!a.incidents.length) return <p className="text-slate-400">No se correlacionaron cadenas de hallazgos.</p>;
  return (
    <div className="space-y-5">
      {a.incidents.map((inc) => {
        const fs = inc.findingIds.map((id) => a.findings.find((f) => f.id === id)).filter(Boolean) as AnalysisDTO['findings'];
        return (
          <div key={inc.key} className="card overflow-hidden">
            <div className="flex flex-wrap items-center gap-3 border-b border-ink-700 bg-ink-850 px-5 py-3">
              <span className="font-mono text-sm font-semibold text-accent">{inc.key}</span>
              <SeverityBadge severity={inc.severity} />
              <h3 className="flex-1 font-semibold text-white">{inc.title}</h3>
              <span className="text-xs text-slate-400">
                {inc.firstSeen} → {inc.lastSeen?.slice(11)}
              </span>
            </div>
            <div className="p-5">
              <div className="mb-4 flex flex-wrap items-center gap-1.5">
                {inc.tactics.map((t, i) => (
                  <span key={t} className="flex items-center gap-1.5">
                    <span className="rounded-md bg-ink-700 px-2 py-1 text-xs text-slate-200">{MITRE_TACTICS[t].es}</span>
                    {i < inc.tactics.length - 1 && <span className="text-slate-600">›</span>}
                  </span>
                ))}
              </div>
              <ol className="relative space-y-3 border-l border-ink-600 pl-5">
                {fs.map((f) => (
                  <li key={f.id} className="relative">
                    <span className="absolute top-1.5 -left-[25px] h-2.5 w-2.5 rounded-full ring-4 ring-ink-900" style={{ background: SEV_HEX[f.effectiveSeverity] }} />
                    <button className="group w-full text-left" onClick={() => openFinding(f.id)}>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-slate-500">{f.firstSeen?.slice(11)}</span>
                        <span className="text-sm font-medium text-slate-100 group-hover:text-accent">{f.title}</span>
                        <SeverityBadge severity={f.effectiveSeverity} />
                        <StatusBadge status={f.status} />
                      </div>
                      <p className="mt-0.5 line-clamp-1 text-xs text-slate-400">{f.summary}</p>
                    </button>
                  </li>
                ))}
              </ol>
              <div className="mt-4 grid gap-3 text-xs text-slate-400 md:grid-cols-2">
                <div>
                  <p className="mb-1 font-semibold text-slate-300">Entidades</p>
                  <p>Equipos: {inc.entities.hosts.join(', ')}</p>
                  <p className="font-mono">IPs: {inc.entities.ips.join(', ')}</p>
                </div>
                <div>
                  <p className="mb-1 flex items-center gap-1 font-semibold text-slate-300">
                    <GitBranch className="h-3.5 w-3.5" /> Criterio de correlación
                  </p>
                  {inc.correlation.map((c) => (
                    <p key={c}>{c}</p>
                  ))}
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function MitreMatrix({ a, openFinding }: { a: AnalysisDTO; openFinding: (id: string) => void }) {
  const tactics = (Object.keys(MITRE_TACTICS) as TacticId[]).sort((x, y) => MITRE_TACTICS[x].order - MITRE_TACTICS[y].order);
  const cells = new Map<TacticId, { id: string; name: string; findings: AnalysisDTO['findings'] }[]>();
  for (const f of a.findings.filter((x) => x.status !== 'false_positive'))
    for (const m of f.mitre)
      for (const t of m.tactics) {
        const list = cells.get(t) ?? [];
        const e = list.find((x) => x.id === m.id);
        if (e) e.findings.push(f);
        else list.push({ id: m.id, name: m.name, findings: [f] });
        cells.set(t, list);
      }
  return (
    <div className="overflow-x-auto">
      <div className="grid min-w-[1300px] gap-2" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))` }}>
        {tactics.map((t) => (
          <div key={t}>
            <div className={`mb-2 rounded-md px-2 py-2 text-center text-[11px] font-semibold ${cells.get(t) ? 'bg-accent/15 text-orange-200' : 'bg-ink-800 text-slate-500'}`}>
              {MITRE_TACTICS[t].es}
              <div className="font-mono text-[9px] opacity-70">{t}</div>
            </div>
            <div className="space-y-2">
              {(cells.get(t) ?? []).map((c) => {
                const worst = c.findings.reduce((w, f) => (SEVERITIES.indexOf(f.effectiveSeverity) < SEVERITIES.indexOf(w) ? f.effectiveSeverity : w), c.findings[0].effectiveSeverity);
                return (
                  <button
                    key={c.id}
                    onClick={() => openFinding(c.findings[0].id)}
                    title={c.findings.map((f) => f.title).join('\n')}
                    className="w-full rounded-md border border-ink-700 bg-ink-850 p-2 text-left hover:border-accent/60"
                    style={{ borderLeft: `3px solid ${SEV_HEX[worst]}` }}
                  >
                    <p className="font-mono text-[10px] text-accent">{c.id}</p>
                    <p className="text-[11px] leading-tight text-slate-200">{c.name}</p>
                    <p className="mt-1 text-[10px] text-slate-500">{c.findings.length} hallazgo(s)</p>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AnalysisPage() {
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = (params.get('tab') as Tab) ?? 'overview';
  const [selected, setSelected] = useState<string | null>(params.get('finding'));
  const { data: a, isLoading, error } = useAnalysis(id);
  const navigate = useNavigate();

  const setTab = (t: Tab) => setParams((p) => (p.set('tab', t), p), { replace: true });
  const openFinding = (fid: string) => {
    setSelected(fid);
    setParams((p) => (p.set('tab', 'findings'), p.set('finding', fid), p), { replace: true });
  };

  if (isLoading) return <Spinner label="Cargando análisis..." />;
  if (!a) return <p className="text-red-300">{error?.message ?? 'Análisis no encontrado'}</p>;
  if (a.status === 'failed') return <p className="text-red-300">El análisis falló: {a.error}</p>;

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            Análisis de seguridad
            {a.aiStatus === 'completed' && (
              <span className="inline-flex items-center gap-1 rounded-md bg-violet-500/15 px-2 py-0.5 text-xs font-medium text-violet-300">
                <Bot className="h-3.5 w-3.5" /> IA
              </span>
            )}
          </span>
        }
        subtitle={
          <>
            {a.uploadName} · ejecutado {fmtDateTime(a.createdAt)} por {a.createdBy} · motor v{a.engineVersion}
          </>
        }
        actions={
          <button className="btn-ghost" onClick={() => navigate(`/uploads/${a.uploadId}`)}>
            <ArrowLeft className="h-4 w-4" /> Back
          </button>
        }
      />
      <AiBanner a={a} />
      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { id: 'overview', label: 'Dashboard' },
          { id: 'findings', label: `Hallazgos (${a.findings.length})` },
          { id: 'incidents', label: `Incidentes (${a.incidents.length})` },
          { id: 'mitre', label: 'Matriz MITRE' },
          { id: 'events', label: 'Eventos' },
          { id: 'report', label: 'Informe técnico' },
        ]}
      />
      {tab === 'overview' && <Overview a={a} goFindings={() => setTab('findings')} />}
      {tab === 'findings' && <FindingsTab a={a} selected={selected} onSelect={openFinding} />}
      {tab === 'incidents' && <Incidents a={a} openFinding={openFinding} />}
      {tab === 'mitre' && <MitreMatrix a={a} openFinding={openFinding} />}
      {tab === 'events' && <EventsGrid uploadId={a.uploadId} analysisId={a.id} />}
      {tab === 'report' && <ReportTab a={a} />}
    </>
  );
}
