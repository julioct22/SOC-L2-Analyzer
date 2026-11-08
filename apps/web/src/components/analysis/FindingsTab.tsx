import { useEffect, useMemo, useState } from 'react';
import { Bot, CheckCircle2, XCircle, RotateCcw, Save, Search, Cpu, Loader2, Crosshair, ShieldHalf, Wrench } from 'lucide-react';
import { toast } from 'sonner';
import {
  L1_VERDICT_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
  SEVERITY_SCALE_TEXT,
  can,
  type AnalysisDTO,
  type FindingDTO,
  type FindingStatus,
  type Severity,
} from '@soc/shared';
import { useReviewFinding } from '../../api/hooks';
import { useSession } from '../../lib/session';
import { EventsGrid } from '../EventsGrid';
import { MitreChips, SeverityBadge, StatusBadge } from '../ui';
import { SEV_HEX, fmtDateTime } from '../../lib/format';

function Section({ title, children, badge }: { title: string; children: React.ReactNode; badge?: React.ReactNode }) {
  return (
    <section>
      <h4 className="mb-2 flex items-center gap-2 text-xs font-semibold tracking-wider text-slate-400 uppercase">
        {title} {badge}
      </h4>
      {children}
    </section>
  );
}

function ReviewPanel({ f, analysisId }: { f: FindingDTO; analysisId: string }) {
  const review = useReviewFinding(analysisId);
  const [notes, setNotes] = useState(f.analystNotes ?? '');
  const [override, setOverride] = useState<Severity | ''>(f.severityOverride ?? '');
  useEffect(() => {
    setNotes(f.analystNotes ?? '');
    setOverride(f.severityOverride ?? '');
  }, [f.id, f.analystNotes, f.severityOverride]);

  const save = (status?: FindingStatus) =>
    review.mutate(
      { id: f.id, status, analystNotes: notes.trim() || null, severityOverride: override || null },
      { onSuccess: () => toast.success('Revisión guardada'), onError: (e) => toast.error(e.message) },
    );

  return (
    <div className="rounded-xl border border-accent/30 bg-accent/[0.04] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h4 className="text-sm font-semibold text-white">Validación del analista L2</h4>
        {f.reviewedBy && (
          <span className="text-xs text-slate-500">
            Última revisión: {f.reviewedBy} · {fmtDateTime(f.reviewedAt)}
          </span>
        )}
      </div>
      <div className="grid gap-3 md:grid-cols-[1fr_200px]">
        <div>
          <label className="label">Notas / justificación (obligatoria para falso positivo o cambio de criticidad)</label>
          <textarea className="input min-h-20" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Ej.: Se confirmó con el dueño de la cuenta que no reconoce el acceso..." />
        </div>
        <div>
          <label className="label">Criticidad final</label>
          <select className="input" value={override} onChange={(e) => setOverride(e.target.value as Severity | '')}>
            <option value="">Mantener motor ({SEVERITY_LABELS[f.severity]})</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABELS[s]}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button className="btn border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20" disabled={review.isPending} onClick={() => save('confirmed')}>
          <CheckCircle2 className="h-4 w-4" /> Confirmar
        </button>
        <button className="btn-danger" disabled={review.isPending} onClick={() => save('false_positive')}>
          <XCircle className="h-4 w-4" /> Falso positivo
        </button>
        <button className="btn-ghost" disabled={review.isPending} onClick={() => save('pending_review')}>
          <RotateCcw className="h-4 w-4" /> Volver a pendiente
        </button>
        <button className="btn-ghost ml-auto" disabled={review.isPending} onClick={() => save()}>
          {review.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Guardar notas
        </button>
      </div>
    </div>
  );
}

function FindingDetail({ f, a }: { f: FindingDTO; a: AnalysisDTO }) {
  const { me } = useSession();
  return (
    <div className="card overflow-hidden">
      <div className="border-b border-ink-700 bg-ink-850 px-5 py-4" style={{ borderTop: `3px solid ${SEV_HEX[f.effectiveSeverity]}` }}>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.effectiveSeverity} size="md" />
          <StatusBadge status={f.status} />
          {f.incidentKey && <span className="rounded bg-ink-700 px-2 py-0.5 font-mono text-[11px] text-accent">{f.incidentKey}</span>}
          <span className="font-mono text-[11px] text-slate-500">{f.ruleId}</span>
        </div>
        <h3 className="mt-2 text-lg font-semibold text-white">{f.title}</h3>
        <p className="mt-1 text-xs text-slate-400">
          {f.firstSeen} → {f.lastSeen?.slice(11)} · {f.eventCount} evento(s) de evidencia
        </p>
      </div>

      <div className="space-y-6 p-5">
        {can(me.user.role, 'findings:review') && <ReviewPanel f={f} analysisId={a.id} />}

        <Section title="Qué se detectó">
          <p className="text-sm leading-relaxed text-slate-200">{f.summary}</p>
        </Section>

        <Section
          title="Explicación técnica"
          badge={
            f.narrativeSource === 'ai' ? (
              <span className="inline-flex items-center gap-1 rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-medium tracking-normal text-violet-300 normal-case">
                <Bot className="h-3 w-3" /> IA validada contra evidencia
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded bg-ink-700 px-1.5 py-0.5 text-[10px] font-medium tracking-normal text-slate-400 normal-case">
                <Cpu className="h-3 w-3" /> Motor determinista
              </span>
            )
          }
        >
          <p className="text-sm leading-relaxed whitespace-pre-line text-slate-300">{f.technicalExplanation}</p>
        </Section>

        <div className="grid gap-6 md:grid-cols-2">
          <Section title="MITRE ATT&CK">
            <MitreChips mitre={f.mitre} />
            <ul className="mt-2 space-y-1 text-xs text-slate-400">
              {f.mitre.map((m) => (
                <li key={m.id}>
                  <span className="font-mono text-slate-300">{m.id}</span> {m.name}
                </li>
              ))}
            </ul>
          </Section>
          <Section title="Entidades">
            <dl className="space-y-1 text-xs">
              <div className="flex gap-2">
                <dt className="w-16 text-slate-500">Equipos</dt>
                <dd className="text-slate-300">{f.entities.hosts.join(', ') || '—'}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-16 text-slate-500">Usuarios</dt>
                <dd className="text-slate-300">{f.entities.users.join(', ') || '—'}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-16 text-slate-500">IPs</dt>
                <dd className="font-mono text-slate-300">{f.entities.ips.join(', ') || '—'}</dd>
              </div>
            </dl>
          </Section>
        </div>

        <Section title="Criticidad y justificación">
          <div className="flex items-center gap-3">
            <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-ink-700">
              <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${f.score}%`, background: SEV_HEX[f.severity] }} />
            </div>
            <span className="font-mono text-sm text-white">{f.score}/100</span>
          </div>
          <table className="mt-3 w-full text-xs">
            <tbody>
              {f.scoreFactors.map((s, i) => (
                <tr key={i} className="border-b border-ink-800">
                  <td className="py-1.5 text-slate-300">{s.label}</td>
                  <td className="py-1.5 text-right font-mono text-slate-400">
                    {i === 0 ? '' : '+'}
                    {s.points}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-[11px] text-slate-500">{SEVERITY_SCALE_TEXT}</p>
          {f.l1Verdict && (
            <p className="mt-2 rounded-lg bg-ink-800 px-3 py-2 text-xs text-slate-300">
              <span className="font-semibold text-slate-100">Triaje L1: {L1_VERDICT_LABELS[f.l1Verdict]}.</span> {f.l1Rationale}
            </p>
          )}
        </Section>

        <Section title="Posible impacto">
          <p className="text-sm leading-relaxed text-slate-300">{f.impact}</p>
        </Section>

        <Section title="Plan de acción">
          <div className="grid gap-3 md:grid-cols-3">
            {[
              { k: 'investigate' as const, t: 'Investigar', icon: <Search className="h-4 w-4 text-sky-400" /> },
              { k: 'contain' as const, t: 'Contener', icon: <ShieldHalf className="h-4 w-4 text-amber-400" /> },
              { k: 'remediate' as const, t: 'Remediar', icon: <Wrench className="h-4 w-4 text-emerald-400" /> },
            ].map((c) => (
              <div key={c.k} className="rounded-lg border border-ink-700 bg-ink-850 p-3">
                <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
                  {c.icon} {c.t}
                </p>
                <ul className="list-disc space-y-1.5 pl-4 text-xs text-slate-300">
                  {f.actionPlan[c.k].map((x) => (
                    <li key={x}>{x}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </Section>

        <Section title={`Evidencias en los logs (${f.eventCount})`}>
          <EventsGrid uploadId={a.uploadId} findingId={f.id} compact />
        </Section>
      </div>
    </div>
  );
}

export function FindingsTab({ a, selected, onSelect }: { a: AnalysisDTO; selected: string | null; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState<'all' | FindingStatus>('all');
  const list = useMemo(() => a.findings.filter((f) => filter === 'all' || f.status === filter), [a.findings, filter]);
  const current = a.findings.find((f) => f.id === selected) ?? list[0];

  if (!a.findings.length)
    return (
      <div className="card flex flex-col items-center gap-2 p-10 text-center">
        <Crosshair className="h-8 w-8 text-slate-500" />
        <p className="text-slate-300">El motor no identificó actividad sospechosa en este archivo.</p>
      </div>
    );

  return (
    <div className="grid gap-5 xl:grid-cols-[380px_1fr]">
      <div className="space-y-3">
        <div className="flex gap-1 rounded-lg bg-ink-850 p-1 text-xs">
          {(
            [
              ['all', 'Todos'],
              ['pending_review', 'Pendientes'],
              ['confirmed', 'Confirmados'],
              ['false_positive', 'Falsos +'],
            ] as const
          ).map(([k, l]) => (
            <button key={k} onClick={() => setFilter(k)} className={`flex-1 rounded-md px-2 py-1.5 ${filter === k ? 'bg-ink-700 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
              {l} ({k === 'all' ? a.findings.length : a.findings.filter((f) => f.status === k).length})
            </button>
          ))}
        </div>
        <div className="max-h-[calc(100vh-300px)] space-y-2 overflow-y-auto pr-1">
          {list.map((f) => (
            <button
              key={f.id}
              onClick={() => onSelect(f.id)}
              className={`w-full rounded-lg border p-3 text-left transition ${
                current?.id === f.id ? 'border-accent/60 bg-ink-800' : 'border-ink-700 bg-ink-900 hover:border-ink-600'
              } ${f.status === 'false_positive' ? 'opacity-60' : ''}`}
              style={{ borderLeft: `3px solid ${SEV_HEX[f.effectiveSeverity]}` }}
            >
              <div className="flex items-center gap-2">
                <SeverityBadge severity={f.effectiveSeverity} />
                <span className="font-mono text-[10px] text-slate-500">{f.score}</span>
                {f.incidentKey && <span className="font-mono text-[10px] text-accent">{f.incidentKey}</span>}
                <span className="ml-auto">
                  <StatusBadge status={f.status} />
                </span>
              </div>
              <p className="mt-1.5 text-sm leading-snug font-medium text-slate-100">{f.title}</p>
              <p className="mt-1 font-mono text-[10px] text-slate-500">
                {f.firstSeen?.slice(11)} · {f.mitre.map((m) => m.id).join(' ')}
              </p>
            </button>
          ))}
        </div>
      </div>
      {current && <FindingDetail f={current} a={a} />}
    </div>
  );
}
