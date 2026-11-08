import { useState } from 'react';
import { Bot, Download, ExternalLink, FileText, Loader2, RefreshCw, ShieldAlert, Eye } from 'lucide-react';
import { toast } from 'sonner';
import { can, type AnalysisDTO } from '@soc/shared';
import { useGenerateReport, useReports, useRetryAi } from '../../api/hooks';
import { useSession } from '../../lib/session';
import { fmtBytes, fmtDateTime } from '../../lib/format';

export function ReportTab({ a }: { a: AnalysisDTO }) {
  const { me } = useSession();
  const reports = useReports(a.id);
  const generate = useGenerateReport(a.id);
  const retry = useRetryAi(a.id);
  const [includePending, setIncludePending] = useState(true);
  const [format, setFormat] = useState<'summary' | 'full'>('summary');
  const pending = a.findings.filter((f) => f.status === 'pending_review').length;
  const confirmed = a.findings.filter((f) => f.status === 'confirmed').length;
  const fp = a.findings.filter((f) => f.status === 'false_positive').length;

  const doGenerate = () =>
    generate.mutate(
      { includePending, format },
      {
        onSuccess: (r) => {
          toast.success('Informe PDF generado');
          window.open(`/api/reports/${r.id}/download?inline=1`, '_blank');
        },
        onError: (e) => toast.error(e.message),
      },
    );

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_400px]">
      <div className="space-y-6">
        <div className="card p-6">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Resumen ejecutivo</h3>
            {a.aiStatus === 'completed' ? (
              <span className="inline-flex items-center gap-1 rounded bg-violet-500/15 px-2 py-0.5 text-xs text-violet-300">
                <Bot className="h-3.5 w-3.5" /> Redactado con IA ({a.aiModel})
              </span>
            ) : (
              <span className="rounded bg-ink-700 px-2 py-0.5 text-xs text-slate-400">Generado por el motor</span>
            )}
          </div>
          <div className="space-y-3 text-sm leading-relaxed whitespace-pre-line text-slate-300">{a.executiveSummary}</div>
        </div>

        <div className="card p-6">
          <h3 className="mb-3 text-lg font-semibold text-white">Recomendaciones generales de seguridad</h3>
          <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-300">
            {a.generalRecommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ol>
        </div>

        {a.aiRejected.length > 0 && (
          <div className="card border-amber-500/30 p-6">
            <h3 className="mb-2 flex items-center gap-2 font-semibold text-amber-200">
              <ShieldAlert className="h-4 w-4" /> Validación anti-alucinación
            </h3>
            <p className="mb-3 text-xs text-slate-400">Textos de la IA descartados por mencionar datos que no están en la evidencia. Se conservó el texto del motor.</p>
            <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
              {a.aiRejected.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="space-y-6">
        <div className="card p-5">
          <h3 className="flex items-center gap-2 font-semibold text-white">
            <FileText className="h-4 w-4 text-accent" /> Informe técnico PDF
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Incluye resumen ejecutivo, hallazgos, explicación técnica, evidencias, criticidad y justificación, impacto, plan de acción y recomendaciones.
          </p>
          <div className="mt-4 grid grid-cols-2 gap-2">
            {(
              [
                ['summary', 'Resumido', 'Fichas compactas por hallazgo con la evidencia clave'],
                ['full', 'Completo', 'Una página por hallazgo, toda la evidencia y anexos'],
              ] as const
            ).map(([k, t, d]) => (
              <button
                key={k}
                type="button"
                onClick={() => setFormat(k)}
                className={`rounded-lg border p-3 text-left transition ${format === k ? 'border-accent bg-accent/10' : 'border-ink-600 hover:border-slate-500'}`}
              >
                <p className={`text-sm font-semibold ${format === k ? 'text-white' : 'text-slate-300'}`}>{t}</p>
                <p className="mt-0.5 text-[11px] leading-snug text-slate-500">{d}</p>
              </button>
            ))}
          </div>
          <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
            <div className="rounded-lg bg-emerald-500/10 p-2 text-emerald-300">
              <b className="block text-lg">{confirmed}</b>confirmados
            </div>
            <div className="rounded-lg bg-amber-500/10 p-2 text-amber-300">
              <b className="block text-lg">{pending}</b>pendientes
            </div>
            <div className="rounded-lg bg-slate-500/10 p-2 text-slate-400">
              <b className="block text-lg">{fp}</b>excluidos (FP)
            </div>
          </div>
          {can(me.user.role, 'reports:generate') && (
            <>
              <label className="mt-4 flex items-start gap-2 text-sm text-slate-300">
                <input type="checkbox" className="mt-1 accent-orange-500" checked={includePending} onChange={(e) => setIncludePending(e.target.checked)} />
                <span>
                  Incluir hallazgos pendientes de validación
                  <span className="block text-xs text-slate-500">Si se desmarca, el informe solo contendrá los confirmados por el L2.</span>
                </span>
              </label>
              <button className="btn-primary mt-4 w-full" onClick={doGenerate} disabled={generate.isPending || a.aiStatus === 'pending'}>
                {generate.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                {a.aiStatus === 'pending' ? 'Esperando a la IA...' : `Generar informe ${format === 'full' ? 'completo' : 'resumido'} (PDF)`}
              </button>
            </>
          )}
          <a className="btn-ghost mt-2 w-full" href={`/api/analyses/${a.id}/report-preview?format=${format}`} target="_blank" rel="noreferrer">
            <Eye className="h-4 w-4" /> Vista previa HTML
          </a>
        </div>

        {can(me.user.role, 'analysis:run') && me.aiEnabled && (
          <div className="card p-5">
            <h3 className="flex items-center gap-2 font-semibold text-white">
              <Bot className="h-4 w-4 text-violet-400" /> Asistencia de IA
            </h3>
            <p className="mt-1 text-xs text-slate-400">
              Estado: <b className="text-slate-200">{{ disabled: 'deshabilitada', pending: 'redactando...', completed: 'completada', failed: 'falló' }[a.aiStatus]}</b>
              {a.aiError && <span className="block text-red-300">{a.aiError}</span>}
            </p>
            <button className="btn-ghost mt-3 w-full" disabled={retry.isPending || a.aiStatus === 'pending'} onClick={() => retry.mutate()}>
              <RefreshCw className={`h-4 w-4 ${a.aiStatus === 'pending' ? 'animate-spin' : ''}`} /> Volver a redactar con IA
            </button>
          </div>
        )}

        <div className="card p-5">
          <h3 className="mb-3 font-semibold text-white">Informes generados</h3>
          {reports.data?.length ? (
            <ul className="space-y-2">
              {reports.data.map((r) => (
                <li key={r.id} className="rounded-lg border border-ink-700 bg-ink-850 p-3">
                  <p className="truncate text-sm text-slate-200" title={r.fileName}>
                    {r.fileName}
                  </p>
                  <p className="text-xs text-slate-500">
                    {fmtDateTime(r.generatedAt)} · {r.generatedBy} · {fmtBytes(r.sizeBytes)}
                  </p>
                  <p className="truncate font-mono text-[10px] text-slate-600" title="SHA-256">
                    {r.sha256}
                  </p>
                  <div className="mt-2 flex gap-2">
                    <a className="btn-ghost flex-1 py-1 text-xs" href={`/api/reports/${r.id}/download?inline=1`} target="_blank" rel="noreferrer">
                      <ExternalLink className="h-3.5 w-3.5" /> Ver
                    </a>
                    <a className="btn-ghost flex-1 py-1 text-xs" href={`/api/reports/${r.id}/download`}>
                      <Download className="h-3.5 w-3.5" /> Descargar
                    </a>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-500">Aún no se ha generado ningún informe.</p>
          )}
        </div>
      </div>
    </div>
  );
}
