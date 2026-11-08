import { Link, useNavigate, useParams } from 'react-router';
import { ArrowLeft, Download, Loader2, Radar, ArrowRight } from 'lucide-react';
import { toast } from 'sonner';
import { can } from '@soc/shared';
import { useAnalyses, useRunAnalysis, useUpload } from '../api/hooks';
import { useSession } from '../lib/session';
import { EventsGrid } from '../components/EventsGrid';
import { PageHeader, Spinner } from '../components/ui';
import { fmtBytes, fmtDateTime, ymdLocal } from '../lib/format';

export function UploadDetailPage() {
  const { id = '' } = useParams();
  const { me } = useSession();
  const upload = useUpload(id);
  const analyses = useAnalyses(id);
  const run = useRunAnalysis();
  const navigate = useNavigate();

  if (upload.isLoading) return <Spinner />;
  if (!upload.data) return <p className="text-red-300">{upload.error?.message ?? 'No encontrado'}</p>;
  const u = upload.data;
  const day = ymdLocal(u.uploadedAt);

  const analyze = () =>
    run.mutate(u.id, {
      onSuccess: (a) => {
        toast.success(`Análisis completado: ${a.findings.length} hallazgos, ${a.incidents.length} incidentes`);
        navigate(`/analyses/${a.id}`);
      },
      onError: (e) => toast.error(e.message),
    });

  return (
    <>
      <PageHeader
        title={u.originalName}
        subtitle={
          <>
            {u.rowCount} eventos · hoja “{u.sheetName}” · {fmtBytes(u.sizeBytes)} · cargado {fmtDateTime(u.uploadedAt)} por {u.uploadedBy}
            <br />
            <span className="font-mono text-[11px] text-slate-500">SHA-256 {u.sha256}</span>
          </>
        }
        actions={
          <>
            <a className="btn-ghost" href={`/api/uploads/${u.id}/download`}>
              <Download className="h-4 w-4" /> Original
            </a>
            {can(me.user.role, 'analysis:run') && (
              <button className="btn-primary" onClick={analyze} disabled={run.isPending}>
                {run.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
                {u.analysisCount ? 'Ejecutar nuevo análisis' : 'Analizar seguridad'}
              </button>
            )}
            <button className="btn-ghost" onClick={() => navigate(`/uploads?date=${day}`)}>
              <ArrowLeft className="h-4 w-4" /> Back
            </button>
          </>
        }
      />

      {!!analyses.data?.length && (
        <div className="card mb-5 p-4">
          <h2 className="mb-2 text-sm font-semibold text-white">Análisis de este archivo</h2>
          <div className="flex flex-wrap gap-2">
            {analyses.data.map((a) => (
              <Link key={a.id} to={`/analyses/${a.id}`} className="group flex items-center gap-3 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2 text-sm hover:border-accent/50">
                <span className="text-slate-300">{fmtDateTime(a.createdAt)}</span>
                <span className="text-xs text-slate-500">{a.createdBy}</span>
                <span className="text-xs text-red-300">{a.criticalCount} crít.</span>
                <span className="text-xs text-orange-300">{a.highCount} altos</span>
                <span className="text-xs text-amber-300">{a.pendingCount} por validar</span>
                <ArrowRight className="h-3.5 w-3.5 text-slate-600 group-hover:text-accent" />
              </Link>
            ))}
          </div>
        </div>
      )}

      <EventsGrid uploadId={u.id} analysisId={u.latestAnalysisId ?? undefined} />
    </>
  );
}
