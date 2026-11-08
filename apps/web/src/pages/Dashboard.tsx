import { Link } from 'react-router';
import { ArrowRight, FileSpreadsheet, Upload } from 'lucide-react';
import { SEVERITIES, SEVERITY_LABELS, can } from '@soc/shared';
import { useAnalyses, useDashboard, useRecentUploads } from '../api/hooks';
import { useSession } from '../lib/session';
import { Chart } from '../components/Chart';
import { Empty, PageHeader, Spinner, Stat } from '../components/ui';
import { SEV_HEX, fmtDateTime } from '../lib/format';

export function DashboardPage() {
  const { me } = useSession();
  const dash = useDashboard();
  const analyses = useAnalyses();
  const uploads = useRecentUploads();

  const open = (sev: string) => dash.data?.findings.filter((f) => f.severity === sev && f.status !== 'false_positive').reduce((s, f) => s + f.count, 0) ?? 0;
  const pending = dash.data?.findings.filter((f) => f.status === 'pending_review').reduce((s, f) => s + f.count, 0) ?? 0;
  const confirmed = dash.data?.findings.filter((f) => f.status === 'confirmed').reduce((s, f) => s + f.count, 0) ?? 0;
  const fp = dash.data?.findings.filter((f) => f.status === 'false_positive').reduce((s, f) => s + f.count, 0) ?? 0;

  return (
    <>
      <PageHeader
        title={`Hola, ${me.user.fullName.split(' ')[0]}`}
        subtitle={me.user.role === 'admin' ? 'Vista de supervisión de la plataforma (todas las cargas y análisis).' : 'Resumen de tu trabajo como analista SOC L2.'}
        actions={
          can(me.user.role, 'uploads:create') && (
            <Link to="/uploads?upload=1" className="btn-primary">
              <Upload className="h-4 w-4" /> Upload Log File
            </Link>
          )
        }
      />
      {dash.isLoading ? (
        <Spinner />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
            <Stat label="Archivos cargados" value={dash.data?.uploadsCount ?? 0} />
            <Stat label="Análisis" value={dash.data?.analysesCount ?? 0} />
            {SEVERITIES.map((s) => (
              <Stat key={s} label={`${SEVERITY_LABELS[s]} abiertos`} value={open(s)} accent={SEV_HEX[s]} />
            ))}
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-3">
            <div className="card p-5">
              <h2 className="font-semibold text-white">Estado de validación L2</h2>
              <p className="text-xs text-slate-500">Hallazgos propuestos por el motor (L1) y su revisión</p>
              <Chart
                height={230}
                option={{
                  tooltip: { trigger: 'item' },
                  legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
                  series: [
                    {
                      type: 'pie',
                      radius: ['55%', '78%'],
                      center: ['50%', '45%'],
                      itemStyle: { borderColor: '#0b1220', borderWidth: 3 },
                      label: { show: false },
                      data: [
                        { name: 'Pendientes', value: pending, itemStyle: { color: '#f59e0b' } },
                        { name: 'Confirmados', value: confirmed, itemStyle: { color: '#10b981' } },
                        { name: 'Falsos positivos', value: fp, itemStyle: { color: '#475569' } },
                      ],
                    },
                  ],
                }}
              />
            </div>

            <div className="card p-5 lg:col-span-2">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="font-semibold text-white">Análisis recientes</h2>
                <Link to="/uploads" className="text-xs text-accent hover:underline">
                  Ver todos
                </Link>
              </div>
              {analyses.data?.length ? (
                <div className="divide-y divide-ink-700">
                  {analyses.data.map((a) => (
                    <Link key={a.id} to={`/analyses/${a.id}`} className="group flex items-center gap-4 py-3 hover:bg-ink-800/40">
                      <FileSpreadsheet className="h-5 w-5 shrink-0 text-emerald-400" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-slate-100">{a.uploadName}</p>
                        <p className="text-xs text-slate-500">
                          {fmtDateTime(a.createdAt)} · {a.createdBy} · {a.findingsCount} hallazgos
                        </p>
                      </div>
                      <div className="flex gap-1.5 text-xs">
                        {a.criticalCount > 0 && <span className="rounded bg-red-500/15 px-2 py-0.5 text-red-300">{a.criticalCount} crít.</span>}
                        {a.highCount > 0 && <span className="rounded bg-orange-500/15 px-2 py-0.5 text-orange-300">{a.highCount} altos</span>}
                        {a.pendingCount > 0 && <span className="rounded bg-amber-500/10 px-2 py-0.5 text-amber-300">{a.pendingCount} por validar</span>}
                      </div>
                      <ArrowRight className="h-4 w-4 text-slate-600 group-hover:text-accent" />
                    </Link>
                  ))}
                </div>
              ) : (
                <Empty title="Aún no hay análisis">Sube un archivo de logs y ejecuta el análisis para ver resultados aquí.</Empty>
              )}
            </div>
          </div>

          <div className="card mt-6 p-5">
            <h2 className="mb-3 font-semibold text-white">Últimas cargas</h2>
            {uploads.data?.length ? (
              <table className="w-full text-sm">
                <thead className="text-left text-xs text-slate-500">
                  <tr>
                    <th className="pb-2">Archivo</th>
                    <th className="pb-2">Cargado</th>
                    <th className="pb-2">Por</th>
                    <th className="pb-2 text-right">Eventos</th>
                    <th className="pb-2 text-right">Análisis</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-800">
                  {uploads.data.map((u) => (
                    <tr key={u.id}>
                      <td className="py-2">
                        <Link to={`/uploads/${u.id}`} className="text-slate-200 hover:text-accent">
                          {u.originalName}
                        </Link>
                      </td>
                      <td className="text-slate-400">{fmtDateTime(u.uploadedAt)}</td>
                      <td className="text-slate-400">{u.uploadedBy}</td>
                      <td className="text-right tabular-nums">{u.rowCount}</td>
                      <td className="text-right tabular-nums">{u.analysisCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-sm text-slate-500">Sin cargas todavía.</p>
            )}
          </div>
        </>
      )}
    </>
  );
}
