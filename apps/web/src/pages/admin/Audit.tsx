import { Fragment, useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Search } from 'lucide-react';
import { useAudit, useAuditActions } from '../../api/hooks';
import { PageHeader, Spinner } from '../../components/ui';
import { fmtDateTime } from '../../lib/format';

const ACTION_COLOR: Record<string, string> = {
  auth: 'text-sky-300',
  user: 'text-violet-300',
  upload: 'text-emerald-300',
  analysis: 'text-orange-300',
  finding: 'text-amber-300',
  report: 'text-pink-300',
  system: 'text-slate-300',
};

export function AuditPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [q, setQ] = useState('');
  const [action, setAction] = useState('');
  const [open, setOpen] = useState<number | null>(null);
  const actions = useAuditActions();
  const { data, isLoading, isFetching } = useAudit({ page, pageSize: 50, q: q || undefined, action: action || undefined });
  const pages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;

  useEffect(() => {
    const t = setTimeout(() => (setQ(search), setPage(1)), 300);
    return () => clearTimeout(t);
  }, [search]);

  return (
    <>
      <PageHeader title="Auditoría" subtitle="Bitácora inmutable de acciones: inicios de sesión, cargas, análisis, validaciones e informes." />
      <div className="card overflow-hidden">
        <div className="flex flex-wrap gap-2 border-b border-ink-700 p-3">
          <div className="relative min-w-64 flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input className="input py-1.5 pl-9" placeholder="Buscar por usuario, acción o id..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <select className="input w-auto py-1.5" value={action} onChange={(e) => (setAction(e.target.value), setPage(1))}>
            <option value="">Todas las acciones</option>
            {actions.data?.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>
        {isLoading ? (
          <Spinner />
        ) : (
          <div className={`overflow-x-auto ${isFetching ? 'opacity-60' : ''}`}>
            <table className="w-full text-sm">
              <thead className="bg-ink-850 text-left text-xs text-slate-400">
                <tr>
                  <th className="px-4 py-2.5">Fecha</th>
                  <th className="px-4 py-2.5">Usuario</th>
                  <th className="px-4 py-2.5">Acción</th>
                  <th className="px-4 py-2.5">Entidad</th>
                  <th className="px-4 py-2.5">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {data?.items.map((e) => (
                  <Fragment key={e.id}>
                    <tr className="cursor-pointer hover:bg-ink-800/50" onClick={() => setOpen(open === e.id ? null : e.id)}>
                      <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-slate-400">{fmtDateTime(e.at)}</td>
                      <td className="px-4 py-2 text-slate-200">{e.username ?? '—'}</td>
                      <td className={`px-4 py-2 font-mono text-xs ${ACTION_COLOR[e.action.split('.')[0]] ?? ''}`}>{e.action}</td>
                      <td className="px-4 py-2 font-mono text-[11px] text-slate-500">{e.entityType ? `${e.entityType}:${e.entityId?.slice(0, 8)}` : ''}</td>
                      <td className="px-4 py-2 font-mono text-xs text-slate-500">{e.ip}</td>
                    </tr>
                    {open === e.id && e.details && (
                      <tr>
                        <td colSpan={5} className="bg-ink-950 px-4 py-3">
                          <pre className="overflow-x-auto text-[11px] text-slate-300">{JSON.stringify(e.details, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex items-center justify-between border-t border-ink-700 px-3 py-2 text-xs text-slate-400">
          <span>
            {data?.total ?? 0} registro(s) · Página {page} de {pages}
          </span>
          <div className="flex gap-2">
            <button className="btn-ghost px-2 py-1" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button className="btn-ghost px-2 py-1" disabled={page >= pages} onClick={() => setPage(page + 1)}>
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
