import { useEffect, useMemo, useState } from 'react';
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { ChevronLeft, ChevronRight, Search, ShieldAlert } from 'lucide-react';
import type { LogEventDTO } from '@soc/shared';
import { useEvents, useFacets, type EventFilters } from '../api/hooks';
import { Spinner } from './ui';

const SRC_SEV: Record<string, string> = {
  High: 'text-red-300',
  Medium: 'text-orange-300',
  Warning: 'text-yellow-300',
  Informational: 'text-slate-400',
};

const columns: ColumnDef<LogEventDTO>[] = [
  { accessorKey: 'logId', header: 'Log_ID', cell: (c) => <span className="font-mono text-[11px] text-slate-300">{c.getValue<string>()}</span> },
  { accessorKey: 'ts', header: 'Timestamp', cell: (c) => <span className="whitespace-nowrap font-mono text-[11px]">{c.getValue<string>()}</span> },
  { accessorKey: 'hostname', header: 'Hostname' },
  { accessorKey: 'eventId', header: 'Event_ID', cell: (c) => <span className="font-mono">{c.getValue<string>()}</span> },
  { accessorKey: 'user', header: 'User' },
  { accessorKey: 'sourceIp', header: 'Source_IP', cell: (c) => <span className="font-mono text-[11px]">{c.getValue<string>()}</span> },
  { accessorKey: 'destination', header: 'Destination' },
  { accessorKey: 'logSource', header: 'Log_Source' },
  { accessorKey: 'description', header: 'Event_Description', cell: (c) => <span className="line-clamp-2 min-w-56" title={c.getValue<string>() ?? ''}>{c.getValue<string>()}</span> },
  {
    accessorKey: 'commandLine',
    header: 'Process_CommandLine',
    cell: (c) => (c.getValue() ? <code className="line-clamp-2 min-w-48 break-all text-[11px] text-orange-200/90" title={c.getValue<string>()}>{c.getValue<string>()}</code> : null),
  },
  { accessorKey: 'result', header: 'Result' },
  { accessorKey: 'severitySrc', header: 'Severity', cell: (c) => <span className={SRC_SEV[c.getValue<string>()] ?? ''}>{c.getValue<string>()}</span> },
];

/** Datagrid del Excel con paginación, búsqueda y filtros resueltos en el servidor */
export function EventsGrid({ uploadId, analysisId, findingId, compact }: { uploadId: string; analysisId?: string; findingId?: string; compact?: boolean }) {
  const [filters, setFilters] = useState<EventFilters>({ page: 1, pageSize: compact ? 15 : 50, findingId });
  const [search, setSearch] = useState('');
  const [onlyEvidence, setOnlyEvidence] = useState(false);
  const facets = useFacets(uploadId);

  // Búsqueda con retardo para no consultar en cada tecla
  useEffect(() => {
    const t = setTimeout(() => setFilters((f) => ({ ...f, q: search || undefined, page: 1 })), 300);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => setFilters((f) => ({ ...f, findingId, page: 1 })), [findingId]);

  const effective = useMemo(() => ({ ...filters, analysisId: onlyEvidence ? analysisId : undefined }), [filters, onlyEvidence, analysisId]);
  const { data, isLoading, isFetching } = useEvents(uploadId, effective);
  const table = useReactTable({ data: data?.items ?? [], columns, getCoreRowModel: getCoreRowModel(), manualPagination: true });
  const pages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;

  const select = (key: keyof EventFilters, label: string, options: string[] | undefined) => (
    <select className="input w-auto max-w-44 py-1.5" value={(filters[key] as string) ?? ''} onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value || undefined, page: 1 }))}>
      <option value="">{label}: todos</option>
      {options?.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );

  return (
    <div className="card overflow-hidden">
      {!findingId && (
        <div className="flex flex-wrap items-center gap-2 border-b border-ink-700 p-3">
          <div className="relative min-w-64 flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input className="input py-1.5 pl-9" placeholder="Buscar en Log_ID, host, usuario, IP, descripción, comando..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {select('hostname', 'Host', facets.data?.hostname)}
          {select('eventId', 'Event_ID', facets.data?.eventId)}
          {select('logSource', 'Fuente', facets.data?.logSource)}
          {select('severitySrc', 'Severidad SIEM', facets.data?.severitySrc)}
          {analysisId && (
            <label className={`btn-ghost cursor-pointer py-1.5 ${onlyEvidence ? 'border-accent text-accent' : ''}`}>
              <input type="checkbox" className="hidden" checked={onlyEvidence} onChange={(e) => (setOnlyEvidence(e.target.checked), setFilters((f) => ({ ...f, page: 1 })))} />
              <ShieldAlert className="h-4 w-4" /> Solo evidencias
            </label>
          )}
        </div>
      )}
      {isLoading ? (
        <Spinner />
      ) : (
        <div className={`overflow-auto ${compact ? 'max-h-[420px]' : 'max-h-[calc(100vh-330px)]'} ${isFetching ? 'opacity-60' : ''}`}>
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 z-10 bg-ink-850">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => (
                    <th key={h.id} className="border-b border-ink-700 px-3 py-2 font-semibold whitespace-nowrap text-slate-400">
                      {flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((r) => (
                <tr key={r.id} className="border-b border-ink-800 align-top hover:bg-ink-800/60">
                  {r.getVisibleCells().map((c) => (
                    <td key={c.id} className="px-3 py-1.5 text-slate-300">
                      {flexRender(c.column.columnDef.cell, c.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
              {!data?.items.length && (
                <tr>
                  <td colSpan={columns.length} className="py-10 text-center text-slate-500">
                    Sin eventos para los filtros seleccionados
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex items-center justify-between border-t border-ink-700 px-3 py-2 text-xs text-slate-400">
        <span>
          {data ? `${data.total} evento(s)` : ''} · Página {filters.page} de {pages}
        </span>
        <div className="flex items-center gap-2">
          <select className="input w-auto py-1" value={filters.pageSize} onChange={(e) => setFilters((f) => ({ ...f, pageSize: Number(e.target.value), page: 1 }))}>
            {[15, 25, 50, 100, 200].map((n) => (
              <option key={n} value={n}>
                {n} / pág.
              </option>
            ))}
          </select>
          <button className="btn-ghost px-2 py-1" disabled={filters.page <= 1} onClick={() => setFilters((f) => ({ ...f, page: f.page - 1 }))}>
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button className="btn-ghost px-2 py-1" disabled={filters.page >= pages} onClick={() => setFilters((f) => ({ ...f, page: f.page + 1 }))}>
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
