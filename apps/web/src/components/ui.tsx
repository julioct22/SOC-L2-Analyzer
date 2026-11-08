import { useEffect, type ReactNode } from 'react';
import { Loader2, X, Inbox } from 'lucide-react';
import {
  FINDING_STATUS_LABELS,
  SEVERITY_LABELS,
  mitreUrl,
  type FindingStatus,
  type MitreRef,
  type Severity,
} from '@soc/shared';
import { SEV_CLASSES } from '../lib/format';

export function SeverityBadge({ severity, size = 'sm' }: { severity: Severity; size?: 'sm' | 'md' }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-semibold ring-1 ring-inset ${SEV_CLASSES[severity]} ${size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]'}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

const STATUS_CLASSES: Record<FindingStatus, string> = {
  pending_review: 'text-amber-300 bg-amber-500/10 ring-amber-500/30',
  confirmed: 'text-emerald-300 bg-emerald-500/10 ring-emerald-500/30',
  false_positive: 'text-slate-400 bg-slate-500/10 ring-slate-500/30 line-through decoration-slate-500/60',
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return <span className={`inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${STATUS_CLASSES[status]}`}>{FINDING_STATUS_LABELS[status]}</span>;
}

export function MitreChips({ mitre }: { mitre: MitreRef[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {mitre.map((m) => (
        <a
          key={m.id}
          href={mitreUrl(m.id)}
          target="_blank"
          rel="noreferrer"
          title={m.name}
          className="rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-300 hover:border-accent hover:text-accent"
        >
          {m.id}
        </a>
      ))}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin" /> {label ?? 'Cargando...'}
    </div>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-ink-600 px-6 py-12 text-center">
      <div className="text-slate-500">{icon ?? <Inbox className="h-8 w-8" />}</div>
      <p className="font-medium text-slate-300">{title}</p>
      {children && <div className="max-w-md text-sm text-slate-500">{children}</div>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string }) {
  return (
    <div className="card relative overflow-hidden p-4">
      {accent && <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: accent }} />}
      <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</p>
      <p className="mt-2 text-3xl font-semibold tabular-nums text-white">{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, width = 'max-w-lg' }: { open: boolean; onClose: () => void; title: string; children: ReactNode; width?: string }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onMouseDown={onClose}>
      <div className={`card w-full ${width} bg-ink-900 shadow-2xl`} onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="flex items-center justify-between border-b border-ink-700 px-5 py-3.5">
          <h2 className="font-semibold text-white">{title}</h2>
          <button className="rounded p-1 text-slate-400 hover:bg-ink-700 hover:text-white" onClick={onClose} aria-label="Cerrar">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="mb-5 flex gap-1 overflow-x-auto border-b border-ink-700">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`-mb-px whitespace-nowrap border-b-2 px-4 py-2.5 text-sm font-medium transition ${
            value === t.id ? 'border-accent text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
