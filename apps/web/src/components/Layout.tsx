import { NavLink, Outlet } from 'react-router';
import { LayoutDashboard, FolderUp, Users, ScrollText, LogOut, ShieldCheck, Sparkles } from 'lucide-react';
import { ROLE_LABELS, can } from '@soc/shared';
import { useLogout } from '../api/hooks';
import { useSession } from '../lib/session';

const linkCls = ({ isActive }: { isActive: boolean }) =>
  `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
    isActive ? 'bg-accent/10 text-white ring-1 ring-inset ring-accent/30' : 'text-slate-400 hover:bg-ink-800 hover:text-slate-100'
  }`;

export function Layout() {
  const { me } = useSession();
  const logout = useLogout();
  const role = me.user.role;

  return (
    <div className="flex h-full">
      <aside className="flex w-64 shrink-0 flex-col border-r border-ink-700 bg-ink-900/60">
        {/* Usuario + cerrar sesión arriba a la izquierda */}
        <div className="border-b border-ink-700 p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 font-semibold text-accent ring-1 ring-accent/30">
              {me.user.fullName.slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-white">{me.user.fullName}</p>
              <p className="truncate text-xs text-slate-400">
                @{me.user.username} · {ROLE_LABELS[role]}
              </p>
            </div>
          </div>
          <button className="btn-ghost mt-3 w-full py-1.5 text-xs" onClick={() => logout.mutate()} disabled={logout.isPending}>
            <LogOut className="h-3.5 w-3.5" /> Cerrar sesión
          </button>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          <NavLink to="/" end className={linkCls}>
            <LayoutDashboard className="h-4 w-4" /> Dashboard
          </NavLink>
          {can(role, 'uploads:read') && (
            <NavLink to="/uploads" className={linkCls}>
              <FolderUp className="h-4 w-4" /> Logs y análisis
            </NavLink>
          )}
          {can(role, 'users:manage') && (
            <>
              <p className="px-3 pt-5 pb-1 text-[10px] font-semibold tracking-widest text-slate-500 uppercase">Administración</p>
              <NavLink to="/admin/users" className={linkCls}>
                <Users className="h-4 w-4" /> Usuarios
              </NavLink>
            </>
          )}
          {can(role, 'audit:read') && (
            <NavLink to="/admin/audit" className={linkCls}>
              <ScrollText className="h-4 w-4" /> Auditoría
            </NavLink>
          )}
        </nav>

        <div className="space-y-2 border-t border-ink-700 p-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-accent" />
            <span className="font-semibold text-slate-300">SOC L2 Analyzer</span>
          </div>
          <div className="flex items-center gap-2">
            <Sparkles className={`h-3.5 w-3.5 ${me.aiEnabled ? 'text-violet-400' : 'text-slate-600'}`} />
            <span title={me.aiModel ?? ''}>IA {me.aiEnabled ? `habilitada (${me.aiProvider === 'gemini' ? 'Gemini' : 'Claude'})` : 'deshabilitada'}</span>
          </div>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1500px] px-8 py-7">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
