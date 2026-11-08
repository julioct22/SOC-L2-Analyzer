import { useState, type FormEvent } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { ShieldCheck, Lock, User, Loader2 } from 'lucide-react';
import { useLogin } from '../api/hooks';

export function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const login = useLogin();
  const navigate = useNavigate();
  const location = useLocation();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate(
      { username, password },
      {
        onSuccess: (r) => {
          const from = (location.state as { from?: string } | null)?.from;
          navigate(r.user.mustChangePassword ? '/change-password' : from && from !== '/login' ? from : '/', { replace: true });
        },
      },
    );
  };

  return (
    <div className="grid min-h-full lg:grid-cols-[1.1fr_1fr]">
      <div className="relative hidden overflow-hidden border-r border-ink-700 bg-ink-900 lg:block">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(249,115,22,0.18),transparent_45%),radial-gradient(circle_at_80%_80%,rgba(59,130,246,0.12),transparent_40%)]" />
        <div
          className="absolute inset-0 opacity-[0.07]"
          style={{ backgroundImage: 'linear-gradient(#94a3b8 1px, transparent 1px), linear-gradient(90deg, #94a3b8 1px, transparent 1px)', backgroundSize: '36px 36px' }}
        />
        <div className="relative flex h-full flex-col justify-between p-12">
          <div className="flex items-center gap-3">
            <ShieldCheck className="h-8 w-8 text-accent" />
            <span className="text-lg font-semibold text-white">SOC L2 Analyzer</span>
          </div>
          <div className="max-w-lg">
            <p className="text-xs font-semibold tracking-[0.25em] text-accent uppercase">Centro de Operaciones de Seguridad</p>
            <h1 className="mt-4 text-4xl leading-tight font-semibold text-white">De los logs a un informe defendible, con cada conclusión respaldada por evidencia.</h1>
            <ul className="mt-8 space-y-3 text-sm text-slate-300">
              <li>▸ Detección automática mapeada a MITRE ATT&amp;CK (rol de analista L1)</li>
              <li>▸ Validación humana de cada hallazgo por el analista L2</li>
              <li>▸ Redacción asistida por IA con verificación anti-alucinación</li>
              <li>▸ Trazabilidad completa: quién subió, analizó, validó y exportó</li>
            </ul>
          </div>
          <p className="text-xs text-slate-500">Acceso restringido a personal autorizado. Toda actividad queda registrada.</p>
        </div>
      </div>

      <div className="flex items-center justify-center p-6">
        <form onSubmit={submit} className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <ShieldCheck className="h-10 w-10 text-accent" />
          </div>
          <h2 className="text-2xl font-semibold text-white">Iniciar sesión</h2>
          <p className="mt-1 text-sm text-slate-400">Ingrese sus credenciales corporativas</p>

          <div className="mt-8 space-y-4">
            <div>
              <label className="label" htmlFor="username">
                Usuario
              </label>
              <div className="relative">
                <User className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input id="username" className="input pl-9" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required />
              </div>
            </div>
            <div>
              <label className="label" htmlFor="password">
                Contraseña
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input id="password" type="password" className="input pl-9" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </div>
            </div>
            {login.isError && <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{login.error.message}</p>}
            <button className="btn-primary w-full py-2.5" disabled={login.isPending}>
              {login.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Ingresar
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
