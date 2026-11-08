import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { KeyRound, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { useChangePassword, useLogout } from '../api/hooks';
import { useSession } from '../lib/session';

export function ChangePasswordPage() {
  const { me } = useSession();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const change = useChangePassword();
  const logout = useLogout();
  const navigate = useNavigate();
  const mismatch = confirm.length > 0 && next !== confirm;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (mismatch) return;
    change.mutate(
      { currentPassword: current, newPassword: next },
      {
        onSuccess: () => {
          toast.success('Contraseña actualizada');
          navigate('/', { replace: true });
        },
      },
    );
  };

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <form onSubmit={submit} className="card w-full max-w-md p-7">
        <KeyRound className="h-8 w-8 text-accent" />
        <h1 className="mt-4 text-xl font-semibold text-white">Cambio de contraseña</h1>
        <p className="mt-1 text-sm text-slate-400">
          {me.user.mustChangePassword ? 'Por seguridad debe definir una contraseña personal antes de continuar.' : 'Defina su nueva contraseña.'}
        </p>
        <div className="mt-6 space-y-4">
          <div>
            <label className="label">Contraseña actual</label>
            <input type="password" className="input" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
          </div>
          <div>
            <label className="label">Nueva contraseña</label>
            <input type="password" className="input" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required />
            <p className="mt-1.5 text-xs text-slate-500">Mínimo 10 caracteres, con mayúsculas, minúsculas, números y símbolos.</p>
          </div>
          <div>
            <label className="label">Confirmar nueva contraseña</label>
            <input type="password" className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
            {mismatch && <p className="mt-1.5 text-xs text-red-300">Las contraseñas no coinciden</p>}
          </div>
          {change.isError && <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{change.error.message}</p>}
          <div className="flex gap-2 pt-2">
            <button type="button" className="btn-ghost flex-1" onClick={() => logout.mutate()}>
              Salir
            </button>
            <button className="btn-primary flex-1" disabled={change.isPending || mismatch}>
              {change.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Guardar
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
