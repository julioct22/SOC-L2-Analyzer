import { useState, type FormEvent } from 'react';
import { UserPlus, KeyRound, Power, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { ROLES, ROLE_LABELS, ROLE_PERMISSIONS, type Role, type UserDTO } from '@soc/shared';
import { useCreateUser, useResetPassword, useUpdateUser, useUsers } from '../../api/hooks';
import { useSession } from '../../lib/session';
import { Modal, PageHeader, Spinner } from '../../components/ui';
import { fmtDateTime } from '../../lib/format';

const PW_HINT = 'Mín. 10 caracteres, mayúsculas, minúsculas, números y símbolo. El usuario deberá cambiarla al ingresar.';

function CreateUserModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateUser();
  const [form, setForm] = useState({ username: '', fullName: '', role: 'analyst' as Role, password: '' });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(form, {
      onSuccess: () => {
        toast.success(`Usuario ${form.username} creado`);
        setForm({ username: '', fullName: '', role: 'analyst', password: '' });
        onClose();
      },
    });
  };
  return (
    <Modal open={open} onClose={onClose} title="Nuevo usuario">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Usuario</label>
            <input className="input" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
          </div>
          <div>
            <label className="label">Rol</label>
            <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <label className="label">Nombre completo</label>
          <input className="input" value={form.fullName} onChange={(e) => setForm({ ...form, fullName: e.target.value })} required />
        </div>
        <div>
          <label className="label">Contraseña temporal</label>
          <input className="input" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
          <p className="mt-1.5 text-xs text-slate-500">{PW_HINT}</p>
        </div>
        {create.isError && <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{create.error.message}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancelar
          </button>
          <button className="btn-primary" disabled={create.isPending}>
            {create.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Crear
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ResetModal({ user, onClose }: { user: UserDTO | null; onClose: () => void }) {
  const reset = useResetPassword();
  const [pw, setPw] = useState('');
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!user) return;
    reset.mutate(
      { id: user.id, password: pw },
      {
        onSuccess: () => {
          toast.success('Contraseña restablecida; se cerraron sus sesiones');
          setPw('');
          onClose();
        },
      },
    );
  };
  return (
    <Modal open={!!user} onClose={onClose} title={`Restablecer contraseña de ${user?.username ?? ''}`}>
      <form onSubmit={submit} className="space-y-4">
        <input className="input" type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} required placeholder="Nueva contraseña temporal" />
        <p className="text-xs text-slate-500">{PW_HINT}</p>
        {reset.isError && <p className="text-sm text-red-300">{reset.error.message}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancelar
          </button>
          <button className="btn-primary" disabled={reset.isPending}>
            Restablecer
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function UsersPage() {
  const { me } = useSession();
  const users = useUsers();
  const update = useUpdateUser();
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<UserDTO | null>(null);

  const patch = (u: UserDTO, body: { role?: Role; isActive?: boolean }) =>
    update.mutate({ id: u.id, ...body }, { onSuccess: () => toast.success('Usuario actualizado'), onError: (e) => toast.error(e.message) });

  return (
    <>
      <PageHeader
        title="Usuarios"
        subtitle="Administración de cuentas y roles. Cada cambio queda registrado en la auditoría."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)}>
            <UserPlus className="h-4 w-4" /> Nuevo usuario
          </button>
        }
      />
      <div className="mb-6 grid gap-4 md:grid-cols-2">
        {ROLES.map((r) => (
          <div key={r} className="card p-4">
            <p className="font-semibold text-white">{ROLE_LABELS[r]}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {ROLE_PERMISSIONS[r].map((p) => (
                <span key={p} className="rounded bg-ink-700 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
                  {p}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      {users.isLoading ? (
        <Spinner />
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-ink-850 text-left text-xs text-slate-400">
              <tr>
                <th className="px-4 py-3">Usuario</th>
                <th className="px-4 py-3">Rol</th>
                <th className="px-4 py-3">Estado</th>
                <th className="px-4 py-3">Último ingreso</th>
                <th className="px-4 py-3">Creado</th>
                <th className="px-4 py-3 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {users.data?.map((u) => (
                <tr key={u.id} className={u.isActive ? '' : 'opacity-50'}>
                  <td className="px-4 py-3">
                    <p className="font-medium text-slate-100">{u.fullName}</p>
                    <p className="text-xs text-slate-500">@{u.username}</p>
                  </td>
                  <td className="px-4 py-3">
                    <select className="input w-auto py-1 text-xs" value={u.role} disabled={u.id === me.user.id} onChange={(e) => patch(u, { role: e.target.value as Role })}>
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {ROLE_LABELS[r]}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {u.isActive ? <span className="text-emerald-300">Activo</span> : <span className="text-slate-400">Desactivado</span>}
                    {u.mustChangePassword && <span className="ml-2 text-amber-300">· debe cambiar clave</span>}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">{fmtDateTime(u.lastLoginAt)}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{fmtDateTime(u.createdAt)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      <button className="btn-ghost px-2.5 py-1 text-xs" onClick={() => setResetting(u)}>
                        <KeyRound className="h-3.5 w-3.5" /> Clave
                      </button>
                      {u.id !== me.user.id && (
                        <button className={`${u.isActive ? 'btn-danger' : 'btn-ghost'} px-2.5 py-1 text-xs`} onClick={() => patch(u, { isActive: !u.isActive })}>
                          <Power className="h-3.5 w-3.5" /> {u.isActive ? 'Desactivar' : 'Activar'}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateUserModal open={creating} onClose={() => setCreating(false)} />
      <ResetModal user={resetting} onClose={() => setResetting(null)} />
    </>
  );
}
