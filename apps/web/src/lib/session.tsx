import { createContext, useContext, useEffect, type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router';
import { can, type MeDTO, type Permission } from '@soc/shared';
import { useMe } from '../api/hooks';
import { Spinner } from '../components/ui';
import { setTimezone } from './format';

const SessionCtx = createContext<{ me: MeDTO } | null>(null);

export function useSession() {
  const ctx = useContext(SessionCtx);
  if (!ctx) throw new Error('useSession fuera de RequireAuth');
  return ctx;
}

/** Protege rutas: exige sesión, fuerza cambio de clave pendiente y valida permisos */
export function RequireAuth({ children, perm }: { children: ReactNode; perm?: Permission }) {
  const { data, isLoading, isError, refetch } = useMe();
  const location = useLocation();

  useEffect(() => {
    const h = () => void refetch();
    window.addEventListener('soc:unauthorized', h);
    return () => window.removeEventListener('soc:unauthorized', h);
  }, [refetch]);

  useEffect(() => {
    if (data?.timezone) setTimezone(data.timezone);
  }, [data?.timezone]);

  if (isLoading) return <Spinner label="Verificando sesión..." />;
  if (isError || !data) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (data.user.mustChangePassword && location.pathname !== '/change-password') return <Navigate to="/change-password" replace />;
  if (perm && !can(data.user.role, perm)) return <Navigate to="/" replace />;
  return <SessionCtx.Provider value={{ me: data }}>{children}</SessionCtx.Provider>;
}
