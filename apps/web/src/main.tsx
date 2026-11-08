import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import './index.css';
import { RequireAuth } from './lib/session';
import { Layout } from './components/Layout';
import { LoginPage } from './pages/Login';
import { ChangePasswordPage } from './pages/ChangePassword';
import { DashboardPage } from './pages/Dashboard';
import { UploadsPage } from './pages/Uploads';
import { UploadDetailPage } from './pages/UploadDetail';
import { AnalysisPage } from './pages/Analysis';
import { UsersPage } from './pages/admin/Users';
import { AuditPage } from './pages/admin/Audit';

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: (count, err) => count < 1 && (err as { status?: number }).status !== 401 } },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/change-password"
            element={
              <RequireAuth>
                <ChangePasswordPage />
              </RequireAuth>
            }
          />
          <Route
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="uploads" element={<UploadsPage />} />
            <Route path="uploads/:id" element={<UploadDetailPage />} />
            <Route path="analyses/:id" element={<AnalysisPage />} />
            <Route
              path="admin/users"
              element={
                <RequireAuth perm="users:manage">
                  <UsersPage />
                </RequireAuth>
              }
            />
            <Route
              path="admin/audit"
              element={
                <RequireAuth perm="audit:read">
                  <AuditPage />
                </RequireAuth>
              }
            />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster theme="dark" richColors position="top-right" />
    </QueryClientProvider>
  </StrictMode>,
);
