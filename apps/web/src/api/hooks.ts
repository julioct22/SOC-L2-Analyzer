import { useMutation, useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import type {
  AnalysisDTO,
  AnalysisListItem,
  AuditEntryDTO,
  FindingStatus,
  LogEventDTO,
  MeDTO,
  Paged,
  ReportDTO,
  Role,
  Severity,
  UploadDTO,
  UserDTO,
} from '@soc/shared';
import { api, qs } from './client';

// ───── Sesión ─────
export const useMe = () => useQuery({ queryKey: ['me'], queryFn: () => api.get<MeDTO>('/auth/me'), retry: false, staleTime: 60_000 });

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { username: string; password: string }) => api.post<{ user: UserDTO }>('/auth/login', b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me'] }),
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post('/auth/logout'),
    onSettled: () => {
      qc.clear();
      window.location.href = '/login';
    },
  });
}

export function useChangePassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { currentPassword: string; newPassword: string }) => api.post('/auth/change-password', b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me'] }),
  });
}

// ───── Cargas ─────
export const useUploadsByDay = (date: string) =>
  useQuery({ queryKey: ['uploads', 'day', date], queryFn: () => api.get<UploadDTO[]>(`/uploads${qs({ date })}`) });

export const useUploadDays = (month: string) =>
  useQuery({ queryKey: ['uploads', 'days', month], queryFn: () => api.get<{ day: string; count: number }[]>(`/uploads/days${qs({ month })}`) });

export const useRecentUploads = () => useQuery({ queryKey: ['uploads', 'recent'], queryFn: () => api.get<UploadDTO[]>('/uploads/recent') });

export const useUpload = (id: string) => useQuery({ queryKey: ['uploads', id], queryFn: () => api.get<UploadDTO>(`/uploads/${id}`) });

export function useUploadFile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append('file', file);
      return api.post<{ upload: UploadDTO; missingColumns: string[] }>('/uploads', fd);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['uploads'] }),
  });
}

export interface EventFilters {
  page: number;
  pageSize: number;
  q?: string;
  hostname?: string;
  eventId?: string;
  logSource?: string;
  severitySrc?: string;
  analysisId?: string;
  findingId?: string;
}

export const useEvents = (uploadId: string, f: EventFilters) =>
  useQuery({
    queryKey: ['events', uploadId, f],
    queryFn: () => api.get<Paged<LogEventDTO>>(`/uploads/${uploadId}/events${qs({ ...f })}`),
    placeholderData: keepPreviousData,
  });

export const useFacets = (uploadId: string) =>
  useQuery({
    queryKey: ['facets', uploadId],
    queryFn: () => api.get<{ hostname: string[]; eventId: string[]; logSource: string[]; severitySrc: string[] }>(`/uploads/${uploadId}/facets`),
    staleTime: Infinity,
  });

// ───── Análisis ─────
export const useAnalyses = (uploadId?: string) =>
  useQuery({ queryKey: ['analyses', uploadId ?? 'recent'], queryFn: () => api.get<AnalysisListItem[]>(`/analyses${qs({ uploadId })}`) });

export const useAnalysis = (id: string) =>
  useQuery({
    queryKey: ['analysis', id],
    queryFn: () => api.get<AnalysisDTO>(`/analyses/${id}`),
    // Mientras la IA redacta, se consulta cada 4 s
    refetchInterval: (q) => (q.state.data?.aiStatus === 'pending' ? 4000 : false),
  });

export function useRunAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uploadId: string) => api.post<AnalysisDTO>(`/uploads/${uploadId}/analyses`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analyses'] });
      qc.invalidateQueries({ queryKey: ['uploads'] });
    },
  });
}

export function useRetryAi(analysisId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post(`/analyses/${analysisId}/ai`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['analysis', analysisId] }),
  });
}

export function useReviewFinding(analysisId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; status?: FindingStatus; severityOverride?: Severity | null; analystNotes?: string | null }) =>
      api.patch(`/findings/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analysis', analysisId] });
      qc.invalidateQueries({ queryKey: ['analyses'] });
    },
  });
}

export const useReports = (analysisId: string) =>
  useQuery({ queryKey: ['reports', analysisId], queryFn: () => api.get<ReportDTO[]>(`/analyses/${analysisId}/reports`) });

export function useGenerateReport(analysisId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { includePending: boolean; format: 'summary' | 'full' }) => api.post<ReportDTO>(`/analyses/${analysisId}/reports`, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports', analysisId] }),
  });
}

export const useDashboard = () =>
  useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<{ uploadsCount: number; analysesCount: number; findings: { severity: Severity; status: FindingStatus; count: number }[] }>('/dashboard'),
  });

// ───── Administración ─────
export const useUsers = () => useQuery({ queryKey: ['users'], queryFn: () => api.get<UserDTO[]>('/users') });

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { username: string; fullName: string; role: Role; password: string }) => api.post<UserDTO>('/users', b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...b }: { id: string; fullName?: string; role?: Role; isActive?: boolean }) => api.patch<UserDTO>(`/users/${id}`, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}

export function useResetPassword() {
  return useMutation({ mutationFn: ({ id, password }: { id: string; password: string }) => api.post(`/users/${id}/reset-password`, { password }) });
}

export const useAudit = (f: { page: number; pageSize: number; q?: string; action?: string }) =>
  useQuery({
    queryKey: ['audit', f],
    queryFn: () => api.get<Paged<AuditEntryDTO>>(`/audit${qs(f)}`),
    placeholderData: keepPreviousData,
  });

export const useAuditActions = () => useQuery({ queryKey: ['audit-actions'], queryFn: () => api.get<string[]>('/audit/actions') });
