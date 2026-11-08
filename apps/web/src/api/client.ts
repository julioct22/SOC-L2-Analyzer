/** Cliente HTTP mínimo: cookies de sesión, JSON y errores en español */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

type Json = Record<string, unknown> | unknown[];

async function request<T>(method: string, url: string, body?: Json | FormData): Promise<T> {
  const init: RequestInit = { method, credentials: 'same-origin', headers: {} };
  if (body instanceof FormData) init.body = body;
  else if (body !== undefined) {
    init.body = JSON.stringify(body);
    (init.headers as Record<string, string>)['Content-Type'] = 'application/json';
  }
  const res = await fetch(`/api${url}`, init);
  if (res.status === 401 && !url.startsWith('/auth/')) {
    window.dispatchEvent(new Event('soc:unauthorized'));
  }
  const isJson = res.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await res.json() : null;
  if (!res.ok) {
    const details = data?.details;
    const detailMsg = Array.isArray(details) ? details.map((d: { path?: string; message?: string }) => `${d.path ? `${d.path}: ` : ''}${d.message}`).join(' · ') : '';
    throw new ApiError(res.status, [data?.error ?? `Error ${res.status}`, detailMsg].filter(Boolean).join(' — '), details);
  }
  return data as T;
}

export const api = {
  get: <T>(url: string) => request<T>('GET', url),
  post: <T>(url: string, body?: Json | FormData) => request<T>('POST', url, body ?? {}),
  patch: <T>(url: string, body: Json) => request<T>('PATCH', url, body),
};

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}
