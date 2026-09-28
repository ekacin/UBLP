// Adapted from incoterms-escrow/panel/src/api.ts's request()/ApiError/sessionStore — same
// shape, but the base URL is fixed per deployment (VITE_AGENT_BASE_URL) instead of runtime-
// switchable, since this panel always talks to exactly one backend (whichever
// VITE_SERVICE_ROLE it was built for), not several instances of the same role.

export const BASE_URL = import.meta.env.VITE_AGENT_BASE_URL;

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
  }
}

export async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = sessionStore.getToken();
  const res = await fetch(`${BASE_URL}${path}`, {
    ...opts,
    headers: {
      ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...opts.headers,
    },
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : undefined;
  if (!res.ok) throw new ApiError(res.status, json?.message ?? json?.error ?? `${res.status}`);
  return json as T;
}

// Only the session token is ever stored — same as escrow's panel, one localStorage slot since
// there's only ever one backend this deployment talks to.
const TOKEN_KEY = 'ublp_zk_customs_session_token';
const EXPIRES_KEY = 'ublp_zk_customs_session_expires_at';

export const sessionStore = {
  getToken(): string | null {
    const expiresAt = Number(localStorage.getItem(EXPIRES_KEY) ?? 0);
    if (Date.now() > expiresAt) return null;
    return localStorage.getItem(TOKEN_KEY);
  },
  setSession(token: string, expiresAt: number): void {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(EXPIRES_KEY, String(expiresAt));
  },
  clearSession(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(EXPIRES_KEY);
  },
};

export function login(passphrase: string): Promise<{ sessionToken: string; expiresAt: number }> {
  return request('/auth/login', { method: 'POST', body: JSON.stringify({ passphrase }) });
}
