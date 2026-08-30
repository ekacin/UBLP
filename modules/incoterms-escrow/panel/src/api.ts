import type { DealStatus, PendingAction } from './types';

const BASE_URL = import.meta.env.VITE_AGENT_BASE_URL ?? 'http://127.0.0.1:4100';

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
  }
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
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

// ---- session storage (AGENTS.md 5.26 login model — see src/crypto/loginSign.ts for why the
// private key round-trips through localStorage in this v0.1 panel) ----
const LS_PEM = 'ublp_login_private_key_pem';
const LS_TOKEN = 'ublp_session_token';
const LS_EXPIRES = 'ublp_session_expires_at';

export const sessionStore = {
  getStoredPem(): string | null {
    return localStorage.getItem(LS_PEM);
  },
  setStoredPem(pem: string): void {
    localStorage.setItem(LS_PEM, pem);
  },
  clearStoredPem(): void {
    localStorage.removeItem(LS_PEM);
  },
  getToken(): string | null {
    const expiresAt = Number(localStorage.getItem(LS_EXPIRES) ?? 0);
    if (Date.now() > expiresAt) return null;
    return localStorage.getItem(LS_TOKEN);
  },
  setSession(token: string, expiresAt: number): void {
    localStorage.setItem(LS_TOKEN, token);
    localStorage.setItem(LS_EXPIRES, String(expiresAt));
  },
  clearSession(): void {
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_EXPIRES);
  },
};

// ---- auth (AGENTS.md 5.26 flow, steps 1-4) ----
export function issueChallenge(): Promise<{ challengeId: string; nonceHex: string; expiresAt: number }> {
  return request('/auth/challenge', { method: 'POST' });
}

export function verifyChallenge(
  challengeId: string,
  signature: string
): Promise<{ sessionToken: string; expiresAt: number }> {
  return request('/auth/verify', { method: 'POST', body: JSON.stringify({ challengeId, signature }) });
}

// ---- pending-approval queue ----
export function listPending(dealRef?: string): Promise<PendingAction[]> {
  const qs = dealRef ? `?dealRef=${encodeURIComponent(dealRef)}` : '';
  return request(`/deals/pending${qs}`);
}

export function approvePending(id: number): Promise<PendingAction & { txId?: string }> {
  return request(`/deals/pending/${id}/approve`, { method: 'POST' });
}

export function rejectPending(id: number): Promise<PendingAction> {
  return request(`/deals/pending/${id}/reject`, { method: 'POST' });
}

// ---- deal status — convenience passthrough only, not the source of truth (AGENTS.md 5.28);
// pair with indexerWatch.ts's subscription for "when to refetch" ----
export async function getDealStatus(contractAddress: string): Promise<DealStatus | null> {
  try {
    return await request<DealStatus>(`/deals/${encodeURIComponent(contractAddress)}/status`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}
