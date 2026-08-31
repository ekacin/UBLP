import type { DealStatus, EscrowProposal, LockDealParams, PendingAction, ProposeDealParams, WhoAmI } from './types';
import { getActiveBaseUrl } from './agentInstances';

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
  }
}

// Read fresh on every call, not cached at module load — the active instance can change at
// runtime via the header's instance switcher (agentInstances.ts), unlike a build-time constant.
async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const baseUrl = getActiveBaseUrl();
  const token = sessionStore.getToken(baseUrl);
  const res = await fetch(`${baseUrl}${path}`, {
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

// ---- session storage (AGENTS.md 5.26 login model) — only the session token is ever stored;
// the operator's private key stays in their wallet extension and never touches this code.
// Keyed by baseUrl: each agent instance issues its own independent session (server/auth.ts's
// AuthStore is per-process, in-memory), so switching instances must not reuse one instance's
// token against another's. ----
function tokenKey(baseUrl: string): string {
  return `ublp_session_token::${baseUrl}`;
}
function expiresKey(baseUrl: string): string {
  return `ublp_session_expires_at::${baseUrl}`;
}

export const sessionStore = {
  getToken(baseUrl: string = getActiveBaseUrl()): string | null {
    const expiresAt = Number(localStorage.getItem(expiresKey(baseUrl)) ?? 0);
    if (Date.now() > expiresAt) return null;
    return localStorage.getItem(tokenKey(baseUrl));
  },
  setSession(token: string, expiresAt: number, baseUrl: string = getActiveBaseUrl()): void {
    localStorage.setItem(tokenKey(baseUrl), token);
    localStorage.setItem(expiresKey(baseUrl), String(expiresAt));
  },
  clearSession(baseUrl: string = getActiveBaseUrl()): void {
    localStorage.removeItem(tokenKey(baseUrl));
    localStorage.removeItem(expiresKey(baseUrl));
  },
};

// ---- auth (AGENTS.md 5.26 flow, steps 1-4) ----
export function issueChallenge(): Promise<{ challengeId: string; nonceHex: string; expiresAt: number }> {
  return request('/auth/challenge', { method: 'POST' });
}

export function verifyChallenge(
  challengeId: string,
  signature: string,
  signedDataHex: string,
  verifyingKey: string
): Promise<{ sessionToken: string; expiresAt: number }> {
  return request('/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ challengeId, signature, signedDataHex, verifyingKey }),
  });
}

// ---- this agent's fixed identity — determines which dashboard the panel renders ----
export function whoAmI(): Promise<WhoAmI> {
  return request('/identity/whoami');
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

// ---- originating new pending actions — the two ways a fresh propose/lockEscrow enters the
// queue (AGENTS.md 5.21: still needs a human's separate /approve before anything touches the
// chain, same gate as everything else in this queue) ----
export function proposeDeal(params: ProposeDealParams): Promise<PendingAction> {
  return request('/deals/propose', { method: 'POST', body: JSON.stringify(params) });
}

export function lockDeal(params: LockDealParams): Promise<PendingAction> {
  return request('/deals/lock', { method: 'POST', body: JSON.stringify(params) });
}

/** Fetches a counterparty's own public identity from THEIR agent (a different base URL, a
 * different company, no auth — these are the two intentionally-public identity endpoints,
 * AGENTS.md 5.12/5.18) — a convenience so an operator doesn't have to copy-paste a hex string
 * (or, worse, hand-type a DID that has to match that agent's real one exactly) from an
 * email/chat. Returns the DID alongside the hex — a mistyped DID is exactly the kind of
 * transcription error this endpoint exists to avoid in the first place, same as the hex
 * itself. Never used for anything but these two read-only GETs. */
export async function fetchCounterpartyIdentity(
  agentBaseUrl: string,
  which: 'port-authority-key-hash' | 'memo-public-key'
): Promise<{ hex: string; did: string }> {
  const res = await fetch(`${agentBaseUrl.replace(/\/$/, '')}/identity/${which}`);
  const text = await res.text();
  const json = text ? JSON.parse(text) : undefined;
  if (!res.ok) throw new ApiError(res.status, json?.error ?? `${res.status}`);
  const hex = which === 'port-authority-key-hash' ? json.portAuthorityKeyHashHex : json.memoPublicKeyHex;
  return { hex, did: json.did };
}

// ---- immediate actions, no approval gate (AGENTS.md 5.21 — attest/claim/release-timeout
// carry no financial-commitment risk the way propose/lockEscrow do, see routes.ts's header) ----
export function attestDeal(contractAddress: string): Promise<{ txId: string }> {
  return request(`/deals/${encodeURIComponent(contractAddress)}/attest`, { method: 'POST' });
}

export function claimDeal(contractAddress: string): Promise<{ txId: string }> {
  return request(`/deals/${encodeURIComponent(contractAddress)}/claim`, { method: 'POST' });
}

export function releaseTimeoutDeal(contractAddress: string): Promise<{ txId: string }> {
  return request(`/deals/${encodeURIComponent(contractAddress)}/release-timeout`, { method: 'POST' });
}

export function parseEscrowProposal(raw: string): EscrowProposal {
  const parsed = JSON.parse(raw);
  if (!parsed?.terms || typeof parsed.sellerSignature !== 'string' || typeof parsed.sellerPublicKey !== 'string') {
    throw new Error('This does not look like a signed EscrowTerms proposal (missing terms/sellerSignature/sellerPublicKey).');
  }
  return parsed as EscrowProposal;
}
