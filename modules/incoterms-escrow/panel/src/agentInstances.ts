/**
 * A single browser session can manage more than one deployed agent instance — the same
 * company is very often both a buyer (raw materials in) and a seller (value-added goods out)
 * across different deals, and AGENTS.md 5.27 already models that as two separate
 * frontend+backend pairs (one per role), not one "universal" role. This is purely a connection
 * manager for switching between those pairs in one browser tab — no backend/contract change,
 * since a seller identity and a buyer identity are cryptographically distinct anyway (see
 * identity.ts's roleSecretKeyHex doc comment).
 */

export interface AgentInstance {
  baseUrl: string;
  label: string;
  /** Cached from the last successful /identity/whoami fetch, purely for display in the
   * switcher before you've switched to (and logged into) an instance. */
  role?: string;
}

const INSTANCES_KEY = 'ublp_agent_instances';
const ACTIVE_KEY = 'ublp_active_agent_base_url';
const DEFAULT_BASE_URL = (import.meta.env.VITE_AGENT_BASE_URL as string | undefined) ?? 'http://127.0.0.1:4100';

function normalize(baseUrl: string): string {
  return baseUrl.trim().replace(/\/$/, '');
}

export function listInstances(): AgentInstance[] {
  try {
    const raw = localStorage.getItem(INSTANCES_KEY);
    const parsed = raw ? (JSON.parse(raw) as AgentInstance[]) : [];
    if (parsed.length > 0) return parsed;
  } catch {
    // fall through to the seeded default below
  }
  // First-ever load: seed with the build-time default so the switcher is never empty.
  const seeded = [{ baseUrl: DEFAULT_BASE_URL, label: 'This agent' }];
  localStorage.setItem(INSTANCES_KEY, JSON.stringify(seeded));
  return seeded;
}

function saveInstances(list: AgentInstance[]): void {
  localStorage.setItem(INSTANCES_KEY, JSON.stringify(list));
}

export function addInstance(baseUrl: string, label: string): void {
  const url = normalize(baseUrl);
  const list = listInstances();
  const existing = list.find((i) => i.baseUrl === url);
  if (existing) {
    existing.label = label || existing.label;
  } else {
    list.push({ baseUrl: url, label: label || url });
  }
  saveInstances(list);
}

export function removeInstance(baseUrl: string): void {
  saveInstances(listInstances().filter((i) => i.baseUrl !== baseUrl));
}

export function updateInstanceRole(baseUrl: string, role: string): void {
  const list = listInstances();
  const existing = list.find((i) => i.baseUrl === baseUrl);
  if (existing && existing.role !== role) {
    existing.role = role;
    saveInstances(list);
  }
}

export function getActiveBaseUrl(): string {
  return normalize(localStorage.getItem(ACTIVE_KEY) ?? DEFAULT_BASE_URL);
}

export function setActiveBaseUrl(baseUrl: string): void {
  localStorage.setItem(ACTIVE_KEY, normalize(baseUrl));
}
