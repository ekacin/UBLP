/**
 * Append-only EvidenceLog operations. See types.ts and AGENTS.md Section 5.16/5.17.
 *
 * No function ever mutates or removes a prior entry — only appends. This prevents a party
 * from hiding history at dispute time and showing only "what it currently says" (see
 * AGENTS.md 5.16's "storing only the latest value is a risk" finding).
 */

import type { ShipmentId } from '../identity/did';
import type { EvidenceAuthorizer, EvidenceEntry, EvidenceType } from './types';

/** Appends to the log if authorization passes. The caller must persist the returned array. */
export async function appendEvidence(
  log: readonly EvidenceEntry[],
  entry: EvidenceEntry,
  authorize: EvidenceAuthorizer
): Promise<EvidenceEntry[]> {
  const authorized = await authorize(entry);
  if (!authorized) {
    throw new Error(
      `Unauthorized evidence submission: ${entry.submitterDid} -> "${entry.evidenceType}" (${entry.subjectId})`
    );
  }
  return [...log, entry];
}

/** Full, time-ordered history for a shipment + type — for dispute resolution / audit. */
export function historyByType(
  log: readonly EvidenceEntry[],
  subjectId: ShipmentId,
  evidenceType: EvidenceType
): EvidenceEntry[] {
  return log
    .filter((e) => e.subjectId === subjectId && e.evidenceType === evidenceType)
    .sort((a, b) => a.anchoredAt - b.anchoredAt);
}

/**
 * Current/effective value — the most recently anchored entry. Must NEVER be used to gate
 * a payment release (EvidenceLog is non-gating by design) — display/informational use only.
 */
export function latestByType(
  log: readonly EvidenceEntry[],
  subjectId: ShipmentId,
  evidenceType: EvidenceType
): EvidenceEntry | undefined {
  const history = historyByType(log, subjectId, evidenceType);
  return history[history.length - 1];
}
