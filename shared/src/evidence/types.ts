/**
 * EvidenceLog — generic, append-only, NON-gating evidence primitive. See AGENTS.md Section 5.16/5.17.
 *
 * Not to be confused with Attestation/AttestationPolicy (../attestation): an Attestation
 * TRIGGERS payment (gating), an EvidenceEntry never does — it exists purely for record-
 * keeping / audit / dispute resolution (the generalization of the "Layer 2" concept from
 * Section 5.4). Examples: an insurance-status flag, single-party handover photos.
 */

import type { ShipmentId, UBLPDid } from '../identity/did';

/** The evidence type a module defines — e.g. "insurance-status", "handover-photo-solo". */
export type EvidenceType = string;

export interface EvidenceEntry {
  subjectId: ShipmentId;
  evidenceType: EvidenceType;
  /** Serialized value or hash reference — format is a module decision per evidenceType. */
  value: string;
  submitterDid: UBLPDid;
  /**
   * On-chain anchor time (block-time) — NOT self-reported. See AGENTS.md 5.15: an
   * ordering/history guarantee only holds if it's backed by a time source that can't be forged.
   */
  anchoredAt: number;
}

/**
 * Module-specific function that checks whether an entry is authorized to be submitted.
 * Example: for "insurance-status", only the escrow's `insuranceResponsibleParty` DID is
 * authorized — this rule isn't hardcoded into EvidenceLog, the calling module supplies it
 * (same pattern as AttestationVerifier, see ../attestation/types.ts).
 */
export type EvidenceAuthorizer = (entry: EvidenceEntry) => boolean | Promise<boolean>;
