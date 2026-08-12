/**
 * Generic Attestation — atomic, single claim. See AGENTS.md Section 3.4.
 *
 * "Layered verification" (a module wanting another module's attestation plus its own extra
 * checks) is NOT solved by nesting structure inside Attestation itself — it's solved by the
 * consuming module's AttestationPolicy requiring multiple Attestations (see policy.ts).
 */

import type { ShipmentId, UBLPDid } from '../identity/did';

/** The claim type a module defines — e.g. "loading-confirmed", "customs-cleared". */
export type ClaimType = string;

export interface Attestation {
  subjectId: ShipmentId;
  claimType: ClaimType;
  /** Signature/ZK proof/Merkle proof reference — module-specific format, opaque to the evaluator. */
  proofRef: string;
  issuerSet: UBLPDid[];
  /** Required signature count (t-of-n). issuerSet.length alone isn't enough — signer identity must match too. */
  threshold: number;
  timestamp: number;
}

/**
 * Signature for the function responsible for an attestation's cryptographic verification.
 * Each claimType may have its own verification logic (BLS threshold, plain ECDSA, etc.) —
 * so the evaluator (verify.ts) takes this as a dependency rather than hardcoding it.
 */
export type AttestationVerifier = (attestation: Attestation) => Promise<boolean>;
