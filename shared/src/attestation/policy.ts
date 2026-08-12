/**
 * AttestationPolicy — a generic rule set combining multiple Attestations via AND/OR/
 * threshold logic. See AGENTS.md Section 3.5.
 *
 * The same evaluator (verify.ts) runs different rule sets across different modules —
 * one evaluator, rules as configuration.
 *
 * Example — FOB Policy:
 *   requireClaim('loading-confirmed', { threshold: 2 })
 *
 * Example — DDP Policy:
 *   and(
 *     requireClaim('loading-confirmed'),
 *     requireClaim('customs-cleared'),
 *   )
 *
 * Example — Module 4 escrow's per-shipment scoping for "C" (the loading-confirmation
 * authority, see AGENTS.md Section 5.12): requiredIssuers carries the single DID locked in
 * when the escrow was created — not a global registry, a per-shipment agreed party.
 */

import type { ClaimType } from './types';
import type { UBLPDid } from '../identity/did';

export interface RequiredClaim {
  claimType: ClaimType;
  /** t-of-n threshold. Defaults to 1 (a single signature suffices) if unset. */
  threshold?: number;
  /**
   * Only these DIDs are authorized to make this claim (e.g. an escrow-specific C).
   * If unset, any issuer is accepted (the evaluator only checks cryptographic
   * validity and the threshold).
   */
  requiredIssuers?: UBLPDid[];
}

export type PolicyNode =
  | { kind: 'claim'; claim: RequiredClaim }
  | { kind: 'and'; nodes: PolicyNode[] }
  | { kind: 'or'; nodes: PolicyNode[] };

export interface AttestationPolicy {
  name: string;
  root: PolicyNode;
}

export function requireClaim(claimType: ClaimType, opts?: Omit<RequiredClaim, 'claimType'>): PolicyNode {
  return { kind: 'claim', claim: { claimType, threshold: opts?.threshold ?? 1, requiredIssuers: opts?.requiredIssuers } };
}

export function and(...nodes: PolicyNode[]): PolicyNode {
  return { kind: 'and', nodes };
}

export function or(...nodes: PolicyNode[]): PolicyNode {
  return { kind: 'or', nodes };
}

export function definePolicy(name: string, root: PolicyNode): AttestationPolicy {
  return { name, root };
}
