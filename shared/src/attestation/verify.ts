/**
 * STATELESS AttestationPolicy evaluator. See AGENTS.md Section 3.6 — CRITICAL PRINCIPLE.
 *
 * The evaluator is "dumb": the client/Agent gathers ALL required attestations into a single
 * bundle and presents it. The evaluator only checks "are they all there? are the signatures
 * valid? is the policy satisfied?" It NEVER goes looking for a missing attestation on its
 * own / does a retroactive lookup — in a smart contract that leads to unpredictable gas
 * cost and a DoS vector (see AGENTS.md 3.6 for the full rationale).
 */

import type { Attestation, AttestationVerifier, ClaimType } from './types';
import type { AttestationPolicy, PolicyNode, RequiredClaim } from './policy';

export interface PolicyEvaluationResult {
  satisfied: boolean;
  /** Why each failing node failed — for debugging / dispute resolution. */
  reasons: string[];
}

function findMatchingAttestations(
  bundle: readonly Attestation[],
  claimType: ClaimType
): Attestation[] {
  return bundle.filter((a) => a.claimType === claimType);
}

async function evaluateClaim(
  claim: RequiredClaim,
  bundle: readonly Attestation[],
  verifyAttestation: AttestationVerifier
): Promise<{ ok: boolean; reason?: string }> {
  const candidates = findMatchingAttestations(bundle, claim.claimType);
  if (candidates.length === 0) {
    return { ok: false, reason: `No attestation for claim "${claim.claimType}" in the bundle.` };
  }

  const threshold = claim.threshold ?? 1;

  for (const attestation of candidates) {
    if (attestation.issuerSet.length < threshold) {
      continue;
    }
    if (claim.requiredIssuers && claim.requiredIssuers.length > 0) {
      const allowed = new Set(claim.requiredIssuers);
      const hasUnauthorizedIssuer = attestation.issuerSet.some((did) => !allowed.has(did));
      if (hasUnauthorizedIssuer) {
        continue;
      }
    }
    const valid = await verifyAttestation(attestation);
    if (valid) {
      return { ok: true };
    }
  }

  return {
    ok: false,
    reason: `Found ${candidates.length} attestation(s) for "${claim.claimType}" but none satisfied ` +
      `the threshold/authorized-issuer/cryptographic-validity requirements.`,
  };
}

async function evaluateNode(
  node: PolicyNode,
  bundle: readonly Attestation[],
  verifyAttestation: AttestationVerifier
): Promise<{ ok: boolean; reasons: string[] }> {
  switch (node.kind) {
    case 'claim': {
      const result = await evaluateClaim(node.claim, bundle, verifyAttestation);
      return { ok: result.ok, reasons: result.reason ? [result.reason] : [] };
    }
    case 'and': {
      const results = await Promise.all(node.nodes.map((n) => evaluateNode(n, bundle, verifyAttestation)));
      const ok = results.every((r) => r.ok);
      return { ok, reasons: results.flatMap((r) => r.reasons) };
    }
    case 'or': {
      const results = await Promise.all(node.nodes.map((n) => evaluateNode(n, bundle, verifyAttestation)));
      const ok = results.some((r) => r.ok);
      return { ok, reasons: ok ? [] : results.flatMap((r) => r.reasons) };
    }
  }
}

/**
 * Evaluates an AttestationPolicy against a pre-gathered attestation bundle.
 * `verifyAttestation` is a module-specific function that checks each candidate's
 * cryptographic validity (signature/ZK proof/Merkle proof) — the evaluator doesn't know
 * or care how it works internally.
 */
export async function evaluatePolicy(
  policy: AttestationPolicy,
  bundle: readonly Attestation[],
  verifyAttestation: AttestationVerifier
): Promise<PolicyEvaluationResult> {
  const { ok, reasons } = await evaluateNode(policy.root, bundle, verifyAttestation);
  return { satisfied: ok, reasons };
}
