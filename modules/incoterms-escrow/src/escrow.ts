/**
 * Escrow data model + propose/accept flow. See AGENTS.md Section 5.12.
 *
 * This layer stays chain-agnostic on purpose — the actual on-chain lock/release logic lives
 * in `contracts/Escrow.compact` (see Section 5.14.1). This file only prepares the
 * propose/accept step's data/signature, independent of the contract call layer.
 */

import { sha256Hash, signDocument, verifySignature } from '@ublp/shared';
import type { ShipmentId, UBLPDid } from '@ublp/shared';

/**
 * v0.1 implements FOB only (see AGENTS.md 5.2 — incremental build order). The other 10
 * rules will extend this union later.
 */
export type IncotermRule = 'FOB';

export interface EscrowTerms {
  shipmentId: ShipmentId;
  sellerDid: UBLPDid;
  buyerDid: UBLPDid;
  /** "C" — Section 5.12, the shipment-specific loading-confirmation authority. */
  portAuthorityDid: UBLPDid;
  /** Section 5.16 — insurance-responsible party; may be left unset for rules that don't require it (FOB). */
  insuranceResponsibleParty?: UBLPDid;
  incoterm: IncotermRule;
  /** Amount to lock, as an integer string in the smallest unit (e.g. "1000000") — a string
   * rather than a bigint because canonicalJson/JSON.stringify can't serialize bigint. */
  amount: string;
  /** Section 7.2 — if point (c) isn't confirmed / a dispute drags on past this time, the
   * auto-release timeout fires (7 days, unix seconds). */
  deadlineTimestamp: number;
}

export interface EscrowProposal {
  terms: EscrowTerms;
  /** Proof that the seller signed off on the terms — Section 5.12 step 1 ("create the offer"). */
  sellerSignature: string;
  sellerPublicKey: string;
}

export type EscrowStatus = 'proposed' | 'accepted';

export interface EscrowState {
  proposal: EscrowProposal;
  status: EscrowStatus;
}

function termsIdHash(terms: EscrowTerms): string {
  return sha256Hash(terms.shipmentId);
}

/**
 * Seller — "create the offer" (Section 5.12, step 1). Signs the terms with its own key.
 * This does not write to any chain — the signed object is later passed as a parameter to
 * the contract's `propose` circuit.
 */
export function proposeEscrow(
  terms: EscrowTerms,
  sellerPrivateKey: string,
  sellerPublicKey: string
): EscrowProposal {
  const idHash = termsIdHash(terms);
  const sellerSignature = signDocument(terms as unknown as Record<string, unknown>, sellerPrivateKey, idHash);
  return { terms, sellerSignature, sellerPublicKey };
}

/** Verifies the seller's signature — proves the offer really came from that seller. */
export function verifyProposal(proposal: EscrowProposal): boolean {
  const idHash = termsIdHash(proposal.terms);
  return verifySignature(
    proposal.terms as unknown as Record<string, unknown>,
    proposal.sellerSignature,
    proposal.sellerPublicKey,
    idHash
  );
}

/**
 * Buyer — "lock the funds" (Section 5.12, step 2). Verifies the offer's signature and
 * accepts it. The actual on-chain lock happens via the contract's `lockEscrow` circuit —
 * this function only models the "buyer accepted these terms" transition.
 */
export function acceptEscrow(proposal: EscrowProposal, acceptingBuyerDid: UBLPDid): EscrowState {
  if (!verifyProposal(proposal)) {
    throw new Error('Invalid proposal signature — not signed by the seller.');
  }
  if (proposal.terms.buyerDid !== acceptingBuyerDid) {
    throw new Error('This proposal is not addressed to this buyer.');
  }
  if (BigInt(proposal.terms.amount) <= 0n) {
    throw new Error('The locked amount must be positive.');
  }
  return { proposal, status: 'accepted' };
}
