/**
 * EXW (Ex Works) — Incoterms 2020 rule, any mode of transport. The seller's minimum-
 * responsibility rule.
 *
 * Risk/payment transfer point: when the goods are placed at the buyer's disposal at the
 * seller's own premises (or another named place) — the seller does not load them or arrange
 * carriage. Unlike FOB/FAS/FCA/CPT/CIP (an independent terminal/carrier) or DAP/DPU/DDP (a
 * destination-side warehouse), EXW has no natural independent third party at the transfer
 * point: "C" here is realistically the buyer's own nominated carrier, picking up from the
 * seller's premises. That's a different trust shape than the other rules — the attesting
 * party is aligned with the buyer, not neutral — so choose who plays "C" deliberately for an
 * EXW deal rather than defaulting to whatever DID played "C" in a previous FOB/FCA deal.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const GOODS_MADE_AVAILABLE_CLAIM = 'goods-made-available-confirmed';

export function exwPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'EXW',
    requireClaim(GOODS_MADE_AVAILABLE_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
