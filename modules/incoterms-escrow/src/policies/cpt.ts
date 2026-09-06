/**
 * CPT (Carriage Paid To) — Incoterms 2020 rule, any mode of transport.
 *
 * Risk transfer point is identical to FCA: goods handed to the first carrier. CPT adds a cost
 * obligation on top of FCA (seller pays carriage to the named destination) that this escrow
 * doesn't model — same reasoning as `cfr.ts` reusing FOB's claim — so this reuses FCA's exact
 * claim rather than defining a new one.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';
import { HANDED_TO_CARRIER_CONFIRMED_CLAIM } from './fca.js';

export function cptPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'CPT',
    requireClaim(HANDED_TO_CARRIER_CONFIRMED_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
