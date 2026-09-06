/**
 * CIP (Carriage and Insurance Paid To) — Incoterms 2020 rule, any mode of transport.
 *
 * Risk transfer point is identical to FCA/CPT: goods handed to the first carrier. CIP adds
 * carriage AND a higher minimum-cover insurance obligation on top of CPT — neither modeled by
 * this escrow — so this reuses FCA's exact claim rather than defining a new one.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';
import { HANDED_TO_CARRIER_CONFIRMED_CLAIM } from './fca.js';

export function cipPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'CIP',
    requireClaim(HANDED_TO_CARRIER_CONFIRMED_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
