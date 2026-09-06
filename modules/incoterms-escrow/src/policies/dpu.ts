/**
 * DPU (Delivered at Place Unloaded) — Incoterms 2020 rule, any mode of transport.
 *
 * Risk/payment transfer point: when the goods are unloaded from the arriving means of
 * transport at the named destination — one step later than DAP, and the only Incoterms 2020
 * rule that requires the seller to unload. "C" is whoever at the destination can confirm the
 * unloading actually happened (a receiving warehouse, a destination terminal operator).
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const UNLOADED_AT_DESTINATION_CLAIM = 'unloaded-at-destination-confirmed';

export function dpuPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'DPU',
    requireClaim(UNLOADED_AT_DESTINATION_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
