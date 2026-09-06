/**
 * DAP (Delivered at Place) — Incoterms 2020 rule, any mode of transport.
 *
 * Risk/payment transfer point: when the goods are placed at the buyer's disposal, ready for
 * unloading, on the arriving means of transport at the named destination — the first of the
 * three "D" (destination) rules, and the first where "C" sits on the buyer's/destination side
 * rather than at origin. In practice "C" is whoever can confirm arrival at that place (a
 * receiving warehouse, a destination terminal operator).
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const ARRIVED_READY_FOR_UNLOADING_CLAIM = 'arrived-ready-for-unloading-confirmed';

export function dapPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'DAP',
    requireClaim(ARRIVED_READY_FOR_UNLOADING_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
