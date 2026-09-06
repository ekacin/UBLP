/**
 * CIF (Cost, Insurance and Freight) — Incoterms 2020 rule, sea/inland waterway transport only.
 *
 * Risk transfer point is identical to FOB/CFR: goods loaded on board at the named port of
 * shipment. CIF adds two cost obligations on top of CFR (freight AND minimum-cover insurance
 * to the destination) that this escrow doesn't model — same reasoning as `cfr.ts`, so this
 * reuses FOB's exact claim rather than defining a new one.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';
import { LOADING_CONFIRMED_CLAIM } from './fob.js';

export function cifPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'CIF',
    requireClaim(LOADING_CONFIRMED_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
