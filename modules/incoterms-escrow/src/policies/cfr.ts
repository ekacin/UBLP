/**
 * CFR (Cost and Freight) — Incoterms 2020 rule, sea/inland waterway transport only.
 *
 * Risk transfer point is identical to FOB: when the goods are loaded on board the vessel at
 * the named port of shipment. The only difference from FOB is a cost allocation — the seller
 * additionally pays the freight to the named destination port — which this escrow doesn't
 * model at all (it only custodies a single agreed amount, see AGENTS.md 5.16). CFR therefore
 * reuses FOB's exact claim rather than defining a new one: the milestone being attested is
 * genuinely the same event.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';
import { LOADING_CONFIRMED_CLAIM } from './fob.js';

export function cfrPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'CFR',
    requireClaim(LOADING_CONFIRMED_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
