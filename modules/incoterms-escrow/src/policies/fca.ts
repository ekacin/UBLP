/**
 * FCA (Free Carrier) — Incoterms 2020 rule, any mode of transport.
 *
 * Risk/payment transfer point: when the goods are handed over to the carrier (or another
 * person) nominated by the buyer, at the seller's premises or another named place — not tied
 * to sea transport, unlike FOB/FAS/CFR/CIF. "C" here is typically that carrier or a terminal
 * operator at the named place, rather than a port authority; the escrow's own contract call
 * doesn't care which real-world role plays "C", only that the DID/key committed at propose
 * time matches whoever calls the attest circuit.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const HANDED_TO_CARRIER_CONFIRMED_CLAIM = 'handed-to-carrier-confirmed';

export function fcaPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'FCA',
    requireClaim(HANDED_TO_CARRIER_CONFIRMED_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
