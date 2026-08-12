/**
 * FOB (Free on Board) — Incoterms 2020 rule. See AGENTS.md Section 5.2/5.3.
 *
 * Risk/payment transfer point: when the goods are loaded onto the vessel (point (c) in
 * 5.3) — not at the destination. Only the "C" chosen specifically for that shipment
 * (Section 5.12, portAuthorityDid) is authorized to make this claim — there is no global
 * registry of port authorities.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const LOADING_CONFIRMED_CLAIM = 'loading-confirmed';

/**
 * `portAuthorityDid` is the "C" DID locked in for this specific shipment during the
 * escrow's propose/accept step (Section 5.12) — the policy takes it as a parameter rather
 * than referencing a hardcoded/global authority list.
 */
export function fobPolicy(portAuthorityDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'FOB',
    requireClaim(LOADING_CONFIRMED_CLAIM, { threshold, requiredIssuers: [portAuthorityDid] })
  );
}
