/**
 * FAS (Free Alongside Ship) — Incoterms 2020 rule, sea/inland waterway transport only.
 *
 * Risk/payment transfer point: when the goods are placed alongside the vessel (e.g. on the
 * quay or a barge) at the named port of shipment — one step earlier than FOB's "on board."
 * Mechanically identical to FOB/CFR/CIF's escrow flow: the same generic "C attests one
 * milestone, then payout" contract handles it (see Escrow.compact's own comment — the
 * `attestLoadingConfirmed` circuit only checks a role-key-hash, it has no maritime-specific
 * logic), so this policy differs from `fob.ts` only in which claim it requires.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const ALONGSIDE_SHIP_CONFIRMED_CLAIM = 'alongside-ship-confirmed';

/**
 * `attestingPartyDid` is the "C" DID locked in for this specific shipment during the escrow's
 * propose/accept step — in practice a terminal/quay operator who can confirm the goods were
 * placed alongside the vessel, not a global registry.
 */
export function fasPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'FAS',
    requireClaim(ALONGSIDE_SHIP_CONFIRMED_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
