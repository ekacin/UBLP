/**
 * DDP (Delivered Duty Paid) — Incoterms 2020 rule, any mode of transport.
 *
 * Risk/payment transfer point: when the goods are placed at the buyer's disposal, cleared for
 * import (duties/taxes paid), ready for unloading at the named destination — the seller's
 * maximum-responsibility rule.
 *
 * A textbook-complete DDP policy would combine two independent claims — delivery AND customs
 * clearance (`and(requireClaim('delivered'), requireClaim('customs-cleared'))`, see this
 * shared policy module's own doc comment) — with the customs leg potentially verified by a
 * separate system entirely (UBLP's own `zk-customs` module handles exactly that domain). This
 * v0.1 policy deliberately does NOT do that: it treats "delivered, duty paid" as a single
 * claim from a single attesting party, matching every other rule here and requiring no
 * changes to Escrow.compact's one-attest-one-payout contract. Wiring DDP to a real customs
 * clearance proof is a deliberate future option, not a dependency — DDP must work standalone,
 * without requiring another module to be production-ready first.
 */

import { requireClaim, definePolicy } from '@ublp/shared';
import type { AttestationPolicy, UBLPDid } from '@ublp/shared';

export const DELIVERED_DUTY_PAID_CLAIM = 'delivered-duty-paid-confirmed';

export function ddpPolicy(attestingPartyDid: UBLPDid, threshold = 1): AttestationPolicy {
  return definePolicy(
    'DDP',
    requireClaim(DELIVERED_DUTY_PAID_CLAIM, { threshold, requiredIssuers: [attestingPartyDid] })
  );
}
