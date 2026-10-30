/**
 * Pure "should the watcher act on this deal right now" decisions — deliberately separated
 * from watcher.ts's actual chain calls so this logic is unit-testable without a live devnet.
 *
 * Both functions are conservative on purpose: a false negative just means we check again next
 * tick (cheap), a false positive would mean an unnecessary/failing on-chain attempt (wasted
 * proof generation, never a security issue — Escrow.compact's own asserts are the real
 * authority, see AGENTS.md 5.29).
 */

import type { AgentRole } from '../deploy/wallet.js';
import type { DealStatus } from './actions.js';

const LOCKED_STATE = 2; // Escrow.compact's EscrowState.Locked ordinal

/** claimPayout is only meaningful for the seller (the payee), only once C has attested, and
 * only while the deal is still Locked (already-Released means someone else got there first —
 * harmless, just nothing left to do). AGENTS.md 5.36's Fix B: `depositVerified === false`
 * means the seller's own independent recomputation of heldCommitment disagreed with the
 * on-chain value — never auto-act on that, surface it to a human instead (watcher.ts just
 * skips the deal; the panel shows the mismatch — see DealStatus.tsx). `null` (nothing to
 * check yet, or not a seller) and `true` both pass through unaffected. */
export function shouldAutoClaimDeal(role: AgentRole, status: DealStatus): boolean {
  return (
    role === 'seller' &&
    status.state === LOCKED_STATE &&
    status.milestoneConfirmed &&
    status.depositVerified !== false
  );
}

/** releaseOnTimeout, either direction — matching role to the ledger's own `timeoutDirection`
 * so each agent only ever attempts the branch it actually has the witness data for (buyer's
 * own deposit/address from lockEscrow, seller's own pre-committed depositNonce/depositSalt
 * from propose — see actions.ts's releaseTimeoutAsSeller, AGENTS.md 5.36). Same
 * `depositVerified` guard as shouldAutoClaimDeal above, for the same reason — the seller
 * branch needs the same coin data claimPayout does. */
export function shouldAutoReleaseTimeout(role: AgentRole, status: DealStatus, nowSeconds: number): boolean {
  return (
    (role === 'buyer' || role === 'seller') &&
    status.timeoutDirection === role &&
    status.state === LOCKED_STATE &&
    !status.milestoneConfirmed &&
    nowSeconds >= status.deadlineTimestamp &&
    status.depositVerified !== false
  );
}
