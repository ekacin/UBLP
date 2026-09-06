/**
 * Background "otonom güvenlik ağı" loop — the piece that actually makes claimPayout-on-attest
 * and releaseOnTimeout "automatic" (AGENTS.md 5.9/5.21's decision) rather than merely
 * callable. Without this, /deals/:address/claim and /deals/:address/release-timeout only do
 * anything if a human (or an external script) remembers to POST to them.
 *
 * Deliberately ONE simple polling loop, not a mix of indexer subscriptions + a timer:
 * "has the deadline passed" can only ever be answered by checking wall-clock time against the
 * ledger's deadlineTimestamp (a subscription only fires on real on-chain calls, never on the
 * mere passage of time — AGENTS.md 5.29), so a periodic check is unavoidable for that case
 * regardless. Reusing the same loop for the attest->claim case too avoids running two
 * different mechanisms for what's conceptually the same job. Given the expected deal volume
 * (a handful of concurrently open deals per company, not thousands), this is deliberately the
 * simplest thing that works — no job queue, no distributed locking.
 *
 * Deliberately does NOTHING for the port-authority role: attestMilestone requires a
 * real physical observation (the oracle-problem boundary discussed alongside AGENTS.md
 * Section 6's Module 3 note) — it is the one action in this system that must never be
 * automated, so there is nothing for this role's watcher to do.
 */

import { getDealStatus, claimDeal, releaseTimeoutDeal, type AgentContext } from './actions.js';
import { listDealRefs } from './db.js';
import { shouldAutoClaimDeal, shouldAutoReleaseTimeout } from './dealPolicy.js';

export interface DealWatcherHandle {
  stop: () => void;
}

export function startDealWatcher(ctx: AgentContext, intervalMs = 60_000): DealWatcherHandle {
  if (ctx.role !== 'seller' && ctx.role !== 'buyer') {
    return { stop: () => {} }; // port-authority — see file header
  }

  let ticking = false;
  const tick = async (): Promise<void> => {
    if (ticking) return; // a slow tick (e.g. indexer lag) shouldn't overlap with the next timer fire
    ticking = true;
    try {
      for (const dealRef of listDealRefs(ctx.db)) {
        await checkOneDeal(ctx, dealRef);
      }
    } catch (err) {
      console.error('[watcher] tick failed', err);
    } finally {
      ticking = false;
    }
  };

  const handle = setInterval(() => void tick(), intervalMs);
  void tick(); // don't make the first check wait a full interval after boot
  return { stop: () => clearInterval(handle) };
}

async function checkOneDeal(ctx: AgentContext, dealRef: string): Promise<void> {
  const status = await getDealStatus(ctx, dealRef);
  if (!status) return; // not deployed yet, or the address doesn't resolve

  const nowSeconds = Math.floor(Date.now() / 1000);

  if (shouldAutoClaimDeal(ctx.role, status)) {
    try {
      await claimDeal(ctx, dealRef);
      console.log(`[watcher] auto-claimed payout for ${dealRef}`);
    } catch (err) {
      // Safe to just retry next tick — e.g. this agent's witness data for the deal isn't
      // complete yet, or (harmlessly) someone else already claimed it in the meantime.
      console.warn(`[watcher] auto-claim attempt failed for ${dealRef}, will retry next tick`, err);
    }
  }

  if (shouldAutoReleaseTimeout(ctx.role, status, nowSeconds)) {
    try {
      await releaseTimeoutDeal(ctx, dealRef);
      console.log(`[watcher] auto-released timeout refund for ${dealRef}`);
    } catch (err) {
      console.warn(`[watcher] auto-release attempt failed for ${dealRef}, will retry next tick`, err);
    }
  }
}
