/**
 * HTTP surface for the incoterms-escrow settlement agent. AGENTS.md 5.27/5.28: this is the
 * ONLY thing that talks to this company's chain identity — no UBLP-operated backend is ever
 * in this path. Read-heavy "what's the state of the world" questions are meant to be answered
 * by the panel/ERP subscribing to Midnight's own public indexer directly (5.28); the one
 * `/status` route here exists purely as a convenience passthrough, not the source of truth.
 *
 * Approval gating follows AGENTS.md 5.21 exactly: `propose`/`lockEscrow` (new financial
 * commitments) go through the pending-action queue and need an explicit /approve call;
 * `attest`/`claim`/`release-timeout` execute immediately — C's attestation carries no
 * financial risk, claimPayout has nothing left to decide once C has attested, and
 * releaseOnTimeout is deliberately unattended by design (5.9/5.21).
 */

import type { FastifyInstance } from 'fastify';
import type { AuthStore } from './auth.js';
import {
  createPendingAction,
  findInFlightAction,
  getPendingAction,
  updatePendingActionStatus,
  listPendingActions,
} from './db.js';
import {
  type AgentContext,
  type ProposeParams,
  type LockParams,
  proposeDeal,
  lockDeal,
  attestDeal,
  claimDeal,
  releaseTimeoutDeal,
  getDealStatus,
  computePortAuthorityKeyHash,
} from './actions.js';

export function registerSettlementRoutes(app: FastifyInstance, ctx: AgentContext, auth: AuthStore): void {
  // ---- auth (AGENTS.md 5.26 — wallet-signature challenge-response, no passwords) ----
  app.post('/auth/challenge', async () => auth.issueChallenge());

  app.post<{ Body: { challengeId: string; signature: string } }>('/auth/verify', async (req, reply) => {
    const result = auth.verifyChallenge(req.body.challengeId, req.body.signature);
    if (!result) return reply.code(401).send({ error: 'invalid_or_expired_challenge' });
    return result;
  });

  app.addHook('onRequest', async (req, reply) => {
    if (req.url.startsWith('/auth/')) return;
    const token = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
    if (!auth.isSessionValid(token)) {
      await reply.code(401).send({ error: 'unauthorized' });
    }
  });

  // ---- pure off-chain helper: derive C's roleKeyHash to publish during negotiation ----
  app.post<{ Body: { portAuthoritySecretKeyHex: string } }>('/identity/port-authority-key-hash', async (req) => {
    return { portAuthorityKeyHashHex: computePortAuthorityKeyHash(req.body.portAuthoritySecretKeyHex) };
  });

  // ---- propose (seller) — queued for approval ----
  app.post<{ Body: ProposeParams }>('/deals/propose', async (req, reply) => {
    // No dealRef/contractAddress exists yet (propose() deploys a *new* contract), so there's
    // nothing to run findInFlightAction against — every propose() is an independent new deal.
    const pending = createPendingAction(ctx.db, {
      dealRef: `pending-propose:${Date.now()}`,
      action: 'propose',
      requestedBy: 'operator',
      payload: req.body as unknown as Record<string, unknown>,
    });
    return reply.code(202).send(pending);
  });

  // ---- lockEscrow (buyer) — queued for approval, refuses a redundant resubmit ----
  app.post<{ Body: LockParams }>('/deals/lock', async (req, reply) => {
    const inFlight = findInFlightAction(ctx.db, req.body.contractAddress, 'lockEscrow');
    if (inFlight) {
      return reply.code(409).send({ error: 'already_in_flight', pendingActionId: inFlight.id });
    }
    const pending = createPendingAction(ctx.db, {
      dealRef: req.body.contractAddress,
      action: 'lockEscrow',
      requestedBy: 'operator',
      payload: req.body as unknown as Record<string, unknown>,
    });
    return reply.code(202).send(pending);
  });

  app.post<{ Params: { id: string } }>('/deals/pending/:id/approve', async (req, reply) => {
    const id = Number(req.params.id);
    const pending = getPendingAction(ctx.db, id);
    if (!pending) return reply.code(404).send({ error: 'not_found' });
    if (pending.status !== 'awaiting_approval') {
      return reply.code(409).send({ error: 'not_awaiting_approval', status: pending.status });
    }

    updatePendingActionStatus(ctx.db, id, 'submitted_pending');
    try {
      const result =
        pending.action === 'propose'
          ? await proposeDeal(ctx, pending.payload as unknown as ProposeParams)
          : pending.action === 'lockEscrow'
            ? await lockDeal(ctx, pending.payload as unknown as LockParams)
            : (() => {
                throw new Error(`Unsupported pending action: ${pending.action}`);
              })();
      updatePendingActionStatus(ctx.db, id, 'confirmed', result.txId);
      return { ...pending, ...result, status: 'confirmed' as const };
    } catch (err) {
      updatePendingActionStatus(ctx.db, id, 'failed');
      return reply.code(502).send({ error: 'chain_call_failed', message: (err as Error).message });
    }
  });

  app.post<{ Params: { id: string } }>('/deals/pending/:id/reject', async (req, reply) => {
    const id = Number(req.params.id);
    const pending = getPendingAction(ctx.db, id);
    if (!pending) return reply.code(404).send({ error: 'not_found' });
    updatePendingActionStatus(ctx.db, id, 'rejected');
    return { ...pending, status: 'rejected' };
  });

  app.get<{ Querystring: { dealRef?: string } }>('/deals/pending', async (req) => {
    return listPendingActions(ctx.db, req.query.dealRef);
  });

  // ---- attest / claim / release-timeout — immediate, no approval gate (AGENTS.md 5.21) ----
  app.post<{ Params: { contractAddress: string } }>('/deals/:contractAddress/attest', async (req) => {
    return attestDeal(ctx, req.params.contractAddress);
  });
  app.post<{ Params: { contractAddress: string } }>('/deals/:contractAddress/claim', async (req) => {
    return claimDeal(ctx, req.params.contractAddress);
  });
  app.post<{ Params: { contractAddress: string } }>('/deals/:contractAddress/release-timeout', async (req) => {
    return releaseTimeoutDeal(ctx, req.params.contractAddress);
  });

  // ---- read passthrough — convenience only, not the source of truth (see file header) ----
  app.get<{ Params: { contractAddress: string } }>('/deals/:contractAddress/status', async (req, reply) => {
    const status = await getDealStatus(ctx, req.params.contractAddress);
    if (!status) return reply.code(404).send({ error: 'not_found' });
    return status;
  });
}
