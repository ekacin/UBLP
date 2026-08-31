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
  type ProposeDealParams,
  type LockDealParams,
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

  app.post<{ Body: { challengeId: string; signature: string; signedDataHex: string; verifyingKey: string } }>(
    '/auth/verify',
    async (req, reply) => {
      const { challengeId, signature, signedDataHex, verifyingKey } = req.body;
      const result = auth.verifyChallenge(challengeId, signature, signedDataHex, verifyingKey);
      if (!result) return reply.code(401).send({ error: 'invalid_or_expired_challenge' });
      return result;
    }
  );

  // These two GETs are deliberately public — see their own handlers below and
  // fetchCounterpartyIdentity's doc comment in the panel's api.ts: a genuine counterparty (a
  // different company, with no session on THIS agent) is exactly who is supposed to call them
  // during negotiation, before either side has anything to authenticate with here. Live-tested
  // 2026-08-31: a second agent's browser session got a bare {"error":"unauthorized"} from these
  // until this exemption was added — the blanket hook below was catching them along with
  // everything else.
  const PUBLIC_IDENTITY_PATHS = ['/identity/port-authority-key-hash', '/identity/memo-public-key'];

  app.addHook('onRequest', async (req, reply) => {
    if (req.url.startsWith('/auth/') || PUBLIC_IDENTITY_PATHS.includes(req.url)) return;
    const token = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
    if (!auth.isSessionValid(token)) {
      await reply.code(401).send({ error: 'unauthorized' });
    }
  });

  // ---- this agent's fixed role (AgentContext.role — set once at boot, never chosen by the
  // operator in the UI: a single deployed agent is always one company's seller, buyer, or
  // port-authority identity, never a role picker). The panel needs this to render a role-
  // appropriate dashboard (e.g. only sellers see "New deal", only port-authority sees attest). ----
  app.get('/identity/whoami', async () => {
    return { role: ctx.role, did: ctx.did, network: ctx.network.networkId };
  });

  // ---- pure off-chain helper: derive C's own roleKeyHash to publish during negotiation.
  // Reads ctx.identity.roleSecretKeyHex directly (already decrypted, in-process) — the raw
  // secret key must never be accepted as a request parameter, even over localhost, the same
  // witness-never-leaves-the-trust-boundary rule as everywhere else in this codebase. ----
  app.get('/identity/port-authority-key-hash', async (_req, reply) => {
    if (ctx.role !== 'port-authority' || !ctx.identity.roleSecretKeyHex) {
      return reply.code(400).send({ error: 'this agent has no port-authority role key' });
    }
    // `did` rides along here too — the operator building `terms` needs BOTH values, and
    // typing the DID by hand (must match this agent's real ctx.did, or the counterparty's
    // later accept/lock check rejects it) is exactly the kind of transcription error this
    // endpoint already exists to avoid for the hash itself.
    return { portAuthorityKeyHashHex: computePortAuthorityKeyHash(ctx.identity.roleSecretKeyHex), did: ctx.did };
  });

  // ---- this agent's own X25519 memo public key — a real public key, safe to hand out; the
  // counterparty needs it to fill in buyerMemoPublicKeyHex/sellerMemoPublicKeyHex when
  // negotiating terms (AGENTS.md 5.18). No such endpoint existed before this agent's first
  // real end-to-end test — every ProposeParams/LockParams caller had no way to actually learn
  // the counterparty's key otherwise. ----
  app.get('/identity/memo-public-key', async () => {
    return { memoPublicKeyHex: ctx.identity.memoKeyPair.publicKey, did: ctx.did };
  });

  // ---- propose (seller) — queued for approval ----
  app.post<{ Body: ProposeDealParams }>('/deals/propose', async (req, reply) => {
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
  app.post<{ Body: LockDealParams }>('/deals/lock', async (req, reply) => {
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
      // For 'propose', the result's contractAddress is the deal's real, permanent identity —
      // the pending row's dealRef started as a placeholder (no contract existed yet); pass it
      // through to updatePendingActionStatus so later lookups by contract address find this
      // action too (see db.ts). Branching on pending.action (already known) rather than an
      // `in` check on the result's inferred union keeps this a plain, TS-narrowable if/else.
      let result: { txId: string; contractAddress?: string; proposal?: unknown };
      let realDealRef: string | undefined;
      if (pending.action === 'propose') {
        const proposeResult = await proposeDeal(ctx, pending.payload as unknown as ProposeDealParams);
        result = proposeResult;
        realDealRef = proposeResult.contractAddress;
      } else if (pending.action === 'lockEscrow') {
        result = await lockDeal(ctx, pending.payload as unknown as LockDealParams);
      } else {
        throw new Error(`Unsupported pending action: ${pending.action}`);
      }
      updatePendingActionStatus(ctx.db, id, 'confirmed', result.txId, realDealRef);
      return { ...pending, ...result, status: 'confirmed' as const, dealRef: realDealRef ?? pending.dealRef };
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
