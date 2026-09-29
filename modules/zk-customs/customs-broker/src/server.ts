/**
 * Customs Broker — persistent backend (replaces the old one-shot `index.ts` CLI as this
 * module's `start` entrypoint; `index.ts` is kept as a `npm run smoke` dev script, see its own
 * header). Exposes a REST API a future frontend (reusing incoterms-escrow's panel patterns) can
 * call: an operator prepares a document, approves it, and everything from "sent to Ministry"
 * onward (Ministry's own human review, then the unchanged Agent -> L2 pipeline)
 * proceeds automatically, tracked in `submissions`.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import path from 'path';
import {
  SimpleSessionAuthStore,
  createReviewItem,
  decideReviewItem,
  createAgentServer,
  startAgentServer,
} from '@ublp/shared';
import {
  openBrokerDb,
  createSubmission,
  getSubmission,
  listSubmissions,
  updateSubmission,
  SubmissionStatus,
} from './db';
import { startSubmissionPoller } from './poller';

const DB_PATH = path.join(__dirname, '..', 'data', 'broker.db');
const PORT = parseInt(process.env.BROKER_PORT ?? '3005', 10);

const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';
const MINISTRY_API_KEY = process.env.MINISTRY_BROKER_API_KEY ?? '';
const UBLP_AGENT_URL = process.env.UBLP_AGENT_URL ?? 'http://localhost:3002';
const POLL_INTERVAL_MS = parseInt(process.env.BROKER_POLL_INTERVAL_MS ?? '5000', 10);

const OPERATOR_PASSPHRASE = process.env.BROKER_OPERATOR_PASSPHRASE ?? '';
if (!OPERATOR_PASSPHRASE) {
  console.warn('[Broker] ⚠ BROKER_OPERATOR_PASSPHRASE is not set — operator login is disabled.');
}
if (!MINISTRY_API_KEY) {
  console.warn('[Broker] ⚠ MINISTRY_BROKER_API_KEY is not set — the call to Ministry will be rejected (dev only).');
}

const auth = new SimpleSessionAuthStore(OPERATOR_PASSPHRASE);
setInterval(() => auth.sweepExpired(), 60_000);

function requireSession(request: FastifyRequest, reply: FastifyReply, done: (err?: Error) => void): void {
  const header = request.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
  if (!token || !auth.isSessionValid(token)) {
    reply.status(401).send({ error: 'Not authenticated. Log in via POST /auth/login.' });
    return;
  }
  done();
}

interface MinistryApproveResponse {
  submissionId: number;
  status: SubmissionStatus;
}

export async function buildServer(db: ReturnType<typeof openBrokerDb>) {
  const app = createAgentServer({ logger: false });
  await app.register(cors, { origin: true });
  await app.register(rateLimit, { global: false });

  app.post<{ Body: { passphrase: string } }>(
    '/auth/login',
    { schema: { body: { type: 'object', required: ['passphrase'], properties: { passphrase: { type: 'string' } } } } },
    async (request, reply) => {
      const result = auth.login(request.body.passphrase);
      if (!result) return reply.status(401).send({ error: 'Invalid passphrase.' });
      return result;
    }
  );

  // ── Submissions ──────────────────────────────────────────────────────────────

  app.post<{ Body: Record<string, unknown> }>(
    '/api/submissions',
    {
      preHandler: requireSession,
      schema: { body: { type: 'object', required: ['documentId'], properties: { documentId: { type: 'string', minLength: 1 } } } },
    },
    async (request, reply) => {
      const document = request.body;
      const reviewItem = createReviewItem(db, {
        kind: 'submission-approval',
        refId: document.documentId as string,
        payload: document,
        requestedBy: 'operator',
      });
      const submission = createSubmission(db, { reviewItemId: reviewItem.id, document });
      return reply.status(201).send(submission);
    }
  );

  app.get('/api/submissions', { preHandler: requireSession }, async (request) => {
    const status = (request.query as { status?: SubmissionStatus }).status;
    return listSubmissions(db, status);
  });

  app.get<{ Params: { id: string } }>('/api/submissions/:id', { preHandler: requireSession }, async (request, reply) => {
    const submission = getSubmission(db, Number(request.params.id));
    if (!submission) return reply.status(404).send({ error: 'Unknown submission.' });
    return submission;
  });

  app.post<{ Params: { id: string } }>(
    '/api/submissions/:id/approve',
    { preHandler: requireSession },
    async (request, reply) => {
      const id = Number(request.params.id);
      const submission = getSubmission(db, id);
      if (!submission) return reply.status(404).send({ error: 'Unknown submission.' });

      const decided = decideReviewItem(db, submission.reviewItemId, 'approved', 'operator');
      if (!decided) return reply.status(409).send({ error: 'Already decided.' });

      updateSubmission(db, id, { status: 'sent_to_ministry' });

      try {
        const res = await fetch(`${MINISTRY_URL}/api/approve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': MINISTRY_API_KEY },
          body: JSON.stringify(submission.document),
        });
        const body = (await res.json()) as MinistryApproveResponse & { error?: string };
        if (!res.ok) {
          updateSubmission(db, id, { status: 'failed', error: body.error ?? `Ministry HTTP ${res.status}` });
          return reply.status(502).send({ error: 'Ministry rejected the submission.', detail: body.error });
        }
        updateSubmission(db, id, { status: 'awaiting_ministry_approval', ministryRefId: body.submissionId });
        return getSubmission(db, id);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        updateSubmission(db, id, { status: 'failed', error: message });
        return reply.status(503).send({ error: 'Could not reach Ministry.', detail: message });
      }
    }
  );

  app.post<{ Params: { id: string }; Body: { note?: string } }>(
    '/api/submissions/:id/reject',
    { preHandler: requireSession },
    async (request, reply) => {
      const id = Number(request.params.id);
      const submission = getSubmission(db, id);
      if (!submission) return reply.status(404).send({ error: 'Unknown submission.' });

      const decided = decideReviewItem(db, submission.reviewItemId, 'rejected', 'operator', request.body?.note);
      if (!decided) return reply.status(409).send({ error: 'Already decided.' });

      updateSubmission(db, id, { status: 'rejected' });
      return getSubmission(db, id);
    }
  );

  return app;
}

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  const db = openBrokerDb(DB_PATH);
  const app = await buildServer(db);
  await startAgentServer(app, { port: PORT });
  console.log(`[Broker] ✓ Customs Broker API — http://localhost:${PORT}`);

  const poller = startSubmissionPoller(db, {
    ministryUrl: MINISTRY_URL,
    ministryApiKey: MINISTRY_API_KEY,
    agentUrl: UBLP_AGENT_URL,
    intervalMs: POLL_INTERVAL_MS,
  });

  const shutdown = async (): Promise<void> => {
    poller.stop();
    await app.close();
    db.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
};

// Only auto-starts when run directly — see ministry/src/index.ts's identical guard for why
// (importing this module from a test must not also bind the real BROKER_PORT or start the poller).
if (!process.env.VITEST) {
  start().catch((err) => {
    console.error('[Broker] Startup error:', err);
    process.exit(1);
  });
}
