/**
 * Integration test against Customs Broker's REAL route wiring (`customs-broker/src/server.ts`'s
 * exported `buildServer`), with a REAL Ministry instance (`ministry/src/index.ts`'s `buildServer`)
 * behind it on its own ephemeral port — not mocks, not a duplicated inline copy. Exercises the
 * operator-approval -> Ministry-submit -> officer-approval leg end to end. The Agent/Committee/
 * L2 leg is intentionally NOT exercised here (that part of the pipeline is unchanged by this
 * work and already covered by the existing e2e/agent/committee/l2-verifier tests) — these tests
 * point UBLP_AGENT_URL at an address nothing listens on and assert the submission correctly
 * lands on `vc_received` (poller retries rather than marking it failed), matching the
 * resilience behavior described in the backend-foundation plan.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { generateKeyPair } from '../../../../shared/src/crypto/documentCrypto';
import { SAMPLE_CUSTOMS_DOCUMENT, ALT_CUSTOMS_DOCUMENT } from '../fixtures/sample-documents';

const MINISTRY_OPERATOR_PASSPHRASE = 'ministry-officer-test-pw';
const MINISTRY_BROKER_API_KEY = 'ministry-broker-shared-test-key';
const BROKER_OPERATOR_PASSPHRASE = 'broker-operator-test-pw';

process.env.MINISTRY_OPERATOR_PASSPHRASE = MINISTRY_OPERATOR_PASSPHRASE;
process.env.MINISTRY_BROKER_API_KEY = MINISTRY_BROKER_API_KEY;
process.env.BROKER_OPERATOR_PASSPHRASE = BROKER_OPERATOR_PASSPHRASE;

function addressToUrl(app: FastifyInstance): string {
  const address = app.server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return `http://127.0.0.1:${port}`;
}

async function login(baseUrl: string, passphrase: string): Promise<string> {
  const res = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ passphrase }),
  });
  const { sessionToken } = await res.json();
  return sessionToken;
}

describe('customs-broker backend (real route wiring, real Ministry)', () => {
  let ministryApp: FastifyInstance;
  let brokerApp: FastifyInstance;
  let ministryUrl: string;
  let brokerUrl: string;
  let stopPoller: () => void;

  beforeAll(async () => {
    const { buildServer: buildMinistry } = await import('../../ministry/src/index');
    const { openMinistryDb } = await import('../../ministry/src/db');
    const ministryDb = openMinistryDb(':memory:');
    const keys = generateKeyPair();
    ministryApp = (await buildMinistry(keys, ministryDb)) as unknown as FastifyInstance;
    await ministryApp.listen({ port: 0, host: '127.0.0.1' });
    ministryUrl = addressToUrl(ministryApp);

    // server.ts reads MINISTRY_URL into a top-level const at import time, so this must be set
    // before the dynamic import below, not just before the first request.
    process.env.MINISTRY_URL = ministryUrl;

    const { buildServer: buildBroker } = await import('../../customs-broker/src/server');
    const { openBrokerDb } = await import('../../customs-broker/src/db');
    const { startSubmissionPoller } = await import('../../customs-broker/src/poller');
    const brokerDb = openBrokerDb(':memory:');
    brokerApp = (await buildBroker(brokerDb)) as unknown as FastifyInstance;
    await brokerApp.listen({ port: 0, host: '127.0.0.1' });
    brokerUrl = addressToUrl(brokerApp);

    // server.ts's own `start()` (which normally wires this up) is guarded off under Vitest —
    // see its header comment — so the poller has to be started explicitly here, exactly the
    // same way `start()` does it.
    const poller = startSubmissionPoller(brokerDb, {
      ministryUrl,
      ministryApiKey: MINISTRY_BROKER_API_KEY,
      agentUrl: 'http://127.0.0.1:1',
      intervalMs: 200,
    });
    stopPoller = poller.stop;
  });

  afterAll(async () => {
    stopPoller();
    await brokerApp.close();
    await ministryApp.close();
  });

  it('rejects operator actions without a session', async () => {
    const res = await fetch(`${brokerUrl}/api/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(SAMPLE_CUSTOMS_DOCUMENT),
    });
    expect(res.status).toBe(401);
  });

  it('creates a draft submission, approves it, and confirms it reaches Ministry', async () => {
    const sessionToken = await login(brokerUrl, BROKER_OPERATOR_PASSPHRASE);

    const createRes = await fetch(`${brokerUrl}/api/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify(SAMPLE_CUSTOMS_DOCUMENT),
    });
    expect(createRes.status).toBe(201);
    const submission = await createRes.json();
    expect(submission.status).toBe('draft');

    const approveRes = await fetch(`${brokerUrl}/api/submissions/${submission.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    expect(approveRes.status).toBe(200);
    const approved = await approveRes.json();
    expect(approved.status).toBe('awaiting_ministry_approval');
    expect(approved.ministryRefId).toBeTypeOf('number');

    // Confirm it really landed at Ministry as a pending review item.
    const ministrySession = await login(ministryUrl, MINISTRY_OPERATOR_PASSPHRASE);
    const pendingRes = await fetch(`${ministryUrl}/api/pending`, {
      headers: { Authorization: `Bearer ${ministrySession}` },
    });
    const pending = await pendingRes.json();
    expect(pending.some((item: { id: number }) => item.id === approved.ministryRefId)).toBe(true);
  });

  it('picks up Ministry approval via polling and reaches vc_received (Agent unreachable by design)', async () => {
    const sessionToken = await login(brokerUrl, BROKER_OPERATOR_PASSPHRASE);
    const doc = { ...ALT_CUSTOMS_DOCUMENT, documentId: 'DOC-broker-poll-test' };

    const createRes = await fetch(`${brokerUrl}/api/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify(doc),
    });
    const submission = await createRes.json();

    const approveRes = await fetch(`${brokerUrl}/api/submissions/${submission.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const approved = await approveRes.json();

    const ministrySession = await login(ministryUrl, MINISTRY_OPERATOR_PASSPHRASE);
    const ministryApproveRes = await fetch(`${ministryUrl}/api/pending/${approved.ministryRefId}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ministrySession}` },
    });
    expect(ministryApproveRes.status).toBe(200);

    // Give the broker's poller (200ms interval in this suite) a few ticks to notice.
    let latest = approved;
    for (let attempt = 0; attempt < 20 && latest.status !== 'vc_received'; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 150));
      const statusRes = await fetch(`${brokerUrl}/api/submissions/${submission.id}`, {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      latest = await statusRes.json();
    }

    expect(latest.status).toBe('vc_received');
    expect(latest.verifiableCredential.credentialSubject.documentId).toBe(doc.documentId);
  });

  it('marks a submission rejected end to end when Ministry rejects it', async () => {
    const sessionToken = await login(brokerUrl, BROKER_OPERATOR_PASSPHRASE);
    const doc = { ...ALT_CUSTOMS_DOCUMENT, documentId: 'DOC-broker-reject-test' };

    const createRes = await fetch(`${brokerUrl}/api/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify(doc),
    });
    const submission = await createRes.json();

    const approveRes = await fetch(`${brokerUrl}/api/submissions/${submission.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const approved = await approveRes.json();

    const ministrySession = await login(ministryUrl, MINISTRY_OPERATOR_PASSPHRASE);
    await fetch(`${ministryUrl}/api/pending/${approved.ministryRefId}/reject`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ministrySession}` },
    });

    let latest = approved;
    for (let attempt = 0; attempt < 20 && latest.status !== 'rejected'; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 150));
      const statusRes = await fetch(`${brokerUrl}/api/submissions/${submission.id}`, {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      latest = await statusRes.json();
    }

    expect(latest.status).toBe('rejected');
  });
});
