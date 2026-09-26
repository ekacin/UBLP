/**
 * Integration test against Ministry's REAL route wiring (`ministry/src/index.ts`'s exported
 * `buildServer`), not a duplicated inline copy — closes the coverage gap the backend-foundation
 * plan flagged (the existing `ministry.test.ts` only exercises a hand-copied reimplementation).
 * Real HTTP over an ephemeral port, an in-memory db — no fixed ports, no on-disk state.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { generateKeyPair } from '../../../../shared/src/crypto/documentCrypto';
import { SAMPLE_CUSTOMS_DOCUMENT } from '../fixtures/sample-documents';

const OPERATOR_PASSPHRASE = 'ministry-officer-test-pw';
const BROKER_API_KEY = 'ministry-broker-shared-test-key';

process.env.MINISTRY_OPERATOR_PASSPHRASE = OPERATOR_PASSPHRASE;
process.env.MINISTRY_BROKER_API_KEY = BROKER_API_KEY;

describe('ministry backend (real route wiring)', () => {
  let app: FastifyInstance;
  let baseUrl: string;

  beforeAll(async () => {
    const { buildServer } = await import('../../ministry/src/index');
    const { openMinistryDb } = await import('../../ministry/src/db');
    const db = openMinistryDb(':memory:');
    const keys = generateKeyPair();
    app = (await buildServer(keys, db)) as unknown as FastifyInstance;
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it('exposes the ministry public key without auth', async () => {
    const res = await fetch(`${baseUrl}/api/public-key`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ministryPublicKey).toBeTruthy();
  });

  it('rejects /api/approve without the broker API key', async () => {
    const res = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(SAMPLE_CUSTOMS_DOCUMENT),
    });
    expect(res.status).toBe(401);
  });

  it('rejects officer login with the wrong passphrase', async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: 'wrong' }),
    });
    expect(res.status).toBe(401);
  });

  it('queues a document, then lets an officer review, approve, and issue a VC', async () => {
    // Submit — broker side, API-key protected.
    const submitRes = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': BROKER_API_KEY },
      body: JSON.stringify(SAMPLE_CUSTOMS_DOCUMENT),
    });
    expect(submitRes.status).toBe(202);
    const { submissionId, status: submitStatus } = await submitRes.json();
    expect(submitStatus).toBe('awaiting_approval');

    // Not yet decided — the machine-facing status endpoint should reflect that.
    const pendingStatusRes = await fetch(`${baseUrl}/api/documents/${submissionId}`, {
      headers: { 'x-api-key': BROKER_API_KEY },
    });
    expect((await pendingStatusRes.json()).status).toBe('awaiting_approval');

    // Officer logs in.
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: OPERATOR_PASSPHRASE }),
    });
    expect(loginRes.status).toBe(200);
    const { sessionToken } = await loginRes.json();

    // Officer sees it in the pending queue.
    const pendingListRes = await fetch(`${baseUrl}/api/pending`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const pendingList = await pendingListRes.json();
    expect(pendingList.some((item: { id: number }) => item.id === submissionId)).toBe(true);

    // Officer approves — this is where the VC actually gets signed now (moved out of the
    // old synchronous /api/approve handler).
    const approveRes = await fetch(`${baseUrl}/api/pending/${submissionId}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    expect(approveRes.status).toBe(200);
    const { verifiableCredential } = await approveRes.json();
    expect(verifiableCredential.id).toBe(`urn:ublp:vc:${SAMPLE_CUSTOMS_DOCUMENT.documentId}`);
    expect(verifiableCredential.credentialSubject.documentId).toBe(SAMPLE_CUSTOMS_DOCUMENT.documentId);

    // Broker's poller would now see 'approved' with the VC attached.
    const finalStatusRes = await fetch(`${baseUrl}/api/documents/${submissionId}`, {
      headers: { 'x-api-key': BROKER_API_KEY },
    });
    const finalStatus = await finalStatusRes.json();
    expect(finalStatus.status).toBe('approved');
    expect(finalStatus.verifiableCredential.id).toBe(verifiableCredential.id);

    // A decided item can't be approved (or rejected) again.
    const secondApprove = await fetch(`${baseUrl}/api/pending/${submissionId}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    expect(secondApprove.status).toBe(409);
  });

  it('lets an officer reject a document, with no VC issued', async () => {
    const doc = { ...SAMPLE_CUSTOMS_DOCUMENT, documentId: 'DOC-reject-test' };
    const submitRes = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': BROKER_API_KEY },
      body: JSON.stringify(doc),
    });
    const { submissionId } = await submitRes.json();

    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: OPERATOR_PASSPHRASE }),
    });
    const { sessionToken } = await loginRes.json();

    const rejectRes = await fetch(`${baseUrl}/api/pending/${submissionId}/reject`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: 'incomplete HS code' }),
    });
    expect(rejectRes.status).toBe(200);

    const statusRes = await fetch(`${baseUrl}/api/documents/${submissionId}`, {
      headers: { 'x-api-key': BROKER_API_KEY },
    });
    const status = await statusRes.json();
    expect(status.status).toBe('rejected');
    expect(status.verifiableCredential).toBeUndefined();
  });
});
