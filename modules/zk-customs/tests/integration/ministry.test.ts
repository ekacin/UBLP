import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import crypto from 'crypto';
import {
  generateKeyPair,
  signDocument,
  sha256HashDocument,
  sha256Hash,
  verifySignature,
  UBLPVerifiableCredential,
} from '../../shared/src/crypto/mockCrypto';

const testKeys = generateKeyPair();
let app: ReturnType<typeof Fastify>;
const MINISTRY_DID = 'did:ublp:ministry:test';

async function buildTestServer() {
  app = Fastify({ logger: false });

  app.get('/api/public-key', async () => ({
    ministryPublicKey: testKeys.publicKey,
    did: MINISTRY_DID,
  }));

  app.post<{ Body: Record<string, unknown> }>(
    '/api/approve',
    {
      schema: {
        body: {
          type: 'object',
          required: ['documentId'],
          properties: {
            documentId: { type: 'string', minLength: 1 },
            holderDid: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const document = request.body;
      const documentId = document['documentId'] as string;
      const holderDid = (document['holderDid'] as string) ?? 'did:ublp:agent:unknown';
      const documentHash = sha256HashDocument(document);
      const documentIdHash = sha256Hash(documentId);
      const signature = signDocument(document, testKeys.privateKey, documentIdHash);

      const vc: UBLPVerifiableCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ublp.io/vc/v1'],
        id: `urn:ublp:vc:${documentId}`,
        type: ['VerifiableCredential', 'UBLPCustomsCredential'],
        issuer: MINISTRY_DID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDid,
          documentId,
          rawDocument: document,
        },
        proof: {
          type: 'EcdsaSecp256r1Signature2019',
          created: new Date().toISOString(),
          verificationMethod: `${MINISTRY_DID}#key-1`,
          proofPurpose: 'assertionMethod',
          proofValue: signature,
          ministryPublicKey: testKeys.publicKey,
        },
      };

      return reply.status(200).send(vc);
    }
  );

  await app.listen({ port: 0, host: '127.0.0.1' });
  return (app.server.address() as { port: number }).port;
}

describe('Ministry Service Integration', () => {
  let port: number;
  let baseUrl: string;

  beforeAll(async () => {
    port = await buildTestServer();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /api/public-key returns the ministry public key', async () => {
    const res = await fetch(`${baseUrl}/api/public-key`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.ministryPublicKey).toBe(testKeys.publicKey);
    expect(data.did).toBe(MINISTRY_DID);
  });

  it('POST /api/approve with valid document returns VC', async () => {
    const doc = {
      documentId: 'DOC-INTEGRATION-TEST-001',
      holderDid: 'did:ublp:agent:integration',
      exporterName: 'Integration Test Ltd.',
      totalValue: '10000 USD',
    };

    const res = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });

    expect(res.status).toBe(200);
    const vc: UBLPVerifiableCredential = await res.json();
    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.issuer).toBe(MINISTRY_DID);
    expect(vc.credentialSubject.id).toBe('did:ublp:agent:integration');
    expect(vc.credentialSubject.documentId).toBe('DOC-INTEGRATION-TEST-001');
    expect(vc.proof.type).toBe('EcdsaSecp256r1Signature2019');
    expect(vc.proof.proofValue).toBeTruthy();

    const committeeAtt = (vc as Record<string, unknown>).committeeAttestation;
    expect(committeeAtt).toBeUndefined();
  });

  it('POST /api/approve VC signature is verifiable', async () => {
    const doc = {
      documentId: 'DOC-VERIFY-SIG-001',
      holderDid: 'did:ublp:agent:verifier',
      goodsDescription: 'Test goods for signature verification',
    };

    const res = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });

    const vc: UBLPVerifiableCredential = await res.json();
    const documentIdHash = sha256Hash(doc.documentId);
    const isValid = verifySignature(
      doc,
      vc.proof.proofValue,
      vc.proof.ministryPublicKey,
      documentIdHash
    );

    expect(isValid).toBe(true);
  });

  it('POST /api/approve rejects missing documentId', async () => {
    const res = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ holderDid: 'did:ublp:agent:test' }),
    });

    expect(res.status).toBe(400);
  });

  it('POST /api/approve document hash domain separation is correct', async () => {
    const doc = {
      documentId: 'DOC-DOMAIN-001',
      exporterName: 'Domain Test',
    };

    const res = await fetch(`${baseUrl}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });

    const vc: UBLPVerifiableCredential = await res.json();

    const documentHash = sha256HashDocument(doc);
    const documentIdHash = sha256Hash(doc.documentId);
    const rawDocument = vc.credentialSubject.rawDocument as Record<string, unknown>;

    const recomputedDocHash = sha256HashDocument(rawDocument);
    const recomputedIdHash = sha256Hash(vc.credentialSubject.documentId);

    expect(recomputedDocHash).toBe(documentHash);
    expect(recomputedIdHash).toBe(documentIdHash);
  });
});
