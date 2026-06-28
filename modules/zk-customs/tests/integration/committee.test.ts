import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import crypto from 'crypto';
import {
  generateKeyPair,
  signDocument,
  sha256HashDocument,
  sha256Hash,
  verifySignatureOverHash,
  combinedSignatureHash,
  blsGenerateKeyPair,
  blsSign,
  blsAggregateSignatures,
  blsGroupKeyHash,
  CommitteeAttestation,
} from '../../shared/src/crypto/mockCrypto';

const ministryKeys = generateKeyPair();
const MINISTRY_DID = 'did:ublp:ministry:test';

const MEMBER_IDS = [
  'did:ublp:committee:customs-authority',
  'did:ublp:committee:importer-chamber',
  'did:ublp:committee:exporter-union',
];

const committeeMembers = MEMBER_IDS.map((memberId) => ({
  memberId,
  ...blsGenerateKeyPair(),
}));

const THRESHOLD = 2;
const groupKeyHash = blsGroupKeyHash(committeeMembers.map((m) => m.publicKey));

let app: ReturnType<typeof Fastify>;
let port: number;

async function buildTestCommittee() {
  app = Fastify({ logger: false });

  // GET /api/info — L2 sync
  app.get('/api/info', async () => ({
    type: 'BLSThreshold',
    groupKeyHash,
    threshold: THRESHOLD,
    totalMembers: committeeMembers.length,
    members: committeeMembers.map((m) => ({
      memberId: m.memberId,
      blsPublicKey: m.publicKey,
    })),
  }));

  // POST /api/attest — simplified mock to verify ZK proof function works
  interface AttestRequest {
    proofBytes: string;
    proofSystem: string;
    publicValues: {
      documentHash: string;
      documentIdHash: string;
      ministryPubKeyHash: string;
      holderPubKeyHash: string;
    };
    ministryPublicKey: string;
  }

  app.post<{ Body: AttestRequest }>(
    '/api/attest',
    async (request, reply) => {
      const { proofBytes, proofSystem, publicValues, ministryPublicKey } = request.body;
      const { documentHash, documentIdHash } = publicValues;

      // Verify proof (mock mode)
      let proofValid: boolean;
      if (proofSystem === 'sp1-groth16' || proofSystem === 'sp1-plonk') {
        proofValid = false;
      } else {
        const combined = combinedSignatureHash(documentHash, documentIdHash);
        proofValid = verifySignatureOverHash(combined, proofBytes, ministryPublicKey);
      }

      if (!proofValid) {
        return reply.status(400).send({ error: 'ZK kaniti dogrulanamadi.' });
      }

      // BLS threshold sign
      const msgHex = combinedSignatureHash(documentHash, documentIdHash);
      const partialSigs: string[] = [];
      const signerIds: string[] = [];

      for (const member of committeeMembers) {
        try {
          const sig = await blsSign(msgHex, member.privateKey);
          partialSigs.push(sig);
          signerIds.push(member.memberId);
        } catch {
          // skip failed members
        }
      }

      if (partialSigs.length < THRESHOLD) {
        return reply.status(503).send({ error: 'Esik saglanamadi.' });
      }

      const aggregatedSignature = blsAggregateSignatures(partialSigs);

      const attestation: CommitteeAttestation = {
        type: 'BLSThreshold',
        threshold: THRESHOLD,
        totalMembers: committeeMembers.length,
        groupKeyHash,
        signerIds,
        aggregatedSignature,
        attestedAt: new Date().toISOString(),
      };

      return reply.status(200).send(attestation);
    }
  );

  await app.listen({ port: 0, host: '127.0.0.1' });
  return (app.server.address() as { port: number }).port;
}

describe('Committee Service Integration', () => {
  let baseUrl: string;

  beforeAll(async () => {
    port = await buildTestCommittee();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /api/info returns committee info', async () => {
    const res = await fetch(`${baseUrl}/api/info`);
    expect(res.status).toBe(200);
    const info = await res.json();
    expect(info.type).toBe('BLSThreshold');
    expect(info.threshold).toBe(THRESHOLD);
    expect(info.totalMembers).toBe(3);
    expect(info.members).toHaveLength(3);
    expect(info.groupKeyHash).toBe(groupKeyHash);
    expect(info.members[0].memberId).toBe(MEMBER_IDS[0]);
    expect(info.members[0].blsPublicKey).toHaveLength(96);
  });

  it('POST /api/attest accepts valid ZK proof (mock mode) and returns BLS attestation', async () => {
    const doc = {
      documentId: 'DOC-COMM-TEST-' + crypto.randomUUID(),
      holderDid: 'did:ublp:agent:committee-test',
      goodsDescription: 'Committee integration test goods',
    };
    const idHash = sha256Hash(doc.documentId);
    const docHash = sha256HashDocument(doc);
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);

    const pubKeyDer = crypto.createPublicKey(ministryKeys.publicKey)
      .export({ type: 'spki', format: 'der' }) as Buffer;
    const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
    const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

    const res = await fetch(`${baseUrl}/api/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBytes: sig,
        proofSystem: 'mock-ecdsa-p256',
        publicValues: {
          documentHash: docHash,
          documentIdHash: idHash,
          ministryPubKeyHash: pubKeyHash,
          holderPubKeyHash: 'aa'.repeat(32),
        },
        ministryPublicKey: ministryKeys.publicKey,
      }),
    });

    expect(res.status).toBe(200);
    const attestation: CommitteeAttestation = await res.json();
    expect(attestation.type).toBe('BLSThreshold');
    expect(attestation.threshold).toBe(THRESHOLD);
    expect(attestation.totalMembers).toBe(3);
    expect(attestation.groupKeyHash).toBe(groupKeyHash);
    expect(attestation.signerIds.length).toBeGreaterThanOrEqual(THRESHOLD);
    expect(attestation.aggregatedSignature).toBeTruthy();
    expect(attestation.aggregatedSignature).toHaveLength(192); // hex 96 bytes = 192 chars
  });

  it('POST /api/attest rejects invalid ZK proof', async () => {
    const res = await fetch(`${baseUrl}/api/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBytes: 'AAAA' + 'AA'.repeat(42) + '=',
        proofSystem: 'mock-ecdsa-p256',
        publicValues: {
          documentHash: '00'.repeat(32),
          documentIdHash: '11'.repeat(32),
          ministryPubKeyHash: '22'.repeat(32),
          holderPubKeyHash: '33'.repeat(32),
        },
        ministryPublicKey: ministryKeys.publicKey,
      }),
    });

    expect(res.status).toBe(400);
  });

  it('POST /api/attest BLS attestation is independently verifiable', async () => {
    const doc = {
      documentId: 'DOC-COMM-VERIFY-' + crypto.randomUUID(),
      holderDid: 'did:ublp:agent:verify',
    };
    const idHash = sha256Hash(doc.documentId);
    const docHash = sha256HashDocument(doc);
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);

    const pubKeyDer = crypto.createPublicKey(ministryKeys.publicKey)
      .export({ type: 'spki', format: 'der' }) as Buffer;
    const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
    const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

    const res = await fetch(`${baseUrl}/api/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBytes: sig,
        proofSystem: 'mock-ecdsa-p256',
        publicValues: {
          documentHash: docHash,
          documentIdHash: idHash,
          ministryPubKeyHash: pubKeyHash,
          holderPubKeyHash: 'bb'.repeat(32),
        },
        ministryPublicKey: ministryKeys.publicKey,
      }),
    });

    expect(res.status).toBe(200);
    const att: CommitteeAttestation = await res.json();

    // Verify BLS attestation independently
    const msgHex = combinedSignatureHash(docHash, idHash);
    const memberMap = new Map(committeeMembers.map((m) => [m.memberId, m.publicKey]));
    const signerPubs = att.signerIds.map((id) => memberMap.get(id)!);

    const { blsVerifyThreshold } = await import('../../shared/src/crypto/blsCrypto');
    const result = await blsVerifyThreshold(att.aggregatedSignature, msgHex, signerPubs, att.threshold);
    expect(result.valid).toBe(true);
  });

  it('POST /api/attest BLS attestation uses correct groupKeyHash', async () => {
    const doc = {
      documentId: 'DOC-COMM-GROUP-' + crypto.randomUUID(),
      holderDid: 'did:ublp:agent:group',
    };
    const idHash = sha256Hash(doc.documentId);
    const docHash = sha256HashDocument(doc);
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);

    const pubKeyDer = crypto.createPublicKey(ministryKeys.publicKey)
      .export({ type: 'spki', format: 'der' }) as Buffer;
    const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
    const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

    const res = await fetch(`${baseUrl}/api/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBytes: sig,
        proofSystem: 'mock-ecdsa-p256',
        publicValues: {
          documentHash: docHash,
          documentIdHash: idHash,
          ministryPubKeyHash: pubKeyHash,
          holderPubKeyHash: 'cc'.repeat(32),
        },
        ministryPublicKey: ministryKeys.publicKey,
      }),
    });

    expect(res.status).toBe(200);
    const att: CommitteeAttestation = await res.json();

    const recomputedHash = blsGroupKeyHash(committeeMembers.map((m) => m.publicKey));
    expect(att.groupKeyHash).toBe(recomputedHash);
    expect(att.groupKeyHash).toBe(groupKeyHash);
  });
});
