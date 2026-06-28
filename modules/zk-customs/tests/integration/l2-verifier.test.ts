import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { Mutex } from 'async-mutex';
import {
  generateKeyPair,
  signDocument,
  sha256HashDocument,
  sha256Hash,
  verifySignatureOverHash,
  combinedSignatureHash,
  verifySignature,
  UBLPVerifiablePresentation,
  UBLPVerifiableCredential,
  CommitteeAttestation,
  L2SettleRecord,
  L2SettleResponse,
  l2verifier as l2Module,
} from '../../shared/src/crypto/mockCrypto';

import type { blsVerifyThreshold, blsGroupKeyHash } from '../../shared/src/crypto/blsCrypto';

const ministryKeys = generateKeyPair();
const unauthorizedKeys = generateKeyPair();
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'l2-test-'));

let app: ReturnType<typeof Fastify>;
let port: number;
let baseUrl: string;

// Minimal L2 Verifier for integration testing
async function buildTestL2Verifier() {
  app = Fastify({ logger: false });

  const dbPath = path.join(TEST_DB_DIR, 'settled.json');
  const revokedPath = path.join(TEST_DB_DIR, 'revoked_keys.json');
  const dbMutex = new Mutex();

  const authorizedKeys: Set<string> = new Set([ministryKeys.publicKey]);
  const revokedKeys: Map<string, string> = new Map();

  app.post('/api/sync', async () => ({ success: true }));

  app.post<{ Body: { presentation: UBLPVerifiablePresentation } }>(
    '/api/verify-and-settle',
    async (request, reply) => {
      const { presentation } = request.body;
      const vpProof = presentation.proof;
      const vc = presentation.verifiableCredential[0];
      const cs = vc.credentialSubject;

      const ministryPublicKey = vpProof.ministryPublicKey;
      const documentHash = vpProof.publicValues.documentHash;
      const documentIdHash = vpProof.publicValues.documentIdHash;
      const holderPubKeyHash = vpProof.publicValues.holderPubKeyHash;

      if (!authorizedKeys.has(ministryPublicKey)) {
        return reply.status(403).send({ error: 'Yetkisiz Bakanlik public key.' });
      }
      if (revokedKeys.has(ministryPublicKey)) {
        return reply.status(403).send({ error: 'Bakanlik anahtari iptal edilmis.' });
      }

      if (cs.rawDocument !== undefined) {
        return reply.status(400).send({ error: 'VP rawDocument iceremez.' });
      }
      if (!holderPubKeyHash || holderPubKeyHash.length !== 64) {
        return reply.status(400).send({ error: 'holderPubKeyHash gecersiz.' });
      }

      const combined = combinedSignatureHash(documentHash, documentIdHash);
      const proofValid = verifySignatureOverHash(combined, vpProof.proofBytes, ministryPublicKey);
      if (!proofValid) {
        return reply.status(400).send({ error: 'Proof/imza dogrulamasi basarisiz.' });
      }

      return await dbMutex.runExclusive(async () => {
        const db: L2SettleRecord[] = fs.existsSync(dbPath)
          ? JSON.parse(fs.readFileSync(dbPath, 'utf8'))
          : [];

        const duplicate = db.find((r) => r.documentIdHash === documentIdHash);
        if (duplicate) {
          return reply.status(409).send({ error: 'Belge zaten onaylanmis.', record: duplicate });
        }

        const record: L2SettleRecord = {
          documentHash,
          documentIdHash,
          ministryPublicKeyHash: sha256Hash(ministryPublicKey),
          holderDid: presentation.holder,
          status: 'ONAYLANDI',
          settledAt: new Date().toISOString(),
          proofSystem: vpProof.proofSystem,
        };

        db.push(record);
        fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));

        const response: L2SettleResponse = { status: 'ONAYLANDI', record };
        return reply.status(200).send(response);
      });
    }
  );

  app.post<{ Body: { ministryPublicKey: string; compromisedAt?: string } }>(
    '/api/revoke-key',
    async (request, reply) => {
      const { ministryPublicKey, compromisedAt } = request.body;
      if (!authorizedKeys.has(ministryPublicKey)) {
        return reply.status(404).send({ error: 'Bu public key yetkili listede degil.' });
      }
      const revokedAt = compromisedAt ?? new Date().toISOString();
      revokedKeys.set(ministryPublicKey, revokedAt);
      const entries = [...revokedKeys.entries()].map(([pem, t]) => ({ pem, revokedAt: t }));
      fs.writeFileSync(revokedPath, JSON.stringify(entries, null, 2));

      const keyHash = sha256Hash(ministryPublicKey);
      return reply.status(200).send({
        revoked: true,
        compromisedAt: revokedAt,
        ministryPublicKeyHash: keyHash,
        suspiciousRecords: 0,
      });
    }
  );

  app.get('/api/records', async () => {
    if (!fs.existsSync(dbPath)) return [];
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  });

  await app.listen({ port: 0, host: '127.0.0.1' });
  return (app.server.address() as { port: number }).port;
}

function makeSamplePresentation(overrides?: {
  customSig?: string;
  customPubKey?: string;
  includeRawDoc?: boolean;
  invalidHolderHash?: boolean;
  docIdHash?: string;
}): UBLPVerifiablePresentation {
  const doc = {
    documentId: 'DOC-L2-TEST-' + crypto.randomUUID(),
    holderDid: 'did:ublp:agent:l2-test',
    goodsDescription: 'L2 Integration Test Goods',
  };
  const docIdHash = overrides?.docIdHash ?? sha256Hash(doc.documentId);
  const sig = overrides?.customSig ?? signDocument(doc, ministryKeys.privateKey, docIdHash);
  const pubKey = overrides?.customPubKey ?? ministryKeys.publicKey;

  const docHash = sha256HashDocument(doc);
  const pubKeyDer = crypto.createPublicKey(pubKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
  const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

  const cs: Record<string, unknown> = { id: 'did:ublp:agent:l2-test', documentId: doc.documentId };
  if (overrides?.includeRawDoc) {
    cs.rawDocument = doc;
  }

  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation', 'UBLPZKPresentation'],
    holder: 'did:ublp:agent:l2-test',
    verifiableCredential: [{
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: `urn:ublp:vc:${doc.documentId}`,
      type: ['VerifiableCredential', 'UBLPCustomsCredential'],
      issuer: 'did:ublp:ministry',
      issuanceDate: new Date().toISOString(),
      credentialSubject: cs,
      proof: {
        type: 'EcdsaSecp256r1Signature2019',
        created: new Date().toISOString(),
        verificationMethod: 'did:ublp:ministry#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: sig,
        ministryPublicKey: pubKey,
      },
    }],
    proof: {
      type: 'MockECDSAProof',
      created: new Date().toISOString(),
      proofPurpose: 'authentication',
      proofSystem: 'mock-ecdsa-p256',
      publicValues: {
        documentHash: docHash,
        pubKeyHash,
        documentIdHash: docIdHash,
        holderPubKeyHash: overrides?.invalidHolderHash ? '00'.repeat(31) : 'aa'.repeat(32),
      },
      proofBytes: sig,
      ministryPublicKey: pubKey,
      committeeAttestation: {
        type: 'BLSThreshold',
        threshold: 2,
        totalMembers: 3,
        groupKeyHash: 'test-group-hash',
        signerIds: ['member-1', 'member-2'],
        aggregatedSignature: 'test-agg-sig',
        attestedAt: new Date().toISOString(),
      },
    },
  };
}

describe('L2 Verifier Integration', () => {
  beforeAll(async () => {
    port = await buildTestL2Verifier();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  });

  it('POST /api/verify-and-settle approves valid presentation', async () => {
    const vp = makeSamplePresentation();
    const res = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp }),
    });

    expect(res.status).toBe(200);
    const result: L2SettleResponse = await res.json();
    expect(result.status).toBe('ONAYLANDI');
    expect(result.record.documentHash).toBe(vp.proof.publicValues.documentHash);
    expect(result.record.status).toBe('ONAYLANDI');
  });

  it('POST /api/verify-and-settle rejects replay (same documentIdHash)', async () => {
    const docIdHash = sha256Hash('DOC-REPLAY-' + crypto.randomUUID());
    const vp1 = makeSamplePresentation({ docIdHash });
    const res1 = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp1 }),
    });
    expect(res1.status).toBe(200);

    const vp2 = makeSamplePresentation({ docIdHash });
    const res2 = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp2 }),
    });
    expect(res2.status).toBe(409);
    const err = await res2.json();
    expect(err.error).toContain('onaylanm');
  });

  it('POST /api/verify-and-settle rejects unauthorized ministry key', async () => {
    const unauthorizedSig = signDocument(
      { documentId: 'DOC-UNAUTH', test: true },
      unauthorizedKeys.privateKey,
      sha256Hash('DOC-UNAUTH')
    );
    const vp = makeSamplePresentation({ customSig: unauthorizedSig, customPubKey: unauthorizedKeys.publicKey });
    const res = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp }),
    });

    expect(res.status).toBe(403);
  });

  it('POST /api/verify-and-settle rejects invalid proof signature', async () => {
    const vp = makeSamplePresentation({ customSig: 'AAAA' + 'AA'.repeat(42) + '=' });
    const res = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp }),
    });

    expect(res.status).toBe(400);
    const err = await res.json();
    expect(err.error).toContain('basari');
  });

  it('POST /api/verify-and-settle rejects VP with rawDocument', async () => {
    const vp = makeSamplePresentation({ includeRawDoc: true });
    const res = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp }),
    });

    expect(res.status).toBe(400);
    const err = await res.json();
    expect(err.error).toContain('rawDocument');
  });

  it('POST /api/verify-and-settle rejects invalid holderPubKeyHash length', async () => {
    const vp = makeSamplePresentation({ invalidHolderHash: true });
    const res = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp }),
    });

    expect(res.status).toBe(400);
  });

  it('POST /api/revoke-key revokes a key and subsequent submissions fail', async () => {
    const vp1 = makeSamplePresentation();
    const res1 = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp1 }),
    });
    expect(res1.status).toBe(200);

    const revokeRes = await fetch(`${baseUrl}/api/revoke-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ministryPublicKey: ministryKeys.publicKey }),
    });
    expect(revokeRes.status).toBe(200);
    const revokeResult = await revokeRes.json();
    expect(revokeResult.revoked).toBe(true);

    const vp2 = makeSamplePresentation();
    const res2 = await fetch(`${baseUrl}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: vp2 }),
    });
    expect(res2.status).toBe(403);
  });

  it('GET /api/records returns all settled records', async () => {
    const recordsRes = await fetch(`${baseUrl}/api/records`);
    expect(recordsRes.status).toBe(200);
    const records: L2SettleRecord[] = await recordsRes.json();
    expect(Array.isArray(records)).toBe(true);
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) {
      expect(r.documentHash).toHaveLength(64);
      expect(r.documentIdHash).toHaveLength(64);
      expect(r.status).toMatch(/^(ONAYLANDI|REDDEDILDI|SUSPICIOUS)$/);
    }
  });
});
