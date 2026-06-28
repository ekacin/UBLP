import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'crypto';
import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Mutex } from 'async-mutex';

import {
  generateKeyPair,
  signDocument,
  verifySignature,
  verifySignatureOverHash,
  sha256HashDocument,
  sha256Hash,
  combinedSignatureHash,
  holderProofHash,
  canonicalJson,
  generateMockZKProof,
  PrivateInputs,
  PublicInputs,
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  CommitteeAttestation,
  L2SettleRecord,
  L2SettleResponse,
} from '../../shared/src/crypto/mockCrypto';
import {
  blsGenerateKeyPair,
  blsSign,
  blsVerify,
  blsAggregateSignatures,
  blsAggregatePublicKeys,
  blsGroupKeyHash,
  blsVerifyThreshold,
} from '../../shared/src/crypto/blsCrypto';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const ministryKeys = generateKeyPair();
const agentKeys = generateKeyPair();
const MINISTRY_DID = 'did:ublp:ministry:e2e';
const AGENT_DID = 'did:ublp:agent:e2e';
const THRESHOLD = 2;
const TOTAL_MEMBERS = 3;

const committeeMembers = Array.from({ length: TOTAL_MEMBERS }, (_, i) => ({
  memberId: `did:ublp:committee:member-${i + 1}`,
  ...blsGenerateKeyPair(),
}));

const committeeGroupKeyHash = blsGroupKeyHash(committeeMembers.map(m => m.publicKey));

// ─── Services ─────────────────────────────────────────────────────────────────

interface Services {
  ministry: { app: ReturnType<typeof Fastify>; port: number };
  agent: { app: ReturnType<typeof Fastify>; port: number };
  l2: { app: ReturnType<typeof Fastify>; port: number };
}

async function buildMinistry(): Promise<{ app: ReturnType<typeof Fastify>; port: number }> {
  const app = Fastify({ logger: false });

  app.get('/api/public-key', async () => ({
    ministryPublicKey: ministryKeys.publicKey,
    did: MINISTRY_DID,
  }));

  app.post<{ Body: Record<string, unknown> }>('/api/approve', async (request, reply) => {
    const doc = request.body;
    const documentId = doc['documentId'] as string;
    const holderDid = (doc['holderDid'] as string) ?? AGENT_DID;
    const documentHash = sha256HashDocument(doc);
    const documentIdHash = sha256Hash(documentId);
    const signature = signDocument(doc, ministryKeys.privateKey, documentIdHash);

    const vc: UBLPVerifiableCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ublp.io/vc/v1'],
      id: `urn:ublp:vc:${documentId}`,
      type: ['VerifiableCredential', 'UBLPCustomsCredential'],
      issuer: MINISTRY_DID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: { id: holderDid, documentId, rawDocument: doc },
      proof: {
        type: 'EcdsaSecp256r1Signature2019',
        created: new Date().toISOString(),
        verificationMethod: `${MINISTRY_DID}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: signature,
        ministryPublicKey: ministryKeys.publicKey,
      },
    };
    return reply.status(200).send(vc);
  });

  await app.listen({ port: 0, host: '127.0.0.1' });
  return { app, port: (app.server.address() as { port: number }).port };
}

async function buildAgent(ministryUrl: string): Promise<{ app: ReturnType<typeof Fastify>; port: number }> {
  const app = Fastify({ logger: false });

  app.post<{ Body: { verifiableCredential: UBLPVerifiableCredential } }>(
    '/api/process',
    async (request, reply) => {
      const { verifiableCredential: vc } = request.body;
      const cs = vc.credentialSubject;
      const holderDid = cs.id ?? AGENT_DID;
      const rawDocument = cs.rawDocument as Record<string, unknown>;
      const documentHash = sha256HashDocument(rawDocument);
      const documentIdHash = sha256Hash(cs.documentId);

      const isValid = verifySignature(rawDocument, vc.proof.proofValue, vc.proof.ministryPublicKey, documentIdHash);
      if (!isValid) {
        return reply.status(400).send({ error: 'Bakanlik VC imzasi dogrulanamadi.' });
      }

      const payloadHex = holderProofHash(documentHash, documentIdHash, holderDid);
      const payload = Buffer.from(payloadHex, 'hex');
      const holderSignature = crypto.sign(null, payload, { key: agentKeys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');

      const privateInputs: PrivateInputs = {
        rawDocument, salt: '', signature: vc.proof.proofValue,
        holderSignature, holderPublicKey: agentKeys.publicKey, holderDid,
      };
      const publicInputs: PublicInputs = {
        documentHash, ministryPublicKey: vc.proof.ministryPublicKey, documentIdHash,
      };

      const zkProof = generateMockZKProof(privateInputs, publicInputs);
      if (zkProof.status !== 'verified') {
        return reply.status(400).send({ error: 'ZK proof basarisiz.' });
      }

      const pubKeyDer = crypto.createPublicKey(vc.proof.ministryPublicKey)
        .export({ type: 'spki', format: 'der' }) as Buffer;
      const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
      const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

      // Committee attestation (simulated)
      const msgHex = combinedSignatureHash(documentHash, documentIdHash);
      const partialSigs: string[] = [];
      const signerIds: string[] = [];
      for (let i = 0; i < THRESHOLD; i++) {
        const sig = await blsSign(msgHex, committeeMembers[i].privateKey);
        partialSigs.push(sig);
        signerIds.push(committeeMembers[i].memberId);
      }
      const aggSig = blsAggregateSignatures(partialSigs);

      const committeeAttestation: CommitteeAttestation = {
        type: 'BLSThreshold',
        threshold: THRESHOLD,
        totalMembers: TOTAL_MEMBERS,
        groupKeyHash: committeeGroupKeyHash,
        signerIds,
        aggregatedSignature: aggSig,
        attestedAt: new Date().toISOString(),
      };

      const vcForVP: UBLPVerifiableCredential = {
        ...vc,
        credentialSubject: { id: holderDid, documentId: cs.documentId },
        proof: { ...vc.proof, proofValue: '' },
      };

      const presentation: UBLPVerifiablePresentation = {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ublp.io/vc/v1'],
        type: ['VerifiablePresentation', 'UBLPZKPresentation'],
        holder: holderDid,
        verifiableCredential: [vcForVP],
        proof: {
          type: 'MockECDSAProof',
          created: new Date().toISOString(),
          proofPurpose: 'authentication',
          proofSystem: zkProof.proof_system,
          publicValues: { documentHash, pubKeyHash, documentIdHash, holderPubKeyHash: zkProof.holderPubKeyHash },
          proofBytes: zkProof.ministrySignature,
          ministryPublicKey: vc.proof.ministryPublicKey,
          committeeAttestation,
        },
      };

      return reply.status(200).send({ presentation });
    }
  );

  await app.listen({ port: 0, host: '127.0.0.1' });
  return { app, port: (app.server.address() as { port: number }).port };
}

async function buildL2Verifier(): Promise<{ app: ReturnType<typeof Fastify>; port: number }> {
  const app = Fastify({ logger: false });
  const dbPath = path.join(os.tmpdir(), 'e2e-settled.json');
  const dbMutex = new Mutex();
  const authorizedKeys = new Set<string>([ministryKeys.publicKey]);
  const revokedKeys = new Map<string, string>();

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

      // 0. Whitelist
      if (!authorizedKeys.has(ministryPublicKey)) {
        return reply.status(403).send({ error: 'Yetkisiz Bakanlik public key.' });
      }
      if (revokedKeys.has(ministryPublicKey)) {
        return reply.status(403).send({ error: 'Bakanlik anahtari iptal edilmis.' });
      }

      // 1. rawDocument check
      if (cs.rawDocument !== undefined) {
        return reply.status(400).send({ error: 'VP rawDocument iceremez.' });
      }

      // 2. holderPubKeyHash
      if (!holderPubKeyHash || holderPubKeyHash.length !== 64) {
        return reply.status(400).send({ error: 'holderPubKeyHash gecersiz.' });
      }

      // 3. BLS committee attestation verification
      const committeeAtt = vpProof.committeeAttestation;
      if (committeeAtt.groupKeyHash !== committeeGroupKeyHash) {
        return reply.status(400).send({ error: 'groupKeyHash uyusmazligi.' });
      }

      const memberMap = new Map(committeeMembers.map(m => [m.memberId, m.publicKey]));
      const signerPubs = committeeAtt.signerIds.map(id => memberMap.get(id)!);
      const msgHex = combinedSignatureHash(documentHash, documentIdHash);
      const blsResult = await blsVerifyThreshold(committeeAtt.aggregatedSignature, msgHex, signerPubs, committeeAtt.threshold);
      if (!blsResult.valid) {
        return reply.status(400).send({ error: `BLS gecersiz: ${blsResult.reason}` });
      }

      // 4. ZK proof verification (mock mode)
      const proofValid = verifySignatureOverHash(
        combinedSignatureHash(documentHash, documentIdHash),
        vpProof.proofBytes,
        ministryPublicKey
      );
      if (!proofValid) {
        return reply.status(400).send({ error: 'Proof dogrulamasi basarisiz.' });
      }

      // 5. Replay protection
      return await dbMutex.runExclusive(async () => {
        const db: L2SettleRecord[] = fs.existsSync(dbPath)
          ? JSON.parse(fs.readFileSync(dbPath, 'utf8'))
          : [];

        const duplicate = db.find(r => r.documentIdHash === documentIdHash);
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

        return reply.status(200).send({ status: 'ONAYLANDI' as const, record });
      });
    }
  );

  await app.listen({ port: 0, host: '127.0.0.1' });
  return { app, port: (app.server.address() as { port: number }).port };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('E2E: Complete Customs Clearance Flow', () => {
  let services: Services;
  let l2DbPath: string;

  beforeAll(async () => {
    const ministry = await buildMinistry();
    const l2 = await buildL2Verifier();
    const agent = await buildAgent(`http://127.0.0.1:${ministry.port}`);
    services = { ministry, agent, l2 };
    l2DbPath = path.join(os.tmpdir(), 'e2e-settled.json');
  });

  afterAll(async () => {
    await services.ministry.app.close();
    await services.agent.app.close();
    await services.l2.app.close();
    if (fs.existsSync(l2DbPath)) fs.unlinkSync(l2DbPath);
  });

  it('1. Broker creates document → Ministry signs → VC received', async () => {
    const doc = {
      documentId: 'DOC-E2E-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
      exporterName: 'E2E Test Corp.',
      goodsDescription: 'E2E Full Flow Test',
      totalValue: '75000 USD',
      hsCode: '8471.50',
    };

    const vcRes = await fetch(`http://127.0.0.1:${services.ministry.port}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });
    expect(vcRes.status).toBe(200);
    const vc: UBLPVerifiableCredential = await vcRes.json();

    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.issuer).toBe(MINISTRY_DID);
    expect(vc.credentialSubject.documentId).toBe(doc.documentId);
    expect(vc.proof.proofValue).toBeTruthy();

    // Verify signature independently
    const documentIdHash = sha256Hash(doc.documentId);
    const sigValid = verifySignature(doc, vc.proof.proofValue, vc.proof.ministryPublicKey, documentIdHash);
    expect(sigValid).toBe(true);

    const committeeAtt = (vc as Record<string, unknown>).committeeAttestation;
    expect(committeeAtt).toBeUndefined();
  });

  it('2. Agent processes VC → ZK proof → Committee BLS → VP constructed', async () => {
    const doc = {
      documentId: 'DOC-E2E-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
      exporterName: 'E2E Flow Test',
    };

    const vcRes = await fetch(`http://127.0.0.1:${services.ministry.port}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });
    const vc: UBLPVerifiableCredential = await vcRes.json();

    const agentRes = await fetch(`http://127.0.0.1:${services.agent.port}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });
    expect(agentRes.status).toBe(200);
    const result = await agentRes.json();
    const pres: UBLPVerifiablePresentation = result.presentation;

    // VP structure checks
    expect(pres.type).toContain('VerifiablePresentation');
    expect(pres.type).toContain('UBLPZKPresentation');
    expect(pres.holder).toBe(AGENT_DID);

    // VC in VP should NOT have rawDocument
    expect(pres.verifiableCredential[0].credentialSubject.rawDocument).toBeUndefined();

    // Proof structure
    expect(pres.proof.publicValues.documentHash).toHaveLength(64);
    expect(pres.proof.publicValues.holderPubKeyHash).toHaveLength(64);
    expect(pres.proof.publicValues.pubKeyHash).toHaveLength(64);
    expect(pres.proof.publicValues.documentIdHash).toHaveLength(64);

    // Committee attestation
    expect(pres.proof.committeeAttestation.type).toBe('BLSThreshold');
    expect(pres.proof.committeeAttestation.signerIds.length).toBeGreaterThanOrEqual(THRESHOLD);
    expect(pres.proof.committeeAttestation.groupKeyHash).toBe(committeeGroupKeyHash);

    // Verify BLS threshold on attestation
    const att = pres.proof.committeeAttestation;
    const msgHex = combinedSignatureHash(pres.proof.publicValues.documentHash, pres.proof.publicValues.documentIdHash);
    const memberMap = new Map(committeeMembers.map(m => [m.memberId, m.publicKey]));
    const signerPubs = att.signerIds.map(id => memberMap.get(id)!);
    const blsResult = await blsVerifyThreshold(att.aggregatedSignature, msgHex, signerPubs, att.threshold);
    expect(blsResult.valid).toBe(true);
  });

  it('3. Full flow: Broker → Ministry → Agent → L2 settle (mocked committee)', async () => {
    const doc = {
      documentId: 'DOC-E2E-FULL-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
      exporterName: 'Full Flow Test Inc.',
      goodsDescription: 'Complete E2E test from broker to L2 settlement',
      hsCode: '8471.30',
      totalValue: '100000 USD',
    };

    // Step 1: Ministry approves
    const vcRes = await fetch(`http://127.0.0.1:${services.ministry.port}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });
    expect(vcRes.status).toBe(200);
    const vc: UBLPVerifiableCredential = await vcRes.json();

    // Step 2: Agent processes → gets VP with committee attestation
    const agentRes = await fetch(`http://127.0.0.1:${services.agent.port}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });
    expect(agentRes.status).toBe(200);
    const agentResult = await agentRes.json();
    const presentation: UBLPVerifiablePresentation = agentResult.presentation;

    // Step 3: L2 verifies and settles
    const l2Res = await fetch(`http://127.0.0.1:${services.l2.port}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation }),
    });
    expect(l2Res.status).toBe(200);
    const l2Result: L2SettleResponse = await l2Res.json();
    expect(l2Result.status).toBe('ONAYLANDI');
    expect(l2Result.record.documentHash).toBe(presentation.proof.publicValues.documentHash);
    expect(l2Result.record.documentIdHash).toBe(presentation.proof.publicValues.documentIdHash);
    expect(l2Result.record.proofSystem).toBe('mock-ecdsa-p256');
  });

  it('4. L2 rejects replay of same documentIdHash', async () => {
    const doc = {
      documentId: 'DOC-E2E-REPLAY-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
      exporterName: 'Replay Test',
    };

    // Approve + process once
    const vcRes = await fetch(`http://127.0.0.1:${services.ministry.port}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });
    const vc: UBLPVerifiableCredential = await vcRes.json();

    const agentRes = await fetch(`http://127.0.0.1:${services.agent.port}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });
    const agentResult = await agentRes.json();

    // First settle should work
    const l2Res1 = await fetch(`http://127.0.0.1:${services.l2.port}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: agentResult.presentation }),
    });
    expect(l2Res1.status).toBe(200);

    // Second settle with same VP should fail (replay)
    const l2Res2 = await fetch(`http://127.0.0.1:${services.l2.port}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentation: agentResult.presentation }),
    });
    expect(l2Res2.status).toBe(409);
  });

  it('5. BLS committee attestation is independently verifiable', async () => {
    const doc = {
      documentId: 'DOC-E2E-BLS-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
    };

    const vcRes = await fetch(`http://127.0.0.1:${services.ministry.port}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });
    const vc: UBLPVerifiableCredential = await vcRes.json();

    const agentRes = await fetch(`http://127.0.0.1:${services.agent.port}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });
    const agentResult = await agentRes.json();
    const att: CommitteeAttestation = agentResult.presentation.proof.committeeAttestation;

    // Verify BLS threshold independently (as L2 would)
    const docHash = agentResult.presentation.proof.publicValues.documentHash;
    const idHash = agentResult.presentation.proof.publicValues.documentIdHash;
    const msgHex = combinedSignatureHash(docHash, idHash);

    const memberMap = new Map(committeeMembers.map(m => [m.memberId, m.publicKey]));
    const signerPubs = att.signerIds.map(id => memberMap.get(id)!);

    const blsResult = await blsVerifyThreshold(att.aggregatedSignature, msgHex, signerPubs, att.threshold);
    expect(blsResult.valid).toBe(true);

    const recomputedGroupHash = blsGroupKeyHash(committeeMembers.map(m => m.publicKey));
    expect(att.groupKeyHash).toBe(recomputedGroupHash);
    expect(att.groupKeyHash).toBe(committeeGroupKeyHash);
  });

  it('6. Holder identity privacy: raw key never leaves agent', async () => {
    const doc = {
      documentId: 'DOC-E2E-PRIVACY-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
    };

    const vcRes = await fetch(`http://127.0.0.1:${services.ministry.port}/api/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc),
    });
    const vc: UBLPVerifiableCredential = await vcRes.json();

    const agentRes = await fetch(`http://127.0.0.1:${services.agent.port}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });
    const result = await agentRes.json();
    const pres = result.presentation;

    // holderPubKeyHash is present (64-char hex)
    expect(pres.proof.publicValues.holderPubKeyHash).toHaveLength(64);

    // The VP JSON should not contain raw holder key or signature
    const vpJson = JSON.stringify(pres);
    expect(vpJson).not.toContain(agentKeys.publicKey);
    expect(vpJson).not.toContain('holderSignature');
  });
});
