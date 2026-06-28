import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import crypto from 'crypto';
import {
  generateKeyPair,
  signDocument,
  sha256HashDocument,
  sha256Hash,
  verifySignature,
  holderProofHash,
  canonicalJson,
  generateMockZKProof,
  PrivateInputs,
  PublicInputs,
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
} from '../../shared/src/crypto/mockCrypto';

const ministryKeys = generateKeyPair();
const agentKeys = generateKeyPair();
const AGENT_DID = 'did:ublp:agent:integration-test';
const MINISTRY_DID = 'did:ublp:ministry:integration';

let agentApp: ReturnType<typeof Fastify>;
let agentPort: number;

async function buildAgentServer() {
  agentApp = Fastify({ logger: false });

  agentApp.post<{ Body: { verifiableCredential: UBLPVerifiableCredential } }>(
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
        rawDocument,
        salt: '',
        signature: vc.proof.proofValue,
        holderSignature,
        holderPublicKey: agentKeys.publicKey,
        holderDid,
      };
      const publicInputs: PublicInputs = {
        documentHash,
        ministryPublicKey: vc.proof.ministryPublicKey,
        documentIdHash,
      };

      const zkProof = generateMockZKProof(privateInputs, publicInputs);

      if (zkProof.status !== 'verified') {
        return reply.status(400).send({ error: 'ZK proof basarisiz.' });
      }

      const pubKeyDer = crypto.createPublicKey(vc.proof.ministryPublicKey)
        .export({ type: 'spki', format: 'der' }) as Buffer;
      const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
      const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

      const mockCommitteeAttestation = {
        type: 'BLSThreshold' as const,
        threshold: 2,
        totalMembers: 3,
        groupKeyHash: 'mock-group-key-hash-' + sha256Hash('test'),
        signerIds: ['member-1', 'member-2'],
        aggregatedSignature: 'mock-agg-sig',
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
          publicValues: {
            documentHash,
            pubKeyHash,
            documentIdHash,
            holderPubKeyHash: zkProof.holderPubKeyHash,
          },
          proofBytes: zkProof.ministrySignature,
          ministryPublicKey: vc.proof.ministryPublicKey,
          committeeAttestation: mockCommitteeAttestation,
        },
      };

      return {
        presentation,
        l2Result: { status: 'ONAYLANDI' as const, record: null },
      };
    }
  );

  await agentApp.listen({ port: 0, host: '127.0.0.1' });
  return (agentApp.server.address() as { port: number }).port;
}

describe('Agent Service Integration', () => {
  beforeAll(async () => {
    agentPort = await buildAgentServer();
  });

  afterAll(async () => {
    await agentApp.close();
  });

  async function createValidVC(): Promise<UBLPVerifiableCredential> {
    const doc = {
      documentId: 'DOC-AGENT-TEST-' + crypto.randomUUID(),
      holderDid: AGENT_DID,
      exporterName: 'Agent Integration Test',
    };
    const documentIdHash = sha256Hash(doc.documentId);
    const signature = signDocument(doc, ministryKeys.privateKey, documentIdHash);
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ublp.io/vc/v1'],
      id: `urn:ublp:vc:${doc.documentId}`,
      type: ['VerifiableCredential', 'UBLPCustomsCredential'],
      issuer: MINISTRY_DID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: { id: AGENT_DID, documentId: doc.documentId, rawDocument: doc },
      proof: {
        type: 'EcdsaSecp256r1Signature2019',
        created: new Date().toISOString(),
        verificationMethod: `${MINISTRY_DID}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: signature,
        ministryPublicKey: ministryKeys.publicKey,
      },
    };
  }

  it('POST /api/process accepts valid VC and returns presentation', async () => {
    const vc = await createValidVC();
    const res = await fetch(`http://127.0.0.1:${agentPort}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });

    expect(res.status).toBe(200);
    const result = await res.json();
    expect(result.presentation).toBeDefined();
    expect(result.presentation.type).toContain('UBLPZKPresentation');
    expect(result.presentation.holder).toBe(AGENT_DID);
    expect(result.presentation.proof.publicValues.documentHash).toHaveLength(64);
    expect(result.presentation.proof.publicValues.holderPubKeyHash).toHaveLength(64);
    expect(result.presentation.proof.committeeAttestation).toBeDefined();
    expect(result.l2Result.status).toBe('ONAYLANDI');
  });

  it('POST /api/process removes rawDocument from VC in VP', async () => {
    const vc = await createValidVC();
    const res = await fetch(`http://127.0.0.1:${agentPort}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });

    const result = await res.json();
    const vcInVP = result.presentation.verifiableCredential[0];
    expect(vcInVP.credentialSubject.rawDocument).toBeUndefined();
    expect(vcInVP.credentialSubject.documentId).toBe(vc.credentialSubject.documentId);
  });

  it('POST /api/process rejects invalid VC signature', async () => {
    const vc = await createValidVC();
    vc.proof.proofValue = 'AAAA' + vc.proof.proofValue.slice(4);

    const res = await fetch(`http://127.0.0.1:${agentPort}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });

    expect(res.status).toBe(400);
  });

  it('POST /api/process computes correct holderPubKeyHash', async () => {
    const vc = await createValidVC();
    const res = await fetch(`http://127.0.0.1:${agentPort}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });

    const result = await res.json();

    const pubKeyDer = crypto.createPublicKey(agentKeys.publicKey)
      .export({ type: 'spki', format: 'der' }) as Buffer;
    const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
    const expectedHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

    expect(result.presentation.proof.publicValues.holderPubKeyHash).toBe(expectedHash);
  });
});
