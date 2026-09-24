import crypto from 'crypto';
import path from 'path';
import {
  verifySignature,
  generateZKProof,
  holderProofHash,
  sha256Hash,
  sha256HashDocument,
  canonicalJson,
  PrivateInputs,
  PublicInputs,
  KeyPair,
  ZKProof,
  loadOrGenerateAgentKeys,
  createAgentServer,
  startAgentServer,
  openTransactionLog,
  logTransaction,
} from '@ublp/shared';
import {
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  CommitteeAttestation,
  L2SettleResponse,
} from '@ublp/zk-customs-types';

const app = createAgentServer();
const L2_VERIFIER_URL = process.env.L2_VERIFIER_URL ?? 'http://localhost:3003';
const COMMITTEE_URL = process.env.COMMITTEE_URL ?? 'http://localhost:3004';
const AGENT_DID = process.env.AGENT_DID ?? 'did:ublp:agent:default';
const AGENT_KEYS_PATH = path.join(__dirname, '..', 'data', 'agent-keypair.json');
const TRANSACTION_LOG_PATH = path.join(__dirname, '..', 'data', 'transactions.db');

/**
 * Reporting/accounting log — "how many verifications did we run, of what kind, this month"
 * (see AGENTS.md 5.24). Logs only metadata about the verification event (claim type, pass/
 * fail, references) — never the raw document content or the ZK proof bytes themselves. The
 * proof/document are ephemeral to the request; this is a durable, queryable record on top.
 */
const transactionLogDb = openTransactionLog(TRANSACTION_LOG_PATH);

function logVerificationEvent(
  documentId: string,
  action: 'customs-verified' | 'customs-verification-rejected',
  metadata: Record<string, unknown>
): void {
  logTransaction(transactionLogDb, { module: 'zk-customs', dealRef: documentId, action, metadata });
}

/**
 * K-3: The agent signs the VP with its own P-256 key.
 * Payload = SHA256(documentHash || documentIdHash || holderDid)
 * ZK circuit private input → never returned raw to L2.
 */
function signHolderProof(
  documentHash: string,
  documentIdHash: string,
  holderDid: string,
  agentPrivKey: string
): string {
  const payloadHex = holderProofHash(documentHash, documentIdHash, holderDid);
  const payload = Buffer.from(payloadHex, 'hex');
  return crypto
    .sign(null, payload, { key: agentPrivKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64');
}

/**
 * Submits the ZK proof to the Committee — the raw document is never shown.
 * The committee verifies the ZK proof → mathematical conviction → BLS signs.
 */
async function requestCommitteeAttestation(
  zkProof: ZKProof,
  publicInputs: PublicInputs,
  ministryPublicKey: string,
  ministryPubKeyHash: string
): Promise<CommitteeAttestation> {
  const body = {
    proofBytes: zkProof.ministrySignature,     // proof bytes (Groth16 or ECDSA sig)
    proofSystem: zkProof.proof_system,
    publicValues: {
      documentHash: publicInputs.documentHash,
      documentIdHash: publicInputs.documentIdHash,
      ministryPubKeyHash,
      holderPubKeyHash: zkProof.holderPubKeyHash,
    },
    ministryPublicKey,
  };

  const res = await fetch(`${COMMITTEE_URL}/api/attest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`[Committee] HTTP ${res.status}: ${text}`);
  }

  return res.json() as Promise<CommitteeAttestation>;
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface ProcessVCRequest {
  verifiableCredential: UBLPVerifiableCredential;
}

interface ProcessResult {
  presentation: UBLPVerifiablePresentation;
  l2Result: L2SettleResponse;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

async function buildServer(agentKeys: KeyPair): Promise<void> {
  app.post<{ Body: ProcessVCRequest }>(
    '/api/process',
    {
      schema: {
        body: {
          type: 'object',
          required: ['verifiableCredential'],
          properties: {
            verifiableCredential: {
              type: 'object',
              required: ['id', 'type', 'issuer', 'credentialSubject', 'proof'],
              properties: {
                id: { type: 'string' },
                type: { type: 'array' },
                issuer: { type: 'string' },
                issuanceDate: { type: 'string' },
                credentialSubject: {
                  type: 'object',
                  // documentHash / documentIdHash are no longer in the VC.
                  // The Agent computes them locally from rawDocument + documentId,
                  // and puts them only into the ZK publicValues — single source of truth.
                  required: ['documentId', 'rawDocument'],
                  properties: {
                    id: { type: 'string' },
                    documentId: { type: 'string', minLength: 1 },
                    rawDocument: { type: 'object' },
                  },
                },
                proof: {
                  type: 'object',
                  required: ['proofValue', 'ministryPublicKey'],
                  properties: {
                    proofValue: { type: 'string', minLength: 1 },
                    ministryPublicKey: { type: 'string', minLength: 1 },
                  },
                },
                // committeeAttestation is no longer in the VC — the committee verifies the agent's ZK proof
              },
            },
          },
          additionalProperties: false,
        },
      },
    },
    async (request, reply): Promise<ProcessResult> => {
      const { verifiableCredential: vc } = request.body;
      const { credentialSubject: cs, proof: vcProof } = vc;
      const holderDid = cs.id ?? AGENT_DID;

      console.log('[UBLP Agent] VC received. ID:', vc.id);
      console.log('[UBLP Agent] Issuer:', vc.issuer, '| Holder:', holderDid);

      // ── 1. Compute hashes locally — single source of truth: rawDocument + documentId ─
      // credentialSubject no longer carries documentHash / documentIdHash.
      // The Agent derives them from rawDocument; the Ministry's signature is over the same values.
      const rawDocument = cs.rawDocument as Record<string, unknown>;
      const documentHash = sha256HashDocument(rawDocument);  // domain: ublp-doc-v1:
      const documentIdHash = sha256Hash(cs.documentId);

      // ── 2. Verify the Ministry's VC signature ────────────────────────────────
      const isValid = verifySignature(rawDocument, vcProof.proofValue, vcProof.ministryPublicKey, documentIdHash);

      if (!isValid) {
        console.error('[UBLP Agent] ✗ VC signature INVALID.');
        logVerificationEvent(cs.documentId, 'customs-verification-rejected', { reason: 'invalid-ministry-signature' });
        return reply.status(400).send({ error: 'Ministry VC signature could not be verified.' }) as never;
      }
      console.log('[UBLP Agent] ✓ VC signature valid.');

      // ── 3. K-3: Holder signature — ZK circuit private input ──────────────────
      const holderSignature = signHolderProof(documentHash, documentIdHash, holderDid, agentKeys.privateKey);
      console.log('[UBLP Agent] Holder signature produced (ZK private input).');

      // ── 4. Produce ZK Proof ────────────────────────────────────────────────────
      const privateInputs: PrivateInputs = {
        rawDocument,
        salt: '',
        signature: vcProof.proofValue,
        holderSignature,
        holderPublicKey: agentKeys.publicKey,
        holderDid,
      };
      const publicInputs: PublicInputs = {
        documentHash,     // computed locally — not cs.documentHash
        ministryPublicKey: vcProof.ministryPublicKey,
        documentIdHash,   // computed locally — not cs.documentIdHash
      };

      console.log('[UBLP Agent] Producing ZK Proof...');
      const zkProof = await generateZKProof(privateInputs, publicInputs);
      console.log('[UBLP Agent] ✓ ZK Proof produced. system:', zkProof.proof_system);
      console.log('[UBLP Agent] holderPubKeyHash:', zkProof.holderPubKeyHash.slice(0, 16) + '…');

      // ── 5. pubKeyHash: SHA256(ministry uncompressed P-256 raw bytes) ──────────
      const pubKeyDer = crypto.createPublicKey(vcProof.ministryPublicKey)
        .export({ type: 'spki', format: 'der' }) as Buffer;
      const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
      const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

      // ── 6. Submit the ZK proof to the committee — the raw document is never shown (trade secret) ──
      // The committee verifies the ZK proof → mathematically convinced → BLS signs.
      // No more "blind" signing.
      console.log('[UBLP Agent] Submitting ZK proof to the committee →', COMMITTEE_URL);
      let committeeAttestation: CommitteeAttestation;
      try {
        committeeAttestation = await requestCommitteeAttestation(
          zkProof,
          publicInputs,
          vcProof.ministryPublicKey,
          pubKeyHash
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[UBLP Agent] ✗ Committee attestation failed:', msg);
        logVerificationEvent(cs.documentId, 'customs-verification-rejected', { reason: 'committee-attestation-failed', detail: msg });
        return reply.status(502).send({ error: 'Committee could not verify the ZK proof.', detail: msg }) as never;
      }
      console.log('[UBLP Agent] ✓ Committee BLS attestation received. signers:', committeeAttestation.signerIds.length);

      // ── 7. Minimal VC copy for the VP ────────────────────────────────────────
      //
      // credentialSubject: only { id, documentId } — NO hashes.
      // documentHash / documentIdHash are now read ONLY from proof.publicValues.
      // rawDocument removed (OPEN-2) — L2 never sees the document contents.
      //
      // In SP1 mode, proofValue (the raw ECDSA signature) must not be carried in the VP.
      // The signature was consumed as a Groth16 circuit private input.
      // In mock mode, proofValue isn't needed for L2 verify since there's no ZK
      // (L2 already uses vp.proof.proofBytes, it doesn't look at vc.proof.proofValue).
      const isZKMode = zkProof.proof_system.startsWith('sp1');
      const vcForVP: UBLPVerifiableCredential = {
        ...vc,
        credentialSubject: {
          id: holderDid,
          documentId: cs.documentId,
          // documentHash REMOVED — fingerprint leak, already in publicValues
          // documentIdHash REMOVED — same reason
          // rawDocument REMOVED — OPEN-2
        },
        proof: {
          ...vcProof,
          proofValue: isZKMode ? '' : vcProof.proofValue,
        },
      };

      // ── 9. Verifiable Presentation ───────────────────────────────────────────
      // committeeAttestation lives inside the VP proof — no longer in the VC.
      // K-3: holderSignature / holderPublicKey do NOT go into the VP.
      // publicValues = single source of truth: L2 and Committee read from here.
      const presentation: UBLPVerifiablePresentation = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://ublp.io/vc/v1',
        ],
        type: ['VerifiablePresentation', 'UBLPZKPresentation'],
        holder: holderDid,
        verifiableCredential: [vcForVP],
        proof: {
          type: zkProof.proof_system.startsWith('sp1') ? 'SP1ZKProof' : 'MockECDSAProof',
          created: new Date().toISOString(),
          proofPurpose: 'authentication',
          proofSystem: zkProof.proof_system,
          publicValues: {
            documentHash,      // computed locally — single source of truth
            pubKeyHash,
            documentIdHash,    // computed locally — single source of truth
            holderPubKeyHash: zkProof.holderPubKeyHash,
          },
          proofBytes: zkProof.ministrySignature,
          ministryPublicKey: vcProof.ministryPublicKey,
          committeeAttestation,                          // carried inside the VP proof
        },
      };

      // ── 10. Send to L2 ───────────────────────────────────────────────────────
      console.log('[UBLP Agent] Sending VP to L2 →', L2_VERIFIER_URL);

      let l2Response: Response;
      let l2Result: L2SettleResponse;

      try {
        l2Response = await fetch(`${L2_VERIFIER_URL}/api/verify-and-settle`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ presentation }),
        });
        l2Result = await l2Response.json() as L2SettleResponse;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[UBLP Agent] ✗ Could not reach L2 Verifier:', msg);
        logVerificationEvent(cs.documentId, 'customs-verification-rejected', { reason: 'l2-unreachable', detail: msg });
        return reply.status(503).send({ error: 'Could not reach the L2 Verifier service.', detail: msg }) as never;
      }

      if (!l2Response.ok) {
        console.error('[UBLP Agent] ✗ L2 rejected:', l2Result);
        logVerificationEvent(cs.documentId, 'customs-verification-rejected', { reason: 'l2-rejected', l2Result });
        return reply.status(502).send({ error: 'L2 Verifier did not approve.', detail: l2Result }) as never;
      }

      console.log('[UBLP Agent] ✓ L2 approved. Status:', l2Result.status);
      logVerificationEvent(cs.documentId, 'customs-verified', {
        proofSystem: zkProof.proof_system,
        l2Status: l2Result.status,
        issuer: vc.issuer,
        holderDid,
      });
      return { presentation, l2Result };
    }
  );
}

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  const agentKeys = await loadOrGenerateAgentKeys(AGENT_KEYS_PATH, 'UBLP Agent');
  await buildServer(agentKeys);
  await startAgentServer(app, { port: 3002, host: '0.0.0.0' });
  console.log('[UBLP Agent] ✓ UBLP Agent — http://localhost:3002');
  console.log('[UBLP Agent] DID:', AGENT_DID);
  console.log('[UBLP Agent] Mode: ZK proof → Committee verify → BLS → L2');
};

start().catch((err) => {
  console.error('[UBLP Agent] Startup error:', err);
  process.exit(1);
});
