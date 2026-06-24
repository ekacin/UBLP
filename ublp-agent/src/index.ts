import Fastify from 'fastify';
import {
  verifySignature,
  generateZKProof,
  PrivateInputs,
  PublicInputs,
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  L2SettleResponse,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const L2_VERIFIER_URL = process.env.L2_VERIFIER_URL ?? 'http://localhost:3003';
const AGENT_DID = process.env.AGENT_DID ?? 'did:ublp:agent:default';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ProcessVCRequest {
  verifiableCredential: UBLPVerifiableCredential;
}

interface ProcessResult {
  presentation: UBLPVerifiablePresentation;
  l2Result: L2SettleResponse;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

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
            required: ['id', 'type', 'issuer', 'credentialSubject', 'proof', 'committeeAttestation'],
            properties: {
              id: { type: 'string' },
              type: { type: 'array' },
              issuer: { type: 'string' },
              issuanceDate: { type: 'string' },
              credentialSubject: {
                type: 'object',
                required: ['documentId', 'documentHash', 'documentIdHash', 'rawDocument'],
                properties: {
                  id: { type: 'string' },
                  documentId: { type: 'string', minLength: 1 },
                  documentHash: { type: 'string', minLength: 1 },
                  documentIdHash: { type: 'string', minLength: 1 },
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
              committeeAttestation: {
                type: 'object',
                required: ['type', 'threshold', 'groupKeyHash', 'signatures'],
              },
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

    console.log('[UBLP Agent] VC alındı. ID:', vc.id);
    console.log('[UBLP Agent] Issuer:', vc.issuer, '| Holder:', cs.id ?? AGENT_DID);

    // ── 1. VC proof doğrulama (Bakanlık birleşik hash imzası) ────────────────
    // AÇIK-1 fix: verifySignature artık documentIdHash'i de parametre olarak alır.
    // Kombinasyon: SHA256(documentHash || documentIdHash)
    console.log('[UBLP Agent] Bakanlık VC imzası doğrulanıyor (combined hash)...');
    const rawDocument = cs.rawDocument as Record<string, unknown>;
    const isValid = verifySignature(
      rawDocument,
      vcProof.proofValue,
      vcProof.ministryPublicKey,
      cs.documentIdHash
    );

    if (!isValid) {
      console.error('[UBLP Agent] ✗ VC imzası GEÇERSİZ.');
      return reply.status(400).send({ error: 'Bakanlık VC imzası doğrulanamadı.' }) as never;
    }
    console.log('[UBLP Agent] ✓ VC imzası geçerli.');

    // ── 2. ZK Proof üret (SP1 veya mock) ────────────────────────────────────
    const privateInputs: PrivateInputs = {
      rawDocument,
      salt: '',
      signature: vcProof.proofValue,
    };
    const publicInputs: PublicInputs = {
      documentHash: cs.documentHash,
      ministryPublicKey: vcProof.ministryPublicKey,
      documentIdHash: cs.documentIdHash,
    };

    console.log('[UBLP Agent] ZK Proof üretiliyor...');
    const zkProof = await generateZKProof(privateInputs, publicInputs);
    console.log('[UBLP Agent] ZK Proof üretildi. system:', zkProof.proof_system);

    // ── 3. AÇIK-2 fix: VP için rawDocument'siz VC kopyası ───────────────────
    // rawDocument gizli ticari veri — L2'ye asla gönderilmez.
    // Agent kendi yerel deposunda VC'nin tam halini saklar (burada sadece loglanıyor).
    const vcForVP: UBLPVerifiableCredential = {
      ...vc,
      credentialSubject: {
        id: cs.id,
        documentId: cs.documentId,
        documentHash: cs.documentHash,
        documentIdHash: cs.documentIdHash,
        // rawDocument intentionally excluded — ZK proof gizliliği korur
      },
    };

    // ── 4. Verifiable Presentation oluştur ───────────────────────────────────
    const presentation: UBLPVerifiablePresentation = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://ublp.io/vc/v1',
      ],
      type: ['VerifiablePresentation', 'UBLPZKPresentation'],
      holder: cs.id ?? AGENT_DID,
      verifiableCredential: [vcForVP],
      proof: {
        type: zkProof.proof_system.startsWith('sp1') ? 'SP1ZKProof' : 'MockECDSAProof',
        created: new Date().toISOString(),
        proofPurpose: 'authentication',
        proofSystem: zkProof.proof_system,
        publicValues: {
          documentHash: cs.documentHash,
          pubKeyHash: '',
          documentIdHash: cs.documentIdHash,
        },
        proofBytes: zkProof.ministrySignature,
        ministryPublicKey: vcProof.ministryPublicKey,
      },
    };

    // ── 5. L2'ye gönder ──────────────────────────────────────────────────────
    console.log('[UBLP Agent] Verifiable Presentation L2\'ye gönderiliyor →', L2_VERIFIER_URL);

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
      console.error('[UBLP Agent] ✗ L2 Verifier\'a ulaşılamadı:', msg);
      return reply.status(503).send({ error: 'L2 Verifier servisine ulaşılamadı.', detail: msg }) as never;
    }

    if (!l2Response.ok) {
      console.error('[UBLP Agent] ✗ L2 Verifier reddetti:', l2Result);
      return reply.status(502).send({ error: 'L2 Verifier onaylamadı.', detail: l2Result }) as never;
    }

    console.log('[UBLP Agent] ✓ L2 onayladı. Durum:', l2Result.status);
    return { presentation, l2Result };
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  await app.listen({ port: 3002, host: '0.0.0.0' });
  console.log('[UBLP Agent] ✓ UBLP Agent — http://localhost:3002');
  console.log('[UBLP Agent] DID:', AGENT_DID);
};

start().catch((err) => {
  console.error('[UBLP Agent] Başlatma hatası:', err);
  process.exit(1);
});
