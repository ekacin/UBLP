import Fastify from 'fastify';
import crypto from 'crypto';
import {
  verifySignature,
  poseidon2Hash,
  generateMockZKProof,
  PrivateInputs,
  PublicInputs,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const L2_VERIFIER_URL = process.env.L2_VERIFIER_URL ?? 'http://localhost:3003';

// ─── Types ────────────────────────────────────────────────────────────────────

interface MinistryApprovedPayload {
  document: Record<string, unknown>;
  signature: string;
  ministryPublicKey: string;
  approvedAt: string;
}

interface ProcessResult {
  proof: ReturnType<typeof generateMockZKProof>;
  publicInputs: PublicInputs;
  l2Result: unknown;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.post<{ Body: MinistryApprovedPayload }>(
  '/api/process',
  { schema: { body: { type: 'object' } } },
  async (request, reply): Promise<ProcessResult> => {
    const { document, signature, ministryPublicKey } = request.body;

    console.log('[UBLP Agent] İmzalı belge alındı. ID:', document['documentId'] ?? 'N/A');
    console.log('[UBLP Agent] Bakanlık imzası doğrulanıyor...');

    const isValid = verifySignature(document, signature, ministryPublicKey);

    if (!isValid) {
      console.error('[UBLP Agent] ✗ Bakanlık imzası GEÇERSİZ. İşlem reddedildi.');
      return reply.status(400).send({ error: 'Bakanlık imzası doğrulanamadı.' }) as never;
    }

    console.log('[UBLP Agent] ✓ Bakanlık imzası doğrulandı. Poseidon2 hash üretiliyor...');

    // Salt → gizlilik katmanı; ileride ZK devresine private input olarak girer
    const salt = crypto.randomBytes(32).toString('hex');
    const documentHash = poseidon2Hash(JSON.stringify({ ...document, salt }));

    console.log('[UBLP Agent] Hash üretildi (SHA-256/mock):', documentHash);
    console.log('[UBLP Agent] Mock ZK Proof üretiliyor...');

    const privateInputs: PrivateInputs = { rawDocument: document, salt, signature };
    const publicInputs: PublicInputs = { documentHash, ministryPublicKey };

    const proof = generateMockZKProof(privateInputs, publicInputs);

    console.log('[UBLP Agent] ZK Proof üretildi:', JSON.stringify(proof, null, 2));
    console.log('[UBLP Agent] L2 Verifier\'a gönderiliyor →', L2_VERIFIER_URL);

    const l2Response = await fetch(`${L2_VERIFIER_URL}/api/verify-and-settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proof, publicInputs }),
    });

    const l2Result = await l2Response.json();

    if (!l2Response.ok) {
      console.error('[UBLP Agent] ✗ L2 Verifier reddetti:', l2Result);
      return reply.status(502).send({ error: 'L2 Verifier onaylamadı.', detail: l2Result }) as never;
    }

    console.log('[UBLP Agent] ✓ L2 Verifier onayladı:', l2Result);
    return { proof, publicInputs, l2Result };
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  await app.listen({ port: 3002, host: '0.0.0.0' });
  console.log('[UBLP Agent] ✓ UBLP Agent — http://localhost:3002');
};

start().catch((err) => {
  console.error('[UBLP Agent] Başlatma hatası:', err);
  process.exit(1);
});
