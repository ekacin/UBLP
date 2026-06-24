import Fastify from 'fastify';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  verifySignature,
  generateZKProof,
  holderProofHash,
  PrivateInputs,
  PublicInputs,
  KeyPair,
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  L2SettleResponse,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const L2_VERIFIER_URL = process.env.L2_VERIFIER_URL ?? 'http://localhost:3003';
const AGENT_DID = process.env.AGENT_DID ?? 'did:ublp:agent:default';
const AGENT_KEYS_PATH = path.join(__dirname, '..', 'data', 'agent-keypair.json');

// ─── Agent Key Management (K-3) ───────────────────────────────────────────────

async function loadOrGenerateAgentKeys(): Promise<KeyPair> {
  if (fs.existsSync(AGENT_KEYS_PATH)) {
    const raw = await fs.promises.readFile(AGENT_KEYS_PATH, 'utf-8');
    console.log('[UBLP Agent] Mevcut P-256 anahtarı yüklendi.');
    return JSON.parse(raw) as KeyPair;
  }
  console.log('[UBLP Agent] Yeni EC P-256 anahtar çifti üretiliyor...');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const keys: KeyPair = { privateKey, publicKey };
  await fs.promises.mkdir(path.dirname(AGENT_KEYS_PATH), { recursive: true });
  await fs.promises.writeFile(AGENT_KEYS_PATH, JSON.stringify(keys, null, 2), 'utf-8');
  return keys;
}

/**
 * K-3 fix: Agent VP'yi kendi P-256 anahtarıyla imzalar.
 * Payload = SHA256(documentHash || documentIdHash || holderDid)
 * L2 bu imzayı holder DID'ine bağlı anahtarla doğrular.
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
                  required: ['type', 'threshold', 'groupKeyHash', 'signerIds', 'aggregatedSignature'],
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
      const holderDid = cs.id ?? AGENT_DID;

      console.log('[UBLP Agent] VC alındı. ID:', vc.id);
      console.log('[UBLP Agent] Issuer:', vc.issuer, '| Holder:', holderDid);

      // ── 1. VC proof doğrulama (Bakanlık combined hash imzası) ────────────────
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

      // ── 2. ZK Proof üret ─────────────────────────────────────────────────────
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
      const vcForVP: UBLPVerifiableCredential = {
        ...vc,
        credentialSubject: {
          id: holderDid,
          documentId: cs.documentId,
          documentHash: cs.documentHash,
          documentIdHash: cs.documentIdHash,
          // rawDocument intentionally excluded
        },
      };

      // ── 4. pubKeyHash hesapla — circuit ile aynı: SHA256(uncompressed P-256 raw 65 bytes)
      // SP1 modunda bu değer circuit output'tan gelir; mock modda agent hesaplar.
      const pubKeyDer = crypto.createPublicKey(vcProof.ministryPublicKey)
        .export({ type: 'spki', format: 'der' }) as Buffer;
      const pubKeyRaw = pubKeyDer.slice(-65); // 04 || x || y — uncompressed SEC1
      const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

      // ── 5. K-3 fix: Holder VP imzası — payload = SHA256(docHash||idHash||holderDid) ──
      // Payload = SHA256(documentHash || documentIdHash || holderDid)
      // L2 bu imzayı holderPublicKey ile doğrular; holderDid değiştirilirse kırılır.
      const holderSignature = signHolderProof(
        cs.documentHash,
        cs.documentIdHash,
        holderDid,
        agentKeys.privateKey
      );

      // ── 5. Verifiable Presentation ───────────────────────────────────────────
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
            documentHash: cs.documentHash,
            pubKeyHash,
            documentIdHash: cs.documentIdHash,
          },
          proofBytes: zkProof.ministrySignature,
          ministryPublicKey: vcProof.ministryPublicKey,
          holderSignature,
          holderPublicKey: agentKeys.publicKey,
        },
      };

      // ── 6. L2'ye gönder ──────────────────────────────────────────────────────
      console.log('[UBLP Agent] VP L2\'ye gönderiliyor →', L2_VERIFIER_URL);

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
        console.error('[UBLP Agent] ✗ L2 reddetti:', l2Result);
        return reply.status(502).send({ error: 'L2 Verifier onaylamadı.', detail: l2Result }) as never;
      }

      console.log('[UBLP Agent] ✓ L2 onayladı. Durum:', l2Result.status);
      return { presentation, l2Result };
    }
  );
}

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  const agentKeys = await loadOrGenerateAgentKeys();
  await buildServer(agentKeys);
  await app.listen({ port: 3002, host: '0.0.0.0' });
  console.log('[UBLP Agent] ✓ UBLP Agent — http://localhost:3002');
  console.log('[UBLP Agent] DID:', AGENT_DID);
};

start().catch((err) => {
  console.error('[UBLP Agent] Başlatma hatası:', err);
  process.exit(1);
});
