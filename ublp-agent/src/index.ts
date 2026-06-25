import Fastify from 'fastify';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  verifySignature,
  generateZKProof,
  holderProofHash,
  sha256Hash,
  canonicalJson,
  PrivateInputs,
  PublicInputs,
  KeyPair,
  ZKProof,
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  CommitteeAttestation,
  L2SettleResponse,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const L2_VERIFIER_URL = process.env.L2_VERIFIER_URL ?? 'http://localhost:3003';
const COMMITTEE_URL = process.env.COMMITTEE_URL ?? 'http://localhost:3004';
const AGENT_DID = process.env.AGENT_DID ?? 'did:ublp:agent:default';
const AGENT_KEYS_PATH = path.join(__dirname, '..', 'data', 'agent-keypair.json');

// ─── Agent Key Management ─────────────────────────────────────────────────────

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
 * K-3: Agent VP'yi kendi P-256 anahtarıyla imzalar.
 * Payload = SHA256(documentHash || documentIdHash || holderDid)
 * ZK circuit private input → L2'ye ham olarak dönmez.
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
 * ZK kanıtını Committee'ye sunar — ham belge gösterilmez.
 * Kurul ZK proof'u verify eder → matematiksel ikna → BLS imzalar.
 */
async function requestCommitteeAttestation(
  zkProof: ZKProof,
  publicInputs: PublicInputs,
  ministryPublicKey: string,
  ministryPubKeyHash: string
): Promise<CommitteeAttestation> {
  const body = {
    proofBytes: zkProof.ministrySignature,     // proof bytes (Groth16 veya ECDSA sig)
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
                  // documentHash / documentIdHash VC'de artık YOK.
                  // Agent bunları rawDocument + documentId'den yerel hesaplar,
                  // sadece ZK publicValues'a koyar — tek kaynak.
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
                // committeeAttestation VC'de artık YOK — kurul agent'ın ZK kanıtını verify eder
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

      // ── 1. Hash'leri yerel hesapla — tek kaynak: rawDocument + documentId ─────
      // credentialSubject artık documentHash / documentIdHash taşımıyor.
      // Agent rawDocument'ten türetir; Bakanlık imzası da aynı değerler üzerinde.
      const rawDocument = cs.rawDocument as Record<string, unknown>;
      const documentHash = sha256Hash(canonicalJson(rawDocument));
      const documentIdHash = sha256Hash(cs.documentId);

      // ── 2. Bakanlık VC imzasını doğrula ──────────────────────────────────────
      const isValid = verifySignature(rawDocument, vcProof.proofValue, vcProof.ministryPublicKey, documentIdHash);

      if (!isValid) {
        console.error('[UBLP Agent] ✗ VC imzası GEÇERSİZ.');
        return reply.status(400).send({ error: 'Bakanlık VC imzası doğrulanamadı.' }) as never;
      }
      console.log('[UBLP Agent] ✓ VC imzası geçerli.');

      // ── 3. K-3: Holder imzası — ZK circuit private input ─────────────────────
      const holderSignature = signHolderProof(documentHash, documentIdHash, holderDid, agentKeys.privateKey);
      console.log('[UBLP Agent] Holder imzası üretildi (ZK private input).');

      // ── 4. ZK Proof üret ──────────────────────────────────────────────────────
      const privateInputs: PrivateInputs = {
        rawDocument,
        salt: '',
        signature: vcProof.proofValue,
        holderSignature,
        holderPublicKey: agentKeys.publicKey,
        holderDid,
      };
      const publicInputs: PublicInputs = {
        documentHash,     // yerel hesaplanmış — cs.documentHash değil
        ministryPublicKey: vcProof.ministryPublicKey,
        documentIdHash,   // yerel hesaplanmış — cs.documentIdHash değil
      };

      console.log('[UBLP Agent] ZK Proof üretiliyor...');
      const zkProof = await generateZKProof(privateInputs, publicInputs);
      console.log('[UBLP Agent] ✓ ZK Proof üretildi. system:', zkProof.proof_system);
      console.log('[UBLP Agent] holderPubKeyHash:', zkProof.holderPubKeyHash.slice(0, 16) + '…');

      // ── 5. pubKeyHash: SHA256(ministry uncompressed P-256 raw bytes) ──────────
      const pubKeyDer = crypto.createPublicKey(vcProof.ministryPublicKey)
        .export({ type: 'spki', format: 'der' }) as Buffer;
      const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
      const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');

      // ── 6. Kurula ZK kanıtını sun — ham belge gösterilmez (ticari sır) ────────
      // Kurul ZK proof'u verify eder → matematiksel olarak ikna → BLS imzalar.
      // "Körü körüne" imzalama yok artık.
      console.log('[UBLP Agent] ZK kanıtı kurula sunuluyor →', COMMITTEE_URL);
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
        console.error('[UBLP Agent] ✗ Kurul attestation başarısız:', msg);
        return reply.status(502).send({ error: 'Kurul ZK kanıtını doğrulayamadı.', detail: msg }) as never;
      }
      console.log('[UBLP Agent] ✓ Kurul BLS attestation alındı. signers:', committeeAttestation.signerIds.length);

      // ── 7. VP için minimal VC kopyası ────────────────────────────────────────
      //
      // credentialSubject: sadece { id, documentId } — hash'ler YOK.
      // documentHash / documentIdHash artık YALNIZCA proof.publicValues'dan okunur.
      // rawDocument çıkarıldı (AÇIK-2) — L2 belge içeriğini görmez.
      //
      // SP1 modunda proofValue (ham ECDSA imzası) VP'de taşınmamalı.
      // İmza Groth16 circuit private input'u olarak tüketildi.
      // Mock modunda ise proofValue ZK yokken L2 verify için gerekli değil
      // (L2 zaten vp.proof.proofBytes'ı kullanıyor, vc.proof.proofValue'ya bakmıyor).
      const isZKMode = zkProof.proof_system.startsWith('sp1');
      const vcForVP: UBLPVerifiableCredential = {
        ...vc,
        credentialSubject: {
          id: holderDid,
          documentId: cs.documentId,
          // documentHash ÇIKARILDI — fingerprint sızıntısı, publicValues'da zaten var
          // documentIdHash ÇIKARILDI — aynı sebep
          // rawDocument ÇIKARILDI — AÇIK-2
        },
        proof: {
          ...vcProof,
          proofValue: isZKMode ? '' : vcProof.proofValue,
        },
      };

      // ── 9. Verifiable Presentation ───────────────────────────────────────────
      // committeeAttestation VP proof içinde — VC'de artık YOK.
      // K-3: holderSignature / holderPublicKey VP'ye GİRMEZ.
      // publicValues = tek kaynak: L2 ve Committee buradan okur.
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
            documentHash,      // yerel hesaplanmış — tek kaynak
            pubKeyHash,
            documentIdHash,    // yerel hesaplanmış — tek kaynak
            holderPubKeyHash: zkProof.holderPubKeyHash,
          },
          proofBytes: zkProof.ministrySignature,
          ministryPublicKey: vcProof.ministryPublicKey,
          committeeAttestation,                          // VP proof içinde taşınıyor
        },
      };

      // ── 10. L2'ye gönder ─────────────────────────────────────────────────────
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
  console.log('[UBLP Agent] Mod: ZK proof → Committee verify → BLS → L2');
};

start().catch((err) => {
  console.error('[UBLP Agent] Başlatma hatası:', err);
  process.exit(1);
});
