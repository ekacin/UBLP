import Fastify from 'fastify';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { Mutex } from 'async-mutex';
import {
  verifySignatureOverHash,
  combinedSignatureHash,
  poseidon2Hash,
  sp1VerifyProof,
  UBLPVerifiablePresentation,
  CommitteeAttestation,
  L2SettleRecord,
  L2SettleResponse,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const DB_PATH = path.join(__dirname, '..', 'data', 'settled.json');
const REVOKED_PATH = path.join(__dirname, '..', 'data', 'revoked_keys.json');
const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';
const COMMITTEE_URL = process.env.COMMITTEE_URL ?? 'http://localhost:3004';

// ─── Authorized / Revoked Keys ────────────────────────────────────────────────

let authorizedPublicKeys: Set<string> = new Set();
let revokedPublicKeys: Set<string> = new Set();

// Kurul grup key hash — startup'ta committee'den senkronize edilir
let committeeGroupKeyHash: string | null = null;
// Kurul üyelerinin public key'leri — attestation doğrulaması için
let committeeMembers: Array<{ memberId: string; publicKey: string }> = [];

async function loadRevokedKeys(): Promise<Set<string>> {
  if (!fs.existsSync(REVOKED_PATH)) return new Set();
  const raw = await fs.promises.readFile(REVOKED_PATH, 'utf-8');
  return new Set(JSON.parse(raw) as string[]);
}

async function persistRevokedKeys(keys: Set<string>): Promise<void> {
  await fs.promises.mkdir(path.dirname(REVOKED_PATH), { recursive: true });
  await fs.promises.writeFile(REVOKED_PATH, JSON.stringify([...keys], null, 2), 'utf-8');
}

async function syncMinistryPublicKey(): Promise<boolean> {
  try {
    const res = await fetch(`${MINISTRY_URL}/api/public-key`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { ministryPublicKey: string };
    authorizedPublicKeys.add(data.ministryPublicKey);
    console.log('[L2 Verifier] ✓ Bakanlık public key yetkili listeye eklendi.');
    return true;
  } catch (err) {
    console.warn('[L2 Verifier] ✗ Bakanlık public key yüklenemedi:', (err as Error).message);
    return false;
  }
}

async function syncCommitteeInfo(): Promise<boolean> {
  try {
    const res = await fetch(`${COMMITTEE_URL}/api/info`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as {
      groupKeyHash: string;
      threshold: number;
      totalMembers: number;
      members: Array<{ memberId: string; publicKey: string }>;
    };
    committeeGroupKeyHash = data.groupKeyHash;
    committeeMembers = data.members;
    console.log('[L2 Verifier] ✓ Kurul bilgisi senkronize edildi. groupKeyHash:', committeeGroupKeyHash?.slice(0, 16) + '…');
    return true;
  } catch (err) {
    console.warn('[L2 Verifier] ✗ Kurul bilgisi yüklenemedi:', (err as Error).message);
    return false;
  }
}

function syncWithRetry(maxAttempts = 12, baseDelayMs = 1000): void {
  let attempt = 0;
  const tryOnce = async (): Promise<void> => {
    attempt++;
    const ministryOk = await syncMinistryPublicKey();
    const committeeOk = await syncCommitteeInfo();
    if (ministryOk && committeeOk) return;
    if (attempt >= maxAttempts) {
      console.error(`[L2 Verifier] ✗ Sync ${maxAttempts} denemede başarısız.`);
      return;
    }
    const delay = Math.min(baseDelayMs * Math.pow(2, attempt - 1), 30_000);
    console.log(`[L2 Verifier] Retry (${attempt}/${maxAttempts}) — ${delay}ms sonra.`);
    setTimeout(() => void tryOnce(), delay);
  };
  void tryOnce();
}

// ─── Committee Attestation Doğrulama ─────────────────────────────────────────

function verifyCommitteeAttestation(
  attestation: CommitteeAttestation,
  documentHash: string,
  documentIdHash: string
): { valid: boolean; reason?: string } {
  // groupKeyHash kontrolü — L2'nin sync ettiği değerle eşleşmeli
  if (!committeeGroupKeyHash) {
    return { valid: false, reason: 'L2 kurul bilgisini henüz senkronize etmedi.' };
  }
  if (attestation.groupKeyHash !== committeeGroupKeyHash) {
    return { valid: false, reason: 'Kurul group key hash uyuşmuyor — sahte attestation?' };
  }

  // groupKeyHash'i attestation içindeki public key'lerden yeniden hesapla
  const sorted = [...attestation.signatures].sort((a, b) =>
    a.memberId.localeCompare(b.memberId)
  );
  const joined = sorted.map((s) => s.publicKey).join('');
  const recomputed = crypto.createHash('sha256').update(joined).digest('hex');
  if (recomputed !== attestation.groupKeyHash) {
    return { valid: false, reason: 'groupKeyHash yeniden hesaplandı — public key listesi değiştirilmiş.' };
  }

  // Her imzayı doğrula — combined hash üzerinde
  const combined = combinedSignatureHash(documentHash, documentIdHash);
  let validCount = 0;
  for (const sig of attestation.signatures) {
    if (verifySignatureOverHash(combined, sig.signature, sig.publicKey)) {
      validCount++;
    } else {
      console.warn('[L2 Verifier] ⚠ Kurul üyesi imzası geçersiz:', sig.memberId);
    }
  }

  if (validCount < attestation.threshold) {
    return {
      valid: false,
      reason: `Kurul eşiği sağlanamadı: ${validCount}/${attestation.threshold} geçerli imza.`,
    };
  }

  return { valid: true };
}

// ─── DB ───────────────────────────────────────────────────────────────────────

const dbMutex = new Mutex();

async function loadDB(): Promise<L2SettleRecord[]> {
  if (!fs.existsSync(DB_PATH)) return [];
  const raw = await fs.promises.readFile(DB_PATH, 'utf-8');
  return JSON.parse(raw) as L2SettleRecord[];
}

async function saveDB(records: L2SettleRecord[]): Promise<void> {
  await fs.promises.mkdir(path.dirname(DB_PATH), { recursive: true });
  await fs.promises.writeFile(DB_PATH, JSON.stringify(records, null, 2), 'utf-8');
}

// ─── Routes ───────────────────────────────────────────────────────────────────

interface VerifyRequest {
  presentation: UBLPVerifiablePresentation;
}

app.post<{ Body: VerifyRequest }>(
  '/api/verify-and-settle',
  {
    schema: {
      body: {
        type: 'object',
        required: ['presentation'],
        properties: {
          presentation: {
            type: 'object',
            required: ['type', 'holder', 'verifiableCredential', 'proof'],
            properties: {
              type: { type: 'array' },
              holder: { type: 'string', minLength: 1 },
              verifiableCredential: {
                type: 'array',
                minItems: 1,
                items: {
                  type: 'object',
                  required: ['credentialSubject', 'proof', 'committeeAttestation'],
                },
              },
              proof: {
                type: 'object',
                required: ['proofSystem', 'publicValues', 'proofBytes', 'ministryPublicKey'],
                properties: {
                  proofSystem: { type: 'string', minLength: 1 },
                  publicValues: {
                    type: 'object',
                    required: ['documentHash', 'documentIdHash'],
                    properties: {
                      documentHash: { type: 'string', minLength: 1 },
                      documentIdHash: { type: 'string', minLength: 1 },
                    },
                  },
                  proofBytes: { type: 'string', minLength: 1 },
                  ministryPublicKey: { type: 'string', minLength: 1 },
                },
              },
            },
          },
        },
        additionalProperties: false,
      },
    },
  },
  async (request, reply) => {
    const { presentation } = request.body;
    const vpProof = presentation.proof;
    const vc = presentation.verifiableCredential[0];
    const cs = vc.credentialSubject;

    const ministryPublicKey = vpProof.ministryPublicKey;
    const documentHash = vpProof.publicValues.documentHash;
    const documentIdHash = vpProof.publicValues.documentIdHash;
    const holderDid = presentation.holder;

    console.log('[L2 Verifier] VP alındı. Holder:', holderDid);
    console.log('[L2 Verifier] documentIdHash:', documentIdHash);

    // ── 0. Whitelist + revocation ──────────────────────────────────────────────
    if (!authorizedPublicKeys.has(ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ Yetkisiz Bakanlık public key. Issuer:', vc.issuer);
      return reply.status(403).send({ error: 'Yetkisiz Bakanlık public key.' });
    }
    if (revokedPublicKeys.has(ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ İptal edilmiş Bakanlık public key.');
      return reply.status(403).send({ error: 'Bakanlık anahtarı iptal edilmiş.' });
    }

    // ── 1. VC / VP tutarlılık kontrolü ────────────────────────────────────────
    if (cs.documentHash !== documentHash || cs.documentIdHash !== documentIdHash) {
      console.error('[L2 Verifier] ✗ VP publicValues VC credentialSubject ile uyuşmuyor.');
      return reply.status(400).send({ error: 'VP ve VC hash değerleri uyuşmuyor.' });
    }

    // AÇIK-2 kontrolü: rawDocument VP içinde olmamalı
    if (cs.rawDocument !== undefined) {
      console.error('[L2 Verifier] ✗ VP içinde rawDocument tespit edildi (AÇIK-2).');
      return reply.status(400).send({ error: 'VP rawDocument içeremez.' });
    }

    // ── 2. Kurul attestation doğrulama ────────────────────────────────────────
    const committeeResult = verifyCommitteeAttestation(
      vc.committeeAttestation,
      documentHash,
      documentIdHash
    );
    if (!committeeResult.valid) {
      console.error('[L2 Verifier] ✗ Kurul attestation başarısız:', committeeResult.reason);
      return reply.status(400).send({ error: `Kurul attestation geçersiz: ${committeeResult.reason}` });
    }
    console.log('[L2 Verifier] ✓ Kurul attestation doğrulandı.');

    // ── 3. ZK Proof / ECDSA doğrulama ─────────────────────────────────────────
    let proofValid: boolean;
    const proofSystem = vpProof.proofSystem;

    if (proofSystem === 'sp1-groth16' || proofSystem === 'sp1-plonk') {
      console.log('[L2 Verifier] SP1 proof doğrulanıyor...');
      proofValid = await sp1VerifyProof({
        proofBytes: vpProof.proofBytes,
        documentHash,
        documentIdHash,
        ministryPublicKey,
      });
    } else {
      // mock-ecdsa-p256: proofBytes = bakanlığın ECDSA imzası (combined hash üzerinde)
      // AÇIK-1 fix: documentHash tek başına değil, SHA256(documentHash || documentIdHash) doğrulanır
      const combined = combinedSignatureHash(documentHash, documentIdHash);
      proofValid = verifySignatureOverHash(combined, vpProof.proofBytes, ministryPublicKey);
    }

    if (!proofValid) {
      console.error('[L2 Verifier] ✗ Proof doğrulaması başarısız. [', proofSystem, ']');
      return reply.status(400).send({ error: 'ZK Proof / imza doğrulaması başarısız.' });
    }
    console.log('[L2 Verifier] ✓ Proof doğrulandı. [', proofSystem, ']');

    // ── 4. Replay kontrolü + atomik kayıt ─────────────────────────────────────
    return await dbMutex.runExclusive(async () => {
      const db = await loadDB();

      const duplicate = db.find((r) => r.documentIdHash === documentIdHash);
      if (duplicate) {
        console.warn('[L2 Verifier] ⚠ Replay tespiti:', documentIdHash);
        return reply.status(409).send({ error: 'Belge zaten onaylanmış.', record: duplicate });
      }

      const record: L2SettleRecord = {
        documentHash,
        documentIdHash,
        ministryPublicKeyHash: poseidon2Hash(ministryPublicKey),
        holderDid,
        status: 'ONAYLANDI',
        settledAt: new Date().toISOString(),
        proofSystem,
      };

      db.push(record);
      await saveDB(db);

      console.log('[L2 Verifier] ✓ VP "ONAYLANDI" kaydedildi. Toplam:', db.length);
      const response: L2SettleResponse = { status: 'ONAYLANDI', record };
      return reply.status(200).send(response);
    });
  }
);

app.get('/api/records', async () => loadDB());

app.post('/api/sync', async () => {
  const ministryOk = await syncMinistryPublicKey();
  const committeeOk = await syncCommitteeInfo();
  return {
    success: ministryOk && committeeOk,
    authorizedCount: authorizedPublicKeys.size,
    committeeGroupKeyHash,
  };
});

app.post<{ Body: { ministryPublicKey: string } }>(
  '/api/revoke-key',
  {
    schema: {
      body: {
        type: 'object',
        required: ['ministryPublicKey'],
        properties: { ministryPublicKey: { type: 'string', minLength: 1 } },
      },
    },
  },
  async (request, reply) => {
    const { ministryPublicKey } = request.body;
    if (!authorizedPublicKeys.has(ministryPublicKey)) {
      return reply.status(404).send({ error: 'Bu public key yetkili listede değil.' });
    }
    revokedPublicKeys.add(ministryPublicKey);
    await persistRevokedKeys(revokedPublicKeys);

    const keyHash = poseidon2Hash(ministryPublicKey);

    // MİM-2 fix: iptal sonrası geçmiş kayıtları SUSPICIOUS olarak işaretle (forensic)
    const suspiciousCount = await dbMutex.runExclusive(async () => {
      const db = await loadDB();
      let count = 0;
      for (const record of db) {
        if (record.ministryPublicKeyHash === keyHash && record.status === 'ONAYLANDI') {
          record.status = 'SUSPICIOUS';
          count++;
        }
      }
      if (count > 0) await saveDB(db);
      return count;
    });

    console.warn(
      `[L2 Verifier] ⚠ Key iptal edildi (kalıcı). ` +
      `SUSPICIOUS işaretlenen: ${suspiciousCount}. Forensic analizi başlatın.`
    );
    return reply.status(200).send({
      revoked: true,
      ministryPublicKeyHash: keyHash,
      suspiciousRecords: suspiciousCount,
    });
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  revokedPublicKeys = await loadRevokedKeys();
  if (revokedPublicKeys.size > 0)
    console.log(`[L2 Verifier] ${revokedPublicKeys.size} iptal edilmiş anahtar yüklendi.`);
  await app.listen({ port: 3003, host: '0.0.0.0' });
  console.log('[L2 Verifier] ✓ L2 Verifier Mock — http://localhost:3003');
  syncWithRetry();
};

start().catch((err) => {
  console.error('[L2 Verifier] Başlatma hatası:', err);
  process.exit(1);
});
