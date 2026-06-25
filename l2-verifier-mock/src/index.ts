import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import { Mutex } from 'async-mutex';
import {
  verifySignatureOverHash,
  combinedSignatureHash,
  sha256Hash,
  sp1VerifyProof,
  blsVerifyThreshold,
  blsGroupKeyHash,
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

/**
 * K-1 fix: Proof mode L2 env'inden belirlenir, istemciden değil.
 * PROOF_MODE=sp1  → yalnızca sp1-groth16 / sp1-plonk kabul edilir.
 * PROOF_MODE=dev  → mock-ecdsa-p256 de kabul edilir.
 */
const PROOF_MODE = (process.env.PROOF_MODE ?? 'dev') as 'sp1' | 'dev';

// ─── Revoked Keys — Timestamped ───────────────────────────────────────────────

interface RevokedKeyEntry {
  pem: string;
  revokedAt: string; // ISO — compromise time T
}

let authorizedPublicKeys: Set<string> = new Set();
let revokedKeys: Map<string, string> = new Map(); // PEM → compromise timestamp

// K-2: L2 kendi deposu — attestation'daki pubkey'lere güvenmez
let committeeGroupKeyHash: string | null = null;
let committeeMembers: Array<{ memberId: string; blsPublicKey: string }> = [];
let committeeThreshold = 2;

async function loadRevokedKeys(): Promise<Map<string, string>> {
  if (!fs.existsSync(REVOKED_PATH)) return new Map();
  const raw = await fs.promises.readFile(REVOKED_PATH, 'utf-8');
  const entries = JSON.parse(raw) as RevokedKeyEntry[] | string[];
  if (entries.length > 0 && typeof entries[0] === 'string') {
    const now = new Date().toISOString();
    return new Map((entries as string[]).map((pem) => [pem, now]));
  }
  return new Map((entries as RevokedKeyEntry[]).map((e) => [e.pem, e.revokedAt]));
}

async function persistRevokedKeys(keys: Map<string, string>): Promise<void> {
  await fs.promises.mkdir(path.dirname(REVOKED_PATH), { recursive: true });
  const entries: RevokedKeyEntry[] = [...keys.entries()].map(([pem, revokedAt]) => ({ pem, revokedAt }));
  await fs.promises.writeFile(REVOKED_PATH, JSON.stringify(entries, null, 2), 'utf-8');
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
      members: Array<{ memberId: string; blsPublicKey: string }>;
    };
    committeeGroupKeyHash = data.groupKeyHash;
    committeeMembers = data.members;
    committeeThreshold = data.threshold;
    console.log('[L2 Verifier] ✓ Kurul BLS bilgisi senkronize edildi. groupKeyHash:', committeeGroupKeyHash?.slice(0, 16) + '…');
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

// ─── Committee BLS Attestation Doğrulama (K-2 fix) ───────────────────────────
//
// L2, committee'nin önceden ZK doğruladığını biliyor ama bağımsız olarak da
// BLS imzasını verify eder. Güven zinciri: ZK (agent) + BLS (committee) → L2.

async function verifyCommitteeAttestation(
  attestation: CommitteeAttestation,
  documentHash: string,
  documentIdHash: string
): Promise<{ valid: boolean; reason?: string }> {
  if (!committeeGroupKeyHash || committeeMembers.length === 0) {
    return { valid: false, reason: 'L2 kurul bilgisini henüz senkronize etmedi.' };
  }
  if (attestation.groupKeyHash !== committeeGroupKeyHash) {
    return { valid: false, reason: 'groupKeyHash uyuşmuyor — sahte veya eski attestation.' };
  }

  const allPubKeys = committeeMembers.map((m) => m.blsPublicKey);
  const recomputed = blsGroupKeyHash(allPubKeys);
  if (recomputed !== committeeGroupKeyHash) {
    return { valid: false, reason: 'groupKeyHash recompute tutarsız — L2 member listesi bozuk.' };
  }

  const memberMap = new Map(committeeMembers.map((m) => [m.memberId, m.blsPublicKey]));
  const signerPubKeys: string[] = [];
  const unknownSigners: string[] = [];

  for (const signerId of attestation.signerIds) {
    const pk = memberMap.get(signerId);
    if (pk) signerPubKeys.push(pk);
    else unknownSigners.push(signerId);
  }

  if (unknownSigners.length > 0) {
    return { valid: false, reason: `Bilinmeyen imzacılar: ${unknownSigners.join(', ')}` };
  }

  const msgHex = combinedSignatureHash(documentHash, documentIdHash);
  return blsVerifyThreshold(attestation.aggregatedSignature, msgHex, signerPubKeys, attestation.threshold);
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
                  required: ['credentialSubject', 'proof'],
                  properties: {
                    credentialSubject: {
                      type: 'object',
                      // documentHash / documentIdHash ÇIKARILDI — tek kaynak: publicValues
                      required: ['documentId'],
                      properties: {
                        id: { type: 'string' },
                        documentId: { type: 'string', minLength: 1 },
                      },
                    },
                  },
                },
              },
              proof: {
                type: 'object',
                required: [
                  'proofSystem', 'publicValues', 'proofBytes',
                  'ministryPublicKey', 'committeeAttestation',
                ],
                properties: {
                  proofSystem: { type: 'string', minLength: 1 },
                  publicValues: {
                    type: 'object',
                    required: ['documentHash', 'documentIdHash', 'holderPubKeyHash'],
                    properties: {
                      documentHash: { type: 'string', minLength: 1 },
                      documentIdHash: { type: 'string', minLength: 1 },
                      holderPubKeyHash: { type: 'string', minLength: 64, maxLength: 64 },
                    },
                  },
                  proofBytes: { type: 'string', minLength: 1 },
                  ministryPublicKey: { type: 'string', minLength: 1 },
                  // committeeAttestation VP proof içinde — agent ZK verify ettirdikten sonra alıyor
                  committeeAttestation: {
                    type: 'object',
                    required: ['type', 'threshold', 'groupKeyHash', 'signerIds', 'aggregatedSignature'],
                  },
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
    const holderPubKeyHash = vpProof.publicValues.holderPubKeyHash;
    const holderDid = presentation.holder;

    // committeeAttestation artık VP proof içinde (VC'de değil)
    const committeeAttestation = vpProof.committeeAttestation;

    console.log('[L2 Verifier] VP alındı. Holder:', holderDid);
    console.log('[L2 Verifier] documentIdHash:', documentIdHash);

    // ── 0. Whitelist + revocation ──────────────────────────────────────────────
    if (!authorizedPublicKeys.has(ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ Yetkisiz Bakanlık public key.');
      return reply.status(403).send({ error: 'Yetkisiz Bakanlık public key.' });
    }
    if (revokedKeys.has(ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ İptal edilmiş Bakanlık public key.');
      return reply.status(403).send({ error: 'Bakanlık anahtarı iptal edilmiş.' });
    }

    // ── 1. rawDocument yokluğu (AÇIK-2) ─────────────────────────────────────
    // documentHash / documentIdHash consistency check KALDIRILDI.
    // ZK publicValues tek kaynak — circuit commit etti, L2 tekrar vc'den okumaz.
    // Mock modda da aynı: agent publicValues'ı yerel hesaplar, L2 oraya güvenir.
    if (cs.rawDocument !== undefined) {
      console.error('[L2 Verifier] ✗ VP içinde rawDocument (AÇIK-2).');
      return reply.status(400).send({ error: 'VP rawDocument içeremez.' });
    }

    // ── 2. K-3: holderPubKeyHash ──────────────────────────────────────────────
    if (!holderPubKeyHash || holderPubKeyHash.length !== 64) {
      return reply.status(400).send({ error: 'holderPubKeyHash geçersiz (K-3).' });
    }

    // ── 3. Kurul BLS attestation (K-2) ───────────────────────────────────────
    // L2 bağımsız olarak verify eder — committee'nin ZK verify ettiğine güvenmez.
    // İki katman: Committee (ZK → BLS) + L2 (BLS bağımsız verify).
    const committeeResult = await verifyCommitteeAttestation(committeeAttestation, documentHash, documentIdHash);
    if (!committeeResult.valid) {
      console.error('[L2 Verifier] ✗ Kurul attestation başarısız:', committeeResult.reason);
      return reply.status(400).send({ error: `Kurul attestation geçersiz: ${committeeResult.reason}` });
    }
    console.log('[L2 Verifier] ✓ Kurul BLS attestation doğrulandı.');

    // ── 4. K-1: ZK Proof / ECDSA ─────────────────────────────────────────────
    const proofSystem = vpProof.proofSystem;

    if (PROOF_MODE === 'sp1') {
      if (proofSystem !== 'sp1-groth16' && proofSystem !== 'sp1-plonk') {
        return reply.status(400).send({ error: 'Production mode: SP1 ZK proof zorunlu.' });
      }
    }

    let proofValid: boolean;

    if (proofSystem === 'sp1-groth16' || proofSystem === 'sp1-plonk') {
      console.log('[L2 Verifier] SP1 proof doğrulanıyor...');
      proofValid = await sp1VerifyProof({
        proofBytes: vpProof.proofBytes,
        documentHash,
        documentIdHash,
        ministryPublicKey,
        holderPubKeyHash,
      });
    } else if (PROOF_MODE === 'dev') {
      const combined = combinedSignatureHash(documentHash, documentIdHash);
      proofValid = verifySignatureOverHash(combined, vpProof.proofBytes, ministryPublicKey);
    } else {
      proofValid = false;
    }

    if (!proofValid) {
      console.error('[L2 Verifier] ✗ Proof başarısız. [', proofSystem, ']');
      return reply.status(400).send({ error: 'ZK Proof / imza doğrulaması başarısız.' });
    }
    console.log('[L2 Verifier] ✓ Proof doğrulandı. [', proofSystem, ']');

    // ── 5. Replay + atomik kayıt ──────────────────────────────────────────────
    return await dbMutex.runExclusive(async () => {
      const db = await loadDB();
      const duplicate = db.find((r) => r.documentIdHash === documentIdHash);
      if (duplicate) {
        console.warn('[L2 Verifier] ⚠ Replay:', documentIdHash);
        return reply.status(409).send({ error: 'Belge zaten onaylanmış.', record: duplicate });
      }

      const record: L2SettleRecord = {
        documentHash,
        documentIdHash,
        ministryPublicKeyHash: sha256Hash(ministryPublicKey),
        holderDid,
        status: 'ONAYLANDI',
        settledAt: new Date().toISOString(),
        proofSystem,
      };

      db.push(record);
      await saveDB(db);
      console.log('[L2 Verifier] ✓ VP "ONAYLANDI". Toplam:', db.length);
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
    proofMode: PROOF_MODE,
  };
});

// ─── Key İptali — Zaman Damgalı ───────────────────────────────────────────────

app.post<{ Body: { ministryPublicKey: string; compromisedAt?: string } }>(
  '/api/revoke-key',
  {
    schema: {
      body: {
        type: 'object',
        required: ['ministryPublicKey'],
        properties: {
          ministryPublicKey: { type: 'string', minLength: 1 },
          compromisedAt: { type: 'string' },
        },
      },
    },
  },
  async (request, reply) => {
    const { ministryPublicKey, compromisedAt } = request.body;

    if (!authorizedPublicKeys.has(ministryPublicKey)) {
      return reply.status(404).send({ error: 'Bu public key yetkili listede değil.' });
    }

    const revokedAt = compromisedAt ?? new Date().toISOString();
    revokedKeys.set(ministryPublicKey, revokedAt);
    await persistRevokedKeys(revokedKeys);

    const keyHash = sha256Hash(ministryPublicKey);

    const suspiciousCount = await dbMutex.runExclusive(async () => {
      const db = await loadDB();
      let count = 0;
      for (const record of db) {
        if (
          record.ministryPublicKeyHash === keyHash &&
          record.status === 'ONAYLANDI' &&
          record.settledAt >= revokedAt
        ) {
          record.status = 'SUSPICIOUS';
          count++;
        }
      }
      if (count > 0) await saveDB(db);
      return count;
    });

    console.warn(`[L2 Verifier] ⚠ Key iptal. compromisedAt=${revokedAt} SUSPICIOUS=${suspiciousCount}`);
    return reply.status(200).send({
      revoked: true,
      compromisedAt: revokedAt,
      ministryPublicKeyHash: keyHash,
      suspiciousRecords: suspiciousCount,
    });
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  revokedKeys = await loadRevokedKeys();
  if (revokedKeys.size > 0)
    console.log(`[L2 Verifier] ${revokedKeys.size} iptal anahtar yüklendi.`);
  await app.listen({ port: 3003, host: '0.0.0.0' });
  console.log('[L2 Verifier] ✓ L2 Verifier Mock — http://localhost:3003');
  console.log('[L2 Verifier] PROOF_MODE:', PROOF_MODE);
  syncWithRetry();
};

start().catch((err) => {
  console.error('[L2 Verifier] Başlatma hatası:', err);
  process.exit(1);
});
