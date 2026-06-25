/**
 * UBLP Committee Service — BLS12-381 Eşik İmza Servisi (v0.2 Agent-first ZK)
 *
 * Yeni mimari:
 *   Kurul artık ham belgeyi görmüyor (ticari sır korunuyor).
 *   Nakliyeci (Agent) önce ZK kanıtı üretir, sonra kurula sunar.
 *   Kurul ZK kanıtını doğrular → matematiksel olarak ikna olur → BLS imzasını basar.
 *
 *   ESKI: Ministry → Committee (hash ver → kör BLS)
 *   YENİ: Agent → Committee (ZK proof ver → verify → ikna olmuş BLS)
 *
 * Bu tasarımın avantajı:
 *   Kurul "körü körüne" değil, belgenin kurallara uyduğuna KANONIK olarak ikna olarak imzalar.
 *   ZK sayesinde belge içeriği açıklanmadan kanıt doğrulanabilir.
 *
 * Özel anahtar güvenliği:
 *   COMMITTEE_KEY_PASSPHRASE → AES-256-GCM + PBKDF2(SHA-512, 600k iter)
 *
 * API:
 *   POST /api/attest  — ZK proof doğrula → BLS eşik imzası üret
 *   GET  /api/info    — groupKeyHash + üye BLS pubkey'leri (L2 sync)
 */

import Fastify from 'fastify';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  blsGenerateKeyPair,
  blsSign,
  blsAggregateSignatures,
  blsGroupKeyHash,
  combinedSignatureHash,
  verifySignatureOverHash,
  sp1VerifyProof,
  CommitteeAttestation,
  BLSKeyPair,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const MEMBERS_PATH = path.join(__dirname, '..', 'data', 'members.json');
const PORT = parseInt(process.env.COMMITTEE_PORT ?? '3004', 10);
const THRESHOLD = 2;
const PASSPHRASE = process.env.COMMITTEE_KEY_PASSPHRASE ?? '';

// ─── Üye Tanımları ────────────────────────────────────────────────────────────

interface CommitteeMember {
  memberId: string;
  privateKey: string;
  publicKey: string;
}

interface EncryptedMemberRecord {
  memberId: string;
  encryptedPrivateKey: string;
  publicKey: string;
}

interface PlaintextMemberRecord {
  memberId: string;
  privateKey: string;
  publicKey: string;
}

type MemberRecord = EncryptedMemberRecord | PlaintextMemberRecord;

const MEMBER_IDS = [
  'did:ublp:committee:customs-authority',
  'did:ublp:committee:importer-chamber',
  'did:ublp:committee:exporter-union',
];

// ─── AES-256-GCM Key Encryption ───────────────────────────────────────────────

interface EncryptedPayload {
  salt: string;
  iv: string;
  tag: string;
  ct: string;
}

function deriveKey(passphrase: string, saltHex: string): Buffer {
  return crypto.pbkdf2Sync(passphrase, Buffer.from(saltHex, 'hex'), 600_000, 32, 'sha512');
}

function encryptPrivateKeyHex(hexKey: string, passphrase: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(hexKey, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload: EncryptedPayload = { salt, iv: iv.toString('hex'), tag: tag.toString('hex'), ct: ct.toString('hex') };
  return JSON.stringify(payload);
}

function decryptPrivateKeyHex(encryptedJson: string, passphrase: string): string {
  const { salt, iv, tag, ct } = JSON.parse(encryptedJson) as EncryptedPayload;
  const key = deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'hex')), decipher.final()]).toString('utf8');
}

// ─── Persistence ──────────────────────────────────────────────────────────────

async function saveMembers(members: CommitteeMember[]): Promise<void> {
  await fs.promises.mkdir(path.dirname(MEMBERS_PATH), { recursive: true });
  let records: MemberRecord[];
  if (PASSPHRASE) {
    records = members.map((m): EncryptedMemberRecord => ({
      memberId: m.memberId,
      encryptedPrivateKey: encryptPrivateKeyHex(m.privateKey, PASSPHRASE),
      publicKey: m.publicKey,
    }));
  } else {
    records = members.map((m): PlaintextMemberRecord => ({
      memberId: m.memberId,
      privateKey: m.privateKey,
      publicKey: m.publicKey,
    }));
  }
  await fs.promises.writeFile(MEMBERS_PATH, JSON.stringify(records, null, 2), 'utf-8');
}

async function loadOrGenerateMembers(): Promise<CommitteeMember[]> {
  if (fs.existsSync(MEMBERS_PATH)) {
    const raw = await fs.promises.readFile(MEMBERS_PATH, 'utf-8');
    const stored = JSON.parse(raw) as MemberRecord[];

    if (stored.length > 0) {
      const isEncrypted = 'encryptedPrivateKey' in stored[0];
      const isPlainBLS = !isEncrypted &&
        'privateKey' in stored[0] &&
        /^[0-9a-f]{64}$/i.test((stored[0] as PlaintextMemberRecord).privateKey);

      if (isEncrypted) {
        if (!PASSPHRASE) throw new Error('[Committee] Şifreli format var ama COMMITTEE_KEY_PASSPHRASE ayarlı değil.');
        console.log('[Committee] Şifreli BLS anahtarları çözümleniyor...');
        const members: CommitteeMember[] = (stored as EncryptedMemberRecord[]).map((r) => ({
          memberId: r.memberId,
          privateKey: decryptPrivateKeyHex(r.encryptedPrivateKey, PASSPHRASE),
          publicKey: r.publicKey,
        }));
        for (const m of members) {
          if (!/^[0-9a-f]{64}$/i.test(m.privateKey))
            throw new Error(`[Committee] Çözümleme başarısız veya yanlış parola — üye: ${m.memberId}`);
        }
        console.log('[Committee] ✓ Şifreli BLS anahtarları yüklendi.');
        return members;
      } else if (isPlainBLS) {
        if (PASSPHRASE) {
          console.log('[Committee] Plaintext → AES-256-GCM şifreleniyor...');
          const members: CommitteeMember[] = (stored as PlaintextMemberRecord[]).map((r) => ({
            memberId: r.memberId, privateKey: r.privateKey, publicKey: r.publicKey,
          }));
          await saveMembers(members);
          return members;
        }
        console.log('[Committee] BLS anahtarları yüklendi (dev modu).');
        return (stored as PlaintextMemberRecord[]).map((r) => ({
          memberId: r.memberId, privateKey: r.privateKey, publicKey: r.publicKey,
        }));
      } else {
        console.warn('[Committee] Eski ECDSA format — BLS yeniden üretiliyor...');
      }
    }
  }

  console.log('[Committee] Yeni BLS12-381 anahtar çiftleri üretiliyor...');
  const members: CommitteeMember[] = MEMBER_IDS.map((memberId) => {
    const kp: BLSKeyPair = blsGenerateKeyPair();
    return { memberId, privateKey: kp.privateKey, publicKey: kp.publicKey };
  });
  await saveMembers(members);
  if (PASSPHRASE) {
    console.log('[Committee] ✓ Yeni BLS anahtarları AES-256-GCM ile kaydedildi.');
  } else {
    console.warn('[Committee] ⚠ COMMITTEE_KEY_PASSPHRASE ayarlı değil — plaintext (dev modu).');
  }
  return members;
}

// ─── Server ───────────────────────────────────────────────────────────────────

async function buildServer(members: CommitteeMember[]): Promise<void> {
  const groupKeyHash = blsGroupKeyHash(members.map((m) => m.publicKey));

  console.log('[Committee] BLS groupKeyHash:', groupKeyHash.slice(0, 16) + '…');
  console.log('[Committee] Üyeler:', members.map((m) => m.memberId).join(', '));

  // GET /api/info — L2 sync endpoint
  app.get('/api/info', async () => ({
    type: 'BLSThreshold',
    groupKeyHash,
    threshold: THRESHOLD,
    totalMembers: members.length,
    members: members.map((m) => ({ memberId: m.memberId, blsPublicKey: m.publicKey })),
  }));

  // ── POST /api/attest — Agent ZK proof'u sunar, kurul verify eder → BLS imzalar ──

  interface AttestPublicValues {
    documentHash: string;
    documentIdHash: string;
    ministryPubKeyHash: string;
    holderPubKeyHash: string;
  }

  interface AttestRequest {
    proofBytes: string;         // base64 — Groth16/PLONK (SP1) veya ECDSA (mock)
    proofSystem: string;        // 'sp1-groth16' | 'sp1-plonk' | 'mock-ecdsa-p256'
    publicValues: AttestPublicValues;
    ministryPublicKey: string;  // PEM SPKI — mock verify için; SP1'de pubKeyHash kontrolü
  }

  app.post<{ Body: AttestRequest }>(
    '/api/attest',
    {
      schema: {
        body: {
          type: 'object',
          required: ['proofBytes', 'proofSystem', 'publicValues', 'ministryPublicKey'],
          properties: {
            proofBytes: { type: 'string', minLength: 1 },
            proofSystem: { type: 'string', minLength: 1 },
            publicValues: {
              type: 'object',
              required: ['documentHash', 'documentIdHash', 'ministryPubKeyHash', 'holderPubKeyHash'],
              properties: {
                documentHash: { type: 'string', minLength: 64, maxLength: 64 },
                documentIdHash: { type: 'string', minLength: 64, maxLength: 64 },
                ministryPubKeyHash: { type: 'string', minLength: 64, maxLength: 64 },
                holderPubKeyHash: { type: 'string', minLength: 64, maxLength: 64 },
              },
            },
            ministryPublicKey: { type: 'string', minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const { proofBytes, proofSystem, publicValues, ministryPublicKey } = request.body;
      const { documentHash, documentIdHash, holderPubKeyHash } = publicValues;

      console.log('[Committee] ZK kanıtı doğrulanıyor...', proofSystem);

      // ── 1. ZK Proof Doğrulama ─────────────────────────────────────────────────
      // Kurul ham belgeyi görmez — sadece ZK kanıtını doğrular.
      // Matematiksel ikna: kanıt geçerliyse belge yasal VE Bakanlık imzalamış.
      let proofValid: boolean;

      if (proofSystem === 'sp1-groth16' || proofSystem === 'sp1-plonk') {
        proofValid = await sp1VerifyProof({
          proofBytes,
          documentHash,
          documentIdHash,
          ministryPublicKey,
          holderPubKeyHash,
        });
      } else {
        // Mock mode: proofBytes = Bakanlık ECDSA imzası over combinedHash
        const combined = combinedSignatureHash(documentHash, documentIdHash);
        proofValid = verifySignatureOverHash(combined, proofBytes, ministryPublicKey);
      }

      if (!proofValid) {
        console.error('[Committee] ✗ ZK kanıtı geçersiz — BLS imzası reddedildi.');
        return reply.status(400).send({
          error: 'ZK kanıtı doğrulanamadı. Kurul imzalamayı reddetti.',
        });
      }

      console.log('[Committee] ✓ ZK kanıtı doğrulandı. BLS eşik imzası üretiliyor...');

      // ── 2. BLS Eşik İmzası — matematiksel ikna sonrası ───────────────────────
      // Kurul artık "körü körüne" değil, ZK kanıtına dayanarak imzalıyor.
      const msgHex = combinedSignatureHash(documentHash, documentIdHash);
      const partialSigs: string[] = [];
      const signerIds: string[] = [];

      for (const member of members) {
        try {
          const sig = await blsSign(msgHex, member.privateKey);
          partialSigs.push(sig);
          signerIds.push(member.memberId);
        } catch (err) {
          console.warn(`[Committee] ⚠ Üye imzalayamadı: ${member.memberId}`, err);
        }
      }

      if (partialSigs.length < THRESHOLD) {
        return reply.status(503).send({
          error: `Eşik sağlanamadı: ${partialSigs.length}/${THRESHOLD} üye imzaladı.`,
        });
      }

      const aggregatedSignature = blsAggregateSignatures(partialSigs);

      const attestation: CommitteeAttestation = {
        type: 'BLSThreshold',
        threshold: THRESHOLD,
        totalMembers: members.length,
        groupKeyHash,
        signerIds,
        aggregatedSignature,
        attestedAt: new Date().toISOString(),
      };

      console.log(
        `[Committee] ✓ BLS aggregate imzası üretildi. ` +
        `docHash=${documentHash.slice(0, 8)}… signers=${signerIds.length}/${members.length}`
      );

      return reply.status(200).send(attestation);
    }
  );
}

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  const members = await loadOrGenerateMembers();
  await buildServer(members);
  await app.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`[Committee] ✓ BLS12-381 Threshold Committee — http://localhost:${PORT}`);
  console.log(`[Committee] Threshold: ${THRESHOLD}/${MEMBER_IDS.length}`);
  console.log(`[Committee] Key encryption: ${PASSPHRASE ? 'AES-256-GCM' : '⚠ PLAINTEXT (dev)'}`);
  console.log(`[Committee] Mod: Agent ZK → Committee verify → BLS sign`);
};

start().catch((err) => {
  console.error('[Committee] Başlatma hatası:', err);
  process.exit(1);
});
