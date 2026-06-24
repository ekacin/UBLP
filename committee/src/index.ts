/**
 * UBLP Committee Service — BLS12-381 Eşik İmza Servisi
 *
 * Mimari:
 *   Bakanlık belgeyi imzaladıktan sonra VC'yi doğrudan agent'a dönmez.
 *   Önce bu servise POST eder; kurul üyeleri BLS12-381 ile imzalar,
 *   aggregate signature üretilir ve CommitteeAttestation olarak döner.
 *
 * BLS Avantajı:
 *   n ayrı ECDSA imzası yerine tek bir aggregate BLS imzası + aggregate pubkey.
 *   t-of-n: signerIds'ten L2 kendi stored pubkey'lerini kullanır (attestation'a güvenmez).
 *
 * K-2 fix:
 *   groupKeyHash = SHA256(sorted ALL n member BLS pubkeys) — statik.
 *   Attestation sadece hangi t üyenin imzaladığını (signerIds) taşır.
 *   L2 kendi member listesinden pubkey lookup yapar.
 *
 * Oyun teorisi: customs-authority, importer-chamber, exporter-union — çelişen çıkarlar.
 * Dürüst kalmak her biri için dominant strateji (diğerleri hileyi raporlar).
 *
 * Eşik: 2/3 (t=2, n=3)
 * API:
 *   POST /api/attest  — belge için BLS eşik imzası üret
 *   GET  /api/info    — groupKeyHash + üye BLS pubkey'leri (L2 senkronizasyonu için)
 */

import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import {
  blsGenerateKeyPair,
  blsSign,
  blsAggregateSignatures,
  blsGroupKeyHash,
  combinedSignatureHash,
  CommitteeAttestation,
  BLSKeyPair,
} from '@ublp/shared';

const app = Fastify({ logger: false });
const MEMBERS_PATH = path.join(__dirname, '..', 'data', 'members.json');
const PORT = parseInt(process.env.COMMITTEE_PORT ?? '3004', 10);
const THRESHOLD = 2; // t-of-n: 2/3

// ─── Üye Tanımları ────────────────────────────────────────────────────────────

interface CommitteeMember {
  memberId: string;
  privateKey: string; // hex BLS private key
  publicKey: string;  // hex BLS G1 compressed pubkey (48 bytes)
}

const MEMBER_IDS = [
  'did:ublp:committee:customs-authority',
  'did:ublp:committee:importer-chamber',
  'did:ublp:committee:exporter-union',
];

// ─── Key Yönetimi ─────────────────────────────────────────────────────────────

async function loadOrGenerateMembers(): Promise<CommitteeMember[]> {
  if (fs.existsSync(MEMBERS_PATH)) {
    const raw = await fs.promises.readFile(MEMBERS_PATH, 'utf-8');
    const stored = JSON.parse(raw) as CommitteeMember[];
    // BLS private key = 32-byte hex (64 chars). Old ECDSA keys are PEM → regenerate.
    const isBLS = stored.every((m) => /^[0-9a-f]{64}$/i.test(m.privateKey));
    if (isBLS) {
      console.log('[Committee] Mevcut BLS üye anahtarları yüklendi.');
      return stored;
    }
    console.warn('[Committee] Eski format anahtar tespit edildi — BLS anahtarları yeniden üretiliyor...');
  }
  console.log('[Committee] Yeni BLS12-381 anahtar çiftleri üretiliyor...');
  const members: CommitteeMember[] = MEMBER_IDS.map((memberId) => {
    const kp: BLSKeyPair = blsGenerateKeyPair();
    return { memberId, privateKey: kp.privateKey, publicKey: kp.publicKey };
  });
  await fs.promises.mkdir(path.dirname(MEMBERS_PATH), { recursive: true });
  await fs.promises.writeFile(MEMBERS_PATH, JSON.stringify(members, null, 2), 'utf-8');
  return members;
}

// ─── Server ───────────────────────────────────────────────────────────────────

async function buildServer(members: CommitteeMember[]): Promise<void> {
  // K-2 fix: groupKeyHash = SHA256(sorted ALL n member pubkeys) — statik, değişmez
  const groupKeyHash = blsGroupKeyHash(members.map((m) => m.publicKey));

  console.log('[Committee] BLS groupKeyHash:', groupKeyHash.slice(0, 16) + '…');
  console.log('[Committee] Üyeler:', members.map((m) => m.memberId).join(', '));

  // ── GET /api/info ──────────────────────────────────────────────────────────
  // L2 bu endpoint'ten groupKeyHash + member BLS pubkey'leri alır.
  // Böylece L2 attestation doğrulamasında kendi deposundan pubkey lookup yapabilir.
  app.get('/api/info', async () => ({
    type: 'BLSThreshold',
    groupKeyHash,
    threshold: THRESHOLD,
    totalMembers: members.length,
    members: members.map((m) => ({ memberId: m.memberId, blsPublicKey: m.publicKey })),
  }));

  // ── POST /api/attest ───────────────────────────────────────────────────────
  interface AttestRequest {
    documentHash: string;
    documentIdHash: string;
  }

  app.post<{ Body: AttestRequest }>(
    '/api/attest',
    {
      schema: {
        body: {
          type: 'object',
          required: ['documentHash', 'documentIdHash'],
          properties: {
            documentHash: { type: 'string', minLength: 64, maxLength: 64 },
            documentIdHash: { type: 'string', minLength: 64, maxLength: 64 },
          },
        },
      },
    },
    async (request, reply) => {
      const { documentHash, documentIdHash } = request.body;

      // Mesaj: combinedSignatureHash — bakanlık imzasıyla aynı preimage
      const msgHex = combinedSignatureHash(documentHash, documentIdHash);

      // Her üye BLS imzalar (mock: tüm üyeler çevrimiçi, production'da t-of-n subset)
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

      // BLS aggregate — t (veya daha fazla) kısmi imzadan tek aggregate sig
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
        `[COMMITTEE] Threshold signature aggregated. ` +
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
};

start().catch((err) => {
  console.error('[Committee] Başlatma hatası:', err);
  process.exit(1);
});
