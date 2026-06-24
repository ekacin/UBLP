/**
 * UBLP Committee Service — Eşik İmza Servisi (Threshold ECDSA)
 *
 * Mimari:
 *   Bakanlık belgeyi imzaladıktan sonra VC'yi doğrudan agent'a dönmez.
 *   Önce bu servise POST eder; kurul üyeleri bağımsız olarak onaylarsa
 *   CommitteeAttestation üretilir ve VC'ye eklenir.
 *
 *   Oyun teorisi: Üyeler (gümrük, ithalatçı, ihracatçı) birbiriyle
 *   çelişen çıkarlara sahiptir. Dürüst kalmak her biri için dominant
 *   stratejidir — diğer üyeler hileyi raporlayabilir, itibar kaybı
 *   ekonomik kazancı geçer.
 *
 * Üyeler:
 *   did:ublp:committee:customs-authority  — devlet / gümrük
 *   did:ublp:committee:importer-chamber   — ithalatçı
 *   did:ublp:committee:exporter-union     — ihracatçı
 *
 * Eşik: 3/3 (mock; production'da 2/3 + BLS aggregation)
 *
 * API:
 *   POST /api/attest       — belge için kurul imzası al
 *   GET  /api/info         — groupKeyHash + üye bilgileri
 */

import Fastify from 'fastify';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { combinedSignatureHash, CommitteeAttestation, CommitteeMemberSig } from '@ublp/shared';

const app = Fastify({ logger: false });
const MEMBERS_PATH = path.join(__dirname, '..', 'data', 'members.json');
const PORT = parseInt(process.env.COMMITTEE_PORT ?? '3004', 10);
const THRESHOLD = 2; // t-of-n

// ─── Üye Yapısı ───────────────────────────────────────────────────────────────

interface CommitteeMember {
  memberId: string;
  privateKey: string;
  publicKey: string;
}

const MEMBER_IDS = [
  'did:ublp:committee:customs-authority',
  'did:ublp:committee:importer-chamber',
  'did:ublp:committee:exporter-union',
];

// ─── Key Yönetimi ─────────────────────────────────────────────────────────────

function generateMember(memberId: string): CommitteeMember {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { memberId, privateKey, publicKey };
}

async function loadOrGenerateMembers(): Promise<CommitteeMember[]> {
  if (fs.existsSync(MEMBERS_PATH)) {
    const raw = await fs.promises.readFile(MEMBERS_PATH, 'utf-8');
    console.log('[Committee] Mevcut üye anahtarları yüklendi.');
    return JSON.parse(raw) as CommitteeMember[];
  }
  console.log('[Committee] Yeni üye anahtar çiftleri üretiliyor...');
  const members = MEMBER_IDS.map(generateMember);
  await fs.promises.mkdir(path.dirname(MEMBERS_PATH), { recursive: true });
  await fs.promises.writeFile(MEMBERS_PATH, JSON.stringify(members, null, 2), 'utf-8');
  return members;
}

function computeGroupKeyHash(members: CommitteeMember[]): string {
  // SHA256(sorted public key'lerin birleşimi) — L2 bu değeri startup'ta senkronize eder
  const sorted = [...members].sort((a, b) => a.memberId.localeCompare(b.memberId));
  const joined = sorted.map((m) => m.publicKey).join('');
  return crypto.createHash('sha256').update(joined).digest('hex');
}

function signCombined(member: CommitteeMember, combinedHashHex: string): string {
  const hashBytes = Buffer.from(combinedHashHex, 'hex');
  return crypto
    .sign(null, hashBytes, { key: member.privateKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64');
}

// ─── Server ───────────────────────────────────────────────────────────────────

async function buildServer(members: CommitteeMember[]): Promise<void> {
  const groupKeyHash = computeGroupKeyHash(members);

  console.log('[Committee] groupKeyHash:', groupKeyHash);
  console.log('[Committee] Üyeler:', members.map((m) => m.memberId).join(', '));

  // ── GET /api/info ──────────────────────────────────────────────────────────
  app.get('/api/info', async () => ({
    groupKeyHash,
    threshold: THRESHOLD,
    totalMembers: members.length,
    members: members.map((m) => ({ memberId: m.memberId, publicKey: m.publicKey })),
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

      // Birleşik hash — her üye bunu imzalar (bakanlık imzasıyla aynı preimage)
      const combined = combinedSignatureHash(documentHash, documentIdHash);

      const signatures: CommitteeMemberSig[] = members.map((member) => ({
        memberId: member.memberId,
        publicKey: member.publicKey,
        signature: signCombined(member, combined),
      }));

      const attestation: CommitteeAttestation = {
        type: 'ThresholdECDSA',
        threshold: THRESHOLD,
        totalMembers: members.length,
        groupKeyHash,
        signatures,
        attestedAt: new Date().toISOString(),
      };

      console.log(
        `[COMMITTEE] Threshold signature aggregated. ` +
        `docHash=${documentHash.slice(0, 8)}… signer_count=${signatures.length}`
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
  console.log(`[Committee] ✓ Committee Threshold Service — http://localhost:${PORT}`);
  console.log(`[Committee] Threshold: ${THRESHOLD}/${members.length}`);
};

start().catch((err) => {
  console.error('[Committee] Başlatma hatası:', err);
  process.exit(1);
});
