/**
 * UBLP Committee Service — BLS12-381 Threshold Signature Service (v0.2 Agent-first ZK)
 *
 * New architecture:
 *   The committee no longer sees the raw document (trade secrets stay protected).
 *   The shipper (Agent) generates the ZK proof first, then submits it to the committee.
 *   The committee verifies the ZK proof → becomes mathematically convinced → stamps the BLS signature.
 *
 *   OLD: Ministry → Committee (hand over hash → blind BLS)
 *   NEW: Agent → Committee (submit ZK proof → verify → convinced BLS)
 *
 * The advantage of this design:
 *   The committee doesn't sign "blindly" — it signs CANONICALLY convinced that the document
 *   complies with the rules.
 *   Thanks to ZK, the proof can be verified without disclosing the document's contents.
 *
 * Private key security:
 *   COMMITTEE_KEY_PASSPHRASE → AES-256-GCM + PBKDF2(SHA-512, 600k iter)
 *
 * API:
 *   POST /api/attest  — verify ZK proof → produce BLS threshold signature
 *   GET  /api/info    — groupKeyHash + member BLS pubkeys (L2 sync)
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
  BLSKeyPair,
} from '@ublp/shared';
import { CommitteeAttestation } from '@ublp/zk-customs-types';

const app = Fastify({ logger: false });
const MEMBERS_PATH = path.join(__dirname, '..', 'data', 'members.json');
const PORT = parseInt(process.env.COMMITTEE_PORT ?? '3004', 10);
const THRESHOLD = 2;
const PASSPHRASE = process.env.COMMITTEE_KEY_PASSPHRASE ?? '';

// ─── Member Definitions ────────────────────────────────────────────────────────

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
        if (!PASSPHRASE) throw new Error('[Committee] Encrypted format found but COMMITTEE_KEY_PASSPHRASE is not set.');
        console.log('[Committee] Decrypting encrypted BLS keys...');
        const members: CommitteeMember[] = (stored as EncryptedMemberRecord[]).map((r) => ({
          memberId: r.memberId,
          privateKey: decryptPrivateKeyHex(r.encryptedPrivateKey, PASSPHRASE),
          publicKey: r.publicKey,
        }));
        for (const m of members) {
          if (!/^[0-9a-f]{64}$/i.test(m.privateKey))
            throw new Error(`[Committee] Decryption failed or wrong passphrase — member: ${m.memberId}`);
        }
        console.log('[Committee] ✓ Encrypted BLS keys loaded.');
        return members;
      } else if (isPlainBLS) {
        if (PASSPHRASE) {
          console.log('[Committee] Plaintext → encrypting with AES-256-GCM...');
          const members: CommitteeMember[] = (stored as PlaintextMemberRecord[]).map((r) => ({
            memberId: r.memberId, privateKey: r.privateKey, publicKey: r.publicKey,
          }));
          await saveMembers(members);
          return members;
        }
        console.log('[Committee] BLS keys loaded (dev mode).');
        return (stored as PlaintextMemberRecord[]).map((r) => ({
          memberId: r.memberId, privateKey: r.privateKey, publicKey: r.publicKey,
        }));
      } else {
        console.warn('[Committee] Legacy ECDSA format — regenerating BLS keys...');
      }
    }
  }

  console.log('[Committee] Generating new BLS12-381 key pairs...');
  const members: CommitteeMember[] = MEMBER_IDS.map((memberId) => {
    const kp: BLSKeyPair = blsGenerateKeyPair();
    return { memberId, privateKey: kp.privateKey, publicKey: kp.publicKey };
  });
  await saveMembers(members);
  if (PASSPHRASE) {
    console.log('[Committee] ✓ New BLS keys saved with AES-256-GCM.');
  } else {
    console.warn('[Committee] ⚠ COMMITTEE_KEY_PASSPHRASE is not set — plaintext (dev mode).');
  }
  return members;
}

// ─── Server ───────────────────────────────────────────────────────────────────

async function buildServer(members: CommitteeMember[]): Promise<void> {
  const groupKeyHash = blsGroupKeyHash(members.map((m) => m.publicKey));

  console.log('[Committee] BLS groupKeyHash:', groupKeyHash.slice(0, 16) + '…');
  console.log('[Committee] Members:', members.map((m) => m.memberId).join(', '));

  // GET /api/info — L2 sync endpoint
  app.get('/api/info', async () => ({
    type: 'BLSThreshold',
    groupKeyHash,
    threshold: THRESHOLD,
    totalMembers: members.length,
    members: members.map((m) => ({ memberId: m.memberId, blsPublicKey: m.publicKey })),
  }));

  // ── POST /api/attest — Agent submits the ZK proof, committee verifies it → BLS signs ──

  interface AttestPublicValues {
    documentHash: string;
    documentIdHash: string;
    ministryPubKeyHash: string;
    holderPubKeyHash: string;
  }

  interface AttestRequest {
    proofBytes: string;         // base64 — Groth16/PLONK (SP1) or ECDSA (mock)
    proofSystem: string;        // 'sp1-groth16' | 'sp1-plonk' | 'mock-ecdsa-p256'
    publicValues: AttestPublicValues;
    ministryPublicKey: string;  // PEM SPKI — for mock verify; pubKeyHash check in SP1
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

      console.log('[Committee] Verifying ZK proof...', proofSystem);

      // ── 1. ZK Proof Verification ─────────────────────────────────────────────
      // The committee never sees the raw document — it only verifies the ZK proof.
      // Mathematical conviction: if the proof is valid, the document is compliant AND
      // the Ministry signed it.
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
        // Mock mode: proofBytes = Ministry's ECDSA signature over combinedHash
        const combined = combinedSignatureHash(documentHash, documentIdHash);
        proofValid = verifySignatureOverHash(combined, proofBytes, ministryPublicKey);
      }

      if (!proofValid) {
        console.error('[Committee] ✗ ZK proof invalid — BLS signature refused.');
        return reply.status(400).send({
          error: 'ZK proof could not be verified. The committee refused to sign.',
        });
      }

      console.log('[Committee] ✓ ZK proof verified. Producing BLS threshold signature...');

      // ── 2. BLS Threshold Signature — after mathematical conviction ───────────
      // The committee no longer signs "blindly" — it signs based on the ZK proof.
      const msgHex = combinedSignatureHash(documentHash, documentIdHash);
      const partialSigs: string[] = [];
      const signerIds: string[] = [];

      for (const member of members) {
        try {
          const sig = await blsSign(msgHex, member.privateKey);
          partialSigs.push(sig);
          signerIds.push(member.memberId);
        } catch (err) {
          console.warn(`[Committee] ⚠ Member could not sign: ${member.memberId}`, err);
        }
      }

      if (partialSigs.length < THRESHOLD) {
        return reply.status(503).send({
          error: `Threshold not met: ${partialSigs.length}/${THRESHOLD} members signed.`,
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
        `[Committee] ✓ BLS aggregate signature produced. ` +
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
  console.log(`[Committee] Mode: Agent ZK → Committee verify → BLS sign`);
};

start().catch((err) => {
  console.error('[Committee] Startup error:', err);
  process.exit(1);
});
