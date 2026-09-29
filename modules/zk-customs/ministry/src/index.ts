import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import crypto from 'crypto';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import {
  generateKeyPair,
  signDocument,
  sha256Hash,
  sha256HashDocument,
  KeyPair,
  SimpleSessionAuthStore,
  createReviewItem,
  decideReviewItem,
  getReviewItem,
  listReviewItems,
  encryptSecretHex,
  decryptSecretHex,
  timingSafeEqual,
} from '@ublp/shared';
import { UBLPVerifiableCredential } from '@ublp/zk-customs-types';
import { openMinistryDb, upsertDocumentRecord, getDocumentRecord } from './db';

const pbkdf2 = promisify(crypto.pbkdf2);

const KEYS_PATH = path.join(__dirname, '..', 'keys', 'keypair.json');
const DB_PATH = path.join(__dirname, '..', 'data', 'ministry.db');
const MINISTRY_DID = process.env.MINISTRY_DID ?? 'did:ublp:ministry';
const PORT = parseInt(process.env.MINISTRY_PORT ?? '3001', 10);

// ─── Auth ───────────────────────────────────────────────────────────────────────
//
// Two separate trust boundaries, deliberately not conflated (see the backend-foundation plan):
//   - OPERATOR_PASSPHRASE: a human officer logging into the (future) review panel — session
//     bearer tokens via SimpleSessionAuthStore, same shape as incoterms-escrow's wallet-based
//     AuthStore minus the wallet (zk-customs has no user-facing wallet identity yet).
//   - BROKER_API_KEY: machine-to-machine traffic from a genuinely separate self-hosted
//     organization (the customs broker's own backend), not a human session. A v0.1
//     simplification — no PKI/wallet identity between organizations exists yet, flagged rather
//     than hidden, same as the rest of this project's own v0.1 shortcuts.
const OPERATOR_PASSPHRASE = process.env.MINISTRY_OPERATOR_PASSPHRASE ?? '';
const BROKER_API_KEY = process.env.MINISTRY_BROKER_API_KEY ?? '';

if (!OPERATOR_PASSPHRASE) {
  console.warn('[Ministry] ⚠ MINISTRY_OPERATOR_PASSPHRASE is not set — officer login is disabled.');
}
if (!BROKER_API_KEY) {
  console.warn('[Ministry] ⚠ MINISTRY_BROKER_API_KEY is not set — broker-facing routes are unprotected (dev only).');
}

const auth = new SimpleSessionAuthStore(OPERATOR_PASSPHRASE);
setInterval(() => auth.sweepExpired(), 60_000);

function requireSession(request: FastifyRequest, reply: FastifyReply, done: (err?: Error) => void): void {
  const header = request.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
  if (!token || !auth.isSessionValid(token)) {
    reply.status(401).send({ error: 'Not authenticated. Log in via POST /auth/login.' });
    return;
  }
  done();
}

function requireApiKey(request: FastifyRequest, reply: FastifyReply, done: (err?: Error) => void): void {
  const provided = request.headers['x-api-key'];
  if (!BROKER_API_KEY || !timingSafeEqual(String(provided ?? ''), BROKER_API_KEY)) {
    reply.status(401).send({ error: 'Missing or invalid API key.' });
    return;
  }
  done();
}

// ─── Key Encryption ───────────────────────────────────────────────────────────
//
// Current (v3) format delegates entirely to @ublp/shared's walletKeyStorage (AES-256-GCM,
// PBKDF2 600k/sha512) via encryptSecretHex/decryptSecretHex over the whole {privateKey,
// publicKey} JSON blob — the same proven pattern incoterms-escrow's identity.ts already uses
// for its own keypairs. A hand-rolled v2 scheme predated this (different PBKDF2 params, a
// different on-disk shape) and is NOT byte-compatible with v3, so loadOrGenerateKeys below
// still knows how to read (never write) a v2 file, one time, to migrate it forward.

const PASSPHRASE = process.env.MINISTRY_KEY_PASSPHRASE ?? '';

interface EncryptedKeyFileV2 {
  version: '2';
  algorithm: 'EC-P256';
  publicKey: string;
  encryptedPrivateKey: string;
}

interface LegacyKeyFile {
  privateKey: string;
  publicKey: string;
}

/** v2-only, read path kept solely to migrate a pre-existing v2 file forward to v3 — never used
 * for new writes. Mirrors the v2 format's own since-replaced parameters (100k/sha256) exactly,
 * which is why this couldn't just be swapped in place for @ublp/shared's walletKeyStorage. */
async function decryptPrivateKeyV2(encryptedJson: string, passphrase: string): Promise<string> {
  const parsed = JSON.parse(encryptedJson) as { salt: string; iv: string; tag: string; data: string };
  const derivedKey = await pbkdf2(passphrase, Buffer.from(parsed.salt, 'hex'), 100_000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, Buffer.from(parsed.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(parsed.tag, 'hex'));
  return decipher.update(Buffer.from(parsed.data, 'hex'), undefined, 'utf8') + decipher.final('utf8');
}

// ─── Key Management ───────────────────────────────────────────────────────────

async function persistKeys(keys: KeyPair): Promise<void> {
  await fs.promises.mkdir(path.dirname(KEYS_PATH), { recursive: true });
  if (PASSPHRASE) {
    await fs.promises.writeFile(KEYS_PATH, encryptSecretHex(JSON.stringify(keys), PASSPHRASE), { mode: 0o600 });
    console.log('[Ministry] ✓ Private key encrypted and saved with AES-256-GCM.');
  } else {
    await fs.promises.writeFile(KEYS_PATH, JSON.stringify(keys, null, 2), 'utf-8');
    console.log('[Ministry] Key pair saved (unencrypted/dev).');
  }
}

async function loadOrGenerateKeys(): Promise<KeyPair> {
  if (!PASSPHRASE) {
    console.warn('[Ministry] ⚠  MINISTRY_KEY_PASSPHRASE is not set — private key unencrypted (dev only).');
  }
  if (fs.existsSync(KEYS_PATH)) {
    const rawText = await fs.promises.readFile(KEYS_PATH, 'utf-8');
    const raw = JSON.parse(rawText) as { ct?: string } | EncryptedKeyFileV2 | LegacyKeyFile;

    if ('ct' in raw) {
      if (!PASSPHRASE) throw new Error('Encrypted key file found but MINISTRY_KEY_PASSPHRASE is not set.');
      const keys = JSON.parse(decryptSecretHex(rawText, PASSPHRASE)) as KeyPair;
      console.log('[Ministry] ✓ Encrypted key decrypted.');
      return keys;
    }

    if ('version' in raw && raw.version === '2') {
      if (!PASSPHRASE) throw new Error('Encrypted key file found but MINISTRY_KEY_PASSPHRASE is not set.');
      const privateKey = await decryptPrivateKeyV2(raw.encryptedPrivateKey, PASSPHRASE);
      console.warn('[Ministry] ⚠  Legacy encrypted (v2) key file — migrating to current format...');
      const keys: KeyPair = { privateKey, publicKey: raw.publicKey };
      await persistKeys(keys);
      return keys;
    }

    const legacy = raw as LegacyKeyFile;
    console.warn('[Ministry] ⚠  Legacy plaintext key file — migrating to current format...');
    const keys: KeyPair = { privateKey: legacy.privateKey, publicKey: legacy.publicKey };
    await persistKeys(keys);
    return keys;
  }
  console.log('[Ministry] Generating new EC P-256 key pair...');
  const keys = generateKeyPair();
  await persistKeys(keys);
  return keys;
}

// ─── VC issuance — unchanged logic, now runs on approval instead of on submit ───

function issueVerifiableCredential(document: Record<string, unknown>, keys: KeyPair): UBLPVerifiableCredential {
  const documentId = document['documentId'] as string;
  const holderDid = (document['holderDid'] as string | undefined) ?? 'did:ublp:agent:unknown';

  const documentIdHash = sha256Hash(documentId);
  // OPEN-1 fix: signs the combined hash SHA256(documentHash || documentIdHash)
  const signature = signDocument(document, keys.privateKey, documentIdHash);
  const issuanceDate = new Date().toISOString();

  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://ublp.io/vc/v1',
    ],
    id: `urn:ublp:vc:${documentId}`,
    type: ['VerifiableCredential', 'UBLPCustomsCredential'],
    issuer: MINISTRY_DID,
    issuanceDate,
    credentialSubject: {
      id: holderDid,
      documentId,
      // documentHash / documentIdHash intentionally not embedded — see the original comment
      // this replaces: the Agent recomputes them from rawDocument for the ZK publicValues.
      rawDocument: document,
    },
    proof: {
      type: 'EcdsaSecp256r1Signature2019',
      created: issuanceDate,
      verificationMethod: `${MINISTRY_DID}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: signature,
      ministryPublicKey: keys.publicKey,
    },
  };
}

// ─── Server ───────────────────────────────────────────────────────────────────

export async function buildServer(keys: KeyPair, db: ReturnType<typeof openMinistryDb>) {
  const app = Fastify({ logger: false });
  await app.register(cors, { origin: true });
  await app.register(rateLimit, { global: false });

  app.get('/api/public-key', async () => ({
    ministryPublicKey: keys.publicKey,
    did: MINISTRY_DID,
  }));

  app.post<{ Body: { passphrase: string } }>(
    '/auth/login',
    { schema: { body: { type: 'object', required: ['passphrase'], properties: { passphrase: { type: 'string' } } } } },
    async (request, reply) => {
      const result = auth.login(request.body.passphrase);
      if (!result) return reply.status(401).send({ error: 'Invalid passphrase.' });
      return result;
    }
  );

  // ── Broker-facing (API-key protected): submit a document for review, poll its outcome ──

  app.post<{ Body: Record<string, unknown> }>(
    '/api/approve',
    {
      preHandler: requireApiKey,
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
      schema: {
        body: {
          type: 'object',
          required: ['documentId'],
          properties: {
            documentId: { type: 'string', minLength: 1 },
            holderDid: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const document = request.body;
      const documentId = document['documentId'] as string;
      console.log('[Ministry] Customs document received for review. ID:', documentId);

      const item = createReviewItem(db, {
        kind: 'document-approval',
        refId: documentId,
        payload: document,
        requestedBy: 'broker',
      });
      upsertDocumentRecord(db, item.id, 'awaiting_approval', null);

      return reply.status(202).send({ submissionId: item.id, status: 'awaiting_approval' });
    }
  );

  app.get<{ Params: { submissionId: string } }>(
    '/api/documents/:submissionId',
    { preHandler: requireApiKey },
    async (request, reply) => {
      const submissionId = Number(request.params.submissionId);
      const record = getDocumentRecord(db, submissionId);
      if (!record) return reply.status(404).send({ error: 'Unknown submissionId.' });
      return { status: record.status, verifiableCredential: record.verifiableCredential ?? undefined };
    }
  );

  // ── Officer-facing (session protected): review queue ──

  // No status filter — returns every document-approval item (awaiting + already decided) so
  // the panel can split "needs review" from "recently decided" client-side, same pattern as
  // Broker's GET /api/submissions and escrow's listPending().
  app.get('/api/pending', { preHandler: requireSession }, async () =>
    listReviewItems(db, { kind: 'document-approval' })
  );

  app.post<{ Params: { id: string } }>(
    '/api/pending/:id/approve',
    { preHandler: requireSession },
    async (request, reply) => {
      const id = Number(request.params.id);
      const item = decideReviewItem(db, id, 'approved', 'officer');
      if (!item) return reply.status(409).send({ error: 'Item not found or already decided.' });

      const vc = issueVerifiableCredential(item.payload as Record<string, unknown>, keys);
      upsertDocumentRecord(db, id, 'approved', vc);
      console.log('[Ministry] ✓ Verifiable Credential issued. ID:', vc.id);
      return { item, verifiableCredential: vc };
    }
  );

  app.post<{ Params: { id: string }; Body: { note?: string } }>(
    '/api/pending/:id/reject',
    { preHandler: requireSession },
    async (request, reply) => {
      const id = Number(request.params.id);
      const item = decideReviewItem(db, id, 'rejected', 'officer', request.body?.note);
      if (!item) return reply.status(409).send({ error: 'Item not found or already decided.' });

      upsertDocumentRecord(db, id, 'rejected', null);
      return { item };
    }
  );

  return app;
}

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  const keys = await loadOrGenerateKeys();
  const db = openMinistryDb(DB_PATH);
  const app = await buildServer(keys, db);
  await app.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`[Ministry] ✓ Ministry of Trade API — http://localhost:${PORT}`);
  console.log('[Ministry] DID:', MINISTRY_DID);
};

// Only auto-starts when run directly (`node dist/index.js` / `ts-node src/index.ts`) — importing
// this module from a test (to exercise the real route wiring against an ephemeral port instead
// of a duplicated inline copy) must not also bind the real MINISTRY_PORT. `VITEST` is set
// automatically by the test runner (https://vitest.dev/config/#test-env), a more portable check
// here than `require.main === module` under Vitest's own module transform.
if (!process.env.VITEST) {
  start().catch((err) => {
    console.error('[Ministry] Startup error:', err);
    process.exit(1);
  });
}
