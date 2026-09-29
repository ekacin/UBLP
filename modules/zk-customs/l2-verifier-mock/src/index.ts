import fs from 'fs';
import path from 'path';
import { Mutex } from 'async-mutex';
import {
  verifySignatureOverHash,
  combinedSignatureHash,
  sha256Hash,
  sp1VerifyProof,
  createAgentServer,
  startAgentServer,
} from '@ublp/shared';
import {
  UBLPVerifiablePresentation,
  L2SettleRecord,
  L2SettleResponse,
} from '@ublp/zk-customs-types';

const app = createAgentServer({ logger: false });
const DB_PATH = path.join(__dirname, '..', 'data', 'settled.json');
const REVOKED_PATH = path.join(__dirname, '..', 'data', 'revoked_keys.json');
const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';

/**
 * K-1 fix: Proof mode is determined from the L2 env, not from the client.
 * PROOF_MODE=sp1  → only sp1-groth16 / sp1-plonk are accepted.
 * PROOF_MODE=dev  → mock-ecdsa-p256 is also accepted.
 */
const PROOF_MODE = (process.env.PROOF_MODE ?? 'dev') as 'sp1' | 'dev';

// ─── Revoked Keys — Timestamped ───────────────────────────────────────────────

interface RevokedKeyEntry {
  pem: string;
  revokedAt: string; // ISO — compromise time T
}

let authorizedPublicKeys: Set<string> = new Set();
let revokedKeys: Map<string, string> = new Map(); // PEM → compromise timestamp

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
    console.log('[L2 Verifier] ✓ Ministry public key added to the authorized list.');
    return true;
  } catch (err) {
    console.warn('[L2 Verifier] ✗ Failed to load Ministry public key:', (err as Error).message);
    return false;
  }
}

function syncWithRetry(maxAttempts = 12, baseDelayMs = 1000): void {
  let attempt = 0;
  const tryOnce = async (): Promise<void> => {
    attempt++;
    const ministryOk = await syncMinistryPublicKey();
    if (ministryOk) return;
    if (attempt >= maxAttempts) {
      console.error(`[L2 Verifier] ✗ Sync failed after ${maxAttempts} attempts.`);
      return;
    }
    const delay = Math.min(baseDelayMs * Math.pow(2, attempt - 1), 30_000);
    console.log(`[L2 Verifier] Retry (${attempt}/${maxAttempts}) — in ${delay}ms.`);
    setTimeout(() => void tryOnce(), delay);
  };
  void tryOnce();
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
                      // documentHash / documentIdHash REMOVED — single source of truth: publicValues
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
                  'proofSystem', 'publicValues', 'proofBytes', 'ministryPublicKey',
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

    console.log('[L2 Verifier] VP received. Holder:', holderDid);
    console.log('[L2 Verifier] documentIdHash:', documentIdHash);

    // ── 0. Whitelist + revocation ──────────────────────────────────────────────
    if (!authorizedPublicKeys.has(ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ Unauthorized Ministry public key.');
      return reply.status(403).send({ error: 'Unauthorized Ministry public key.' });
    }
    if (revokedKeys.has(ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ Revoked Ministry public key.');
      return reply.status(403).send({ error: 'Ministry key has been revoked.' });
    }

    // ── 1. Absence of rawDocument (OPEN-2) ───────────────────────────────────
    // documentHash / documentIdHash consistency check REMOVED.
    // ZK publicValues is the single source of truth — the circuit committed to it,
    // L2 doesn't re-read it from the vc.
    // Same in mock mode: the agent computes publicValues locally, L2 trusts it.
    if (cs.rawDocument !== undefined) {
      console.error('[L2 Verifier] ✗ rawDocument present in VP (OPEN-2).');
      return reply.status(400).send({ error: 'VP must not contain rawDocument.' });
    }

    // ── 2. K-3: holderPubKeyHash ──────────────────────────────────────────────
    if (!holderPubKeyHash || holderPubKeyHash.length !== 64) {
      return reply.status(400).send({ error: 'holderPubKeyHash invalid (K-3).' });
    }

    // ── 3. K-1: ZK Proof / ECDSA ──────────────────────────────────────────────
    const proofSystem = vpProof.proofSystem;

    if (PROOF_MODE === 'sp1') {
      if (proofSystem !== 'sp1-groth16' && proofSystem !== 'sp1-plonk') {
        return reply.status(400).send({ error: 'Production mode: SP1 ZK proof is required.' });
      }
    }

    let proofValid: boolean;

    if (proofSystem === 'sp1-groth16' || proofSystem === 'sp1-plonk') {
      console.log('[L2 Verifier] Verifying SP1 proof...');
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
      console.error('[L2 Verifier] ✗ Proof failed. [', proofSystem, ']');
      return reply.status(400).send({ error: 'ZK Proof / signature verification failed.' });
    }
    console.log('[L2 Verifier] ✓ Proof verified. [', proofSystem, ']');

    // ── 4. Replay + atomic record ─────────────────────────────────────────────
    return await dbMutex.runExclusive(async () => {
      const db = await loadDB();
      const duplicate = db.find((r) => r.documentIdHash === documentIdHash);
      if (duplicate) {
        console.warn('[L2 Verifier] ⚠ Replay:', documentIdHash);
        return reply.status(409).send({ error: 'Document already approved.', record: duplicate });
      }

      const record: L2SettleRecord = {
        documentHash,
        documentIdHash,
        ministryPublicKeyHash: sha256Hash(ministryPublicKey),
        holderDid,
        status: 'APPROVED',
        settledAt: new Date().toISOString(),
        proofSystem,
      };

      db.push(record);
      await saveDB(db);
      console.log('[L2 Verifier] ✓ VP "APPROVED". Total:', db.length);
      const response: L2SettleResponse = { status: 'APPROVED', record };
      return reply.status(200).send(response);
    });
  }
);

app.get('/api/records', async () => loadDB());

app.post('/api/sync', async () => {
  const ministryOk = await syncMinistryPublicKey();
  return {
    success: ministryOk,
    authorizedCount: authorizedPublicKeys.size,
    proofMode: PROOF_MODE,
  };
});

// ─── Key Revocation — Timestamped ─────────────────────────────────────────────

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
      return reply.status(404).send({ error: 'This public key is not on the authorized list.' });
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
          record.status === 'APPROVED' &&
          record.settledAt >= revokedAt
        ) {
          record.status = 'SUSPICIOUS';
          count++;
        }
      }
      if (count > 0) await saveDB(db);
      return count;
    });

    console.warn(`[L2 Verifier] ⚠ Key revoked. compromisedAt=${revokedAt} SUSPICIOUS=${suspiciousCount}`);
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
    console.log(`[L2 Verifier] ${revokedKeys.size} revoked key(s) loaded.`);
  await startAgentServer(app, { port: 3003 });
  console.log('[L2 Verifier] ✓ L2 Verifier Mock — http://localhost:3003');
  console.log('[L2 Verifier] PROOF_MODE:', PROOF_MODE);
  syncWithRetry();
};

start().catch((err) => {
  console.error('[L2 Verifier] Startup error:', err);
  process.exit(1);
});
