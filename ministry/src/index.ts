import Fastify from 'fastify';
import crypto from 'crypto';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import {
  generateKeyPair,
  signDocument,
  poseidon2Hash,
  canonicalJson,
  KeyPair,
  UBLPVerifiableCredential,
  CommitteeAttestation,
} from '@ublp/shared';

const pbkdf2 = promisify(crypto.pbkdf2);

const app = Fastify({ logger: false });
const KEYS_PATH = path.join(__dirname, '..', 'keys', 'keypair.json');
const MINISTRY_DID = process.env.MINISTRY_DID ?? 'did:ublp:ministry';
const COMMITTEE_URL = process.env.COMMITTEE_URL ?? 'http://localhost:3004';

// ─── Key Encryption ───────────────────────────────────────────────────────────

const PASSPHRASE = process.env.MINISTRY_KEY_PASSPHRASE ?? '';

interface EncryptedKeyFile {
  version: '2';
  algorithm: 'EC-P256';
  publicKey: string;
  encryptedPrivateKey: string;
}

interface LegacyKeyFile {
  privateKey: string;
  publicKey: string;
}

async function encryptPrivateKey(pem: string, passphrase: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const derivedKey = await pbkdf2(passphrase, salt, 100_000, 32, 'sha256');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex'),
  });
}

async function decryptPrivateKey(encryptedJson: string, passphrase: string): Promise<string> {
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
    const fileData: EncryptedKeyFile = {
      version: '2',
      algorithm: 'EC-P256',
      publicKey: keys.publicKey,
      encryptedPrivateKey: await encryptPrivateKey(keys.privateKey, PASSPHRASE),
    };
    await fs.promises.writeFile(KEYS_PATH, JSON.stringify(fileData, null, 2), 'utf-8');
    console.log('[Ministry] ✓ Private key AES-256-GCM ile şifrelenerek kaydedildi.');
  } else {
    await fs.promises.writeFile(KEYS_PATH, JSON.stringify(keys, null, 2), 'utf-8');
    console.log('[Ministry] Anahtar çifti (şifresiz/dev) kaydedildi.');
  }
}

async function loadOrGenerateKeys(): Promise<KeyPair> {
  if (!PASSPHRASE) {
    console.warn('[Ministry] ⚠  MINISTRY_KEY_PASSPHRASE ayarlı değil — private key şifresiz (sadece geliştirme).');
  }
  if (fs.existsSync(KEYS_PATH)) {
    const raw = JSON.parse(await fs.promises.readFile(KEYS_PATH, 'utf-8')) as EncryptedKeyFile | LegacyKeyFile;
    if ('version' in raw && raw.version === '2') {
      if (!PASSPHRASE) throw new Error('Şifreli anahtar dosyası var ama MINISTRY_KEY_PASSPHRASE ayarlı değil.');
      const privateKey = await decryptPrivateKey(raw.encryptedPrivateKey, PASSPHRASE);
      console.log('[Ministry] ✓ Şifreli anahtar çözüldü.');
      return { privateKey, publicKey: raw.publicKey };
    }
    const legacy = raw as LegacyKeyFile;
    console.warn('[Ministry] ⚠  Eski format — yeni formata geçiriliyor...');
    const keys: KeyPair = { privateKey: legacy.privateKey, publicKey: legacy.publicKey };
    await persistKeys(keys);
    return keys;
  }
  console.log('[Ministry] Yeni EC P-256 anahtar çifti üretiliyor...');
  const keys = generateKeyPair();
  await persistKeys(keys);
  return keys;
}

// ─── Committee ────────────────────────────────────────────────────────────────

async function requestCommitteeAttestation(
  documentHash: string,
  documentIdHash: string
): Promise<CommitteeAttestation> {
  const res = await fetch(`${COMMITTEE_URL}/api/attest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentHash, documentIdHash }),
  });
  if (!res.ok) {
    throw new Error(`[Committee] HTTP ${res.status}: ${await res.text()}`);
  }
  return res.json() as Promise<CommitteeAttestation>;
}

// ─── Server ───────────────────────────────────────────────────────────────────

async function buildServer(keys: KeyPair): Promise<typeof app> {
  app.get('/api/public-key', async () => ({
    ministryPublicKey: keys.publicKey,
    did: MINISTRY_DID,
  }));

  app.post<{ Body: Record<string, unknown> }>(
    '/api/approve',
    {
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
      const holderDid = (document['holderDid'] as string | undefined) ?? 'did:ublp:agent:unknown';

      console.log('[Ministry] Gümrük belgesi alındı. ID:', documentId);

      const documentHash = poseidon2Hash(canonicalJson(document));
      const documentIdHash = poseidon2Hash(documentId);

      // AÇIK-1 fix: SHA256(documentHash || documentIdHash) birleşik hash'i imzalanır
      const signature = signDocument(document, keys.privateKey, documentIdHash);

      const issuanceDate = new Date().toISOString();

      // Kurul onayı — çelişen çıkarlı üyeler bağımsız olarak doğrular
      console.log('[Ministry] Kurul onayı isteniyor →', COMMITTEE_URL);
      const committeeAttestation = await requestCommitteeAttestation(documentHash, documentIdHash);
      console.log(
        `[Ministry] ✓ Kurul onayı alındı. signer_count=${committeeAttestation.signerIds.length}`
      );

      const vc: UBLPVerifiableCredential = {
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
          documentHash,
          documentIdHash,
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
        committeeAttestation,
      };

      console.log('[Ministry] ✓ Verifiable Credential üretildi. ID:', vc.id);
      return reply.status(200).send(vc);
    }
  );

  return app;
}

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  const keys = await loadOrGenerateKeys();
  await buildServer(keys);
  await app.listen({ port: 3001, host: '0.0.0.0' });
  console.log('[Ministry] ✓ Ticaret Bakanlığı API — http://localhost:3001');
  console.log('[Ministry] DID:', MINISTRY_DID);
};

start().catch((err) => {
  console.error('[Ministry] Başlatma hatası:', err);
  process.exit(1);
});
