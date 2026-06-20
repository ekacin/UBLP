import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import { generateKeyPair, signDocument, KeyPair } from '@ublp/shared';

const app = Fastify({ logger: false });
const KEYS_PATH = path.join(__dirname, '..', 'keys', 'keypair.json');

// ─── Key Management ───────────────────────────────────────────────────────────

function loadOrGenerateKeys(): KeyPair {
  if (fs.existsSync(KEYS_PATH)) {
    console.log('[Ministry] Mevcut anahtar çifti yüklendi:', KEYS_PATH);
    return JSON.parse(fs.readFileSync(KEYS_PATH, 'utf-8')) as KeyPair;
  }
  console.log('[Ministry] Yeni EC P-256 anahtar çifti üretiliyor...');
  const keys = generateKeyPair();
  fs.mkdirSync(path.dirname(KEYS_PATH), { recursive: true });
  fs.writeFileSync(KEYS_PATH, JSON.stringify(keys, null, 2), 'utf-8');
  console.log('[Ministry] Anahtar çifti kaydedildi:', KEYS_PATH);
  return keys;
}

const keys = loadOrGenerateKeys();

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/api/public-key', async (_req, _reply) => {
  return { ministryPublicKey: keys.publicKey };
});

app.post<{ Body: Record<string, unknown> }>(
  '/api/approve',
  { schema: { body: { type: 'object' } } },
  async (request, reply) => {
    const document = request.body;

    console.log('[Ministry] Gümrük belgesi alındı. ID:', document['documentId'] ?? 'N/A');
    console.log('[Ministry] Belge ECDSA/SHA-256 ile imzalanıyor...');

    const signature = signDocument(document, keys.privateKey);

    const response = {
      document,        // imzalanan orijinal belge — değişmez
      signature,       // belge üzerindeki Bakanlık imzası
      ministryPublicKey: keys.publicKey,
      approvedAt: new Date().toISOString(),
    };

    console.log('[Ministry] Belge imzalandı. Signature (ilk 40 karakter):', signature.slice(0, 40) + '…');
    console.log('[Ministry] İmzalı yanıt gönderiliyor.');

    return reply.status(200).send(response);
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  await app.listen({ port: 3001, host: '0.0.0.0' });
  console.log('[Ministry] ✓ Ticaret Bakanlığı API — http://localhost:3001');
};

start().catch((err) => {
  console.error('[Ministry] Başlatma hatası:', err);
  process.exit(1);
});
