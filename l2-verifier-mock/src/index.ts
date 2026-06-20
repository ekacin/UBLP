import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';

const app = Fastify({ logger: false });
const DB_PATH = path.join(__dirname, '..', 'data', 'settled.json');
const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';

// ─── Authorized Keys Store ────────────────────────────────────────────────────
// Swap hedef: on-chain whitelist / governance contract

let authorizedPublicKeys: Set<string> = new Set();

async function syncMinistryPublicKey(): Promise<void> {
  try {
    const res = await fetch(`${MINISTRY_URL}/api/public-key`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { ministryPublicKey: string };
    authorizedPublicKeys.add(data.ministryPublicKey);
    console.log('[L2 Verifier] ✓ Bakanlık public key yetkili listeye eklendi.');
  } catch (err) {
    console.warn('[L2 Verifier] ✗ Bakanlık public key yüklenemedi:', (err as Error).message);
    console.warn('[L2 Verifier]   Servis çalışıyor; Ministry başladıktan sonra /api/sync çağır.');
  }
}

// ─── JSON File DB ─────────────────────────────────────────────────────────────

interface SettledRecord {
  documentHash: string;
  status: 'ONAYLANDI' | 'REDDEDILDI';
  settledAt: string;
  proof: ZKProof;
}

function loadDB(): SettledRecord[] {
  if (!fs.existsSync(DB_PATH)) return [];
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8')) as SettledRecord[];
}

function saveDB(records: SettledRecord[]): void {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(records, null, 2), 'utf-8');
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface ZKProof {
  status: string;
  constraints_passed: boolean;
  signature_valid: boolean;
  timestamp: number;
  proof_system: string;
  public_inputs_hash: string;
}

interface PublicInputs {
  documentHash: string;
  ministryPublicKey: string;
}

interface VerifyRequest {
  proof: ZKProof;
  publicInputs: PublicInputs;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.post<{ Body: VerifyRequest }>(
  '/api/verify-and-settle',
  { schema: { body: { type: 'object' } } },
  async (request, reply) => {
    const { proof, publicInputs } = request.body;

    console.log('[L2 Verifier] Kanıt alındı. Doğrulama başlıyor...');
    console.log('[L2 Verifier] Belge hash:', publicInputs.documentHash);

    // 1. Public key yetki kontrolü
    if (!authorizedPublicKeys.has(publicInputs.ministryPublicKey)) {
      console.error('[L2 Verifier] ✗ Yetkisiz public key. İşlem reddedildi.');
      return reply.status(403).send({ error: 'Yetkisiz Bakanlık public key.' });
    }

    // 2. Proof geçerlilik kontrolü
    //    Swap: burayı snarkjs.groth16.verify(vKey, publicSignals, proof) ile değiştir
    const proofValid =
      proof.constraints_passed === true &&
      proof.signature_valid === true &&
      proof.status === 'verified';

    if (!proofValid) {
      console.error('[L2 Verifier] ✗ ZK Proof geçersiz. İşlem reddedildi.');
      return reply.status(400).send({ error: 'Geçersiz ZK Proof.' });
    }

    // 3. Duplicate hash kontrolü
    const db = loadDB();
    const duplicate = db.find((r) => r.documentHash === publicInputs.documentHash);
    if (duplicate) {
      console.warn('[L2 Verifier] ⚠ Belge zaten kaydedilmiş:', publicInputs.documentHash);
      return reply.status(409).send({ error: 'Belge zaten onaylanmış.', record: duplicate });
    }

    // 4. Kaydet
    const record: SettledRecord = {
      documentHash: publicInputs.documentHash,
      status: 'ONAYLANDI',
      settledAt: new Date().toISOString(),
      proof,
    };

    db.push(record);
    saveDB(db);

    console.log('[L2 Verifier] ✓ Belge "ONAYLANDI" olarak DB\'ye kaydedildi.');
    console.log('[L2 Verifier] Toplam onaylı belge sayısı:', db.length);

    return reply.status(200).send({ status: 'ONAYLANDI', record });
  }
);

// Tüm onaylanmış kayıtlar
app.get('/api/records', async () => {
  return loadDB();
});

// Ministry başladıktan sonra manuel sync için
app.post('/api/sync', async () => {
  await syncMinistryPublicKey();
  return { authorizedCount: authorizedPublicKeys.size };
});

// ─── Start ────────────────────────────────────────────────────────────────────

const start = async (): Promise<void> => {
  await app.listen({ port: 3003, host: '0.0.0.0' });
  console.log('[L2 Verifier] ✓ L2 Verifier Mock — http://localhost:3003');
  await syncMinistryPublicKey();
};

start().catch((err) => {
  console.error('[L2 Verifier] Başlatma hatası:', err);
  process.exit(1);
});
