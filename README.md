# UBLP — Unified Blockchain Logistics Protocol

**Zero-Knowledge customs clearance over a mock L2 settlement layer.**

Gümrük belgelerini ZK kanıtı, BLS eşik imzası ve W3C Verifiable Credentials ile güvence altına alır. Bakanlık ECDSA imzası, nakliyeci ZK kanıtı, kurul BLS imzası — üçü L2'de tek doğrulama noktasında birleşir.

---

## Mimari

```
Customs Broker
    │
    ▼ POST /api/approve
┌─────────────────────┐
│  Ministry  :3001    │  EC P-256 ECDSA — belgeyi imzalar
│  (Bakanlık)         │  AES-256-GCM key at rest
└────────┬────────────┘
         │ Verifiable Credential (rawDocument + ECDSA sig)
         ▼
┌─────────────────────┐
│  UBLP Agent :3002   │  1. VC imzasını doğrula
│  (Nakliyeci)        │  2. Holder ECDSA sig üret (ZK private input)
│                     │  3. SP1 ZK Proof üret (mock: ECDSA, prod: Groth16)
│                     │  4. ZK kanıtını Committee'ye sun (ham belge gitmez)
└────────┬────────────┘
         │ ZK proof
         ▼
┌─────────────────────┐
│  Committee  :3004   │  ZK proof verify eder → matematiksel ikna
│  (Kurul)            │  BLS12-381 t-of-n imzalar (2/3)
│  3 üye, eşik 2/3    │  AES-256-GCM key at rest
└────────┬────────────┘
         │ BLS aggregate attestation
         ▼
┌─────────────────────┐
│  UBLP Agent :3002   │  Verifiable Presentation oluşturur
└────────┬────────────┘
         │ VP { ZK proof + BLS attestation }
         ▼
┌─────────────────────┐
│  L2 Verifier :3003  │  1. Whitelist + revocation
│  (L2 Katmanı)       │  2. BLS threshold verify (bağımsız)
│                     │  3. ZK proof verify (bağımsız)
│                     │  4. Replay dedup (documentIdHash)
└─────────────────────┘
         │
    settled.json  (ONAYLANDI / SUSPICIOUS)
```

---

## Teknoloji

| Katman | Teknoloji |
|--------|-----------|
| ZK Proof | [SP1 zkVM](https://github.com/succinctlabs/sp1) (RISC-V, Groth16/PLONK) |
| Threshold Sig | BLS12-381 G1, `@noble/bls12-381` |
| Identity | EC P-256 ECDSA, IEEE P1363, SPKI PEM |
| Credentials | W3C VC/VP (`did:ublp:*`) |
| Hash | SHA-256 (SP1 hardware precompile) |
| Key security | AES-256-GCM + PBKDF2 |
| Runtime | Node.js 20+, TypeScript, Fastify |
| Circuit | Rust (`no_std`, `sp1-zkvm`) |

---

## Hızlı Başlangıç

### Gereksinimler

- Node.js 20+
- npm 10+

```bash
git clone https://github.com/<kullanici>/ublp.git
cd ublp
npm install
npm run dev
```

`npm run dev` şunları yapar (sırayla, paralel):
1. Tüm workspace'leri derler (`tsc`)
2. Committee → Ministry → Agent → L2 başlatır
3. Customs Broker demo akışını çalıştırır

**Portlar:**
- `3001` — Ministry (Bakanlık)
- `3002` — UBLP Agent (Nakliyeci)
- `3003` — L2 Verifier
- `3004` — Committee (Kurul)

---

## Ortam Değişkenleri

Tüm servisler sıfır config ile çalışır (development modu). Production için:

### Ministry (`ministry/.env`)
```env
# Private key şifrelemesi — ayarlanmazsa plaintext (sadece geliştirme!)
MINISTRY_KEY_PASSPHRASE=guclu-sifre-buraya

# Opsiyonel
MINISTRY_DID=did:ublp:ministry
COMMITTEE_URL=http://localhost:3004
```

### Committee (`committee/.env`)
```env
# BLS private key şifrelemesi — ayarlanmazsa plaintext (sadece geliştirme!)
COMMITTEE_KEY_PASSPHRASE=guclu-sifre-buraya

# Opsiyonel
COMMITTEE_PORT=3004
```

### UBLP Agent (`ublp-agent/.env`)
```env
# Opsiyonel
AGENT_DID=did:ublp:agent:default
L2_VERIFIER_URL=http://localhost:3003
COMMITTEE_URL=http://localhost:3004
```

### L2 Verifier (`l2-verifier-mock/.env`)
```env
# dev (varsayılan): mock-ecdsa-p256 kabul edilir
# sp1: yalnızca sp1-groth16 / sp1-plonk kabul edilir
PROOF_MODE=dev

# Opsiyonel
MINISTRY_URL=http://localhost:3001
COMMITTEE_URL=http://localhost:3004
```

### SP1 (Gerçek ZK için — opsiyonel)
```env
# Succinct Prover Network
SP1_PROVER_NETWORK_KEY=<succinct-api-anahtari>
SP1_PROVER_URL=https://rpc.succinct.xyz

# sp1-circuit/ içinde "cargo prove build" sonrası üretilen ELF
SP1_ELF_PATH=sp1-circuit/elf/ublp-verifier
```

> SP1 env ayarlanmazsa sistem otomatik olarak mock moda geçer.

---

## API Referansı

### Ministry — `POST /api/approve`
```json
{
  "documentId": "DOC-uuid",
  "holderDid": "did:ublp:agent:default",
  "exporterName": "ACME Lojistik A.Ş.",
  "..."
}
```
Döner: `UBLPVerifiableCredential`

### UBLP Agent — `POST /api/process`
```json
{
  "verifiableCredential": { "..." }
}
```
Döner: `{ presentation: UBLPVerifiablePresentation, l2Result: L2SettleResponse }`

### L2 Verifier — `GET /api/records`
Döner: Tüm `L2SettleRecord[]`

### L2 Verifier — `POST /api/revoke-key`
```json
{
  "ministryPublicKey": "-----BEGIN PUBLIC KEY-----...",
  "compromisedAt": "2024-01-15T10:00:00.000Z"
}
```
`compromisedAt` isteğe bağlı. Belirtilmezse o andan itibaren kabul edilmez; geçmiş kayıtlar etkilenmez.

### L2 Verifier — `POST /api/sync`
Ministry ve Committee bilgilerini yeniler (servis yeniden başlarsa kullan).

---

## ZK Circuit (SP1)

```
sp1-circuit/src/main.rs
```

**Private inputs (L2'ye açıklanmaz):**
1. `ministry_signature` — P-256 ECDSA, 64 byte IEEE P1363
2. `ministry_pub_key_raw` — uncompressed SEC1, 65 byte
3. `document_hash` — SHA256(canonicalJson), 32 byte
4. `document_id_hash` — 32 byte
5. `holder_signature` — P-256 ECDSA, 64 byte (K-3)
6. `holder_pub_key_raw` — 65 byte (K-3)
7. `holder_did` — UTF-8 (K-3)

**Public outputs (L2 doğrular):**
- `document_hash` — belge parmak izi
- `ministry_pub_key_hash` — SHA256(ministry raw key)
- `document_id_hash` — replay koruması
- `holder_pub_key_hash` — K-3: holder kimlik kanıtı, ham key değil

**Circuit derleme (Rust + SP1 toolchain gerekli):**
```bash
cd sp1-circuit
cargo prove build
```

---

## Güvenlik Modeli

| Risk | Koruma |
|------|--------|
| Bakanlık tekel riski | BLS t-of-n kurul; 2/3 eşik |
| Holder kimlik sızıntısı | K-3: holder sig ZK private input; L2 yalnızca `holderPubKeyHash` görür |
| Belge içerik sızıntısı | `rawDocument` VP'den çıkarıldı; `credentialSubject` yalnızca `{ id, documentId }` |
| Replay saldırısı | `documentIdHash` L2'de unique constraint |
| Anahtar sızması | Zaman damgalı revocation; sadece `settledAt >= compromisedAt` SUSPICIOUS |
| Proof downgrade | `PROOF_MODE` L2 env'den; client'tan değil |
| Key at rest | Ministry + Committee: AES-256-GCM + PBKDF2 |

---

## v0.2 Yol Haritası

- [ ] BLS threshold verify → SP1 circuit içine (L2'de tek Groth16 verify)
- [ ] `groupKeyHash` dynamic public input (kurul rotasyonu circuit rebuild gerektirmez)
- [ ] PostgreSQL + Redis (settled.json flat-file → production DB)
- [ ] Binary calldata formatı (W3C JSON yerine ABI-encoded — gas tasarrufu)
- [ ] SP1 proof recursion + EIP-4844 blob batch (10x throughput)
- [ ] Agent key at rest şifrelemesi
- [ ] mTLS / API key servisler arası

---

## Lisans

MIT

---

*Efe Kaan Açın — [acinefekaan@gmail.com](mailto:acinefekaan@gmail.com)*
