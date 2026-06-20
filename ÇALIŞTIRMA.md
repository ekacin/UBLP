# UBLP MVP — Çalıştırma Talimatları

## Akış

```
[Customs Broker] → POST /api/approve → [Ministry :3001]
                                             ↓ imzalı belge
[Customs Broker] → POST /api/process → [UBLP Agent :3002]
                                             ↓ ZK proof
                               POST /api/verify-and-settle → [L2 Verifier :3003]
                                                                   ↓
                                                           data/settled.json
```

## Kurulum (tek seferlik)

```bash
# 1. Shared modülü derle (diğerleri buna bağlı)
cd shared
npm install
npm run build
cd ..

# 2. Tüm servisleri kur
npm install   # root — workspace bağlantılarını kurar
```

## Servisleri Başlat (3 ayrı terminal)

**Terminal 1 — Bakanlık**
```bash
cd ministry
npx ts-node src/index.ts
```

**Terminal 2 — UBLP Agent**
```bash
cd ublp-agent
npx ts-node src/index.ts
```

**Terminal 3 — L2 Verifier**
```bash
cd l2-verifier-mock
npx ts-node src/index.ts
```

## Akışı Tetikle (4. terminal)

```bash
cd customs-broker
npx ts-node src/index.ts
```

## Kayıtları Gör

```bash
curl http://localhost:3003/api/records
```

## L2 Verifier Ministry Sync (Ministry yeniden başlarsa)

```bash
curl -X POST http://localhost:3003/api/sync
```

---

## Swap Noktaları (Gerçek ZK için)

| Dosya | Fonksiyon | Değişecek |
|---|---|---|
| `shared/src/crypto/mockCrypto.ts` | `poseidon2Hash` | SHA-256 → Poseidon2 |
| `shared/src/crypto/mockCrypto.ts` | `generateMockZKProof` | Mock → `snarkjs.groth16.prove` |
| `shared/src/crypto/mockCrypto.ts` | `generateKeyPair` / `signDocument` | P-256 → BabyJubJub/EdDSA |
| `l2-verifier-mock/src/index.ts` | proof doğrulama bloğu | Manuel kontrol → `snarkjs.groth16.verify` |

Diğer tüm dosyalar değişmez.
