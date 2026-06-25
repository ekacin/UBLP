# UBLP — Unified Blockchain Logistics Protocol

**Zero-Knowledge customs clearance over a mock L2 settlement layer.**

Gümrük belgelerini ZK kanıtı, BLS eşik imzası ve W3C Verifiable Credentials ile güvence altına alır. Bakanlık ECDSA imzası, nakliyeci ZK kanıtı, kurul BLS imzası — üçü L2'de tek doğrulama noktasında birleşir.

---

## Neden?

### Mevcut Gümrük Sisteminin Sorunları

**Merkezi onay → tek yozlaşma noktası.** Bugün bir gümrük beyannamesi, tek bir müdürün "tamam" demesiyle geçer ya da geçmez. Bu kapı bekçisi yapısı, yetkili karar alma sürecini bir bireyin tercihine — ve dürüstlüğüne — indirger.

**Memur rüşveti.** Gümrük idareleri, Transparency International raporlarında küresel ölçekte en yüksek rüşvet riskli kurumlar arasında gösterilmektedir. Nedeni yapısaldır: belge onayı elle yapılan bir muamele, açık bir audit trail yok, ret gerekçesi yazılı tutulmak zorunda değil. "Ücret" ödenirse süreç hızlanır, ödenmezse belge takılır. Nakliye süresindeki her gün ihracatçıya doğrudan maliyet olduğu için baskı mekanizması otomatik işler.

**Bürokratik darboğaz.** Uzun imza zinciri, her adımda insan — gecikme, veri giriş hatası ve manipülasyon için birden fazla fırsat. Ortalama bir ithalat belgesi Türkiye'de 6–9 gün bekler; Dünya Bankası verilerine göre bu sürenin büyük bölümü fiilî gümrük işlemi değil, onay kuyruğudur.

**Sahte belge ve kaçakçılık.** Tek imzacı modeli, belge içeriğinin değiştirilmesine karşı yapısal bir koruma sunmaz. "Elma" beyan edilip farklı bir ürün geçirilebilir; imzalanan belgeyle fiziksel yükün eşleşip eşleşmediğini sorgulayan bağımsız bir doğrulama katmanı yoktur. Gümrükte yakalanan kaçakçılık vakalarının önemli bir kısmında sahte beyanname ve usulsüz mühür kullanımı tespit edilmektedir.

**Şeffaflık yokluğu.** Neden reddedildi? Kim imzaladı? Hangi yetkiyle? Bu soruların cevabı çoğu zaman erişilemez. Denetim izi kâğıt ya da kapalı sistemde — üçüncü taraflar doğrulayamaz.

### UBLP'nin Yaklaşımı

| Sorun | UBLP Karşılığı |
|-------|----------------|
| Tek yetkili = tek yozlaşma noktası | BLS t-of-n: 2/3 kurul imzası olmadan onay geçmez |
| "Belge mi imzalandı?" doğrulanamaz | ZK circuit: SHA256(belge) ↔ ministry sig matematiksel bağ |
| Sahte belge fark edilmez | `document_hash` L2'de immutable — sonradan değiştirilse ZK doğrulaması başarısız |
| Holder kimliği cleartext | Holder kimlik gizliliği: holder sig ZK private input, L2 yalnızca `holderPubKeyHash` görür |
| Anahtar ele geçirilirse geçmiş tehlikede | Timestamped revocation: yalnızca `settledAt >= compromisedAt` SUSPICIOUS |
| Kimin onayladığı belirsiz | `groupKeyHash` + `signerIds` → hangi kurul üyelerinin imzaladığı kayıt altında |

UBLP, bakanlık onayından sonraki aşamada — nakliye, kurul onayları ve sınır geçişlerinde — verinin manipüle edilmesini ve çoklu aktörler arasındaki yozlaşma zincirini yapısal olarak imkânsız kılar. Bakanlığın ilk onayı hâlâ insan kararına dayanır; UBLP bu aşamayı değil, onayın verilmesinden sonra gerçekleşebilecek her türlü müdahaleyi kriptografik güvence altına alır. Tek bir kurul üyesi imzalasa onay geçmez; bakanlık onayından sonra belgede değişiklik yapılsa ZK doğrulaması kırılır.

---

## Mimari

### Rol Tanımları

| Servis | Gerçek Dünya Karşılığı | Rol |
|--------|------------------------|-----|
| `customs-broker` | Gümrük müşaviri | Belgeyi hazırlar, nakliyeciye iletir — demo istemcisi |
| `ministry` | Gümrük Bakanlığı | Belgeyi inceler, ECDSA ile imzalar, VC düzenler |
| `ublp-agent` | Nakliyeci / taşıyıcı firma | VC'yi alır, ZK kanıtı üretir, kurul onayı alır, L2'ye sunar |
| `committee` | Akredite kurul (ör. ihracatçılar birliği) | ZK doğrular, BLS eşik imzası atar |
| `l2-verifier-mock` | L2 zinciri | BLS + ZK doğrular, belgeyi settle eder |

### Akış

```
┌──────────────────────────┐
│  Gümrük Müşaviri         │  Belgeyi hazırlar. holderDid = nakliyeci DID.
│  (customs-broker)        │
└────────┬─────────────────┘
         │ 1. POST /api/approve  { belge + holderDid }
         ▼
┌─────────────────────┐
│  Ministry  :3001    │  EC P-256 ECDSA imzalar. VC düzenler.
│  (Bakanlık)         │  AES-256-GCM key at rest.
└────────┬────────────┘
         │ Verifiable Credential (imzalı)
         ▼ (müşavir VC'yi nakliyeciye iletir)
         │ 2. POST /api/process  { verifiableCredential }
         ▼
┌─────────────────────┐
│  UBLP Agent :3002   │  1. VC imzasını doğrula
│  (Nakliyeci)        │  2. Holder ECDSA sig üret (ZK private input — holder kimlik gizliliği)
│                     │  3. ZK Proof üret (mock: ECDSA, prod: SP1 Groth16)
│                     │  4. ZK kanıtını Kurul'a sun (ham belge gitmez)
└────────┬────────────┘
         │ 3. POST /api/attest  { proofBytes, publicValues }
         ▼
┌─────────────────────┐
│  Committee  :3004   │  ZK proof verify eder → matematiksel ikna.
│  (Kurul)            │  BLS12-381 t-of-n imzalar (eşik: 2/3).
│  3 üye, eşik 2/3    │  AES-256-GCM key at rest.
└────────┬────────────┘
         │ BLS aggregate attestation
         ▼
┌─────────────────────┐
│  UBLP Agent :3002   │  Verifiable Presentation oluşturur.
└────────┬────────────┘
         │ 4. POST /api/verify-and-settle  { VP }
         ▼
┌─────────────────────┐
│  L2 Verifier :3003  │  1. Whitelist + revocation check
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
2. Committee (:3004) başlar → Ministry (:3001) → Agent (:3002) → L2 (:3003)
3. Gümrük müşaviri demo akışını (`customs-broker`) çalıştırır: belge hazırlar, ministry'den VC alır, agent'a iletir, L2 sonucunu loglar

**Portlar:**
- `3001` — Ministry / Bakanlık
- `3002` — UBLP Agent / Nakliyeci
- `3003` — L2 Verifier
- `3004` — Committee / Kurul

> `customs-broker` bir port açmaz — one-shot demo script'i. Üretimde bu rolü gümrük müşavirinin kendi sistemi üstlenir.

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

### Gümrük Müşaviri (`customs-broker/.env`)
```env
# Opsiyonel — varsayılanlar dev için çalışır
MINISTRY_URL=http://localhost:3001
UBLP_AGENT_URL=http://localhost:3002

# Belgeye gömülecek nakliyeci DID'i — Agent'ın AGENT_DID'i ile eşleşmeli
AGENT_DID=did:ublp:agent:default
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
3. `document_hash` — SHA256("ublp-doc-v1:" + canonicalJson), 32 byte
4. `document_id_hash` — 32 byte
5. `holder_signature` — P-256 ECDSA, 64 byte — holder kimlik gizliliği
6. `holder_pub_key_raw` — uncompressed SEC1, 65 byte
7. `holder_did` — UTF-8 bytes

**Public outputs (L2 doğrular):**
- `document_hash` — belge parmak izi
- `ministry_pub_key_hash` — SHA256(ministry raw key)
- `document_id_hash` — replay koruması
- `holder_pub_key_hash` — holder kimlik kanıtı; ham key değil, hash'i

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
| Holder kimlik sızıntısı | Holder kimlik gizliliği: holder sig ZK private input; L2 yalnızca `holderPubKeyHash` görür |
| Belge içerik sızıntısı | `rawDocument` VP'ye dahil edilmez; L2 ZK Proof + BLS imzasını doğrular — belge içeriği circuit içinde tüketilir, VP'yi okuyan taraf içeriğe erişemez |
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
