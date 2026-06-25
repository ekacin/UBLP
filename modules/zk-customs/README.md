# UBLP · ZK Customs Clearance Module
> **[UBLP Ecosystem](https://github.com/ekacin/UBLP) → `modules/zk-customs`**
>
> This repository contains the Zero-Knowledge customs verification module of UBLP.
> UBLP is a multi-module protocol for end-to-end cryptographic security across logistics processes.
**Zero-Knowledge customs clearance over a mock L2 settlement layer.**
Secures customs documents using ZK proofs, BLS threshold signatures, and W3C Verifiable Credentials. Ministry ECDSA signature, carrier ZK proof, committee BLS signature — all three converge at a single L2 verification point.
---
## Why UBLP?
### Structural Vulnerabilities in Current Customs Systems
**Bureaucratic corruption risk.** Customs administrations are structurally exposed to integrity risks: document approval is a manual process, no open audit trail exists, and rejection reasons are not required to be documented. Every day of shipping delay is a direct cost to the exporter — making the pressure mechanism self-executing.

**Bureaucratic bottleneck.** Long approval chains, a human at every step — multiple opportunities for delay, data entry error, and manipulation. A significant portion of this time is not actual customs processing but approval queues.

**Lack of transparency.** Who signed it? Under what authority? These answers are often inaccessible to the parties involved. The audit trail lives on paper or in closed systems — third parties cannot verify it.

**Trust mechanism is fundamentally misaligned.** Current systems rely on the good faith of institutions and individuals. UBLP's proposition: move trust to cryptographic verification and immutable records. Low-risk, compliant shipments clear automatically — human oversight focuses on genuinely high-risk cases.

### UBLP's Approach
| Problem | UBLP Solution |
|---------|---------------|
| Single authority = single corruption point | BLS t-of-n: approval requires 2/3 committee signatures |
| "Was the document signed?" cannot be verified | ZK circuit: SHA256(document) ↔ ministry sig — mathematical binding |
| Forged documents go undetected | `document_hash` immutable on L2 — any post-approval change breaks ZK verification |
| Holder identity exposed | Holder privacy: holder sig is ZK private input, L2 only sees `holderPubKeyHash` |
| Compromised key endangers past records | Timestamped revocation: only `settledAt >= compromisedAt` flagged SUSPICIOUS |
| Who approved is unclear | `groupKeyHash` + `signerIds` → which committee members signed is on record |
UBLP makes data manipulation structurally impossible in the post-approval phase — during transport, committee signing, and border crossing. The ministry's initial approval still relies on human judgment; UBLP does not replace that decision, it cryptographically secures everything that follows. A single committee member's signature is insufficient; any document change after ministry approval breaks ZK verification.
---
## Architecture
### Role Definitions
| Service | Real-World Counterpart | Role |
|---------|------------------------|------|
| `customs-broker` | Customs broker | Prepares document, forwards to carrier — demo client |
| `ministry` | Customs Ministry | Reviews document, signs with ECDSA, issues VC |
| `ublp-agent` | Carrier / freight forwarder | Receives VC, generates ZK proof, obtains committee attestation, submits to L2 |
| `committee` | Accredited committee (e.g. exporters' union) | Verifies ZK proof, applies BLS threshold signature |
| `l2-verifier-mock` | L2 chain | Verifies BLS + ZK, settles document |
### Flow

```
┌──────────────────────────┐
│  Customs Broker          │  Prepares document. holderDid = carrier DID.
│  (customs-broker)        │
└────────┬─────────────────┘
         │ 1. POST /api/approve  { document + holderDid }
         ▼
┌─────────────────────┐
│  Ministry  :3001    │  Signs with EC P-256 ECDSA. Issues VC.
│                     │  AES-256-GCM key at rest.
└────────┬────────────┘
         │ Verifiable Credential (signed)
         ▼ (broker forwards VC to carrier)
         │ 2. POST /api/process  { verifiableCredential }
         ▼
┌─────────────────────┐
│  UBLP Agent :3002   │  1. Verify VC signature
│  (Carrier)          │  2. Generate holder ECDSA sig (ZK private input — holder privacy)
│                     │  3. Generate ZK Proof (mock: ECDSA, prod: SP1 Groth16)
│                     │  4. Submit ZK proof to Committee (raw document never sent)
└────────┬────────────┘
         │ 3. POST /api/attest  { proofBytes, publicValues }
         ▼
┌─────────────────────┐
│  Committee  :3004   │  Verifies ZK proof → mathematical conviction.
│                     │  BLS12-381 t-of-n sign (threshold: 2/3).
│  3 members, 2/3     │  AES-256-GCM key at rest.
└────────┬────────────┘
         │ BLS aggregate attestation
         ▼
┌─────────────────────┐
│  UBLP Agent :3002   │  Builds Verifiable Presentation.
└────────┬────────────┘
         │ 4. POST /api/verify-and-settle  { VP }
         ▼
┌─────────────────────┐
│  L2 Verifier :3003  │  1. Whitelist + revocation check
│  (L2 Layer)         │  2. BLS threshold verify (independent)
│                     │  3. ZK proof verify (independent)
│                     │  4. Replay dedup (documentIdHash)
└─────────────────────┘
         │
    settled.json  (APPROVED / SUSPICIOUS)
```
---
## Technology Stack
| Layer | Technology |
|-------|------------|
| ZK Proof | [SP1 zkVM](https://github.com/succinctlabs/sp1) (RISC-V, Groth16/PLONK) |
| Threshold Sig | BLS12-381 G1, `@noble/bls12-381` |
| Identity | EC P-256 ECDSA, IEEE P1363, SPKI PEM |
| Credentials | W3C VC/VP (`did:ublp:*`) |
| Hash | SHA-256 (SP1 hardware precompile) |
| Key security | AES-256-GCM + PBKDF2 |
| Runtime | Node.js 20+, TypeScript, Fastify |
| Circuit | Rust (`no_std`, `sp1-zkvm`) |
---
## Quick Start
### Requirements
- Node.js 20+
- npm 10+
```bash
git clone https://github.com/ekacin/UBLP.git
cd UBLP/modules/zk-customs
npm install
npm run dev
```
npm run dev does the following:

Compiles all workspaces (tsc)
Committee (:3004) → Ministry (:3001) → Agent (:3002) → L2 (:3003)
Runs the customs broker demo: prepares document, receives VC from ministry, forwards to agent, logs L2 result
Ports:

3001 — Ministry
3002 — UBLP Agent / Carrier
3003 — L2 Verifier
3004 — Committee
customs-broker does not open a port — it is a one-shot demo script. In production, this role is handled by the customs broker's own system.

## Environment Variables

All services run with zero config in development mode. For production:

### Ministry (`ministry/.env`)

```env
# Private key encryption — if unset, stored as plaintext (development only!)
MINISTRY_KEY_PASSPHRASE=strong-passphrase-here

# Optional
MINISTRY_DID=did:ublp:ministry
COMMITTEE_URL=http://localhost:3004
```

### Committee (`committee/.env`)

```env
# BLS private key encryption — if unset, stored as plaintext (development only!)
COMMITTEE_KEY_PASSPHRASE=strong-passphrase-here

# Optional
COMMITTEE_PORT=3004
```

### UBLP Agent (`ublp-agent/.env`)

```env
# Optional
AGENT_DID=did:ublp:agent:default
L2_VERIFIER_URL=http://localhost:3003
COMMITTEE_URL=http://localhost:3004
```

### L2 Verifier (`l2-verifier-mock/.env`)

```env
# dev (default): accepts mock-ecdsa-p256
# sp1: accepts only sp1-groth16 / sp1-plonk
PROOF_MODE=dev

# Optional
MINISTRY_URL=http://localhost:3001
COMMITTEE_URL=http://localhost:3004
```

### Customs Broker (`customs-broker/.env`)

```env
# Optional — defaults work for development
MINISTRY_URL=http://localhost:3001
UBLP_AGENT_URL=http://localhost:3002

# Carrier DID embedded in document — must match agent's AGENT_DID
AGENT_DID=did:ublp:agent:default
```

### SP1 (For real ZK proving — optional)

```env
# Succinct Prover Network
SP1_PROVER_NETWORK_KEY=<succinct-api-key>
SP1_PROVER_URL=https://rpc.succinct.xyz

# ELF generated after "cargo prove build" in sp1-circuit/
SP1_ELF_PATH=sp1-circuit/elf/ublp-verifier
```

> If SP1 env is not set, the system automatically falls back to mock mode.

---

## API Reference

### Ministry — `POST /api/approve`

```json
{
  "documentId": "DOC-uuid",
  "holderDid": "did:ublp:agent:default",
  "exporterName": "ACME Logistics Ltd."
}
```

Returns: `UBLPVerifiableCredential`

### UBLP Agent — `POST /api/process`

```json
{
  "verifiableCredential": { "..." }
}
```

Returns: `{ presentation: UBLPVerifiablePresentation, l2Result: L2SettleResponse }`

### L2 Verifier — `GET /api/records`

Returns: `L2SettleRecord[]`

### L2 Verifier — `POST /api/revoke-key`

```json
{
  "ministryPublicKey": "-----BEGIN PUBLIC KEY-----...",
  "compromisedAt": "2024-01-15T10:00:00.000Z"
}
```

`compromisedAt` is optional. If omitted, key is rejected from this point forward; past records unaffected.

### L2 Verifier — `POST /api/sync`

Refreshes ministry and committee data (use if a service restarts).

---

## ZK Circuit (SP1)

`sp1-circuit/src/main.rs`

**Private inputs (not exposed to L2):**
1. `ministry_signature` — P-256 ECDSA, 64 byte IEEE P1363
2. `ministry_pub_key_raw` — uncompressed SEC1, 65 byte
3. `document_hash` — SHA256("ublp-doc-v1:" + canonicalJson), 32 byte
4. `document_id_hash` — 32 byte
5. `holder_signature` — P-256 ECDSA, 64 byte — holder privacy
6. `holder_pub_key_raw` — uncompressed SEC1, 65 byte
7. `holder_did` — UTF-8 bytes

**Public outputs (verified by L2):**
- `document_hash` — document fingerprint
- `ministry_pub_key_hash` — SHA256(ministry raw key)
- `document_id_hash` — replay protection
- `holder_pub_key_hash` — holder identity proof; hash only, not raw key

**Circuit build (requires Rust + SP1 toolchain):**

```bash
cd sp1-circuit
cargo prove build
```

---

## Security Model

| Risk | Protection |
|------|------------|
| Ministry monopoly | BLS t-of-n committee; 2/3 threshold |
| Holder identity leak | Holder sig is ZK private input; L2 only sees `holderPubKeyHash` |
| Document content leak | `rawDocument` excluded from VP; content consumed inside circuit |
| Replay attack | `documentIdHash` unique constraint on L2 |
| Key compromise | Timestamped revocation; only `settledAt >= compromisedAt` flagged SUSPICIOUS |
| Proof downgrade | `PROOF_MODE` set server-side; not client-controlled |
| Key at rest | Ministry + Committee: AES-256-GCM + PBKDF2 |

---

## v0.2 Roadmap

- [ ] BLS threshold verify → inside SP1 circuit (single Groth16 verify on L2)
- [ ] `groupKeyHash` as dynamic public input (committee rotation without circuit rebuild)
- [ ] PostgreSQL + Redis (replace `settled.json` flat-file)
- [ ] Binary calldata format (ABI-encoded instead of W3C JSON — gas savings)
- [ ] SP1 proof recursion + EIP-4844 blob batching (10x throughput)
- [ ] Agent key at rest encryption
- [ ] mTLS / API key authentication between services

---

## License

Apache 2.0 — Patent grant included. Commercial use unrestricted, no copyleft, no source disclosure required for modifications.

---

**Ecosystem:** [ekacin/UBLP](https://github.com/ekacin/UBLP)

*Efe Kaan Açin*
