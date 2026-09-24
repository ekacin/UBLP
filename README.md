# UBLP — Universal Blockchain Logistics Protocol

A multi-module, multi-chain open protocol for end-to-end cryptographic security across
logistics processes. Each module picks the chain that fits its own requirements — see the
table below for which chain each module currently targets.

Protects customs, freight, and supply chain documents against manipulation using Zero-Knowledge proofs, BLS threshold signatures, and W3C Verifiable Credentials.

---

## Modules

| Module | Directory | Chain | Description |
|--------|-----------|-------|-------------|
| ZK Customs Clearance | [`modules/zk-customs`](./modules/zk-customs) | TBD (SP1 zkVM, L2 settlement currently mocked) | Customs document ZK proof, BLS committee attestation, L2 settlement |
| Incoterms Escrow | [`modules/incoterms-escrow`](./modules/incoterms-escrow) | Midnight Network | Incoterms-based trade escrow with ZK-shielded fund custody and encrypted agent-to-agent deal delivery |

---

## Quick Start

Each module runs independently.

**ZK Customs Clearance:**

```bash
cd modules/zk-customs
npm install
npm run dev
```

**Incoterms Escrow:**

```bash
cd modules/incoterms-escrow
npm install
```

See [`modules/incoterms-escrow/README.md`](./modules/incoterms-escrow/README.md) for the full
local-devnet setup (funding wallets, running buyer/seller/port-authority agents, etc.) — it
needs more than `npm install` to run end-to-end.

## Contributors
| | |
|---|---|
| **Efe Kaan Açin** | Architect, developer |
---
## License
GPL-3 — see [LICENSE](./LICENSE)
