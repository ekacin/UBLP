# UBLP — Universal Blockchain Logistics Protocol

A multi-module open protocol for end-to-end cryptographic security across logistics processes.

Protects customs, freight, and supply chain documents against manipulation using Zero-Knowledge proofs, BLS threshold signatures, and W3C Verifiable Credentials.

---

## Modules

| Module | Directory | Description |
|--------|-----------|-------------|
| ZK Customs Clearance | [`modules/zk-customs`](./modules/zk-customs) | Customs document ZK proof, BLS committee attestation, L2 settlement |
| Incoterms Escrow | [`modules/incoterms-escrow`](./modules/incoterms-escrow) | Incoterms-based trade escrow on Midnight Network, with ZK-shielded fund custody and encrypted agent-to-agent deal delivery |

---

## Quick Start

Each module runs independently. For the ZK Customs module:

```bash
cd modules/zk-customs
npm install
npm run dev
```

## Contributors
| | |
|---|---|
| **Efe Kaan Açin** | Architect, developer |
---
## License
Apache 2.0 — see [LICENSE](./LICENSE)
