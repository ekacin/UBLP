# UBLP — Unified Blockchain Logistics Protocol

Lojistik süreçlerini uçtan uca kriptografik güvence altına alan çok modüllü açık protokol.

Zero-Knowledge kanıtı, BLS eşik imzası ve W3C Verifiable Credentials kombinasyonu ile gümrük, taşımacılık ve tedarik zinciri belgelerini manipülasyona karşı matematiksel olarak korur.

---

## Modüller

| Modül | Dizin | Açıklama |
|-------|-------|----------|
| ZK Gümrük Doğrulama | [`modules/zk-customs`](./modules/zk-customs) | Gümrük belgesi ZK kanıtı, BLS kurul onayı, L2 settlement |

---

## Hızlı Başlangıç

Her modül bağımsız çalışır. ZK Gümrük modülü için:

```bash
cd modules/zk-customs
npm install
npm run dev
```

---

## Lisans

Apache 2.0 — bkz. [LICENSE](./LICENSE)

*Efe Kaan Açın — [acinefekaan@gmail.com](mailto:acinefekaan@gmail.com)*
