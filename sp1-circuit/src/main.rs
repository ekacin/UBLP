// UBLP ZK Verifier Circuit (SP1 zkVM)
//
// Private inputs (L2'ye açıklanmaz — circuit içinde tüketilir):
//   1. ministry_signature:     Vec<u8> — IEEE P1363, 64 byte (r||s)
//   2. ministry_pub_key_raw:   Vec<u8> — uncompressed P-256 point, 65 byte
//   3. document_hash:          Vec<u8> — SHA256(canonicalJson), 32 byte (önceden hesaplanmış)
//   4. document_id_hash:       Vec<u8> — SHA256(documentId), 32 byte
//   5. holder_signature:       Vec<u8> — IEEE P1363, 64 byte — K-3 holder auth
//   6. holder_pub_key_raw:     Vec<u8> — uncompressed P-256 point, 65 byte — K-3
//   7. holder_did:             Vec<u8> — UTF-8 bytes — K-3 payload
//
// NOT — Önceki tasarım (ham JSON) neden değişti:
//   Eski tasarım document_canonical_json'ı circuit'e private input olarak veriyordu.
//   SP1 RISC-V VM içinde string parse + key sıralama + dinamik bellek alloc
//   proof cycle'larını feci şişirir. Bakanlık trusted issuer → hash'i dışarıda
//   doğru hesaplar. Circuit yalnızca 32 byte sabit hash alır; cycle tasarrufu %80+.
//
// NOT — Gelecek v0.2 BLS migration tasarımı (groupKeyHash public input):
//   BLS komite doğrulaması circuit'e taşındığında groupKeyHash compile-time
//   sabiti OLMAMALI — public input olmalı. L2 geçerli kurul hash'ini devreye
//   paslar; circuit içeride SHA256(sort(signerPubKeys)) == groupKeyHash doğrular.
//   Böylece komite üyesi değiştiğinde ZK devresine dokunmak gerekmez, yalnızca
//   L2 state'i güncellenir.
//
// Public outputs — commit (L2 doğrular, Succinct API bağlar):
//   [0] document_hash:         [u8; 32] — SHA256(canonicalJson) — trusted issuer
//   [1] ministry_pub_key_hash: [u8; 32] — SHA256(ministry_pub_key_raw)
//   [2] document_id_hash:      [u8; 32] — replay koruması; proof'a bağlı
//   [3] holder_pub_key_hash:   [u8; 32] — K-3: SHA256(holder_pub_key_raw)
//
// Kriptografik bağlar:
//   - Ministry sig: SHA256(doc_hash || id_hash) üzerinde P-256 ECDSA
//   - Holder sig:   SHA256(doc_hash || id_hash || holder_did) üzerinde P-256 ECDSA
//                   Holder DID değiştirilirse imza kırılır → MitM koruması

#![no_main]
sp1_zkvm::entrypoint!(main);

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn main() {
    // ── Private inputs ──────────────────────────────────────────────────────────
    let ministry_signature: Vec<u8> = sp1_zkvm::io::read_vec();
    let ministry_pub_key_raw: Vec<u8> = sp1_zkvm::io::read_vec();
    // document_hash: önceden hesaplanmış SHA256(canonicalJson) — 32 byte
    // Trusted issuer model: Bakanlık hash'i dışarıda doğru hesaplar.
    // Ham JSON circuit'e sokulmuyor → masraf yok, güvenlik aynı.
    let document_hash_input: Vec<u8> = sp1_zkvm::io::read_vec();
    let document_id_hash: Vec<u8> = sp1_zkvm::io::read_vec();
    // K-3: holder auth private inputs — L2'ye hiç gönderilmez
    let holder_signature: Vec<u8> = sp1_zkvm::io::read_vec();
    let holder_pub_key_raw: Vec<u8> = sp1_zkvm::io::read_vec();
    let holder_did: Vec<u8> = sp1_zkvm::io::read_vec();

    // ── document_hash: pre-computed, trusted issuer ────────────────────────────
    let document_hash: [u8; 32] = document_hash_input
        .as_slice()
        .try_into()
        .expect("documentHash must be 32 bytes");

    let id_hash: [u8; 32] = document_id_hash
        .as_slice()
        .try_into()
        .expect("documentIdHash must be 32 bytes");

    // ── AÇIK-1 fix: ministry sig = SHA256(doc_hash || id_hash) ─────────────────
    let mut ministry_combined = Vec::with_capacity(64);
    ministry_combined.extend_from_slice(&document_hash);
    ministry_combined.extend_from_slice(&id_hash);
    let ministry_combined_hash: [u8; 32] = Sha256::digest(&ministry_combined).into();

    let ministry_vk = VerifyingKey::from_sec1_bytes(&ministry_pub_key_raw)
        .expect("invalid P-256 ministry public key");
    let ministry_sig_bytes: &[u8; 64] = ministry_signature
        .as_slice()
        .try_into()
        .expect("ministry signature must be 64 bytes");
    let ministry_sig = Signature::from_bytes(ministry_sig_bytes.into())
        .expect("invalid P1363 ministry signature");
    ministry_vk
        .verify_prehash(&ministry_combined_hash, &ministry_sig)
        .expect("ministry P-256 signature verification failed");

    // ── K-3 fix: holder sig = SHA256(doc_hash || id_hash || holder_did) ────────
    let mut holder_payload = Vec::new();
    holder_payload.extend_from_slice(&document_hash);
    holder_payload.extend_from_slice(&id_hash);
    holder_payload.extend_from_slice(&holder_did);
    let holder_payload_hash: [u8; 32] = Sha256::digest(&holder_payload).into();

    let holder_vk = VerifyingKey::from_sec1_bytes(&holder_pub_key_raw)
        .expect("invalid P-256 holder public key");
    let holder_sig_bytes: &[u8; 64] = holder_signature
        .as_slice()
        .try_into()
        .expect("holder signature must be 64 bytes");
    let holder_sig = Signature::from_bytes(holder_sig_bytes.into())
        .expect("invalid P1363 holder signature");
    holder_vk
        .verify_prehash(&holder_payload_hash, &holder_sig)
        .expect("holder P-256 signature verification failed");

    // ── Public outputs ──────────────────────────────────────────────────────────
    sp1_zkvm::io::commit(&document_hash);

    let ministry_pub_key_hash: [u8; 32] = Sha256::digest(&ministry_pub_key_raw).into();
    sp1_zkvm::io::commit(&ministry_pub_key_hash);

    sp1_zkvm::io::commit(&id_hash);

    // K-3: holder ham key değil sadece hash commit edilir — gizlilik korunur
    let holder_pub_key_hash: [u8; 32] = Sha256::digest(&holder_pub_key_raw).into();
    sp1_zkvm::io::commit(&holder_pub_key_hash);
}
