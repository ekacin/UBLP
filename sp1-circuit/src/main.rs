// UBLP ZK Verifier Circuit (SP1 zkVM)
//
// Private inputs (L2'ye açıklanmaz):
//   1. ministry_signature:        Vec<u8> — IEEE P1363, 64 byte (r||s)
//   2. ministry_pub_key_raw:      Vec<u8> — uncompressed P-256 point, 65 byte
//   3. document_canonical_json:   Vec<u8> — canonicalJson(document) UTF-8 bytes
//   4. document_id_hash:          Vec<u8> — SHA256(documentId), 32 byte
//
// Public outputs — commit (L2 doğrular, Succinct API bağlar):
//   [0] document_hash:    [u8; 32] — SHA256(canonicalJson) — devrenin içinde hesaplanır
//   [1] pub_key_hash:     [u8; 32] — SHA256(ministry_pub_key_raw)
//   [2] document_id_hash: [u8; 32] — replay koruması; proof'a bağlanır
//
// AÇIK-1 fix:
//   Bakanlık imzası SHA256(document_hash || document_id_hash) birleşik hash'i
//   kapsar. Devre bu birleşik hash'i hesaplar ve imzayı onun üzerinde doğrular.
//   Böylece saldırgan document_id_hash'i proof'tan bağımsız olarak değiştiremez.
//
// AÇIK-2 (Hash algoritması eşleşme kuralı):
//   Bu devre SHA-256 kullanır. TypeScript tarafında `poseidon2Hash` da SHA-256 stub'ıdır.
//   Gerçek Poseidon2'ye geçiş yapılacaksa HER İKİ YAN birlikte değişmelidir:
//     - Rust: `sha2` → `light-poseidon` veya `zkhash`
//     - TypeScript: `poseidon2Hash` gövdesi → gerçek Poseidon2 impl

#![no_main]
sp1_zkvm::entrypoint!(main);

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn main() {
    // ── Private inputs ──────────────────────────────────────────────────────────
    let ministry_signature: Vec<u8> = sp1_zkvm::io::read_vec();
    let ministry_pub_key_raw: Vec<u8> = sp1_zkvm::io::read_vec();
    let document_canonical_json: Vec<u8> = sp1_zkvm::io::read_vec();
    let document_id_hash: Vec<u8> = sp1_zkvm::io::read_vec();

    // ── document_hash devrenin IÇINDE hesaplanır ────────────────────────────────
    let document_hash: [u8; 32] = Sha256::digest(&document_canonical_json).into();

    // ── document_id_hash'i 32 byte'a dönüştür ──────────────────────────────────
    let id_hash: [u8; 32] = document_id_hash
        .as_slice()
        .try_into()
        .expect("documentIdHash must be 32 bytes");

    // ── AÇIK-1 fix: birleşik hash — sig hem document_hash hem id_hash'i kapsar ─
    // SHA256(document_hash || id_hash): 32+32=64 byte input
    // Bakanlık TypeScript'te aynı combined hash'i imzalar (combinedSignatureHash()).
    // Saldırgan id_hash'i değiştirirse imza doğrulaması başarısız olur.
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&document_hash);
    combined.extend_from_slice(&id_hash);
    let combined_hash: [u8; 32] = Sha256::digest(&combined).into();

    // ── ECDSA P-256 imza doğrulama ─────────────────────────────────────────────
    let verifying_key = VerifyingKey::from_sec1_bytes(&ministry_pub_key_raw)
        .expect("invalid P-256 public key");

    let sig_bytes: &[u8; 64] = ministry_signature
        .as_slice()
        .try_into()
        .expect("signature must be 64 bytes (IEEE P1363)");
    let signature = Signature::from_bytes(sig_bytes.into()).expect("invalid P1363 signature");

    verifying_key
        .verify_prehash(&combined_hash, &signature)
        .expect("P-256 signature verification failed");

    // ── Public outputs ──────────────────────────────────────────────────────────
    sp1_zkvm::io::commit(&document_hash);

    let pub_key_hash: [u8; 32] = Sha256::digest(&ministry_pub_key_raw).into();
    sp1_zkvm::io::commit(&pub_key_hash);

    sp1_zkvm::io::commit(&id_hash);
}
