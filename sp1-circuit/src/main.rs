// UBLP ZK Verifier Circuit (SP1 zkVM)
//
// Private inputs (L2'ye açıklanmaz — circuit içinde tüketilir):
//   1. ministry_signature:        Vec<u8> — IEEE P1363, 64 byte (r||s)
//   2. ministry_pub_key_raw:      Vec<u8> — uncompressed P-256 point, 65 byte
//   3. document_canonical_json:   Vec<u8> — canonicalJson(document) UTF-8 bytes
//   4. document_id_hash:          Vec<u8> — SHA256(documentId), 32 byte
//   5. holder_signature:          Vec<u8> — IEEE P1363, 64 byte — K-3 holder auth
//   6. holder_pub_key_raw:        Vec<u8> — uncompressed P-256 point, 65 byte — K-3
//   7. holder_did:                Vec<u8> — UTF-8 bytes — K-3 payload
//
// Public outputs — commit (L2 doğrular, Succinct API bağlar):
//   [0] document_hash:      [u8; 32] — SHA256(canonicalJson) — devrede hesaplanır
//   [1] ministry_pub_key_hash: [u8; 32] — SHA256(ministry_pub_key_raw)
//   [2] document_id_hash:   [u8; 32] — replay koruması; proof'a bağlı
//   [3] holder_pub_key_hash:[u8; 32] — K-3: SHA256(holder_pub_key_raw)
//                                       L2 sadece bu hash'i görür — ham key sızmaz
//
// Kriptografik bağlar:
//   - AÇIK-1 fix: ministry sig = SHA256(doc_hash || id_hash) üzerinde
//   - K-3 fix:    holder sig = SHA256(doc_hash || id_hash || holder_did) üzerinde
//                 Böylece holder_did değiştirilirse imza kırılır (MitM koruması)

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
    // K-3: holder auth private inputs — L2'ye hiç gönderilmez
    let holder_signature: Vec<u8> = sp1_zkvm::io::read_vec();
    let holder_pub_key_raw: Vec<u8> = sp1_zkvm::io::read_vec();
    let holder_did: Vec<u8> = sp1_zkvm::io::read_vec();

    // ── document_hash devrede hesaplanır ───────────────────────────────────────
    let document_hash: [u8; 32] = Sha256::digest(&document_canonical_json).into();

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
    // Holder DID, belgeye bağlanır — DID değiştirilirse bu constraint kırılır.
    // L2 ham holder sig veya public key görmez; yalnızca holder_pub_key_hash commit edilir.
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
