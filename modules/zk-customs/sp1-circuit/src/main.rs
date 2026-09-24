// UBLP ZK Verifier Circuit (SP1 zkVM)
//
// Private inputs (never disclosed to L2 — consumed inside the circuit):
//   1. ministry_signature:     Vec<u8> — IEEE P1363, 64 byte (r||s)
//   2. ministry_pub_key_raw:   Vec<u8> — uncompressed P-256 point, 65 byte
//   3. document_hash:          Vec<u8> — SHA256("ublp-doc-v1:" + canonicalJson), 32 byte
//   4. document_id_hash:       Vec<u8> — SHA256(documentId), 32 byte
//   5. holder_signature:       Vec<u8> — IEEE P1363, 64 byte — K-3 holder auth
//   6. holder_pub_key_raw:     Vec<u8> — uncompressed P-256 point, 65 byte — K-3
//   7. holder_did:             Vec<u8> — UTF-8 bytes — K-3 payload
//
// NOTE — why the previous design (raw JSON) changed:
//   The old design fed document_canonical_json into the circuit as a private input.
//   Inside the SP1 RISC-V VM, string parsing + key sorting + dynamic memory alloc
//   massively inflates proof cycles. The Ministry is a trusted issuer → it computes
//   the hash correctly outside. The circuit only takes a fixed 32-byte hash; cycle
//   savings 80%+.
//
// NOTE — future v0.2 BLS migration design (groupKeyHash public input):
//   When BLS committee verification moves into the circuit, groupKeyHash must NOT
//   be a compile-time constant — it must be a public input. L2 passes the current
//   committee hash into the circuit; internally it verifies
//   SHA256(sort(signerPubKeys)) == groupKeyHash. That way, when a committee member
//   changes, the ZK circuit doesn't need touching — only the L2 state is updated.
//
// Public outputs — commit (verified by L2, bound via the Succinct API):
//   [0] document_hash:         [u8; 32] — SHA256("ublp-doc-v1:" + canonicalJson) — trusted issuer
//   [1] ministry_pub_key_hash: [u8; 32] — SHA256(ministry_pub_key_raw)
//   [2] document_id_hash:      [u8; 32] — replay protection; bound to the proof
//   [3] holder_pub_key_hash:   [u8; 32] — K-3: SHA256(holder_pub_key_raw)
//
// Cryptographic bindings:
//   - Ministry sig: P-256 ECDSA over SHA256(doc_hash || id_hash)
//   - Holder sig:   P-256 ECDSA over SHA256(doc_hash || id_hash || holder_did)
//                   If the holder DID is tampered with, the signature breaks → MitM protection

#![no_main]
sp1_zkvm::entrypoint!(main);

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn main() {
    // ── Private inputs ──────────────────────────────────────────────────────────
    let ministry_signature: Vec<u8> = sp1_zkvm::io::read_vec();
    let ministry_pub_key_raw: Vec<u8> = sp1_zkvm::io::read_vec();
    // document_hash: SHA256("ublp-doc-v1:" + canonicalJson), computed by the ministry/agent.
    // The domain prefix prevents cross-protocol hash collisions.
    // Raw JSON is never fed into the circuit → no extra cost, same security.
    let document_hash_input: Vec<u8> = sp1_zkvm::io::read_vec();
    let document_id_hash: Vec<u8> = sp1_zkvm::io::read_vec();
    // K-3: holder auth private inputs — never sent to L2
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

    // ── OPEN-1 fix: ministry sig = SHA256(doc_hash || id_hash) ─────────────────
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

    // K-3: only the hash is committed, not the raw holder key — privacy preserved
    let holder_pub_key_hash: [u8; 32] = Sha256::digest(&holder_pub_key_raw).into();
    sp1_zkvm::io::commit(&holder_pub_key_hash);
}
