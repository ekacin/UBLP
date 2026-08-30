/**
 * Persistent per-role identity for a settlement-agent instance. AGENTS.md 5.27: one
 * settlement-agent process represents exactly one role (buyer/seller/port-authority) for one
 * company, self-hosted — so these secrets are generated once on first boot and reused across
 * every future deal, unlike the devnet scripts (full-lifecycle.ts etc.) which mint fresh
 * throwaway keys per run. Reuses the same AES-256-GCM+PBKDF2 encrypted-at-rest scheme wallet
 * mnemonics already use (`@ublp/shared`'s walletKeyStorage), rather than inventing a second one.
 */

import path from 'path';
import crypto from 'crypto';
import {
  loadOrCreateEncryptedSecret,
  generateKeyPair,
  generateX25519KeyPair,
  type X25519KeyPair,
} from '@ublp/shared';
import type { AgentRole } from '../deploy/wallet.js';

export interface LoginKeyPair {
  privateKey: string; // PEM
  publicKey: string; // PEM
}

export interface SettlementIdentity {
  /**
   * 32-byte hex secret behind `roleKeyHash()` (Escrow.compact) — `sellerSecretKey` for the
   * seller role, `portAuthoritySecretKey` for the port-authority role. `null` for buyer: the
   * contract has no buyer role-key witness (buyer's authority comes from actually holding the
   * funds/signing the lockEscrow transaction, not a role-hash check).
   */
  roleSecretKeyHex: string | null;
  /** AGENTS.md 5.18 — X25519 keypair for the dual-recipient encrypted memo. */
  memoKeyPair: X25519KeyPair;
  /**
   * P-256 keypair behind `escrow.ts`'s `proposeEscrow`/`verifyProposal` — proves "this
   * company's agent really signed off on these exact deal terms" (Section 5.12). Deliberately
   * separate from operator login (AGENTS.md 5.26/auth.ts): login now proves "a real Midnight
   * wallet, held by a human operator, authorized this session" via the operator's own wallet
   * extension — a fundamentally different, external identity, not something this agent
   * generates or holds. Conflating the two would let a login session double as (or be
   * confused for) non-repudiable agreement to specific business terms.
   */
  dealSigningKeyPair: LoginKeyPair;
}

function randomHex32(): string {
  return crypto.randomBytes(32).toString('hex');
}

/** `loadOrCreateEncryptedSecret` is typed around a single "hex" string, but its storage is
 * just AES-GCM over UTF-8 bytes (see walletKeyStorage.ts) — safe to hand it any string,
 * including JSON, letting a keypair (not just a lone secret) be persisted as one unit. */
function loadOrCreateKeyPairJson<T>(filePath: string, passphrase: string, generate: () => T): T {
  const json = loadOrCreateEncryptedSecret(filePath, passphrase, () => JSON.stringify(generate()));
  return JSON.parse(json) as T;
}

export function loadOrCreateSettlementIdentity(
  secretsDir: string,
  role: AgentRole,
  passphrase: string
): SettlementIdentity {
  const roleSecretKeyHex =
    role === 'buyer'
      ? null
      : loadOrCreateEncryptedSecret(path.join(secretsDir, `${role}-role-key.json`), passphrase, randomHex32);

  const memoKeyPair = loadOrCreateKeyPairJson<X25519KeyPair>(
    path.join(secretsDir, `${role}-memo-key.json`),
    passphrase,
    generateX25519KeyPair
  );

  const dealSigningKeyPair = loadOrCreateKeyPairJson<LoginKeyPair>(
    path.join(secretsDir, `${role}-deal-signing-key.json`),
    passphrase,
    generateKeyPair
  );

  return { roleSecretKeyHex, memoKeyPair, dealSigningKeyPair };
}
