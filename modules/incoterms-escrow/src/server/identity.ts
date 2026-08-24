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
  /** AGENTS.md 5.26 — P-256 keypair behind the wallet-signature challenge-response login
   * (proves "whoever holds this key is authorized to operate this agent"). */
  loginKeyPair: LoginKeyPair;
  /**
   * P-256 keypair behind `escrow.ts`'s `proposeEscrow`/`verifyProposal` — proves "this
   * company's agent really signed off on these exact deal terms" (Section 5.12). Same key
   * *type* as loginKeyPair but a deliberately separate *instance*, for the same reason
   * roleKeyHash uses a domain separator per purpose (AGENTS.md's "never reuse a key across
   * domains" principle) — a login session proves operator access, not non-repudiable
   * agreement to specific business terms; conflating the two would let a valid login
   * signature potentially double as (or be confused for) a terms signature.
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

  const loginKeyPair = loadOrCreateKeyPairJson<LoginKeyPair>(
    path.join(secretsDir, `${role}-login-key.json`),
    passphrase,
    generateKeyPair
  );

  const dealSigningKeyPair = loadOrCreateKeyPairJson<LoginKeyPair>(
    path.join(secretsDir, `${role}-deal-signing-key.json`),
    passphrase,
    generateKeyPair
  );

  return { roleSecretKeyHex, memoKeyPair, loginKeyPair, dealSigningKeyPair };
}
