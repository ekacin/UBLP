/**
 * Wallet-signature challenge-response login — AGENTS.md 5.26. No username/password ever
 * exists: the server hands out a random one-time nonce, the caller signs it with a private
 * key it holds, the server verifies the signature against a known public key. Off-chain, no
 * DUST/fee cost, never touches the chain (5.26 is explicit about that).
 *
 * REWRITE (2026-08-30): the previous version verified against a P-256 keypair the agent
 * itself generated and encrypted at rest (`identity.ts`'s old `loginKeyPair`), exposed to the
 * operator via a raw PEM export script the operator had to paste into the panel. Live-testing
 * that panel surfaced the real problem with this: pasting a raw private key into a browser
 * textarea is not something a real company would accept its staff doing (error-prone, no
 * revocation story, and the key sits in localStorage). This version verifies against a real
 * Midnight wallet's own "unshielded" signing key instead — the operator connects a wallet
 * extension (1AM/Lace) via the DApp Connector API's `signData()`, the private key never
 * leaves the extension's own isolated context, and this file verifies the result with
 * Midnight's own `verifySignature` (@midnight-ntwrk/ledger-v8) rather than a project-specific
 * P-256 scheme.
 *
 * WHAT WAS ACTUALLY CONFIRMED (2026-08-30), and what wasn't: this file's own verification
 * logic — the wire format, `bytesContains`, and Midnight's `verifySignature()` — was exercised
 * against a real signature produced by a real 1AM extension (window.midnight['1am'], API
 * 4.0.0) and accepted correctly, both inside the full HTTP round trip and re-checked in
 * isolation outside it. `signData()`'s returned `data` came back byte-identical to the
 * nonceHex sent in — 1AM adds no domain-prefix of its own, at least in this build.
 *
 * What this did NOT confirm: whether that signature came from the user's own real, deliberately
 * unlocked account. No approval popup was observed anywhere during connect()/signData() — the
 * user independently confirmed they had not been able to fully activate their own 1AM account
 * (separately hitting a "Gateway sign-in failed" error from 1AM's backend). The working theory
 * is that signData() may be answerable from a local/default keypair the extension already holds
 * without needing that backend-dependent activation step at all — plausible, since Gateway
 * involvement looks specific to fee sponsorship/proving, not local message signing — but this
 * is inference, not something directly observed. Until someone can watch a real approval prompt
 * happen against a fully-activated account, treat the *crypto/wire-format* layer as verified
 * and the *real end-user approval flow* as still open. verifyChallenge checks "nonce is a
 * substring of what was signed" rather than exact equality regardless, since a different wallet
 * (Lace, or a future 1AM version) could still add its own prefix — the substring check costs
 * nothing and is the more defensive default either way.
 *
 * Also worth remembering operationally: the first HTTP round-trip attempt failed even though
 * this file's logic was already correct, purely because the running settlement-agent process
 * hadn't been restarted since this rewrite landed — a stale process serves stale behavior no
 * matter how correct the source on disk is.
 *
 * ALSO OBSERVED — not this file's concern, but relevant context: 1AM's connect() only reliably
 * completed for 'mainnet' during this session; 'preview' succeeded once then hung on a retry,
 * matching the user's independently-reported "Gateway sign-in failed" for any network besides
 * local/main. That's 1AM's own backend availability, not something in this codebase.
 *
 * BOOTSTRAP MODEL (v0.1, single operator, matches the old scope note): the first wallet to
 * complete a valid challenge-response becomes the permanently authorized operator for this
 * agent, persisted to `<secretsDir>/authorized-operator.json` (a public verifying key, not a
 * secret — no encryption needed). Every later login must come from that same verifying key.
 * This is a trust-on-first-use bootstrap: whoever has access to the agent during its first
 * login window becomes its operator, the same trust level the agent's own SETTLEMENT_PASSPHRASE
 * already assumes. A real multi-employee deployment (several authorized keys, per-person audit
 * trail, an explicit admin-approval step instead of TOFU) is real future work (AGENTS.md 5.26)
 * but out of scope here — swapping the single stored key for a small authorized-keys table is a
 * mechanical follow-up that doesn't change the challenge-response protocol itself.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { verifySignature } from '@midnight-ntwrk/ledger-v8';

const CHALLENGE_TTL_MS = 2 * 60_000; // 2 minutes — long enough for a human to sign in a wallet UI
const SESSION_TTL_MS = 8 * 60 * 60_000; // 8 hours

interface Challenge {
  nonceHex: string;
  expiresAt: number;
}

interface Session {
  expiresAt: number;
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesContains(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

export class AuthStore {
  private readonly challenges = new Map<string, Challenge>();
  private readonly sessions = new Map<string, Session>();
  private readonly registryPath: string;
  private authorizedVerifyingKey: string | null;

  constructor(private readonly secretsDir: string) {
    this.registryPath = path.join(secretsDir, 'authorized-operator.json');
    this.authorizedVerifyingKey = this.loadAuthorizedVerifyingKey();
  }

  private loadAuthorizedVerifyingKey(): string | null {
    try {
      const raw = fs.readFileSync(this.registryPath, 'utf8');
      return (JSON.parse(raw) as { verifyingKey: string }).verifyingKey;
    } catch {
      return null;
    }
  }

  private persistAuthorizedVerifyingKey(verifyingKey: string): void {
    fs.mkdirSync(this.secretsDir, { recursive: true });
    fs.writeFileSync(this.registryPath, JSON.stringify({ verifyingKey }), 'utf8');
  }

  /** Step 1 of 5.26's flow: "Backend rastgele, tek kullanımlık bir nonce/mesaj üretir." */
  issueChallenge(): { challengeId: string; nonceHex: string; expiresAt: number } {
    const challengeId = crypto.randomUUID();
    const nonceHex = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + CHALLENGE_TTL_MS;
    this.challenges.set(challengeId, { nonceHex, expiresAt });
    return { challengeId, nonceHex, expiresAt };
  }

  /**
   * Step 4 of 5.26's flow, now against a wallet-produced signature.
   *
   * @param signedDataHex what the wallet says it actually signed (DApp Connector API's
   *   `Signature.data`) — expected to contain the original nonce, but not necessarily be
   *   byte-identical to it (the wallet may prepend its own domain-separation prefix; see the
   *   file header's KNOWN GAP note).
   * @param verifyingKey the wallet's own reported signing key (`Signature.verifyingKey`).
   */
  verifyChallenge(
    challengeId: string,
    signature: string,
    signedDataHex: string,
    verifyingKey: string
  ): { sessionToken: string; expiresAt: number } | null {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) return null;
    this.challenges.delete(challengeId); // one-time use regardless of outcome

    if (Date.now() > challenge.expiresAt) return null;

    const signedBytes = hexToBytes(signedDataHex);
    if (!bytesContains(signedBytes, hexToBytes(challenge.nonceHex))) return null;

    if (!verifySignature(verifyingKey, signedBytes, signature)) return null;

    if (this.authorizedVerifyingKey === null) {
      // First successful login bootstraps this key as the permanent operator (see file header).
      this.authorizedVerifyingKey = verifyingKey;
      this.persistAuthorizedVerifyingKey(verifyingKey);
    } else if (verifyingKey !== this.authorizedVerifyingKey) {
      return null;
    }

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + SESSION_TTL_MS;
    this.sessions.set(sessionToken, { expiresAt });
    return { sessionToken, expiresAt };
  }

  isSessionValid(sessionToken: string): boolean {
    const session = this.sessions.get(sessionToken);
    if (!session) return false;
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(sessionToken);
      return false;
    }
    return true;
  }

  revokeSession(sessionToken: string): void {
    this.sessions.delete(sessionToken);
  }

  /** Sweeps expired entries — call periodically so long-running processes don't leak memory. */
  sweepExpired(): void {
    const now = Date.now();
    for (const [id, c] of this.challenges) if (now > c.expiresAt) this.challenges.delete(id);
    for (const [token, s] of this.sessions) if (now > s.expiresAt) this.sessions.delete(token);
  }
}
