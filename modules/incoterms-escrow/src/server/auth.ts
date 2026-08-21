/**
 * Wallet-signature challenge-response login — AGENTS.md 5.26. No username/password ever
 * exists: the server hands out a random one-time nonce, the caller signs it with a private
 * key it holds, the server verifies the signature against a known public key. Off-chain, no
 * DUST/fee cost, never touches the chain (5.26 is explicit about that).
 *
 * Reuses documentCrypto.ts's P-256 primitives (`verifySignatureOverHash`) — the same key type
 * escrow.ts's proposeEscrow/verifyProposal already signs EscrowTerms with — instead of a new
 * signature scheme.
 *
 * SCOPE NOTE (v0.1): this settlement-agent instance has exactly ONE operator login keypair
 * (identity.ts's `loginKeyPair`), representing "whoever is authorized to operate this agent
 * on the company's behalf." Real multi-employee accounts (several people, several keys,
 * per-person audit trail) are a real future need (AGENTS.md 5.26's multi-user wallet
 * discussion) but out of scope here — swapping the single `authorizedPublicKeyPem` check
 * below for a lookup against a small table of authorized keys is a mechanical follow-up that
 * doesn't change the challenge-response protocol itself.
 */

import crypto from 'crypto';
import { verifySignatureOverHash } from '@ublp/shared';

const CHALLENGE_TTL_MS = 2 * 60_000; // 2 minutes — long enough for a human to sign in a wallet UI
const SESSION_TTL_MS = 8 * 60 * 60_000; // 8 hours

interface Challenge {
  nonceHex: string;
  expiresAt: number;
}

interface Session {
  expiresAt: number;
}

export class AuthStore {
  private readonly challenges = new Map<string, Challenge>();
  private readonly sessions = new Map<string, Session>();

  constructor(private readonly authorizedPublicKeyPem: string) {}

  /** Step 1 of 5.26's flow: "Backend rastgele, tek kullanımlık bir nonce/mesaj üretir." */
  issueChallenge(): { challengeId: string; nonceHex: string; expiresAt: number } {
    const challengeId = crypto.randomUUID();
    const nonceHex = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + CHALLENGE_TTL_MS;
    this.challenges.set(challengeId, { nonceHex, expiresAt });
    return { challengeId, nonceHex, expiresAt };
  }

  /** Step 4 of 5.26's flow: "Backend imzayı iddia edilen adresin public key'iyle doğrular." */
  verifyChallenge(challengeId: string, signature: string): { sessionToken: string; expiresAt: number } | null {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) return null;
    this.challenges.delete(challengeId); // one-time use regardless of outcome

    if (Date.now() > challenge.expiresAt) return null;

    const valid = verifySignatureOverHash(challenge.nonceHex, signature, this.authorizedPublicKeyPem);
    if (!valid) return null;

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
