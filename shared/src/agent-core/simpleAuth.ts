/**
 * Passphrase-based session login — the wallet-free equivalent of incoterms-escrow's
 * `AuthStore` (`modules/incoterms-escrow/src/server/auth.ts`). For modules that have no
 * user-facing wallet identity to challenge (zk-customs' Ministry/Broker operators aren't
 * signing anything with a Midnight wallet), a shared secret set via env var is enough for v0.1:
 * the operator posts the passphrase once, gets back a session token, and every later request
 * carries that token as a bearer credential. No nonce/challenge round-trip is needed since
 * there's no wallet to sign a challenge with — the passphrase itself is the credential.
 */

import crypto from 'crypto';

interface Session {
  expiresAt: number;
}

const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60_000; // 8 hours, same default as escrow's AuthStore

export class SimpleSessionAuthStore {
  private readonly sessions = new Map<string, Session>();
  private readonly sessionTtlMs: number;

  constructor(private readonly passphrase: string, opts?: { sessionTtlMs?: number }) {
    this.sessionTtlMs = opts?.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  }

  /** Constant-time compare against the configured passphrase, then mints a session token.
   * Returns null on a wrong passphrase — deliberately no distinction in the response between
   * "wrong passphrase" and any other failure, same as escrow's challenge verification. */
  login(providedPassphrase: string): { sessionToken: string; expiresAt: number } | null {
    if (!timingSafeEqual(providedPassphrase, this.passphrase)) return null;

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + this.sessionTtlMs;
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

  /** Sweeps expired sessions — call periodically so long-running processes don't leak memory. */
  sweepExpired(): void {
    const now = Date.now();
    for (const [token, s] of this.sessions) if (now > s.expiresAt) this.sessions.delete(token);
  }
}

/** Same length regardless of where the strings first differ — avoids leaking passphrase length
 * or prefix via response-time differences. Falls back to `false` (never throws) when the two
 * inputs differ in byte length, since `crypto.timingSafeEqual` requires equal-length buffers. */
function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
