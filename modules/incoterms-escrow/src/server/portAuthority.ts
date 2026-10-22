/**
 * Buyer-side resolution of C's role-key hash via did:web — AGENTS.md 5.35 (Discord finding
 * #2 fix). Called once per lockDeal, before lockEscrow: fetches the port authority's own
 * did:web document, checks it against the TOFU whitelist (server/db.ts's trusted_ports), and
 * hands back a value the caller still must assert against the seller's proposed terms (that
 * comparison is also re-checked on-chain by the circuit itself — see Escrow.compact's
 * lockEscrow()).
 */

import { fetchDidWebDocument, parseDidWeb, type DidWeb } from '@ublp/shared';
import { getTrustedPort, recordTrustedPort, type SettlementDb } from './db.js';

export interface ResolvedPortAuthority {
  roleKeyHashHex: string;
  /** Already IDNA/punycode-normalized (server/didWeb.ts) — safe to display as-is, including
   * to flag a suspicious-looking domain, since it's never a pretty-rendered Unicode form a
   * homograph could hide behind. */
  domain: string;
  /** True the first time this agent has ever seen this domain (TOFU's "trust" moment). */
  firstSeen: boolean;
}

function isPortAuthorityDocument(doc: unknown): doc is { portAuthorityKeyHashHex: string } {
  return (
    !!doc &&
    typeof doc === 'object' &&
    typeof (doc as Record<string, unknown>).portAuthorityKeyHashHex === 'string' &&
    /^[0-9a-f]{64}$/i.test((doc as Record<string, unknown>).portAuthorityKeyHashHex as string)
  );
}

export async function resolvePortAuthorityKeyHash(
  db: SettlementDb,
  did: DidWeb
): Promise<ResolvedPortAuthority> {
  const { host: domain } = parseDidWeb(did);
  const doc = await fetchDidWebDocument(did);
  if (!isPortAuthorityDocument(doc)) {
    throw new Error(`did:web document at ${did} is missing a valid portAuthorityKeyHashHex field.`);
  }
  const roleKeyHashHex = doc.portAuthorityKeyHashHex.toLowerCase();

  const existing = getTrustedPort(db, domain);
  if (existing && existing.roleKeyHashHex.toLowerCase() !== roleKeyHashHex) {
    // Deliberately a hard stop, not a silent overwrite — see db.ts's recordTrustedPort doc
    // comment for why. Either a legitimate key rotation or an impersonation attempt; this
    // code can't tell which, so it refuses and leaves the decision to a human operator (who
    // must explicitly clear the old trusted_ports row to accept the new key).
    throw new Error(
      `TOFU violation: ${domain} previously published role-key hash ${existing.roleKeyHashHex.slice(0, 16)}... ` +
        `but now publishes ${roleKeyHashHex.slice(0, 16)}... — refusing to lock automatically. If this is a ` +
        `known key rotation, an operator must confirm and clear the old trusted_ports row before retrying.`
    );
  }

  const firstSeen = existing === null;
  recordTrustedPort(db, domain, roleKeyHashHex);
  return { roleKeyHashHex, domain, firstSeen };
}
