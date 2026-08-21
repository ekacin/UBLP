/**
 * TS mirror of Escrow.compact's `roleKeyHash` pure circuit. Validated against the real
 * on-chain circuit in scripts/devnet/full-lifecycle.ts's step 0 (the on-chain `sellerKeyHash`
 * written by propose() matched this replica exactly) before being trusted for deriving
 * `portAuthorityKeyHash` off-chain, which — unlike sellerKeyHash — is never re-derived
 * on-chain: the caller must supply the already-hashed value directly.
 *
 * Lives here (not in scripts/devnet) so both the devnet scripts and the settlement-agent
 * server can import the same validated implementation instead of two copies drifting apart.
 */

import { persistentHash, CompactTypeBytes, CompactTypeVector } from '@midnight-ntwrk/compact-runtime';

export function roleKeyHash(sk: Uint8Array, domain: string): Uint8Array {
  const domainBytes = Buffer.alloc(32);
  Buffer.from(domain, 'utf8').copy(domainBytes);
  const rtType = new CompactTypeVector(2, new CompactTypeBytes(32));
  return persistentHash(rtType, [domainBytes, Buffer.from(sk)]);
}
