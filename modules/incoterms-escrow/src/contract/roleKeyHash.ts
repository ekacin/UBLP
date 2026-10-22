/**
 * TS mirror of Escrow.compact's `roleKeyHash` pure circuit. Used to derive
 * `portAuthorityKeyHash` off-chain, which is never re-derived on-chain: the caller must
 * supply the already-hashed value directly to `propose()`, and `attestMilestone()`'s own
 * `roleKeyHash(sk, domain) == portAuthorityKeyHash` check is what actually proves this
 * replica matches the real circuit — every devnet script that calls attestMilestone()
 * (full-lifecycle, timeout-lifecycle, e2e-settlement-agent) exercises this implicitly; a
 * drift here would surface as that assertion failing, loudly.
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
