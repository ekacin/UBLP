/**
 * Finds a contract-held shielded coin's real Merkle-tree index (`mt_index`) — required by any
 * circuit that spends a coin the contract already holds (`claimPayout`, `releaseOnTimeout`).
 *
 * AGENTS.md 5.23 ("deepest finding"): the contract-scoped `zswapState`'s `firstFree` field
 * stays 0 even long after a real coin has landed — midnight-js-contracts' own call path hits
 * the same stale field, so `mt_index = firstFree - 1` fails with "invalid index into sparse
 * merkle tree". The only proven way to find the real index is dumping
 * `ZswapChainState.toString(true)` and regexing for the entry whose ContractAddress matches
 * ours — e.g. `46: (<commitment>, Some(ContractAddress(<our address>)))`.
 *
 * Lives here (not in scripts/devnet) so both the devnet scripts and the settlement-agent
 * server share one implementation. See AGENTS.md 5.28/5.29: the settlement-agent should try a
 * local cache (`server/db.ts`'s mt_index_cache) before calling this — it's a real indexer
 * round-trip plus a full state dump/regex, not cheap, and gives the mitigation for "indexer
 * temporarily down" some teeth.
 */

import { ZswapChainState } from '@midnight-ntwrk/ledger-v8';

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

export async function findContractCoinMtIndex(indexerUrl: string, contractAddress: string): Promise<bigint | null> {
  const res = await fetch(indexerUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      query: `query($address: HexEncoded!) { contractAction(address: $address) { zswapState } }`,
      variables: { address: contractAddress },
    }),
  });
  const payload = (await res.json()) as any;
  const zswapStateHex: string | undefined = payload?.data?.contractAction?.zswapState;
  if (!zswapStateHex) return null;
  const state = ZswapChainState.deserialize(hexToBytes(zswapStateHex));
  const dump = state.toString(true);
  const pattern = new RegExp(`(\\d+): \\([0-9a-f]+, Some\\(ContractAddress\\(${contractAddress}\\)\\)\\)`);
  const match = dump.match(pattern);
  return match ? BigInt(match[1]) : null;
}

/** Polls `findContractCoinMtIndex` until the indexer has caught up with a just-landed deposit. */
export async function waitForContractCoinMtIndex(
  indexerUrl: string,
  contractAddress: string,
  maxAttempts = 30
): Promise<bigint> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const mtIndex = await findContractCoinMtIndex(indexerUrl, contractAddress);
    if (mtIndex !== null) return mtIndex;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error('Could not find the deposited coin in the indexed zswap state.');
}
