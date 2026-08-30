/**
 * AGENTS.md 5.28 — the panel subscribes directly to Midnight's own indexer for "did anything
 * change" signals, never through our backend. This deliberately does NOT decode the returned
 * `state`/`zswapState` blobs in the browser: that needs @midnight-ntwrk/compact-runtime + the
 * generated Escrow contract's ledger() function, which our settlement-agent already links in
 * (server/actions.ts's getDealStatus) and is proven working there. Duplicating that decode
 * path into the browser bundle would mean carrying Midnight's WASM runtime into the panel for
 * no benefit — this subscription exists purely as a lightweight trigger to refetch the
 * business-friendly view from our own agent's `/deals/:address/status`.
 *
 * Local devnet ("undeployed") indexer note: it serves /api/v3/graphql[/ws], not v4 — see the
 * `indexer` skill. VITE_INDEXER_WS_URL must be set accordingly per network.
 */

import { createClient, type Client } from 'graphql-ws';

const INDEXER_WS_URL = import.meta.env.VITE_INDEXER_WS_URL ?? 'ws://127.0.0.1:8088/api/v3/graphql/ws';

const CONTRACT_ACTIONS_SUBSCRIPTION = `
  subscription WatchContract($address: HexEncoded!) {
    contractActions(address: $address) {
      __typename
      address
      transaction {
        hash
        block { height timestamp }
      }
      ... on ContractCall {
        entryPoint
      }
    }
  }
`;

let sharedClient: Client | null = null;

function getClient(): Client {
  if (!sharedClient) {
    sharedClient = createClient({
      url: INDEXER_WS_URL,
      retryAttempts: Infinity,
      shouldRetry: () => true,
      retryWait: async (retries) => {
        await new Promise((r) => setTimeout(r, Math.min(1000 * 2 ** retries, 30_000)));
      },
    });
  }
  return sharedClient;
}

/** Calls `onChange` every time this contract address is deployed to, called, or updated —
 * callers should treat this purely as a "go refetch /status" trigger, not a data source.
 * Returns an unsubscribe function. */
export function watchContractActions(contractAddress: string, onChange: () => void): () => void {
  return getClient().subscribe(
    { query: CONTRACT_ACTIONS_SUBSCRIPTION, variables: { address: contractAddress } },
    {
      next: () => onChange(),
      error: (err) => console.error('[indexerWatch] subscription error', err),
      complete: () => {},
    }
  );
}
