/**
 * Network configuration for the deploy/provider layer (AGENTS.md 5.21). Only 'undeployed'
 * (local devnet) is wired up for now — see AGENTS.md for why local-first was chosen over
 * testnet. Shaped so preview/preprod/mainnet can be added later without restructuring.
 */

import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import type { EnvironmentConfiguration } from '@midnight-ntwrk/testkit-js';

export type NetworkId = 'undeployed';

export interface NetworkConfig {
  readonly networkId: NetworkId;
  readonly indexer: string;
  readonly indexerWS: string;
  readonly node: string;
  readonly nodeWS: string;
  readonly proofServer: string;
  envConfig(): EnvironmentConfiguration;
}

/** Matches midnight-local-dev's own standalone.yml endpoints exactly (v4 indexer API). */
export class UndeployedNetworkConfig implements NetworkConfig {
  readonly networkId: NetworkId = 'undeployed';
  readonly indexer = 'http://127.0.0.1:8088/api/v4/graphql';
  readonly indexerWS = 'ws://127.0.0.1:8088/api/v4/graphql/ws';
  readonly node = 'http://127.0.0.1:9944';
  readonly nodeWS = 'ws://127.0.0.1:9944';
  readonly proofServer = 'http://127.0.0.1:6300';

  constructor() {
    setNetworkId(this.networkId);
  }

  envConfig(): EnvironmentConfiguration {
    return {
      walletNetworkId: this.networkId,
      networkId: this.networkId,
      indexer: this.indexer,
      indexerWS: this.indexerWS,
      node: this.node,
      nodeWS: this.nodeWS,
      proofServer: this.proofServer,
      faucet: '',
    };
  }
}
