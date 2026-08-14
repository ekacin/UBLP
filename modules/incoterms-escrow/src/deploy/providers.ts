/**
 * Assembles the full MidnightProviders set (indexer, proof server, ZK config, private
 * state, wallet/midnight bridge) for the escrow contract, using testkit-js's
 * initializeMidnightProviders — which builds all five from a single MidnightWalletProvider
 * rather than requiring us to wire each provider by hand.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { initializeMidnightProviders, type ContractConfiguration } from '@midnight-ntwrk/testkit-js';
import type { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
import type { EscrowCircuitId, EscrowPrivateStateId, EscrowPrivateState } from '../contract/index.js';
import type { NetworkConfig } from './networks.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Filesystem path to `compact compile`'s output — keys/ + zkir/ for every circuit. */
export const ESCROW_ZK_CONFIG_PATH = path.resolve(
  __dirname,
  '..',
  '..',
  'contracts',
  'managed',
  'escrow'
);

export function buildEscrowProviders(
  midnightWalletProvider: MidnightWalletProvider,
  network: NetworkConfig,
  role: string
) {
  const contractConfiguration: ContractConfiguration = {
    // Separate private-state store per role — each agent only ever holds its own secrets
    // (see witnesses.ts's role-separation note), so there's no reason for them to share one.
    privateStateStoreName: `incoterms-escrow-${role}`,
    zkConfigPath: ESCROW_ZK_CONFIG_PATH,
  };

  return initializeMidnightProviders<EscrowCircuitId, EscrowPrivateState>(
    midnightWalletProvider,
    network.envConfig(),
    contractConfiguration
  );
}

export type { EscrowPrivateStateId };
