/**
 * Settlement-agent entrypoint. AGENTS.md 5.27: one process = one role = one company's own
 * deployment, self-hosted on that company's own infrastructure — never UBLP's. Wires together
 * everything server/*.ts defines: identity, wallet, providers, the two local SQLite stores,
 * auth, and the HTTP routes.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { openTransactionLog } from '@ublp/shared';
import { createAgentServer, startAgentServer } from '@ublp/shared';
import { buildAgentWallet, type AgentRole } from '../deploy/wallet.js';
import { buildEscrowProviders } from '../deploy/providers.js';
import { UndeployedNetworkConfig, type NetworkConfig } from '../deploy/networks.js';
import { loadOrCreateSettlementIdentity } from './identity.js';
import { openSettlementDb } from './db.js';
import { AuthStore } from './auth.js';
import { registerSettlementRoutes } from './routes.js';
import { startDealWatcher } from './watcher.js';
import type { AgentContext } from './actions.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface SettlementAgentConfig {
  role: AgentRole;
  /** Only `undeployed` (local devnet) is wired up today — see deploy/networks.ts. Passing a
   * pre-built NetworkConfig keeps this ready for preview/preprod without changing this file. */
  network?: NetworkConfig;
  /** Decrypts this agent's wallet mnemonic AND its identity secrets (role key, memo key,
   * login key) — same passphrase for all of them, one secret to actually protect. In
   * production this should come from a secrets manager, not an env var/CLI flag (AGENTS.md
   * 5.21's KMS/HSM note applies here too). */
  passphrase: string;
  port: number;
  /** Defaults to <package root>/.settlement-secrets and .settlement-data next to the existing
   * .devnet-secrets/data conventions. */
  secretsDir?: string;
  dataDir?: string;
}

export async function startSettlementAgent(config: SettlementAgentConfig): Promise<{ stop: () => Promise<void> }> {
  const network = config.network ?? new UndeployedNetworkConfig();
  const secretsDir = config.secretsDir ?? path.join(__dirname, '..', '..', '.settlement-secrets');
  const dataDir = config.dataDir ?? path.join(__dirname, '..', '..', 'data');

  const identity = loadOrCreateSettlementIdentity(secretsDir, config.role, config.passphrase);
  const wallet = await buildAgentWallet(config.role, network, config.passphrase);
  const providers = buildEscrowProviders(wallet.midnightWalletProvider, network, config.role);

  const db = openSettlementDb(path.join(dataDir, 'settlement-agent.db'));
  const txLog = openTransactionLog(path.join(dataDir, 'transactions.db'));

  const ctx: AgentContext = { role: config.role, network, wallet, providers, identity, db, txLog };
  const auth = new AuthStore(identity.loginKeyPair.publicKey);
  const sweepInterval = setInterval(() => auth.sweepExpired(), 60_000);

  const app = createAgentServer({ logger: true });
  registerSettlementRoutes(app, ctx, auth);
  await startAgentServer(app, { port: config.port });

  const watcher = startDealWatcher(ctx);

  return {
    stop: async () => {
      watcher.stop();
      clearInterval(sweepInterval);
      await app.close();
      db.close();
      txLog.close();
      await wallet.wallet.stop();
    },
  };
}
