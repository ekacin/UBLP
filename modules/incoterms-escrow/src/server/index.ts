/**
 * Settlement-agent entrypoint. AGENTS.md 5.27: one process = one role = one company's own
 * deployment, self-hosted on that company's own infrastructure — never UBLP's. Wires together
 * everything server/*.ts defines: identity, wallet, providers, the two local SQLite stores,
 * auth, and the HTTP routes.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { openTransactionLog, isUBLPDid, type UBLPDid } from '@ublp/shared';
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
  /** This company's own DID, e.g. `did:ublp:buyer:acme-import` — a human-chosen label, not
   * derived from any key, so it has to be operator-configured. Used by acceptEscrow (see
   * actions.ts's lockDeal) to check an incoming EscrowProposal was actually addressed to
   * this company, not some other buyer's offer. */
  did: UBLPDid;
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
  /** Defaults to 60s (watcher.ts). Overridable mainly for tests — a real deployment has no
   * reason to poll faster than once a minute. */
  watcherIntervalMs?: number;
  /** Throttles the unauthenticated `/deals/incoming` write endpoint (agent-to-agent proposal
   * delivery) — deliberately a config knob, not a hardcoded constant, since what's a
   * reasonable rate depends on the operator's own traffic patterns. Defaults to a
   * conservative 20 requests/minute per source IP. */
  incomingOfferRateLimit?: { max: number; timeWindow: string | number };
}

export async function startSettlementAgent(config: SettlementAgentConfig): Promise<{ stop: () => Promise<void> }> {
  if (!isUBLPDid(config.did)) throw new Error('config.did must be a valid did:ublp:... identifier.');
  const network = config.network ?? new UndeployedNetworkConfig();
  const secretsDir = config.secretsDir ?? path.join(__dirname, '..', '..', '.settlement-secrets');
  const dataDir = config.dataDir ?? path.join(__dirname, '..', '..', 'data');

  const identity = loadOrCreateSettlementIdentity(secretsDir, config.role, config.passphrase);
  const wallet = await buildAgentWallet(config.role, network, config.passphrase);
  const providers = buildEscrowProviders(wallet.midnightWalletProvider, network, config.role);

  const db = openSettlementDb(path.join(dataDir, 'settlement-agent.db'));
  const txLog = openTransactionLog(path.join(dataDir, 'transactions.db'));

  const incomingOfferRateLimit = config.incomingOfferRateLimit ?? { max: 20, timeWindow: '1 minute' };
  const ctx: AgentContext = {
    role: config.role,
    did: config.did,
    network,
    wallet,
    providers,
    identity,
    db,
    txLog,
    incomingOfferRateLimit,
  };
  const auth = new AuthStore(secretsDir);
  const sweepInterval = setInterval(() => auth.sweepExpired(), 60_000);

  const app = createAgentServer({ logger: true });
  // The panel (AGENTS.md 5.26) is a separate origin (its own Vite dev server or static host)
  // from this agent's own port, so the browser needs CORS to even read the response — without
  // it every fetch from the panel fails before ever reaching a route handler (live-tested:
  // the browser reports "Failed to fetch" and the agent's own request log never shows the
  // attempt at all). Reflecting any origin is fine here: this agent is self-hosted, one
  // operator, and the real security boundary is the wallet-signature bearer session
  // (routes.ts's onRequest hook), not network topology — CORS only gates whether a browser
  // lets its own JS *read* a response, not whether the request reaches the server.
  await app.register(cors, { origin: true });
  // global: false — only routes that opt in via `config: { rateLimit: {...} }` are throttled
  // (just POST /deals/incoming, see routes.ts). Every other route stays unthrottled: they're
  // either behind the bearer-session check already, or the two intentionally-public identity
  // GETs, which are cheap reads with no persisted side effect.
  await app.register(rateLimit, { global: false });
  registerSettlementRoutes(app, ctx, auth);
  await startAgentServer(app, { port: config.port });

  const watcher = startDealWatcher(ctx, config.watcherIntervalMs);

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
