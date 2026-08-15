/**
 * Per-agent wallet construction (AGENTS.md 5.21). Reuses the exact wallet-building pattern
 * midnight-local-dev's own src/wallet.ts uses (FluentWalletBuilder from testkit-js) — that's
 * real, working code for this SDK generation, not reverse-engineered from type signatures.
 *
 * The one thing added on top: the mnemonic itself is loaded via the shared encrypted-secret
 * module rather than passed in plaintext, so this matches how a real agent (not just a local
 * devnet script) would hold its wallet secret.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import * as Rx from 'rxjs';
import pino, { type Logger } from 'pino';
import { WebSocket } from 'ws';
import { ZswapSecretKeys, DustSecretKey, LedgerParameters } from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { FluentWalletBuilder, MidnightWalletProvider, type DustWalletOptions } from '@midnight-ntwrk/testkit-js';
import type { WalletFacade } from '@midnight-ntwrk/wallet-sdk';
import { loadOrCreateEncryptedSecret } from '@ublp/shared';
import type { NetworkConfig } from './networks.js';

// @ts-expect-error: needed for GraphQL subscriptions (wallet sync) to work in Node.js
globalThis.WebSocket = WebSocket;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SECRETS_DIR = path.resolve(__dirname, '..', '..', '.devnet-secrets');

export type AgentRole = 'buyer' | 'seller' | 'port-authority';

const DUST_OPTIONS: DustWalletOptions = {
  ledgerParams: LedgerParameters.initialParameters(),
  additionalFeeOverhead: 1_000n,
  feeBlocksMargin: 5,
};

function isStrictlyComplete(progress: unknown): boolean {
  if (!progress || typeof progress !== 'object') return false;
  const fn = (progress as { isStrictlyComplete?: unknown }).isStrictlyComplete;
  return typeof fn === 'function' && (fn as () => boolean).call(progress);
}

export const waitForSync = (wallet: WalletFacade, timeout = 300_000): Promise<unknown> =>
  Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.filter(
        (state: any) =>
          isStrictlyComplete(state.shielded.state.progress) &&
          isStrictlyComplete(state.unshielded.progress) &&
          isStrictlyComplete(state.dust.state.progress)
      ),
      Rx.timeout({
        each: timeout,
        with: () => Rx.throwError(() => new Error(`Wallet sync timeout after ${timeout}ms`)),
      })
    )
  );

/**
 * Loads (or, on first run, generates) the given role's mnemonic from the same encrypted
 * store generate-test-accounts.ts writes to — so a real deploy run and that setup script
 * always refer to the same identity per role.
 */
export function loadAgentMnemonic(role: AgentRole, passphrase: string): string {
  return loadOrCreateEncryptedSecret(path.join(SECRETS_DIR, `${role}.json`), passphrase, () => {
    throw new Error(
      `No secret found for role "${role}" — run scripts/generate-test-accounts.ts first.`
    );
  });
}

export interface AgentWallet {
  role: AgentRole;
  wallet: WalletFacade;
  midnightWalletProvider: MidnightWalletProvider;
  shieldedSecretKeys: ZswapSecretKeys;
  dustSecretKey: DustSecretKey;
}

/**
 * Builds and syncs a wallet for one agent role, then wraps it as a MidnightWalletProvider —
 * the bridge midnight-js-contracts' deployContract/findDeployedContract/submitCallTx expect
 * (implements both WalletProvider and MidnightProvider). Using MidnightWalletProvider.withWallet
 * here instead of hand-rolling balanceTx/submitTx avoids re-deriving the transaction-signing
 * workarounds testkit-js already handles for this SDK generation.
 */
export async function buildAgentWallet(
  role: AgentRole,
  network: NetworkConfig,
  passphrase: string,
  logger: Logger = pino({ level: 'silent' })
): Promise<AgentWallet> {
  const mnemonic = loadAgentMnemonic(role, passphrase);

  const { wallet, seeds, keystore } = await FluentWalletBuilder.forEnvironment(network.envConfig())
    .withDustOptions(DUST_OPTIONS)
    .withMnemonic(mnemonic)
    .buildWithoutStarting();

  const shieldedSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const dustSecretKey = DustSecretKey.fromSeed(seeds.dust);

  await wallet.start(shieldedSecretKeys, dustSecretKey);
  logger.info(`[${role}] Waiting for wallet to sync...`);
  await waitForSync(wallet);
  logger.info(`[${role}] Wallet synced.`);

  const midnightWalletProvider = await MidnightWalletProvider.withWallet(
    logger,
    network.envConfig(),
    wallet,
    shieldedSecretKeys,
    dustSecretKey,
    keystore
  );

  return { role, wallet, midnightWalletProvider, shieldedSecretKeys, dustSecretKey };
}

export async function closeAgentWallet(agent: AgentWallet): Promise<void> {
  await agent.wallet.stop();
}
