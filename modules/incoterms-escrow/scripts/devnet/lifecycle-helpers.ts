/**
 * Shared helpers for the devnet lifecycle scripts (full-lifecycle.ts, timeout-lifecycle.ts).
 * See AGENTS.md 5.23 for the SDK gotchas these helpers work around.
 */

import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import * as Rx from 'rxjs';
import {
  shieldedToken,
  ZswapSecretKeys,
  DustSecretKey,
  LedgerParameters,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { ShieldedAddress, ShieldedCoinPublicKey, ShieldedEncryptionPublicKey } from '@midnight-ntwrk/wallet-sdk-address-format';
import { FluentWalletBuilder } from '@midnight-ntwrk/testkit-js';
import { openTransactionLog, logTransaction, type TransactionLogDb } from '@ublp/shared';
import type { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { waitForSync, type AgentWallet } from '../../src/deploy/wallet.js';
export { roleKeyHash } from '../../src/contract/roleKeyHash.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TRANSACTION_LOG_PATH = path.join(__dirname, '..', '..', 'data', 'transactions.db');

/**
 * Accounting/reporting log — "how many deals, how much" (AGENTS.md 5.24). Same shared module
 * ublp-agent (Module 1) uses, distinguished by `module: 'incoterms-escrow'`. Logs plaintext
 * deal metadata the agent already generated/holds — this is not a privacy mechanism, and isn't
 * meant to be one; the chain's privacy guarantees protect this data from OUTSIDE observers,
 * not from the company's own bookkeeping.
 */
export function openEscrowTransactionLog(): TransactionLogDb {
  return openTransactionLog(TRANSACTION_LOG_PATH);
}

export function logEscrowAction(
  db: TransactionLogDb,
  dealRef: string,
  action: string,
  fields: { counterparty?: string; amount?: string; currency?: string; txId?: string; metadata?: Record<string, unknown> } = {}
): void {
  logTransaction(db, { module: 'incoterms-escrow', dealRef, action, ...fields });
}

export function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

export function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

// Same seed midnight-local-dev's genesis wallet uses — pre-funded with real shielded NIGHT
// (proven in AGENTS.md 5.22's independent shield-test: 250 trillion Stars available).
const GENESIS_SEED = '0000000000000000000000000000000000000000000000000000000000000001';

/** Funds `agent`'s own shielded address from the genesis wallet via a plain shielded-to-
 * shielded transfer. Deliberately sidesteps buyer's own unshielded->shielded conversion:
 * that path goes through WalletFacade.initSwap, which builds a cross-pool atomic swap whose
 * NIGHT-value balancing this SDK generation does not handle transparently for app code (the
 * node rejected it with an InvariantViolation(NightBalance(...)) — see AGENTS.md 5.23, still
 * unresolved). A same-pool shielded transfer from an already-shielded source avoids that
 * entirely, and is strictly simpler than the receiveShielded call already proven to work in
 * the standalone shield-test. */
export async function shieldFundsFromGenesis(network: UndeployedNetworkConfig, agent: AgentWallet, amount: bigint): Promise<void> {
  const { wallet: genesisWallet, seeds } = await FluentWalletBuilder.forEnvironment(network.envConfig())
    .withDustOptions({ ledgerParams: LedgerParameters.initialParameters(), additionalFeeOverhead: 1_000n, feeBlocksMargin: 5 })
    .withSeed(GENESIS_SEED)
    .buildWithoutStarting();
  const genesisShieldedSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const genesisDustSecretKey = DustSecretKey.fromSeed(seeds.dust);
  await genesisWallet.start(genesisShieldedSecretKeys, genesisDustSecretKey);
  await waitForSync(genesisWallet);

  const cpk = ShieldedCoinPublicKey.fromHexString(agent.shieldedSecretKeys.coinPublicKey);
  const epk = ShieldedEncryptionPublicKey.fromHexString(agent.shieldedSecretKeys.encryptionPublicKey);
  const recipientShieldedAddress = new ShieldedAddress(cpk, epk);

  const recipe = await genesisWallet.transferTransaction(
    [{ type: 'shielded', outputs: [{ type: shieldedToken().raw, receiverAddress: recipientShieldedAddress, amount }] }],
    { shieldedSecretKeys: genesisShieldedSecretKeys, dustSecretKey: genesisDustSecretKey },
    { ttl: new Date(Date.now() + 5 * 60_000), payFees: true }
  );
  const finalized = await genesisWallet.finalizeRecipe(recipe);
  const txId = await genesisWallet.submitTransaction(finalized);
  console.log(`  [genesis -> ${agent.role}] shield tx submitted: ${txId}`);

  await Rx.firstValueFrom(
    agent.wallet.state().pipe(
      Rx.filter((s: any) => (s.shielded?.balances?.[shieldedToken().raw] ?? 0n) >= amount),
      Rx.timeout({ each: 120_000, with: () => Rx.throwError(() => new Error('Timed out waiting for shielded balance to land')) })
    )
  );
  console.log(`  [${agent.role}] shielded balance confirmed >= ${amount}`);
  await genesisWallet.stop();
}

export { findContractCoinMtIndex, waitForContractCoinMtIndex } from '../../src/contract/mtIndex.js';
