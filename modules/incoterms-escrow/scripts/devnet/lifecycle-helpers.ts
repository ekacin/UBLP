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
  nativeToken,
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

/**
 * Gives `agent` spendable DUST, i.e. the ability to pay its own transaction fees.
 *
 * This is a genuinely separate concern from shieldFundsFromGenesis above: DUST is generated
 * from **unshielded** NIGHT UTXOs that have been explicitly registered on-chain via
 * `registerNightUtxosForDustGeneration` (confirmed by reading midnight-local-dev's own
 * src/wallet.ts — `registerNightForDust`/`waitForSpendableDust`, the same tool this devnet's
 * `--fund-config` flow uses). Shielded NIGHT — what shieldFundsFromGenesis transfers — can
 * never be registered for DUST generation no matter the amount or how long you wait; earlier
 * attempts that funded agents via shieldFundsFromGenesis alone and then waited for DUST failed
 * with "Insufficient Funds: could not balance dust" for exactly this reason.
 *
 * Two steps, both required:
 *   1. An unshielded-to-unshielded transfer from genesis (mirrors midnight-local-dev's own
 *      transferNight — unlike the shielded path, this needs the genesis wallet's own
 *      unshielded-keystore signature, since it spends genesis's unshielded UTXOs directly).
 *   2. `agent.wallet.registerNightUtxosForDustGeneration(...)` on the newly-received unshielded
 *      UTXOs, submitted as its own transaction, then waiting for a spendable DUST coin to
 *      appear (DUST accrues over real chain time once registered — it isn't instant).
 *
 * The wait after step 1 filters on `state.unshielded` balance specifically, not
 * shielded+unshielded combined — mixing the two reproduces a real race midnight-local-dev's own
 * `--fund-config` run hit against an agent that already had leftover shielded NIGHT from a
 * previous run: `waitForFunds`-style code resolved immediately on the pre-existing shielded
 * balance, before the new unshielded transfer had synced, so DUST registration silently saw zero
 * unregistered UTXOs and skipped itself entirely, only to time out later waiting for a spendable
 * DUST coin that could never appear.
 */
export async function fundUnshieldedAndRegisterDust(
  network: UndeployedNetworkConfig,
  agent: AgentWallet,
  amount: bigint
): Promise<void> {
  const { wallet: genesisWallet, seeds, keystore: genesisUnshieldedKeystore } = await FluentWalletBuilder.forEnvironment(
    network.envConfig()
  )
    .withDustOptions({ ledgerParams: LedgerParameters.initialParameters(), additionalFeeOverhead: 1_000n, feeBlocksMargin: 5 })
    .withSeed(GENESIS_SEED)
    .buildWithoutStarting();
  const genesisShieldedSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const genesisDustSecretKey = DustSecretKey.fromSeed(seeds.dust);
  await genesisWallet.start(genesisShieldedSecretKeys, genesisDustSecretKey);
  await waitForSync(genesisWallet);

  const receiverAddress = await agent.wallet.unshielded.getAddress();

  const recipe = await genesisWallet.transferTransaction(
    [{ type: 'unshielded', outputs: [{ type: nativeToken().raw, receiverAddress, amount }] }],
    { shieldedSecretKeys: genesisShieldedSecretKeys, dustSecretKey: genesisDustSecretKey },
    { ttl: new Date(Date.now() + 5 * 60_000) }
  );
  const signed = await genesisWallet.signRecipe(recipe, (payload) => genesisUnshieldedKeystore.signData(payload));
  const finalized = await genesisWallet.finalizeRecipe(signed);
  const txId = await genesisWallet.submitTransaction(finalized);
  console.log(`  [genesis -> ${agent.role}] unshielded NIGHT tx submitted: ${txId}`);

  const stateAfterFunding: any = await Rx.firstValueFrom(
    agent.wallet.state().pipe(
      Rx.filter((s: any) => (s.unshielded?.balances?.[nativeToken().raw] ?? 0n) >= amount),
      Rx.timeout({
        each: 120_000,
        with: () => Rx.throwError(() => new Error('Timed out waiting for unshielded NIGHT balance to land')),
      })
    )
  );
  console.log(`  [${agent.role}] unshielded NIGHT balance confirmed >= ${amount}`);
  await genesisWallet.stop();

  const unregisteredCoins = stateAfterFunding.unshielded?.availableCoins?.filter(
    (coin: any) => coin.meta.registeredForDustGeneration === false
  ) ?? [];
  if (unregisteredCoins.length === 0) {
    throw new Error(
      `[${agent.role}] expected unregistered NIGHT UTXOs right after a fresh unshielded transfer, found none — the funding tx may not have synced correctly.`
    );
  }

  const registerRecipe = await agent.wallet.registerNightUtxosForDustGeneration(
    unregisteredCoins,
    agent.unshieldedKeystore.getPublicKey(),
    (payload) => agent.unshieldedKeystore.signData(payload)
  );
  const registerFinalized = await agent.wallet.finalizeRecipe(registerRecipe);
  const registerTxId = await agent.wallet.submitTransaction(registerFinalized);
  console.log(`  [${agent.role}] DUST registration tx submitted: ${registerTxId}`);

  console.log(`  [${agent.role}] waiting for a spendable DUST coin to appear (this takes real chain time)...`);
  await Rx.firstValueFrom(
    agent.wallet.state().pipe(
      Rx.filter((s: any) => (s.dust?.availableCoins?.length ?? 0) >= 1),
      Rx.timeout({
        each: 180_000,
        with: () => Rx.throwError(() => new Error(`[${agent.role}] no spendable DUST coin appeared within 180000ms`)),
      })
    )
  );
  console.log(`  [${agent.role}] DUST is spendable.`);
}

export { findContractCoinMtIndex, waitForContractCoinMtIndex } from '../../src/contract/mtIndex.js';
