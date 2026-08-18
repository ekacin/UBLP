/**
 * Task 18 (AGENTS.md 5.23): exercises the OTHER branch of Escrow.compact's state
 * machine — propose -> lockEscrow -> (deadline passes, port authority never attests) ->
 * releaseOnTimeout() -> buyer refunded. Complements full-lifecycle.ts, which only proves the
 * happy path (claimPayout, seller paid). Uses a short deadline (few seconds) so the script
 * doesn't have to wait 7 real days.
 *
 * Buyer self-serves every witness this circuit needs (qualifiedCoin, depositSalt,
 * payoutBuyerAddress, payoutBuyerAddressSalt) from its own private state — unlike claimPayout
 * in the happy path, there's no memo-recovery step here: the buyer deposited the coin itself
 * and is refunding itself, so it already has everything.
 */

import crypto from 'crypto';
import * as Rx from 'rxjs';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import {
  createShieldedCoinInfo,
  shieldedToken,
  encodeShieldedCoinInfo,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { generateX25519KeyPair } from '@ublp/shared';
import { ledger, TimeoutDirection } from '../../contracts/managed/escrow/contract/index.js';
import {
  compiledEscrowContract,
  EscrowPrivateStateId,
  emptyEscrowPrivateState,
  zswapRecipient,
  type EscrowPrivateState,
} from '../../src/contract/index.js';
import { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { buildAgentWallet, closeAgentWallet } from '../../src/deploy/wallet.js';
import { buildEscrowProviders } from '../../src/deploy/providers.js';
import { shieldFundsFromGenesis, waitForContractCoinMtIndex, openEscrowTransactionLog, logEscrowAction } from './lifecycle-helpers.js';

const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';
const AGREED_AMOUNT = 1_000_000n;

function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}
function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

async function main(): Promise<void> {
  const network = new UndeployedNetworkConfig();
  const txLog = openEscrowTransactionLog();

  console.log('Building wallets for buyer, seller...');
  const seller = await buildAgentWallet('seller', network, PASSPHRASE);
  const buyer = await buildAgentWallet('buyer', network, PASSPHRASE);

  console.log('\n[0] Deploying and proposing with a short (15s) deadline, timeoutDirection=Buyer...');
  const sellerProviders = buildEscrowProviders(seller.midnightWalletProvider, network, seller.role);
  const deployed = await deployContract(sellerProviders, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });
  const contractAddress = deployed.deployTxData.public.contractAddress;
  console.log(`  Deployed at: ${contractAddress}`);

  const sellerSecretKey = randomBytes32();
  const sellerMemoKeyPair = generateX25519KeyPair();
  const buyerMemoKeyPair = generateX25519KeyPair();
  const portAuthoritySecretKey = randomBytes32();
  // portAuthKeyHash's exact value doesn't matter here — C never attests in this scenario —
  // but propose() still requires some value.
  const portAuthKeyHash = randomBytes32();

  const amountSalt = randomBytes32();
  const sellerAddressSalt = randomBytes32();
  const deadlineAt = BigInt(Math.floor(Date.now() / 1000) + 15);

  const sellerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerSecretKey,
    sellerAddress: zswapRecipient(hexToBytes(seller.midnightWalletProvider.getCoinPublicKey())),
    sellerAddressSalt,
    ownMemoPrivateKey: hexToBytes(sellerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(buyerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
  };
  await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);
  const proposeResult = await deployed.callTx.propose(portAuthKeyHash, deadlineAt, TimeoutDirection.Buyer);
  console.log(`  Deadline set to ${deadlineAt} (now + 15s), timeoutDirection = Buyer`);
  logEscrowAction(txLog, contractAddress, 'propose', {
    amount: AGREED_AMOUNT.toString(),
    currency: 'NIGHT',
    txId: proposeResult.public.txId,
    metadata: { deadlineAt: deadlineAt.toString(), timeoutDirection: 'buyer' },
  });

  console.log('\n[1] Buyer shielding funds and calling lockEscrow()...');
  await shieldFundsFromGenesis(network, buyer, AGREED_AMOUNT + 10_000n);

  const depositSalt = randomBytes32();
  const buyerAddressSalt = randomBytes32();
  const buyerAddress = zswapRecipient(hexToBytes(buyer.midnightWalletProvider.getCoinPublicKey()));
  const depositedCoinSdk = createShieldedCoinInfo(shieldedToken().raw, AGREED_AMOUNT);
  const depositedCoinEncoded = encodeShieldedCoinInfo(depositedCoinSdk) as any;
  const buyerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositedCoin: {
      nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositedCoinSdk.nonce),
      color: hexToBytes(depositedCoinEncoded.color),
      value: AGREED_AMOUNT,
    },
    depositSalt,
    buyerAddress,
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(buyerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(sellerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
  };
  const buyerProviders = buildEscrowProviders(buyer.midnightWalletProvider, network, buyer.role);
  const buyerContract = await findDeployedContract(buyerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: buyerPrivateState,
  });
  const lockResult = await buyerContract.callTx.lockEscrow();
  const stateAfterLock = ledger((await buyerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after lockEscrow(): ${stateAfterLock.state} (expect 2=Locked)`);

  const depositedCoinMtIndex = await waitForContractCoinMtIndex(network.indexer, contractAddress);
  console.log(`  deposited coin's real Merkle-tree mt_index: ${depositedCoinMtIndex}`);
  logEscrowAction(txLog, contractAddress, 'lockEscrow', {
    counterparty: seller.midnightWalletProvider.getCoinPublicKey(),
    amount: AGREED_AMOUNT.toString(),
    currency: 'NIGHT',
    txId: lockResult.public.txId,
  });

  console.log('\n[2] Waiting for the deadline to pass (port authority never attests)...');
  const waitMs = deadlineAt * 1000n - BigInt(Date.now()) + 6000n; // + one block's margin
  if (waitMs > 0n) await new Promise((resolve) => setTimeout(resolve, Number(waitMs)));

  const buyerBalanceBefore: any = await Rx.firstValueFrom(buyer.wallet.state());
  const shieldedBefore: bigint = buyerBalanceBefore.shielded?.balances?.[shieldedToken().raw] ?? 0n;
  console.log(`  buyer's shielded balance before releaseOnTimeout(): ${shieldedBefore}`);

  console.log('\n[3] Buyer calling releaseOnTimeout()...');
  const buyerReleasePrivateState: EscrowPrivateState = {
    ...buyerPrivateState,
    qualifiedCoin: { ...buyerPrivateState.depositedCoin!, mt_index: depositedCoinMtIndex },
    payoutBuyerAddress: buyerAddress,
    payoutBuyerAddressSalt: buyerAddressSalt,
  } as EscrowPrivateState;
  await buyerProviders.privateStateProvider.set(EscrowPrivateStateId, buyerReleasePrivateState);
  const buyerReleaseContract = await findDeployedContract(buyerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: buyerReleasePrivateState,
  });
  const releaseResult = await buyerReleaseContract.callTx.releaseOnTimeout();
  const stateAfterRelease = ledger((await buyerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after releaseOnTimeout(): ${stateAfterRelease.state} (expect 3=Released)`);
  console.log(`  loadingConfirmed: ${stateAfterRelease.loadingConfirmed} (expect false — C never attested)`);

  const buyerBalanceAfter: any = await Rx.firstValueFrom(buyer.wallet.state());
  const shieldedAfter: bigint = buyerBalanceAfter.shielded?.balances?.[shieldedToken().raw] ?? 0n;
  console.log(`  buyer's shielded balance after releaseOnTimeout(): ${shieldedAfter}`);
  console.log(`  buyer refunded exactly ${AGREED_AMOUNT}: ${shieldedAfter - shieldedBefore === AGREED_AMOUNT}`);
  logEscrowAction(txLog, contractAddress, 'releaseOnTimeout', {
    counterparty: buyer.midnightWalletProvider.getCoinPublicKey(),
    amount: AGREED_AMOUNT.toString(),
    currency: 'NIGHT',
    txId: releaseResult.public.txId,
    metadata: { paidTo: 'buyer' },
  });

  await closeAgentWallet(seller);
  await closeAgentWallet(buyer);
  console.log('\nDone — timeout-release lifecycle completed successfully.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
