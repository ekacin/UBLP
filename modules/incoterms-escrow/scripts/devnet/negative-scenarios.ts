/**
 * Negative-path coverage for Escrow.compact's `assert` guards, run against the real local
 * devnet — full-lifecycle.ts and timeout-lifecycle.ts only ever prove the circuits accept
 * correct inputs; this proves they actually REJECT incorrect ones (auth bypass attempts,
 * amount mismatches, wrong-state calls, replay/double-actions). Every scenario here is
 * expected to throw; the script fails loudly (non-zero exit) if any of them unexpectedly
 * succeeds — that would mean a real security hole.
 *
 * Runs everything against ONE deployed contract, sequentially, interleaving the minimum
 * amount of real progress (propose/lockEscrow/attest) needed to reach each guarded state,
 * since a failed `assert` throws locally during simulation and never touches the chain — the
 * contract's on-chain state doesn't advance on a rejected attempt.
 */

import crypto from 'crypto';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { createShieldedCoinInfo, shieldedToken, encodeShieldedCoinInfo } from '@midnight-ntwrk/midnight-js-protocol/ledger';
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
import { shieldFundsFromGenesis, waitForContractCoinMtIndex, roleKeyHash } from './lifecycle-helpers.js';

const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';
const AGREED_AMOUNT = 1_000_000n;

function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}
function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

let failures = 0;

/** Runs `fn`, expecting it to throw. Logs pass/fail; does NOT stop the script on an
 * unexpected pass — we want the full report, so failures accumulate into `failures` and are
 * checked at the very end. */
async function expectRejected(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    console.log(`  [FAIL] ${label} — succeeded, but should have been rejected!`);
    failures++;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    console.log(`  [ok]   ${label} — rejected as expected (${message.slice(0, 80)}...)`);
  }
}

async function main(): Promise<void> {
  const network = new UndeployedNetworkConfig();

  console.log('Building wallets for buyer, seller, port-authority...');
  const seller = await buildAgentWallet('seller', network, PASSPHRASE);
  const buyer = await buildAgentWallet('buyer', network, PASSPHRASE);
  const portAuthority = await buildAgentWallet('port-authority', network, PASSPHRASE);

  const sellerProviders = buildEscrowProviders(seller.midnightWalletProvider, network, seller.role);
  const buyerProviders = buildEscrowProviders(buyer.midnightWalletProvider, network, buyer.role);
  const portAuthorityProviders = buildEscrowProviders(portAuthority.midnightWalletProvider, network, portAuthority.role);

  console.log('\nDeploying Escrow.compact...');
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
  const wrongPortAuthoritySecretKey = randomBytes32();
  // Derived for real — needed so the "real key" attest attempt (step 4) actually succeeds,
  // which is what makes the "wrong key" attempt (step 3) and the double-attest guard (step 5)
  // meaningful tests rather than both trivially failing against an unattestable hash.
  const portAuthKeyHash = roleKeyHash(portAuthoritySecretKey, 'incoterms-escrow:port-auth:v1');

  const amountSalt = randomBytes32();
  const sellerAddressSalt = randomBytes32();
  // Long deadline (7 days) — releaseOnTimeout's "too early" rejection needs it in the future
  // for the entire script run.
  const deadlineAt = BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60);

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
  await deployed.callTx.propose(portAuthKeyHash, deadlineAt, TimeoutDirection.Buyer);
  console.log('  propose() succeeded.');

  console.log('\n[1] Guards around propose() / lockEscrow() preconditions:');

  await expectRejected('propose() a second time on an already-Proposed contract', async () => {
    await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);
    await deployed.callTx.propose(portAuthKeyHash, deadlineAt, TimeoutDirection.Buyer);
  });

  const depositSalt = randomBytes32();
  const depositedCoinSdk = createShieldedCoinInfo(shieldedToken().raw, AGREED_AMOUNT);
  const depositedCoinEncoded = encodeShieldedCoinInfo(depositedCoinSdk) as any;
  const realDepositedCoin = {
    nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositedCoinSdk.nonce),
    color: hexToBytes(depositedCoinEncoded.color),
    value: AGREED_AMOUNT,
  };
  const buyerAddressSalt = randomBytes32();
  const buyerAddress = zswapRecipient(hexToBytes(buyer.midnightWalletProvider.getCoinPublicKey()));
  const basebuyerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositSalt,
    buyerAddress,
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(buyerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(sellerMemoKeyPair.publicKey),
  };

  await expectRejected('lockEscrow() with a coin value that does not match the agreed amount', async () => {
    const wrongState: EscrowPrivateState = {
      ...basebuyerPrivateState,
      depositedCoin: { ...realDepositedCoin, value: AGREED_AMOUNT - 1n }, // coin.value != amount
      agreedAmount: AGREED_AMOUNT, // correct — matches agreedAmountCommitment
      agreedAmountSalt: amountSalt,
    };
    const contract = await findDeployedContract(buyerProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: wrongState,
    });
    await contract.callTx.lockEscrow();
  });

  await expectRejected('lockEscrow() with a lockedAmount that does not match agreedAmountCommitment', async () => {
    const wrongState: EscrowPrivateState = {
      ...basebuyerPrivateState,
      depositedCoin: realDepositedCoin,
      agreedAmount: AGREED_AMOUNT + 1n, // wrong — won't reproduce the propose-time commitment
      agreedAmountSalt: amountSalt,
    };
    const contract = await findDeployedContract(buyerProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: wrongState,
    });
    await contract.callTx.lockEscrow();
  });

  console.log('\n[2] Real lockEscrow() (needed to test the guards past this point)...');
  await shieldFundsFromGenesis(network, buyer, AGREED_AMOUNT + 10_000n);
  const realBuyerPrivateState: EscrowPrivateState = {
    ...basebuyerPrivateState,
    depositedCoin: realDepositedCoin,
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
  };
  const buyerContract = await findDeployedContract(buyerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: realBuyerPrivateState,
  });
  await buyerContract.callTx.lockEscrow();
  const stateAfterLock = ledger((await buyerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after lockEscrow(): ${stateAfterLock.state} (expect 2=Locked)`);
  const depositedCoinMtIndex = await waitForContractCoinMtIndex(network.indexer, contractAddress);
  console.log(`  deposited coin's mt_index: ${depositedCoinMtIndex}`);

  console.log('\n[3] Guards around the Locked state:');

  await expectRejected('lockEscrow() a second time (already Locked, not Proposed)', async () => {
    const contract = await findDeployedContract(buyerProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: realBuyerPrivateState,
    });
    await contract.callTx.lockEscrow();
  });

  await expectRejected('claimPayout() before the port authority has attested', async () => {
    const claimState: EscrowPrivateState = {
      ...emptyEscrowPrivateState,
      qualifiedCoin: { ...realDepositedCoin, mt_index: depositedCoinMtIndex },
      depositSalt,
      sellerAddress: sellerPrivateState.sellerAddress,
      sellerAddressSalt,
    };
    await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, claimState);
    const contract = await findDeployedContract(sellerProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: claimState,
    });
    await contract.callTx.claimPayout();
  });

  await expectRejected('attestLoadingConfirmed() with the wrong port-authority secret key', async () => {
    const wrongState: EscrowPrivateState = {
      ...emptyEscrowPrivateState,
      portAuthoritySecretKey: wrongPortAuthoritySecretKey,
    };
    const contract = await findDeployedContract(portAuthorityProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: wrongState,
    });
    await contract.callTx.attestLoadingConfirmed();
  });

  await expectRejected('releaseOnTimeout() before the deadline has passed', async () => {
    const releaseState: EscrowPrivateState = {
      ...emptyEscrowPrivateState,
      qualifiedCoin: { ...realDepositedCoin, mt_index: depositedCoinMtIndex },
      depositSalt,
      payoutBuyerAddress: buyerAddress,
      payoutBuyerAddressSalt: buyerAddressSalt,
    };
    await buyerProviders.privateStateProvider.set(EscrowPrivateStateId, releaseState);
    const contract = await findDeployedContract(buyerProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: releaseState,
    });
    await contract.callTx.releaseOnTimeout();
  });

  console.log('\n[4] Real attestLoadingConfirmed() (needed to test double-attest)...');
  const realPortAuthorityState: EscrowPrivateState = { ...emptyEscrowPrivateState, portAuthoritySecretKey };
  await portAuthorityProviders.privateStateProvider.set(EscrowPrivateStateId, realPortAuthorityState);
  const portAuthorityContract = await findDeployedContract(portAuthorityProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: realPortAuthorityState,
  });
  await portAuthorityContract.callTx.attestLoadingConfirmed();
  const stateAfterAttest = ledger((await portAuthorityProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  loadingConfirmed after attest: ${stateAfterAttest.loadingConfirmed} (expect true)`);

  console.log('\n[5] Guard against re-attestation:');
  await expectRejected('attestLoadingConfirmed() a second time (already confirmed)', async () => {
    const contract = await findDeployedContract(portAuthorityProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: realPortAuthorityState,
    });
    await contract.callTx.attestLoadingConfirmed();
  });

  await closeAgentWallet(seller);
  await closeAgentWallet(buyer);
  await closeAgentWallet(portAuthority);

  console.log(`\n${failures === 0 ? 'All negative scenarios correctly rejected.' : `${failures} scenario(s) that should have been rejected were NOT — see [FAIL] above.`}`);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
