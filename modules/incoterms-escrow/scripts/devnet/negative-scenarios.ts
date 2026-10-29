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
import { shieldedToken, encodeShieldedCoinInfo, type ShieldedCoinInfo } from '@midnight-ntwrk/midnight-js-protocol/ledger';
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
  // AGENTS.md 5.36 — seller pre-chooses the deposited coin's own nonce+salt.
  const depositNonce = randomBytes32();
  const depositSalt = randomBytes32();
  // Long duration (7 days) — releaseOnTimeout's "too early" rejection needs the eventual
  // deadline (fixed at lockEscrow time, AGENTS.md 5.29) to stay in the future for the entire
  // script run.
  const durationSeconds = BigInt(7 * 24 * 60 * 60);

  const sellerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerAddress: zswapRecipient(hexToBytes(seller.midnightWalletProvider.getCoinPublicKey())),
    sellerAddressSalt,
    ownMemoPrivateKey: hexToBytes(sellerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(buyerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
    depositNonce,
    depositSalt,
  };
  await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);
  await deployed.callTx.propose(portAuthKeyHash, durationSeconds, TimeoutDirection.Buyer);
  console.log('  propose() succeeded.');

  console.log('\n[1] Guards around propose() / lockEscrow() preconditions:');

  await expectRejected('propose() a second time on an already-Proposed contract', async () => {
    await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);
    await deployed.callTx.propose(portAuthKeyHash, durationSeconds, TimeoutDirection.Buyer);
  });

  // AGENTS.md 5.36 — hand-built with the SELLER's pre-chosen nonce (set above, before
  // propose()), not createShieldedCoinInfo (which would pick its own random one).
  const depositNonceHex = Buffer.from(depositNonce).toString('hex');
  const handBuiltCoin: ShieldedCoinInfo = { type: shieldedToken().raw, nonce: depositNonceHex, value: AGREED_AMOUNT };
  const depositedCoinEncoded = encodeShieldedCoinInfo(handBuiltCoin) as any;
  const realDepositedCoin = {
    nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositNonceHex),
    color: hexToBytes(depositedCoinEncoded.color),
    value: AGREED_AMOUNT,
  };
  const buyerAddressSalt = randomBytes32();
  const buyerAddress = zswapRecipient(hexToBytes(buyer.midnightWalletProvider.getCoinPublicKey()));
  // AGENTS.md 5.29 — every lockEscrow() call below needs a valid claimedLockTime so each test
  // fails for the ONE specific guard being exercised, not for an unrelated block-time mismatch.
  const claimedLockTime = () => BigInt(Math.floor(Date.now() / 1000));
  const basebuyerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositSalt,
    buyerAddress,
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(buyerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(sellerMemoKeyPair.publicKey),
    // AGENTS.md 5.35 — no real did:web document to resolve here (direct circuit calls), so
    // just reuse the value propose() was given, same as full-lifecycle.ts/timeout-lifecycle.ts.
    resolvedPortAuthorityKeyHash: portAuthKeyHash,
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
    await contract.callTx.lockEscrow(claimedLockTime());
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
    await contract.callTx.lockEscrow(claimedLockTime());
  });

  // AGENTS.md 5.36 (Discord finding #3 fix) — THE key new guard this fix adds: a buyer who
  // uses a nonce/salt different from what the seller committed to at propose() time must be
  // rejected, even though the coin's VALUE is otherwise correct. Without this check, a buyer
  // could lock real funds under one nonce/salt while reporting a different one to the seller
  // (the old, removed buyerMemo), permanently freezing the deal.
  await expectRejected('lockEscrow() with a deposit nonce/salt that does not match depositParamsCommitment', async () => {
    const wrongNonceCoin: ShieldedCoinInfo = {
      type: shieldedToken().raw,
      nonce: Buffer.from(randomBytes32()).toString('hex'), // NOT the seller-committed nonce
      value: AGREED_AMOUNT,
    };
    const wrongNonceEncoded = encodeShieldedCoinInfo(wrongNonceCoin) as any;
    const wrongState: EscrowPrivateState = {
      ...basebuyerPrivateState,
      depositedCoin: {
        nonce: hexToBytes(wrongNonceEncoded.nonce ?? wrongNonceCoin.nonce),
        color: hexToBytes(wrongNonceEncoded.color),
        value: AGREED_AMOUNT,
      },
      agreedAmount: AGREED_AMOUNT,
      agreedAmountSalt: amountSalt,
    };
    const contract = await findDeployedContract(buyerProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: wrongState,
    });
    await contract.callTx.lockEscrow(claimedLockTime());
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
    // Disposable clone — findDeployedContract mutates initialPrivateState in place, coercing
    // bigint fields to strings (see actions.ts's lockDeal comment). realBuyerPrivateState is
    // reused below (section [3]'s "lockEscrow() a second time" guard), so it must stay intact.
    initialPrivateState: structuredClone(realBuyerPrivateState),
  });
  await buyerContract.callTx.lockEscrow(claimedLockTime());
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
      initialPrivateState: structuredClone(realBuyerPrivateState),
    });
    await contract.callTx.lockEscrow(claimedLockTime());
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

  await expectRejected('attestMilestone() with the wrong port-authority secret key', async () => {
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
    await contract.callTx.attestMilestone();
  });

  await expectRejected('releaseOnTimeout() before the deadline has passed', async () => {
    const releaseState: EscrowPrivateState = {
      ...emptyEscrowPrivateState,
      qualifiedCoin: { ...realDepositedCoin, mt_index: depositedCoinMtIndex },
      depositSalt,
      buyerAddress,
      buyerAddressSalt,
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

  console.log('\n[4] Real attestMilestone() (needed to test double-attest)...');
  const realPortAuthorityState: EscrowPrivateState = { ...emptyEscrowPrivateState, portAuthoritySecretKey };
  await portAuthorityProviders.privateStateProvider.set(EscrowPrivateStateId, realPortAuthorityState);
  const portAuthorityContract = await findDeployedContract(portAuthorityProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: structuredClone(realPortAuthorityState),
  });
  await portAuthorityContract.callTx.attestMilestone();
  const stateAfterAttest = ledger((await portAuthorityProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  milestoneConfirmed after attest: ${stateAfterAttest.milestoneConfirmed} (expect true)`);

  console.log('\n[5] Guard against re-attestation:');
  await expectRejected('attestMilestone() a second time (already confirmed)', async () => {
    const contract = await findDeployedContract(portAuthorityProviders, {
      contractAddress,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: structuredClone(realPortAuthorityState),
    });
    await contract.callTx.attestMilestone();
  });

  console.log('\n[6] Separate deal, short deadline: releaseOnTimeout() after attestation...');
  // A fresh contract is needed here — the main deal above has a 7-day deadline already locked
  // in, so it can never actually reach "deadline passed" within this script's runtime. This
  // proves the new guard (Escrow.compact's releaseOnTimeout now asserts !milestoneConfirmed)
  // for real: without it, this exact call used to SUCCEED once the deadline passed, even
  // though C had already attested — see the Discord review that found this.
  const shortDuration = 20n;
  const deployed2 = await deployContract(sellerProviders, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });
  const contractAddress2 = deployed2.deployTxData.public.contractAddress;
  console.log(`  Deployed at: ${contractAddress2}`);

  const amountSalt2 = randomBytes32();
  const sellerAddressSalt2 = randomBytes32();
  // AGENTS.md 5.36 — fresh nonce for this SECOND, separate deal (reusing deal 1's nonce would
  // produce an identical coin commitment — same value+color+nonce — which the real shielded
  // pool rejects; nonce exists specifically to keep every coin instance unique).
  const depositNonce2 = randomBytes32();
  const depositSalt2 = randomBytes32();
  const sellerPrivateState2: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerAddress: zswapRecipient(hexToBytes(seller.midnightWalletProvider.getCoinPublicKey())),
    sellerAddressSalt: sellerAddressSalt2,
    ownMemoPrivateKey: hexToBytes(sellerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(buyerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt2,
    depositNonce: depositNonce2,
    depositSalt: depositSalt2,
  };
  await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState2);
  await deployed2.callTx.propose(portAuthKeyHash, shortDuration, TimeoutDirection.Buyer);
  console.log('  propose() succeeded (20s deadline).');

  await shieldFundsFromGenesis(network, buyer, AGREED_AMOUNT + 10_000n);
  const depositNonce2Hex = Buffer.from(depositNonce2).toString('hex');
  const handBuiltCoin2: ShieldedCoinInfo = { type: shieldedToken().raw, nonce: depositNonce2Hex, value: AGREED_AMOUNT };
  const depositedCoinEncoded2 = encodeShieldedCoinInfo(handBuiltCoin2) as any;
  const realDepositedCoin2 = {
    nonce: hexToBytes(depositedCoinEncoded2.nonce ?? depositNonce2Hex),
    color: hexToBytes(depositedCoinEncoded2.color),
    value: AGREED_AMOUNT,
  };
  const buyerAddressSalt2 = randomBytes32();
  const buyerAddress2 = zswapRecipient(hexToBytes(buyer.midnightWalletProvider.getCoinPublicKey()));
  const buyerPrivateState2: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositedCoin: realDepositedCoin2,
    depositSalt: depositSalt2,
    buyerAddress: buyerAddress2,
    buyerAddressSalt: buyerAddressSalt2,
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt2,
    ownMemoPrivateKey: hexToBytes(buyerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(sellerMemoKeyPair.publicKey),
    resolvedPortAuthorityKeyHash: portAuthKeyHash,
  };
  const buyerContract2 = await findDeployedContract(buyerProviders, {
    contractAddress: contractAddress2,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: structuredClone(buyerPrivateState2),
  });
  await buyerContract2.callTx.lockEscrow(claimedLockTime());
  console.log('  lockEscrow() succeeded.');
  const mtIndex2 = await waitForContractCoinMtIndex(network.indexer, contractAddress2);

  const portAuthorityState2: EscrowPrivateState = { ...emptyEscrowPrivateState, portAuthoritySecretKey };
  const portAuthorityContract2 = await findDeployedContract(portAuthorityProviders, {
    contractAddress: contractAddress2,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: structuredClone(portAuthorityState2),
  });
  await portAuthorityContract2.callTx.attestMilestone();
  const stateAfterAttest2 = ledger((await portAuthorityProviders.publicDataProvider.queryContractState(contractAddress2))!.data);
  console.log(`  attestMilestone() succeeded, milestoneConfirmed: ${stateAfterAttest2.milestoneConfirmed} (expect true)`);

  console.log('  Waiting 30s for the 20s deadline to actually pass...');
  await new Promise((resolve) => setTimeout(resolve, 30_000));

  await expectRejected('releaseOnTimeout() after C already attested (deadline has also passed)', async () => {
    const releaseState2: EscrowPrivateState = {
      ...emptyEscrowPrivateState,
      qualifiedCoin: { ...realDepositedCoin2, mt_index: mtIndex2 },
      depositSalt: depositSalt2,
      buyerAddress: buyerAddress2,
      buyerAddressSalt: buyerAddressSalt2,
    };
    await buyerProviders.privateStateProvider.set(EscrowPrivateStateId, releaseState2);
    const contract = await findDeployedContract(buyerProviders, {
      contractAddress: contractAddress2,
      compiledContract: compiledEscrowContract,
      privateStateId: EscrowPrivateStateId,
      initialPrivateState: releaseState2,
    });
    await contract.callTx.releaseOnTimeout();
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
