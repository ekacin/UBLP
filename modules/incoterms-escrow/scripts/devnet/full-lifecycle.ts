/**
 * Task 17 (AGENTS.md 5.23): drives Escrow.compact through its full happy-path
 * state machine — propose -> lockEscrow -> attestMilestone -> claimPayout — against
 * the real local devnet, with three separate real wallets (buyer/seller/port-authority),
 * real ZK proofs, and a real shielded coin actually moving on-chain.
 *
 * Unlike deploy-escrow.ts (which only sanity-checked propose()), this exercises every
 * circuit and every witness path. AGENTS.md 5.36 (Discord finding #3 fix): the deposited
 * coin's nonce+salt are now SELLER-chosen at propose() time (depositParamsCommitment), not
 * recovered from a buyer-supplied memo — the seller already knows everything it needs for
 * claimPayout without decrypting anything.
 */

import crypto from 'crypto';
import * as Rx from 'rxjs';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import {
  shieldedToken,
  encodeShieldedCoinInfo,
  type ShieldedCoinInfo,
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
import { shieldFundsFromGenesis, waitForContractCoinMtIndex, roleKeyHash, openEscrowTransactionLog, logEscrowAction } from './lifecycle-helpers.js';

const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';
const AGREED_AMOUNT = 1_000_000n; // Stars

function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

async function main(): Promise<void> {
  const network = new UndeployedNetworkConfig();
  const txLog = openEscrowTransactionLog();

  console.log('Building wallets for buyer, seller, port-authority...');
  const seller = await buildAgentWallet('seller', network, PASSPHRASE);
  const buyer = await buildAgentWallet('buyer', network, PASSPHRASE);
  const portAuthority = await buildAgentWallet('port-authority', network, PASSPHRASE);

  // --- Step 0: deploy + propose ---
  // roleKeyHash()'s TS replica (src/contract/roleKeyHash.ts) used to be checked explicitly here
  // against an on-chain `sellerKeyHash` field — that field was removed (it was never read by
  // any circuit, see AGENTS.md). The same replica is still implicitly proven correct below: C's
  // attestMilestone() call only succeeds if roleKeyHash(sk, domain) there matches the
  // portAuthorityKeyHash computed here with this same function — a drift would surface as that
  // assertion failing, loudly.
  console.log('\n[0] Deploying and proposing...');
  const sellerProviders = buildEscrowProviders(seller.midnightWalletProvider, network, seller.role);
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
  const portAuthKeyHash = roleKeyHash(portAuthoritySecretKey, 'incoterms-escrow:port-auth:v1');

  const amountSalt = randomBytes32();
  const sellerAddressSalt = randomBytes32();
  const durationSeconds = BigInt(7 * 24 * 60 * 60); // AGENTS.md 5.29 — length, not an absolute timestamp anymore
  // AGENTS.md 5.36 — seller pre-chooses the deposited coin's own nonce+salt here, conveyed to
  // the buyer off-chain in a real deal (signed EscrowTerms); this script plays both roles, so
  // it just shares the same values directly below.
  const depositNonce = randomBytes32();
  const depositSalt = randomBytes32();

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

  console.log('  Calling propose()...');
  const proposeResult = await deployed.callTx.propose(portAuthKeyHash, durationSeconds, TimeoutDirection.Buyer);

  const stateAfterPropose = ledger((await sellerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after propose(): ${stateAfterPropose.state} (expect 1=Proposed)`);
  logEscrowAction(txLog, contractAddress, 'propose', {
    amount: AGREED_AMOUNT.toString(),
    currency: 'NIGHT',
    txId: proposeResult.public.txId,
    metadata: { durationSeconds: durationSeconds.toString(), timeoutDirection: 'buyer' },
  });

  // --- Step 1: buyer shields funds, then locks them into the escrow ---
  console.log('\n[1] Buyer shielding funds and calling lockEscrow()...');
  await shieldFundsFromGenesis(network, buyer, AGREED_AMOUNT + 10_000n); // headroom for change

  // AGENTS.md 5.36 — hand-built with the SELLER's pre-chosen nonce (not createShieldedCoinInfo,
  // which would pick its own random one) — confirmed working end-to-end via a live devnet
  // experiment (2026-10-29): lockEscrow()'s depositParamsCommitment assert requires this exact
  // nonce+salt, matching what propose() committed to above.
  const depositNonceHex = Buffer.from(depositNonce).toString('hex');
  const handBuiltCoin: ShieldedCoinInfo = { type: shieldedToken().raw, nonce: depositNonceHex, value: AGREED_AMOUNT };
  const depositedCoinEncoded = encodeShieldedCoinInfo(handBuiltCoin) as any;

  const buyerAddressSalt = randomBytes32();
  const buyerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositedCoin: {
      nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositNonceHex),
      color: hexToBytes(depositedCoinEncoded.color),
      value: AGREED_AMOUNT,
    },
    depositSalt,
    buyerAddress: zswapRecipient(hexToBytes(buyer.midnightWalletProvider.getCoinPublicKey())),
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(buyerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(sellerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
    // AGENTS.md 5.35 — real agents resolve this via did:web (server/portAuthority.ts); this
    // script calls the circuit directly with no did:web document to resolve, so it just
    // reuses the same value propose() was given, the same way C's own real roleKeyHash()
    // check already gets exercised below without a real did:web round-trip either.
    resolvedPortAuthorityKeyHash: portAuthKeyHash,
  };

  const buyerProviders = buildEscrowProviders(buyer.midnightWalletProvider, network, buyer.role);
  const buyerContract = await findDeployedContract(buyerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: buyerPrivateState,
  });

  // AGENTS.md 5.29 — deadlineTimestamp is now anchored here (blockTimeGte/blockTimeLte-checked
  // against this claimed value), not at propose() time.
  const claimedLockTime = BigInt(Math.floor(Date.now() / 1000));
  const lockResult = await buyerContract.callTx.lockEscrow(claimedLockTime);
  const stateAfterLock = ledger((await buyerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after lockEscrow(): ${stateAfterLock.state} (expect 2=Locked)`);
  console.log(`  deadlineTimestamp now fixed at: ${stateAfterLock.deadlineTimestamp} (expect ~claimedLockTime + durationSeconds)`);

  const depositedCoinMtIndex = await waitForContractCoinMtIndex(network.indexer, contractAddress);
  console.log(`  deposited coin's real Merkle-tree mt_index: ${depositedCoinMtIndex}`);
  logEscrowAction(txLog, contractAddress, 'lockEscrow', {
    counterparty: seller.midnightWalletProvider.getCoinPublicKey(),
    amount: AGREED_AMOUNT.toString(),
    currency: 'NIGHT',
    txId: lockResult.public.txId,
  });

  // --- Step 2: port authority attests loading confirmed ---
  console.log('\n[2] Port authority calling attestMilestone()...');
  const portAuthorityProviders = buildEscrowProviders(portAuthority.midnightWalletProvider, network, portAuthority.role);
  const portAuthorityPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    portAuthoritySecretKey,
  };
  const portAuthorityContract = await findDeployedContract(portAuthorityProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: portAuthorityPrivateState,
  });
  const attestResult = await portAuthorityContract.callTx.attestMilestone();
  const stateAfterAttest = ledger((await portAuthorityProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  milestoneConfirmed after attest: ${stateAfterAttest.milestoneConfirmed} (expect true)`);
  logEscrowAction(txLog, contractAddress, 'attestMilestone', { txId: attestResult.public.txId });

  // --- Step 3: seller claims payout. AGENTS.md 5.36 — no memo decryption: the seller already
  // knows the real coin (it chose nonce+salt itself at propose() time, value is the agreed
  // amount) — just rebuild the exact same encoded coin lockEscrow() used. ---
  console.log('\n[3] Seller calling claimPayout() (no buyerMemo decryption needed)...');

  // The coin's real Merkle-tree index was already resolved above via findContractCoinMtIndex
  // (mt_index=0 was tried first and failed with "invalid index into sparse merkle tree: 0" —
  // see AGENTS.md 5.23).
  const sellerClaimPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    qualifiedCoin: {
      nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositNonceHex),
      color: hexToBytes(depositedCoinEncoded.color),
      value: AGREED_AMOUNT,
      mt_index: depositedCoinMtIndex,
    },
    depositSalt,
    sellerAddress: sellerPrivateState.sellerAddress,
    sellerAddressSalt,
  };
  await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerClaimPrivateState);
  const sellerClaimContract = await findDeployedContract(sellerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: sellerClaimPrivateState,
  });
  const claimResult = await sellerClaimContract.callTx.claimPayout();
  const stateAfterClaim = ledger((await sellerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after claimPayout(): ${stateAfterClaim.state} (expect 3=Released)`);
  logEscrowAction(txLog, contractAddress, 'claimPayout', {
    counterparty: buyer.midnightWalletProvider.getCoinPublicKey(),
    amount: AGREED_AMOUNT.toString(),
    currency: 'NIGHT',
    txId: claimResult.public.txId,
  });

  const sellerStateAfter: any = await Rx.firstValueFrom(seller.wallet.state());
  console.log(`  seller's shielded balance after claim: ${sellerStateAfter.shielded?.balances?.[shieldedToken().raw] ?? 0n}`);

  await closeAgentWallet(seller);
  await closeAgentWallet(buyer);
  await closeAgentWallet(portAuthority);
  console.log('\nDone — full happy-path lifecycle completed successfully.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
