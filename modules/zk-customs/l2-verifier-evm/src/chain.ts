/**
 * viem client + Settlement contract interaction. Chain-agnostic by design: which EVM chain to
 * talk to is entirely determined by L2_RPC_URL/L2_CHAIN_ID — nothing here hardcodes a chain.
 */
import {
  createPublicClient,
  createWalletClient,
  http,
  type PublicClient,
  type WalletClient,
  type PrivateKeyAccount,
  type Hex,
  ContractFunctionRevertedError,
  BaseError,
} from 'viem';
import { loadSettlerAccount } from './keyStore.js';

// Minimal ABI — only what the connector calls/decodes. Kept in sync by hand with
// contracts/src/Settlement.sol; a `forge build` artifact could replace this once the contract
// toolchain is wired into the TS build, but a hand-written ABI avoids a build-order dependency.
export const SETTLEMENT_ABI = [
  {
    type: 'function',
    name: 'settle',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'documentHash', type: 'bytes32' },
      { name: 'ministryPubKeyHash', type: 'bytes32' },
      { name: 'documentIdHash', type: 'bytes32' },
      { name: 'holderPubKeyHash', type: 'bytes32' },
      { name: 'holderDid', type: 'string' },
      { name: 'proofBytes', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isSettled',
    stateMutability: 'view',
    inputs: [{ name: 'documentIdHash', type: 'bytes32' }],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'error',
    name: 'AlreadySettled',
    inputs: [{ name: 'documentIdHash', type: 'bytes32' }],
  },
  {
    type: 'event',
    name: 'Settled',
    inputs: [
      { name: 'documentIdHash', type: 'bytes32', indexed: true },
      { name: 'documentHash', type: 'bytes32', indexed: false },
      { name: 'ministryPubKeyHash', type: 'bytes32', indexed: false },
      { name: 'holderDid', type: 'string', indexed: false },
      { name: 'settler', type: 'address', indexed: true },
      { name: 'settledAt', type: 'uint256', indexed: false },
    ],
  },
] as const;

export interface ChainConfig {
  rpcUrl: string;
  chainId?: number;
  settlementAddress: `0x${string}`;
  txConfirmations: number;
}

export function loadChainConfig(): ChainConfig {
  const rpcUrl = process.env.L2_RPC_URL;
  if (!rpcUrl) throw new Error('L2_RPC_URL is required.');
  const settlementAddress = process.env.SETTLEMENT_CONTRACT_ADDRESS;
  if (!settlementAddress) throw new Error('SETTLEMENT_CONTRACT_ADDRESS is required.');
  const chainId = process.env.L2_CHAIN_ID ? Number(process.env.L2_CHAIN_ID) : undefined;
  const txConfirmations = process.env.L2_TX_CONFIRMATIONS ? Number(process.env.L2_TX_CONFIRMATIONS) : 1;
  return { rpcUrl, chainId, settlementAddress: settlementAddress as `0x${string}`, txConfirmations };
}

export interface ChainClient {
  publicClient: PublicClient;
  walletClient: WalletClient;
  account: PrivateKeyAccount;
  config: ChainConfig;
}

export async function createChainClient(config: ChainConfig): Promise<ChainClient> {
  const account = loadSettlerAccount();
  const transport = http(config.rpcUrl);

  const publicClient = createPublicClient({ transport }) as PublicClient;
  const walletClient = createWalletClient({ account, transport }) as WalletClient;

  if (config.chainId !== undefined) {
    const actual = await publicClient.getChainId();
    if (actual !== config.chainId) {
      throw new Error(`L2_CHAIN_ID mismatch: configured ${config.chainId}, RPC reports ${actual}.`);
    }
  }

  return { publicClient, walletClient, account, config };
}

export type SettleArgs = {
  documentHash: Hex;
  ministryPubKeyHash: Hex;
  documentIdHash: Hex;
  holderPubKeyHash: Hex;
  holderDid: string;
  proofBytes: Hex;
};

export type SettleOutcome =
  | { kind: 'settled'; txHash: Hex; settledAt: number }
  | { kind: 'already-settled' }
  | { kind: 'proof-rejected'; reason: string };

/** Simulates first (catches a revert, including AlreadySettled, before spending gas), then
 * submits and waits for the receipt on success. */
export async function submitSettlement(client: ChainClient, args: SettleArgs): Promise<SettleOutcome> {
  const { publicClient, walletClient, account, config } = client;

  try {
    const { request } = await publicClient.simulateContract({
      address: config.settlementAddress,
      abi: SETTLEMENT_ABI,
      functionName: 'settle',
      args: [args.documentHash, args.ministryPubKeyHash, args.documentIdHash, args.holderPubKeyHash, args.holderDid, args.proofBytes],
      account,
    });

    const txHash = await walletClient.writeContract(request);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, confirmations: config.txConfirmations });
    const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

    return { kind: 'settled', txHash, settledAt: Number(block.timestamp) };
  } catch (err) {
    if (err instanceof BaseError) {
      const revertError = err.walk((e) => e instanceof ContractFunctionRevertedError);
      if (revertError instanceof ContractFunctionRevertedError) {
        if (revertError.data?.errorName === 'AlreadySettled') {
          return { kind: 'already-settled' };
        }
        return { kind: 'proof-rejected', reason: revertError.data?.errorName ?? revertError.shortMessage };
      }
    }
    throw err;
  }
}
