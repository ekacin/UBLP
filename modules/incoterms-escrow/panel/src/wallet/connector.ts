/**
 * Real Midnight wallet connection for operator login (AGENTS.md 5.26, rewritten 2026-08-30).
 * Replaces the earlier raw-PEM-paste login: the operator connects their own 1AM/Lace wallet
 * extension, its private key never leaves the extension's own isolated context.
 *
 * CONFIRMED (2026-08-30) against a real 1AM extension: wallet detection, `connect()`, and
 * `signData()` all run without throwing and produce a signature server/auth.ts accepts —
 * `signData`'s returned `data` came back byte-identical to the nonceHex sent in. NOT confirmed:
 * that this exercised the operator's own real, deliberately-unlocked wallet account rather than
 * some local/default identity the extension already held — no approval popup was ever observed
 * during connect()/signData(), and the user separately could not get their own 1AM account past
 * a backend "Gateway sign-in failed" error at all. See server/auth.ts's header for the fuller
 * writeup — treat the code path here as proven correct, and the real end-user approval
 * experience as still unverified until someone can watch it happen on a fully-activated account.
 *
 * One real constraint found along the way: `connect(networkId)`'s `networkId` is typed as a
 * plain `string` (no restricted union) and is only a *hint* — 1AM's own connect() reliably
 * completed for 'mainnet' during this session, while 'preview' worked once then started failing
 * with the Gateway error on retry, and our local devnet's 'undeployed' id was never recognized
 * at all. That's 1AM's own backend/network support, not something this file controls —
 * VITE_NETWORK_ID should be set to whatever network the operator's actual wallet is configured
 * for, not assumed to match this project's devnet convention.
 */

import '@midnight-ntwrk/dapp-connector-api';
import type { InitialAPI, ConnectedAPI } from '@midnight-ntwrk/dapp-connector-api';

const NETWORK_ID = (import.meta.env.VITE_NETWORK_ID ?? 'undeployed') as
  | 'undeployed'
  | 'preview'
  | 'preprod'
  | 'mainnet';

export function listWallets(): InitialAPI[] {
  const injected = window.midnight;
  return injected ? Object.values(injected) : [];
}

export async function connectWallet(wallet: InitialAPI): Promise<ConnectedAPI> {
  return wallet.connect(NETWORK_ID);
}

/** Signs `nonceHex` with the wallet's own unshielded key — the wallet decides the exact
 * encoding/prefix (see file header); server/auth.ts verifies against whatever it reports it
 * actually signed, not against nonceHex directly. */
export async function signLoginNonce(
  api: ConnectedAPI,
  nonceHex: string
): Promise<{ signature: string; signedDataHex: string; verifyingKey: string }> {
  const result = await api.signData(nonceHex, { encoding: 'hex', keyType: 'unshielded' });
  return { signature: result.signature, signedDataHex: result.data, verifyingKey: result.verifyingKey };
}
