/**
 * One-off local devnet setup script (AGENTS.md 5.21) — generates a mnemonic per role
 * (buyer/seller/port-authority), persists each encrypted via @ublp/shared's
 * loadOrCreateEncryptedSecret (same pattern as everything else, see walletKeyStorage.ts),
 * and writes an accounts.json in the format midnight-local-dev's --fund-config expects.
 *
 * Local devnet money has zero real value — the encryption here is just so this script uses
 * the same reusable pattern our real agent wallets will, not because these specific secrets
 * are actually sensitive.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateMnemonicWords, joinMnemonicWords } from '@midnight-ntwrk/wallet-sdk-hd';
import { loadOrCreateEncryptedSecret } from '@ublp/shared';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SECRETS_DIR = path.resolve(__dirname, '..', '..', '.devnet-secrets');
const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';

const ROLES = ['buyer', 'seller', 'port-authority'] as const;

function main(): void {
  fs.mkdirSync(SECRETS_DIR, { recursive: true });

  const accounts = ROLES.map((role) => {
    const mnemonic = loadOrCreateEncryptedSecret(
      path.join(SECRETS_DIR, `${role}.json`),
      PASSPHRASE,
      () => joinMnemonicWords(generateMnemonicWords())
    );
    return { name: role, mnemonic };
  });

  const accountsFilePath = path.join(SECRETS_DIR, 'accounts.json');
  fs.writeFileSync(accountsFilePath, JSON.stringify({ accounts }, null, 2), { mode: 0o600 });

  console.log(`Generated/loaded ${accounts.length} test accounts.`);
  console.log(`Encrypted secrets: ${SECRETS_DIR}/{${ROLES.join(',')}}.json`);
  console.log(`Funding config (plaintext, local devnet only): ${accountsFilePath}`);
}

main();
