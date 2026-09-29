/**
 * Loads the settler wallet's private key, encrypted at rest via @ublp/shared's
 * walletKeyStorage — the same AES-256-GCM + PBKDF2 scheme every other UBLP secret uses, instead
 * of a bare plaintext env var. Generated on first run if the encrypted file doesn't exist yet.
 */
import path from 'path';
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { loadOrCreateEncryptedSecret } from '@ublp/shared';

export function loadSettlerAccount(): PrivateKeyAccount {
  const passphrase = process.env.L2_SETTLER_KEY_PASSPHRASE;
  if (!passphrase) {
    throw new Error('L2_SETTLER_KEY_PASSPHRASE must be set — the settler private key is never read as a plaintext env var.');
  }
  const keyPath = path.resolve(process.env.L2_SETTLER_KEY_PATH ?? 'data/settler.key.enc');

  const privateKeyHex = loadOrCreateEncryptedSecret(keyPath, passphrase, () => generatePrivateKey());

  return privateKeyToAccount(privateKeyHex as `0x${string}`);
}
