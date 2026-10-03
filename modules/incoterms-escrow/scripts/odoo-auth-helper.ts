/**
 * Signs an `/auth/challenge` nonce for the Odoo ERP integration, so Odoo (a server-side Python
 * app with no Midnight wallet extension) can log into its own settlement-agent without a human
 * clicking through a wallet popup every 8 hours (the session TTL — see src/server/auth.ts).
 *
 * TRUST MODEL, read before reusing this pattern elsewhere: this generates and holds its own
 * dedicated signing key — it is a MACHINE/SERVICE identity, not a human operator's personal
 * wallet. `auth.ts`'s own header comment is explicit that wallet-login was built to prove "a
 * real Midnight wallet, held by a human operator, authorized this session" — this script
 * deliberately trades that human-presence guarantee for unattended automation, scoped to
 * *login* only. It does NOT touch `identity.ts`'s `dealSigningKeyPair` — actually proposing/
 * locking a deal still goes through that separate, agent-held identity exactly as before; this
 * key only ever authenticates an HTTP session, the same trust level as `auth.ts`'s own TOFU
 * bootstrap already assumes for whichever key logs in first. A real multi-operator deployment
 * would want this scoped down (e.g. a session that can only call read/propose endpoints, not
 * claim/release) — out of scope for this v0.1 pilot, flagged rather than hidden.
 *
 * Usage (invoked by the Odoo module's escrow_client.py via subprocess, not run by a human):
 *   tsx scripts/odoo-auth-helper.ts <secretsDir> <role> <nonceHex>
 * The passphrase is read from stdin (one line, no trailing processing beyond a trim), NOT an
 * argv — a process's argv is visible to any other local user via `ps aux` for as long as it
 * runs; stdin isn't. escrow_client.py passes it via subprocess.run(..., input=passphrase).
 * Prints one line of JSON to stdout: {"signature","signedDataHex","verifyingKey"}
 */
import path from 'path';
import { readFileSync } from 'fs';
import { sampleSigningKey, signData, signatureVerifyingKey, type SigningKey } from '@midnight-ntwrk/ledger-v8';
import { loadOrCreateEncryptedSecret } from '@ublp/shared';

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function loadOrCreateOdooLoginKey(secretsDir: string, role: string, passphrase: string): SigningKey {
  const filePath = path.join(secretsDir, `${role}-odoo-login-key.json`);
  return loadOrCreateEncryptedSecret(filePath, passphrase, () => sampleSigningKey()) as SigningKey;
}

function main(): void {
  const [secretsDir, role, nonceHex] = process.argv.slice(2);
  if (!secretsDir || !role || !nonceHex) {
    console.error('Usage: tsx odoo-auth-helper.ts <secretsDir> <role> <nonceHex>  (passphrase on stdin)');
    process.exit(1);
  }
  const passphrase = readFileSync(0, 'utf-8').trim();
  if (!passphrase) {
    console.error('No passphrase received on stdin.');
    process.exit(1);
  }

  const key = loadOrCreateOdooLoginKey(secretsDir, role, passphrase);
  const signature = signData(key, hexToBytes(nonceHex));
  const verifyingKey = signatureVerifyingKey(key);

  process.stdout.write(JSON.stringify({ signature, signedDataHex: nonceHex, verifyingKey }));
}

main();
