/**
 * End-to-end smoke test — mirrors customs-broker's own `npm run smoke` pattern. Starts a local
 * Anvil chain, deploys AlwaysValidSP1Verifier + Settlement (reading forge build artifacts —
 * run `npm run compile:contract` first), starts this connector against it, then exercises the
 * full HTTP-to-chain-to-HTTP round trip: first settle -> 200, duplicate -> 409, bad proofSystem
 * -> 400. No real SP1 proving involved (the mock verifier accepts anything).
 */
import { spawn, type ChildProcess } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  toHex,
  type Hex,
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import type { UBLPVerifiablePresentation } from '@ublp/zk-customs-types';

const ANVIL_PORT = 8555;
const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;
// Anvil's well-known default funded dev keys (index 0 = deployer/settler, same key for both —
// fine for a local smoke test; production should use distinct keys, see .env.example).
const ANVIL_KEY: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

function readArtifact(contractPath: string): { abi: unknown[]; bytecode: Hex } {
  const artifactPath = path.resolve(__dirname, '../contracts/out', contractPath);
  const json = JSON.parse(fs.readFileSync(artifactPath, 'utf-8'));
  return { abi: json.abi, bytecode: json.bytecode.object as Hex };
}

function waitForRpc(url: string, timeoutMs = 15_000): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
        });
        if (res.ok) return resolve();
      } catch {
        // not up yet
      }
      if (Date.now() - start > timeoutMs) return reject(new Error('anvil did not become ready in time'));
      setTimeout(tick, 300);
    };
    void tick();
  });
}

function hex32(seed: string): Hex {
  return keccak256(toHex(seed));
}

async function main() {
  const account = privateKeyToAccount(ANVIL_KEY);
  let anvil: ChildProcess | undefined;
  let server: { close: () => Promise<void> } | undefined;

  try {
    anvil = spawn('anvil', ['--port', String(ANVIL_PORT), '--silent']);
    await waitForRpc(ANVIL_RPC);
    console.log('[smoke] anvil up on', ANVIL_RPC);

    const publicClient = createPublicClient({ chain: foundry, transport: http(ANVIL_RPC) });
    const walletClient = createWalletClient({ chain: foundry, account, transport: http(ANVIL_RPC) });

    const verifierArtifact = readArtifact('AlwaysValidSP1Verifier.sol/AlwaysValidSP1Verifier.json');
    const verifierDeployHash = await walletClient.deployContract({
      abi: verifierArtifact.abi,
      bytecode: verifierArtifact.bytecode,
      account,
      chain: foundry,
    });
    const verifierReceipt = await publicClient.waitForTransactionReceipt({ hash: verifierDeployHash });
    const verifierAddress = verifierReceipt.contractAddress!;
    console.log('[smoke] AlwaysValidSP1Verifier deployed at', verifierAddress);

    const settlementArtifact = readArtifact('Settlement.sol/Settlement.json');
    const programVKey = hex32('smoke-test-vkey');
    const settlementDeployHash = await walletClient.deployContract({
      abi: settlementArtifact.abi,
      bytecode: settlementArtifact.bytecode,
      args: [verifierAddress, programVKey],
      account,
      chain: foundry,
    });
    const settlementReceipt = await publicClient.waitForTransactionReceipt({ hash: settlementDeployHash });
    const settlementAddress = settlementReceipt.contractAddress!;
    console.log('[smoke] Settlement deployed at', settlementAddress);

    process.env.L2_RPC_URL = ANVIL_RPC;
    process.env.SETTLEMENT_CONTRACT_ADDRESS = settlementAddress;
    process.env.SP1_VERIFIER_ADDRESS = verifierAddress;
    process.env.SP1_PROGRAM_VKEY = programVKey;
    process.env.L2_SETTLER_KEY_PASSPHRASE = 'smoke-test-passphrase';
    process.env.L2_SETTLER_KEY_PATH = path.resolve(__dirname, '../data/smoke-settler.key.enc');
    process.env.L2_EVM_PORT = '3606';
    fs.rmSync(process.env.L2_SETTLER_KEY_PATH, { force: true });

    // Force the smoke run's key file to hold the same Anvil dev key the deploy used, so the
    // connector's own settler account is funded — write it directly via the same encryption
    // helper the connector uses, rather than letting it generate an unfunded random key.
    const { loadOrCreateEncryptedSecret } = await import('@ublp/shared');
    loadOrCreateEncryptedSecret(process.env.L2_SETTLER_KEY_PATH, process.env.L2_SETTLER_KEY_PASSPHRASE, () => ANVIL_KEY);

    const { startServer } = await import('./server.js');
    server = await startServer();

    const base = `http://localhost:${process.env.L2_EVM_PORT}`;
    const presentation = (documentIdSeed: string): UBLPVerifiablePresentation => ({
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation', 'UBLPZKPresentation'],
      holder: 'did:ublp:agent:default',
      verifiableCredential: [
        {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          id: 'urn:uuid:smoke',
          type: ['VerifiableCredential', 'UBLPCustomsCredential'],
          issuer: 'did:ublp:ministry',
          issuanceDate: new Date().toISOString(),
          credentialSubject: { id: 'did:ublp:ministry', documentId: documentIdSeed },
          proof: {
            type: 'EcdsaSecp256r1Signature2019',
            created: new Date().toISOString(),
            verificationMethod: 'did:ublp:ministry#key-1',
            proofPurpose: 'assertionMethod',
            proofValue: 'unused-in-smoke',
            ministryPublicKey: 'unused-in-smoke',
          },
        },
      ],
      proof: {
        type: 'SP1ZKProof',
        created: new Date().toISOString(),
        proofPurpose: 'authentication',
        proofSystem: 'sp1-groth16',
        publicValues: {
          documentHash: hex32(`${documentIdSeed}:doc`),
          pubKeyHash: hex32('ministry-pubkey'),
          documentIdHash: hex32(documentIdSeed),
          holderPubKeyHash: hex32('holder-pubkey'),
        },
        proofBytes: Buffer.from('deadbeef', 'hex').toString('base64'),
        ministryPublicKey: 'unused-in-smoke',
      },
    });

    const post = (body: unknown) =>
      fetch(`${base}/api/verify-and-settle`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });

    const first = await post({ presentation: presentation('smoke-doc-1') });
    if (first.status !== 200) throw new Error(`expected 200 on first settle, got ${first.status}: ${await first.text()}`);
    console.log('[smoke] first settle -> 200 OK');

    const duplicate = await post({ presentation: presentation('smoke-doc-1') });
    if (duplicate.status !== 409) throw new Error(`expected 409 on duplicate, got ${duplicate.status}: ${await duplicate.text()}`);
    console.log('[smoke] duplicate settle -> 409 OK');

    const badProof = presentation('smoke-doc-2');
    badProof.proof.proofSystem = 'mock-ecdsa-p256';
    const bad = await post({ presentation: badProof });
    if (bad.status !== 400) throw new Error(`expected 400 on bad proofSystem, got ${bad.status}: ${await bad.text()}`);
    console.log('[smoke] bad proofSystem -> 400 OK');

    console.log('[smoke] all checks passed');
  } finally {
    if (server) await server.close();
    if (anvil) anvil.kill();
  }
}

main().catch((err) => {
  console.error('[smoke] FAILED:', err);
  process.exit(1);
});
