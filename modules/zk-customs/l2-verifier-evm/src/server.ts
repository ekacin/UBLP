/**
 * Real, on-chain settlement connector for ZK Customs Clearance — a peer/alternative to
 * l2-verifier-mock, not a replacement (l2-verifier-mock stays untouched, the dev default).
 * ublp-agent needs zero code changes to target this: same POST /api/verify-and-settle path,
 * same L2SettleResponse shape, only L2_VERIFIER_URL's value changes at deploy time.
 */
import path from 'path';
import { fileURLToPath } from 'url';
import type { FastifyInstance } from 'fastify';
import { createAgentServer, startAgentServer, openTransactionLog, logTransaction, queryTransactions } from '@ublp/shared';
import type { UBLPVerifiablePresentation, L2SettleResponse, L2SettleRecord } from '@ublp/zk-customs-types';
import type { Hex } from 'viem';
import { loadChainConfig, createChainClient, submitSettlement, type ChainClient } from './chain.js';

const MODULE_TAG = 'zk-customs-l2-evm';
const PORT = Number(process.env.L2_EVM_PORT ?? '3006');
const ACCEPTED_PROOF_SYSTEMS = new Set(['sp1-groth16', 'sp1-plonk']);

function toHex32(value: string): Hex {
  const hex = value.startsWith('0x') ? value : `0x${value}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`Expected a 32-byte hex value, got: ${value}`);
  }
  return hex as Hex;
}

function proofBytesToHex(proofBytes: string): Hex {
  // proofBytes travels as base64 (matching sp1Client.ts's convention elsewhere in this repo).
  return `0x${Buffer.from(proofBytes, 'base64').toString('hex')}` as Hex;
}

function recordFromLog(row: ReturnType<typeof queryTransactions>[number]): L2SettleRecord {
  const meta = (row.metadata ?? {}) as { documentHash?: string; ministryPubKeyHash?: string; proofSystem?: string };
  return {
    documentHash: meta.documentHash ?? '',
    documentIdHash: row.dealRef,
    ministryPublicKeyHash: meta.ministryPubKeyHash ?? '',
    holderDid: row.counterparty ?? '',
    status: 'APPROVED',
    settledAt: new Date(row.timestamp).toISOString(),
    proofSystem: meta.proofSystem ?? '',
  };
}

async function build(app: FastifyInstance, chainClient: ChainClient, db: ReturnType<typeof openTransactionLog>) {
  app.get('/healthz', async () => ({ ok: true }));

  app.get('/api/records', async () => {
    return queryTransactions(db, { module: MODULE_TAG }).map(recordFromLog);
  });

  app.post<{ Body: { presentation: UBLPVerifiablePresentation } }>('/api/verify-and-settle', async (req, reply) => {
    const { presentation } = req.body ?? ({} as { presentation?: UBLPVerifiablePresentation });
    if (!presentation?.proof?.publicValues) {
      return reply.code(400).send({ error: 'Missing presentation.proof.publicValues.' });
    }

    const { proof, holder } = presentation;
    if (!ACCEPTED_PROOF_SYSTEMS.has(proof.proofSystem)) {
      return reply.code(400).send({
        error: `This connector only settles real SP1 proofs (sp1-groth16/sp1-plonk); got proofSystem="${proof.proofSystem}". ` +
          'There is no on-chain equivalent of l2-verifier-mock\'s dev/mock-ECDSA path.',
      });
    }

    let documentIdHash: Hex;
    try {
      documentIdHash = toHex32(proof.publicValues.documentIdHash);
    } catch (err) {
      return reply.code(400).send({ error: (err as Error).message });
    }

    // Cheap pre-check to return a friendlier 409 before spending a simulateContract round trip —
    // the contract's own AlreadySettled check is still the authoritative gate.
    const existing = queryTransactions(db, { module: MODULE_TAG, dealRef: documentIdHash });
    if (existing.length > 0) {
      return reply.code(409).send({
        status: 'REJECTED',
        record: recordFromLog(existing[0]),
      } satisfies { status: 'REJECTED'; record: L2SettleRecord });
    }

    const outcome = await submitSettlement(chainClient, {
      documentHash: toHex32(proof.publicValues.documentHash),
      ministryPubKeyHash: toHex32(proof.publicValues.pubKeyHash),
      documentIdHash,
      holderPubKeyHash: toHex32(proof.publicValues.holderPubKeyHash),
      holderDid: holder,
      proofBytes: proofBytesToHex(proof.proofBytes),
    });

    if (outcome.kind === 'already-settled') {
      // The chain itself is authoritative here — our local log may be missing this row (e.g. a
      // different connector instance settled it), so fall back to a minimal record built from
      // what the request already told us rather than leaving fields blank/undefined.
      const rows = queryTransactions(db, { module: MODULE_TAG, dealRef: documentIdHash });
      const fallback: L2SettleRecord = {
        documentHash: proof.publicValues.documentHash,
        documentIdHash: proof.publicValues.documentIdHash,
        ministryPublicKeyHash: proof.publicValues.pubKeyHash,
        holderDid: holder,
        status: 'APPROVED',
        settledAt: new Date().toISOString(),
        proofSystem: proof.proofSystem,
      };
      return reply.code(409).send({
        status: 'REJECTED',
        record: rows[0] ? recordFromLog(rows[0]) : fallback,
      } satisfies { status: 'REJECTED'; record: L2SettleRecord });
    }
    if (outcome.kind === 'proof-rejected') {
      return reply.code(400).send({ error: `On-chain SP1 proof verification failed: ${outcome.reason}` });
    }

    const record: L2SettleRecord = {
      documentHash: proof.publicValues.documentHash,
      documentIdHash: proof.publicValues.documentIdHash,
      ministryPublicKeyHash: proof.publicValues.pubKeyHash,
      holderDid: holder,
      status: 'APPROVED',
      settledAt: new Date(outcome.settledAt * 1000).toISOString(),
      proofSystem: proof.proofSystem,
    };

    logTransaction(db, {
      module: MODULE_TAG,
      dealRef: proof.publicValues.documentIdHash,
      action: 'settle',
      counterparty: holder,
      txId: outcome.txHash,
      metadata: {
        documentHash: proof.publicValues.documentHash,
        proofSystem: proof.proofSystem,
        ministryPubKeyHash: proof.publicValues.pubKeyHash,
      },
    });

    const response: L2SettleResponse = { status: 'APPROVED', record };
    return reply.code(200).send(response);
  });
}

export async function startServer(): Promise<FastifyInstance> {
  const config = loadChainConfig();
  const chainClient = await createChainClient(config);
  const db = openTransactionLog(path.resolve('data/transactions.db'));

  const app = createAgentServer({ logger: false });
  await build(app, chainClient, db);
  await startAgentServer(app, { port: PORT });
  console.log(`[l2-verifier-evm] listening on :${PORT}, chain RPC ${config.rpcUrl}, settlement ${config.settlementAddress}`);
  return app;
}

if (!process.env.VITEST && process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer().catch((err) => {
    console.error('[l2-verifier-evm] failed to start:', err);
    process.exit(1);
  });
}
