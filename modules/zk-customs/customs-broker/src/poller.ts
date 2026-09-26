/**
 * Orchestration poller — modeled on incoterms-escrow's `watcher.ts` (single interval + an
 * in-flight guard so overlapping ticks are skipped), but polling an HTTP status endpoint instead
 * of chain state. Drives a submission from `awaiting_ministry_approval` through to
 * `settled`/`rejected`/`failed`, automatically and unattended — everything from here on
 * (Ministry's decision already made, Agent -> Committee -> L2) has no human gate, unchanged
 * from before this work.
 *
 * A network error talking to Ministry or the Agent is caught and logged, then retried next
 * tick — a submission stays exactly where it is rather than being marked failed just because a
 * downstream service was briefly unreachable (see the backend-foundation plan's resilience note).
 */

import { BrokerDb, listSubmissions, updateSubmission } from './db';
import { UBLPVerifiableCredential, L2SettleResponse, UBLPVerifiablePresentation } from '@ublp/zk-customs-types';

export interface PollerConfig {
  ministryUrl: string;
  ministryApiKey: string;
  agentUrl: string;
  intervalMs?: number;
}

interface MinistryDocumentResponse {
  status: 'awaiting_approval' | 'approved' | 'rejected';
  verifiableCredential?: UBLPVerifiableCredential;
}

interface AgentProcessResponse {
  presentation: UBLPVerifiablePresentation;
  l2Result: L2SettleResponse;
}

async function checkMinistryDecision(
  db: BrokerDb,
  submissionId: number,
  ministryRefId: number,
  config: PollerConfig
): Promise<void> {
  const res = await fetch(`${config.ministryUrl}/api/documents/${ministryRefId}`, {
    headers: { 'x-api-key': config.ministryApiKey },
  });
  if (!res.ok) {
    console.warn(`[Broker] Ministry status check failed for submission ${submissionId}: HTTP ${res.status}`);
    return;
  }
  const body = (await res.json()) as MinistryDocumentResponse;

  if (body.status === 'awaiting_approval') return; // nothing new yet, retry next tick

  if (body.status === 'rejected') {
    updateSubmission(db, submissionId, { status: 'rejected' });
    console.log(`[Broker] Submission ${submissionId} rejected by Ministry.`);
    return;
  }

  if (body.status === 'approved' && body.verifiableCredential) {
    updateSubmission(db, submissionId, { status: 'vc_received', verifiableCredential: body.verifiableCredential });
    await runRestOfPipeline(db, submissionId, body.verifiableCredential, config);
  }
}

/** Everything after the VC exists — Agent -> Committee -> L2 — is unchanged from before this
 * work: Broker just calls Agent's existing `POST /api/process`, exactly like the old one-shot
 * CLI script did. */
async function runRestOfPipeline(
  db: BrokerDb,
  submissionId: number,
  vc: UBLPVerifiableCredential,
  config: PollerConfig
): Promise<void> {
  updateSubmission(db, submissionId, { status: 'proof_requested' });
  try {
    const res = await fetch(`${config.agentUrl}/api/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: vc }),
    });
    const body = (await res.json()) as AgentProcessResponse & { error?: string };
    if (!res.ok) {
      updateSubmission(db, submissionId, { status: 'failed', error: body.error ?? `Agent HTTP ${res.status}` });
      console.error(`[Broker] Submission ${submissionId} failed at Agent/Committee/L2:`, body.error);
      return;
    }

    const settled = body.l2Result.status === 'APPROVED';
    updateSubmission(db, submissionId, {
      status: settled ? 'settled' : 'rejected',
      presentation: body.presentation,
      l2Result: body.l2Result,
    });
    console.log(`[Broker] Submission ${submissionId} → ${settled ? 'settled' : 'rejected'} (L2 status: ${body.l2Result.status}).`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`[Broker] Could not reach Agent for submission ${submissionId}, will retry:`, message);
    // Deliberately not marked failed — a transient network error shouldn't strand the
    // submission; it's still holding a VC, so the next tick's status check on Ministry would
    // see 'approved' again and retry this same step.
    updateSubmission(db, submissionId, { status: 'vc_received' });
  }
}

export function startSubmissionPoller(db: BrokerDb, config: PollerConfig): { stop: () => void } {
  const intervalMs = config.intervalMs ?? 5_000;
  let ticking = false;

  const tick = async (): Promise<void> => {
    if (ticking) return;
    ticking = true;
    try {
      for (const submission of listSubmissions(db, 'awaiting_ministry_approval')) {
        if (submission.ministryRefId === null) continue;
        try {
          await checkMinistryDecision(db, submission.id, submission.ministryRefId, config);
        } catch (err) {
          console.warn(`[Broker] Poller error on submission ${submission.id}, will retry:`, err);
        }
      }
      // A submission that failed to reach Agent gets reset to 'vc_received' by
      // runRestOfPipeline's catch block — pick those up too, same as awaiting_ministry_approval.
      for (const submission of listSubmissions(db, 'vc_received')) {
        if (!submission.verifiableCredential) continue;
        try {
          await runRestOfPipeline(db, submission.id, submission.verifiableCredential, config);
        } catch (err) {
          console.warn(`[Broker] Poller error resuming submission ${submission.id}, will retry:`, err);
        }
      }
    } finally {
      ticking = false;
    }
  };

  void tick();
  const handle = setInterval(() => void tick(), intervalMs);
  return { stop: () => clearInterval(handle) };
}
