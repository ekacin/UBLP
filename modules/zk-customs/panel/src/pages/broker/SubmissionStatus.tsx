import React, { useCallback, useEffect, useState } from 'react';
import { getSubmission } from '../../api/broker';
import SubmissionStepper from '../../components/SubmissionStepper';
import type { Submission, VPProof } from '../../types';

const POLL_INTERVAL_MS = 5_000;

function truncateMiddle(value: string, edge = 16): string {
  return value.length > edge * 2 + 3 ? `${value.slice(0, edge)}…${value.slice(-edge)}` : value;
}

/** The proof object's own shape — `publicValues` are the 4 hashes a real SP1 circuit would
 * commit to as public outputs; `proofBytes` is either a real zkSNARK (sp1-groth16/sp1-plonk)
 * or, in dev mode with no SP1 prover-network key configured, Ministry's own ECDSA signature
 * standing in for one (mock-ecdsa-p256) — same publicValues shape either way, only the proof
 * bytes' actual cryptographic meaning differs. Shown here mainly so "is this a real ZK proof or
 * the mock" is never ambiguous from the UI alone. */
const ProofCard: React.FC<{ proof: VPProof }> = ({ proof }) => {
  const [copied, setCopied] = useState(false);
  const isMock = proof.proofSystem.startsWith('mock');

  const copyProofBytes = () => {
    navigator.clipboard?.writeText(proof.proofBytes).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="card">
      <div className="queue-item-head">
        <div className="queue-item-title">ZK Proof</div>
        <span className={`badge ${isMock ? 'badge-awaiting_approval' : 'badge-settled'}`}>{proof.proofSystem}</span>
      </div>
      {isMock && (
        <p className="action-note">
          Mock mode — SP1_PROVER_NETWORK_KEY isn't configured, so this is Ministry's own ECDSA signature standing in
          for a real zkSNARK. The four hashes below are exactly what a real SP1 circuit would commit to as public
          outputs; only the proof bytes' cryptographic meaning differs.
        </p>
      )}
      <dl className="terms-table">
        <dt>Document hash</dt>
        <dd title={proof.publicValues.documentHash}>{truncateMiddle(proof.publicValues.documentHash)}</dd>
        <dt>Ministry pubkey hash</dt>
        <dd title={proof.publicValues.pubKeyHash}>{truncateMiddle(proof.publicValues.pubKeyHash)}</dd>
        <dt>Document ID hash</dt>
        <dd title={proof.publicValues.documentIdHash}>{truncateMiddle(proof.publicValues.documentIdHash)}</dd>
        <dt>Holder pubkey hash</dt>
        <dd title={proof.publicValues.holderPubKeyHash}>{truncateMiddle(proof.publicValues.holderPubKeyHash)}</dd>
        <dt>Proof bytes</dt>
        <dd title={proof.proofBytes}>{truncateMiddle(proof.proofBytes, 20)}</dd>
      </dl>
      <div className="queue-item-actions">
        <button type="button" className="btn btn-sm" onClick={copyProofBytes}>
          {copied ? 'Copied' : 'Copy proof bytes'}
        </button>
      </div>
    </div>
  );
};

interface SubmissionStatusProps {
  id: number;
  onClose: () => void;
}

const SubmissionStatus: React.FC<SubmissionStatusProps> = ({ id, onClose }) => {
  const [submission, setSubmission] = useState<Submission | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setSubmission(await getSubmission(id));
    } catch (err) {
      setError((err as Error).message);
    }
  }, [id]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <div>
      <button type="button" className="btn btn-ghost btn-sm" onClick={onClose} style={{ marginBottom: 16 }}>
        ← Back to queue
      </button>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}

      {!submission && !error && <p className="empty-state">Loading…</p>}

      {submission && (
        <>
          <div className="deal-address">
            #{submission.id} · {submission.document.documentId}
          </div>
          <SubmissionStepper status={submission.status} />
          <dl className="status-grid">
            <dt>Status</dt>
            <dd>
              <span className={`badge badge-${submission.status}`}>{submission.status}</span>
            </dd>
            <dt>Exporter</dt>
            <dd>{submission.document.exporterName}</dd>
            <dt>Importer</dt>
            <dd>{submission.document.importerName}</dd>
            <dt>Route</dt>
            <dd>
              {submission.document.originCountry} → {submission.document.destinationCountry}
            </dd>
            {submission.verifiableCredential && (
              <>
                <dt>Verifiable Credential</dt>
                <dd>{submission.verifiableCredential.id}</dd>
              </>
            )}
            {submission.l2Result && (
              <>
                <dt>L2 settlement</dt>
                <dd>
                  {submission.l2Result.status} · {submission.l2Result.record.settledAt}
                </dd>
              </>
            )}
            {submission.error && (
              <>
                <dt>Error</dt>
                <dd>{submission.error}</dd>
              </>
            )}
          </dl>
          {submission.presentation && <ProofCard proof={submission.presentation.proof} />}
          <div className="last-updated">Last updated: {new Date(submission.updatedAt).toLocaleString()}</div>
        </>
      )}
    </div>
  );
};

export default SubmissionStatus;
