import React, { useEffect, useState } from 'react';
import { attestDeal, claimDeal, getDealStatus, releaseTimeoutDeal } from '../api';
import { watchContractActions } from '../indexerWatch';
import Stepper from '../components/Stepper';
import { ESCROW_STATE_LABELS, type AgentRole, type DealStatus as DealStatusType } from '../types';

interface DealStatusProps {
  contractAddress: string;
  role: AgentRole | null;
  onClose: () => void;
}

const STATE_BADGE_CLASS = ['badge-rejected', 'badge-awaiting_approval', 'badge-submitted_pending', 'badge-confirmed'];

const NOW_TICK_MS = 5_000;

const DealStatus: React.FC<DealStatusProps> = ({ contractAddress, role, onClose }) => {
  const [status, setStatus] = useState<DealStatusType | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());
  // The blocking overlay pattern from PendingQueue's approve/reject — attest/claim/release-
  // timeout submit straight to the chain (no approval queue, AGENTS.md 5.21) and take the same
  // 30-60s real ZK proof time.
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const result = await getDealStatus(contractAddress);
      setStatus(result);
      setNotFound(result === null);
      setLastUpdated(Date.now());
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    void refresh();
    const unsubscribe = watchContractActions(contractAddress, () => void refresh());
    const tick = setInterval(() => setNow(Date.now()), NOW_TICK_MS);
    return () => {
      unsubscribe();
      clearInterval(tick);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contractAddress]);

  const runAction = async (label: string, run: () => Promise<unknown>) => {
    setBusy(label);
    setActionError(null);
    try {
      await run();
      await refresh();
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const expired = !!status && status.deadlineTimestamp > 0 && now > status.deadlineTimestamp * 1000;
  const canAttest = role === 'port-authority' && status?.state === 2 && !status.loadingConfirmed;
  const canClaim = role === 'seller' && status?.state === 2 && status.loadingConfirmed;
  const canReleaseTimeout =
    !!status &&
    status.state === 2 &&
    !status.loadingConfirmed &&
    expired &&
    ((role === 'buyer' && status.timeoutDirection === 'buyer') || (role === 'seller' && status.timeoutDirection === 'seller'));

  return (
    <div>
      <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>
        ← Back
      </button>
      <h2 className="section-title">Deal status</h2>

      {busy && (
        <div className="blocking-overlay" role="alert" aria-busy="true">
          <div className="blocking-card">
            <div className="spinner" />
            <div className="blocking-title">{busy}</div>
            <div className="blocking-sub">This generates a real ZK proof and can take 30–60 seconds. Don't close this page.</div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="deal-address">{contractAddress}</div>

        {error && (
          <div className="alert alert-error" role="alert">
            {error}
          </div>
        )}
        {!status && !error && !notFound && <p className="empty-state">Loading…</p>}
        {notFound && !error && (
          <p className="empty-state">
            No deal found at this address on this network. It may not have been proposed yet, or the network reset
            since it was.
          </p>
        )}

        {status && <Stepper state={status.state} loadingConfirmed={status.loadingConfirmed} expired={expired} />}

        {status && (
          <dl className="status-grid">
            <dt>State</dt>
            <dd>
              <span className={`badge ${STATE_BADGE_CLASS[status.state] ?? ''}`}>
                {ESCROW_STATE_LABELS[status.state] ?? status.state}
              </span>
            </dd>
            <dt>Loading confirmed by port authority</dt>
            <dd>{status.loadingConfirmed ? 'Yes' : 'Not yet'}</dd>
            <dt>Deadline</dt>
            <dd>
              {status.deadlineTimestamp > 0 ? new Date(status.deadlineTimestamp * 1000).toLocaleString() : '(not locked yet)'}
              {expired && status.state === 2 && !status.loadingConfirmed && ' — passed'}
            </dd>
            <dt>Timeout pays out to</dt>
            <dd>{status.timeoutDirection}</dd>
          </dl>
        )}

        {(canAttest || canClaim || canReleaseTimeout) && (
          <div className="queue-item-actions">
            {canAttest && (
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy !== null}
                onClick={() => runAction('Confirming loading…', () => attestDeal(contractAddress))}
              >
                Confirm loading completed
              </button>
            )}
            {canClaim && (
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy !== null}
                onClick={() => runAction('Collecting payment…', () => claimDeal(contractAddress))}
              >
                Collect payment
              </button>
            )}
            {canReleaseTimeout && (
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy !== null}
                onClick={() => runAction('Releasing funds…', () => releaseTimeoutDeal(contractAddress))}
              >
                {role === 'buyer' ? 'Take my money back' : 'Take the payment'}
              </button>
            )}
          </div>
        )}
        {actionError && (
          <div className="alert alert-error" role="alert">
            {actionError}
          </div>
        )}

        {lastUpdated && <div className="last-updated">Last updated {new Date(lastUpdated).toLocaleTimeString()}</div>}
      </div>

      {status && status.ownRecord.length > 0 && (
        <>
          <h2 className="section-title">Your company's own record</h2>
          <div className="card">
            <p className="action-note" style={{ marginTop: 0 }}>
              This amount is never written to the chain — only your own agent's bookkeeping knows it. A
              counterparty sees none of this.
            </p>
            <dl className="status-grid">
              {status.ownRecord.map((entry, i) => (
                <React.Fragment key={i}>
                  <dt>{entry.action}</dt>
                  <dd>
                    {entry.amount ?? '—'} {entry.currency ?? ''} · {new Date(entry.timestamp).toLocaleString()}
                  </dd>
                </React.Fragment>
              ))}
            </dl>
          </div>
        </>
      )}
    </div>
  );
};

export default DealStatus;
