import React, { useEffect, useState } from 'react';
import { getDealStatus } from '../api';
import { watchContractActions } from '../indexerWatch';
import { ESCROW_STATE_LABELS, type DealStatus as DealStatusType } from '../types';

interface DealStatusProps {
  contractAddress: string;
  onClose: () => void;
}

const DealStatus: React.FC<DealStatusProps> = ({ contractAddress, onClose }) => {
  const [status, setStatus] = useState<DealStatusType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);

  const refresh = async () => {
    try {
      const result = await getDealStatus(contractAddress);
      setStatus(result);
      setLastUpdated(Date.now());
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    void refresh();
    // Real-time trigger straight from Midnight's indexer (AGENTS.md 5.28) — every deploy/
    // call/update against this contract address refetches the business-friendly view from
    // our own agent, instead of polling on a timer.
    const unsubscribe = watchContractActions(contractAddress, () => void refresh());
    return unsubscribe;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contractAddress]);

  return (
    <div>
      <button type="button" onClick={onClose}>
        ← Back
      </button>
      <h2>Deal status</h2>
      <p>
        <code>{contractAddress}</code>
      </p>
      {error && <p role="alert">{error}</p>}
      {!status && !error && <p>Loading…</p>}
      {status && (
        <dl>
          <dt>State</dt>
          <dd>{ESCROW_STATE_LABELS[status.state] ?? status.state}</dd>
          <dt>Loading confirmed by port authority</dt>
          <dd>{status.loadingConfirmed ? 'Yes' : 'Not yet'}</dd>
          <dt>Deadline</dt>
          <dd>{status.deadlineTimestamp > 0 ? new Date(status.deadlineTimestamp * 1000).toLocaleString() : '(not locked yet)'}</dd>
          <dt>Timeout pays out to</dt>
          <dd>{status.timeoutDirection}</dd>
        </dl>
      )}
      {lastUpdated && <p>Last updated: {new Date(lastUpdated).toLocaleTimeString()}</p>}
    </div>
  );
};

export default DealStatus;
