import React, { useCallback, useEffect, useState } from 'react';
import { listPending, approvePending, rejectPending } from '../api';
import type { PendingAction, ProposeDealParams, LockDealParams } from '../types';

const POLL_INTERVAL_MS = 5_000;

function isProposePayload(action: PendingAction): action is PendingAction & { payload: ProposeDealParams } {
  return action.action === 'propose';
}

function isLockPayload(action: PendingAction): action is PendingAction & { payload: LockDealParams } {
  return action.action === 'lockEscrow';
}

/** Full-detail view of what approving this pending action actually commits to on-chain —
 * shown before approval per the "always show full EscrowTerms" decision, since propose/
 * lockEscrow create real financial exposure (AGENTS.md 5.21). */
const PendingDetail: React.FC<{ action: PendingAction }> = ({ action }) => {
  if (isProposePayload(action)) {
    const p = action.payload;
    return (
      <dl>
        <dt>Action</dt>
        <dd>propose — creates a new offer on-chain</dd>
        <dt>Shipment ID</dt>
        <dd>{p.shipmentId}</dd>
        <dt>Buyer DID</dt>
        <dd>{p.buyerDid}</dd>
        <dt>Port authority (C) DID</dt>
        <dd>{p.portAuthorityDid}</dd>
        <dt>Incoterm</dt>
        <dd>{p.incoterm}</dd>
        <dt>Agreed amount</dt>
        <dd>{p.agreedAmount}</dd>
        <dt>Duration</dt>
        <dd>{p.durationSeconds ?? '(default 7 days)'} seconds</dd>
        <dt>Timeout direction</dt>
        <dd>{p.timeoutDirection ?? '(default buyer)'}</dd>
      </dl>
    );
  }

  if (isLockPayload(action)) {
    const { terms, sellerSignature, sellerPublicKey } = action.payload.proposal;
    return (
      <dl>
        <dt>Action</dt>
        <dd>lockEscrow — locks funds against contract {action.payload.contractAddress}</dd>
        <dt>Shipment ID</dt>
        <dd>{terms.shipmentId}</dd>
        <dt>Seller DID</dt>
        <dd>{terms.sellerDid}</dd>
        <dt>Buyer DID</dt>
        <dd>{terms.buyerDid}</dd>
        <dt>Port authority (C) DID</dt>
        <dd>{terms.portAuthorityDid}</dd>
        <dt>Incoterm</dt>
        <dd>{terms.incoterm}</dd>
        <dt>Amount</dt>
        <dd>{terms.amount}</dd>
        <dt>Duration</dt>
        <dd>{terms.durationSeconds} seconds</dd>
        <dt>Timeout direction</dt>
        <dd>{terms.timeoutDirection}</dd>
        <dt>Insurance-responsible party</dt>
        <dd>{terms.insuranceResponsibleParty ?? '(none)'}</dd>
        <dt>Seller signature</dt>
        <dd title={sellerPublicKey}>{sellerSignature.slice(0, 24)}… (verified server-side via acceptEscrow before this reaches the chain)</dd>
      </dl>
    );
  }

  return <p>Unrecognized pending action shape.</p>;
};

interface PendingQueueProps {
  onViewDeal: (contractAddress: string) => void;
}

const PendingQueue: React.FC<PendingQueueProps> = ({ onViewDeal }) => {
  const [items, setItems] = useState<PendingAction[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setItems(await listPending());
    } catch (err) {
      setLastError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  const handleApprove = async (id: number) => {
    setBusyId(id); // blocking spinner: the whole action list is disabled while busyId is set
    setLastError(null);
    try {
      await approvePending(id);
      await refresh();
    } catch (err) {
      setLastError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const handleReject = async (id: number) => {
    setBusyId(id);
    setLastError(null);
    try {
      await rejectPending(id);
      await refresh();
    } catch (err) {
      setLastError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const awaiting = items.filter((i) => i.status === 'awaiting_approval');
  const others = items.filter((i) => i.status !== 'awaiting_approval');

  return (
    <div>
      <h1>Pending approval queue</h1>
      {lastError && <p role="alert">{lastError}</p>}

      {busyId !== null && (
        <div role="alert" aria-busy="true">
          <p>
            Submitting — this generates a real ZK proof and can take 30-60 seconds. Do not close this page.
          </p>
        </div>
      )}

      <h2>Awaiting approval ({awaiting.length})</h2>
      {awaiting.length === 0 && <p>Nothing waiting.</p>}
      <ul>
        {awaiting.map((item) => (
          <li key={item.id}>
            <div>
              <strong>#{item.id}</strong> — {item.action} — {item.dealRef}
              <button type="button" onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}>
                {expandedId === item.id ? 'Hide details' : 'Show full terms'}
              </button>
            </div>
            {expandedId === item.id && <PendingDetail action={item} />}
            <div>
              <button type="button" disabled={busyId !== null} onClick={() => handleApprove(item.id)}>
                Approve
              </button>
              <button type="button" disabled={busyId !== null} onClick={() => handleReject(item.id)}>
                Reject
              </button>
            </div>
          </li>
        ))}
      </ul>

      <h2>History</h2>
      <ul>
        {others.map((item) => {
          // dealRef starts as a 'pending-propose:<timestamp>' placeholder until propose()
          // actually deploys and confirms (server/db.ts) — only a real address is worth a
          // status link.
          const hasRealDealRef = item.status === 'confirmed' && !item.dealRef.startsWith('pending-propose:');
          return (
            <li key={item.id}>
              #{item.id} — {item.action} — {item.dealRef} — {item.status}
              {item.txId && <> — tx {item.txId}</>}
              {hasRealDealRef && (
                <button type="button" onClick={() => onViewDeal(item.dealRef)}>
                  View status
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
};

export default PendingQueue;
