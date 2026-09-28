import React, { useCallback, useEffect, useState } from 'react';
import { listSubmissions, approveSubmission, rejectSubmission } from '../../api/broker';
import type { Submission } from '../../types';

const POLL_INTERVAL_MS = 5_000;

const STATUS_LABELS: Record<string, string> = {
  draft: 'Draft — awaiting your approval',
  sent_to_ministry: 'Sent to Ministry',
  awaiting_ministry_approval: 'Awaiting Ministry',
  vc_received: 'VC received',
  proof_requested: 'Generating proof / settling',
  settled: 'Settled',
  rejected: 'Rejected',
  failed: 'Failed',
};

function truncate(value: string, edge = 8): string {
  return value.length > edge * 2 + 3 ? `${value.slice(0, edge)}…${value.slice(-edge)}` : value;
}

interface SubmissionQueueProps {
  onView: (id: number) => void;
}

const SubmissionQueue: React.FC<SubmissionQueueProps> = ({ onView }) => {
  const [items, setItems] = useState<Submission[]>([]);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setItems(await listSubmissions());
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
    setBusyId(id);
    setLastError(null);
    try {
      await approveSubmission(id);
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
      await rejectSubmission(id);
      await refresh();
    } catch (err) {
      setLastError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const drafts = items.filter((i) => i.status === 'draft');
  const others = items.filter((i) => i.status !== 'draft');

  return (
    <div>
      {lastError && (
        <div className="alert alert-error" role="alert">
          {lastError}
        </div>
      )}

      <h2 className="section-title">Awaiting your approval ({drafts.length})</h2>
      {drafts.length === 0 && <p className="empty-state">Nothing waiting right now.</p>}
      {drafts.map((item) => (
        <div className="card" key={item.id}>
          <div className="queue-item-head">
            <div>
              <div className="queue-item-title">{item.document.exporterName ?? item.document.documentId}</div>
              <div className="queue-item-sub">
                #{item.id} · {truncate(item.document.documentId)} · {item.document.originCountry}→{item.document.destinationCountry}
              </div>
            </div>
          </div>
          <dl className="terms-table">
            <dt>Goods</dt>
            <dd>{item.document.goodsDescription}</dd>
            <dt>HS code</dt>
            <dd>{item.document.hsCode}</dd>
            <dt>Value</dt>
            <dd>
              {item.document.totalValue} {item.document.currency}
            </dd>
          </dl>
          <div className="queue-item-actions">
            <button type="button" className="btn btn-primary" disabled={busyId !== null} onClick={() => handleApprove(item.id)}>
              {busyId === item.id ? 'Sending…' : 'Approve & send to Ministry'}
            </button>
            <button type="button" className="btn btn-danger" disabled={busyId !== null} onClick={() => handleReject(item.id)}>
              Reject
            </button>
          </div>
        </div>
      ))}

      <h2 className="section-title">In progress / history</h2>
      {others.length === 0 && <p className="empty-state">No submissions sent yet.</p>}
      {others.map((item) => (
        <div className="card" key={item.id}>
          <div className="queue-item-head">
            <div>
              <div className="queue-item-title">{item.document.exporterName ?? item.document.documentId}</div>
              <div className="queue-item-sub">
                #{item.id} · {truncate(item.document.documentId)}
              </div>
            </div>
            <span className={`badge badge-${item.status}`}>{STATUS_LABELS[item.status] ?? item.status}</span>
          </div>
          <div className="queue-item-actions">
            <button type="button" className="btn btn-sm" onClick={() => onView(item.id)}>
              View status
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default SubmissionQueue;
