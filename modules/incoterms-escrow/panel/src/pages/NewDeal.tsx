import React, { useState } from 'react';
import { fetchCounterpartyIdentity, lockDeal, parseEscrowProposal, proposeDeal } from '../api';
import type { AgentRole, LockDealParams, ProposeDealParams } from '../types';

type Mode = 'propose' | 'lock';

interface NewDealProps {
  role: AgentRole | null;
  onCreated: () => void;
}

const emptyProposeForm: ProposeDealParams = {
  shipmentId: '',
  buyerDid: '',
  portAuthorityDid: '',
  portAuthorityKeyHashHex: '',
  buyerMemoPublicKeyHex: '',
  incoterm: 'FOB',
  agreedAmount: '',
  durationSeconds: undefined,
  timeoutDirection: 'buyer',
};

/** Small helper for the two identity fields a seller needs from the buyer's / port authority's
 * own agent (AGENTS.md 5.12/5.18) — normally relayed by email/chat as a hex string; this lets
 * an operator fetch it directly from that agent's base URL instead of copy-pasting. */
const FetchIdentityButton: React.FC<{
  which: 'port-authority-key-hash' | 'memo-public-key';
  onFetched: (hex: string) => void;
}> = ({ which, onFetched }) => {
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    if (!url) return;
    setBusy(true);
    setError(null);
    try {
      onFetched(await fetchCounterpartyIdentity(url, which));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fetch-identity">
      <input
        type="text"
        placeholder="http://their-agent-host:port"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />
      <button type="button" className="btn btn-sm" disabled={busy || !url} onClick={run}>
        {busy ? 'Fetching…' : 'Fetch'}
      </button>
      {error && <span className="field-error">{error}</span>}
    </div>
  );
};

const ProposeForm: React.FC<{ onCreated: () => void }> = ({ onCreated }) => {
  const [form, setForm] = useState<ProposeDealParams>(emptyProposeForm);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const set = <K extends keyof ProposeDealParams>(key: K, value: ProposeDealParams[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await proposeDeal(form);
      setForm(emptyProposeForm);
      onCreated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="new-deal-form">
      <label>
        Shipment ID
        <input required value={form.shipmentId} onChange={(e) => set('shipmentId', e.target.value)} />
      </label>
      <label>
        Buyer DID
        <input
          required
          placeholder="did:ublp:buyer:..."
          value={form.buyerDid}
          onChange={(e) => set('buyerDid', e.target.value)}
        />
      </label>
      <label>
        Port authority (C) DID
        <input
          required
          placeholder="did:ublp:port-authority:..."
          value={form.portAuthorityDid}
          onChange={(e) => set('portAuthorityDid', e.target.value)}
        />
      </label>
      <label>
        Port authority's key hash
        <input
          required
          placeholder="hex"
          value={form.portAuthorityKeyHashHex}
          onChange={(e) => set('portAuthorityKeyHashHex', e.target.value)}
        />
      </label>
      <FetchIdentityButton which="port-authority-key-hash" onFetched={(hex) => set('portAuthorityKeyHashHex', hex)} />

      <label>
        Buyer's memo public key
        <input
          required
          placeholder="hex"
          value={form.buyerMemoPublicKeyHex}
          onChange={(e) => set('buyerMemoPublicKeyHex', e.target.value)}
        />
      </label>
      <FetchIdentityButton which="memo-public-key" onFetched={(hex) => set('buyerMemoPublicKeyHex', hex)} />

      <label>
        Incoterm
        <select value={form.incoterm} onChange={(e) => set('incoterm', e.target.value)}>
          <option value="FOB">FOB</option>
        </select>
      </label>
      <label>
        Agreed amount
        <input
          required
          type="text"
          inputMode="numeric"
          placeholder="1000000"
          value={form.agreedAmount}
          onChange={(e) => set('agreedAmount', e.target.value)}
        />
      </label>
      <label>
        Duration (seconds)
        <input
          type="text"
          inputMode="numeric"
          placeholder="604800 (default — 7 days)"
          value={form.durationSeconds ?? ''}
          onChange={(e) => set('durationSeconds', e.target.value ? Number(e.target.value) : undefined)}
        />
      </label>
      <label>
        If C never attests, timeout pays out to
        <select
          value={form.timeoutDirection ?? 'buyer'}
          onChange={(e) => set('timeoutDirection', e.target.value as 'buyer' | 'seller')}
        >
          <option value="buyer">buyer (refund)</option>
          <option value="seller">seller</option>
        </select>
      </label>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? 'Queuing…' : 'Queue offer for approval'}
      </button>
    </form>
  );
};

const LockForm: React.FC<{ onCreated: () => void }> = ({ onCreated }) => {
  const [contractAddress, setContractAddress] = useState('');
  const [proposalText, setProposalText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const proposal = parseEscrowProposal(proposalText);
      const params: LockDealParams = { contractAddress, proposal };
      await lockDeal(params);
      setContractAddress('');
      setProposalText('');
      onCreated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="new-deal-form">
      <p className="empty-state" style={{ marginTop: 0 }}>
        Paste the contract address and the signed offer the seller sent you out-of-band (email, EDI, etc.). The
        signature is verified before anything is submitted on-chain — a tampered or forged offer is rejected.
      </p>
      <label>
        Contract address
        <input required value={contractAddress} onChange={(e) => setContractAddress(e.target.value)} />
      </label>
      <label>
        Signed offer (JSON)
        <textarea
          required
          rows={8}
          placeholder='{"terms": {...}, "sellerSignature": "...", "sellerPublicKey": "..."}'
          value={proposalText}
          onChange={(e) => setProposalText(e.target.value)}
        />
      </label>
      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? 'Queuing…' : 'Queue lock for approval'}
      </button>
    </form>
  );
};

/** propose() only accepts calls from the seller role's agent, lockEscrow() only from the
 * buyer's (server/actions.ts) — a single deployed agent is always one fixed identity, never
 * both, so there's no real choice to present here (unlike a generic multi-role demo). */
const NewDeal: React.FC<NewDealProps> = ({ role, onCreated }) => {
  const mode: Mode | null = role === 'buyer' ? 'lock' : role === 'seller' ? 'propose' : null;

  return (
    <div>
      <h2 className="section-title">New deal</h2>
      <div className="card">
        {mode === 'propose' && <ProposeForm onCreated={onCreated} />}
        {mode === 'lock' && <LockForm onCreated={onCreated} />}
        {mode === null && <p className="empty-state">This agent's role doesn't originate new deals.</p>}
      </div>
    </div>
  );
};

export default NewDeal;
