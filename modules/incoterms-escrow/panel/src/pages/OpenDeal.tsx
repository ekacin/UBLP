import React, { useState } from 'react';

interface OpenDealProps {
  onOpen: (contractAddress: string) => void;
}

/** A port-authority agent has no propose/lockEscrow history of its own (see App.tsx's comment)
 * — the counterparty hands it the deal's contract address out-of-band once funds are locked,
 * and this is the only way it ever reaches a deal's status page. Useful for seller/buyer too
 * for revisiting a deal that scrolled out of their own queue history. */
const OpenDeal: React.FC<OpenDealProps> = ({ onOpen }) => {
  const [address, setAddress] = useState('');

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (address.trim()) onOpen(address.trim());
  };

  return (
    <div>
      <h2 className="section-title">Open a deal</h2>
      <div className="card">
        <p className="empty-state" style={{ marginTop: 0 }}>
          Paste the contract address the other party shared with you.
        </p>
        <form className="open-deal-form" onSubmit={submit}>
          <input
            type="text"
            placeholder="0200…"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            required
          />
          <button type="submit" className="btn btn-primary">
            Open
          </button>
        </form>
      </div>
    </div>
  );
};

export default OpenDeal;
