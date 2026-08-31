import React, { useState } from 'react';
import { addInstance, listInstances, type AgentInstance } from '../agentInstances';

interface InstanceSwitcherProps {
  activeBaseUrl: string;
  onSwitch: (baseUrl: string) => void;
}

const ROLE_LABEL: Record<string, string> = {
  buyer: 'Buyer',
  seller: 'Seller',
  'port-authority': 'Port authority',
};

function shortUrl(url: string): string {
  return url.replace(/^https?:\/\//, '');
}

/** Lets one browser tab switch between separately-deployed agent instances — e.g. the same
 * company's seller-role and buyer-role agents (AGENTS.md 5.27, and the "a company is usually
 * both an importer and an exporter" gap this closes). Purely a connection manager: no
 * backend/contract change, each instance keeps its own independent identity and session. */
const InstanceSwitcher: React.FC<InstanceSwitcherProps> = ({ activeBaseUrl, onSwitch }) => {
  const [open, setOpen] = useState(false);
  const [adding, setAdding] = useState(false);
  const [newLabel, setNewLabel] = useState('');
  const [newUrl, setNewUrl] = useState('');
  const instances = listInstances();
  const active = instances.find((i) => i.baseUrl === activeBaseUrl);

  const submitAdd = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl.trim()) return;
    addInstance(newUrl, newLabel || newUrl);
    const url = newUrl.trim().replace(/\/$/, '');
    setNewLabel('');
    setNewUrl('');
    setAdding(false);
    setOpen(false);
    onSwitch(url);
  };

  return (
    <div className="instance-switcher">
      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen((o) => !o)}>
        {active ? active.label : shortUrl(activeBaseUrl)} ▾
      </button>
      {open && (
        <div className="instance-menu">
          {instances.map((i: AgentInstance) => (
            <button
              type="button"
              key={i.baseUrl}
              className={`instance-item${i.baseUrl === activeBaseUrl ? ' active' : ''}`}
              onClick={() => {
                setOpen(false);
                onSwitch(i.baseUrl);
              }}
            >
              <span className="instance-item-label">{i.label}</span>
              <span className="instance-item-meta">
                {i.role && <span className="badge">{ROLE_LABEL[i.role] ?? i.role}</span>}
                <span className="instance-item-url">{shortUrl(i.baseUrl)}</span>
              </span>
            </button>
          ))}
          {adding ? (
            <form className="instance-add-form" onSubmit={submitAdd}>
              <input
                type="text"
                placeholder="Label (e.g. Acme — Buyer)"
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
              />
              <input
                type="text"
                placeholder="http://host:port"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                required
              />
              <button type="submit" className="btn btn-primary btn-sm">
                Connect
              </button>
            </form>
          ) : (
            <button type="button" className="instance-item instance-item-add" onClick={() => setAdding(true)}>
              + Add another instance
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default InstanceSwitcher;
