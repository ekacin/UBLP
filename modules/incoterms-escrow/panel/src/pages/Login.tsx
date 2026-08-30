import React from 'react';
import type { InitialAPI } from '@midnight-ntwrk/dapp-connector-api';

interface LoginProps {
  wallets: InitialAPI[];
  connecting: boolean;
  error: string | null;
  onConnect: (wallet: InitialAPI) => void;
}

const Login: React.FC<LoginProps> = ({ wallets, connecting, error, onConnect }) => {
  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="brand">UBLP</div>
        <h1>Settlement Panel</h1>
        <p className="subtitle">Sign in with your Midnight wallet to manage this company's deals.</p>

        {wallets.length === 0 && !connecting && (
          <div className="login-empty">
            <p>No Midnight wallet extension detected.</p>
            <p className="hint">Install 1AM or Lace, then reload this page.</p>
          </div>
        )}

        {wallets.length > 0 && (
          <div className="wallet-list">
            {wallets.map((wallet) => (
              <button
                key={wallet.name}
                type="button"
                className="wallet-button"
                disabled={connecting}
                onClick={() => onConnect(wallet)}
              >
                {connecting ? 'Connecting…' : `Connect ${wallet.name}`}
              </button>
            ))}
          </div>
        )}

        {error && (
          <div className="alert alert-error" role="alert">
            {error}
          </div>
        )}
      </div>
    </div>
  );
};

export default Login;
