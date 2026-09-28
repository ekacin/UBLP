import React, { useState } from 'react';

interface LoginProps {
  role: 'ministry' | 'broker';
  connecting: boolean;
  error: string | null;
  onLogin: (passphrase: string) => void;
}

const TITLE: Record<LoginProps['role'], string> = {
  ministry: 'Ministry Review',
  broker: 'Customs Broker',
};

const SUBTITLE: Record<LoginProps['role'], string> = {
  ministry: "Sign in to review and sign this ministry's customs documents.",
  broker: "Sign in to manage this broker's customs submissions.",
};

const Login: React.FC<LoginProps> = ({ role, connecting, error, onLogin }) => {
  const [passphrase, setPassphrase] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (passphrase) onLogin(passphrase);
  };

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="brand">UBLP</div>
        <h1>{TITLE[role]}</h1>
        <p className="subtitle">{SUBTITLE[role]}</p>

        <form onSubmit={handleSubmit} className="wallet-list">
          <input
            type="password"
            placeholder="Operator passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            disabled={connecting}
            autoFocus
            className="login-input"
          />
          <button type="submit" className="wallet-button" disabled={connecting || !passphrase}>
            {connecting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

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
