import React, { useState } from 'react';

interface LoginProps {
  error: string | null;
  onSubmit: (pem: string) => void;
}

/** One-time key load. Run `npx tsx scripts/export-login-key.ts` on the agent's machine and
 * paste the printed private key PEM here — it is kept only in this browser's localStorage,
 * used locally to sign login challenges, and never sent to any server directly (see
 * src/crypto/loginSign.ts for what actually gets transmitted). */
const Login: React.FC<LoginProps> = ({ error, onSubmit }) => {
  const [pem, setPem] = useState('');

  return (
    <div>
      <h1>UBLP Settlement Panel</h1>
      <h2>Load your login key</h2>
      <p>
        Run <code>npx tsx scripts/export-login-key.ts</code> on the machine running your settlement agent, and
        paste the printed private key PEM below. It stays in this browser only.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(pem);
        }}
      >
        <textarea
          rows={12}
          cols={64}
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
        />
        <div>
          <button type="submit">Load key &amp; sign in</button>
        </div>
      </form>
      {error && <p role="alert">{error}</p>}
    </div>
  );
};

export default Login;
