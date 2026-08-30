import { useCallback, useEffect, useState } from 'react';
import { issueChallenge, verifyChallenge, sessionStore } from '../api';
import { listWallets, connectWallet, signLoginNonce } from '../wallet/connector';
import type { InitialAPI } from '@midnight-ntwrk/dapp-connector-api';

export type AuthStatus = 'checking' | 'authenticated' | 'connecting' | 'unauthenticated';

export function useAuth() {
  const [status, setStatus] = useState<AuthStatus>('checking');
  const [error, setError] = useState<string | null>(null);
  const [wallets, setWallets] = useState<InitialAPI[]>([]);

  useEffect(() => {
    setStatus(sessionStore.getToken() ? 'authenticated' : 'unauthenticated');
  }, []);

  /** Wallet extensions inject asynchronously — poll briefly rather than assuming they're
   * present on first render (same pattern the 1am-wallet/react-wallet-connector skills use). */
  useEffect(() => {
    if (status !== 'unauthenticated') return;
    let attempts = 0;
    const id = setInterval(() => {
      const found = listWallets();
      if (found.length > 0 || ++attempts > 30) {
        setWallets(found);
        clearInterval(id);
      }
    }, 200);
    return () => clearInterval(id);
  }, [status]);

  const login = useCallback(async (wallet: InitialAPI) => {
    setError(null);
    setStatus('connecting');
    try {
      const api = await connectWallet(wallet);
      const { challengeId, nonceHex } = await issueChallenge();
      const { signature, signedDataHex, verifyingKey } = await signLoginNonce(api, nonceHex);
      const { sessionToken, expiresAt } = await verifyChallenge(challengeId, signature, signedDataHex, verifyingKey);
      sessionStore.setSession(sessionToken, expiresAt);
      setStatus('authenticated');
    } catch (err) {
      setError((err as Error).message);
      setStatus('unauthenticated');
    }
  }, []);

  const logout = useCallback(() => {
    sessionStore.clearSession();
    setStatus('unauthenticated');
  }, []);

  return { status, error, wallets, login, logout };
}
