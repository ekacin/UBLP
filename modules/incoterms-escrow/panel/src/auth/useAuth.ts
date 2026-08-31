import { useCallback, useEffect, useState } from 'react';
import { issueChallenge, verifyChallenge, sessionStore } from '../api';
import { listWallets, connectWallet, signLoginNonce } from '../wallet/connector';
import { getActiveBaseUrl, setActiveBaseUrl } from '../agentInstances';
import type { InitialAPI } from '@midnight-ntwrk/dapp-connector-api';

export type AuthStatus = 'checking' | 'authenticated' | 'connecting' | 'unauthenticated';

export function useAuth() {
  const [activeBaseUrl, setActiveBaseUrlState] = useState(getActiveBaseUrl);
  const [status, setStatus] = useState<AuthStatus>('checking');
  const [error, setError] = useState<string | null>(null);
  const [wallets, setWallets] = useState<InitialAPI[]>([]);
  // Bumped on every switchInstance() call, even a no-op reselect of the already-active
  // instance — see the wallet-poll effect below for why a value-based dependency isn't enough.
  const [instanceEpoch, setInstanceEpoch] = useState(0);

  useEffect(() => {
    setStatus(sessionStore.getToken(activeBaseUrl) ? 'authenticated' : 'unauthenticated');
  }, [activeBaseUrl]);

  /** Wallet extensions inject asynchronously — poll briefly rather than assuming they're
   * present on first render (same pattern the 1am-wallet/react-wallet-connector skills use).
   * Depends on instanceEpoch, not activeBaseUrl: switchInstance() always clears `wallets`, but
   * React bails out of re-running an effect whose dependencies didn't change VALUE — e.g.
   * reselecting the already-active instance, or switching between two still-unauthenticated
   * instances in a row (status stays 'unauthenticated' both times). Either left `wallets`
   * stranded at [] with no poll ever restarting to refill it — instanceEpoch increments
   * unconditionally on every switch call so this always re-fires. */
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
  }, [status, instanceEpoch]);

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

  /** Switches which deployed agent instance this browser tab talks to (agentInstances.ts) —
   * e.g. the same company's separate buyer-role and seller-role agents (AGENTS.md 5.27). Each
   * instance has its own independent session, so this re-derives status from that instance's
   * own stored token rather than carrying the previous instance's auth state over. */
  const switchInstance = useCallback((baseUrl: string) => {
    setActiveBaseUrl(baseUrl);
    setActiveBaseUrlState(baseUrl);
    setError(null);
    setWallets([]);
    setInstanceEpoch((e) => e + 1);
    setStatus(sessionStore.getToken(baseUrl) ? 'authenticated' : 'unauthenticated');
  }, []);

  return { status, error, wallets, login, logout, activeBaseUrl, switchInstance };
}
