import { useCallback, useEffect, useState } from 'react';
import { login as apiLogin, sessionStore } from '../api/core';

// Same state shape as incoterms-escrow/panel's useAuth — 'connecting' stays even though there's
// no wallet round-trip here, so the login button's disabled/pending styling and error-handling
// path stay identical to escrow's, only the network call underneath differs.
export type AuthStatus = 'checking' | 'authenticated' | 'connecting' | 'unauthenticated';

export function useAuth() {
  const [status, setStatus] = useState<AuthStatus>('checking');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setStatus(sessionStore.getToken() ? 'authenticated' : 'unauthenticated');
  }, []);

  const login = useCallback(async (passphrase: string) => {
    setError(null);
    setStatus('connecting');
    try {
      const { sessionToken, expiresAt } = await apiLogin(passphrase);
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

  return { status, error, login, logout };
}
