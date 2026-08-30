import { useCallback, useEffect, useState } from 'react';
import { issueChallenge, verifyChallenge, sessionStore } from '../api';
import { signNonceHex, validateLoginKeyPem } from '../crypto/loginSign';

export type AuthStatus = 'checking' | 'authenticated' | 'unauthenticated';

/** Runs the AGENTS.md 5.26 challenge-response flow against a private key PEM held only in
 * this browser tab's process memory + localStorage — never sent anywhere but through the
 * ECDSA signature itself. */
async function loginWithPem(pem: string): Promise<void> {
  const { challengeId, nonceHex } = await issueChallenge();
  const signature = await signNonceHex(pem, nonceHex);
  const { sessionToken, expiresAt } = await verifyChallenge(challengeId, signature);
  sessionStore.setSession(sessionToken, expiresAt);
}

export function useAuth() {
  const [status, setStatus] = useState<AuthStatus>('checking');
  const [error, setError] = useState<string | null>(null);

  const trySilentLogin = useCallback(async () => {
    if (sessionStore.getToken()) {
      setStatus('authenticated');
      return;
    }
    const pem = sessionStore.getStoredPem();
    if (!pem) {
      setStatus('unauthenticated');
      return;
    }
    try {
      await loginWithPem(pem);
      setStatus('authenticated');
    } catch (err) {
      setError((err as Error).message);
      setStatus('unauthenticated');
    }
  }, []);

  useEffect(() => {
    void trySilentLogin();
  }, [trySilentLogin]);

  const submitLoginKey = useCallback(async (pem: string) => {
    setError(null);
    const valid = await validateLoginKeyPem(pem);
    if (!valid) {
      setError('This does not look like a valid P-256 PKCS8 private key PEM.');
      return;
    }
    try {
      await loginWithPem(pem);
      sessionStore.setStoredPem(pem);
      setStatus('authenticated');
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  const logout = useCallback((forgetKey: boolean) => {
    sessionStore.clearSession();
    if (forgetKey) sessionStore.clearStoredPem();
    setStatus('unauthenticated');
  }, []);

  return { status, error, submitLoginKey, logout };
}
