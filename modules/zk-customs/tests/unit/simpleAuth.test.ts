import { describe, it, expect } from 'vitest';
import { SimpleSessionAuthStore } from '../../../../shared/src/agent-core/simpleAuth';

describe('SimpleSessionAuthStore', () => {
  it('issues a session token for the correct passphrase', () => {
    const auth = new SimpleSessionAuthStore('correct-pw');
    const result = auth.login('correct-pw');
    expect(result).not.toBeNull();
    expect(auth.isSessionValid(result!.sessionToken)).toBe(true);
  });

  it('rejects the wrong passphrase', () => {
    const auth = new SimpleSessionAuthStore('correct-pw');
    expect(auth.login('wrong-pw')).toBeNull();
  });

  it('rejects a passphrase of a different length without throwing', () => {
    const auth = new SimpleSessionAuthStore('a-longer-passphrase');
    expect(() => auth.login('short')).not.toThrow();
    expect(auth.login('short')).toBeNull();
  });

  it('treats an unknown token as invalid', () => {
    const auth = new SimpleSessionAuthStore('pw');
    expect(auth.isSessionValid('nonexistent-token')).toBe(false);
  });

  it('revokes a session', () => {
    const auth = new SimpleSessionAuthStore('pw');
    const { sessionToken } = auth.login('pw')!;
    auth.revokeSession(sessionToken);
    expect(auth.isSessionValid(sessionToken)).toBe(false);
  });

  it('expires a session past its TTL', () => {
    const auth = new SimpleSessionAuthStore('pw', { sessionTtlMs: -1 }); // already expired on issue
    const { sessionToken } = auth.login('pw')!;
    expect(auth.isSessionValid(sessionToken)).toBe(false);
  });

  it('sweeps expired sessions', () => {
    const auth = new SimpleSessionAuthStore('pw', { sessionTtlMs: -1 });
    const { sessionToken } = auth.login('pw')!;
    auth.sweepExpired();
    expect(auth.isSessionValid(sessionToken)).toBe(false);
  });
});
